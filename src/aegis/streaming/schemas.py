"""The Avro schema for our event envelope, and the Schema Registry contract.

WHY A SCHEMA AT ALL
-------------------
Right now the producer and the consumer are both our code, so we could send
JSON and everything would work. The problem arrives later: someone renames a
field, and the consumer keeps running while quietly reading nulls. Nothing
crashes. The data is wrong for three weeks. This is the single most common way
data platforms fail, and it fails *silently*, which is what makes it expensive.

A schema turns that into an error at the moment of the change, on the producer
side, before a single bad record is written.

WHAT THE SCHEMA REGISTRY ADDS
-----------------------------
The registry is a small service (built into Redpanda here) that stores schemas
and assigns each one an ID. The wire format becomes:

    [ 1 magic byte ][ 4-byte schema ID ][ Avro-encoded payload ]

So each message carries a 5-byte pointer to its schema instead of repeating
field names on every record. Two consequences:

  * Messages get dramatically smaller. JSON repeats every key in every record;
    Avro writes values only, in schema order.
  * A consumer can decode a message written last year, because it can fetch
    that exact schema by ID. This is what makes long retention safe.

The registry also ENFORCES compatibility. Configured as BACKWARD (our choice
below), it refuses to register a new schema that would break existing readers -
for example, removing a field, or adding a required one without a default.
The rejection happens at deploy time, not at 3 a.m.

THE DESIGN DECISION: A TYPED ENVELOPE AROUND AN OPAQUE PAYLOAD
--------------------------------------------------------------
Our envelope fields (source, event_type, occurred_at, ...) are strongly typed
in Avro. The `payload` is a JSON string, not an Avro record.

That is deliberate, and it is the same pattern the CloudEvents specification
uses. The reasoning:

  * The envelope is OURS. We control it, it changes rarely, and every consumer
    depends on it - so it must be strictly enforced.
  * The payload belongs to someone else. URLhaus can add a column tomorrow
    without telling us. Modelling each source's payload in Avro would mean a
    schema change, a registry round-trip and a deployment every time an
    upstream provider tweaked their format - and a hard failure whenever we
    were slower than they were.

The trade-off is real: we get no field-level validation of payload contents
here. That validation is not skipped, it is *moved* - to the Silver layer in
Phase 4, where per-source contracts are enforced with dbt tests and rejects
are quarantined. Validating the payload where its shape is actually understood
is better engineering than validating it at the door where it is not.
"""

from __future__ import annotations

import json
from typing import Any

from aegis.sources.models import Event

# ---------------------------------------------------------------------------
# The envelope schema.
#
# Every field has a `doc`. That is not politeness: the registry serves these
# descriptions to anyone inspecting the schema, so this text becomes the
# documentation a future consumer of your stream actually reads.
#
# Note that optional fields are written as ["null", "string"] with a default of
# null. Avro unions must list the default's type FIRST, and a field without a
# default cannot be added later without breaking backward compatibility.
# ---------------------------------------------------------------------------
EVENT_ENVELOPE_SCHEMA: dict[str, Any] = {
    "type": "record",
    "name": "Event",
    "namespace": "ch.aegis.raw",
    "doc": (
        "The standard AEGIS envelope. Carries provenance and timing for one "
        "observation; the source's own data rides in `payload` as JSON."
    ),
    "fields": [
        {
            "name": "event_id",
            "type": "string",
            "doc": "UUIDv7 with a monotonic counter. Time-ordered, and the key "
            "we deduplicate on downstream.",
        },
        {
            "name": "source",
            "type": "string",
            "doc": "Which system produced this: urlhaus, cisa_kev, feodo, tor_exit, cowrie.",
        },
        {
            "name": "event_type",
            "type": "string",
            "doc": "What kind of thing this describes: ioc.url, ioc.ip, "
            "vuln.cve, network.tor_exit, session.ssh.",
        },
        {
            "name": "schema_version",
            "type": "int",
            "default": 1,
            "doc": "Version of the PAYLOAD shape for this source. Distinct from "
            "the Avro schema version of this envelope.",
        },
        {
            "name": "occurred_at",
            # logicalType tells any reader that this long is a timestamp, not
            # an arbitrary number. Avro stores it as microseconds since epoch:
            # compact, timezone-free by definition (always UTC), and directly
            # convertible to a real timestamp column in Iceberg later.
            "type": {"type": "long", "logicalType": "timestamp-micros"},
            "doc": "When the event happened in the real world (UTC). Drives "
            "correctness: which day this belongs to.",
        },
        {
            "name": "ingested_at",
            "type": {"type": "long", "logicalType": "timestamp-micros"},
            "doc": "When AEGIS first observed it (UTC). Drives operations: "
            "whether the pipeline is falling behind.",
        },
        {
            "name": "payload",
            "type": "string",
            "doc": "The source's own record, JSON-encoded, byte-for-byte as "
            "received. Never cleaned or reshaped before this point.",
        },
        {
            "name": "content_hash",
            "type": "string",
            "doc": "SHA-256 of the canonicalised payload. Distinguishes 'we saw "
            "this again' from 'this changed'.",
        },
        {
            "name": "collector_run_id",
            "type": ["null", "string"],
            "default": None,
            "doc": "Links the event to the collector run that produced it, so a "
            "bad batch can be traced and replayed.",
        },
        {
            "name": "collector_host",
            "type": ["null", "string"],
            "default": None,
            "doc": "Machine that performed the collection.",
        },
    ],
}


# ---------------------------------------------------------------------------
# The dead-letter schema.
#
# A failed record must be preserved with enough context to diagnose AND replay
# it. That means the ORIGINAL BYTES, not a parsed version - because if parsing
# is what failed, a parsed copy is exactly the thing we cannot trust.
# ---------------------------------------------------------------------------
DEAD_LETTER_SCHEMA: dict[str, Any] = {
    "type": "record",
    "name": "DeadLetter",
    "namespace": "ch.aegis.dlq",
    "doc": "A record that could not be processed, kept with the reason it failed.",
    "fields": [
        {"name": "dlq_id", "type": "string", "doc": "UUIDv7 of this failure record."},
        {
            "name": "failed_at",
            "type": {"type": "long", "logicalType": "timestamp-micros"},
            "doc": "When the failure occurred (UTC).",
        },
        {
            "name": "stage",
            "type": "string",
            "doc": "Where it failed: parse, validate, serialize, produce, consume.",
        },
        {
            "name": "source",
            "type": ["null", "string"],
            "default": None,
            "doc": "Which feed the record came from, when that is known. Null "
            "when the failure happened before the source could be determined.",
        },
        {
            "name": "original_topic",
            "type": ["null", "string"],
            "default": None,
            "doc": "Topic it was headed for, or came from. This is what a replay "
            "job reads to know where to put the record once it is fixed.",
        },
        {
            "name": "error_type",
            "type": "string",
            "doc": "Exception class name - the field you group by on a dashboard.",
        },
        {"name": "error_message", "type": "string", "doc": "Human-readable detail."},
        {
            "name": "raw_payload",
            "type": "string",
            "doc": "The original content, unmodified. This is what makes replay "
            "possible once the bug is fixed.",
        },
        {
            "name": "retry_count",
            "type": "int",
            "default": 0,
            "doc": "How many times this record has already been retried.",
        },
    ],
}


# The Schema Registry names schemas by SUBJECT. The default convention is
# "<topic>-value" for the message body and "<topic>-key" for the key. Sticking
# to the convention means standard tooling (Console, Connect, ksqlDB) finds our
# schemas without configuration.
def subject_for(topic: str) -> str:
    """Registry subject name for a topic's message value."""
    return f"{topic}-value"


def event_to_avro_dict(event: Event) -> dict[str, Any]:
    """Convert an Event into the dict shape the Avro serialiser expects.

    Two conversions matter here:

    * `payload` becomes a JSON string. `sort_keys=True` keeps it canonical so
      the same content always produces identical bytes - which is what makes
      content_hash meaningful.
    * datetimes are passed as datetime objects; the Avro serialiser converts
      them to microseconds using the logicalType. We must NOT convert them
      ourselves, or they would be encoded twice.
    """
    return {
        "event_id": event.event_id,
        "source": event.source.value,
        "event_type": event.event_type.value,
        "schema_version": event.schema_version,
        "occurred_at": event.occurred_at,
        "ingested_at": event.ingested_at,
        "payload": json.dumps(event.payload, sort_keys=True, separators=(",", ":"), default=str),
        "content_hash": event.content_hash,
        "collector_run_id": event.collector_run_id,
        "collector_host": event.collector_host,
    }
