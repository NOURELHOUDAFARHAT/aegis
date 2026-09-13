"""Topic definitions, declared as code.

WHAT A TOPIC IS
---------------
A topic is a named, append-only log. Producers add records to the end;
consumers read forward from wherever they left off. Nothing is deleted when it
is read - a record stays until its retention period expires. That is what makes
replay possible, and replay is the reason we put Kafka in the middle at all.

Each topic is split into PARTITIONS. A partition is the unit of ordering and of
parallelism:

  * Kafka guarantees order WITHIN a partition, and makes no promise across them.
  * Only one consumer in a group reads a given partition at a time, so a topic
    with 3 partitions can be processed by at most 3 consumers in parallel.

Those two facts drive every decision in this file.

WHY DECLARE TOPICS IN CODE
--------------------------
You can create a topic by clicking in a UI, or by letting a producer create one
automatically on first write. Both are traps. Auto-created topics get the
broker's defaults - usually one partition and a week of retention - and you
discover this months later when you cannot scale a consumer without recreating
the topic and losing its history. Declaring them here means the settings are
reviewed, versioned, and reproducible on an empty broker.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from aegis.sources.models import Source

# Every topic we own starts with this prefix. A shared cluster usually hosts
# many teams, and a prefix is what stops "events" from meaning six things.
PREFIX = "aegis"

# Locally we have a single broker, so a partition can only exist in one copy.
# In AWS MSK or any real cluster this becomes 3, so the loss of one broker
# costs nothing. It is called out as a constant rather than hard-coded so the
# difference between local and production is one obvious line.
LOCAL_REPLICATION_FACTOR = 1


@dataclass(frozen=True)
class TopicSpec:
    """Everything we decide about one topic."""

    name: str
    partitions: int
    retention_hours: int
    description: str
    # Extra broker-level settings, merged over the defaults below.
    config: dict[str, str] = field(default_factory=dict)

    def broker_config(self) -> dict[str, str]:
        base = {
            # How long records stay before the broker deletes them.
            "retention.ms": str(self.retention_hours * 3_600_000),
            # "delete" = drop old records once retention expires. The other
            # option, "compact", keeps only the newest record per key forever.
            # Raw event streams want delete: we care about every observation,
            # not just the latest state of each key.
            "cleanup.policy": "delete",
            # The broker stores exactly what the producer sent. Our producer
            # already compresses with zstd, so re-compressing here would waste
            # CPU for nothing.
            "compression.type": "producer",
            # Roll to a new log segment daily. Retention can only delete whole
            # segments, so huge segments mean data outliving its retention.
            "segment.ms": str(24 * 3_600_000),
            # ---------------------------------------------------------------
            # THE BROKER STAMPS THE TIME, NOT THE PRODUCER.
            #
            # The default is `CreateTime`, which trusts whatever timestamp the
            # producer supplies - and the broker then uses that value to decide
            # when a segment has aged out of retention.
            #
            # This project learned what that costs. An early producer set the
            # message timestamp from the event's own `occurred_at`. URLhaus
            # publishes a rolling 30-day window, so on a 7-day-retention topic
            # most records were expired the moment they were written. 45,233
            # messages were accepted, acknowledged, and silently deleted before
            # any consumer read them. See docs/adr/0005.
            #
            # `LogAppendTime` makes the broker overwrite the timestamp with its
            # own clock on arrival. Retention then means what it says: N days
            # from when we RECEIVED the data. The producer was fixed too, but
            # this setting is what makes the bug unrepeatable - a future
            # producer, or a colleague's script, cannot reintroduce it.
            #
            # The trade-off is real: Kafka's time-based lookups now answer
            # "what arrived around 14:00", not "what happened around 14:00".
            # That is the correct meaning for a transport layer. Event time
            # lives in `occurred_at` in the payload, where analysis reads it.
            # ---------------------------------------------------------------
            "message.timestamp.type": "LogAppendTime",
        }
        base.update(self.config)
        return base


# ---------------------------------------------------------------------------
# ONE TOPIC PER SOURCE
#
# The alternative was one topic per event TYPE (all IOCs together, whatever
# produced them). Per-source wins here for three reasons:
#
#   1. Replay is naturally per-source. "Re-read everything URLhaus sent last
#      week" is a real operation; "re-read all IOCs but only the URLhaus ones"
#      means reading and discarding the rest.
#   2. Volume differs by three orders of magnitude. URLhaus sends ~15,000
#      records a run; Feodo sends five. Shared retention and partitioning
#      would be wrong for one of them whatever we chose.
#   3. A broken parser is contained. If the URLhaus format changes and its
#      topic fills with rejects, the CVE stream is unaffected.
#
# The cost: a consumer wanting "every IOC" must subscribe to several topics.
# Kafka supports that directly, including by regular expression, so the cost
# is small and the isolation is worth it.
# ---------------------------------------------------------------------------
TOPICS: dict[str, TopicSpec] = {
    Source.URLHAUS.value: TopicSpec(
        name=f"{PREFIX}.raw.urlhaus",
        # 3 partitions: the only high-volume feed, so it is the only one that
        # could ever need parallel consumers. Note that partitions can be ADDED
        # later but never removed, and adding them changes which partition a
        # key lands in - so pick with the next year in mind, not the next week.
        partitions=3,
        retention_hours=24 * 7,
        description="Malicious URLs from abuse.ch URLhaus",
    ),
    Source.CISA_KEV.value: TopicSpec(
        name=f"{PREFIX}.raw.cisa_kev",
        partitions=1,
        # 90 days: this is reference data that changes slowly and is small.
        # Long retention here costs almost nothing and makes historical
        # rebuilds trivial.
        retention_hours=24 * 90,
        description="Vulnerabilities under active exploitation (CISA KEV)",
    ),
    Source.FEODO.value: TopicSpec(
        name=f"{PREFIX}.raw.feodo",
        partitions=1,
        retention_hours=24 * 90,
        description="Botnet command-and-control servers (Feodo Tracker)",
    ),
    Source.TOR_EXIT.value: TopicSpec(
        name=f"{PREFIX}.raw.tor_exit",
        partitions=1,
        retention_hours=24 * 30,
        description="Current Tor exit-node addresses",
    ),
    Source.COWRIE.value: TopicSpec(
        name=f"{PREFIX}.raw.cowrie",
        partitions=3,
        retention_hours=24 * 30,
        description="Live honeypot SSH/Telnet sessions",
    ),
}

# ---------------------------------------------------------------------------
# THE DEAD-LETTER TOPIC
#
# When a record cannot be processed - it fails validation, it will not
# serialise, the payload is corrupt - there are three possible responses:
#
#   1. Crash the pipeline.  One bad record stops everything. Unacceptable.
#   2. Drop it silently.    The pipeline looks healthy while losing data.
#                           This is the worst option and the most common one.
#   3. Send it here.        The pipeline keeps running, and the bad record is
#                           preserved with the reason it failed attached.
#
# Option 3 is the only professional answer. A dead-letter topic turns "we lost
# some data, we think" into "here are the 47 records that failed, with their
# error messages, ready to replay once the parser is fixed".
#
# It also becomes a metric: a sudden spike in dead letters is usually the first
# sign that an upstream source changed its format.
# ---------------------------------------------------------------------------
DLQ_TOPIC = TopicSpec(
    name=f"{PREFIX}.dlq",
    partitions=1,
    # 30 days, deliberately longer than most source topics. You need time to
    # notice a problem, diagnose it, fix the code and replay - and that clock
    # starts when someone looks at a dashboard, not when the record failed.
    retention_hours=24 * 30,
    description="Records that failed validation or serialisation, with the reason",
)


def all_specs() -> list[TopicSpec]:
    """Every topic AEGIS owns, source topics plus the dead-letter topic."""
    return [*TOPICS.values(), DLQ_TOPIC]


def topic_for(source: Source | str) -> str:
    """Map a source to its topic name."""
    key = source.value if isinstance(source, Source) else source
    if key not in TOPICS:
        raise KeyError(f"No topic declared for source '{key}'. Add one in topics.py.")
    return TOPICS[key].name
