# ADR 0005 — Kafka message timestamps carry ingestion time, not event time

- **Status:** Accepted
- **Date:** 2026-09-13
- **Cost of learning this:** 45,233 silently deleted records

## Context

Phase 1 established the distinction the whole platform rests on:

- **`occurred_at`** — when the thing happened in the real world. Drives correctness.
- **`ingested_at`** — when AEGIS first saw it. Drives operations.

Phase 2's producer then set Kafka's own message timestamp from `occurred_at`,
reasoning that the message should describe the event it carries. The comment in
the code at the time said so explicitly, and it sounded right.

It was wrong, because **Kafka's message timestamp is not metadata — it is an
input to retention.** With the default `message.timestamp.type=CreateTime`, the
broker trusts the producer's value and uses it to decide when a log segment has
aged out.

The consequences compound badly with our sources:

| Feed | Age of `occurred_at` on arrival | Topic retention | Result |
|---|---|---|---|
| URLhaus | up to 30 days | 7 days | Most records expired **on write** |
| CISA KEV | back to 2021 | 90 days | Records dated 2021 expired immediately |
| Feodo | back to 2022 | 90 days | Same |

Nothing errored. The producer reported 45,233 messages produced and 45,233
delivered. The broker acknowledged every one. They were then deleted before any
consumer read them, and only surfaced a week later when the Bronze writer
reported `rows_read=0` against a topic that should have held tens of thousands
of records.

The three partition watermarks told the story precisely:

```
PARTITION  LOG-START-OFFSET  HIGH-WATERMARK
0                     14766           14766
1                     15297           15297
2                     15170           15170
```

Start equals end on every partition: 45,233 messages had been written, and all
45,233 had been deleted.

## Decision

**Two changes, deliberately redundant.**

1. **The producer sends `ingested_at`.** Event time is not lost — it rides in
   `occurred_at` inside the payload, which is where a consumer should read it
   from anyway.

2. **Every topic sets `message.timestamp.type=LogAppendTime`.** The broker
   overwrites whatever timestamp a producer supplies with its own clock on
   arrival.

Change 1 alone would have been sufficient for *our* code. Change 2 is what makes
the bug unrepeatable: a future producer, a colleague's script, or a Kafka
Connect job cannot reintroduce it, because the broker no longer listens.

Change 2 also required building `aegis topics apply`, because Kafka does not
reconcile the configuration of topics that already exist — see Consequences.

## Consequences

**Positive**

- Retention now means what the declaration says: N days from when we received
  the data.
- The general rule this establishes: **a transport layer's clock describes the
  transport, not the cargo.** Kafka's timestamp answers "when did this arrive";
  the payload answers "when did this happen". Conflating them lets an
  operational concern silently corrupt an analytical one.
- It forced a genuinely useful capability into existence. Fixing the
  declaration in `topics.py` changed nothing on the running broker, because
  `create_topics` only configures topics it creates. That gap — configuration
  drift — now has an explicit reconciler, `aegis topics apply`, modelled on
  `terraform plan` / `terraform apply`.

**Negative**

- Kafka's time-based lookups (`offsets_for_times`) now answer "what arrived
  around 14:00" rather than "what happened around 14:00". That is the correct
  semantics for a log, but it means event-time queries must go through the
  lakehouse, not through Kafka. Given that the lakehouse exists precisely to
  answer event-time questions, the cost is theoretical.
- `LogAppendTime` discards the producer's timestamp entirely. If a producer
  ever had a legitimate reason to set it — for example replaying a historical
  archive while preserving original arrival times — that is now impossible on
  these topics. Judged worth it: the failure mode it prevents is silent, and
  the capability it removes has no current use.

**Neutral**

- The 45,233 lost records could not be recovered. URLhaus publishes a rolling
  window, so re-collection returned 12,710 different records rather than the
  same ones. This is itself the argument for the Bronze layer: had those
  records reached Iceberg, the Kafka expiry would have been irrelevant.

## Alternatives considered

- **Extend URLhaus retention to 30+ days** — rejected. It treats the symptom.
  Retention would still have been measured from the wrong clock, and CISA
  records dated 2021 would have expired under any finite retention.
- **Set `message.timestamp.difference.max.ms` to reject old timestamps** — the
  original code did set this, to 7 days, and it did not help. Redpanda accepted
  the messages regardless. Relying on a broker to reject bad input is weaker
  than not sending it.
- **`LogAppendTime` only, without fixing the producer** — rejected. It would
  work, but it would leave code in the repository that reads as though event
  time belongs in that field, waiting for someone to copy it into a context
  where the broker setting is different.

## How this is prevented from recurring

Two unit tests in `tests/test_lakehouse.py`, both of which run in milliseconds
and need no infrastructure:

- `test_kafka_message_timestamp_uses_ingestion_time` reads the producer source
  and fails if `occurred_at` reappears in the `timestamp=` argument.
- `test_topics_force_broker_side_timestamps` asserts every topic declares
  `LogAppendTime`.

Asserting on source text is unusual and slightly crude. It is justified here
because the correct alternative — a live broker, a 7-day wait, and an
observation that data vanished — is not a test anyone would run.
