# ADR 0003 — Redpanda instead of Apache Kafka

- **Status:** Accepted
- **Date:** 2026-09-05

## Context

AEGIS needs a durable, replayable, partitioned event log between the collectors
and the lakehouse. That decoupling is not decoration:

- A collector must not block because the lakehouse writer is slow.
- A parsing bug must be fixable by **replaying** events, not by re-downloading
  feeds that may have already rotated their content.
- Multiple consumers (Bronze writer, real-time dashboard, anomaly scorer) must
  read the same stream independently, at their own pace.

The industry-standard answer is Apache Kafka. Its practical footprint, however,
is roughly 1.5–2 GB across the broker and its coordination layer, against a
total Docker allocation of 3.95 GB on the development machine.

## Decision

Use **Redpanda** as the broker.

Redpanda implements the Kafka wire protocol, so `confluent-kafka` — the same
librdkafka-based client used against Apache Kafka, MSK, and Confluent Cloud —
connects unchanged. It is a single C++ binary with no JVM and no ZooKeeper, and
it ships its own Schema Registry and HTTP proxy in the same process.

Measured footprint in this project: **220 MB resident** with `--smp=1
--memory=900M --overprovisioned`.

The critical property is that **this decision is reversible for free**. Nothing
in the application layer knows it is talking to Redpanda; `aegis.config`
produces a standard Kafka client configuration. Switching to AWS MSK in Phase 9
is a change to one environment variable.

## Consequences

**Positive**

- ~9× less memory, and no ZooKeeper/KRaft quorum to reason about.
- Schema Registry included, removing a separate container.
- Redpanda Console gives a genuinely good UI for inspecting topics, consumer
  lag and schemas — which shortens the feedback loop while learning streaming.
- The skill transfers: everything learned here about partitioning, consumer
  groups, offsets, delivery semantics and compaction is Kafka knowledge.

**Negative**

- Not Apache Kafka. Some employers screen for the literal word, so the CV entry
  must read "Kafka API (Redpanda)" and the reasoning must be defensible.
- The ecosystem of Kafka Connect connectors is less proven against Redpanda.
  AEGIS does not use Kafka Connect — collectors are plain Python producers,
  which is more instructive anyway.
- Tiered storage and multi-region replication differ from Kafka's model. Out of
  scope for this workload.

## Alternatives considered

- **Apache Kafka in KRaft mode** — rejected on memory alone; it is the right
  answer on a machine with 32 GB.
- **Redis Streams** — rejected: no real consumer-group replay semantics for our
  case, weaker durability guarantees, and the skill does not transfer.
- **NATS JetStream** — genuinely light and pleasant, but the Kafka API is the
  employable interface and the one most cloud services speak.
- **No broker: write Parquet straight from collectors** — rejected: this is the
  single most common beginner shortcut, and it destroys replayability. Once the
  raw event is gone, every downstream bug becomes permanent data loss.
