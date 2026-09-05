# AEGIS — Architecture

This document explains *how the system works*. For *why each technology was
chosen*, see the [ADRs](adr/).

---

## 1. The governing principle: raw data is sacred

Every design choice below follows from one rule:

> **The system must be able to reproduce any downstream table from scratch,
> from data it already has, without contacting a source again.**

This matters because threat-intelligence sources are ephemeral. URLhaus prunes
entries. A honeypot session happens once. If a parsing bug corrupts a table and
the only copy of the truth was the source, the data is gone permanently.

So AEGIS never transforms data in flight before persisting it. The raw payload
is written to the Bronze layer exactly as received, and every transformation is
a *derivation* that can be deleted and rebuilt. This is what "replayable
pipeline" actually means, and it is the difference between a pipeline and a
script.

---

## 2. Data flow

```
 SOURCE            TRANSPORT              STORAGE                 CONSUMPTION
 ------            ---------              -------                 -----------
 collector  ──►  Kafka topic  ──►  Bronze (Iceberg)  ──►  Silver ──►  Gold
    │               │                    │                  │          │
    │               ├─► DLQ topic        │                  │          ├─► dbt tests
    │               │   (bad records)    │                  │          ├─► ML features
    └─ watermark    └─► Console UI       └─ time travel      └─ SCD2   └─► API / dashboard
       (Postgres)                           snapshots
```

### Stage 1 — Collection (`src/aegis/sources/`)

Each source is a small, independent collector with three responsibilities:

1. **Fetch** with retry, backoff and a timeout (`tenacity` + `httpx`).
2. **Emit** every record to a Kafka topic, unmodified, with envelope metadata.
3. **Record a watermark** in `ops.ingestion_watermark` so the next run resumes.

Collectors never write to the lakehouse directly. They only produce events.
That single constraint is what allows a new consumer to be added later without
touching any collector.

### Stage 2 — Transport (`src/aegis/streaming/`)

Kafka provides four properties nothing else in the stack does:

| Property | What it buys us |
|---|---|
| **Durability** | An event survives a consumer crash |
| **Replay** | Reset an offset to rebuild Bronze from the log |
| **Fan-out** | The Bronze writer, the live dashboard and the scorer read independently |
| **Back-pressure isolation** | A slow writer cannot stall a collector |

Every message carries a standard envelope so that provenance is never lost:

```json
{
  "event_id":     "uuid-v7, time-ordered and unique",
  "source":       "urlhaus | nvd | cisa_kev | cowrie | tor_exit",
  "event_type":   "ioc.url | vuln.cve | session.ssh",
  "occurred_at":  "when the event happened in the real world (UTC)",
  "ingested_at":  "when AEGIS first saw it (UTC)",
  "schema_version": 1,
  "payload":      { "...": "the source's own structure, untouched" }
}
```

The distinction between `occurred_at` and `ingested_at` is the single most
important field pair in the system. **Event time** drives correctness (which
day does this attack belong to?); **ingestion time** drives operations (is the
pipeline falling behind?). Conflating them is the root cause of most late-data
bugs in data engineering.

### Stage 3 — Bronze (`src/aegis/lakehouse/`)

An append-only Iceberg table per event type, partitioned by ingestion day.
Nothing is validated, deduplicated or corrected here. Iceberg gives us:

- **Snapshot isolation** — readers never see a half-written commit
- **Time travel** — `SELECT ... FOR VERSION AS OF <snapshot>` to reproduce a
  past state exactly, which is how a data incident is actually investigated
- **Schema evolution** — a source adding a field does not break the table
- **Hidden partitioning** — queries do not need to know the partition scheme

### Stage 4 — Silver

Validated, typed, deduplicated, enriched. One row = one real-world event.
This is where:

- Records failing their schema contract are routed to **quarantine**, never
  dropped silently — a spike in rejections is itself a detection signal
- IP addresses are enriched with ASN, country and Tor-exit status
- Attacker IPs are **pseudonymised** (Phase 8) because under the GDPR an IP
  address is personal data, even an attacker's
- Deduplication happens on `event_id`, making the whole pipeline idempotent:
  replaying the same Kafka range produces an identical table

### Stage 5 — Gold

Dimensional models answering questions directly:

| Model | Grain | Answers |
|---|---|---|
| `fct_attack_session` | one honeypot session | What did this attacker actually do? |
| `dim_attacker` | one source IP (SCD2) | How has this actor's behaviour changed? |
| `dim_credential` | one username/password pair | Which credentials are being sprayed? |
| `fct_ioc_match` | one enrichment hit | Which attackers appear in public feeds? |
| `agg_threat_daily` | one day | Is the threat level rising? |

---

## 3. Idempotency: the property everything depends on

A pipeline that cannot be safely re-run is a pipeline that cannot be operated.
AEGIS achieves end-to-end idempotency in four places:

| Layer | Mechanism |
|---|---|
| Collector | Watermark in `ops.ingestion_watermark` + content hashing |
| Producer | `enable.idempotence=true` — the broker de-duplicates retries |
| Consumer | Offsets committed **after** the downstream write succeeds, never before |
| Silver | `MERGE`/deduplicate on `event_id`, so a replay overwrites rather than appends |

Consumer offset ordering deserves emphasis. The default `enable.auto.commit=true`
commits offsets on a timer, *before* your code has finished with the message.
A crash then loses everything between the last commit and the failure — silently.
`aegis.config.KafkaSettings.consumer_config` disables it globally so no consumer
in this project can make that mistake.

---

## 4. Failure handling

| Failure | Response |
|---|---|
| Source API is down | Retry with exponential backoff + jitter; mark watermark `failed`; alert on staleness |
| Malformed record | Route to the dead-letter topic with the error and the raw bytes attached |
| Schema violation | Quarantine bucket; the run continues; the rejection rate becomes a monitored metric |
| Consumer crash mid-batch | Offsets were not committed, so the batch is re-read; idempotent writes make the retry safe |
| Duplicate event | Deduplicated on `event_id` in Silver |
| Late-arriving data | Partitioned on event time, so a late record lands in its correct day and only that partition is rebuilt |

The consistent theme: **fail loudly, quarantine rather than drop, and make
every retry safe.**

---

## 5. Environments

| Concern | Local (now) | Cloud (Phase 9) |
|---|---|---|
| Broker | Redpanda container | AWS MSK / Azure Event Hubs (Kafka API) |
| Object storage | MinIO | AWS S3 |
| Catalogue | Postgres `SqlCatalog` | AWS Glue / Iceberg REST |
| Compute | DuckDB + Polars on the host | Same, on Fargate; EMR Serverless for large backfills |
| Orchestration | Dagster local | Dagster on ECS |
| Secrets | `.env` (git-ignored) | AWS Secrets Manager via OIDC — no static keys |

Because every layer is addressed through configuration rather than hard-coded
clients, this table is a list of environment variables, not a rewrite.
