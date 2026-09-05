# ADR 0004 — FULL schema compatibility, not the default BACKWARD

- **Status:** Accepted
- **Date:** 2026-09-05

## Context

Every event AEGIS produces is Avro-encoded against a schema stored in the
Schema Registry. The registry enforces a *compatibility level*, which decides
which schema changes it will accept:

| Level | Question it asks | Permits |
|---|---|---|
| `BACKWARD` (default) | Can a **new** reader read **old** data? | Deleting a field; adding one **with** a default |
| `FORWARD` | Can an **old** reader read **new** data? | Adding a field; deleting one **with** a default |
| `FULL` | Both of the above | Adding or deleting **only with** a default |
| `NONE` | — | Anything |

The registry defaults to `BACKWARD`, and that default was in force when this
project's first schema was registered.

We discovered the problem by writing a demonstration script that tried to
register a deliberately breaking change and asserted it would be refused. The
registry **accepted it**. The script was wrong about Avro's semantics, and the
registry was right: under `BACKWARD`, deleting a field is legal, because a new
reader that no longer knows about the field simply ignores it.

That is a correct answer to the wrong question for this system. AEGIS does not
deploy its producers and consumers together. The Bronze writer, the real-time
dashboard and the anomaly scorer are separate long-lived processes, released on
different schedules. The dangerous sequence under `BACKWARD` is:

1. A producer is updated to drop a field, and the registry allows it.
2. The producer ships. New messages no longer carry the field.
3. Consumers have **not** been redeployed. They still expect it.
4. Avro fills the missing field in as absent. **Nothing raises.** The consumer
   keeps running and silently computes on incomplete data.

Silent wrong data is precisely the failure the schema was introduced to prevent.

## Decision

Set the Schema Registry's global compatibility level to **`FULL`**, applied
idempotently by `aegis.streaming.admin.ensure_compatibility()` and invoked
automatically by `aegis topics create`, so it is reproducible on an empty
broker rather than configured by hand once and forgotten.

Under `FULL`, a field may only be added or removed if it declares a default.
Consequently **every optional field in every AEGIS schema declares a default**,
and a unit test enforces that rule so it cannot quietly decay.

## Consequences

**Positive**

- Producers and consumers can be deployed in either order, safely. That is the
  actual operational property we need, and it is now guaranteed rather than
  hoped for.
- Breaking changes fail at registration time — in CI, on the author's screen —
  instead of manifesting as wrong numbers on a dashboard weeks later.
- It forces a habit that pays off far beyond Kafka: every field is either
  required from the start or has a defined default forever.

**Negative**

- `FULL` is genuinely stricter, and it will sometimes block a change that feels
  obviously safe. Removing a field that provably nobody reads still requires a
  two-step migration: first give it a default, deploy, then remove it.
- That inconvenience is the point. The cost of the friction is a few minutes;
  the cost of a silent schema break is weeks of wrong data and the loss of
  trust in the platform that follows.

**Neutral**

- Set globally rather than per-subject. Per-subject levels are available and
  would allow relaxing the rule for a genuinely internal topic, but a single
  global rule is easier to reason about and harder to erode one exception at a
  time.

## Alternatives considered

- **Keep `BACKWARD`** — rejected: it does not protect the deployment ordering
  this system actually has.
- **`FORWARD`** — rejected: it protects old consumers reading new data but
  permits adding a required field, which breaks replay of historical messages.
  Replay is a core capability here, so this is unacceptable.
- **`NONE`, with discipline** — rejected: "we will simply remember not to do
  that" is not a control. The registry is the only place the rule can be
  enforced mechanically, which is the only kind of enforcement that survives a
  deadline.
- **`FULL_TRANSITIVE`** — genuinely tempting. It checks a new schema against
  *every* previous version, not just the most recent one, which matters because
  our retention is up to 90 days and a consumer may replay across several
  schema generations. Deferred rather than dismissed: revisit in Phase 5, when
  the first real schema evolution happens and there is more than one prior
  version for the check to be meaningful against.

## Notes

The error in the original demonstration script is preserved in
`scripts/demo_contracts.py`, which now shows the same change being accepted
under `BACKWARD` and refused under `FULL`. A mistake that produced a better
design is worth keeping visible rather than tidying away.
