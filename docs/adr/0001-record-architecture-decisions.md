# ADR 0001 — Record architecture decisions

- **Status:** Accepted
- **Date:** 2026-09-05

## Context

The most valuable part of an engineering project is rarely the code — it is the
reasoning that produced the code. Six months later, neither the author nor a
reviewer can reconstruct *why* a stack was chosen, which alternatives were
weighed, or what the choice cost. In an interview, "I used Kafka" is a fact;
"I chose Redpanda over Kafka because I measured a 9× memory difference and the
API is identical, accepting weaker multi-datacentre replication which this
workload does not need" is evidence of engineering judgement.

## Decision

Every significant technical decision in AEGIS is recorded as a short Markdown
file in `docs/adr/`, numbered sequentially, using the format below:

- **Context** — the forces at play, including constraints and measurements
- **Decision** — what was chosen, stated in the active voice
- **Consequences** — what this makes easy, what it makes hard, what it costs
- **Alternatives considered** — and the specific reason each was rejected

A decision is "significant" if reversing it later would require changing more
than one module, or if a reviewer would reasonably ask "why did you do that?".

ADRs are immutable. When a decision is revisited, a *new* ADR supersedes the
old one and the old one is marked `Superseded by ADR-XXXX`. The history of
being wrong is as instructive as the current state.

## Consequences

**Positive**

- The repository explains itself without the author present.
- Reviewers can challenge the reasoning rather than guessing at it.
- Onboarding cost drops sharply.

**Negative**

- Roughly 15 minutes of writing per significant decision.
- A discipline that decays without deliberate effort; ADRs that stop being
  written are worse than none, because they imply nothing important happened.

## Alternatives considered

- **A single `DECISIONS.md`** — rejected: it grows unreadable and invites
  editing history rather than appending to it.
- **Wiki pages** — rejected: decisions must be versioned *with* the code they
  describe, and reviewed in the same pull request.
- **Nothing** — rejected: this is the default, and it is the reason most
  portfolio projects cannot be defended under questioning.
