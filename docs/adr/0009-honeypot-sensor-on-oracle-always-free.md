# ADR 0009 — A honeypot sensor on Oracle Cloud Always Free

- **Status:** Accepted
- **Date:** 2026-09-15

## Context

Every source before Phase 7 is published by someone else. The honeypot is the
first data AEGIS observes first-hand: attackers connecting to a decoy SSH and
Telnet server. That has three consequences the feeds never had:

1. **It must be reachable from the internet.** A laptop behind a home router
   would mean port forwarding into a home network, exposing it to exactly the
   traffic being studied.
2. **It invites hostile people in.** The design must assume the sensor is
   attacked, and must stop it being used against anyone else.
3. **Its data arrives as a growing, rotating log file** on a remote machine,
   not a document on a web server.

Constraints: €0, and the development laptop has about 0.5 GB of RAM free.

## Decision

### Where it runs

An **Oracle Cloud Always Free** VM, created with Terraform
(`infra/honeypot/terraform`). A second option, replaying published honeypot
logs, was rejected because the data would be neither live nor this project's.

- **Shape.** `VM.Standard.A1.Flex` with 1 OCPU and 6 GB. Oracle halved the Always
  Free A1 allowance to 2 OCPUs and 12 GB on 15 June 2026. `VM.Standard.E2.1.Micro`
  is the fallback when A1 capacity is unavailable. Variable validation refuses
  any other shape, and caps CPU, memory and disk at the free allowance, so the
  configuration cannot create a billed VM.
- **Image.** The newest Ubuntu 24.04 for the chosen shape. Image updates are
  ignored after creation, so a new Oracle image never recreates the sensor and
  destroys uncollected logs.

### Network

| Port | Open to | Purpose |
|---|---|---|
| 22 | internet | Cowrie SSH |
| 23 | internet (if `enable_telnet`) | Cowrie Telnet |
| 22222 | `admin_cidr` only, validated as /24 or narrower | real SSH |

Outbound traffic is limited to TCP 80/443, NTP, and DNS to the VCN resolver.
SMTP, SSH and Telnet out are blocked, so the sensor cannot relay spam or
brute-force attacks even if Cowrie's forwarding were enabled.

Oracle's Ubuntu images also reject everything except port 22 in iptables, on
top of the security list. The bootstrap script edits `/etc/iptables/rules.v4`
directly rather than re-saving, because Docker is already running and a save
would persist Docker's own chains.

### Lock-out safety

Cowrie takes port 22, which is where real SSH listens at first boot. The
bootstrap switches Ubuntu 24.04 from `ssh.socket` (which listens on 22
regardless of `sshd_config`) to `ssh.service`, then **verifies** sshd is
listening on 22222 and nothing is left on 22. If either check fails, it exits
without starting Cowrie, and the VM stays reachable.

### Cowrie configuration

Pinned to `cowrie/cowrie:3.0.14`, published 2026-09-14 for amd64 and arm64.
Every default below was read from Cowrie's own `cowrie.cfg.dist`, not assumed:

| Setting | Cowrie default | AEGIS | Why |
|---|---|---|---|
| `ssh.forwarding` | `true` | `false` | attackers could tunnel through the sensor |
| `honeypot.download_limit_size` | `0` (unlimited) | 10 MB | one attacker could fill the disk |
| `honeypot.hostname` | `svr04` | a believable name | `svr04` is a known Cowrie fingerprint |
| `telnet.enabled` | `false` | `true` | Telnet is where IoT botnets recruit |

The container follows Cowrie's own compose file (read-only root filesystem, all
capabilities dropped, `no-new-privileges`), and adds memory and process limits.
Only the log directory is bind-mounted to the host.

### Getting logs out: a forced command, not a shell

AEGIS connects as a separate `aegis` user whose key is installed as
`restrict,command="/usr/local/bin/aegis-log-reader"`. The reader accepts two
requests, `list` and `read <inode> <offset>`, validates both with anchored
patterns, refuses symbolic links, and caps each read at 8 MiB. A stolen AEGIS
key can read attack logs and do nothing else.

The client uses the system OpenSSH binary (no Python SSH dependency), a
dedicated `known_hosts` file, and `StrictHostKeyChecking=accept-new`: trust on
first use, then any host-key change is refused. Terraform cannot know the key
before the VM exists, so trust-on-first-use is the honest option.

### Reading a rotating file exactly once

- **Files are tracked by inode, not name.** Cowrie's daily rotation renames
  `cowrie.json` to `cowrie.json.YYYY-MM-DD` (`CowrieDailyLogFile.suffix`, read in
  Cowrie's source). A rename keeps the inode, so the byte offset follows the
  file and nothing is read twice.
- **Only complete lines are consumed.** A half-written last line waits.
- **The cursor moves only after delivery is proven.** `flush()` returning is not
  enough, because the Kafka sink counts unacknowledged messages instead of
  raising. The collector checks `all_delivered` before saving the cursor.
- **Delivery is at-least-once.** A crash between sending and saving re-sends
  lines. Silver removes the copies on `content_hash`: a re-sent line has a
  byte-identical payload, but a new `event_id`.

### Kafka key: the session

Every Cowrie event is keyed by its `session`. The generic key function looked
for `session_id`, which Cowrie does not use, and checked `url` first, so a
download event would have landed on a different partition from its own
session. A test now pins this.

### Models

- `stg_cowrie`: one row per Bronze row, fields unpacked.
- `silver.honeypot_events`: deduplicated on `content_hash`; documentation IPs
  excluded.
- `silver.honeypot_sessions`: one row per session, as behaviours: login
  attempts, distinct passwords, whether it logged in, commands, downloads,
  client version, and `hassh`, a fingerprint of the SSH client's key-exchange
  choices that survives IP changes.

A full `dbt build` needs the Docker stack, which was down. The three models are
instead tested by running the real SQL files in DuckDB against synthetic Bronze
rows (`tests/test_honeypot_models.py`).

### Session anomaly detection

`ml/honeypot_session_anomalies`: an Isolation Forest over closed sessions. There
are no labels, so no precision is claimed. Instead:

- **Stability:** the mean Jaccard overlap of the top-k sessions across five seeds.
- **Explanations:** each flagged session names what makes it unusual.
- **Too little data:** below 200 closed sessions, nothing is scored or written.

### Dagster

- **Ingestion is registered only when `AEGIS_HONEYPOT_HOST` is set.** A failed
  step makes Dagster skip everything downstream, including the single dbt step
  that builds Silver and Gold for every feed. A sensor that was never built
  must not stop the pipeline.
- **`cowrie_has_rows` warns instead of blocking,** for the same reason: a quiet
  first few hours is not a broken collector.

## A trap found on the way: the frozen manifest

`ensure_manifest()` regenerated dbt's manifest only when it was missing. The
three new models were therefore absent from the Dagster graph, with no error,
until a test looked for `stg_cowrie`. The manifest is now rebuilt when any
model, macro, test or project file is newer than it.

## Verification

**Verified:**
- `terraform validate` passes against the OCI provider v9.1.
- The first-boot files were rendered through Terraform's `templatefile` for
  both Telnet settings, and 34 checks pass on them:
  - valid YAML
  - the reader script embedded byte for byte
  - `bash -n` on both scripts
  - the forced-command key line
  - the pinned image, disabled forwarding and container hardening
- The log reader was run in Git Bash against a real folder, and 18 checks pass:
  - `list` and `read`, byte for byte
  - eight malformed or hostile requests refused with exit 2
  - an unknown inode exits 3
  - the real `CowrieCollector` reads through the real script, including an append
- Unit tests pass for:
  - the collector: rotation, partial lines, unacknowledged delivery, limits
  - the Kafka key
  - the three dbt models
  - the session model
  - the Dagster wiring

**Not yet verified,** and not claimable until the VM exists:
- cloud-init and the bootstrap on a real Ubuntu 24.04 A1 instance, including
  the `ssh.socket` switch, the `rules.v4` edit, and the `docker-compose-v2`
  package
- Cowrie's environment-variable overrides taking effect in 3.0.14
- `terraform apply` itself, and Always Free A1 capacity in the chosen region
- anomaly results on real sessions

## Consequences

- **Positive:** AEGIS gains first-hand data, joinable with Feodo C2 servers and
  Tor exits by IP address.
- **Positive:** every security property in the table above is enforced by
  configuration and checked by a test or a render check, not left to good
  intentions.
- **Negative:** trust-on-first-use for the host key. The first connection must
  happen soon after `apply`, from a trusted network.
- **Negative:** attacker IPs are personal data under the GDPR. They are
  pseudonymised in Phase 9; until then they stay in the private lakehouse.
- **Negative:** the Always Free A1 allowance was halved once without notice and
  could change again.
