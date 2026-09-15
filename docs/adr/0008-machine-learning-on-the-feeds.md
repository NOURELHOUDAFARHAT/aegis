# ADR 0008 — Machine learning on the feeds

- **Status:** Accepted
- **Date:** 2026-09-14

## Context

Phase 6 was planned as "anomaly detection over honeypot sessions, plus a RAG
assistant". The data profile taken before writing any model changed that plan:

| Source | What exists |
|---|---|
| URLhaus (Silver) | 13,101 URLs on 5,295 hosts; 89.6% raw IPv4; 100% tagged |
| CISA KEV (Silver) | 1,709 CVEs, 283 vendors; 21.1% ransomware-linked; 89.8% with a CWE |
| Honeypot | **no real sessions** |

An anomaly detector trained on invented sessions would demonstrate nothing.
The machine constraint also still applies: 7.7 GB RAM, about 0.1 GB free.

## Decision

1. **Apply ML to the feeds that exist now. The honeypot becomes Phase 7**, and
   session anomaly detection goes with it. Later phases shift by one.
2. Build three models, each answering one analyst question, each evaluated in
   the way it will actually be used.
3. Keep everything local and free: scikit-learn, fastembed on ONNX Runtime, and
   mlflow-skinny. No PyTorch, no API keys, no vector database server.

### Models

| Asset | Method | Output table |
|---|---|---|
| `ml/url_campaigns` | Binary TF-IDF over `path=`, `tag=` and `port=` tokens, then DBSCAN with cosine distance (eps 0.35, at least 5 servers) | `ml.url_campaigns`, `ml.url_campaign_servers` |
| `ml/kev_ransomware_scores` | TF-IDF (1-2 grams) plus logistic regression with balanced classes; scores produced out-of-fold | `ml.kev_ransomware_scores` |
| `ml/cve_embeddings` | BAAI/bge-small-en-v1.5, 384 dimensions, cosine similarity; only new or changed CVEs re-embedded (text hash plus model name) | `ml.cve_embeddings` |

### Evaluations, and what each one showed

**Campaigns: validated against something the model never sees.** IP addresses
are not features. Servers in the same campaign nonetheless share a /24 subnet
8.6% of the time, against 0.1% for random pairs, a **131x lift**. Result: 66
campaigns covering 503 of 5,295 servers (9.5%). The largest are a Mirai kit
(23 servers, 350 URLs), ScreenConnect installers (20) and a PowerShell
`crypted.ps1` loader (17). Low coverage is deliberate: DBSCAN leaves a server
unassigned instead of forcing it into the nearest group.

**Ransomware: a random split inflates the score.**

| Evaluation | PR-AUC |
|---|---:|
| Shuffled 5-fold cross-validation | 0.498 |
| **Time split** (train before 2025-01-01, test after; 1,239 / 470) | **0.282** |
| Chance (test prevalence) | 0.121 |

The time split is the honest number: 2.3x chance, ROC-AUC 0.739. Two further
checks:

- **Label lag.** 23-27% of CVEs added in 2021-2024 are ransomware-linked, but
  12.7% in 2025 and 11.6% in 2026, because CISA adds the flag later. Recent
  high scores that are not yet linked are published as a **watch list**, not
  as errors.
- **Leakage.** Only 0.1% of descriptions contain "ransom", so the model is not
  simply reading the answer.

**Search: the first comparison was biased and was redone.** The first run
reported keyword search ahead of semantic search. Two of its "paraphrased"
questions shared words with the rule defining the correct answers. The redone
evaluation (`scripts/eval_search.py`) fails if any paraphrase shares a word
with its answer rule:

| Precision@5 | Keyword | Semantic | Hybrid (RRF) |
|---|---:|---:|---:|
| Keyword control (1 question) | 0.80 | 0.80 | 0.80 |
| 7 true paraphrases | 0.14 | **0.46** | 0.23 |

**Hybrid search is rejected.** On paraphrases the keyword ranking is mostly
noise, and reciprocal rank fusion weights it equally. Two questions defeated
every method (file transfer tools, help-desk remote access). Seven questions is
a small sample.

Cost measured on this machine: a 65 MB model, 517 MB peak memory, 132 s to
embed all 1,709 CVEs, 4 s when nothing changed, 32-43 ms per query, 2.6 MB of
vectors.

### Orchestration

- The three models are Dagster assets downstream of Silver. The `refresh_ml`
  job rebuilds them without collection or dbt.
- **One writer on the warehouse.** dbt and the ML assets share the pool
  `duckdb_warehouse`; `dagster.yaml` sets `concurrency.pools.default_limit: 1`.
  This was tested both ways. Without the limit, the three steps started
  together and two failed with DuckDB's file lock. With it, the log shows
  "Step blocked by limit for pool duckdb_warehouse", the steps run in turn,
  and the run succeeds.
- **Decay checks.** `campaigns_align_with_subnets` (lift at least 2x) and
  `ransomware_beats_chance` (at least 1.5x) are warnings;
  `every_cve_is_searchable` is an error. A model that keeps running but stops
  meaning anything produces no failure otherwise.
- Every materialisation records its `mlflow_run_id`, linking the Dagster run to
  the MLflow run.

### Ownership of the warehouse

dbt owns `staging`, `silver` and `gold`. Python owns `ml`. dbt never writes to
`ml`, and the ML code only reads Silver. Each side can be rebuilt without the
other.

## Two implementation traps

**PyArrow and ONNX Runtime on Windows.** `import pyarrow` followed by
`import onnxruntime` failed with "DLL load failed". PyArrow bundles
`msvcp140.dll` 14.28, System32 has 14.40, and the first copy loaded wins for
the process. `aegis/__init__.py` now preloads the system runtime, but only when
it is at least as new as PyArrow's. It never raises, and reports what it did in
`aegis.MSVC_RUNTIME_STATUS`. A test starts a fresh interpreter to prove the
order that used to fail now works. If PyArrow was already imported, the fix
cannot apply, and the embedding asset fails with that explanation instead of a
DLL error.

**mlflow-skinny cannot `log_model` without pandas.** Models are saved with
joblib and logged as plain artifacts. Tracking uses SQLite under
`$AEGIS_DATA_DIR/mlflow` with an explicit artifact location, so no `mlruns/`
folder appears in the repository.

## Consequences

- Positive: every published number has an evaluation behind it, and the
  weaker results (9.5% coverage, PR-AUC 0.28, hybrid search) are stated, not
  hidden.
- Positive: the whole phase costs nothing to run and needs no network after
  the one model download.
- Negative: the ransomware watch list inherits label lag. Its precision can
  only be judged months later.
- Negative: search quality rests on seven questions. Growing that set is cheap
  and is the next thing to do before tuning anything.
- Negative: honeypot anomaly detection is deferred to Phase 7.
