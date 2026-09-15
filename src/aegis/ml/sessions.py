"""Anomaly detection over honeypot attack sessions.

THE QUESTION
------------
Almost everything that reaches an internet-facing SSH port is automated and
repetitive: the same bots, the same password lists, then disconnect. Nobody can
read tens of thousands of those sessions. This model answers: which sessions do
not look like the rest, and why?

WHY AN ISOLATION FOREST
-----------------------
There are no labels - nobody has marked sessions as interesting - so this is
unsupervised. An Isolation Forest builds many random trees, each splitting the
data on a random feature at a random threshold. An unusual session is cut off
from the others in a few splits; an ordinary one, surrounded by similar
sessions, needs many. Fewer splits means a higher anomaly score. It assumes
nothing about what "normal" looks like, and it scores thousands of sessions in
well under a second.

HOW IT IS EVALUATED WITHOUT LABELS
----------------------------------
No precision can be claimed: there is no ground truth to compute it against.
Two honest measurements instead:

  * Stability. The model is retrained with five random seeds and the top of
    the ranking is compared (Jaccard overlap of the top-k sets). A ranking that
    reshuffles when only the seed changes is noise, however convincing it looks.
  * Explanations. Every flagged session names the features that make it
    unusual - "commands run 25 (typical 0)" - so an analyst can check the claim
    in seconds instead of trusting a score.

The unit tests plant obvious anomalies among synthetic sessions and check they
rank first. That proves the machinery works, not that real flags are useful:
real evaluation starts once the sensor has collected a few days of sessions.
"""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import duckdb
import numpy as np
import pyarrow as pa

# Below this, "unusual" has too little to be unusual against: with 50 sessions
# a single odd bot is 2% of the data. Scoring is skipped rather than published.
MIN_SESSIONS = 200

# The top 1% of scores are flagged for an analyst to look at.
FLAG_QUANTILE = 0.99

STABILITY_SEEDS = (0, 1, 2, 3, 4)
N_ESTIMATORS = 300

# (column, kind, label). What each kind becomes for the model:
#   count   log1p(value)   - 1 -> 2 commands matters; 1001 -> 1002 does not
#   flag    0 or 1
#   rarity  -log(share)    - how uncommon this value is across all sessions
FEATURES: tuple[tuple[str, str, str], ...] = (
    ("login_attempts", "count", "login attempts"),
    ("distinct_usernames", "count", "distinct usernames"),
    ("distinct_passwords", "count", "distinct passwords"),
    ("commands_run", "count", "commands run"),
    ("downloads", "count", "downloads"),
    ("duration_seconds", "count", "seconds connected"),
    ("login_succeeded", "flag", "logged in"),
    ("is_telnet", "flag", "used Telnet"),
    ("hassh", "rarity", "SSH client fingerprint"),
    ("first_command", "rarity", "first command"),
)

_SESSIONS_QUERY = """
    SELECT session_id, src_ip, started_at, protocol, login_attempts,
           distinct_usernames, distinct_passwords, commands_run, downloads,
           duration_seconds, login_succeeded, hassh, first_command
    FROM silver.honeypot_sessions
    WHERE is_closed
    ORDER BY started_at, session_id
"""


@dataclass(frozen=True)
class Features:
    raw: dict[str, np.ndarray]  # human-readable values: counts, 0/1, or shares for rarity
    matrix: np.ndarray  # what the model sees: one column per FEATURES entry


def build_features(rows: Sequence[dict[str, Any]]) -> Features:
    """Turn session rows into model inputs, keeping readable values for explanations."""
    n = len(rows)
    raw: dict[str, np.ndarray] = {}
    columns: list[np.ndarray] = []

    for name, kind, _ in FEATURES:
        if kind == "count":
            values = np.array([float(r.get(name) or 0.0) for r in rows], dtype=float)
            raw[name] = values
            columns.append(np.log1p(np.maximum(values, 0.0)))
        elif kind == "flag":
            if name == "is_telnet":
                values = np.array([float(r.get("protocol") == "telnet") for r in rows])
            else:
                values = np.array([float(bool(r.get(name))) for r in rows])
            raw[name] = values
            columns.append(values)
        else:
            # A missing fingerprint or no command at all is itself a category.
            keys = [r.get(name) or "(none)" for r in rows]
            counts = Counter(keys)
            shares = np.array([counts[k] / n for k in keys], dtype=float)
            raw[name] = shares
            columns.append(-np.log(shares))

    matrix = np.column_stack(columns) if n else np.empty((0, len(FEATURES)))
    return Features(raw=raw, matrix=matrix)


def anomaly_scores(matrix: np.ndarray, seed: int = 0) -> np.ndarray:
    """One score per session. Higher means more unusual."""
    from sklearn.ensemble import IsolationForest

    model = IsolationForest(n_estimators=N_ESTIMATORS, random_state=seed)
    model.fit(matrix)
    # score_samples is higher for NORMAL points; negate so "high = unusual".
    return np.asarray(-model.score_samples(matrix), dtype=float)


def top_k_size(n: int) -> int:
    """How many top sessions the stability measure compares: 1%, but at least 10."""
    return min(n, max(10, math.ceil(n * (1 - FLAG_QUANTILE))))


def stability(
    matrix: np.ndarray, *, k: int | None = None, seeds: Sequence[int] = STABILITY_SEEDS
) -> float:
    """Mean pairwise Jaccard overlap of the top-k sessions across seeds. 1.0 means identical."""
    size = k or top_k_size(len(matrix))
    tops = [
        set(np.argsort(-anomaly_scores(matrix, seed), kind="stable")[:size].tolist())
        for seed in seeds
    ]
    overlaps = [len(a & b) / len(a | b) for i, a in enumerate(tops) for b in tops[i + 1 :] if a | b]
    return float(np.mean(overlaps)) if overlaps else 1.0


def robust_z(matrix: np.ndarray) -> np.ndarray:
    """How far each value sits from the typical one, in units that ignore outliers.

    Scaled by the interquartile range rather than the standard deviation, so the
    anomalies being explained do not inflate the yardstick they are measured
    with. A column whose middle half is constant (a rare 0/1 flag) falls back to
    its standard deviation, or it could never be called unusual at all.
    """
    median = np.median(matrix, axis=0)
    q75, q25 = np.percentile(matrix, [75, 25], axis=0)
    spread = q75 - q25
    std = matrix.std(axis=0)
    scale = np.where(spread > 0, spread, np.where(std > 0, std, 1.0))
    return np.asarray((matrix - median) / scale, dtype=float)


def explain(
    index: int, features: Features, z: np.ndarray, *, limit: int = 3, threshold: float = 2.0
) -> str:
    """The features that make one session unusual, in plain words."""
    reasons: list[str] = []
    for column in np.argsort(-np.abs(z[index]), kind="stable"):
        if len(reasons) >= limit or abs(z[index, column]) < threshold:
            break
        name, kind, label = FEATURES[column]
        value = float(features.raw[name][index])
        if kind == "count":
            typical = float(np.median(features.raw[name]))
            reasons.append(f"{label} {value:g} (typical {typical:g})")
        elif kind == "flag":
            share = float(features.raw[name].mean())
            answer = "yes" if value else "no"
            reasons.append(
                f"{label}: {answer} (only {share if value else 1 - share:.1%} of sessions)"
            )
        elif z[index, column] > 0:
            # Only rarity is worth reporting; an unusually COMMON value is not a reason.
            reasons.append(f"rare {label} ({value:.1%} of sessions)")
    return "; ".join(reasons)


@dataclass
class SessionRun:
    status: str  # "scored" or "insufficient_data"
    sessions: int
    flagged: int = 0
    stability: float | None = None
    top_k: int = 0
    threshold: float | None = None


def load_sessions(con: duckdb.DuckDBPyConnection) -> list[dict[str, Any]]:
    """Closed sessions only: an open session's duration and command count are not final."""
    exists = con.execute(
        "SELECT count(*) FROM information_schema.tables "
        "WHERE table_schema = 'silver' AND table_name = 'honeypot_sessions'"
    ).fetchone()
    if not exists or not exists[0]:
        return []
    cursor = con.execute(_SESSIONS_QUERY)
    names = [d[0] for d in cursor.description]
    return [dict(zip(names, row, strict=True)) for row in cursor.fetchall()]


def run(
    con: duckdb.DuckDBPyConnection, *, seed: int = 0, min_sessions: int = MIN_SESSIONS
) -> SessionRun:
    """Score every closed session and write ml.honeypot_session_anomalies."""
    rows = load_sessions(con)
    if len(rows) < min_sessions:
        return SessionRun(status="insufficient_data", sessions=len(rows))

    features = build_features(rows)
    scores = anomaly_scores(features.matrix, seed)
    threshold = float(np.quantile(scores, FLAG_QUANTILE))
    flagged = scores >= threshold

    ranks = np.empty(len(rows), dtype=np.int32)
    ranks[np.argsort(-scores, kind="stable")] = np.arange(1, len(rows) + 1, dtype=np.int32)

    z = robust_z(features.matrix)
    reasons = [explain(i, features, z) if flagged[i] else None for i in range(len(rows))]
    k = top_k_size(len(rows))
    stable = stability(features.matrix, k=k)

    table = pa.table(
        {
            "session_id": pa.array([r["session_id"] for r in rows], pa.string()),
            "src_ip": pa.array([r["src_ip"] for r in rows], pa.string()),
            "started_at": pa.array([r["started_at"] for r in rows], pa.timestamp("us", tz="UTC")),
            "protocol": pa.array([r["protocol"] for r in rows], pa.string()),
            "anomaly_score": pa.array(scores, pa.float64()),
            "anomaly_rank": pa.array(ranks, pa.int32()),
            "is_flagged": pa.array(flagged, pa.bool_()),
            "reasons": pa.array(reasons, pa.string()),
            "login_attempts": pa.array([int(r["login_attempts"] or 0) for r in rows], pa.int64()),
            "commands_run": pa.array([int(r["commands_run"] or 0) for r in rows], pa.int64()),
            "downloads": pa.array([int(r["downloads"] or 0) for r in rows], pa.int64()),
            "first_command": pa.array([r["first_command"] for r in rows], pa.string()),
            "scored_at": pa.array(
                [datetime.now(timezone.utc)] * len(rows), pa.timestamp("us", tz="UTC")
            ),
        }
    )

    con.execute("CREATE SCHEMA IF NOT EXISTS ml")
    con.register("_session_scores", table)
    try:
        con.execute(
            "CREATE OR REPLACE TABLE ml.honeypot_session_anomalies AS SELECT * FROM _session_scores"
        )
    finally:
        con.unregister("_session_scores")

    return SessionRun(
        status="scored",
        sessions=len(rows),
        flagged=int(flagged.sum()),
        stability=stable,
        top_k=k,
        threshold=threshold,
    )
