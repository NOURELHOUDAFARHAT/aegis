"""Ransomware-linkage scoring for actively-exploited vulnerabilities.

THE QUESTION
------------
CISA marks a KEV entry as known ransomware campaign use when ransomware
operators are seen exploiting it. Of 1,709 exploited CVEs, 360 (21%) carry that
mark. This model answers: which recently added CVEs look like the ones
ransomware groups adopt?

WHICH NUMBER TO BELIEVE
-----------------------
Random 5-fold cross-validation reports PR-AUC 0.498. That number is inflated:
random folds put CVEs added in 2026 into training while testing on 2022, so the
model learns vocabulary from the future. The honest evaluation trains only on
CVEs added before 2025 and tests on later ones: PR-AUC 0.282 against a chance
level of 0.121, about 2.3x chance. That time-split score is the one logged.

LABEL LAG: WHY EVEN THAT NUMBER IS PESSIMISTIC
----------------------------------------------
The ransomware-linked share is 23-27% for every year added from 2021 to 2024,
then 12.7% for 2025 and 11.6% for 2026. A step change exactly at the recent
boundary is what label lag looks like: ransomware use is observed and flagged
months after a CVE is added. Recent negatives therefore include future
positives, so some apparent false positives on recent CVEs may be early
warnings. The data supports that hypothesis; it does not prove it. So the
output is a watch list to investigate, not a verdict.

NO IN-SAMPLE SCORES
-------------------
Every published score comes from a model that did not see that CVE's label
(out-of-fold prediction). Scoring rows the model was trained on would produce
confident, meaningless probabilities for exactly the CVEs already labelled.

LEAKAGE CHECK
-------------
Only 0.1% of descriptions contain the word "ransom", so the model is not
reading the answer out of the text.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import date, datetime, timezone

import duckdb
import numpy as np
import pyarrow as pa
from sklearn.pipeline import Pipeline

TEMPORAL_CUTOFF = date(2025, 1, 1)


def kev_text(
    vendor: str | None,
    product: str | None,
    name: str | None,
    description: str | None,
    cwes: Sequence[str] | None,
) -> str:
    """The text a CVE is judged on: who makes it, what it is, how it fails."""
    parts = [vendor, product, name, description, " ".join(cwes or [])]
    return " ".join(p for p in parts if p)


def build_model() -> Pipeline:
    """TF-IDF over words and word pairs, then a class-balanced logistic regression.

    Deliberately simple. With 1,709 examples a linear model on sparse text is
    the right size: it trains in milliseconds, its coefficients are readable,
    and anything larger would mostly memorise the vendors in the training set.
    `class_weight="balanced"` stops the 79% majority class from dominating.
    """
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import make_pipeline

    return make_pipeline(
        TfidfVectorizer(ngram_range=(1, 2), min_df=2, sublinear_tf=True),
        LogisticRegression(max_iter=3000, class_weight="balanced"),
    )


def temporal_masks(dates: Sequence[date], cutoff: date) -> tuple[np.ndarray, np.ndarray]:
    """Train on everything added before `cutoff`, test on everything from it on."""
    train = np.array([d < cutoff for d in dates], dtype=bool)
    return train, ~train


@dataclass
class Evaluation:
    roc_auc: float
    pr_auc: float
    test_prevalence: float
    n_train: int
    n_test: int
    cutoff: date

    @property
    def lift_over_chance(self) -> float:
        """PR-AUC divided by the PR-AUC a random ranking would score."""
        return self.pr_auc / self.test_prevalence if self.test_prevalence else float("nan")


def evaluate_temporal(
    texts: Sequence[str],
    labels: np.ndarray,
    dates: Sequence[date],
    cutoff: date = TEMPORAL_CUTOFF,
) -> Evaluation:
    """Fit on the past, score the future. Raises if either side lacks both classes."""
    from sklearn.metrics import average_precision_score, roc_auc_score

    train, test = temporal_masks(dates, cutoff)
    for side, mask in (("training", train), ("test", test)):
        classes = set(labels[mask].tolist())
        if classes != {0, 1}:
            raise ValueError(
                f"the {side} period before/after {cutoff} needs both classes, got {classes}"
            )

    text_array = np.asarray(texts, dtype=object)
    model = build_model().fit(text_array[train], labels[train])
    scores = model.predict_proba(text_array[test])[:, 1]
    return Evaluation(
        roc_auc=float(roc_auc_score(labels[test], scores)),
        pr_auc=float(average_precision_score(labels[test], scores)),
        test_prevalence=float(labels[test].mean()),
        n_train=int(train.sum()),
        n_test=int(test.sum()),
        cutoff=cutoff,
    )


def out_of_fold_scores(
    texts: Sequence[str], labels: np.ndarray, *, n_splits: int = 5, seed: int = 42
) -> np.ndarray:
    """A probability for every row, each from a model that never saw that row's label."""
    from sklearn.model_selection import StratifiedKFold, cross_val_predict

    minority = int(min(labels.sum(), len(labels) - labels.sum()))
    splits = max(2, min(n_splits, minority))
    folds = StratifiedKFold(n_splits=splits, shuffle=True, random_state=seed)
    probabilities = cross_val_predict(
        build_model(), np.asarray(texts, dtype=object), labels, cv=folds, method="predict_proba"
    )
    return np.asarray(probabilities[:, 1], dtype=float)


@dataclass
class ScoringRun:
    evaluation: Evaluation
    scored: int
    watchlist_size: int


def run(con: duckdb.DuckDBPyConnection, *, cutoff: date = TEMPORAL_CUTOFF) -> ScoringRun:
    """Evaluate on a time split, score every CVE out-of-fold, write ml.kev_ransomware_scores."""
    rows = con.sql(
        "SELECT cve_id, vendor, product, vulnerability_name, description, cwes, "
        "is_ransomware_linked, date_added FROM silver.kev_vulnerabilities ORDER BY cve_id"
    ).fetchall()

    texts = [kev_text(r[1], r[2], r[3], r[4], r[5]) for r in rows]
    labels = np.array([int(bool(r[6])) for r in rows])
    dates = [r[7] for r in rows]

    evaluation = evaluate_temporal(texts, labels, dates, cutoff)
    scores = out_of_fold_scores(texts, labels)

    # The watch list: recent CVEs NOT yet linked to ransomware, ranked by how
    # much they resemble the ones that are.
    on_watchlist = np.array([(d >= cutoff) and not y for d, y in zip(dates, labels, strict=True)])
    ranks: list[int | None] = [None] * len(rows)
    for rank, index in enumerate(
        sorted(np.flatnonzero(on_watchlist), key=lambda i: -scores[i]), start=1
    ):
        ranks[index] = rank

    table = pa.table(
        {
            "cve_id": pa.array([r[0] for r in rows], pa.string()),
            "vendor": pa.array([r[1] for r in rows], pa.string()),
            "product": pa.array([r[2] for r in rows], pa.string()),
            "vulnerability_name": pa.array([r[3] for r in rows], pa.string()),
            "date_added": pa.array(dates, pa.date32()),
            "is_ransomware_linked": pa.array(labels.astype(bool), pa.bool_()),
            "ransomware_probability": pa.array(scores, pa.float64()),
            "on_watchlist": pa.array(on_watchlist, pa.bool_()),
            "watchlist_rank": pa.array(ranks, pa.int32()),
            "scored_at": pa.array(
                [datetime.now(timezone.utc)] * len(rows), pa.timestamp("us", tz="UTC")
            ),
        }
    )

    con.execute("CREATE SCHEMA IF NOT EXISTS ml")
    con.register("_kev_scores", table)
    try:
        con.execute("CREATE OR REPLACE TABLE ml.kev_ransomware_scores AS SELECT * FROM _kev_scores")
    finally:
        con.unregister("_kev_scores")

    return ScoringRun(
        evaluation=evaluation, scored=len(rows), watchlist_size=int(on_watchlist.sum())
    )
