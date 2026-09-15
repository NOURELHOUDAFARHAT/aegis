"""Machine-learning assets: campaigns, ransomware scores and CVE embeddings.

Each reads a Silver table, writes to the `ml` schema of the DuckDB warehouse,
and records its run in MLflow. The Dagster run links to the MLflow run through
the `mlflow_run_id` metadata on every materialisation.

    silver/urlhaus_urls        -> ml/url_campaigns
    silver/kev_vulnerabilities -> ml/kev_ransomware_scores
    silver/kev_vulnerabilities -> ml/cve_embeddings

All three are in the warehouse concurrency pool (see orchestration/pools.py).

THE CHECKS GUARD AGAINST SILENT DECAY
-------------------------------------
A model that keeps running but stops meaning anything is worse than one that
fails, because nothing tells you. Each check watches the property that made the
model worth shipping in the first place:

    campaigns_align_with_subnets   campaigns must still cluster by network
    ransomware_beats_chance        the time-split score must stay well above chance
    every_cve_is_searchable        no exploited CVE may be missing from search
"""

# No `from __future__ import annotations`: Dagster validates the context
# annotation against the real class. See the note in orchestration/assets.py.
import sys
import time
from typing import Any

from dagster import (
    AssetCheckExecutionContext,
    AssetCheckResult,
    AssetChecksDefinition,
    AssetCheckSeverity,
    AssetExecutionContext,
    AssetKey,
    AssetsDefinition,
    Failure,
    MaterializeResult,
    asset,
    asset_check,
)

from aegis.orchestration.pools import WAREHOUSE_POOL

URL_CAMPAIGNS = AssetKey(["ml", "url_campaigns"])
KEV_RANSOMWARE = AssetKey(["ml", "kev_ransomware_scores"])
CVE_EMBEDDINGS = AssetKey(["ml", "cve_embeddings"])

# Thresholds for the decay checks. Generous on purpose: they exist to catch a
# model that has stopped working, not to page someone over normal variation.
MIN_SUBNET_LIFT = 2.0  # measured 131x on 2026-09-14
MIN_LIFT_OVER_CHANCE = 1.5  # measured 2.3x on 2026-09-14


def _warehouse(read_only: bool = False) -> Any:
    import duckdb

    from aegis.modeling.dbt_runner import warehouse_path

    return duckdb.connect(str(warehouse_path()), read_only=read_only)


def _latest_metadata(context: AssetCheckExecutionContext, key: AssetKey) -> dict[str, Any]:
    """Metadata from the asset's most recent materialisation, as plain values."""
    event = context.instance.get_latest_materialization_event(key)
    if event is None or event.asset_materialization is None:
        return {}
    return {
        name: getattr(value, "value", value)
        for name, value in event.asset_materialization.metadata.items()
    }


@asset(
    name="url_campaigns",
    key_prefix=["ml"],
    deps=[AssetKey(["silver", "urlhaus_urls"])],
    group_name="ml",
    kinds={"python", "scikit-learn", "duckdb"},
    pool=WAREHOUSE_POOL,
    description=(
        "URLhaus servers grouped into campaigns by the files, tags and ports they serve "
        "(DBSCAN). About 9% of servers cluster; the rest are left unclustered on purpose."
    ),
)
def url_campaigns(context: AssetExecutionContext) -> MaterializeResult:
    from aegis.ml import campaigns
    from aegis.ml.tracking import EXPERIMENT_CAMPAIGNS, track

    con = _warehouse()
    try:
        with track(EXPERIMENT_CAMPAIGNS, f"dagster-{context.run_id[:8]}") as run:
            result = campaigns.run(con)
            run.params({"eps": result.eps, "min_servers": result.min_servers})
            run.metrics(
                {
                    "servers": result.servers,
                    "clustered_servers": result.clustered_servers,
                    "campaigns": result.campaigns,
                    "coverage": result.coverage,
                    "same_subnet_within_campaign": result.coherence.within_rate,
                    "same_subnet_random_pairs": result.coherence.random_rate,
                    "subnet_lift": result.coherence.lift,
                }
            )
            mlflow_run_id = run.run_id
    finally:
        con.close()

    metadata: dict[str, Any] = {
        "dagster/row_count": result.campaigns,
        "servers": result.servers,
        "clustered_servers": result.clustered_servers,
        "coverage": round(result.coverage, 4),
        "same_subnet_within_campaign": round(result.coherence.within_rate, 4),
        "same_subnet_random_pairs": round(result.coherence.random_rate, 4),
        "mlflow_run_id": mlflow_run_id,
    }
    if result.coherence.lift is not None:
        metadata["subnet_lift"] = round(result.coherence.lift, 2)
    return MaterializeResult(metadata=metadata)


@asset(
    name="kev_ransomware_scores",
    key_prefix=["ml"],
    deps=[AssetKey(["silver", "kev_vulnerabilities"])],
    group_name="ml",
    kinds={"python", "scikit-learn", "duckdb"},
    pool=WAREHOUSE_POOL,
    description=(
        "Every exploited CVE scored for resemblance to ransomware-linked ones, out-of-fold. "
        "Recent unlinked CVEs form a watch list. Evaluated on a time split."
    ),
)
def kev_ransomware_scores(context: AssetExecutionContext) -> MaterializeResult:
    from aegis.ml import ransomware
    from aegis.ml.tracking import EXPERIMENT_RANSOMWARE, track

    con = _warehouse()
    try:
        with track(EXPERIMENT_RANSOMWARE, f"dagster-{context.run_id[:8]}") as run:
            result = ransomware.run(con)
            ev = result.evaluation
            run.params(
                {"cutoff": ev.cutoff.isoformat(), "published_scores": "out-of-fold, 5 folds"}
            )
            run.metrics(
                {
                    "pr_auc_time_split": ev.pr_auc,
                    "roc_auc_time_split": ev.roc_auc,
                    "test_prevalence": ev.test_prevalence,
                    "lift_over_chance": ev.lift_over_chance,
                    "watchlist_size": result.watchlist_size,
                }
            )
            mlflow_run_id = run.run_id
    finally:
        con.close()

    return MaterializeResult(
        metadata={
            "dagster/row_count": result.scored,
            "pr_auc_time_split": round(ev.pr_auc, 4),
            "roc_auc_time_split": round(ev.roc_auc, 4),
            "test_prevalence": round(ev.test_prevalence, 4),
            "lift_over_chance": round(ev.lift_over_chance, 3),
            "watchlist_size": result.watchlist_size,
            "mlflow_run_id": mlflow_run_id,
        }
    )


@asset(
    name="cve_embeddings",
    key_prefix=["ml"],
    deps=[AssetKey(["silver", "kev_vulnerabilities"])],
    group_name="ml",
    kinds={"python", "onnx", "duckdb"},
    pool=WAREHOUSE_POOL,
    description=(
        "384-dimension vectors for semantic CVE search (bge-small, local ONNX). "
        "Only new or changed CVEs are embedded: ~130s for a full pass, seconds when nothing changed."
    ),
)
def cve_embeddings(context: AssetExecutionContext) -> MaterializeResult:
    import aegis

    status = aegis.MSVC_RUNTIME_STATUS
    context.log.info(f"C++ runtime preload: {status}")
    if sys.platform == "win32" and status and status.startswith("too late"):
        # Under `dagster dev`, Dagster starts before AEGIS is imported. If
        # anything in that process imported PyArrow first, the runtime fix could
        # not run and onnxruntime will fail to load. Say so plainly instead of
        # surfacing a baffling DLL error. See aegis/_windows_dll.py.
        raise Failure(
            description=(
                "onnxruntime cannot load in this process: PyArrow was imported before "
                "aegis, so the Windows C++ runtime fix could not be applied."
            ),
            metadata={"runtime_status": status},
        )

    from aegis.ml import search
    from aegis.ml.tracking import EXPERIMENT_SEARCH, track

    con = _warehouse()
    try:
        with track(EXPERIMENT_SEARCH, f"dagster-{context.run_id[:8]}") as run:
            started = time.perf_counter()
            result = search.refresh_embeddings(con, search.FastEmbedEmbedder())
            seconds = time.perf_counter() - started
            run.params({"model": search.MODEL_NAME, "dimensions": search.EMBEDDING_DIM})
            run.metrics(
                {
                    "embedded": result.embedded,
                    "reused": result.reused,
                    "removed": result.removed,
                    "total": result.total,
                    "seconds": seconds,
                }
            )
            mlflow_run_id = run.run_id
    finally:
        con.close()

    return MaterializeResult(
        metadata={
            "dagster/row_count": result.total,
            "embedded": result.embedded,
            "reused": result.reused,
            "removed": result.removed,
            "seconds": round(seconds, 1),
            "model": search.MODEL_NAME,
            "runtime_status": status or "n/a",
            "mlflow_run_id": mlflow_run_id,
        }
    )


@asset_check(
    asset=URL_CAMPAIGNS,
    name="campaigns_align_with_subnets",
    description=(
        f"Servers in one campaign must share a /24 subnet at least {MIN_SUBNET_LIFT}x as often "
        "as random pairs. The subnet is never a model feature, so this is independent evidence."
    ),
)
def campaigns_align_with_subnets(context: AssetCheckExecutionContext) -> AssetCheckResult:
    metadata = _latest_metadata(context, URL_CAMPAIGNS)
    lift = metadata.get("subnet_lift")
    within = metadata.get("same_subnet_within_campaign")
    if lift is None:
        # No lift means random pairs never matched. That is fine only if pairs
        # within campaigns do; otherwise there is no evidence either way.
        passed = bool(within and within > 0)
    else:
        passed = float(lift) >= MIN_SUBNET_LIFT
    return AssetCheckResult(
        passed=passed,
        severity=AssetCheckSeverity.WARN,
        metadata={
            "subnet_lift": lift if lift is not None else "undefined",
            "threshold": MIN_SUBNET_LIFT,
        },
    )


@asset_check(
    asset=KEV_RANSOMWARE,
    name="ransomware_beats_chance",
    description=(
        f"On CVEs added after the training cutoff, PR-AUC must stay at least {MIN_LIFT_OVER_CHANCE}x "
        "what a random ranking would score."
    ),
)
def ransomware_beats_chance(context: AssetCheckExecutionContext) -> AssetCheckResult:
    metadata = _latest_metadata(context, KEV_RANSOMWARE)
    lift = metadata.get("lift_over_chance")
    return AssetCheckResult(
        passed=lift is not None and float(lift) >= MIN_LIFT_OVER_CHANCE,
        severity=AssetCheckSeverity.WARN,
        metadata={
            "lift_over_chance": lift if lift is not None else "missing",
            "threshold": MIN_LIFT_OVER_CHANCE,
        },
    )


@asset_check(
    asset=CVE_EMBEDDINGS,
    name="every_cve_is_searchable",
    pool=WAREHOUSE_POOL,
    description="Every CVE in Silver must have a stored vector, or search silently misses it.",
)
def every_cve_is_searchable(context: AssetCheckExecutionContext) -> AssetCheckResult:
    from aegis.ml.search import MODEL_NAME

    con = _warehouse(read_only=True)
    try:
        row = con.execute(
            "SELECT "
            "(SELECT count(*) FROM silver.kev_vulnerabilities), "
            "(SELECT count(*) FROM ml.cve_embeddings e "
            " JOIN silver.kev_vulnerabilities s USING (cve_id) WHERE e.model = ?)",
            [MODEL_NAME],
        ).fetchone()
    finally:
        con.close()
    cves, searchable = (int(row[0]), int(row[1])) if row else (0, 0)
    return AssetCheckResult(
        passed=cves > 0 and searchable == cves,
        severity=AssetCheckSeverity.ERROR,
        metadata={"cves_in_silver": cves, "searchable": searchable, "missing": cves - searchable},
    )


ML_ASSETS: list[AssetsDefinition] = [url_campaigns, kev_ransomware_scores, cve_embeddings]
ML_CHECKS: list[AssetChecksDefinition] = [
    campaigns_align_with_subnets,
    ransomware_beats_chance,
    every_cve_is_searchable,
]
