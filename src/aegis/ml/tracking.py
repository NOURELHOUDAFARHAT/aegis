"""Experiment tracking with MLflow, stored locally.

WHAT GETS RECORDED
------------------
Every ML run writes its parameters, its metrics and supporting files to MLflow,
so a question like "did the ransomware model get better or worse after the last
CISA update?" has an answer instead of a guess.

WHERE
-----
    runs, params, metrics   SQLite, at AEGIS_DATA_DIR/mlflow/mlflow.db
    artifacts               AEGIS_DATA_DIR/mlflow/artifacts/<experiment>/

No tracking server is needed. Every experiment is created with an explicit
artifact location, because MLflow's default is a `mlruns/` folder in whatever
directory the process happens to start in - which would be the repository, and
therefore OneDrive and potentially git.

WHY MODELS ARE SAVED AS PLAIN FILES
-----------------------------------
This project installs `mlflow-skinny` (9 extra packages) rather than full MLflow
(about 28, including Flask, pandas and matplotlib). Skinny's
`mlflow.sklearn.log_model` needs pandas, and failed without it. A model that
retrains in milliseconds on every run does not justify that dependency, so
fitted models are saved with joblib and logged as ordinary artifacts. What is
lost is MLflow's model-flavour packaging, which nothing here consumes.
"""

from __future__ import annotations

import math
import os
import tempfile
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from aegis.config import settings

EXPERIMENT_CAMPAIGNS = "aegis-url-campaigns"
EXPERIMENT_RANSOMWARE = "aegis-kev-ransomware"
EXPERIMENT_SEARCH = "aegis-cve-search"


def tracking_root() -> Path:
    return Path(settings.data_dir) / "mlflow"


def tracking_uri() -> str:
    return f"sqlite:///{(tracking_root() / 'mlflow.db').as_posix()}"


def artifact_root() -> Path:
    return tracking_root() / "artifacts"


def _quiet_environment() -> None:
    """Silence MLflow's agent hint, usage telemetry and progress bars.

    The telemetry setting matters for the same reason as dbt's and Dagster's:
    a security-telemetry platform should make no outbound calls it does not need.
    """
    os.environ.setdefault("MLFLOW_DISABLE_AGENT_HINT", "1")
    os.environ.setdefault("MLFLOW_DISABLE_TELEMETRY", "true")
    os.environ.setdefault("MLFLOW_ENABLE_ARTIFACTS_PROGRESS_BAR", "false")


def _experiment_id(mlflow: Any, name: str) -> str:
    existing = mlflow.get_experiment_by_name(name)
    if existing is not None:
        return str(existing.experiment_id)
    location = artifact_root() / name
    location.mkdir(parents=True, exist_ok=True)
    return str(mlflow.create_experiment(name, artifact_location=location.as_uri()))


class TrackedRun:
    """A thin, typed wrapper over one active MLflow run."""

    def __init__(self, mlflow: Any, active_run: Any) -> None:
        self._mlflow = mlflow
        self._run = active_run

    @property
    def run_id(self) -> str:
        return str(self._run.info.run_id)

    def params(self, values: Mapping[str, Any]) -> None:
        self._mlflow.log_params({k: str(v) for k, v in values.items()})

    def metrics(self, values: Mapping[str, float | int | None]) -> None:
        """Log numeric metrics, skipping missing or undefined values.

        An undefined value - a lift when the baseline rate is zero - is left out
        rather than logged as 0, which would read as a real, terrible score.
        """
        clean = {
            k: float(v)
            for k, v in values.items()
            if v is not None and not (isinstance(v, float) and math.isnan(v))
        }
        if clean:
            self._mlflow.log_metrics(clean)

    def tags(self, values: Mapping[str, str]) -> None:
        self._mlflow.set_tags(dict(values))

    def json(self, payload: Mapping[str, Any], filename: str) -> None:
        self._mlflow.log_dict(dict(payload), filename)

    def text(self, content: str, filename: str) -> None:
        self._mlflow.log_text(content, filename)

    def model(self, model: Any, filename: str = "model.joblib") -> None:
        import joblib

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / filename
            joblib.dump(model, path)
            self._mlflow.log_artifact(str(path), artifact_path="model")


@contextmanager
def track(experiment: str, run_name: str) -> Iterator[TrackedRun]:
    """Open an MLflow run. An exception inside marks the run FAILED and re-raises."""
    _quiet_environment()
    import mlflow

    artifact_root().mkdir(parents=True, exist_ok=True)
    mlflow.set_tracking_uri(tracking_uri())
    experiment_id = _experiment_id(mlflow, experiment)
    with mlflow.start_run(experiment_id=experiment_id, run_name=run_name) as active_run:
        yield TrackedRun(mlflow, active_run)
