"""Tests for experiment tracking.

These run MLflow for real, against a SQLite store in a temporary directory, so
they prove the part that went wrong once already: where MLflow puts things. No
server and no infrastructure are needed.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("mlflow")


@pytest.fixture
def isolated_data_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    from aegis.config import settings

    monkeypatch.setattr(settings, "data_dir", str(tmp_path))
    return tmp_path


class TestLocations:
    def test_tracking_store_is_sqlite_under_the_data_dir(self, isolated_data_dir: Path) -> None:
        from aegis.ml import tracking

        assert tracking.tracking_uri().startswith("sqlite:///")
        assert tracking.tracking_root() == isolated_data_dir / "mlflow"

    def test_artifacts_live_under_the_data_dir(self, isolated_data_dir: Path) -> None:
        from aegis.ml import tracking

        assert tracking.artifact_root().is_relative_to(isolated_data_dir)


class TestRoundTrip:
    def test_a_run_stores_params_metrics_json_and_model(
        self, isolated_data_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Everything the CLI logs must come back out, and land where configured."""
        import mlflow
        import numpy as np
        from sklearn.linear_model import LogisticRegression

        from aegis.ml import tracking

        monkeypatch.chdir(isolated_data_dir)
        model = LogisticRegression().fit(np.array([[0.0], [1.0], [0.0], [1.0]]), [0, 1, 0, 1])

        with tracking.track("aegis-test", "round-trip") as run:
            run.params({"cutoff": "2025-01-01"})
            run.metrics({"pr_auc_time_split": 0.282, "n_test": 470})
            run.json({"roc_auc": 0.739}, "evaluation.json")
            run.model(model)
            run_id = run.run_id

        stored = mlflow.get_run(run_id)
        assert stored.data.params == {"cutoff": "2025-01-01"}
        assert stored.data.metrics["pr_auc_time_split"] == pytest.approx(0.282)
        assert stored.info.status == "FINISHED"

        experiment_dir = isolated_data_dir / "mlflow" / "artifacts" / "aegis-test"
        model_files = list(experiment_dir.rglob("model.joblib"))
        evaluation_files = list(experiment_dir.rglob("evaluation.json"))
        assert len(model_files) == 1
        assert json.loads(evaluation_files[0].read_text(encoding="utf-8")) == {"roc_auc": 0.739}

    def test_no_mlruns_folder_is_created_in_the_working_directory(
        self, isolated_data_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """MLflow's default artifact store is ./mlruns - which would be the repository."""
        from aegis.ml import tracking

        work = isolated_data_dir / "somewhere_else"
        work.mkdir()
        monkeypatch.chdir(work)
        with tracking.track("aegis-test-cwd", "cwd") as run:
            run.metrics({"x": 1.0})
        assert not (work / "mlruns").exists()

    def test_undefined_metrics_are_skipped_not_logged_as_zero(
        self, isolated_data_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A lift of None (baseline never matched) must not appear as a score of 0."""
        import mlflow

        from aegis.ml import tracking

        monkeypatch.chdir(isolated_data_dir)
        with tracking.track("aegis-test-nan", "nan") as run:
            run.metrics({"subnet_lift": None, "undefined": float("nan"), "coverage": 0.09})
            run_id = run.run_id

        assert mlflow.get_run(run_id).data.metrics == {"coverage": pytest.approx(0.09)}

    def test_an_exception_marks_the_run_failed(
        self, isolated_data_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import mlflow

        from aegis.ml import tracking

        monkeypatch.chdir(isolated_data_dir)
        with pytest.raises(RuntimeError), tracking.track("aegis-test-fail", "fail") as run:
            run_id = run.run_id
            raise RuntimeError("model training blew up")

        assert mlflow.get_run(run_id).info.status == "FAILED"
