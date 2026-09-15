"""Tests for the ML layer.

No model download, no MLflow, no infrastructure. The embedding model is
replaced by a deterministic fake, and warehouse tables are built in an
in-memory DuckDB - so these run in seconds on any machine and still exercise
the real storage and ranking code.
"""

from __future__ import annotations

import hashlib
import re
from datetime import date

import duckdb
import numpy as np
import pytest

from aegis.ml import campaigns, ransomware, search


# ============================================================================
# Campaign detection
# ============================================================================
class TestUrlParsing:
    @pytest.mark.parametrize(
        ("url", "port"),
        [
            ("http://1.2.3.4:8080/i", "8080"),
            ("http://1.2.3.4/i", "80"),
            ("https://evil.test/payload.exe", "443"),
        ],
    )
    def test_port_defaults_by_scheme(self, url: str, port: str) -> None:
        assert campaigns.url_port(url) == port

    @pytest.mark.parametrize(
        ("url", "ending"),
        [
            ("http://1.2.3.4:8080/bin.sh", "bin.sh"),
            ("http://1.2.3.4/a/b/Mozi.m", "Mozi.m"),
            ("http://1.2.3.4/", "(root)"),
            ("http://1.2.3.4", "(root)"),
            ("http://1.2.3.4/x.exe?id=7#frag", "x.exe"),
        ],
    )
    def test_path_ending_is_the_served_file(self, url: str, ending: str) -> None:
        assert campaigns.url_path_ending(url) == ending

    def test_subnet_only_for_ipv4(self) -> None:
        assert campaigns.subnet_24("94.154.43.60") == "94.154.43"
        assert campaigns.subnet_24("evil.example.com") is None


def _rows_for(
    hosts: list[str], paths: list[str], tags: list[str]
) -> list[tuple[str, str, list[str], bool]]:
    return [(f"http://{h}/{p}", h, tags, False) for h in hosts for p in paths]


class TestClustering:
    @pytest.fixture
    def profiles(self) -> dict[str, campaigns.ServerProfile]:
        screenconnect = [f"10.0.1.{i}" for i in range(1, 8)]
        powershell = [f"10.0.2.{i}" for i in range(1, 7)]
        loners = ["172.16.9.1", "172.16.8.1", "unique.example.com"]
        rows = (
            _rows_for(screenconnect, ["ScreenConnect.ClientSetup.msi"], ["screenconnect"])
            + _rows_for(powershell, ["crypted.ps1"], ["powershell", "ps1"])
            + [("http://172.16.9.1/a.bin", "172.16.9.1", ["mirai"], True)]
            + [("http://172.16.8.1:81/z", "172.16.8.1", ["gafgyt"], False)]
            + [("https://unique.example.com/q.apk", "unique.example.com", ["android"], False)]
        )
        _ = loners
        return campaigns.build_profiles(rows)

    def test_identical_behaviour_forms_one_campaign_each(
        self, profiles: dict[str, campaigns.ServerProfile]
    ) -> None:
        labels = campaigns.cluster_servers(profiles, eps=0.35, min_servers=5)
        assert len({labels[f"10.0.1.{i}"] for i in range(1, 8)}) == 1
        assert len({labels[f"10.0.2.{i}"] for i in range(1, 7)}) == 1
        assert labels["10.0.1.1"] != labels["10.0.2.1"]

    def test_unique_servers_are_left_unclustered_not_forced_into_a_group(
        self, profiles: dict[str, campaigns.ServerProfile]
    ) -> None:
        """The reason DBSCAN was chosen over k-means: leftovers stay leftovers."""
        labels = campaigns.cluster_servers(profiles, eps=0.35, min_servers=5)
        assert labels["172.16.9.1"] == -1
        assert labels["unique.example.com"] == -1

    def test_campaign_ids_are_deterministic_and_largest_first(
        self, profiles: dict[str, campaigns.ServerProfile]
    ) -> None:
        first = campaigns.cluster_servers(profiles, eps=0.35, min_servers=5)
        second = campaigns.cluster_servers(profiles, eps=0.35, min_servers=5)
        assert first == second
        assert first["10.0.1.1"] == 1  # 7 servers: the biggest campaign is #1
        assert first["10.0.2.1"] == 2

    def test_too_few_servers_means_no_campaigns(self) -> None:
        profiles = campaigns.build_profiles(_rows_for(["1.1.1.1", "2.2.2.2"], ["i"], ["mozi"]))
        assert set(campaigns.cluster_servers(profiles, min_servers=5).values()) == {-1}

    def test_summary_counts_urls_and_subnets(
        self, profiles: dict[str, campaigns.ServerProfile]
    ) -> None:
        labels = campaigns.cluster_servers(profiles, eps=0.35, min_servers=5)
        summary = {c.campaign_id: c for c in campaigns.summarise(profiles, labels)}
        assert summary[1].servers == 7
        assert summary[1].distinct_subnets == 1
        assert summary[1].top_tags == ["screenconnect"]


class TestSubnetCoherence:
    def test_campaigns_that_share_a_subnet_score_above_random(self) -> None:
        labels = {f"10.0.1.{i}": 1 for i in range(1, 9)}
        labels.update({f"10.{i}.{i}.1": -1 for i in range(20, 60)})
        result = campaigns.subnet_coherence(labels)
        assert result.within_rate == 1.0
        assert result.random_rate < result.within_rate

    def test_lift_is_undefined_when_random_pairs_never_match(self) -> None:
        result = campaigns.Coherence(
            within_rate=0.087, random_rate=0.0, within_pairs=10, random_pairs=10
        )
        assert result.lift is None

    def test_domain_names_do_not_count_as_subnet_pairs(self) -> None:
        labels = {f"host{i}.example.com": 1 for i in range(6)}
        result = campaigns.subnet_coherence(labels)
        assert result.within_pairs == 0


class TestCampaignRunWritesTables:
    def test_run_writes_both_ml_tables(self) -> None:
        con = duckdb.connect()
        con.execute("CREATE SCHEMA silver")
        con.execute(
            "CREATE TABLE silver.urlhaus_urls (url VARCHAR, host VARCHAR, tags VARCHAR[], is_online BOOLEAN)"
        )
        rows = _rows_for([f"10.0.1.{i}" for i in range(1, 7)], ["crypted.ps1"], ["powershell"])
        con.executemany("INSERT INTO silver.urlhaus_urls VALUES (?, ?, ?, ?)", rows)

        result = campaigns.run(con, eps=0.35, min_servers=5)

        assert result.campaigns == 1
        assert result.coverage == 1.0
        assert con.sql("SELECT count(*) FROM ml.url_campaigns").fetchone() == (1,)
        assert con.sql("SELECT count(*) FROM ml.url_campaign_servers").fetchone() == (6,)
        con.close()


# ============================================================================
# Ransomware scoring
# ============================================================================
class TestRansomwareScoring:
    def test_text_includes_every_signal_and_skips_blanks(self) -> None:
        text = ransomware.kev_text(
            "Fortinet", "FortiOS", "SSL-VPN overflow", "Heap overflow.", ["CWE-122"]
        )
        assert text == "Fortinet FortiOS SSL-VPN overflow Heap overflow. CWE-122"
        assert ransomware.kev_text(None, "X", None, None, None) == "X"

    def test_temporal_split_never_trains_on_the_future(self) -> None:
        """The honest-evaluation guarantee: every training CVE predates every test CVE."""
        dates = [date(2023, 5, 1), date(2025, 2, 1), date(2024, 12, 31), date(2025, 1, 1)]
        train, test = ransomware.temporal_masks(dates, date(2025, 1, 1))
        assert max(d for d, t in zip(dates, train, strict=True) if t) < min(
            d for d, t in zip(dates, test, strict=True) if t
        )
        assert test.tolist() == [False, True, False, True]  # the cutoff day itself is test

    def test_evaluation_refuses_a_period_with_one_class(self) -> None:
        texts = ["a b", "c d", "e f", "g h"]
        labels = np.array([1, 0, 0, 0])
        dates = [date(2023, 1, 1), date(2023, 1, 2), date(2025, 1, 1), date(2025, 1, 2)]
        with pytest.raises(ValueError, match="needs both classes"):
            ransomware.evaluate_temporal(texts, labels, dates, date(2025, 1, 1))

    def test_out_of_fold_scores_cover_every_row(self) -> None:
        texts = ["lockbit encrypts files for ransom"] * 20 + ["browser memory corruption"] * 20
        labels = np.array([1] * 20 + [0] * 20)
        scores = ransomware.out_of_fold_scores(texts, labels)
        assert scores.shape == (40,)
        assert ((scores >= 0) & (scores <= 1)).all()
        assert scores[:20].mean() > scores[20:].mean()


# ============================================================================
# Semantic search
# ============================================================================
class FakeEmbedder:
    """Deterministic bag-of-words vectors: same words, same direction.

    sha256 rather than Python's hash(), which is randomised per process and
    would make these tests flaky.
    """

    model_name = "fake-bow-384"

    def __init__(self) -> None:
        self.documents_embedded = 0

    def _vector(self, text: str) -> np.ndarray:
        vector = np.zeros(search.EMBEDDING_DIM, dtype=np.float32)
        for token in re.findall(r"[a-z0-9]+", text.lower()):
            vector[int(hashlib.sha256(token.encode()).hexdigest(), 16) % search.EMBEDDING_DIM] += (
                1.0
            )
        return vector

    def embed_documents(self, texts: list[str]) -> np.ndarray:
        self.documents_embedded += len(texts)
        return np.array([self._vector(t) for t in texts], dtype=np.float32)

    def embed_query(self, text: str) -> np.ndarray:
        return self._vector(text)


KEV_ROWS = [
    (
        "CVE-2023-27997",
        "Fortinet",
        "FortiOS SSL-VPN",
        "Heap overflow",
        "Remote code execution in the SSL VPN.",
    ),
    (
        "CVE-2022-1040",
        "Sophos",
        "Firewall",
        "Authentication bypass",
        "Bypass login on the firewall admin portal.",
    ),
    (
        "CVE-2021-44228",
        "Apache",
        "Log4j",
        "JNDI injection",
        "Remote code execution through log messages.",
    ),
]


@pytest.fixture
def kev_con() -> duckdb.DuckDBPyConnection:
    con = duckdb.connect()
    con.execute("CREATE SCHEMA silver")
    con.execute(
        "CREATE TABLE silver.kev_vulnerabilities "
        "(cve_id VARCHAR, vendor VARCHAR, product VARCHAR, vulnerability_name VARCHAR, description VARCHAR)"
    )
    con.executemany("INSERT INTO silver.kev_vulnerabilities VALUES (?, ?, ?, ?, ?)", KEV_ROWS)
    return con


class TestEmbeddingRefresh:
    def test_sql_column_width_matches_the_model_dimension(self) -> None:
        """The table declares FLOAT[384] as a literal; it must track EMBEDDING_DIM."""
        import inspect

        assert search.EMBEDDING_DIM == 384
        assert f"FLOAT[{search.EMBEDDING_DIM}]" in inspect.getsource(search.refresh_embeddings)

    def test_first_refresh_embeds_everything(self, kev_con: duckdb.DuckDBPyConnection) -> None:
        embedder = FakeEmbedder()
        result = search.refresh_embeddings(kev_con, embedder)
        assert (result.embedded, result.reused, result.removed, result.total) == (3, 0, 0, 3)
        assert embedder.documents_embedded == 3

    def test_unchanged_cves_are_never_re_embedded(self, kev_con: duckdb.DuckDBPyConnection) -> None:
        """The reason for the text hash: embedding everything took 129 seconds here."""
        search.refresh_embeddings(kev_con, FakeEmbedder())
        second = FakeEmbedder()
        result = search.refresh_embeddings(kev_con, second)
        assert (result.embedded, result.reused) == (0, 3)
        assert second.documents_embedded == 0

    def test_changed_text_is_re_embedded_and_removed_cves_are_deleted(
        self, kev_con: duckdb.DuckDBPyConnection
    ) -> None:
        search.refresh_embeddings(kev_con, FakeEmbedder())
        kev_con.execute(
            "UPDATE silver.kev_vulnerabilities SET description = 'Now also exploited by botnets.' "
            "WHERE cve_id = 'CVE-2021-44228'"
        )
        kev_con.execute("DELETE FROM silver.kev_vulnerabilities WHERE cve_id = 'CVE-2022-1040'")

        result = search.refresh_embeddings(kev_con, FakeEmbedder())

        assert (result.embedded, result.removed, result.total) == (1, 1, 2)
        stored = {r[0] for r in kev_con.sql("SELECT cve_id FROM ml.cve_embeddings").fetchall()}
        assert stored == {"CVE-2023-27997", "CVE-2021-44228"}

    def test_switching_models_re_embeds_everything(
        self, kev_con: duckdb.DuckDBPyConnection
    ) -> None:
        """Vectors from different models are not comparable; never mix them."""
        search.refresh_embeddings(kev_con, FakeEmbedder())
        other = FakeEmbedder()
        other.model_name = "a-different-model"
        assert search.refresh_embeddings(kev_con, other).embedded == 3


class TestSearch:
    def test_best_match_ranks_first(self, kev_con: duckdb.DuckDBPyConnection) -> None:
        embedder = FakeEmbedder()
        search.refresh_embeddings(kev_con, embedder)
        index = search.load_index(kev_con, model_name=embedder.model_name)

        hits = search.search("firewall authentication bypass login", index, embedder, k=2)

        assert hits[0].cve_id == "CVE-2022-1040"
        assert len(hits) == 2
        assert hits[0].score >= hits[1].score

    def test_k_larger_than_the_index_returns_everything(
        self, kev_con: duckdb.DuckDBPyConnection
    ) -> None:
        embedder = FakeEmbedder()
        search.refresh_embeddings(kev_con, embedder)
        index = search.load_index(kev_con, model_name=embedder.model_name)
        assert len(search.search("remote code execution", index, embedder, k=50)) == 3

    def test_empty_index_returns_no_hits(self) -> None:
        empty = search.SearchIndex(
            [], [], [], [], [], np.zeros((0, search.EMBEDDING_DIM), dtype=np.float32)
        )
        assert search.search("anything", empty, FakeEmbedder()) == []

    def test_document_text_carries_vendor_product_name_and_description(self) -> None:
        text = search.document_text("Fortinet", "FortiOS", "Heap overflow", "RCE in VPN.")
        assert text == "Fortinet FortiOS: Heap overflow. RCE in VPN."
