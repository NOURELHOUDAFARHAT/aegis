"""Semantic search over actively-exploited vulnerabilities, fully offline.

Ask "which exploited vulnerabilities let attackers skip the login screen on
firewalls?" and get the Sophos and PAN-OS authentication bypasses back, even
though neither description uses those words. Keyword search cannot do that.

HOW IT WORKS
------------
Each CVE's vendor, product, name and description are turned into a 384-number
vector by a small local model (BAAI/bge-small-en-v1.5, 65 MB, run through ONNX -
no PyTorch). Texts that mean similar things get vectors pointing in similar
directions, so answering a question is: embed the question, then rank CVEs by
cosine similarity to it.

WHAT IT COSTS ON THIS MACHINE (measured)
----------------------------------------
    model download        36 s, once
    peak memory           517 MB
    embedding 1,709 CVEs  129 s (13 per second)
    one question          32-43 ms once the model is loaded
    stored vectors        2.6 MB

Two minutes to embed everything is too slow to redo on every pipeline run, so
vectors are stored in `ml.cve_embeddings` with a hash of the text they came
from. A refresh embeds only CVEs that are new or whose text changed - a typical
day adds about 14 - and deletes vectors for CVEs that disappeared.

HONEST LIMITS
-------------
On the paraphrased firewall question, 3 of the top 5 results were relevant and
2 were not (a Defender "bypass" and a PAN-OS DNS flaw). Semantic search trades
keyword precision for understanding meaning. Results are ranked evidence to
read, not answers to trust blindly.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

import duckdb
import numpy as np
import pyarrow as pa

MODEL_NAME = "BAAI/bge-small-en-v1.5"
EMBEDDING_DIM = 384


class Embedder(Protocol):
    """Anything that turns text into vectors. Tests supply a fake one."""

    model_name: str

    def embed_documents(self, texts: Sequence[str]) -> np.ndarray: ...

    def embed_query(self, text: str) -> np.ndarray: ...


def model_cache_dir() -> Path:
    """Where the model is downloaded: outside OneDrive, like all regenerable data."""
    from aegis.config import settings

    return Path(settings.data_dir) / "models" / "fastembed"


class FastEmbedEmbedder:
    """The real embedder. The model is loaded on first use, not at import."""

    def __init__(self, model_name: str = MODEL_NAME, cache_dir: Path | None = None) -> None:
        self.model_name = model_name
        self.cache_dir = cache_dir or model_cache_dir()
        self._model: Any = None

    def _load(self) -> Any:
        if self._model is None:
            # Windows without Developer Mode cannot create the symlinks the
            # Hugging Face cache prefers. It falls back to copies, which works,
            # but warns on every load. The progress bars are noise in logs.
            os.environ.setdefault("HF_HUB_DISABLE_SYMLINKS_WARNING", "1")
            os.environ.setdefault("HF_HUB_DISABLE_PROGRESS_BARS", "1")
            import warnings

            # fastembed asks huggingface_hub to show progress bars, which the
            # setting above refuses - with a warning on every model load. The
            # refusal is intended; the warning is noise.
            warnings.filterwarnings("ignore", message="Cannot enable progress bars")
            from fastembed import TextEmbedding

            self.cache_dir.mkdir(parents=True, exist_ok=True)
            self._model = TextEmbedding(model_name=self.model_name, cache_dir=str(self.cache_dir))
        return self._model

    def embed_documents(self, texts: Sequence[str]) -> np.ndarray:
        model = self._load()
        return np.array(list(model.embed(list(texts), batch_size=32)), dtype=np.float32)

    def embed_query(self, text: str) -> np.ndarray:
        # bge models are trained asymmetrically: questions are embedded with a
        # retrieval instruction that documents are not. query_embed applies it.
        model = self._load()
        embed = getattr(model, "query_embed", model.embed)
        row: np.ndarray = np.array(list(embed([text])), dtype=np.float32)[0]
        return row


def document_text(
    vendor: str | None, product: str | None, name: str | None, description: str | None
) -> str:
    """What gets embedded for one CVE."""
    head = " ".join(p for p in (vendor, product) if p)
    return f"{head}: {name or ''}. {description or ''}".strip()


def text_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _normalise_rows(matrix: np.ndarray) -> np.ndarray:
    norms = np.linalg.norm(matrix, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    normalised: np.ndarray = (matrix / norms).astype(np.float32)
    return normalised


@dataclass
class RefreshResult:
    embedded: int
    reused: int
    removed: int
    total: int


def refresh_embeddings(con: duckdb.DuckDBPyConnection, embedder: Embedder) -> RefreshResult:
    """Bring ml.cve_embeddings in line with Silver, embedding only what changed."""
    con.execute("CREATE SCHEMA IF NOT EXISTS ml")
    # FLOAT[384] must match EMBEDDING_DIM; a unit test holds the two together.
    con.execute(
        "CREATE TABLE IF NOT EXISTS ml.cve_embeddings ("
        "cve_id VARCHAR, text_hash VARCHAR, model VARCHAR, "
        "embedding FLOAT[384], embedded_at TIMESTAMPTZ)"
    )

    current = con.sql(
        "SELECT cve_id, vendor, product, vulnerability_name, description FROM silver.kev_vulnerabilities"
    ).fetchall()
    texts = {row[0]: document_text(row[1], row[2], row[3], row[4]) for row in current}
    wanted = {cve: f"{text_hash(text)}|{embedder.model_name}" for cve, text in texts.items()}

    stored = dict(
        con.sql("SELECT cve_id, text_hash || '|' || model FROM ml.cve_embeddings").fetchall()
    )
    to_embed = sorted(cve for cve in texts if stored.get(cve) != wanted[cve])
    to_remove = sorted(cve for cve in stored if cve not in texts)

    new_table = None
    if to_embed:
        vectors = embedder.embed_documents([texts[c] for c in to_embed])
        if vectors.shape != (len(to_embed), EMBEDDING_DIM):
            raise ValueError(
                f"embedder returned {vectors.shape}, expected ({len(to_embed)}, {EMBEDDING_DIM})"
            )
        vectors = _normalise_rows(vectors)
        new_table = pa.table(
            {
                "cve_id": pa.array(to_embed, pa.string()),
                "text_hash": pa.array([text_hash(texts[c]) for c in to_embed], pa.string()),
                "model": pa.array([embedder.model_name] * len(to_embed), pa.string()),
                "embedding": pa.FixedSizeListArray.from_arrays(
                    pa.array(vectors.ravel(), pa.float32()), EMBEDDING_DIM
                ),
                "embedded_at": pa.array(
                    [datetime.now(timezone.utc)] * len(to_embed), pa.timestamp("us", tz="UTC")
                ),
            }
        )

    con.execute("BEGIN TRANSACTION")
    try:
        stale = to_embed + to_remove
        if stale:
            con.execute("DELETE FROM ml.cve_embeddings WHERE list_contains(?, cve_id)", [stale])
        if new_table is not None:
            con.register("_new_embeddings", new_table)
            con.execute("INSERT INTO ml.cve_embeddings SELECT * FROM _new_embeddings")
            con.unregister("_new_embeddings")
        con.execute("COMMIT")
    except Exception:
        con.execute("ROLLBACK")
        raise

    return RefreshResult(
        embedded=len(to_embed),
        reused=len(texts) - len(to_embed),
        removed=len(to_remove),
        total=len(texts),
    )


@dataclass
class SearchIndex:
    cve_ids: list[str]
    vendors: list[str]
    products: list[str]
    names: list[str]
    descriptions: list[str]
    matrix: np.ndarray

    def __len__(self) -> int:
        return len(self.cve_ids)


def load_index(con: duckdb.DuckDBPyConnection, model_name: str = MODEL_NAME) -> SearchIndex:
    """Load stored vectors for the current model, joined to current CVE text."""
    rows = con.execute(
        "SELECT e.cve_id, s.vendor, s.product, s.vulnerability_name, s.description, e.embedding "
        "FROM ml.cve_embeddings e JOIN silver.kev_vulnerabilities s USING (cve_id) "
        "WHERE e.model = ? ORDER BY e.cve_id",
        [model_name],
    ).fetchall()
    matrix = (
        np.array([r[5] for r in rows], dtype=np.float32)
        if rows
        else np.zeros((0, EMBEDDING_DIM), dtype=np.float32)
    )
    return SearchIndex(
        cve_ids=[r[0] for r in rows],
        vendors=[r[1] or "" for r in rows],
        products=[r[2] or "" for r in rows],
        names=[r[3] or "" for r in rows],
        descriptions=[r[4] or "" for r in rows],
        matrix=_normalise_rows(matrix) if rows else matrix,
    )


@dataclass
class SearchHit:
    cve_id: str
    vendor: str
    product: str
    name: str
    description: str
    score: float


def search(question: str, index: SearchIndex, embedder: Embedder, *, k: int = 5) -> list[SearchHit]:
    """The k CVEs whose meaning is closest to the question, best first."""
    if len(index) == 0 or k <= 0:
        return []
    query = embedder.embed_query(question).astype(np.float32)
    norm = float(np.linalg.norm(query))
    if norm > 0:
        query = query / norm
    scores = index.matrix @ query
    top = np.argsort(-scores, kind="stable")[: min(k, len(index))]
    return [
        SearchHit(
            cve_id=index.cve_ids[i],
            vendor=index.vendors[i],
            product=index.products[i],
            name=index.names[i],
            description=index.descriptions[i],
            score=float(scores[i]),
        )
        for i in top
    ]
