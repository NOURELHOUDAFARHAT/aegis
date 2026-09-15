"""Evaluate CVE search: keyword vs semantic vs hybrid, on questions with known answers.

Run with:  python scripts/eval_search.py      (needs `aegis ml embed` first)

WHY THIS SCRIPT EXISTS
----------------------
The first comparison, run ad hoc, reported keyword search ahead of semantic
(mean precision@5 0.56 vs 0.44). It was biased: two of its "paraphrased"
questions contained words that also appeared in the rule defining the correct
answers ("file transfer", "word"), which handed keyword search a shortcut.

This is the corrected evaluation, committed so the numbers can be reproduced:

  * Correct answers come from Silver's structured fields (vendor, product,
    vulnerability name) - defined independently of both search methods.
  * Paraphrased questions share NO words with their answer rule. The `leak`
    column verifies that for every question.
  * One keyword question is kept as a control.
  * Hybrid search (reciprocal rank fusion of both rankings) is measured too,
    rather than assumed to be better.

RESULT ON 2026-09-14 (1,709 CVEs)
---------------------------------
    mean precision@5, 7 paraphrases:  keyword 0.14   semantic 0.46   hybrid 0.23
    keyword control:                  keyword 0.80   semantic 0.80   hybrid 0.80

Semantic search wins on questions phrased in everyday words. Hybrid is WORSE
than semantic alone: on paraphrases the keyword ranking is mostly noise, and
fusion gives it equal weight. Two questions defeated every method. Seven
questions is a small sample; treat this as evidence, not proof.

Results are also logged to MLflow (experiment aegis-cve-search, run "evaluation").
"""

from __future__ import annotations

import os
import sys
import warnings

os.environ.setdefault("HF_HUB_DISABLE_PROGRESS_BARS", "1")
warnings.filterwarnings("ignore", message="Cannot enable progress bars")

import aegis  # noqa: F401, E402 - must be imported before PyArrow (Windows runtime fix)

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from collections.abc import Callable  # noqa: E402

import duckdb  # noqa: E402
import numpy as np  # noqa: E402
from sklearn.feature_extraction.text import TfidfVectorizer  # noqa: E402

from aegis.ml import search  # noqa: E402
from aegis.modeling.dbt_runner import warehouse_path  # noqa: E402

K = 5
FUSION_DEPTH = 50
RRF_K = 60

APPLIANCE_VENDORS = {
    "Fortinet", "Palo Alto Networks", "SonicWall", "Sophos", "Cisco", "Check Point",
    "Zyxel", "Juniper", "Citrix", "Ivanti", "F5", "WatchGuard",
}  # fmt: skip


def has(text: str, *terms: str) -> bool:
    lowered = text.lower()
    return any(term in lowered for term in terms)


Row = tuple[str, str, str, str, str]
Predicate = Callable[[str, str, str, str], bool]

# (kind, question, answer rule, words the rule relies on - checked for leakage)
QUERIES: list[tuple[str, str, Predicate, list[str]]] = [
    (
        "keyword",
        "Fortinet VPN remote code execution",
        lambda v, p, n, d: v == "Fortinet" and has(p + n + d, "vpn"),
        ["fortinet", "vpn"],
    ),
    (
        "paraphrase",
        "attackers skip the login screen on network firewall appliances",
        lambda v, p, n, d: v in APPLIANCE_VENDORS and has(n + " " + d, "authentication bypass"),
        ["authentication", "bypass"],
    ),
    (
        "paraphrase",
        "a booby-trapped spreadsheet opened by an employee runs attacker code",
        lambda v, p, n, d: v == "Microsoft" and has(p + " " + n, "office", "excel", "word"),
        ["office", "excel", "word"],
    ),
    (
        "paraphrase",
        "breaches of tools companies use to send large files to partners",
        lambda v, p, n, d: has(
            p + " " + n + " " + d,
            "moveit",
            "goanywhere",
            "file transfer",
            "cleo",
            "accellion",
            "crushftp",
        ),
        ["moveit", "goanywhere", "file transfer", "cleo", "accellion", "crushftp"],
    ),
    (
        "paraphrase",
        "breaking into a company mail system hosted on its own premises",
        lambda v, p, n, d: has(p + " " + n, "exchange", "zimbra", "roundcube", "mdaemon"),
        ["exchange", "zimbra", "roundcube", "mdaemon"],
    ),
    (
        "paraphrase",
        "abusing software help desks use to take over employee computers",
        lambda v, p, n, d: has(
            p + " " + n,
            "screenconnect",
            "connectwise",
            "anydesk",
            "teamviewer",
            "kaseya",
            "simplehelp",
            "beyondtrust",
            "bomgar",
        ),
        [
            "screenconnect",
            "connectwise",
            "anydesk",
            "teamviewer",
            "kaseya",
            "simplehelp",
            "beyondtrust",
            "bomgar",
        ],
    ),
    (
        "paraphrase",
        "escaping from a guest machine to the host running many virtual servers",
        lambda v, p, n, d: (
            (v == "VMware" and has(p + " " + n, "esxi", "vcenter", "workstation", "fusion"))
            or has(p + " " + n, "hyper-v")
        ),
        ["vmware", "esxi", "vcenter", "workstation", "fusion", "hyper-v"],
    ),
    (
        "paraphrase",
        "visiting a malicious web page is enough to take control",
        lambda v, p, n, d: has(
            p, "chrome", "chromium", "firefox", "safari", "edge", "internet explorer", "webkit"
        ),
        ["chrome", "chromium", "firefox", "safari", "edge", "internet explorer", "webkit"],
    ),
]


def main() -> None:
    con = duckdb.connect(str(warehouse_path()), read_only=True)
    index = search.load_index(con)
    rows: list[Row] = con.sql(
        "SELECT cve_id, vendor, product, vulnerability_name, description FROM silver.kev_vulnerabilities"
    ).fetchall()
    con.close()
    if len(index) == 0:
        raise SystemExit("The embedding index is empty. Run:  aegis ml embed")

    documents = [
        search.document_text(
            index.vendors[i], index.products[i], index.names[i], index.descriptions[i]
        )
        for i in range(len(index))
    ]
    tfidf = TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, stop_words="english")
    doc_matrix = tfidf.fit_transform(documents)
    embedder = search.FastEmbedEmbedder()

    def keyword_rank(question: str) -> list[str]:
        scores = (doc_matrix @ tfidf.transform([question]).T).toarray().ravel()
        return [index.cve_ids[i] for i in np.argsort(-scores, kind="stable")[:FUSION_DEPTH]]

    def semantic_rank(question: str) -> list[str]:
        return [hit.cve_id for hit in search.search(question, index, embedder, k=FUSION_DEPTH)]

    def hybrid_rank(question: str) -> list[str]:
        fused: dict[str, float] = {}
        for ranking in (keyword_rank(question), semantic_rank(question)):
            for position, cve in enumerate(ranking, start=1):
                fused[cve] = fused.get(cve, 0.0) + 1.0 / (RRF_K + position)
        return sorted(fused, key=lambda cve: -fused[cve])

    print(f"index: {len(index):,} CVEs\n")
    print(f"{'type':10} {'rel':>4} {'leak':>5} {'kw':>5} {'sem':>5} {'hyb':>5}  question")
    totals: dict[str, dict[str, float]] = {
        kind: {"keyword": 0.0, "semantic": 0.0, "hybrid": 0.0, "n": 0.0}
        for kind in ("keyword", "paraphrase")
    }
    for kind, question, rule, answer_terms in QUERIES:
        relevant = {r[0] for r in rows if rule(r[1] or "", r[2] or "", r[3] or "", r[4] or "")}
        leak = any(term in question.lower() for term in answer_terms)
        if kind == "paraphrase" and leak:
            raise SystemExit(
                f"Evaluation is invalid: paraphrase shares an answer word: {question!r}"
            )
        if not relevant:
            print(f"{kind:10} {0:>4}   skipped - rule matched nothing: {question}")
            continue
        denominator = min(K, len(relevant))
        scores = {
            "keyword": len(set(keyword_rank(question)[:K]) & relevant) / denominator,
            "semantic": len(set(semantic_rank(question)[:K]) & relevant) / denominator,
            "hybrid": len(set(hybrid_rank(question)[:K]) & relevant) / denominator,
        }
        for method, value in scores.items():
            totals[kind][method] += value
        totals[kind]["n"] += 1
        print(
            f"{kind:10} {len(relevant):>4} {'YES' if leak else 'no':>5} "
            f"{scores['keyword']:>5.2f} {scores['semantic']:>5.2f} {scores['hybrid']:>5.2f}  {question}"
        )

    metrics: dict[str, float] = {}
    print()
    for kind, t in totals.items():
        if not t["n"]:
            continue
        means = {method: t[method] / t["n"] for method in ("keyword", "semantic", "hybrid")}
        print(
            f"mean precision@{K}, {kind:10} ({int(t['n'])} question(s)): "
            f"keyword {means['keyword']:.2f}  semantic {means['semantic']:.2f}  hybrid {means['hybrid']:.2f}"
        )
        metrics.update({f"p{K}_{kind}_{method}": value for method, value in means.items()})

    from aegis.ml.tracking import EXPERIMENT_SEARCH, track

    with track(EXPERIMENT_SEARCH, "evaluation") as run:
        run.params(
            {"k": K, "questions": len(QUERIES), "fusion": f"rrf k={RRF_K}, depth {FUSION_DEPTH}"}
        )
        run.metrics(metrics)
    print("\nlogged to MLflow experiment", EXPERIMENT_SEARCH)


if __name__ == "__main__":
    main()
