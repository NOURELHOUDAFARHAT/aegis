"""Campaign detection: grouping URLhaus servers by what they serve.

WHAT THIS DOES, AND WHAT IT CANNOT DO
-------------------------------------
Each URLhaus server is described by the file names it serves, the tags abuse.ch
gave them, and the ports it listens on. Servers that behave almost identically
are grouped with DBSCAN.

The first experiment set expectations honestly (docs/adr/0008):

* About 9% of servers form campaigns. The rest are generic IoT droppers serving
  the same `/i` and `/bin.sh` from thousands of unrelated machines. Behaviour
  alone cannot tell those operators apart, and DBSCAN leaves them unclustered
  instead of inventing groups - which is why it was chosen over k-means, which
  would have forced every server into some cluster.
* The campaigns it does find hold up against something the model never sees.
  In the 2026-09-14 run, 503 of 5,295 servers (9.5%) formed 66 campaigns, and
  servers in the same campaign shared a /24 subnet 8.6% of the time versus 0.1%
  for random pairs - 131x more often. Recognisable campaigns included a Mirai
  dropper kit serving seven CPU architectures (23 servers, 350 URLs), a
  ScreenConnect remote-access installer campaign (20 servers) and a PowerShell
  "crypted.ps1" campaign (17 servers). An exploratory script written before
  this module grouped servers somewhat differently; the figures here are the
  module's own.

WHY THE SUBNET IS A CHECK, NOT A FEATURE
----------------------------------------
Adding the /24 as a feature would make clusters line up with subnets by
construction, and the validation would prove nothing. Keeping network location
out of the model is what makes agreement with it evidence.
"""

from __future__ import annotations

import random
import re
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone

import duckdb
import pyarrow as pa

DEFAULT_EPS = 0.35
DEFAULT_MIN_SERVERS = 5

_PORT_RE = re.compile(r"^[a-zA-Z]+://[^/:?#]+:([0-9]+)")
_PATH_RE = re.compile(r"/([^/?#]*)(?:[?#].*)?$")
_IPV4_RE = re.compile(r"^[0-9]{1,3}(?:\.[0-9]{1,3}){3}$")


@dataclass
class ServerProfile:
    """Everything the model knows about one server."""

    host: str
    paths: set[str] = field(default_factory=set)
    tags: set[str] = field(default_factory=set)
    ports: set[str] = field(default_factory=set)
    urls: int = 0
    online_urls: int = 0


def url_port(url: str) -> str:
    """The port a URL points at, defaulting by scheme."""
    match = _PORT_RE.match(url)
    if match:
        return match.group(1)
    return "443" if url.lower().startswith("https") else "80"


def url_path_ending(url: str) -> str:
    """The last path segment: the file being served.

    `http://1.2.3.4:8080/bin.sh` -> `bin.sh`. A URL ending in `/` has no file
    name and is recorded as `(root)` rather than an empty string, so it stays a
    visible, countable token.
    """
    after_host = re.sub(r"^[a-zA-Z]+://[^/]+", "", url)
    match = _PATH_RE.search(after_host)
    ending = match.group(1) if match else ""
    return ending or "(root)"


def subnet_24(host: str) -> str | None:
    """The /24 network of an IPv4 host, or None for a domain name."""
    if not _IPV4_RE.match(host):
        return None
    return ".".join(host.split(".")[:3])


def build_profiles(
    rows: Iterable[tuple[str, str, list[str] | None, bool]],
) -> dict[str, ServerProfile]:
    """Aggregate URL rows `(url, host, tags, is_online)` into one profile per server."""
    profiles: dict[str, ServerProfile] = {}
    for url, host, tags, online in rows:
        profile = profiles.setdefault(host, ServerProfile(host=host))
        profile.urls += 1
        profile.online_urls += int(bool(online))
        profile.ports.add(url_port(url))
        profile.paths.add(url_path_ending(url))
        for tag in tags or []:
            profile.tags.add(tag.lower())
    return profiles


def profile_tokens(profile: ServerProfile) -> list[str]:
    """The behaviour a server exhibits, as prefixed tokens.

    Prefixes keep namespaces apart: a file literally named `mirai` and the tag
    `mirai` are different evidence and must not merge into one token.
    """
    tokens = (
        [f"path={p}" for p in sorted(profile.paths)]
        + [f"tag={t}" for t in sorted(profile.tags)]
        + [f"port={p}" for p in sorted(profile.ports)]
    )
    return [t.replace(" ", "_") for t in tokens]


def cluster_servers(
    profiles: dict[str, ServerProfile],
    *,
    eps: float = DEFAULT_EPS,
    min_servers: int = DEFAULT_MIN_SERVERS,
) -> dict[str, int]:
    """Assign each server a campaign id, or -1 when it belongs to none.

    Campaign ids are renumbered 1..k by campaign size (largest first, ties
    broken by the smallest host name), so the same data always yields the same
    ids and campaign 1 is always the biggest.
    """
    hosts = sorted(profiles)
    if len(hosts) < min_servers:
        return dict.fromkeys(hosts, -1)

    import sklearn
    from sklearn.cluster import DBSCAN
    from sklearn.feature_extraction.text import TfidfVectorizer

    docs = [" ".join(profile_tokens(profiles[h])) for h in hosts]
    vectorizer = TfidfVectorizer(
        token_pattern=r"[^ ]+",  # noqa: S106 - a regex that splits on spaces, not a credential
        binary=True,
        lowercase=False,
    )
    matrix = vectorizer.fit_transform(docs)

    # Cosine DBSCAN on sparse input computes neighbourhoods in chunks. The
    # default chunk budget is 1 GB, which on an 8 GB laptop with little free
    # memory turns into heavy paging. 64 MB chunks are slower per chunk and far
    # faster overall here.
    with sklearn.config_context(working_memory=64):
        raw = DBSCAN(eps=eps, min_samples=min_servers, metric="cosine").fit_predict(matrix)

    members: dict[int, list[str]] = defaultdict(list)
    for host, label in zip(hosts, raw, strict=True):
        if label != -1:
            members[int(label)].append(host)

    ranked = sorted(members.items(), key=lambda kv: (-len(kv[1]), min(kv[1])))
    renumber = {raw_label: rank for rank, (raw_label, _) in enumerate(ranked, start=1)}
    return {
        host: (renumber[int(label)] if label != -1 else -1)
        for host, label in zip(hosts, raw, strict=True)
    }


@dataclass
class Coherence:
    """How often servers in the same campaign share a /24, versus random pairs."""

    within_rate: float
    random_rate: float
    within_pairs: int
    random_pairs: int

    @property
    def lift(self) -> float | None:
        return self.within_rate / self.random_rate if self.random_rate > 0 else None


def subnet_coherence(
    labels: dict[str, int], *, seed: int = 7, max_pairs_per_campaign: int = 200
) -> Coherence:
    """External validation: do behaviourally similar servers sit in the same network?

    Pairs are sampled within each campaign and, as a baseline, uniformly from
    all servers. Only pairs where both hosts are IPv4 addresses count, since a
    domain name has no /24.
    """
    rng = random.Random(seed)  # noqa: S311 - reproducible sampling, not security
    hosts = sorted(labels)
    subnets = {h: subnet_24(h) for h in hosts}

    by_campaign: dict[int, list[str]] = defaultdict(list)
    for host in hosts:
        if labels[host] != -1:
            by_campaign[labels[host]].append(host)

    within: list[tuple[str, str]] = []
    for members in by_campaign.values():
        if len(members) < 2:
            continue
        for _ in range(min(max_pairs_per_campaign, len(members) * (len(members) - 1) // 2)):
            a, b = rng.sample(members, 2)
            within.append((a, b))

    baseline: list[tuple[str, str]] = []
    if len(hosts) >= 2:
        for _ in range(len(within)):
            a, b = rng.sample(hosts, 2)
            baseline.append((a, b))

    def rate(pairs: list[tuple[str, str]]) -> tuple[float, int]:
        usable = [(a, b) for a, b in pairs if subnets[a] and subnets[b]]
        if not usable:
            return 0.0, 0
        return sum(subnets[a] == subnets[b] for a, b in usable) / len(usable), len(usable)

    within_rate, within_n = rate(within)
    random_rate, random_n = rate(baseline)
    return Coherence(within_rate, random_rate, within_n, random_n)


@dataclass
class Campaign:
    campaign_id: int
    servers: int
    urls: int
    online_urls: int
    distinct_subnets: int
    top_tags: list[str]
    top_paths: list[str]


def summarise(
    profiles: dict[str, ServerProfile], labels: dict[str, int], *, top: int = 3
) -> list[Campaign]:
    """One summary per campaign, largest first."""
    by_campaign: dict[int, list[ServerProfile]] = defaultdict(list)
    for host, label in labels.items():
        if label != -1:
            by_campaign[label].append(profiles[host])

    campaigns = []
    for campaign_id, members in by_campaign.items():
        tags = Counter(t for p in members for t in p.tags)
        paths = Counter(x for p in members for x in p.paths)
        campaigns.append(
            Campaign(
                campaign_id=campaign_id,
                servers=len(members),
                urls=sum(p.urls for p in members),
                online_urls=sum(p.online_urls for p in members),
                distinct_subnets=len({s for p in members if (s := subnet_24(p.host))}),
                top_tags=[t for t, _ in tags.most_common(top)],
                top_paths=[x for x, _ in paths.most_common(top)],
            )
        )
    return sorted(campaigns, key=lambda c: c.campaign_id)


@dataclass
class CampaignRun:
    servers: int
    clustered_servers: int
    campaigns: int
    coherence: Coherence
    eps: float
    min_servers: int

    @property
    def coverage(self) -> float:
        return self.clustered_servers / self.servers if self.servers else 0.0


def run(
    con: duckdb.DuckDBPyConnection,
    *,
    eps: float = DEFAULT_EPS,
    min_servers: int = DEFAULT_MIN_SERVERS,
) -> CampaignRun:
    """Read Silver, detect campaigns, and write ml.url_campaigns and ml.url_campaign_servers."""
    rows = con.sql("SELECT url, host, tags, is_online FROM silver.urlhaus_urls").fetchall()
    profiles = build_profiles(rows)
    labels = cluster_servers(profiles, eps=eps, min_servers=min_servers)
    campaigns = summarise(profiles, labels)
    coherence = subnet_coherence(labels)

    built_at = datetime.now(timezone.utc)
    campaign_table = pa.table(
        {
            "campaign_id": pa.array([c.campaign_id for c in campaigns], pa.int32()),
            "servers": pa.array([c.servers for c in campaigns], pa.int32()),
            "urls": pa.array([c.urls for c in campaigns], pa.int32()),
            "online_urls": pa.array([c.online_urls for c in campaigns], pa.int32()),
            "distinct_subnets": pa.array([c.distinct_subnets for c in campaigns], pa.int32()),
            "top_tags": pa.array([c.top_tags for c in campaigns], pa.list_(pa.string())),
            "top_paths": pa.array([c.top_paths for c in campaigns], pa.list_(pa.string())),
            "built_at": pa.array([built_at] * len(campaigns), pa.timestamp("us", tz="UTC")),
        }
    )
    clustered = sorted(h for h, label in labels.items() if label != -1)
    server_table = pa.table(
        {
            "host": pa.array(clustered, pa.string()),
            "campaign_id": pa.array([labels[h] for h in clustered], pa.int32()),
            "subnet_24": pa.array([subnet_24(h) for h in clustered], pa.string()),
            "urls": pa.array([profiles[h].urls for h in clustered], pa.int32()),
            "online_urls": pa.array([profiles[h].online_urls for h in clustered], pa.int32()),
        }
    )

    con.execute("CREATE SCHEMA IF NOT EXISTS ml")
    con.register("_campaigns", campaign_table)
    con.register("_campaign_servers", server_table)
    try:
        con.execute("BEGIN TRANSACTION")
        con.execute("CREATE OR REPLACE TABLE ml.url_campaigns AS SELECT * FROM _campaigns")
        con.execute(
            "CREATE OR REPLACE TABLE ml.url_campaign_servers AS SELECT * FROM _campaign_servers"
        )
        con.execute("COMMIT")
    except Exception:
        con.execute("ROLLBACK")
        raise
    finally:
        con.unregister("_campaigns")
        con.unregister("_campaign_servers")

    return CampaignRun(
        servers=len(profiles),
        clustered_servers=len(clustered),
        campaigns=len(campaigns),
        coherence=coherence,
        eps=eps,
        min_servers=min_servers,
    )
