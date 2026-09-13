"""The Iceberg catalog: the thing that knows where every table is.

WHAT PROBLEM A CATALOG SOLVES
-----------------------------
An Iceberg table is not a file. It is a *folder full of files* plus a chain of
metadata describing which files currently belong to the table:

    s3://aegis-lakehouse/bronze.db/urlhaus/
        data/                      <- Parquet files, many of them
        metadata/
            v1.metadata.json       <- table as of the 1st commit
            v2.metadata.json       <- table as of the 2nd commit
            snap-...avro           <- which data files each snapshot contains

Every write appends new files and writes a NEW metadata file. Nothing is
edited in place. So the only genuinely mutable fact in the whole system is the
answer to one question: **which metadata file is current?**

That single pointer is what the catalog stores. It is also what makes writes
atomic: a writer prepares all its files, then swaps the pointer in one
transaction. A reader either sees the old pointer or the new one, never a
half-written table. That is the whole ACID story, and it is why we can query a
table while it is being written to.

WHY POSTGRES HOLDS THE POINTER
------------------------------
The pointer needs a home that supports an atomic compare-and-swap. Options:

    SqlCatalog (Postgres)  <- ours. Any SQL database. Portable, simple.
    AWS Glue               <- the managed AWS option (Phase 9)
    REST catalog           <- a small service; what Snowflake/Databricks expose
    Hive Metastore         <- the old standard; needs a JVM

We use Postgres because the container is already running, it is genuinely
production-viable, and moving to Glue later changes only this file.
"""

from __future__ import annotations

from functools import lru_cache
from urllib.parse import quote

from pyiceberg.catalog import Catalog
from pyiceberg.catalog.sql import SqlCatalog

from aegis.config import settings
from aegis.logging import get_logger

log = get_logger(__name__)

# Namespaces are the lakehouse equivalent of database schemas. Splitting the
# medallion layers into three keeps permissions and lifecycle separable later:
# Bronze is append-only and long-lived; Silver and Gold are rebuildable.
NAMESPACE_BRONZE = "bronze"
NAMESPACE_SILVER = "silver"
NAMESPACE_GOLD = "gold"
ALL_NAMESPACES = (NAMESPACE_BRONZE, NAMESPACE_SILVER, NAMESPACE_GOLD)


def catalog_uri() -> str:
    """Build the SQLAlchemy URL for the catalog's Postgres connection.

    Two details worth noticing:

    * ``search_path=iceberg_catalog`` puts the catalog's own bookkeeping tables
      in their own schema instead of scattering them through ``public``. The
      catalog is infrastructure, not application data, and it should look like
      it.
    * The password is URL-quoted. A password containing ``@`` or ``/`` would
      otherwise silently corrupt the connection string - a genuinely common and
      very confusing production failure.
    """
    db = settings.database
    return (
        f"postgresql+psycopg://{quote(db.pg_user)}:{quote(db.pg_password)}"
        f"@{db.pg_host}:{db.pg_port}/{db.pg_database}"
        f"?options=-csearch_path%3Diceberg_catalog"
    )


@lru_cache(maxsize=1)
def get_catalog() -> Catalog:
    """Return the shared Iceberg catalog.

    Cached because building one opens a database connection pool, and every
    part of the system should be looking at the same catalog instance.
    """
    catalog = SqlCatalog(
        settings.catalog_name,
        **{
            "uri": catalog_uri(),
            # Where table files live. Change this one line, plus the endpoint
            # below, and the entire lakehouse is on AWS S3 instead of MinIO.
            "warehouse": f"s3://{settings.storage.lake_bucket}/",
            # PyIceberg reaches S3 through PyArrow's S3FileSystem. Note there is
            # no "path-style" option here: PyArrow uses path-style addressing by
            # default (bucket in the URL path), which is exactly what MinIO
            # needs. Real AWS accepts it too, so nothing changes in Phase 9.
            "s3.endpoint": settings.storage.s3_endpoint,
            "s3.access-key-id": settings.storage.s3_access_key,
            "s3.secret-access-key": settings.storage.s3_secret_key,
            "s3.region": settings.storage.s3_region,
        },
    )
    log.debug(
        "catalog_ready",
        name=settings.catalog_name,
        warehouse=settings.storage.lake_bucket,
    )
    return catalog


def ensure_namespaces() -> list[str]:
    """Create the bronze/silver/gold namespaces. Idempotent.

    Returns the namespaces that exist afterwards.
    """
    catalog = get_catalog()
    for namespace in ALL_NAMESPACES:
        catalog.create_namespace_if_not_exists(namespace)
    existing = [".".join(ns) for ns in catalog.list_namespaces()]
    log.info("namespaces_ready", namespaces=existing)
    return existing


def reset_catalog_cache() -> None:
    """Drop the cached catalog. For tests, and after a config change."""
    get_catalog.cache_clear()
