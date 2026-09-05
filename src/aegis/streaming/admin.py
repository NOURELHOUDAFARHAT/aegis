"""Creating and inspecting topics on the broker.

This module turns the declarations in `topics.py` into real topics, and can
report on what actually exists. It is written to be **idempotent**: running it
ten times is the same as running it once. That property is what lets it run
automatically at startup, in CI, and on a teammate's fresh machine without
anyone having to remember whether it has been done already.
"""

from __future__ import annotations

from dataclasses import dataclass

from confluent_kafka.admin import AdminClient, ConfigResource, NewTopic

from aegis.config import settings
from aegis.logging import get_logger
from aegis.streaming.topics import LOCAL_REPLICATION_FACTOR, TopicSpec, all_specs

log = get_logger(__name__)


@dataclass
class TopicStatus:
    """What the broker currently reports about one topic."""

    name: str
    exists: bool
    partitions: int = 0
    replication_factor: int = 0
    retention_hours: float | None = None
    message_count: int | None = None


def get_admin() -> AdminClient:
    """Build an admin client pointed at the configured broker."""
    return AdminClient({"bootstrap.servers": settings.kafka.kafka_bootstrap})


def create_topics(*, dry_run: bool = False) -> dict[str, str]:
    """Create every declared topic that does not already exist.

    Returns a mapping of topic name to outcome: 'created', 'exists', or an
    error message.

    IDEMPOTENCY, CONCRETELY
    We ask the broker what exists first, and only create what is missing. Even
    so, we still handle "topic already exists" as a success rather than an
    error - because between our check and our create, another process could
    have created it. Treating that race as a failure would make startup flaky
    for no reason. Designing for "someone else may have done it already" is
    what distinguishes automation from a script.
    """
    admin = get_admin()
    existing = set(admin.list_topics(timeout=10).topics.keys())
    results: dict[str, str] = {}

    to_create: list[NewTopic] = []
    for spec in all_specs():
        if spec.name in existing:
            results[spec.name] = "exists"
            continue
        if dry_run:
            results[spec.name] = "would create"
            continue
        to_create.append(
            NewTopic(
                topic=spec.name,
                num_partitions=spec.partitions,
                replication_factor=LOCAL_REPLICATION_FACTOR,
                config=spec.broker_config(),
            )
        )

    if not to_create:
        return results

    # create_topics returns a dict of futures - the call is asynchronous, and
    # each topic succeeds or fails independently. We must wait on each one, or
    # we would report success before the broker had done anything.
    futures = admin.create_topics(to_create, request_timeout=30)
    for name, future in futures.items():
        try:
            future.result(timeout=30)
            results[name] = "created"
            log.info("topic_created", topic=name)
        except Exception as exc:
            message = str(exc)
            if "already exists" in message.lower():
                results[name] = "exists"  # lost the race; that is fine
            else:
                results[name] = f"error: {message[:120]}"
                log.error("topic_create_failed", topic=name, error=message[:200])

    return results


def describe_topics() -> list[TopicStatus]:
    """Report what the broker actually has, not what we declared.

    The distinction matters. A topic created months ago with different settings
    will not be corrected by create_topics() - Kafka does not reconcile
    configuration the way Terraform does. This function is how you notice the
    drift.
    """
    admin = get_admin()
    metadata = admin.list_topics(timeout=10)
    statuses: list[TopicStatus] = []

    for spec in all_specs():
        topic_meta = metadata.topics.get(spec.name)
        if topic_meta is None or topic_meta.error is not None:
            statuses.append(TopicStatus(name=spec.name, exists=False))
            continue

        partitions = len(topic_meta.partitions)
        replication = len(next(iter(topic_meta.partitions.values())).replicas) if partitions else 0

        retention_hours: float | None = None
        try:
            resource = ConfigResource(ConfigResource.Type.TOPIC, spec.name)
            config = admin.describe_configs([resource])[resource].result(timeout=10)
            retention_ms = config.get("retention.ms")
            if retention_ms is not None and retention_ms.value not in (None, "-1"):
                retention_hours = int(retention_ms.value) / 3_600_000
        except Exception as exc:
            log.debug("describe_config_failed", topic=spec.name, error=str(exc)[:120])

        statuses.append(
            TopicStatus(
                name=spec.name,
                exists=True,
                partitions=partitions,
                replication_factor=replication,
                retention_hours=retention_hours,
                message_count=count_messages(spec.name),
            )
        )

    return statuses


def count_messages(topic: str) -> int | None:
    """Count records currently retained in a topic.

    HOW THIS WORKS, AND WHY IT IS AN ESTIMATE
    Kafka has no "SELECT count(*)". Each partition exposes two offsets: the
    low watermark (oldest record still retained) and the high watermark (next
    offset to be written). Their difference is the number of records retained
    in that partition.

    It is an estimate rather than a truth for two reasons: records deleted by
    retention are excluded, and on a compacted topic the gap between offsets
    includes records that were compacted away. For our delete-policy topics it
    is accurate enough to answer "did anything actually arrive?", which is the
    question we ask it.
    """
    from confluent_kafka import Consumer, TopicPartition

    consumer = Consumer(
        {
            "bootstrap.servers": settings.kafka.kafka_bootstrap,
            # A throwaway group id: this consumer must never join a real group
            # and disturb its partition assignment.
            "group.id": "aegis-admin-count",
            "enable.auto.commit": False,
        }
    )
    try:
        metadata = consumer.list_topics(topic, timeout=10)
        topic_meta = metadata.topics.get(topic)
        if topic_meta is None or topic_meta.error is not None:
            return None

        total = 0
        for partition_id in topic_meta.partitions:
            low, high = consumer.get_watermark_offsets(
                TopicPartition(topic, partition_id), timeout=10, cached=False
            )
            total += high - low
        return total
    except Exception as exc:
        log.debug("count_failed", topic=topic, error=str(exc)[:120])
        return None
    finally:
        consumer.close()


def delete_topics(names: list[str]) -> dict[str, str]:
    """Delete topics. Destructive: every retained record goes with them.

    Exists so `aegis topics reset` can give a clean slate while learning. It is
    deliberately NOT wired into any automated path.
    """
    admin = get_admin()
    results: dict[str, str] = {}
    futures = admin.delete_topics(names, request_timeout=30)
    for name, future in futures.items():
        try:
            future.result(timeout=30)
            results[name] = "deleted"
            log.warning("topic_deleted", topic=name)
        except Exception as exc:
            results[name] = f"error: {str(exc)[:120]}"
    return results


def _spec_by_name(name: str) -> TopicSpec | None:
    return next((s for s in all_specs() if s.name == name), None)


# ---------------------------------------------------------------------------
# Schema Registry compatibility
# ---------------------------------------------------------------------------
# The registry's default is BACKWARD, and that default is wrong for AEGIS.
#
#   BACKWARD means "a NEW reader can read OLD data". It therefore permits
#   DELETING a field, because a reader that no longer knows about a field just
#   ignores it.
#
# That is fine when producers and consumers ship together. Ours do not. The
# Bronze writer, the dashboard and the ML scorer are separate processes,
# deployed at different times. If a producer deletes a field and ships first,
# every consumer still expecting that field gets nothing - and Avro fills it in
# as absent rather than raising. Silent wrong data, exactly what the schema was
# supposed to prevent.
#
#   FULL means "new reads old AND old reads new". Fields can only be added or
#   removed WITH a default, so a reader on either side of a deploy always has a
#   defined value.
#
# The cost is real: FULL is stricter, and it will occasionally block a change
# you wanted to make quickly. That is the point. Making a breaking change
# inconvenient is the entire value of the setting.
# ---------------------------------------------------------------------------
COMPATIBILITY_LEVEL = "FULL"


def ensure_compatibility(level: str = COMPATIBILITY_LEVEL) -> str:
    """Set the registry's global compatibility level. Idempotent.

    Returns the level in force after the call.
    """
    from confluent_kafka.schema_registry import SchemaRegistryClient

    client = SchemaRegistryClient({"url": settings.kafka.schema_registry_url})
    current = client.get_compatibility()
    if current == level:
        log.debug("compatibility_already_set", level=level)
        return str(current)

    client.set_compatibility(level=level)
    after = client.get_compatibility()
    log.info("compatibility_set", was=current, now=after)
    return str(after)
