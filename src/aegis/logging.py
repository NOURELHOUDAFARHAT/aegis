"""Structured logging for AEGIS.

WHY NOT ``print()`` OR PLAIN ``logging``
----------------------------------------
A data pipeline's logs are themselves a dataset. When a nightly run fails you
need to answer questions like "how many records did the urlhaus collector
reject, per hour, over the last week?". You cannot answer that by grepping
free-text lines like ``Rejected 12 records``.

structlog emits every log line as a JSON object with typed fields, so logs can
be shipped to Loki/Elasticsearch/CloudWatch and *queried*. Locally we render
them as colourful human-readable lines instead, because a JSON blob in a
terminal helps nobody.

This is the same instinct behind Wazuh log normalisation - make the machine
output machine-readable, and let the presentation layer make it pretty.
"""

from __future__ import annotations

import logging
import sys
from typing import Any

import structlog

from aegis.config import settings

_configured = False


def configure_logging(*, force_json: bool | None = None) -> None:
    """Configure structlog once per process.

    Args:
        force_json: Override the automatic choice of renderer. ``None`` means
            human-readable output locally, JSON everywhere else.
    """
    global _configured
    if _configured:
        return

    use_json = force_json if force_json is not None else not settings.is_local

    # Processors run in order on every log event, enriching a dict as they go.
    shared: list[Any] = [
        structlog.contextvars.merge_contextvars,  # request/run-scoped context
        structlog.stdlib.add_log_level,
        # NOTE: we deliberately do NOT use structlog.stdlib.add_logger_name here.
        # That processor reads `logger.name`, which only exists on a standard
        # library logger. We use structlog's own PrintLogger (faster, no global
        # logging config to fight with), which has no such attribute. The module
        # name is bound explicitly in get_logger() instead.
        # ISO-8601 UTC. Never log local time in a pipeline: the moment two
        # machines in two timezones write to the same table, ordering breaks.
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    renderer: Any = (
        structlog.processors.JSONRenderer()
        if use_json
        else structlog.dev.ConsoleRenderer(colors=True)
    )

    structlog.configure(
        processors=[*shared, renderer],
        wrapper_class=structlog.make_filtering_bound_logger(
            logging.getLevelName(settings.log_level)
        ),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        cache_logger_on_first_use=True,
    )
    _configured = True


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Return a logger bound to ``name``.

    Usage::

        log = get_logger(__name__)
        log.info("feed_collected", source="urlhaus", records=1420, duration_s=2.1)

    Note the shape: a short snake_case *event name*, then structured keyword
    fields. Never interpolate values into the message string - that is what
    makes logs unqueryable.
    """
    configure_logging()
    # Bind the module name as a normal field. Because it is bound (not derived
    # from the logger object), it survives into the JSON output and can be
    # filtered on: `logger="aegis.sources.feeds"`.
    return structlog.get_logger().bind(logger=name)  # type: ignore[no-any-return]
