-- ============================================================================
-- silver.honeypot_events  -  one row per real event on the sensor
--
-- Deduplication key: content_hash, not event_id.
--
-- The honeypot collector is at-least-once. If it crashes after sending a batch
-- but before saving its cursor, the next run re-reads the same log lines and
-- sends them again. Each re-sent copy gets a NEW event_id, because event_id is
-- assigned when AEGIS observes the line - so event_id cannot recognise it.
-- But a re-sent line has a byte-identical payload (same session, same
-- timestamp to the microsecond, same fields), so its content_hash matches.
-- Two genuinely different events cannot share one: their timestamps differ.
--
-- Documentation addresses (RFC 5737) are excluded, as in every Silver model:
-- tests and demos use them, and no real attacker can.
-- ============================================================================

with ranked as (

    select
        *,
        row_number() over (
            partition by content_hash
            order by ingested_at, _kafka_offset
        ) as copy_rank

    from {{ ref('stg_cowrie') }}
    where eventid is not null
      and session_id is not null
      and src_ip is not null
      and not {{ is_documentation_address('src_ip') }}

)

select
    content_hash,
    event_id           as source_event_id,
    occurred_at,
    eventid,
    session_id,
    sensor,
    src_ip,
    src_port,
    dst_port,
    protocol,
    username,
    password,
    command_input,
    download_url,
    download_sha256,
    client_version,
    hassh,
    duration_seconds,
    ingested_at        as first_ingested_at

from ranked
where copy_rank = 1
