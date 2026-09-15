-- ============================================================================
-- stg_cowrie
-- One Bronze row in, one row out: every honeypot event, with the fields worth
-- querying unpacked. Cowrie events share a few fields (session, src_ip) and
-- each event type adds its own, so a field an event does not carry is NULL.
--
-- dst_port is the port INSIDE the container (2222 for SSH, 2223 for Telnet),
-- not the public 22/23. Use `protocol` to tell them apart.
-- ============================================================================

select
    event_id,
    occurred_at,
    ingested_at,
    content_hash,
    collector_host,
    _kafka_offset,

    json_extract_string(payload, '$.eventid')                        as eventid,
    json_extract_string(payload, '$.session')                        as session_id,
    json_extract_string(payload, '$.sensor')                         as sensor,
    json_extract_string(payload, '$.src_ip')                         as src_ip,
    try_cast(json_extract_string(payload, '$.src_port') as integer)  as src_port,
    try_cast(json_extract_string(payload, '$.dst_port') as integer)  as dst_port,
    json_extract_string(payload, '$.protocol')                       as protocol,

    json_extract_string(payload, '$.username')                       as username,
    json_extract_string(payload, '$.password')                       as password,
    json_extract_string(payload, '$.input')                          as command_input,
    json_extract_string(payload, '$.url')                            as download_url,
    json_extract_string(payload, '$.shasum')                         as download_sha256,
    json_extract_string(payload, '$.version')                        as client_version,
    json_extract_string(payload, '$.hassh')                          as hassh,

    -- The current event reference documents `duration_ms`; older Cowrie
    -- releases wrote `duration` in seconds. Accept either, report seconds.
    coalesce(
        try_cast(json_extract_string(payload, '$.duration_ms') as double) / 1000.0,
        try_cast(json_extract_string(payload, '$.duration') as double)
    )                                                                as duration_seconds

from {{ source('bronze', 'cowrie') }}
