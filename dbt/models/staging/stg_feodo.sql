-- ============================================================================
-- stg_feodo
-- One Bronze row in, one row out. Unpack and type only - including any rows
-- that should not be here. Filtering them is a Silver decision, made visibly.
-- ============================================================================

select
    event_id,
    ingested_at,
    content_hash,
    collector_host,
    _kafka_offset,

    json_extract_string(payload, '$.ip_address')               as ip_address,
    try_cast(json_extract_string(payload, '$.port') as integer) as port,
    json_extract_string(payload, '$.status')                   as status,
    json_extract_string(payload, '$.hostname')                 as hostname,
    try_cast(json_extract_string(payload, '$.as_number') as integer) as as_number,
    json_extract_string(payload, '$.as_name')                  as as_name,
    json_extract_string(payload, '$.country')                  as country,
    json_extract_string(payload, '$.malware')                  as malware,
    try_cast(json_extract_string(payload, '$.first_seen') as timestamp) as first_seen,
    try_cast(json_extract_string(payload, '$.last_online') as date)     as last_online

from {{ source('bronze', 'feodo') }}
