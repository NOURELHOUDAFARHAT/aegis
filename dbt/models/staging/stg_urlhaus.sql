-- ============================================================================
-- stg_urlhaus
-- One Bronze row in, one row out. Unpack and type only.
-- ============================================================================

select
    event_id,
    ingested_at,
    -- For URLhaus, occurred_at is the feed's "dateadded": when abuse.ch first
    -- listed the URL. Renamed here so nobody has to remember that mapping.
    occurred_at                                            as listed_at,
    content_hash,
    _kafka_offset,

    json_extract_string(payload, '$.urlhaus_id')           as urlhaus_id,
    json_extract_string(payload, '$.url')                  as url,
    -- The host is what gets blocked on a firewall, and the thing worth
    -- counting: one compromised server often serves hundreds of URLs.
    lower(regexp_extract(
        json_extract_string(payload, '$.url'), '^[a-zA-Z]+://([^/:?#]+)', 1
    ))                                                     as host,
    json_extract_string(payload, '$.url_status')           as url_status,
    json_extract_string(payload, '$.threat')               as threat,
    from_json(json_extract(payload, '$.tags'), '["VARCHAR"]') as tags,
    json_extract_string(payload, '$.reporter')             as reporter,
    json_extract_string(payload, '$.urlhaus_link')         as urlhaus_link

from {{ source('bronze', 'urlhaus') }}
