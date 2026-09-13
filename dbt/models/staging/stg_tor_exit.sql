-- ============================================================================
-- stg_tor_exit
-- The Tor list is a bare list of IPs with no timestamps of its own, so each
-- collection run is a snapshot: "these were exit nodes at ingested_at".
-- ============================================================================

select
    event_id,
    ingested_at,
    content_hash,
    _kafka_offset,
    json_extract_string(payload, '$.ip_address') as ip_address

from {{ source('bronze', 'tor_exit') }}
