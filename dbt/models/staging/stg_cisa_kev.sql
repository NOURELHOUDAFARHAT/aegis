-- ============================================================================
-- stg_cisa_kev
--
-- Staging does exactly two things: unpack the JSON payload into real columns,
-- and give each column the right type. It does NOT filter or deduplicate -
-- one Bronze row in, one staging row out. Keeping staging that dumb means a
-- surprising number in Silver can always be traced to either "the feed sent
-- it" or "a Silver rule changed it", never to a hidden rule in between.
-- ============================================================================

select
    -- provenance: carried through so any row can be traced back to Kafka
    event_id,
    ingested_at,
    occurred_at,
    content_hash,
    _kafka_offset,

    json_extract_string(payload, '$.cve_id')          as cve_id,
    json_extract_string(payload, '$.vendor')          as vendor,
    json_extract_string(payload, '$.product')         as product,
    json_extract_string(payload, '$.name')            as vulnerability_name,
    json_extract_string(payload, '$.description')     as description,
    json_extract_string(payload, '$.required_action') as required_action,

    -- try_cast returns NULL instead of failing the whole build on one bad
    -- date. A NULL is then caught by a not_null test in Silver, which names
    -- the problem instead of crashing on it.
    try_cast(json_extract_string(payload, '$.date_added') as date) as date_added,
    try_cast(json_extract_string(payload, '$.due_date') as date)   as due_date,

    -- The feed publishes the strings "Known" / "Unknown". A boolean is what
    -- every downstream query actually wants; the raw string is kept beside it
    -- so the conversion itself is checkable.
    json_extract_string(payload, '$.ransomware_use')              as ransomware_use_raw,
    json_extract_string(payload, '$.ransomware_use') = 'Known'    as is_ransomware_linked,

    from_json(json_extract(payload, '$.cwes'), '["VARCHAR"]')     as cwes,
    json_extract_string(payload, '$.catalog_version')             as catalog_version

from {{ source('bronze', 'cisa_kev') }}
