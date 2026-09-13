-- ============================================================================
-- silver.kev_vulnerabilities  -  one row per CVE
--
-- Bronze holds 5,085 rows because the catalogue was collected three times.
-- There are 1,695 distinct vulnerabilities. This model is where 5,085 becomes
-- 1,695, and where "Microsoft: 1,158" becomes "Microsoft: 386".
--
-- HOW THE DEDUPLICATION CHOOSES
-- For each cve_id we keep the MOST RECENTLY INGESTED copy. If CISA corrects a
-- due date or a ransomware flag, the latest collection carries the correction.
-- Ties (two copies ingested in the same microsecond) are broken by Kafka
-- offset, so the choice is deterministic: rebuilding gives the same answer
-- every time, which is what makes Silver safely disposable.
--
-- Nothing is lost by collapsing: first/last observed and times_observed keep
-- the history of how often we saw it.
-- ============================================================================

with ranked as (

    select
        *,
        row_number() over (
            partition by cve_id
            order by ingested_at desc, _kafka_offset desc
        )                                                  as recency_rank,
        min(ingested_at) over (partition by cve_id)        as first_observed_at,
        max(ingested_at) over (partition by cve_id)        as last_observed_at,
        count(*)         over (partition by cve_id)        as times_observed

    from {{ ref('stg_cisa_kev') }}
    -- A record with no CVE id cannot be deduplicated or joined to anything.
    -- There are none today; the not_null test below would still flag the
    -- staging data if one appeared, because this filter is visible here.
    where cve_id is not null

)

select
    cve_id,
    vendor,
    product,
    vulnerability_name,
    description,
    required_action,
    date_added,
    due_date,
    is_ransomware_linked,
    cwes,
    catalog_version,
    first_observed_at,
    last_observed_at,
    times_observed,
    event_id as source_event_id   -- which Bronze row this version came from

from ranked
where recency_rank = 1
