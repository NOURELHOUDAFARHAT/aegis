-- ============================================================================
-- silver.feodo_c2_servers  -  one row per real command-and-control server
--
-- Two jobs here, both visible in the WHERE clause:
--
--   1. Deduplicate: keep the most recently ingested copy of each IP, so status
--      reflects the latest the feed told us.
--
--   2. Exclude records that are not real. Bronze holds 29 rows for 7 addresses,
--      but two of those addresses are RFC 5737 documentation IPs that this
--      project's own demo script and integration test pushed through the live
--      pipeline. They can never be real infrastructure. The rule, and why it is
--      a range check rather than a list of two IPs, lives in the
--      is_documentation_address macro.
--
-- Expected result: 5 servers - exactly what Feodo Tracker publishes.
-- ============================================================================

with ranked as (

    select
        *,
        row_number() over (
            partition by ip_address
            order by ingested_at desc, _kafka_offset desc
        )                                                 as recency_rank,
        min(ingested_at) over (partition by ip_address)   as first_observed_at,
        max(ingested_at) over (partition by ip_address)   as last_observed_at,
        count(*)         over (partition by ip_address)   as times_observed

    from {{ ref('stg_feodo') }}
    where ip_address is not null
      and not {{ is_documentation_address('ip_address') }}

)

select
    ip_address,
    port,
    status,
    status = 'online'  as is_online,
    hostname,
    as_number,
    as_name,
    country,
    malware,
    first_seen,
    last_online,
    first_observed_at,
    last_observed_at,
    times_observed,
    event_id           as source_event_id

from ranked
where recency_rank = 1
