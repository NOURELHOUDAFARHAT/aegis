-- ============================================================================
-- silver.tor_exit_nodes  -  one row per IP ever seen as a Tor exit
--
-- The interesting column is `is_current_exit`. Each collection of the Tor list
-- is a complete snapshot, so an IP that was in an earlier snapshot but missing
-- from the newest one has STOPPED being an exit node. Answering "is this IP a
-- Tor exit?" with "it was once" would wrongly flag an address that has since
-- been reassigned to someone else.
--
-- This is the problem slowly-changing dimensions exist to solve. Here it is
-- handled with first/last observed dates rather than a full SCD2 history,
-- which is enough while the list is collected by hand.
-- ============================================================================

with latest_snapshot as (

    -- Collection runs write every IP within a second or two, so they are
    -- grouped by the ingestion minute rather than an exact timestamp.
    select max(date_trunc('minute', ingested_at)) as snapshot_minute
    from {{ ref('stg_tor_exit') }}

),

per_ip as (

    select
        ip_address,
        min(ingested_at)                          as first_observed_at,
        max(ingested_at)                          as last_observed_at,
        count(distinct date_trunc('minute', ingested_at)) as snapshots_seen_in
    from {{ ref('stg_tor_exit') }}
    where ip_address is not null
    group by ip_address

)

select
    per_ip.ip_address,
    per_ip.first_observed_at,
    per_ip.last_observed_at,
    per_ip.snapshots_seen_in,
    date_trunc('minute', per_ip.last_observed_at) = latest_snapshot.snapshot_minute
        as is_current_exit

from per_ip
cross join latest_snapshot
