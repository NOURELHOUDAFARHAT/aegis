-- ============================================================================
-- Reconciliation: Gold's per-vendor counts must add up to Silver's total.
--
-- A GROUP BY silently drops rows whose grouping key is NULL in some engines and
-- groups them together in others. If a CVE ever arrived with no vendor, this
-- is the test that notices the totals no longer match - rather than the
-- dashboard quietly reporting a smaller number.
-- ============================================================================

with gold as (
    select sum(exploited_cves) as total from {{ ref('vendor_exploitation') }}
),

silver as (
    select count(*) as total from {{ ref('kev_vulnerabilities') }}
)

select
    gold.total   as gold_total,
    silver.total as silver_total
from gold
cross join silver
where gold.total <> silver.total
