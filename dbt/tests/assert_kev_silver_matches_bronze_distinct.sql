-- ============================================================================
-- Reconciliation: Silver must contain exactly one row per distinct CVE in Bronze.
--
-- A singular test returns the rows that are WRONG. No rows = pass.
--
-- `unique` on Silver proves there are no duplicates. It cannot prove nothing
-- went missing: a deduplication rule that accidentally dropped every
-- ransomware-linked CVE would still produce a perfectly unique table. Counting
-- against the source is the only check that catches loss as well as excess.
-- ============================================================================

with bronze as (
    select count(distinct json_extract_string(payload, '$.cve_id')) as distinct_cves
    from {{ source('bronze', 'cisa_kev') }}
    where json_extract_string(payload, '$.cve_id') is not null
),

silver as (
    select count(*) as rows_in_silver
    from {{ ref('kev_vulnerabilities') }}
)

select
    bronze.distinct_cves,
    silver.rows_in_silver,
    bronze.distinct_cves - silver.rows_in_silver as missing_from_silver
from bronze
cross join silver
where bronze.distinct_cves <> silver.rows_in_silver
