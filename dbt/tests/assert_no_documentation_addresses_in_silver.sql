-- ============================================================================
-- No RFC 5737 documentation address may reach Silver.
--
-- Regression test for a real Phase 4 finding: this project's own demo script
-- and integration test published fake records (203.0.113.10, 198.51.100.7)
-- through the live pipeline into bronze.feodo. Silver filters them; this test
-- fails the build if any IP-bearing Silver table ever lets one through.
-- ============================================================================

select 'feodo_c2_servers' as model, ip_address
from {{ ref('feodo_c2_servers') }}
where {{ is_documentation_address('ip_address') }}

union all

select 'tor_exit_nodes' as model, ip_address
from {{ ref('tor_exit_nodes') }}
where {{ is_documentation_address('ip_address') }}
