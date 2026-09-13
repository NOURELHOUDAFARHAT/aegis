-- ============================================================================
-- gold.c2_infrastructure
--
-- The question no single feed can answer: "are the servers controlling these
-- botnets hiding behind Tor, or operating openly?"
--
-- Feodo knows which IPs are C2 servers. The Tor Project knows which IPs are
-- exit nodes. Neither knows about the other. This join is the first table in
-- the project that exists only because two sources now live in one place -
-- which is the argument for the whole lakehouse, expressed as a LEFT JOIN.
--
-- LEFT, not INNER: an inner join would return only C2 servers that ARE Tor
-- exits, and silently drop the ones that are not - which is the actual finding.
-- ============================================================================

select
    c2.ip_address,
    c2.malware,
    c2.is_online,
    c2.port,
    c2.as_name,
    c2.as_number,
    c2.country,
    c2.hostname,
    c2.first_seen,
    c2.last_online,

    tor.ip_address is not null              as was_ever_tor_exit,
    coalesce(tor.is_current_exit, false)    as is_current_tor_exit,

    -- A rough hosting classification from the network owner's name. Attackers
    -- renting from mainstream cloud providers are a different operational
    -- picture from ones on bulletproof hosting: the former can be reported to
    -- an abuse desk that will act.
    case
        when regexp_matches(
            lower(coalesce(c2.as_name, '')),
            'amazon|aws|digitalocean|google|microsoft|azure|ovh|hetzner|linode|akamai|vultr|oracle'
        ) then 'commercial_cloud'
        else 'other'
    end                                     as hosting_type

from {{ ref('feodo_c2_servers') }} as c2
left join {{ ref('tor_exit_nodes') }} as tor
    on c2.ip_address = tor.ip_address
