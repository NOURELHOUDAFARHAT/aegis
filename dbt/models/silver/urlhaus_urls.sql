-- ============================================================================
-- silver.urlhaus_urls  -  one row per malicious URL
--
-- Same pattern as the KEV model: keep the most recently ingested copy, so
-- url_status reflects the latest thing URLhaus told us (a URL that was online
-- last week may be offline now), and record how often we saw it.
-- ============================================================================

with ranked as (

    select
        *,
        row_number() over (
            partition by url
            order by ingested_at desc, _kafka_offset desc
        )                                           as recency_rank,
        min(ingested_at) over (partition by url)    as first_observed_at,
        max(ingested_at) over (partition by url)    as last_observed_at,
        count(*)         over (partition by url)    as times_observed

    from {{ ref('stg_urlhaus') }}
    where url is not null

)

select
    url,
    host,
    urlhaus_id,
    url_status,
    url_status = 'online'   as is_online,
    threat,
    coalesce(tags, [])      as tags,
    reporter,
    listed_at,
    first_observed_at,
    last_observed_at,
    times_observed,
    urlhaus_link,
    event_id                as source_event_id

from ranked
where recency_rank = 1
