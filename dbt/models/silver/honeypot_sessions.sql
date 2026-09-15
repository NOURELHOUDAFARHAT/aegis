-- ============================================================================
-- silver.honeypot_sessions  -  one row per attack session
--
-- A session is one connection to the sensor: from TCP connect to disconnect.
-- Everything an attacker did inside it - every password tried, every command
-- typed, every file fetched - shares Cowrie's session id.
--
-- This is the table the Phase 7 anomaly model learns from, so each column is
-- a behaviour, not a raw event:
--
--   login_attempts / distinct_passwords   how hard it guessed
--   login_succeeded                       whether it got a (fake) shell
--   commands_run / first_command          what it did once inside
--   downloads                             whether it tried to fetch malware
--   client_version / hassh                which SSH software it used - hassh
--                                         fingerprints the client's crypto
--                                         negotiation, so one bot keeps one
--                                         hassh even when it changes IP
--
-- A session still open when the data was collected has no ended_at yet; it is
-- completed on a later build, when its cowrie.session.closed event arrives.
-- ============================================================================

select
    session_id,
    arg_min(sensor, occurred_at)                                         as sensor,
    arg_min(src_ip, occurred_at)                                         as src_ip,
    max(protocol)                                                        as protocol,
    max(client_version) filter (where eventid = 'cowrie.client.version') as client_version,
    max(hassh)          filter (where eventid = 'cowrie.client.kex')     as hassh,

    min(occurred_at)                                                     as started_at,
    max(occurred_at)    filter (where eventid = 'cowrie.session.closed') as ended_at,
    max(duration_seconds) filter (where eventid = 'cowrie.session.closed') as duration_seconds,
    coalesce(bool_or(eventid = 'cowrie.session.closed'), false)          as is_closed,

    count(*) filter (where eventid in ('cowrie.login.failed', 'cowrie.login.success'))
                                                                         as login_attempts,
    coalesce(bool_or(eventid = 'cowrie.login.success'), false)           as login_succeeded,
    count(distinct username)                                             as distinct_usernames,
    count(distinct password)                                             as distinct_passwords,

    count(*) filter (where eventid = 'cowrie.command.input')             as commands_run,
    arg_min(command_input, occurred_at) filter (where eventid = 'cowrie.command.input')
                                                                         as first_command,
    count(*) filter (where eventid = 'cowrie.session.file_download')     as downloads,

    count(*)                                                             as event_count

from {{ ref('honeypot_events') }}
group by session_id
