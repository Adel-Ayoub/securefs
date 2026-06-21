-- Shared session + rate-limit state so multiple stateless server instances can
-- coordinate. The former in-process Arc<Mutex<HashMap>> keyed off a per-process
-- monotonic clock (Instant), which is meaningless across instances; here time is
-- database-authoritative (now()) so any instance computes the same uptime/idle
-- and sees the same window.

-- Active sessions, keyed by the per-connection session id. Any instance can list
-- every session and flag one for forced logout; the owning instance acts on the
-- flag at its next heartbeat. Rows are removed on logout/disconnect and reaped by
-- last_activity if an instance dies mid-session.
CREATE TABLE IF NOT EXISTS sessions (
    session_id    TEXT PRIMARY KEY,
    username      TEXT NOT NULL,
    client_ip     TEXT NOT NULL,
    connected_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_activity TIMESTAMPTZ NOT NULL DEFAULT now(),
    force_logout  BOOLEAN NOT NULL DEFAULT false
);

-- Failed-auth counters per client IP for shared rate limiting. first_attempt
-- anchors the sliding window; a failure after the window resets the count to 1
-- (same semantics as the old in-process limiter). Reused for both login and TOTP.
CREATE TABLE IF NOT EXISTS login_attempts (
    client_ip     TEXT PRIMARY KEY,
    attempts      INTEGER NOT NULL DEFAULT 0,
    first_attempt TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_sessions_last_activity ON sessions(last_activity);
CREATE INDEX IF NOT EXISTS idx_login_attempts_first ON login_attempts(first_attempt);
