// Shared Neon Postgres client + schema bootstrap for analytics.
//
// Uses the @neondatabase/serverless HTTP driver so it works inside Vercel
// Node serverless functions without a raw TCP connection. DATABASE_URL is
// injected automatically by the Vercel–Neon Marketplace integration (the
// pooled connection string). The leading underscore in this filename keeps
// Vercel from exposing it as a routable /api/* endpoint.
import { neon } from '@neondatabase/serverless';

let _sql = null;

// Lazily create one client per process (reused across warm invocations).
export function db() {
  if (_sql) return _sql;
  const url = process.env.DATABASE_URL || process.env.POSTGRES_URL;
  if (!url) throw new Error('DATABASE_URL not set — add the Neon integration in Vercel');
  _sql = neon(url);
  return _sql;
}

// Ordered column list for the wide events table. track.js builds its
// multi-row INSERT from exactly this list so the two never drift.
export const EVENT_COLUMNS = [
  'ts', 'visitor_hash', 'type', 'surface', 'path', 'spa_view', 'referrer',
  'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
  'device_type', 'browser', 'os', 'lang', 'tz',
  'screen_w', 'screen_h', 'viewport_w', 'viewport_h',
  'geo_country', 'geo_region', 'geo_city', 'geo_lat', 'geo_lon',
  'el_tag', 'el_id', 'el_class', 'el_text', 'el_datago', 'el_href',
  'click_x', 'click_y', 'engaged_ms', 'scroll_pct',
  'load_ms', 'ttfb_ms', 'dom_ms', 'form_id', 'outcome', 'extra',
];

let _ready = null;

// Create the table + indexes once per process. CREATE ... IF NOT EXISTS is
// idempotent, so concurrent cold starts racing here is harmless.
export function ensureSchema() {
  if (_ready) return _ready;
  const sql = db();
  _ready = (async () => {
    // All DDL in ONE HTTPS round-trip (idempotent; safe on concurrent cold starts).
    await sql.transaction([
      sql`
      CREATE TABLE IF NOT EXISTS events (
        id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        ts            TIMESTAMPTZ NOT NULL DEFAULT now(),
        visitor_hash  TEXT NOT NULL,
        type          TEXT NOT NULL,
        surface       TEXT,
        path          TEXT,
        spa_view      TEXT,
        referrer      TEXT,
        utm_source    TEXT,
        utm_medium    TEXT,
        utm_campaign  TEXT,
        utm_term      TEXT,
        utm_content   TEXT,
        device_type   TEXT,
        browser       TEXT,
        os            TEXT,
        lang          TEXT,
        tz            TEXT,
        screen_w      INT,
        screen_h      INT,
        viewport_w    INT,
        viewport_h    INT,
        geo_country   TEXT,
        geo_region    TEXT,
        geo_city      TEXT,
        geo_lat       DOUBLE PRECISION,
        geo_lon       DOUBLE PRECISION,
        el_tag        TEXT,
        el_id         TEXT,
        el_class      TEXT,
        el_text       TEXT,
        el_datago     TEXT,
        el_href       TEXT,
        click_x       INT,
        click_y       INT,
        engaged_ms    INT,
        scroll_pct    INT,
        load_ms       INT,
        ttfb_ms       INT,
        dom_ms        INT,
        form_id       TEXT,
        outcome       TEXT,
        extra         JSONB
      )`,
      sql`CREATE INDEX IF NOT EXISTS idx_events_ts         ON events (ts DESC)`,
      sql`CREATE INDEX IF NOT EXISTS idx_events_type_ts    ON events (type, ts DESC)`,
      sql`CREATE INDEX IF NOT EXISTS idx_events_visitor_ts ON events (visitor_hash, ts)`,
      sql`CREATE INDEX IF NOT EXISTS idx_events_path       ON events (path)`,
      sql`CREATE INDEX IF NOT EXISTS idx_events_country    ON events (geo_country)`,
    ]);
  })().catch((err) => {
    _ready = null; // allow a later invocation to retry if the first failed
    throw err;
  });
  return _ready;
}
