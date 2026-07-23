// Public analytics ingest endpoint (Node serverless).
//
// Receives batched events from the inline tracking snippet via
// navigator.sendBeacon. Enriches each event server-side with geo (Vercel IP
// headers), parsed device/browser/OS, and a COOKIELESS, daily-rotating
// anonymous visitor hash. The raw IP is used only to derive geo + the hash,
// then discarded — it is never stored. Honors DNT / GPC. Always responds 204
// quickly and never throws to the client (sendBeacon ignores the response).
//
// This is the ONLY unauthenticated endpoint: visitors must be able to POST
// events without credentials. Abuse guards: same-origin check, bot drop,
// batch-size cap, strict type/shape validation.
import crypto from 'node:crypto';
import { db, ensureSchema, EVENT_COLUMNS } from './_db.js';

const MAX_EVENTS = 60;
const EVENT_TYPES = new Set([
  'pageview', 'virtual_pageview', 'click', 'engage',
  'scroll', 'perf', 'form_submit', 'login_attempt', 'exit',
]);

// ---- small helpers ---------------------------------------------------------

function clip(v, n) {
  if (v == null) return null;
  const s = String(v);
  return s.length > n ? s.slice(0, n) : s;
}
function intOrNull(v) {
  const n = parseInt(v, 10);
  return Number.isFinite(n) ? n : null;
}
function clampInt(v, lo, hi) {
  const n = parseInt(v, 10);
  if (!Number.isFinite(n)) return null;
  return Math.max(lo, Math.min(hi, n));
}
function floatOrNull(v) {
  const n = parseFloat(v);
  return Number.isFinite(n) ? n : null;
}
function decHeader(v) {
  if (!v) return null;
  try { return decodeURIComponent(v); } catch { return v; }
}

// Coarse, dependency-free UA classifier. Only needs broad buckets for the
// dashboard; order matters (most specific first).
function parseUA(ua) {
  const u = (ua || '').toLowerCase();
  if (!u) return { device_type: 'unknown', browser: 'unknown', os: 'unknown' };
  if (/bot|crawl|spider|slurp|bingpreview|headless|lighthouse|preview|curl|wget|python-requests|axios|node-fetch|go-http/.test(u)) {
    return { device_type: 'bot', browser: 'bot', os: 'bot' };
  }
  let os = 'other';
  if (/windows nt/.test(u)) os = 'Windows';
  else if (/iphone|ipad|ipod/.test(u)) os = 'iOS';
  else if (/mac os x/.test(u)) os = 'macOS';
  else if (/android/.test(u)) os = 'Android';
  else if (/linux/.test(u)) os = 'Linux';

  let browser = 'other';
  if (/edg\//.test(u)) browser = 'Edge';
  else if (/opr\/|opera/.test(u)) browser = 'Opera';
  else if (/samsungbrowser/.test(u)) browser = 'Samsung';
  else if (/firefox|fxios/.test(u)) browser = 'Firefox';
  else if (/chrome|crios/.test(u)) browser = 'Chrome';
  else if (/safari/.test(u)) browser = 'Safari';

  let device_type = 'desktop';
  if (/ipad|tablet|playbook|silk/.test(u) || (/android/.test(u) && !/mobile/.test(u))) device_type = 'tablet';
  else if (/mobi|iphone|ipod|android.*mobile|windows phone/.test(u)) device_type = 'mobile';

  return { device_type, browser, os };
}

function dailySalt() {
  const day = new Date().toISOString().slice(0, 10); // UTC YYYY-MM-DD → 24h rotation
  return `${process.env.ANALYTICS_SALT || 'leif-default-salt'}:${day}`;
}
function visitorHash(ip, ua) {
  return crypto.createHash('sha256')
    .update(`${ip}|${ua}|${dailySalt()}`)
    .digest('hex')
    .slice(0, 32);
}

// Trust Vercel's platform-injected client IP, NOT the leftmost X-Forwarded-For
// (client-spoofable — Vercel appends the real client IP to the right). Used only
// to derive geo + the daily hash, then discarded. Best-effort, not abuse-proof
// (UA and other client inputs remain spoofable).
function clientIp(req) {
  return req.headers['x-real-ip']
    || req.headers['x-vercel-forwarded-for']
    || String(req.headers['x-forwarded-for'] || '').split(',').pop().trim()
    || req.socket?.remoteAddress || 'unknown';
}

// Accept the body whether Vercel pre-parsed it (application/json) or handed us
// a raw string (text/plain). sendBeacon sends a Blob typed application/json.
function parseBody(req) {
  let b = req.body;
  if (typeof b === 'string') { try { b = JSON.parse(b); } catch { return null; } }
  return (b && typeof b === 'object') ? b : null;
}

// Same-origin guard: only accept beacons whose Origin matches the host. Spoofable,
// but stops casual cross-site abuse of the public endpoint. Missing Origin (some
// beacon cases) is allowed; a present-but-mismatched Origin is rejected.
function originOk(req) {
  const origin = req.headers['origin'];
  if (!origin) return true;
  try { return new URL(origin).host === req.headers['host']; } catch { return false; }
}

// Map one client event → an ordered value array matching EVENT_COLUMNS.
function rowFor(ev, ctx) {
  const el = ev.el || {};
  const utm = ev.utm || {};
  // Known fields are pulled into columns; anything unrecognized is preserved
  // in `extra` so new client fields never need a migration.
  const known = new Set([
    'type', 'path', 'spa_view', 'ref', 'utm', 'lang', 'tz', 'sw', 'sh',
    'vw', 'vh', 'perf', 'el', 'x', 'y', 'engaged_ms', 'scroll_pct',
    'form_id', 'outcome', 't',
  ]);
  const extra = {};
  for (const k of Object.keys(ev)) if (!known.has(k)) extra[k] = ev[k];
  const perf = ev.perf || {};

  return [
    new Date(),                                   // ts (server authoritative)
    ctx.visitor_hash,
    ev.type,
    ctx.surface,
    clip(ev.path, 256),
    clip(ev.spa_view, 64),
    clip(ev.ref, 512),
    clip(utm.source, 128), clip(utm.medium, 128), clip(utm.campaign, 128),
    clip(utm.term, 128), clip(utm.content, 128),
    ctx.device_type, ctx.browser, ctx.os,
    clip(ev.lang, 32), clip(ev.tz || ctx.geo_tz, 64),
    intOrNull(ev.sw), intOrNull(ev.sh), intOrNull(ev.vw), intOrNull(ev.vh),
    ctx.geo_country, ctx.geo_region, ctx.geo_city, ctx.geo_lat, ctx.geo_lon,
    clip(el.tag, 32), clip(el.id, 128), clip(el.cls, 256),
    clip(el.text, 120), clip(el.datago, 64), clip(el.href, 512),
    intOrNull(ev.x), intOrNull(ev.y),
    clampInt(ev.engaged_ms, 0, 86400000), clampInt(ev.scroll_pct, 0, 100),
    intOrNull(perf.load_ms), intOrNull(perf.ttfb_ms), intOrNull(perf.dom_ms),
    clip(ev.form_id, 64),
    ev.outcome === 'success' || ev.outcome === 'fail' ? ev.outcome : null,
    Object.keys(extra).length ? JSON.stringify(extra) : null,
  ];
}

export default async function handler(req, res) {
  // Beacons are POSTs. Anything else is ignored cheaply.
  if (req.method !== 'POST') { res.setHeader('Allow', 'POST'); return res.status(405).end(); }

  // Privacy: never store anything when the visitor signals opt-out.
  if (req.headers['dnt'] === '1' || req.headers['sec-gpc'] === '1') return res.status(204).end();

  if (!originOk(req)) return res.status(204).end();

  const body = parseBody(req);
  if (!body || body.v !== 1 || !Array.isArray(body.events) || !body.events.length) {
    return res.status(204).end();
  }

  const ua = clip(req.headers['user-agent'], 512) || '';
  const { device_type, browser, os } = parseUA(ua);
  if (device_type === 'bot') return res.status(204).end(); // drop bot traffic entirely

  const ctx = {
    visitor_hash: visitorHash(clientIp(req), ua),
    surface: clip(body.surface, 16),
    device_type, browser, os,
    geo_country: clip(req.headers['x-vercel-ip-country'], 8),
    geo_region: clip(req.headers['x-vercel-ip-country-region'], 16),
    geo_city: clip(decHeader(req.headers['x-vercel-ip-city']), 128),
    geo_lat: floatOrNull(req.headers['x-vercel-ip-latitude']),
    geo_lon: floatOrNull(req.headers['x-vercel-ip-longitude']),
    geo_tz: clip(req.headers['x-vercel-ip-timezone'], 64),
  };

  const events = body.events
    .slice(0, MAX_EVENTS)
    .filter((e) => e && typeof e === 'object' && EVENT_TYPES.has(e.type));
  if (!events.length) return res.status(204).end();

  try {
    await ensureSchema();
    const sql = db();

    const rows = events.map((e) => rowFor(e, ctx));
    const ncol = EVENT_COLUMNS.length;
    const placeholders = rows
      .map((_, r) => '(' + EVENT_COLUMNS.map((_c, c) => `$${r * ncol + c + 1}`).join(',') + ')')
      .join(',');
    const params = rows.flat();
    const text = `INSERT INTO events (${EVENT_COLUMNS.join(',')}) VALUES ${placeholders}`;
    await sql.query(text, params);
  } catch (_err) {
    // Swallow: the public endpoint must never leak errors or block the user.
  }

  return res.status(204).end();
}
