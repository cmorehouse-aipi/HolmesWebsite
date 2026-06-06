// Analytics aggregation endpoint (Node serverless).
//
// Returns the entire dashboard dataset as one JSON object, or a single
// session's event timeline when called with ?session=...&from=...&to=...
//
// Protected by Basic Auth in middleware.js. We ALSO re-check the Authorization
// header here (defense in depth) so the visitor data is never exposed even if
// the middleware matcher is ever misconfigured.
import crypto from 'node:crypto';
import { db } from './_db.js';

const RANGES = {
  '24h': { ms: 24 * 3600 * 1000, unit: 'hour' },
  '7d': { ms: 7 * 86400 * 1000, unit: 'day' },
  '30d': { ms: 30 * 86400 * 1000, unit: 'day' },
};

// Constant-time-ish credential check via fixed-length digests (mirrors api/login.js).
function safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}
function basicAuthOk(req) {
  const { DASHBOARD_USER, DASHBOARD_PASS } = process.env;
  if (!DASHBOARD_USER || !DASHBOARD_PASS) return false;
  const m = /^Basic\s+(.+)$/i.exec(req.headers['authorization'] || '');
  if (!m) return false;
  let decoded = '';
  try { decoded = Buffer.from(m[1], 'base64').toString('utf8'); } catch { return false; }
  const i = decoded.indexOf(':');
  const u = i === -1 ? decoded : decoded.slice(0, i);
  const p = i === -1 ? '' : decoded.slice(i + 1);
  // Evaluate both (no short-circuit) so timing doesn't reveal which field failed.
  const userOk = safeEqual(u, DASHBOARD_USER);
  const passOk = safeEqual(p, DASHBOARD_PASS);
  return userOk && passOk;
}

const sql = () => db();
async function q(text, params) {
  const r = await sql().query(text, params);
  return Array.isArray(r) ? r : (r && r.rows) || [];
}

// Derives sessions from raw events via a 30-minute inactivity gap.
const SESSIONS_CTE = `
  WITH ordered AS (
    SELECT visitor_hash, ts, type, engaged_ms, geo_city, geo_country, device_type, browser,
           LAG(ts) OVER (PARTITION BY visitor_hash ORDER BY ts) AS prev_ts
    FROM events WHERE ts >= $1
  ),
  marked AS (
    SELECT *, CASE WHEN prev_ts IS NULL OR ts - prev_ts > INTERVAL '30 minutes' THEN 1 ELSE 0 END AS new_sess
    FROM ordered
  ),
  sessions AS (
    SELECT *, SUM(new_sess) OVER (PARTITION BY visitor_hash ORDER BY ts) AS seq FROM marked
  ),
  rollup AS (
    SELECT visitor_hash, seq,
           min(ts) AS started, max(ts) AS ended,
           count(*) FILTER (WHERE type IN ('pageview','virtual_pageview'))::int AS views,
           count(*)::int AS events,
           COALESCE(sum(engaged_ms),0)::int AS engaged_ms,
           max(geo_city) AS city, max(geo_country) AS country,
           max(device_type) AS device, max(browser) AS browser
    FROM sessions GROUP BY visitor_hash, seq
  )`;

export default async function handler(req, res) {
  if (!basicAuthOk(req)) {
    res.setHeader('WWW-Authenticate', 'Basic realm="Holmes Analytics", charset="UTF-8"');
    return res.status(401).json({ error: 'Authentication required' });
  }

  let p;
  try { p = sql(); } catch (e) { return res.status(500).json({ error: String(e.message || e) }); }

  try {
    // --- Single-session timeline mode (the "god view" drill-down) ---
    if (req.query && req.query.session) {
      const visitor = String(req.query.session).slice(0, 64);
      // Default to the full retained window so an admin can see a person's
      // ENTIRE behavior; the per-session inline expand passes explicit from/to.
      const from = new Date(req.query.from || Date.now() - 90 * 86400000).toISOString();
      const to = new Date(req.query.to || Date.now()).toISOString();
      const timeline = await q(
        `SELECT ts, type, surface, COALESCE(spa_view, path) AS page, referrer,
                el_text, el_datago, el_href, click_x, click_y,
                scroll_pct, engaged_ms, outcome,
                geo_city, geo_region, geo_country, device_type, browser, os,
                viewport_w, viewport_h, lang, tz
         FROM events WHERE visitor_hash = $1 AND ts BETWEEN $2 AND $3
         ORDER BY ts LIMIT 3000`,
        [visitor, from, to],
      );
      return res.status(200).json({ timeline });
    }

    // --- Full dashboard bundle ---
    const range = RANGES[req.query?.range] ? req.query.range : '7d';
    const { ms, unit } = RANGES[range];
    const startIso = new Date(Date.now() - ms).toISOString();
    const prevStartIso = new Date(Date.now() - 2 * ms).toISOString();
    const S = [startIso];

    const [
      visitorsCur, visitorsPrev, pageviewsCur, pageviewsPrev,
      live, series, sessionRollup, geoCountries, geoCities,
      sources, topPages, scrollDist, topClicks, devices, browsers, oses, funnel,
    ] = await Promise.all([
      q(`SELECT count(DISTINCT visitor_hash)::int AS v FROM events WHERE ts >= $1`, S),
      q(`SELECT count(DISTINCT visitor_hash)::int AS v FROM events WHERE ts >= $1 AND ts < $2`, [prevStartIso, startIso]),
      q(`SELECT count(*)::int AS v FROM events WHERE type IN ('pageview','virtual_pageview') AND ts >= $1`, S),
      q(`SELECT count(*)::int AS v FROM events WHERE type IN ('pageview','virtual_pageview') AND ts >= $1 AND ts < $2`, [prevStartIso, startIso]),
      q(`SELECT count(DISTINCT visitor_hash)::int AS v FROM events WHERE ts > now() - INTERVAL '5 minutes'`, []),
      q(`SELECT date_trunc($2, ts) AS bucket,
                count(*) FILTER (WHERE type IN ('pageview','virtual_pageview'))::int AS views,
                count(DISTINCT visitor_hash)::int AS visitors
         FROM events WHERE ts >= $1 GROUP BY 1 ORDER BY 1`, [startIso, unit]),
      q(`${SESSIONS_CTE} SELECT * FROM rollup ORDER BY started DESC`, S),
      q(`SELECT geo_country AS country, count(DISTINCT visitor_hash)::int AS visitors, count(*)::int AS hits
         FROM events WHERE ts >= $1 AND geo_country IS NOT NULL
         GROUP BY 1 ORDER BY visitors DESC`, S),
      q(`SELECT geo_city AS city, geo_region AS region, geo_country AS country, geo_lat AS lat, geo_lon AS lon,
                count(DISTINCT visitor_hash)::int AS visitors
         FROM events WHERE ts >= $1 AND geo_lat IS NOT NULL AND geo_lon IS NOT NULL
         GROUP BY 1,2,3,4,5 ORDER BY visitors DESC LIMIT 300`, S),
      q(`SELECT COALESCE(NULLIF(utm_source,''),
                  CASE WHEN referrer IS NULL OR referrer = '' THEN '(direct)'
                       ELSE regexp_replace(referrer, '^https?://([^/]+).*$', '\\1') END) AS source,
                count(DISTINCT visitor_hash)::int AS visitors
         FROM events WHERE type IN ('pageview','virtual_pageview') AND ts >= $1
         GROUP BY 1 ORDER BY visitors DESC LIMIT 50`, S),
      q(`WITH ev AS (
            SELECT COALESCE(spa_view, path) AS page, visitor_hash, type, engaged_ms, scroll_pct
            FROM events WHERE ts >= $1
          ),
          sc AS (SELECT page, visitor_hash, max(scroll_pct) AS mx FROM ev WHERE type='scroll' GROUP BY 1,2)
          SELECT e.page,
                 count(*) FILTER (WHERE e.type IN ('pageview','virtual_pageview'))::int AS views,
                 round(COALESCE(sum(e.engaged_ms) FILTER (WHERE e.type='engage'),0)::numeric
                       / NULLIF(count(*) FILTER (WHERE e.type IN ('pageview','virtual_pageview')),0))::int AS avg_dwell_ms,
                 COALESCE((SELECT round(avg(mx))::int FROM sc WHERE sc.page = e.page), 0) AS avg_scroll
          FROM ev e GROUP BY e.page
          HAVING count(*) FILTER (WHERE e.type IN ('pageview','virtual_pageview')) > 0
          ORDER BY views DESC LIMIT 50`, S),
      q(`SELECT (width_bucket(scroll_pct, 0, 101, 4)) * 25 AS bucket, count(*)::int AS count
         FROM events WHERE type='scroll' AND scroll_pct IS NOT NULL AND ts >= $1
         GROUP BY 1 ORDER BY 1`, S),
      q(`SELECT COALESCE(NULLIF(el_text,''), el_datago, el_id, el_tag, '(unknown)') AS label,
                el_datago, el_tag, count(*)::int AS clicks
         FROM events WHERE type='click' AND ts >= $1
         GROUP BY 1,2,3 ORDER BY clicks DESC LIMIT 50`, S),
      q(`SELECT COALESCE(device_type,'unknown') AS k, count(DISTINCT visitor_hash)::int AS v
         FROM events WHERE ts >= $1 GROUP BY 1 ORDER BY v DESC`, S),
      q(`SELECT COALESCE(browser,'unknown') AS k, count(DISTINCT visitor_hash)::int AS v
         FROM events WHERE ts >= $1 GROUP BY 1 ORDER BY v DESC`, S),
      q(`SELECT COALESCE(os,'unknown') AS k, count(DISTINCT visitor_hash)::int AS v
         FROM events WHERE ts >= $1 GROUP BY 1 ORDER BY v DESC`, S),
      q(`WITH pv AS (
            SELECT visitor_hash,
              bool_or(surface='splash') AS splash,
              bool_or(type='login_attempt') AS login,
              bool_or(surface='site') AS site,
              bool_or((type='form_submit' AND form_id='contact') OR (type='virtual_pageview' AND spa_view='contact')) AS contact
            FROM events WHERE ts >= $1 GROUP BY 1)
          SELECT count(*) FILTER (WHERE splash)::int AS splash,
                 count(*) FILTER (WHERE login)::int AS login,
                 count(*) FILTER (WHERE site)::int AS site,
                 count(*) FILTER (WHERE contact)::int AS contact
          FROM pv`, S),
    ]);

    // Roll the session list into KPIs (sessions, bounce, avg engaged time).
    const sessCount = sessionRollup.length;
    const bounced = sessionRollup.filter((s) => s.views <= 1).length;
    const engagedVals = sessionRollup.map((s) => s.engaged_ms).filter((n) => n > 0);
    const avgEngagedMs = engagedVals.length
      ? Math.round(engagedVals.reduce((a, b) => a + b, 0) / engagedVals.length) : 0;

    const pct = (cur, prev) => (prev > 0 ? Math.round(((cur - prev) / prev) * 100) : null);
    const vCur = visitorsCur[0]?.v || 0, vPrev = visitorsPrev[0]?.v || 0;
    const pvCur = pageviewsCur[0]?.v || 0, pvPrev = pageviewsPrev[0]?.v || 0;

    return res.status(200).json({
      range,
      generatedAt: new Date().toISOString(),
      kpis: {
        visitors: vCur, visitorsDelta: pct(vCur, vPrev),
        pageviews: pvCur, pageviewsDelta: pct(pvCur, pvPrev),
        sessions: sessCount,
        avgEngagedMs,
        bounceRate: sessCount ? Math.round((bounced / sessCount) * 1000) / 10 : 0,
        liveNow: live[0]?.v || 0,
      },
      series,
      geoCountries,
      geoCities,
      sources,
      topPages,
      scrollDist,
      topClicks,
      devices,
      browsers,
      os: oses,
      funnel: funnel[0] || { splash: 0, login: 0, site: 0, contact: 0 },
      sessions: sessionRollup.slice(0, 100),
    });
  } catch (e) {
    return res.status(500).json({ error: String(e.message || e) });
  }
}
