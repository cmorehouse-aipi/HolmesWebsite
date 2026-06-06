# Analytics & Dashboard

First-party, cookieless visitor analytics with a password-protected "god-view"
dashboard at **/dashboard**. No third-party trackers, no consent banner required.

## One-time Vercel setup

1. **Add a database.** Vercel project → **Storage** → **Create / Connect** →
   **Neon** (free tier). This auto-injects **`DATABASE_URL`** into the project.
2. **Add environment variables** (Project → Settings → Environment Variables,
   all environments):

   | Variable | Value | Why |
   |---|---|---|
   | `DASHBOARD_USER` | _(the username you chose)_ | dashboard login (Basic Auth) |
   | `DASHBOARD_PASS` | _(the password you chose)_ | dashboard login |

   > Do **not** commit the real values — this repo is public. Set them only in
   > Vercel's Environment Variables UI.
   | `ANALYTICS_SALT` | a long random string | salts the daily visitor hash |
   | `CRON_SECRET` | a long random string | authorizes the daily purge cron |

   `DATABASE_URL` comes from the Neon integration — don't set it by hand.
   The existing `AUTH_USER` / `AUTH_PASSWORD` / `AUTH_SECRET` (the site login)
   are unchanged.
3. **Redeploy** (push to `main`, or Vercel → Deployments → Redeploy) so the new
   dependency and env vars take effect.

> Everything **fails closed**: if `DASHBOARD_USER`/`DASHBOARD_PASS` are unset the
> dashboard returns 401; if `CRON_SECRET` is unset the purge returns 401 (data
> just isn't auto-deleted). The `events` table self-creates on the first event.

## Using it

- Visit **`/dashboard`** → browser prompts for your `DASHBOARD_USER` / `DASHBOARD_PASS`.
- Range selector (24H / 7D / 30D), auto-refreshes every 30s.
- Click any row in **God View · Live Sessions** to replay that visitor's journey.

## How it works

- A tiny inline script in `index.html` (splash) and `site/index.html` sends
  batched events via `navigator.sendBeacon` to **`/api/track`** (the only public
  endpoint).
- `/api/track` enriches each event with geo (Vercel IP headers) and a
  **daily-rotating anonymous hash** of `ip + user-agent + salt`. The **raw IP is
  never stored**. Honors `DNT` / `Sec-GPC` (no tracking when set).
- **`/api/stats`** (Basic-Auth protected) runs the aggregations the dashboard reads.
- `middleware.js` enforces auth: cookie session for `/site/*`, Basic Auth for
  `/dashboard` + `/api/stats`, public `/api/track`.
- Events older than **90 days** are purged daily (`/api/purge` via Vercel Cron).

## Files

| File | Role |
|---|---|
| `api/_db.js` | Neon client + self-initializing schema |
| `api/track.js` | public event ingest (geo, UA parse, hashing) |
| `api/stats.js` | dashboard aggregations + per-session timeline |
| `api/purge.js` + `vercel.json` | 90-day retention cron |
| `dashboard/index.html` | the command-center UI (ECharts via CDN) |
| `middleware.js` | auth for all protected routes |

## Notes

- City-level geo works on Vercel's free (Hobby) plan; geo is empty on localhost.
- `/dashboard` and the data are visible to anyone with the password — keep it private.
- This is first-party analytics; for EU/UK traffic, confirm your privacy policy
  reflects it (the cookieless, no-raw-IP design keeps obligations light).
