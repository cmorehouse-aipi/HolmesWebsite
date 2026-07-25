// Edge Middleware.
//
//   • The visitor site is PUBLIC on every host this project serves (leif-ai.com,
//     www.leif-ai.com, the raw *.vercel.app deployment, previews). '/' is
//     rewritten to the site page so the clean URL serves the marketing site;
//     /site/* is public. There is no visitor password.
//   • demo.leif-ai.com is a SEPARATE application (hosted on AWS) with its own
//     auth. It is NOT served by this Vercel project. Do not add it as a domain
//     here — leif-ai.com is on Vercel nameservers, so doing so would pull the
//     subdomain's DNS onto Vercel and break the real demo app.
//   • /dashboard(/*), /api/stats → HTTP Basic Auth (the analytics admin login),
//     credentials from DASHBOARD_USER / DASHBOARD_PASS. Enforced on every host.
//   • /api/track is intentionally NOT matched here, so it stays public — any
//     visitor must be able to POST analytics events without credentials.
//
// The signed-cookie visitor gate below is dormant (GATED_HOSTS is empty). To
// password-gate a host THIS project serves, add it to GATED_HOSTS; it then gets
// the login splash + cookie session (AUTH_USER / AUTH_PASSWORD / AUTH_SECRET, via
// /api/login). Cookie verification uses Web Crypto (HMAC SHA-256) with AUTH_SECRET.
import { next, rewrite } from '@vercel/edge';

export const config = {
  matcher: ['/', '/site', '/site/:path*', '/dashboard', '/dashboard/:path*', '/api/stats'],
};

const COOKIE = 'leif_auth';
// Hosts THIS project serves that should require the visitor login. Empty = the
// site is public everywhere. (demo.leif-ai.com is a separate external app — see
// the note above — so it is NOT listed here.)
const GATED_HOSTS = new Set();
const enc = new TextEncoder();

function b64urlToBytes(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function bytesToB64url(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function ctEq(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

function readCookie(header, name) {
  if (!header) return null;
  for (const part of header.split(/;\s*/)) {
    const i = part.indexOf('=');
    if (i > -1 && part.slice(0, i) === name) return part.slice(i + 1);
  }
  return null;
}

function hostOf(request) {
  // Prefer the forwarded host (the public domain the visitor actually hit).
  const h = request.headers.get('x-forwarded-host') || request.headers.get('host') || '';
  return h.split(',')[0].split(':')[0].trim().toLowerCase();
}

// --- /site cookie session ---------------------------------------------------
async function valid(token, secret) {
  if (!token) return false;
  const dot = token.indexOf('.');
  if (dot < 0) return false;
  const payloadB64 = token.slice(0, dot);
  const sig = token.slice(dot + 1);

  const key = await crypto.subtle.importKey(
    'raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const mac = await crypto.subtle.sign('HMAC', key, enc.encode(payloadB64));
  if (!ctEq(bytesToB64url(new Uint8Array(mac)), sig)) return false;

  try {
    const payload = JSON.parse(new TextDecoder().decode(b64urlToBytes(payloadB64)));
    if (!payload.exp || Date.now() > payload.exp) return false;
  } catch { return false; }
  return true;
}

// --- /dashboard Basic Auth --------------------------------------------------
// Constant-time compare via SHA-256 digests so neither value's length leaks.
async function digestEqual(a, b) {
  const [da, db] = await Promise.all([
    crypto.subtle.digest('SHA-256', enc.encode(String(a))),
    crypto.subtle.digest('SHA-256', enc.encode(String(b))),
  ]);
  const x = new Uint8Array(da), y = new Uint8Array(db);
  let r = 0;
  for (let i = 0; i < x.length; i++) r |= x[i] ^ y[i];
  return r === 0;
}

async function basicAuthOk(request) {
  const u = process.env.DASHBOARD_USER;
  const p = process.env.DASHBOARD_PASS;
  if (!u || !p) return false;
  const m = /^Basic\s+(.+)$/i.exec(request.headers.get('authorization') || '');
  if (!m) return false;
  let decoded;
  try { decoded = atob(m[1]); } catch { return false; }
  const i = decoded.indexOf(':');
  const gotU = i === -1 ? decoded : decoded.slice(0, i);
  const gotP = i === -1 ? '' : decoded.slice(i + 1);
  // Evaluate both (no short-circuit) so timing doesn't reveal which field failed.
  const [okU, okP] = await Promise.all([digestEqual(gotU, u), digestEqual(gotP, p)]);
  return okU && okP;
}

export default async function middleware(request) {
  const { pathname } = new URL(request.url);
  const host = hostOf(request);

  // Dashboard UI + its data API → Basic Auth on every host (public and gated).
  if (pathname === '/dashboard' || pathname.startsWith('/dashboard/') || pathname === '/api/stats') {
    if (await basicAuthOk(request)) return next();
    return new Response('Authentication required', {
      status: 401,
      headers: { 'WWW-Authenticate': 'Basic realm="Leif Analytics", charset="UTF-8"' },
    });
  }

  // Public hosts: no visitor password. Serve the site at the clean root URL;
  // /site/* is served directly.
  if (!GATED_HOSTS.has(host)) {
    if (pathname === '/') return rewrite(new URL('/site/index.html', request.url));
    return next();
  }

  // Gated host (demo.leif-ai.com): '/' is the login splash; /site/* needs the cookie.
  if (pathname === '/') return next();

  const secret = process.env.AUTH_SECRET;
  const token = readCookie(request.headers.get('cookie'), COOKIE);
  if (secret && await valid(token, secret)) return next();

  const url = new URL(request.url);
  url.pathname = '/';
  url.search = '';
  return Response.redirect(url, 302);
}
