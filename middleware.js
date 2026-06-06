// Edge Middleware — two independent auth domains:
//   • /site, /site/*        → signed-cookie session (the visitor login).
//                             Invalid/expired → redirect to the splash (/).
//   • /dashboard(/*), /api/stats → HTTP Basic Auth (the analytics admin login),
//                             credentials from DASHBOARD_USER / DASHBOARD_PASS.
//
// /api/track is intentionally NOT matched here, so it stays public — any
// visitor must be able to POST analytics events without credentials.
//
// Cookie verification uses Web Crypto (HMAC SHA-256) with the same AUTH_SECRET
// the login function signs with.
import { next } from '@vercel/edge';

export const config = {
  matcher: ['/site', '/site/:path*', '/dashboard', '/dashboard/:path*', '/api/stats'],
};

const COOKIE = 'holmes_auth';
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

  // Dashboard UI + its data API → Basic Auth (separate from the site session).
  if (pathname === '/dashboard' || pathname.startsWith('/dashboard/') || pathname === '/api/stats') {
    if (await basicAuthOk(request)) return next();
    return new Response('Authentication required', {
      status: 401,
      headers: { 'WWW-Authenticate': 'Basic realm="Holmes Analytics", charset="UTF-8"' },
    });
  }

  // /site/* → signed-cookie session (unchanged behavior).
  const secret = process.env.AUTH_SECRET;
  const token = readCookie(request.headers.get('cookie'), COOKIE);
  if (secret && await valid(token, secret)) return next();

  const url = new URL(request.url);
  url.pathname = '/';
  url.search = '';
  return Response.redirect(url, 302);
}
