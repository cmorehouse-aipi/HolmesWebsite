// Edge Middleware: guards /site/* . Requests without a valid, unexpired,
// correctly-signed session cookie are redirected to the splash (/), so the
// main page is unreachable by direct URL. Verification uses Web Crypto (HMAC
// SHA-256) with the same AUTH_SECRET the login function signs with.
import { next } from '@vercel/edge';

export const config = { matcher: ['/site', '/site/:path*'] };

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

export default async function middleware(request) {
  const secret = process.env.AUTH_SECRET;
  const token = readCookie(request.headers.get('cookie'), COOKIE);
  if (secret && await valid(token, secret)) return next();

  const url = new URL(request.url);
  url.pathname = '/';
  url.search = '';
  return Response.redirect(url, 302);
}
