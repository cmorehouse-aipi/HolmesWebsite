// Serverless function (Node runtime): validates credentials and issues a
// signed, HttpOnly session cookie. Credentials live ONLY in Vercel environment
// variables (AUTH_USER, AUTH_PASSWORD) — never in the client or this file.
// AUTH_SECRET signs the cookie so it cannot be forged.
import crypto from 'node:crypto';

const COOKIE = 'leif_auth';
const MAX_AGE_SEC = 60 * 60 * 24 * 7; // 7 days

function b64url(buf) {
  return Buffer.from(buf).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function sign(payloadB64, secret) {
  return b64url(crypto.createHmac('sha256', secret).update(payloadB64).digest());
}

// constant-time comparison via fixed-length digests, so neither value's
// length is leaked through timing (timingSafeEqual requires equal lengths)
function safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { AUTH_USER, AUTH_PASSWORD, AUTH_SECRET } = process.env;
  if (!AUTH_USER || !AUTH_PASSWORD || !AUTH_SECRET) {
    return res.status(500).json({ error: 'Server not configured: set AUTH_USER, AUTH_PASSWORD and AUTH_SECRET' });
  }

  let body = req.body;
  if (typeof body === 'string') { try { body = JSON.parse(body); } catch { body = {}; } }
  body = body || {};
  const username = String(body.username || '').trim();
  const password = String(body.password || '');

  // evaluate both comparisons (no short-circuit) so timing doesn't reveal which field failed
  const userOk = safeEqual(username, AUTH_USER);
  const passOk = safeEqual(password, AUTH_PASSWORD);
  if (!(userOk && passOk)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const exp = Date.now() + MAX_AGE_SEC * 1000;
  const payloadB64 = b64url(JSON.stringify({ u: username, exp }));
  const token = payloadB64 + '.' + sign(payloadB64, AUTH_SECRET);

  res.setHeader('Set-Cookie',
    `${COOKIE}=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${MAX_AGE_SEC}`);
  return res.status(200).json({ ok: true });
}
