// Clears the session cookie and returns to the splash. Link to /api/logout
// from the main site to add a "sign out" action.
const COOKIE = 'leif_auth';

export default async function handler(req, res) {
  res.setHeader('Set-Cookie',
    `${COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`);
  res.statusCode = 302;
  res.setHeader('Location', '/');
  res.end();
}
