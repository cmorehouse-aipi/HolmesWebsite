// Daily retention purge (invoked by Vercel Cron — see vercel.json).
//
// Deletes events older than 90 days to bound free-tier storage and minimize
// retained data. Vercel sends `Authorization: Bearer ${CRON_SECRET}` to
// cron-invoked routes; we verify it so the endpoint can't be triggered by
// anyone else.
import { db } from './_db.js';

export default async function handler(req, res) {
  // Fail CLOSED: a missing/empty CRON_SECRET must NOT allow the DELETE to run.
  if (req.method !== 'GET') { res.setHeader('Allow', 'GET'); return res.status(405).json({ error: 'Method not allowed' }); }
  const secret = process.env.CRON_SECRET;
  const auth = req.headers['authorization'] || '';
  if (!secret || auth !== `Bearer ${secret}`) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const sql = db();
    await sql`DELETE FROM events WHERE ts < now() - INTERVAL '90 days'`;
    return res.status(200).json({ ok: true });
  } catch (e) {
    return res.status(500).json({ error: String(e.message || e) });
  }
}
