'use strict';
const express = require('express');
const { Pool } = require('pg');

const app = express();
app.disable('x-powered-by');
const port = Number(process.env.PORT || 10000);

app.get('/livez', (_req, res) => res.status(200).json({ ok: true }));
app.get('/healthz', (_req, res) => res.status(200).json({ ok: true }));
app.get('/', (_req, res) => {
  res.type('html').send(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Practice Secure</title><style>body{font-family:Arial,sans-serif;background:#f5f7fa;color:#123;margin:0;display:grid;place-items:center;min-height:100vh}.card{background:white;border-radius:16px;box-shadow:0 10px 30px #0001;padding:32px;max-width:620px;margin:20px}.ok{color:#087f5b;font-weight:700}</style></head><body><div class="card"><h1>Practice Secure</h1><p class="ok">Recovery deployment is running.</p><p>The application source has been reconnected to Render and the existing database is being verified before the full interface is restored.</p></div></body></html>`);
});

async function inspectDatabase() {
  const url = process.env.DATABASE_URL;
  if (!url) {
    console.log('RECOVERY_SCHEMA: DATABASE_URL is not configured');
    return;
  }
  const pool = new Pool({
    connectionString: url,
    ssl: /render\.com|render\.internal/i.test(url) ? { rejectUnauthorized: false } : undefined,
    max: 2,
    connectionTimeoutMillis: 10000
  });
  try {
    const tables = await pool.query("SELECT table_name FROM information_schema.tables WHERE table_schema='public' ORDER BY table_name");
    console.log('RECOVERY_SCHEMA_TABLES=' + JSON.stringify(tables.rows.map(r => r.table_name)));
    const cols = await pool.query("SELECT table_name,column_name,data_type,is_nullable,column_default FROM information_schema.columns WHERE table_schema='public' ORDER BY table_name,ordinal_position");
    console.log('RECOVERY_SCHEMA_COLUMNS=' + JSON.stringify(cols.rows));
    console.log('Practice Secure database schema inspection complete.');
  } catch (err) {
    console.error('RECOVERY_SCHEMA_ERROR=' + String(err && err.message ? err.message : err));
  } finally {
    await pool.end().catch(() => {});
  }
}

app.listen(port, '0.0.0.0', () => {
  console.log(`Practice Secure recovery server listening on port ${port}`);
  inspectDatabase().catch(err => console.error('RECOVERY_SCHEMA_FATAL=' + err.message));
});
