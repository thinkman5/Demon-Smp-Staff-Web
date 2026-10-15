'use strict';

/* ===========================================================================
 * DEMON SMP — persistence layer
 * ---------------------------------------------------------------------------
 * Two interchangeable backends behind one tiny API:
 *
 *   1. JSON files  (default) — the original behaviour, zero configuration.
 *      The panel always keeps these as a local cache/fallback so a database
 *      outage never takes the panel down.
 *
 *   2. PostgreSQL  (opt-in)  — activated by setting DATABASE_URL (or any of the
 *      Netlify DB / Neon / Supabase aliases below). Works with Netlify DB
 *      (Neon Postgres), Neon, Supabase, Railway, Render Postgres, or a local
 *      container. Users, panel settings and the audit trail are stored as
 *      JSONB rows in a single `panel_kv` table — a drop-in for the JSON model.
 *
 * The console log deliberately stays in files: it is high-volume append-only
 * data that does not belong in the settings/users document store.
 *
 * Design notes
 * ------------
 * - Writes are fire-and-forget + debounced per key, so a control-panel action
 *   never blocks on the network. The in-memory state stays authoritative and is
 *   flushed to disk synchronously by server.js as before.
 * - If DATABASE_URL is set but the `pg` package is missing, or the connection
 *   fails, the panel logs a warning and continues on JSON files rather than
 *   refusing to start.
 * =========================================================================== */

const path = require('path');

const KV_KEYS = { users: 'users', settings: 'settings', audit: 'audit' };
const WRITE_DEBOUNCE_MS = 600;

/* Accept the common provider aliases so a Netlify/Neon integration "just
 * works" whether it exports DATABASE_URL or NETLIFY_DATABASE_URL. */
function resolveDatabaseUrl() {
  const candidates = [
    process.env.DATABASE_URL,
    process.env.NETLIFY_DATABASE_URL,
    process.env.NETLIFY_DB_URL,
    process.env.POSTGRES_URL,
    process.env.POSTGRES_PRISMA_URL,
    process.env.NEON_DATABASE_URL,
  ];
  for (const value of candidates) {
    if (typeof value === 'string' && value.trim()) return value.trim();
  }
  return '';
}

function needsSsl(connectionString) {
  const explicit = String(process.env.PGSSLMODE || '').toLowerCase();
  if (explicit === 'disable') return false;
  if (explicit === 'require' || explicit === 'verify-full' || explicit === 'verify-ca') return true;
  if (/sslmode=disable/i.test(connectionString)) return false;
  // Managed providers (Neon, Supabase, Render) always require TLS; local does not.
  return !/(localhost|127\.0\.0\.1|::1)/i.test(connectionString);
}

function createStore({ dataDir }) {
  const connectionString = resolveDatabaseUrl();

  const store = {
    backend: 'json',
    enabled: false,
    ready: false,
    lastError: null,
    errors: [],
    async init() {},
    async load() {
      return {};
    },
    saveUsers() {},
    saveSettings() {},
    saveAudit() {},
    async close() {},
    describe() {
      return this.backend === 'postgres' ? 'postgres (DATABASE_URL)' : 'json files (data/)';
    },
  };

  if (!connectionString) return store;

  let Pool;
  try {
    // Lazy require so the panel still boots on JSON files if pg is absent.
    ({ Pool } = require('pg'));
  } catch (err) {
    store.lastError = 'pg module is not installed';
    console.warn('[db] DATABASE_URL is set but the "pg" package is not installed — using JSON files.');
    console.warn('[db] Run `npm install pg` to enable the Postgres backend.');
    return store;
  }

  const pool = new Pool({
    connectionString,
    ssl: needsSsl(connectionString) ? { rejectUnauthorized: false } : false,
    max: 4,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000,
    application_name: 'demon-smp-panel',
  });

  pool.on('error', (err) => {
    store.lastError = err.message;
    store.errors.push(err.message);
    if (store.errors.length > 20) store.errors.shift();
    console.error('[db] Idle client error:', err.message);
  });

  const timers = new Map();
  const pending = new Map();

  async function writeKey(key, value) {
    await pool.query(
      `INSERT INTO panel_kv (key, value, updated_at)
       VALUES ($1, $2::jsonb, now())
       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
      [key, JSON.stringify(value)]
    );
  }

  function queueSave(key, value) {
    if (!store.ready) return;
    pending.set(key, value);
    if (timers.has(key)) return;
    timers.set(
      key,
      setTimeout(async () => {
        timers.delete(key);
        const payload = pending.get(key);
        pending.delete(key);
        try {
          await writeKey(key, payload);
          store.lastError = null;
        } catch (err) {
          store.lastError = err.message;
          store.errors.push(err.message);
          if (store.errors.length > 20) store.errors.shift();
          console.error(`[db] Failed to persist "${key}":`, err.message);
        }
      }, WRITE_DEBOUNCE_MS)
    );
  }

  store.backend = 'postgres';
  store.enabled = true;

  store.init = async function init() {
    await pool.query(
      `CREATE TABLE IF NOT EXISTS panel_kv (
         key        text PRIMARY KEY,
         value      jsonb NOT NULL,
         updated_at timestamptz NOT NULL DEFAULT now()
       )`
    );
    store.ready = true;
    console.log('[db] Connected to Postgres; schema ready (table: panel_kv).');
  };

  store.load = async function load() {
    const { rows } = await pool.query('SELECT key, value FROM panel_kv');
    const out = {};
    for (const row of rows) {
      if (Object.values(KV_KEYS).includes(row.key)) out[row.key] = row.value;
    }
    return out;
  };

  store.saveUsers = (users) => queueSave(KV_KEYS.users, users);
  store.saveSettings = (settings) => queueSave(KV_KEYS.settings, settings);
  store.saveAudit = (audit) => queueSave(KV_KEYS.audit, audit);

  store.close = async function close() {
    for (const timer of timers.values()) clearTimeout(timer);
    timers.clear();
    // Best-effort flush of anything still queued.
    const final = [...pending.entries()];
    pending.clear();
    if (store.ready) {
      await Promise.allSettled(final.map(([key, value]) => writeKey(key, value)));
    }
    await pool.end().catch(() => {});
  };

  store.connectionString = connectionString;
  return store;
}

module.exports = { createStore, resolveDatabaseUrl, needsSsl, KV_KEYS };
