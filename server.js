'use strict';

/* ===========================================================================
 * DEMON SMP — Server Control Panel
 * ---------------------------------------------------------------------------
 * Backend: Express REST API + WebSocket console relay + child_process manager.
 * Hardened for internet-exposed deployments (router port forwarding):
 * helmet security headers, CORS policy, express-rate-limit on login and
 * command endpoints, JWT auth on every API route and every WebSocket client,
 * per-user token revocation and a persistent audit trail.
 * =========================================================================== */

require('dotenv').config();

const express = require('express');
const http = require('http');
const path = require('path');
const fs = require('fs');
const fsp = require('fs/promises');
const crypto = require('crypto');
const os = require('os');
const { spawn } = require('child_process');

const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const cors = require('cors');
const { rateLimit } = require('express-rate-limit');
const si = require('systeminformation');
const { WebSocketServer } = require('ws');
const { createStore } = require('./db');

/* bcrypt: prefer the native binding, fall back to the API-identical pure-JS
 * implementation. Native `bcrypt` needs a compiled addon (node-pre-gyp); on
 * Windows that build is frequently unavailable, so bcryptjs keeps the panel
 * working with the exact same algorithm and call signatures. */
let bcrypt;
try {
  bcrypt = require('bcrypt');
  if (typeof bcrypt.hash !== 'function' || typeof bcrypt.compare !== 'function') {
    throw new Error('bcrypt native binding unavailable');
  }
} catch (_) {
  bcrypt = require('bcryptjs');
}

/* ------------------------------------------------------------------ *
 * Paths & constants
 * ------------------------------------------------------------------ */
const ROOT = __dirname;
const PUBLIC_DIR = path.join(ROOT, 'public');
const DATA_DIR = process.env.DATA_DIR ? path.resolve(process.env.DATA_DIR) : path.join(ROOT, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const SETTINGS_FILE = path.join(DATA_DIR, 'settings.json');
const AUDIT_FILE = path.join(DATA_DIR, 'audit.json');
const CONSOLE_LOG = path.join(DATA_DIR, 'console.jsonl');
const CONSOLE_LOG_MAX_BYTES = 5 * 1024 * 1024;

/* Optional Postgres persistence (Netlify DB / Neon / Supabase / any Postgres).
 * When DATABASE_URL is unset the store is a no-op and the panel keeps using the
 * JSON files in DATA_DIR exactly as before. */
const store = createStore({ dataDir: DATA_DIR });

const PORT = Number(process.env.PORT || 8080);
const HOST = process.env.HOST || '0.0.0.0';
const BCRYPT_ROUNDS = 12;
const MAX_EDIT_BYTES = 2 * 1024 * 1024; // 2 MiB for view/edit of text files

const ANSI_RE = /\u001b\[[0-9;?]*[ -/]*[@-~]/g;
const TOKEN_SUB_PROTOCOL = 'bearer';

/* ------------------------------------------------------------------ *
 * Small utilities
 * ------------------------------------------------------------------ */
class HttpError extends Error {
  constructor(status, message, code) {
    super(message);
    this.status = status;
    this.code = code || undefined;
  }
}

const asyncHandler = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

function ensureDirSync(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

function readJsonSync(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (_) {
    return fallback;
  }
}

function writeJsonAtomicSync(file, value) {
  ensureDirSync(path.dirname(file));
  const tmp = `${file}.${process.pid}.${Date.now()}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(value, null, 2), 'utf8');
  fs.renameSync(tmp, file);
}

async function writeJsonAtomic(file, value) {
  ensureDirSync(path.dirname(file));
  const tmp = `${file}.${process.pid}.${Date.now()}.tmp`;
  await fsp.writeFile(tmp, JSON.stringify(value, null, 2), 'utf8');
  await fsp.rename(tmp, file);
}

function stripAnsi(text) {
  return String(text).replace(ANSI_RE, '').replace(/\r/g, '');
}

function clampInt(value, min, max, fallback) {
  const n = Number.parseInt(value, 10);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, n));
}

function deepMerge(base, override) {
  if (Array.isArray(base) || Array.isArray(override)) return override === undefined ? base : override;
  if (typeof base !== 'object' || base === null) return override === undefined ? base : override;
  if (typeof override !== 'object' || override === null) return base;
  const out = { ...base };
  for (const [key, value] of Object.entries(override)) {
    out[key] = key in base ? deepMerge(base[key], value) : value;
  }
  return out;
}

function isValidUsername(name) {
  return typeof name === 'string' && /^[A-Za-z0-9._-]{3,32}$/.test(name);
}

function passwordProblem(password) {
  if (typeof password !== 'string' || password.length < 10) return 'Password must be at least 10 characters long.';
  if (!/[A-Za-z]/.test(password) || !/[0-9]/.test(password)) {
    return 'Password must contain at least one letter and one digit.';
  }
  return null;
}

function levelForLine(line, stream) {
  if (stream === 'stderr') return 'error';
  const t = line.toUpperCase();
  if (/\b(SEVERE|ERROR|FATAL|EXCEPTION|CRASH)\b/.test(t)) return 'error';
  if (/\b(WARN|WARNING)\b/.test(t)) return 'warn';
  if (stream === 'sys') return 'system';
  return 'info';
}

/* ------------------------------------------------------------------ *
 * Default settings
 * ------------------------------------------------------------------ */
function defaultArgs() {
  return ['-Xmx4G', '-Xms2G', '-jar', 'server.jar', 'nogui'];
}

function defaultSettings() {
  return {
    panel: {
      name: 'DEMON SMP — Control Panel',
      sessionHours: clampInt(process.env.SESSION_HOURS, 1, 720, 12),
      idleTimeoutMinutes: 30,
      maxLoginAttempts: 5,
      lockoutMinutes: 15,
      allowedOrigins: (process.env.ALLOWED_ORIGINS || '')
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean),
    },
    server: {
      command: process.env.SERVER_COMMAND || 'java',
      args: process.env.SERVER_ARGS ? process.env.SERVER_ARGS.split(' ').filter(Boolean) : defaultArgs(),
      cwd: process.env.SERVER_CWD || '.',
      autoStart: false,
      autoRestart: false,
      stopCommand: 'stop',
      killTimeoutMs: 20000,
      restartDelayMs: 5000,
    },
    /* Mirrors server.properties keys — the Server Options page edits these and
     * POST /api/options/apply writes them straight into server.properties. */
    properties: {
      'server-port': 25565,
      'max-players': 20,
      difficulty: 'normal',
      motd: 'DEMON SMP',
      pvp: true,
      'online-mode': true,
      'view-distance': 10,
      'simulation-distance': 10,
      gamemode: 'survival',
      'level-name': 'world',
      'white-list': false,
      'enforce-whitelist': true,
      'enable-command-block': false,
      'spawn-protection': 16,
    },
    players: {
      whitelist: [],
      operators: [],
      muted: [],
      muteStrikes: 3,
      defaultGamemode: 'survival',
      spawn: { x: 0, y: 64, z: 0 },
      kickMessage: 'Kicked by an operator',
      banMessage: 'Banned by an operator',
      commands: {
        kick: 'kick {player} {reason}',
        ban: 'ban {player} {reason}',
        unban: 'pardon {player}',
        mute: '',
        teleportToPlayer: 'tp {player} {target}',
        teleportToCoords: 'tp {player} {x} {y} {z}',
      },
    },
    console: { maxLines: 5000 },
  };
}

let settings = deepMerge(defaultSettings(), readJsonSync(SETTINGS_FILE, {}));

function saveSettings() {
  writeJsonAtomicSync(SETTINGS_FILE, settings);
  store.saveSettings(settings);
}

/* Persist the merged configuration on first run so settings.json always
 * exists and can be hand-edited between restarts. */
saveSettings();

function serverRoot() {
  return path.resolve(ROOT, settings.server.cwd || '.');
}

/* ------------------------------------------------------------------ *
 * Audit trail
 * ------------------------------------------------------------------ */
const MAX_AUDIT = 1000;
let auditLog = readJsonSync(AUDIT_FILE, []);
if (!Array.isArray(auditLog)) auditLog = [];

function audit(entry) {
  const record = {
    id: crypto.randomUUID(),
    t: Date.now(),
    user: entry.user || null,
    action: entry.action,
    detail: entry.detail || '',
    ok: entry.ok !== false,
    ip: entry.ip || null,
    ua: entry.ua || null,
  };
  auditLog.push(record);
  if (auditLog.length > MAX_AUDIT) auditLog.splice(0, auditLog.length - MAX_AUDIT);
  try {
    writeJsonAtomicSync(AUDIT_FILE, auditLog);
  } catch (_) {
    /* audit persistence must never break a request */
  }
  store.saveAudit(auditLog);
  return record;
}

/* ------------------------------------------------------------------ *
 * User store (local JSON database)
 * ------------------------------------------------------------------ */
function bootstrapUsers() {
  let users = readJsonSync(USERS_FILE, null);
  if (Array.isArray(users) && users.length > 0) return users;

  const username = process.env.ADMIN_USERNAME || 'admin';
  const generated = !process.env.ADMIN_PASSWORD;
  const password = process.env.ADMIN_PASSWORD || crypto.randomBytes(12).toString('base64url');

  users = [
    {
      id: crypto.randomUUID(),
      username,
      role: 'admin',
      passwordHash: bcrypt.hashSync(password, BCRYPT_ROUNDS),
      tokenVersion: 1,
      createdAt: Date.now(),
      lastLoginAt: null,
      mustChangePassword: generated,
    },
  ];
  writeJsonAtomicSync(USERS_FILE, users);

  const banner = '='.repeat(64);
  console.log(`\n${banner}`);
  if (generated) {
    console.log('  First run — bootstrap administrator created.');
    console.log(`  Username: ${username}`);
    console.log(`  Password: ${password}`);
    console.log('  Change this password on the "Login System" page immediately.');
  } else {
    console.log(`  First run — administrator "${username}" created from ADMIN_PASSWORD.`);
  }
  console.log(`${banner}\n`);
  return users;
}

/* With Postgres enabled the accounts are loaded asynchronously in
 * hydrateFromStore() before listen; otherwise bootstrap synchronously. */
let users = store.enabled ? [] : bootstrapUsers();

function saveUsers() {
  writeJsonAtomicSync(USERS_FILE, users);
  store.saveUsers(users);
}

/* Pull the panel state out of the configured database (Postgres) before the
 * HTTP server starts. No-op for the JSON backend. On a brand-new database the
 * normal bootstrap admin is created and seeded. */
async function hydrateFromStore() {
  if (!store.enabled) return;
  try {
    await store.init();
    const data = await store.load();

    if (data.settings && typeof data.settings === 'object' && !Array.isArray(data.settings)) {
      settings = deepMerge(defaultSettings(), data.settings);
    }
    if (Array.isArray(data.audit)) {
      auditLog = data.audit.slice(-MAX_AUDIT);
    }
    if (Array.isArray(data.users) && data.users.length > 0) {
      users = data.users;
      console.log(`[db] Loaded ${users.length} panel account(s) from Postgres.`);
    }
  } catch (err) {
    /* The database is optional: log loudly, stop attempting writes, and keep
     * running on the JSON files so the panel is never locked out by an outage. */
    store.ready = false;
    store.lastError = err.message;
    console.error(`[db] Could not use Postgres (${err.message}) — falling back to JSON files.`);
  }

  /* Guarantee at least one account exists. bootstrapUsers() also imports an
   * existing local data/users.json, so a first connect migrates the JSON
   * state into the database. */
  if (!Array.isArray(users) || users.length === 0) {
    users = bootstrapUsers();
  }

  /* Mirror the merged state back so the database is authoritative. */
  if (store.ready) {
    saveSettings();
    saveUsers();
    console.log(`[db] Storage backend: ${store.describe()}`);
  }
}

function publicUser(user) {
  return {
    id: user.id,
    username: user.username,
    role: user.role,
    createdAt: user.createdAt,
    lastLoginAt: user.lastLoginAt,
    mustChangePassword: !!user.mustChangePassword,
  };
}

/* ------------------------------------------------------------------ *
 * JWT
 * ------------------------------------------------------------------ */
function jwtSecret() {
  if (process.env.JWT_SECRET) return process.env.JWT_SECRET;
  const file = path.join(DATA_DIR, '.jwt-secret');
  try {
    const existing = fs.readFileSync(file, 'utf8').trim();
    if (existing) return existing;
  } catch (_) {
    /* generate below */
  }
  const secret = crypto.randomBytes(48).toString('hex');
  ensureDirSync(DATA_DIR);
  fs.writeFileSync(file, secret, { mode: 0o600 });
  console.log('[auth] Generated a new JWT secret at data/.jwt-secret');
  return secret;
}

const JWT_SECRET = jwtSecret();

function issueToken(user) {
  const hours = clampInt(settings.panel.sessionHours, 1, 720, 12);
  const expiresAt = Date.now() + hours * 3600 * 1000;
  const token = jwt.sign(
    { sub: user.id, username: user.username, role: user.role, tv: user.tokenVersion },
    JWT_SECRET,
    { expiresIn: `${hours}h`, issuer: 'demon-smp-panel' }
  );
  return { token, expiresAt, hours };
}

function verifyToken(token) {
  let payload;
  try {
    payload = jwt.verify(token, JWT_SECRET, { issuer: 'demon-smp-panel' });
  } catch (_) {
    return null;
  }
  const user = users.find((u) => u.id === payload.sub);
  if (!user) return null;
  /* Revocation: bumping tokenVersion invalidates every previously issued JWT. */
  if (Number(payload.tv) !== Number(user.tokenVersion)) return null;
  return user;
}

function extractToken(req) {
  const header = req.headers.authorization || '';
  if (header.startsWith('Bearer ')) return header.slice(7).trim();

  const proto = req.headers['sec-websocket-protocol'];
  if (typeof proto === 'string') {
    const parts = proto.split(',').map((s) => s.trim());
    const idx = parts.indexOf(TOKEN_SUB_PROTOCOL);
    if (idx !== -1 && parts[idx + 1]) return parts[idx + 1];
  }

  /* Express requests expose req.query; a raw WebSocket upgrade request does not,
     so parse the query string from the URL as a fallback. */
  let queryToken = req.query && req.query.token;
  if (!queryToken && typeof req.url === 'string') {
    try {
      queryToken = new URL(req.url, `http://${req.headers.host || 'localhost'}`).searchParams.get('token');
    } catch (_) {
      queryToken = null;
    }
  }
  return typeof queryToken === 'string' && queryToken ? queryToken : null;
}

function requireAuth(req, res, next) {
  const token = extractToken(req);
  const user = token ? verifyToken(token) : null;
  if (!user) {
    return res.status(401).json({ error: 'Authentication required.', code: 'unauthenticated' });
  }
  req.user = user;
  next();
}

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Administrator privileges required.', code: 'forbidden' });
  }
  next();
}

/* ------------------------------------------------------------------ *
 * Console buffer + persistence
 * ------------------------------------------------------------------ */
let consoleBuffer = [];
let consoleSeq = 0;
let logStream = null;

function openLogStream() {
  try {
    ensureDirSync(DATA_DIR);
    logStream = fs.createWriteStream(CONSOLE_LOG, { flags: 'a' });
    logStream.on('error', () => { logStream = null; });
  } catch (_) {
    logStream = null;
  }
}
openLogStream();

function rotateLogIfNeeded() {
  try {
    const stat = fs.statSync(CONSOLE_LOG);
    if (stat.size > CONSOLE_LOG_MAX_BYTES) {
      fs.renameSync(CONSOLE_LOG, path.join(DATA_DIR, 'console.previous.jsonl'));
      if (logStream) logStream.end();
      openLogStream();
    }
  } catch (_) {
    /* file may not exist yet */
  }
}

let rotateCounter = 0;

function pushConsole(line, stream = 'stdout') {
  const text = stripAnsi(line).replace(/\s+$/, '');
  if (text === '') return null;
  const entry = {
    seq: ++consoleSeq,
    t: Date.now(),
    stream,
    level: levelForLine(text, stream),
    line: text,
  };
  consoleBuffer.push(entry);
  const max = clampInt(settings.console.maxLines, 200, 50000, 5000);
  if (consoleBuffer.length > max) consoleBuffer.splice(0, consoleBuffer.length - max);

  if (logStream) {
    logStream.write(`${JSON.stringify(entry)}\n`);
    if (++rotateCounter % 200 === 0) rotateLogIfNeeded();
  }

  scanLineForEvents(text);
  queueConsoleFlush(entry);
  return entry;
}

function pushSystemConsole(line) {
  return pushConsole(line, 'sys');
}

/* ------------------------------------------------------------------ *
 * Managed server process
 * ------------------------------------------------------------------ */
const proc = {
  child: null,
  status: 'offline', // offline | starting | online | stopping
  pid: null,
  startedAt: null,
  exitInfo: null,
  intentionalStop: false,
  restartTimer: null,
  spawnError: null,
};
const streamRemainder = { stdout: '', stderr: '' };

function processStatus() {
  return {
    status: proc.status,
    running: proc.status === 'online' || proc.status === 'starting',
    pid: proc.pid,
    startedAt: proc.startedAt,
    uptimeMs: proc.startedAt && proc.child ? Date.now() - proc.startedAt : 0,
    command: settings.server.command,
    args: settings.server.args,
    cwd: serverRoot(),
    exitInfo: proc.exitInfo,
    autoRestart: !!settings.server.autoRestart,
    playerCount: players.size,
  };
}

function splitChunk(streamName, chunk) {
  const text = streamRemainder[streamName] + chunk.toString('utf8');
  const parts = text.split('\n');
  streamRemainder[streamName] = parts.pop() ?? '';
  return parts;
}

function handleChildOutput(streamName, chunk) {
  for (const line of splitChunk(streamName, chunk)) pushConsole(line, streamName);
}

function killTree(pid, signal) {
  if (!pid) return;
  if (process.platform === 'win32') {
    try {
      spawn('taskkill', ['/pid', String(pid), '/T', '/F'], { windowsHide: true });
    } catch (_) {
      /* best effort */
    }
  } else {
    try {
      process.kill(-pid, signal || 'SIGTERM');
    } catch (_) {
      try {
        process.kill(pid, signal || 'SIGTERM');
      } catch (_) {
        /* already gone */
      }
    }
  }
}

async function checkEula() {
  const eulaFile = path.join(serverRoot(), 'eula.txt');
  try {
    const text = await fsp.readFile(eulaFile, 'utf8');
    if (/^\s*eula\s*=\s*false/im.test(text)) {
      pushSystemConsole('[panel] WARNING: eula.txt has eula=false — the Minecraft server will refuse to start.');
    }
  } catch (_) {
    /* no eula.txt: not necessarily Minecraft, ignore */
  }
}

function startProcess() {
  if (proc.child) {
    return { ok: false, message: 'Server is already running.' };
  }
  const { command, args, cwd } = settings.server;
  if (!command) {
    throw new HttpError(400, 'No server command configured.');
  }
  const workdir = serverRoot();
  if (!fs.existsSync(workdir)) {
    throw new HttpError(400, `Server working directory does not exist: ${workdir}`);
  }
  if (!fs.existsSync(path.join(workdir, 'server.jar')) && /\.jar$/i.test(args.join(' '))) {
    pushSystemConsole('[panel] NOTE: server.jar was not found in the working directory.');
  }

  proc.exitInfo = null;
  proc.spawnError = null;
  proc.intentionalStop = false;
  proc.status = 'starting';

  let child;
  try {
    child = spawn(command, args, {
      cwd: workdir,
      env: { ...process.env, PANEL_MANAGED: '1' },
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
      detached: process.platform !== 'win32',
    });
  } catch (err) {
    proc.status = 'offline';
    pushSystemConsole(`[panel] Failed to spawn "${command}": ${err.message}`);
    broadcastStatus();
    throw new HttpError(500, `Failed to spawn "${command}": ${err.message}`);
  }

  proc.child = child;
  proc.pid = child.pid;
  proc.startedAt = Date.now();
  streamRemainder.stdout = '';
  streamRemainder.stderr = '';
  pushSystemConsole(`[panel] Starting: ${command} ${args.join(' ')}`);
  pushSystemConsole(`[panel] Working directory: ${workdir}`);
  pushSystemConsole(`[panel] Process id: ${child.pid}`);
  checkEula();

  child.stdout.on('data', (chunk) => handleChildOutput('stdout', chunk));
  child.stderr.on('data', (chunk) => handleChildOutput('stderr', chunk));

  child.on('error', (err) => {
    proc.spawnError = err.message;
    pushSystemConsole(`[panel] Process error: ${err.message}`);
  });

  child.on('spawn', () => {
    proc.status = 'online';
    pushSystemConsole('[panel] Server process started.');
    broadcastStatus();
  });

  child.on('exit', (code, signal) => {
    const wasIntentional = proc.intentionalStop;
    for (const key of ['stdout', 'stderr']) {
      if (streamRemainder[key]) {
        pushConsole(streamRemainder[key], key);
        streamRemainder[key] = '';
      }
    }
    proc.child = null;
    proc.pid = null;
    proc.startedAt = null;
    proc.status = 'offline';
    proc.exitInfo = { code, signal: signal || null, at: Date.now() };
    players.clear();
    broadcastPlayers();
    pushSystemConsole(`[panel] Process exited (code=${code ?? 'null'}${signal ? `, signal=${signal}` : ''}).`);
    broadcastStatus();

    if (!wasIntentional && settings.server.autoRestart) {
      const delay = clampInt(settings.server.restartDelayMs, 1000, 60000, 5000);
      pushSystemConsole(`[panel] Auto-restart enabled — restarting in ${Math.round(delay / 1000)}s.`);
      clearTimeout(proc.restartTimer);
      proc.restartTimer = setTimeout(() => {
        if (!proc.child) {
          try {
            startProcess();
          } catch (err) {
            pushSystemConsole(`[panel] Auto-restart failed: ${err.message}`);
          }
        }
      }, delay);
    }
  });

  broadcastStatus();
  return { ok: true, message: 'Server starting.', pid: child.pid };
}

function stopProcess() {
  return new Promise((resolve) => {
    const child = proc.child;
    if (!child) {
      proc.status = 'offline';
      return resolve({ ok: false, message: 'Server is not running.' });
    }
    clearTimeout(proc.restartTimer);
    proc.intentionalStop = true;
    proc.status = 'stopping';
    broadcastStatus();

    let settled = false;
    const finish = (message) => {
      if (settled) return;
      settled = true;
      clearTimeout(graceTimer);
      resolve({ ok: true, message });
    };

    child.once('exit', () => finish('Server stopped.'));

    const stopCommand = String(settings.server.stopCommand || '').trim();
    pushSystemConsole('[panel] Requesting graceful shutdown...');
    try {
      if (stopCommand && child.stdin && child.stdin.writable) {
        child.stdin.write(`${stopCommand}\n`);
      }
    } catch (err) {
      pushSystemConsole(`[panel] Could not send stop command: ${err.message}`);
    }

    const timeout = clampInt(settings.server.killTimeoutMs, 1000, 300000, 20000);
    const graceTimer = setTimeout(() => {
      pushSystemConsole(`[panel] Graceful shutdown timed out after ${Math.round(timeout / 1000)}s — killing process tree.`);
      killTree(child.pid, 'SIGKILL');
      setTimeout(() => finish('Server force-killed.'), 2000);
    }, timeout);
  });
}

async function restartProcess() {
  if (proc.child) {
    await stopProcess();
    await new Promise((r) => setTimeout(r, 800));
  }
  return startProcess();
}

function sendCommand(command) {
  const trimmed = String(command || '').trim();
  if (!trimmed) throw new HttpError(400, 'Command must not be empty.');
  if (trimmed.length > 1000) throw new HttpError(400, 'Command is too long (max 1000 characters).');
  if (!proc.child || !proc.child.stdin || !proc.child.stdin.writable) {
    throw new HttpError(409, 'Server is not running — command was not sent.');
  }
  proc.child.stdin.write(`${trimmed}\n`);
  pushConsole(`> ${trimmed}`, 'sys');
  return trimmed;
}

/* ------------------------------------------------------------------ *
 * Player tracking
 * ------------------------------------------------------------------ */
const players = new Map(); // name -> { name, joinedAt, lastSeen }
const mutedWarnings = new Map();

/* Deliberately unanchored: real console lines carry a prefix such as
 * "[12:00:01] [Server thread/INFO]: " before the event text. */
const RE_JOIN = /\b([A-Za-z0-9_]{1,16}) (?:joined the game|joined the server)\b/i;
const RE_LEAVE = /\b([A-Za-z0-9_]{1,16}) (?:left the game|lost connection)\b/i;
const RE_LIST = /There are (\d+) of a max of (\d+) players online:?\s*(.*)$/i;
const RE_CHAT = /<([A-Za-z0-9_]{1,16})>\s?(.*)$/;

function scanLineForEvents(text) {
  let m = RE_LIST.exec(text);
  if (m) {
    const names = m[3]
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    players.clear();
    for (const name of names) players.set(name, { name, joinedAt: Date.now(), lastSeen: Date.now() });
    broadcastPlayers();
    return;
  }

  m = RE_JOIN.exec(text);
  if (m) {
    const name = m[1];
    players.set(name, { name, joinedAt: Date.now(), lastSeen: Date.now() });
    broadcastPlayers();
    return;
  }

  m = RE_LEAVE.exec(text);
  if (m) {
    players.delete(m[1]);
    mutedWarnings.delete(m[1]);
    broadcastPlayers();
    return;
  }

  m = RE_CHAT.exec(text);
  if (m) {
    const [, name, message] = m;
    const entry = players.get(name);
    if (entry) entry.lastSeen = Date.now();
    if (isMuted(name)) enforceMute(name, message);
  }
}

function playerList() {
  return [...players.values()]
    .map((p) => ({
      ...p,
      muted: isMuted(p.name),
      op: settings.players.operators.some((n) => n.toLowerCase() === p.name.toLowerCase()),
      whitelisted: settings.players.whitelist.some((n) => n.toLowerCase() === p.name.toLowerCase()),
    }))
    .sort((a, b) => a.name.localeCompare(b.name));
}

function isMuted(name) {
  return settings.players.muted.some((n) => n.toLowerCase() === String(name).toLowerCase());
}

function enforceMute(name, message) {
  const strikes = (mutedWarnings.get(name) || 0) + 1;
  mutedWarnings.set(name, strikes);

  /* Optional server-side mute command (plugins that provide one). */
  const muteCmd = String(settings.players.commands.mute || '').trim();
  if (muteCmd && strikes === 1) {
    try {
      sendCommand(applyTemplate(muteCmd, { player: name }));
    } catch (_) {
      /* server may have stopped */
    }
  }

  if (!proc.child) return;

  const limit = clampInt(settings.players.muteStrikes, 1, 50, 3);
  try {
    if (strikes >= limit) {
      sendCommand(applyTemplate(settings.players.commands.kick, { player: name, reason: 'You are muted.' }));
      mutedWarnings.delete(name);
    } else {
      sendCommand(`tell ${name} You are muted. (${strikes}/${limit})`);
    }
  } catch (_) {
    /* ignore */
  }
}

function applyTemplate(template, vars) {
  return String(template).replace(/\{(\w+)\}/g, (_, key) => (vars[key] === undefined ? '' : String(vars[key])));
}

/* ------------------------------------------------------------------ *
 * WebSocket hub
 * ------------------------------------------------------------------ */
const clients = new Set();
let pendingConsole = [];

function queueConsoleFlush(entry) {
  pendingConsole.push(entry);
  if (pendingConsole.length === 1) {
    setTimeout(flushConsole, 100);
  }
}

function flushConsole() {
  if (pendingConsole.length === 0) return;
  const entries = pendingConsole;
  pendingConsole = [];
  broadcast({ type: 'console', entries });
}

function broadcast(message) {
  if (clients.size === 0) return;
  const payload = JSON.stringify(message);
  for (const ws of clients) {
    if (ws.readyState === ws.OPEN) {
      try {
        ws.send(payload);
      } catch (_) {
        /* dropped client */
      }
    }
  }
}

function broadcastStatus() {
  broadcast({ type: 'status', status: processStatus() });
}

function broadcastPlayers() {
  broadcast({ type: 'players', players: playerList() });
}

/* ------------------------------------------------------------------ *
 * System metrics
 * ---------------------------------------------------------------------------
 * systeminformation shells out to native tooling (WMIC / PowerShell on
 * Windows), and a single probe can take many seconds on a busy or virtualised
 * host. Every probe therefore runs in the BACKGROUND and the API serves the
 * most recent cached snapshot instantly. A slow host can neither stall a
 * request nor pile up overlapping probes.
 * ------------------------------------------------------------------ */
const metrics = {
  info: null,      // static hardware/OS facts: probed once
  stats: null,     // volatile CPU / memory: sampled on an interval
  disk: null,      // filesystem usage: sampled less often
  busy: { info: false, stats: false, disk: false },
  errors: [],
};

function noteMetricsError(scope, err) {
  const message = `${scope}: ${err && err.message ? err.message : err}`;
  if (!metrics.errors.includes(message)) {
    metrics.errors.push(message);
    if (metrics.errors.length > 20) metrics.errors.shift();
  }
}

/* systeminformation spawns native helper processes. Running several probes at
 * once can deadlock or crawl on Windows, so every probe is serialised through
 * this promise chain and bounded by a timeout. */
let probeChain = Promise.resolve();

function withProbeLock(fn) {
  const run = probeChain.then(fn, fn);
  probeChain = run.then(() => {}, () => {});
  return run;
}

function withTimeout(promise, ms, label) {
  let timer;
  const guard = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
    if (timer.unref) timer.unref();
  });
  return Promise.race([promise, guard]).finally(() => clearTimeout(timer));
}

/* Safe probe: serialised, time-bounded, never throws. */
async function probe(label, fn, timeoutMs = 20000) {
  try {
    const value = await withProbeLock(() => withTimeout(Promise.resolve().then(fn), timeoutMs, label));
    return value;
  } catch (err) {
    noteMetricsError(label, err);
    return null;
  }
}

async function refreshSystemInfo() {
  if (metrics.info || metrics.busy.info) return;
  metrics.busy.info = true;
  try {
    const cpu = await probe('cpu', () => si.cpu(), 25000);
    const osInfo = await probe('osInfo', () => si.osInfo(), 25000);
    const graphics = await probe('graphics', () => si.graphics(), 25000);
    const gpu = graphics && Array.isArray(graphics.controllers) && graphics.controllers[0]
      ? { model: graphics.controllers[0].model, vram: graphics.controllers[0].vram }
      : null;
    metrics.info = {
      manufacturer: cpu ? cpu.manufacturer : '',
      brand: cpu ? cpu.brand : '',
      cores: cpu ? cpu.cores : os.cpus().length,
      physicalCores: cpu ? cpu.physicalCores : null,
      speedGHz: cpu ? cpu.speed : null,
      platform: osInfo ? osInfo.platform : os.platform(),
      distro: osInfo ? osInfo.distro : os.type(),
      release: osInfo ? osInfo.release : os.release(),
      arch: osInfo ? osInfo.arch : os.arch(),
      hostname: osInfo ? osInfo.hostname : os.hostname(),
      nodeVersion: process.version,
      serverRoot: serverRoot(),
      gpu,
    };
  } finally {
    metrics.busy.info = false;
  }
}

async function refreshDisk() {
  if (metrics.busy.disk) return;
  metrics.busy.disk = true;
  try {
    const target = serverRoot().toLowerCase();
    const disks = await probe('fsSize', () => si.fsSize(), 25000);
    if (Array.isArray(disks) && disks.length) {
      /* Prefer the deepest mount point containing the server directory. */
      let best = null;
      let bestLen = -1;
      for (const d of disks) {
        const mount = String(d.mount || '').toLowerCase();
        if (mount && target.startsWith(mount) && mount.length > bestLen) {
          best = d;
          bestLen = mount.length;
        }
      }
      if (!best) best = disks.find((d) => d.mount === '/') || disks[0];
      metrics.disk = {
        mount: best.mount,
        fs: best.fs,
        type: best.type,
        size: best.size,
        used: best.used,
        available: best.available,
        usePercent: typeof best.use === 'number' && Number.isFinite(best.use)
          ? best.use
          : best.size ? (best.used / best.size) * 100 : 0,
      };
    }
  } finally {
    metrics.busy.disk = false;
  }
}

async function refreshStats() {
  if (metrics.busy.stats) return;
  metrics.busy.stats = true;
  try {
    const load = await probe('currentLoad', () => si.currentLoad(), 12000);
    const mem = await probe('mem', () => si.mem(), 12000);
    const time = await probe('time', () => si.time(), 5000);

    /* os.* fallbacks keep the dashboard alive if a probe fails outright. */
    const memTotal = (mem && mem.total) || os.totalmem();
    const memUsed = mem ? mem.active || mem.used : os.totalmem() - os.freemem();

    metrics.stats = {
      t: Date.now(),
      cpu: {
        currentLoad: load && Number.isFinite(load.currentLoad) ? load.currentLoad : 0,
        currentLoadUser: load ? load.currentLoadUser : 0,
        currentLoadSystem: load ? load.currentLoadSystem : 0,
        cores: load && Array.isArray(load.cpus) ? load.cpus.map((c) => c.load) : [],
        threads: metrics.info ? metrics.info.cores : os.cpus().length,
      },
      memory: {
        total: memTotal,
        used: memUsed,
        free: Math.max(0, memTotal - memUsed),
        usePercent: memTotal ? (memUsed / memTotal) * 100 : 0,
      },
      disk: metrics.disk,
      uptime: time && Number.isFinite(time.uptime) ? time.uptime : os.uptime(),
      gpu: metrics.info ? metrics.info.gpu : null,
      process: processStatus(),
    };
  } finally {
    metrics.busy.stats = false;
  }
}

/* Kicks off any missing probe without blocking the caller. Warm-up is
 * single-flight and sequential so it never floods the OS with probes. */
let warming = false;

function ensureMetrics() {
  if (warming) return;
  if (metrics.info && metrics.disk && metrics.stats) return;
  warming = true;
  (async () => {
    try {
      if (!metrics.info) await refreshSystemInfo().catch(() => {});
      if (!metrics.disk) await refreshDisk().catch(() => {});
      if (!metrics.stats) await refreshStats().catch(() => {});
    } finally {
      warming = false;
    }
  })();
}

async function systemStats() {
  ensureMetrics();
  if (!metrics.stats) {
    /* First few seconds after boot: report a placeholder so the UI can show
       "measuring" rather than misleading zeroes. */
    await refreshStats().catch(() => {});
  }
  return metrics.stats || {
    t: Date.now(),
    cpu: { currentLoad: 0, currentLoadUser: 0, currentLoadSystem: 0, cores: [], threads: os.cpus().length },
    memory: { total: os.totalmem(), used: os.totalmem() - os.freemem(), free: os.freemem(), usePercent: 0 },
    disk: metrics.disk,
    uptime: os.uptime(),
    gpu: null,
    process: processStatus(),
  };
}

async function systemInfo() {
  ensureMetrics();
  if (!metrics.info) await refreshSystemInfo().catch(() => {});
  return metrics.info || {
    manufacturer: '', brand: '', cores: os.cpus().length, physicalCores: null, speedGHz: null,
    platform: os.platform(), distro: os.type(), release: os.release(), arch: os.arch(),
    hostname: os.hostname(), nodeVersion: process.version, serverRoot: serverRoot(), gpu: null,
  };
}

/* ------------------------------------------------------------------ *
 * Express app
 * ------------------------------------------------------------------ */
const app = express();
app.disable('x-powered-by');

/* Port-forwarded deployments are usually direct (no proxy), so trust proxy
 * stays off by default and req.ip is the true client address. Set
 * TRUST_PROXY=true when running behind a tunnel/reverse proxy. */
const TRUST_PROXY = String(process.env.TRUST_PROXY || '').toLowerCase();
if (TRUST_PROXY === 'true') app.set('trust proxy', 1);
else if (TRUST_PROXY === 'false' || TRUST_PROXY === '') app.set('trust proxy', false);
else app.set('trust proxy', TRUST_PROXY);

app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        'default-src': ["'self'"],
        'script-src': ["'self'", "'unsafe-inline'", "'unsafe-eval'", 'https://cdn.tailwindcss.com'],
        'style-src': ["'self'", "'unsafe-inline'", 'https://cdn.tailwindcss.com'],
        'img-src': ["'self'", 'data:'],
        'font-src': ["'self'", 'data:'],
        'connect-src': ["'self'", 'ws:', 'wss:'],
        'object-src': ["'none'"],
        'base-uri': ["'self'"],
        'form-action': ["'self'"],
        'frame-ancestors': ["'none'"],
      },
    },
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: { policy: 'same-origin' },
    referrerPolicy: { policy: 'no-referrer' },
    hsts: false, // TLS terminates at the router/tunnel in these deployments
    xFrameOptions: { action: 'deny' },
  })
);

function originAllowed(origin) {
  if (!origin) return true; // same-origin fetches and non-browser clients
  const list = settings.panel.allowedOrigins || [];
  if (list.length === 0) return true; // reflect any origin (Bearer tokens, no cookies)
  if (list.includes('*')) return true;
  return list.some((allowed) => allowed.toLowerCase() === origin.toLowerCase());
}

app.use(
  cors({
    origin(origin, callback) {
      callback(null, originAllowed(origin) ? origin || true : false);
    },
    credentials: false,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Authorization', 'Content-Type', 'X-Requested-With'],
    maxAge: 600,
  })
);

app.use(express.json({ limit: '3mb' }));
app.use(express.urlencoded({ extended: false, limit: '1mb' }));

/* Rate limiters — critical on an internet-exposed port. */
const limiterOptions = {
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  validate: { trustProxy: false, xForwardedForHeader: false },
};

const apiLimiter = rateLimit({
  ...limiterOptions,
  windowMs: 60 * 1000,
  limit: 300,
  message: { error: 'Too many requests — slow down.' },
});

const loginLimiter = rateLimit({
  ...limiterOptions,
  windowMs: 15 * 60 * 1000,
  limit: 10,
  skipSuccessfulRequests: true,
  message: { error: 'Too many failed login attempts. Try again in 15 minutes.' },
});

const commandLimiter = rateLimit({
  ...limiterOptions,
  windowMs: 60 * 1000,
  limit: 120,
  message: { error: 'Too many commands — slow down.' },
});

const writeLimiter = rateLimit({
  ...limiterOptions,
  windowMs: 60 * 1000,
  limit: 90,
  message: { error: 'Too many write operations — slow down.' },
});

app.use('/api', apiLimiter);

/* ------------------------------------------------------------------ *
 * Public routes
 * ------------------------------------------------------------------ */
app.get('/api/health', (req, res) => {
  res.json({
    ok: true,
    panel: settings.panel.name,
    status: proc.status,
    time: Date.now(),
    version: '1.0.0',
    storage: store.describe(),
    storageReady: store.backend === 'json' ? true : store.ready,
    storageError: store.lastError,
  });
});

app.post('/api/auth/login', loginLimiter, asyncHandler(async (req, res) => {
  const username = String((req.body && req.body.username) || '').trim();
  const password = String((req.body && req.body.password) || '');
  const ctx = { ip: req.ip, ua: req.get('user-agent') || null, user: username };

  if (!username || !password) {
    audit({ ...ctx, action: 'login', ok: false, detail: 'Missing credentials' });
    return res.status(400).json({ error: 'Username and password are required.' });
  }

  const user = users.find((u) => u.username.toLowerCase() === username.toLowerCase());
  /* Always run a hash comparison so response timing does not leak whether the
     account exists. */
  const hash = user ? user.passwordHash : '$2a$12$0000000000000000000000000000000000000000000000000000';
  const ok = await bcrypt.compare(password, hash);

  if (!user || !ok) {
    audit({ ...ctx, action: 'login', ok: false, detail: 'Invalid credentials' });
    return res.status(401).json({ error: 'Invalid username or password.' });
  }

  user.lastLoginAt = Date.now();
  if (user.mustChangePassword) {
    /* Keep the flag until the password is actually changed. */
  }
  saveUsers();

  const session = issueToken(user);
  audit({ ...ctx, action: 'login', ok: true, detail: `Signed in as ${user.username}` });
  res.json({
    token: session.token,
    expiresAt: session.expiresAt,
    user: publicUser(user),
  });
}));

/* ------------------------------------------------------------------ *
 * Authenticated routes
 * ------------------------------------------------------------------ */
app.post('/api/auth/logout', requireAuth, (req, res) => {
  audit({ user: req.user.username, action: 'logout', ip: req.ip, ua: req.get('user-agent') });
  res.json({ ok: true });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  res.json({ user: publicUser(req.user), expiresAt: null });
});

app.post('/api/auth/password', requireAuth, writeLimiter, asyncHandler(async (req, res) => {
  const current = String((req.body && req.body.currentPassword) || '');
  const next = String((req.body && req.body.newPassword) || '');

  const ok = await bcrypt.compare(current, req.user.passwordHash);
  if (!ok) {
    audit({ user: req.user.username, action: 'change-password', ok: false, detail: 'Wrong current password', ip: req.ip });
    return res.status(400).json({ error: 'Current password is incorrect.' });
  }
  const problem = passwordProblem(next);
  if (problem) return res.status(400).json({ error: problem });

  req.user.passwordHash = await bcrypt.hash(next, BCRYPT_ROUNDS);
  req.user.tokenVersion += 1; // invalidate every other session
  req.user.mustChangePassword = false;
  saveUsers();
  audit({ user: req.user.username, action: 'change-password', ok: true, ip: req.ip });

  const session = issueToken(req.user);
  res.json({ ok: true, token: session.token, expiresAt: session.expiresAt, user: publicUser(req.user) });
}));

app.get('/api/auth/activity', requireAuth, (req, res) => {
  const entries = auditLog
    .filter((e) => e.action === 'login' || e.action === 'logout' || e.action === 'change-password')
    .slice()
    .reverse()
    .slice(0, 100);
  res.json({ activity: entries });
});

/* ------------------------------- Users ------------------------------- */
app.get('/api/users', requireAuth, requireAdmin, (req, res) => {
  res.json({ users: users.map(publicUser) });
});

app.post('/api/users', requireAuth, requireAdmin, writeLimiter, asyncHandler(async (req, res) => {
  const username = String((req.body && req.body.username) || '').trim();
  const password = String((req.body && req.body.password) || '');
  const role = (req.body && req.body.role) === 'viewer' ? 'viewer' : 'admin';

  if (!isValidUsername(username)) {
    return res.status(400).json({ error: 'Username must be 3-32 characters: letters, digits, dot, dash or underscore.' });
  }
  if (users.some((u) => u.username.toLowerCase() === username.toLowerCase())) {
    return res.status(409).json({ error: 'That username already exists.' });
  }
  const problem = passwordProblem(password);
  if (problem) return res.status(400).json({ error: problem });

  const user = {
    id: crypto.randomUUID(),
    username,
    role,
    passwordHash: await bcrypt.hash(password, BCRYPT_ROUNDS),
    tokenVersion: 1,
    createdAt: Date.now(),
    lastLoginAt: null,
    mustChangePassword: false,
  };
  users.push(user);
  saveUsers();
  audit({ user: req.user.username, action: 'user-create', ok: true, detail: `Created ${username} (${role})`, ip: req.ip });
  res.status(201).json({ user: publicUser(user) });
}));

app.patch('/api/users/:id', requireAuth, requireAdmin, writeLimiter, asyncHandler(async (req, res) => {
  const target = users.find((u) => u.id === req.params.id);
  if (!target) return res.status(404).json({ error: 'User not found.' });

  const body = req.body || {};
  let changed = [];

  if (body.role !== undefined) {
    const role = body.role === 'viewer' ? 'viewer' : body.role === 'admin' ? 'admin' : null;
    if (!role) return res.status(400).json({ error: 'Role must be "admin" or "viewer".' });
    if (target.role === 'admin' && role === 'viewer' && adminCount() === 1) {
      return res.status(400).json({ error: 'Cannot demote the only remaining administrator.' });
    }
    target.role = role;
    target.tokenVersion += 1;
    changed.push(`role=${role}`);
  }

  if (body.username !== undefined) {
    const username = String(body.username).trim();
    if (!isValidUsername(username)) {
      return res.status(400).json({ error: 'Username must be 3-32 characters: letters, digits, dot, dash or underscore.' });
    }
    if (users.some((u) => u.id !== target.id && u.username.toLowerCase() === username.toLowerCase())) {
      return res.status(409).json({ error: 'That username already exists.' });
    }
    target.username = username;
    changed.push(`username=${username}`);
  }

  if (body.password !== undefined) {
    const problem = passwordProblem(String(body.password));
    if (problem) return res.status(400).json({ error: problem });
    target.passwordHash = await bcrypt.hash(String(body.password), BCRYPT_ROUNDS);
    target.tokenVersion += 1;
    target.mustChangePassword = false;
    changed.push('password');
  }

  saveUsers();
  audit({ user: req.user.username, action: 'user-update', ok: true, detail: `${target.username}: ${changed.join(', ') || 'no change'}`, ip: req.ip });
  res.json({ user: publicUser(target) });
}));

app.delete('/api/users/:id', requireAuth, requireAdmin, writeLimiter, (req, res) => {
  const index = users.findIndex((u) => u.id === req.params.id);
  if (index === -1) return res.status(404).json({ error: 'User not found.' });
  const target = users[index];

  if (target.id === req.user.id) {
    return res.status(400).json({ error: 'You cannot delete your own account while signed in.' });
  }
  if (target.role === 'admin' && adminCount() === 1) {
    return res.status(400).json({ error: 'Cannot delete the only remaining administrator.' });
  }

  users.splice(index, 1);
  saveUsers();
  audit({ user: req.user.username, action: 'user-delete', ok: true, detail: `Deleted ${target.username}`, ip: req.ip });
  res.json({ ok: true });
});

function adminCount() {
  return users.filter((u) => u.role === 'admin').length;
}

/* ------------------------------ System ------------------------------ */
/* Served from cache: never blocks on a slow probe. */
app.get('/api/system/stats', requireAuth, (req, res) => {
  ensureMetrics();
  res.json({
    stats: metrics.stats,
    info: metrics.info,
    ready: Boolean(metrics.stats && metrics.info),
    warnings: metrics.errors,
  });
});

app.get('/api/system/info', requireAuth, (req, res) => {
  ensureMetrics();
  res.json({ info: metrics.info, ready: Boolean(metrics.info) });
});

/* ------------------------------ Process ----------------------------- */
app.get('/api/process/status', requireAuth, (req, res) => {
  res.json({ status: processStatus() });
});

app.post('/api/process/start', requireAuth, requireAdmin, commandLimiter, (req, res) => {
  const result = startProcess();
  audit({ user: req.user.username, action: 'process-start', ok: result.ok, detail: result.message, ip: req.ip });
  res.json({ ok: result.ok, message: result.message, status: processStatus() });
});

app.post('/api/process/stop', requireAuth, requireAdmin, commandLimiter, asyncHandler(async (req, res) => {
  const result = await stopProcess();
  audit({ user: req.user.username, action: 'process-stop', ok: result.ok, detail: result.message, ip: req.ip });
  res.json({ ok: result.ok, message: result.message, status: processStatus() });
}));

app.post('/api/process/restart', requireAuth, requireAdmin, commandLimiter, asyncHandler(async (req, res) => {
  const result = await restartProcess();
  audit({ user: req.user.username, action: 'process-restart', ok: result.ok, detail: result.message, ip: req.ip });
  res.json({ ok: result.ok, message: result.message, status: processStatus() });
}));

app.post('/api/process/command', requireAuth, requireAdmin, commandLimiter, (req, res) => {
  const sent = sendCommand(req.body && req.body.command);
  audit({ user: req.user.username, action: 'command', ok: true, detail: sent, ip: req.ip });
  res.json({ ok: true, command: sent });
});

/* ------------------------------ Players ----------------------------- */
app.get('/api/players', requireAuth, (req, res) => {
  res.json({ players: playerList() });
});

app.post('/api/players/refresh', requireAuth, commandLimiter, (req, res) => {
  try {
    sendCommand('list');
  } catch (err) {
    return res.status(err.status || 500).json({ error: err.message });
  }
  res.json({ ok: true, message: 'Requested the player list from the server.' });
});

function playerAction(req, res, action, buildCommand) {
  const name = String(req.params.name || '').trim();
  if (!/^[A-Za-z0-9_.-]{1,32}$/.test(name)) {
    return res.status(400).json({ error: 'Invalid player name.' });
  }
  let command;
  try {
    command = buildCommand(name);
    sendCommand(command);
  } catch (err) {
    return res.status(err.status || 500).json({ error: err.message });
  }
  audit({ user: req.user.username, action: `player-${action}`, ok: true, detail: `${name}: ${command}`, ip: req.ip });
  res.json({ ok: true, command });
}

app.post('/api/players/:name/kick', requireAuth, requireAdmin, commandLimiter, (req, res) =>
  playerAction(req, res, 'kick', (name) =>
    applyTemplate(settings.players.commands.kick, {
      player: name,
      reason: (req.body && req.body.reason) || settings.players.kickMessage,
    })
  )
);

app.post('/api/players/:name/ban', requireAuth, requireAdmin, commandLimiter, (req, res) =>
  playerAction(req, res, 'ban', (name) =>
    applyTemplate(settings.players.commands.ban, {
      player: name,
      reason: (req.body && req.body.reason) || settings.players.banMessage,
    })
  )
);

app.post('/api/players/:name/unban', requireAuth, requireAdmin, commandLimiter, (req, res) =>
  playerAction(req, res, 'unban', (name) => applyTemplate(settings.players.commands.unban, { player: name }))
);

app.post('/api/players/:name/mute', requireAuth, requireAdmin, commandLimiter, (req, res) => {
  const name = String(req.params.name || '').trim();
  if (!/^[A-Za-z0-9_.-]{1,32}$/.test(name)) return res.status(400).json({ error: 'Invalid player name.' });
  const mute = (req.body && req.body.mute) !== false;

  settings.players.muted = settings.players.muted.filter((n) => n.toLowerCase() !== name.toLowerCase());
  if (mute) {
    settings.players.muted.push(name);
    mutedWarnings.set(name, 0);
  } else {
    mutedWarnings.delete(name);
  }
  saveSettings();

  /* If the server provides a native mute command, use it as well. */
  const muteCmd = String(settings.players.commands.mute || '').trim();
  let command = null;
  if (muteCmd && proc.child) {
    command = applyTemplate(muteCmd, { player: name, action: mute ? 'mute' : 'unmute' });
    try {
      sendCommand(command);
    } catch (_) {
      command = null;
    }
  }

  audit({ user: req.user.username, action: mute ? 'player-mute' : 'player-unmute', ok: true, detail: name, ip: req.ip });
  broadcastPlayers();
  res.json({ ok: true, muted: mute, command });
});

app.post('/api/players/:name/teleport', requireAuth, requireAdmin, commandLimiter, (req, res) => {
  const name = String(req.params.name || '').trim();
  if (!/^[A-Za-z0-9_.-]{1,32}$/.test(name)) return res.status(400).json({ error: 'Invalid player name.' });

  const body = req.body || {};
  const to = String(body.target || '').trim();
  let command;

  if (to) {
    if (!/^[A-Za-z0-9_.-]{1,32}$/.test(to)) return res.status(400).json({ error: 'Invalid teleport target.' });
    command = applyTemplate(settings.players.commands.teleportToPlayer, { player: name, target: to });
  } else {
    const x = Number(body.x);
    const y = Number(body.y);
    const z = Number(body.z);
    if (![x, y, z].every(Number.isFinite)) {
      return res.status(400).json({ error: 'Provide either a target player or numeric x/y/z coordinates.' });
    }
    command = applyTemplate(settings.players.commands.teleportToCoords, { player: name, x, y, z });
  }

  try {
    sendCommand(command);
  } catch (err) {
    return res.status(err.status || 500).json({ error: err.message });
  }
  audit({ user: req.user.username, action: 'player-teleport', ok: true, detail: `${name}: ${command}`, ip: req.ip });
  res.json({ ok: true, command });
});

/* --------------------------- Player settings ------------------------ */
app.get('/api/player-settings', requireAuth, (req, res) => {
  res.json({ settings: settings.players });
});

app.put('/api/player-settings', requireAuth, requireAdmin, writeLimiter, (req, res) => {
  const body = req.body || {};
  const next = deepMerge(settings.players, {});

  const asNames = (value, field) => {
    if (value === undefined) return undefined;
    if (!Array.isArray(value)) throw new HttpError(400, `${field} must be an array of names.`);
    const names = [];
    for (const raw of value) {
      const name = String(raw).trim();
      if (!name) continue;
      if (!/^[A-Za-z0-9_.-]{1,32}$/.test(name)) throw new HttpError(400, `Invalid name in ${field}: ${name}`);
      if (!names.some((n) => n.toLowerCase() === name.toLowerCase())) names.push(name);
    }
    return names;
  };

  try {
    const whitelist = asNames(body.whitelist, 'whitelist');
    if (whitelist) next.whitelist = whitelist;
    const operators = asNames(body.operators, 'operators');
    if (operators) next.operators = operators;
    const muted = asNames(body.muted, 'muted');
    if (muted) next.muted = muted;

    if (body.defaultGamemode !== undefined) next.defaultGamemode = String(body.defaultGamemode);
    if (body.muteStrikes !== undefined) next.muteStrikes = clampInt(body.muteStrikes, 1, 50, next.muteStrikes);
    if (body.kickMessage !== undefined) next.kickMessage = String(body.kickMessage).slice(0, 200);
    if (body.banMessage !== undefined) next.banMessage = String(body.banMessage).slice(0, 200);

    if (body.spawn && typeof body.spawn === 'object') {
      next.spawn = {
        x: Number.isFinite(Number(body.spawn.x)) ? Number(body.spawn.x) : next.spawn.x,
        y: Number.isFinite(Number(body.spawn.y)) ? Number(body.spawn.y) : next.spawn.y,
        z: Number.isFinite(Number(body.spawn.z)) ? Number(body.spawn.z) : next.spawn.z,
      };
    }
    if (body.commands && typeof body.commands === 'object') {
      next.commands = { ...next.commands };
      for (const key of Object.keys(next.commands)) {
        if (typeof body.commands[key] === 'string') next.commands[key] = body.commands[key].slice(0, 300);
      }
    }
  } catch (err) {
    if (err instanceof HttpError) return res.status(err.status).json({ error: err.message });
    throw err;
  }

  settings.players = next;
  saveSettings();
  audit({ user: req.user.username, action: 'player-settings-update', ok: true, ip: req.ip });
  broadcastPlayers();
  res.json({ settings: settings.players });
});

app.post('/api/player-settings/apply', requireAuth, requireAdmin, commandLimiter, asyncHandler(async (req, res) => {
  const dispatched = [];
  const skipped = [];

  const run = (command) => {
    try {
      sendCommand(command);
      dispatched.push(command);
    } catch (err) {
      skipped.push(`${command} (${err.message})`);
    }
  };

  for (const name of settings.players.whitelist) run(`whitelist add ${name}`);
  for (const name of settings.players.operators) run(`op ${name}`);
  run(`defaultgamemode ${settings.players.defaultGamemode}`);
  const { x, y, z } = settings.players.spawn;
  run(`setworldspawn ${x} ${y} ${z}`);

  const props = { 'white-list': settings.players.whitelist.length > 0, 'enforce-whitelist': true };
  let file = null;
  try {
    file = await applyProperties(props);
  } catch (err) {
    skipped.push(`server.properties (${err.message})`);
  }

  audit({ user: req.user.username, action: 'player-settings-apply', ok: true, detail: `${dispatched.length} commands`, ip: req.ip });
  res.json({ ok: true, dispatched, skipped, propertiesFile: file });
}));

/* ------------------------------ Options ----------------------------- */
app.get('/api/options', requireAuth, (req, res) => {
  res.json({
    server: settings.server,
    properties: settings.properties,
    panel: settings.panel,
    propertiesFile: path.join(serverRoot(), 'server.properties'),
  });
});

app.put('/api/options', requireAuth, requireAdmin, writeLimiter, (req, res) => {
  const body = req.body || {};

  if (body.server && typeof body.server === 'object') {
    const s = body.server;
    if (s.command !== undefined) {
      const command = String(s.command).trim();
      if (!command) return res.status(400).json({ error: 'Server command must not be empty.' });
      settings.server.command = command;
    }
    if (s.args !== undefined) {
      const args = Array.isArray(s.args)
        ? s.args.map((a) => String(a))
        : String(s.args).split(/\s+/).filter(Boolean);
      settings.server.args = args;
    }
    if (s.cwd !== undefined) {
      const cwd = String(s.cwd).trim() || '.';
      const resolved = path.resolve(ROOT, cwd);
      if (!fs.existsSync(resolved)) {
        return res.status(400).json({ error: `Working directory does not exist: ${resolved}` });
      }
      settings.server.cwd = cwd;
    }
    if (s.autoStart !== undefined) settings.server.autoStart = !!s.autoStart;
    if (s.autoRestart !== undefined) settings.server.autoRestart = !!s.autoRestart;
    if (s.stopCommand !== undefined) settings.server.stopCommand = String(s.stopCommand).slice(0, 100);
    if (s.killTimeoutMs !== undefined) settings.server.killTimeoutMs = clampInt(s.killTimeoutMs, 1000, 300000, 20000);
    if (s.restartDelayMs !== undefined) settings.server.restartDelayMs = clampInt(s.restartDelayMs, 1000, 60000, 5000);
  }

  if (body.properties && typeof body.properties === 'object') {
    const allowedTypes = settings.properties;
    for (const [key, value] of Object.entries(body.properties)) {
      if (!/^[A-Za-z0-9._-]{1,64}$/.test(key)) continue;
      if (typeof value === 'boolean' || typeof value === 'number' || typeof value === 'string') {
        allowedTypes[key] = typeof value === 'string' ? value.slice(0, 300) : value;
      }
    }
  }

  if (body.panel && typeof body.panel === 'object') {
    const p = body.panel;
    if (p.name !== undefined) settings.panel.name = String(p.name).slice(0, 80);
    if (p.sessionHours !== undefined) settings.panel.sessionHours = clampInt(p.sessionHours, 1, 720, 12);
    if (p.idleTimeoutMinutes !== undefined) settings.panel.idleTimeoutMinutes = clampInt(p.idleTimeoutMinutes, 0, 720, 30);
    if (p.maxLoginAttempts !== undefined) settings.panel.maxLoginAttempts = clampInt(p.maxLoginAttempts, 1, 100, 5);
    if (p.lockoutMinutes !== undefined) settings.panel.lockoutMinutes = clampInt(p.lockoutMinutes, 1, 1440, 15);
    if (Array.isArray(p.allowedOrigins)) {
      settings.panel.allowedOrigins = p.allowedOrigins.map((o) => String(o).trim()).filter(Boolean).slice(0, 50);
    }
    if (p.consoleMaxLines !== undefined) settings.console.maxLines = clampInt(p.consoleMaxLines, 200, 50000, 5000);
  }

  saveSettings();
  audit({ user: req.user.username, action: 'options-update', ok: true, ip: req.ip });
  res.json({ server: settings.server, properties: settings.properties, panel: settings.panel });
});

/* Writes the configured properties into server.properties, preserving
 * comments and unknown keys. */
async function applyProperties(props) {
  const file = path.join(serverRoot(), 'server.properties');
  const format = (v) => (typeof v === 'boolean' ? (v ? 'true' : 'false') : String(v));

  let lines = [];
  try {
    lines = (await fsp.readFile(file, 'utf8')).split(/\r?\n/);
  } catch (_) {
    lines = ['#Minecraft server properties'];
  }
  /* Drop trailing blank lines so appended keys do not leave a gap. */
  while (lines.length && lines[lines.length - 1].trim() === '') lines.pop();

  const seen = new Set();
  const out = lines.map((line) => {
    const m = /^\s*([^#\s][^=]*)=(.*)$/.exec(line);
    if (!m) return line;
    const key = m[1].trim();
    if (Object.prototype.hasOwnProperty.call(props, key)) {
      seen.add(key);
      return `${key}=${format(props[key])}`;
    }
    return line;
  });

  for (const [key, value] of Object.entries(props)) {
    if (!seen.has(key)) out.push(`${key}=${format(value)}`);
  }

  await fsp.writeFile(file, `${out.join('\n').replace(/\n+$/, '')}\n`, 'utf8');
  return file;
}

app.post('/api/options/apply', requireAuth, requireAdmin, writeLimiter, asyncHandler(async (req, res) => {
  const props = (req.body && req.body.properties) || settings.properties;
  const file = await applyProperties(props);
  audit({ user: req.user.username, action: 'options-apply', ok: true, detail: file, ip: req.ip });
  res.json({ ok: true, file, properties: props });
}));

/* Reads server.properties from disk so the UI can import live values. */
app.get('/api/options/properties', requireAuth, asyncHandler(async (req, res) => {
  const file = path.join(serverRoot(), 'server.properties');
  try {
    const text = await fsp.readFile(file, 'utf8');
    const parsed = {};
    for (const line of text.split(/\r?\n/)) {
      const m = /^\s*([^#\s][^=]*)=(.*)$/.exec(line);
      if (m) parsed[m[1].trim()] = m[2].trim();
    }
    res.json({ file, exists: true, properties: parsed });
  } catch (_) {
    res.json({ file, exists: false, properties: {} });
  }
}));

/* -------------------------------- Files ----------------------------- */
function resolveInRoot(relative) {
  const root = serverRoot();
  const cleaned = String(relative || '.').replace(/\\/g, '/').replace(/^\/+/, '');
  const target = path.resolve(root, cleaned);
  const rel = path.relative(root, target);
  if (rel.startsWith('..') || path.isAbsolute(rel)) {
    throw new HttpError(400, 'Path escapes the server directory.');
  }
  return target;
}

function resolveExisting(relative) {
  const target = resolveInRoot(relative);
  let realRoot;
  let realTarget;
  try {
    realRoot = fs.realpathSync(serverRoot());
    realTarget = fs.realpathSync(target);
  } catch (_) {
    throw new HttpError(404, 'Path not found.');
  }
  const rel = path.relative(realRoot, realTarget);
  if (rel.startsWith('..') || path.isAbsolute(rel)) {
    throw new HttpError(400, 'Path escapes the server directory.');
  }
  return realTarget;
}

const TEXT_EXTENSIONS = new Set([
  '.txt', '.log', '.json', '.json5', '.yml', '.yaml', '.properties', '.conf', '.cfg', '.ini', '.toml',
  '.md', '.markdown', '.csv', '.tsv', '.js', '.mjs', '.cjs', '.ts', '.jsx', '.tsx', '.html', '.htm',
  '.css', '.sh', '.bat', '.cmd', '.ps1', '.xml', '.env', '.sql', '.java', '.py', '.rb', '.php', '.go',
]);

function looksBinary(buffer) {
  const sample = buffer.subarray(0, Math.min(buffer.length, 8000));
  return sample.includes(0);
}

function isTextLike(filePath, buffer) {
  if (looksBinary(buffer)) return false;
  const ext = path.extname(filePath).toLowerCase();
  if (TEXT_EXTENSIONS.has(ext)) return true;
  if (ext === '') return true;
  /* Unknown extension: accept if the sample decodes cleanly as UTF-8. */
  try {
    new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(0, Math.min(buffer.length, 8000)));
    return true;
  } catch (_) {
    return false;
  }
}

app.get('/api/files', requireAuth, asyncHandler(async (req, res) => {
  const relative = req.query.path || '.';
  const target = resolveInRoot(relative);
  const realTarget = resolveExisting(relative);

  const stat = await fsp.stat(realTarget);
  if (!stat.isDirectory()) throw new HttpError(400, 'Not a directory.');

  const entries = await fsp.readdir(realTarget, { withFileTypes: true });
  const items = await Promise.all(
    entries.map(async (entry) => {
      const full = path.join(realTarget, entry.name);
      let info = null;
      try {
        info = await fsp.stat(full);
      } catch (_) {
        /* broken symlink */
      }
      const isDir = entry.isDirectory() || (info && info.isDirectory());
      return {
        name: entry.name,
        path: path.relative(serverRoot(), full).split(path.sep).join('/'),
        type: isDir ? 'directory' : 'file',
        size: info ? info.size : 0,
        modifiedAt: info ? info.mtimeMs : 0,
        extension: isDir ? '' : path.extname(entry.name).toLowerCase(),
      };
    })
  );

  items.sort((a, b) => {
    if (a.type !== b.type) return a.type === 'directory' ? -1 : 1;
    return a.name.localeCompare(b.name);
  });

  const relPath = path.relative(serverRoot(), realTarget).split(path.sep).join('/');
  res.json({
    path: relPath === '' ? '.' : relPath,
    root: serverRoot(),
    parent: relPath === '' ? null : (path.dirname(relPath) === '.' ? '.' : path.dirname(relPath).split(path.sep).join('/')),
    entries: items,
  });
}));

app.get('/api/files/content', requireAuth, asyncHandler(async (req, res) => {
  const realTarget = resolveExisting(req.query.path);
  const stat = await fsp.stat(realTarget);
  if (stat.isDirectory()) throw new HttpError(400, 'That path is a directory.');
  if (stat.size > MAX_EDIT_BYTES) {
    throw new HttpError(413, `File is too large to open (${(stat.size / 1024 / 1024).toFixed(1)} MB). Limit is 2 MB.`);
  }

  const buffer = await fsp.readFile(realTarget);
  if (!isTextLike(realTarget, buffer)) {
    throw new HttpError(415, 'File appears to be binary and cannot be edited as text.');
  }
  res.json({
    path: path.relative(serverRoot(), realTarget).split(path.sep).join('/'),
    size: stat.size,
    modifiedAt: stat.mtimeMs,
    content: buffer.toString('utf8'),
  });
}));

app.put('/api/files/content', requireAuth, requireAdmin, writeLimiter, asyncHandler(async (req, res) => {
  const body = req.body || {};
  if (typeof body.content !== 'string') throw new HttpError(400, 'content must be a string.');
  if (Buffer.byteLength(body.content, 'utf8') > MAX_EDIT_BYTES) throw new HttpError(413, 'Content exceeds the 2 MB limit.');

  const realTarget = resolveExisting(body.path);
  const stat = await fsp.stat(realTarget);
  if (stat.isDirectory()) throw new HttpError(400, 'Cannot write to a directory.');

  if (body.expectedModifiedAt !== undefined && body.expectedModifiedAt !== null) {
    if (Math.abs(stat.mtimeMs - Number(body.expectedModifiedAt)) > 1) {
      return res.status(409).json({
        error: 'This file was modified by someone else. Reload it before saving.',
        code: 'conflict',
      });
    }
  }

  await fsp.writeFile(realTarget, body.content, 'utf8');
  const after = await fsp.stat(realTarget);
  audit({ user: req.user.username, action: 'file-save', ok: true, detail: body.path, ip: req.ip });
  res.json({ ok: true, size: after.size, modifiedAt: after.mtimeMs });
}));

app.post('/api/files/create', requireAuth, requireAdmin, writeLimiter, asyncHandler(async (req, res) => {
  const body = req.body || {};
  const type = body.type === 'directory' ? 'directory' : 'file';
  const target = resolveInRoot(body.path);

  if (fs.existsSync(target)) throw new HttpError(409, 'That path already exists.');

  /* The parent must exist and stay inside the root. */
  const parent = path.dirname(target);
  resolveExisting(path.relative(serverRoot(), parent));

  if (type === 'directory') {
    await fsp.mkdir(target);
  } else {
    await fsp.writeFile(target, typeof body.content === 'string' ? body.content : '', 'utf8');
  }
  audit({ user: req.user.username, action: 'file-create', ok: true, detail: `${type} ${body.path}`, ip: req.ip });
  res.status(201).json({ ok: true });
}));

app.post('/api/files/rename', requireAuth, requireAdmin, writeLimiter, asyncHandler(async (req, res) => {
  const body = req.body || {};
  const from = resolveExisting(body.from);
  const to = resolveInRoot(body.to);
  if (fs.existsSync(to)) throw new HttpError(409, 'Destination already exists.');
  resolveExisting(path.relative(serverRoot(), path.dirname(to)));
  await fsp.rename(from, to);
  audit({ user: req.user.username, action: 'file-rename', ok: true, detail: `${body.from} -> ${body.to}`, ip: req.ip });
  res.json({ ok: true });
}));

app.delete('/api/files', requireAuth, requireAdmin, writeLimiter, asyncHandler(async (req, res) => {
  const relative = req.query.path;
  if (!relative || relative === '.' || relative === '/') {
    throw new HttpError(400, 'Refusing to delete the server root directory.');
  }
  const target = resolveExisting(relative);
  if (path.resolve(target) === path.resolve(serverRoot())) {
    throw new HttpError(400, 'Refusing to delete the server root directory.');
  }
  const stat = await fsp.stat(target);
  if (stat.isDirectory()) {
    await fsp.rm(target, { recursive: true, force: false });
  } else {
    await fsp.unlink(target);
  }
  audit({ user: req.user.username, action: 'file-delete', ok: true, detail: relative, ip: req.ip });
  res.json({ ok: true });
}));

app.get('/api/files/download', requireAuth, asyncHandler(async (req, res) => {
  const realTarget = resolveExisting(req.query.path);
  const stat = await fsp.stat(realTarget);
  if (stat.isDirectory()) throw new HttpError(400, 'Cannot download a directory.');
  const name = path.basename(realTarget);
  res.setHeader('Content-Type', 'application/octet-stream');
  res.setHeader('Content-Disposition', `attachment; filename="${name.replace(/"/g, '')}"`);
  res.setHeader('Content-Length', stat.size);
  fs.createReadStream(realTarget).pipe(res);
}));

/* ------------------------------- Logs ------------------------------- */
app.get('/api/logs', requireAuth, (req, res) => {
  const source = req.query.source === 'audit' ? 'audit' : 'console';
  const limit = clampInt(req.query.lines, 10, 50000, 500);
  const level = String(req.query.level || 'all').toLowerCase();
  const query = String(req.query.q || '').trim().toLowerCase();
  const since = Number(req.query.since);

  let entries;
  if (source === 'audit') {
    entries = auditLog.map((e) => ({
      seq: e.id,
      t: e.t,
      level: e.ok ? 'info' : 'error',
      stream: 'audit',
      line: `[${e.action}] ${e.user || 'anonymous'} ${e.detail || ''} ${e.ip ? `(${e.ip})` : ''}`.trim(),
    }));
  } else {
    entries = consoleBuffer;
  }

  let filtered = entries;
  if (level !== 'all') filtered = filtered.filter((e) => e.level === level);
  if (query) filtered = filtered.filter((e) => e.line.toLowerCase().includes(query));
  if (Number.isFinite(since) && since > 0) filtered = filtered.filter((e) => e.t >= since);

  res.json({
    source,
    total: entries.length,
    returned: filtered.length,
    entries: filtered.slice(-limit),
  });
});

app.delete('/api/logs', requireAuth, requireAdmin, writeLimiter, (req, res) => {
  const source = req.query.source === 'audit' ? 'audit' : 'console';
  if (source === 'audit') {
    auditLog = [];
    writeJsonAtomicSync(AUDIT_FILE, auditLog);
  } else {
    consoleBuffer = [];
    try {
      fs.truncateSync(CONSOLE_LOG, 0);
    } catch (_) {
      /* ignore */
    }
    pushSystemConsole('[panel] Console buffer cleared.');
  }
  audit({ user: req.user.username, action: 'logs-clear', ok: true, detail: source, ip: req.ip });
  res.json({ ok: true });
});

app.get('/api/logs/download', requireAuth, (req, res) => {
  const source = req.query.source === 'audit' ? 'audit' : 'console';
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');

  if (source === 'audit') {
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="audit-${stamp}.json"`);
    return res.send(JSON.stringify(auditLog, null, 2));
  }

  /* Prefer the complete on-disk log; fall back to the in-memory buffer. */
  const files = [CONSOLE_LOG, path.join(DATA_DIR, 'console.previous.jsonl')].filter((f) => fs.existsSync(f));
  if (files.length === 0) {
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="console-${stamp}.log"`);
    return res.send(consoleBuffer.map((e) => `[${new Date(e.t).toISOString()}] ${e.line}`).join('\n'));
  }

  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="console-${stamp}.log"`);

  const stream = fs.createReadStream(files[0]);
  stream.on('error', () => res.end());
  stream.pipe(res, { end: false });
  stream.on('end', () => {
    for (const entry of consoleBuffer) {
      res.write(`[${new Date(entry.t).toISOString()}] ${entry.line}\n`);
    }
    res.end();
  });
});

/* ------------------------------------------------------------------ *
 * Static frontend
 * ------------------------------------------------------------------ */
app.use(express.static(PUBLIC_DIR, { index: 'index.html', maxAge: 0, etag: true }));

app.use('/api', (req, res) => {
  res.status(404).json({ error: `Unknown API endpoint: ${req.method} ${req.originalUrl}` });
});

app.use((req, res, next) => {
  if (req.method !== 'GET') return next();
  res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});

/* Final error handler — must keep the 4-argument signature. */
app.use((err, req, res, _next) => {
  const status = err.status || err.statusCode || 500;
  if (status >= 500) console.error('[error]', err);
  res.status(status).json({
    error: status >= 500 ? 'Internal server error.' : err.message,
    code: err.code,
  });
});

/* ------------------------------------------------------------------ *
 * HTTP server + WebSocket console relay
 * ------------------------------------------------------------------ */
const server = http.createServer(app);

/* Fail with a clear, actionable message instead of an uncaught-exception stack
 * when the port is already taken (e.g. a previous panel instance still running). */
server.on('error', (err) => {
  if (err && err.code === 'EADDRINUSE') {
    console.error('');
    console.error(`[panel] Port ${PORT} is already in use on ${HOST}.`);
    console.error('        Another panel instance (or another app) is already listening there.');
    console.error('        Fix it by either:');
    console.error(`          - stopping the other process:`);
    console.error(`              Windows:  netstat -ano | findstr :${PORT}      then:  taskkill /PID <pid> /F`);
    console.error(`              macOS/Linux:  lsof -i :${PORT}              then:  kill <pid>`);
    console.error(`          - or starting this panel on a different port:  PORT=${PORT + 1} npm start`);
    console.error('');
    process.exit(1);
  }
  console.error('[panel] HTTP server error:', err && err.message ? err.message : err);
  process.exit(1);
});

const wss = new WebSocketServer({ noServer: true, maxPayload: 256 * 1024 });

server.on('upgrade', (req, socket, head) => {
  let pathname;
  try {
    pathname = new URL(req.url, `http://${req.headers.host || 'localhost'}`).pathname;
  } catch (_) {
    socket.destroy();
    return;
  }

  /* The browser always sends Origin on WebSocket handshakes; enforce the same
     policy as the REST API so an exposed port cannot be hijacked by a page. */
  const origin = req.headers.origin;
  if (origin && !originAllowed(origin)) {
    socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
    socket.destroy();
    return;
  }

  if (pathname !== '/ws/console') {
    socket.write('HTTP/1.1 404 Not Found\r\n\r\n');
    socket.destroy();
    return;
  }

  wss.handleUpgrade(req, socket, head, (ws) => wss.emit('connection', ws, req));
});

wss.on('connection', (ws, req) => {
  ws.isAlive = true;

  /* A token supplied via the `bearer,<jwt>` subprotocol counts as an
     immediate authentication so the client can skip the first message. */
  const headerToken = extractToken(req);
  const headerUser = headerToken ? verifyToken(headerToken) : null;

  const authTimer = setTimeout(() => {
    if (!ws.user) {
      try {
        ws.close(4001, 'Authentication timeout');
      } catch (_) {
        /* ignore */
      }
    }
  }, 10000);

  ws.on('pong', () => {
    ws.isAlive = true;
  });

  function acceptAuth(user) {
    ws.user = user;
    clearTimeout(authTimer);
    clients.add(ws);
    ws.send(
      JSON.stringify({
        type: 'init',
        user: publicUser(user),
        settings: {
          panelName: settings.panel.name,
          maxLines: settings.console.maxLines,
          idleTimeoutMinutes: settings.panel.idleTimeoutMinutes,
        },
        status: processStatus(),
        players: playerList(),
        buffer: consoleBuffer.slice(-clampInt(settings.console.maxLines, 200, 50000, 5000)),
      })
    );
  }

  if (headerUser) {
    acceptAuth(headerUser);
  } else {
    ws.send(JSON.stringify({ type: 'auth:required' }));
  }

  ws.on('message', (data) => {
    let msg;
    try {
      msg = JSON.parse(data.toString('utf8'));
    } catch (_) {
      return;
    }
    if (!msg || typeof msg !== 'object') return;

    if (!ws.user) {
      if (msg.type === 'auth' && typeof msg.token === 'string') {
        const user = verifyToken(msg.token);
        if (!user) {
          ws.send(JSON.stringify({ type: 'auth:failed', error: 'Invalid or expired session.' }));
          ws.close(4003, 'Unauthorized');
          return;
        }
        acceptAuth(user);
      }
      return;
    }

    if (msg.type === 'command') {
      try {
        const command = sendCommand(msg.command);
        audit({ user: ws.user.username, action: 'command', ok: true, detail: command, ip: req.socket.remoteAddress });
        ws.send(JSON.stringify({ type: 'command:sent', command }));
      } catch (err) {
        ws.send(JSON.stringify({ type: 'error', error: err.message }));
      }
      return;
    }

    if (msg.type === 'ping') {
      ws.send(JSON.stringify({ type: 'pong', t: Date.now() }));
    }
  });

  ws.on('close', () => {
    clearTimeout(authTimer);
    clients.delete(ws);
  });

  ws.on('error', () => {
    clearTimeout(authTimer);
    clients.delete(ws);
  });
});

/* Keepalive: also keeps the socket warm through NAT routers and tunnels. */
const heartbeat = setInterval(() => {
  for (const ws of clients) {
    if (ws.isAlive === false) {
      ws.terminate();
      clients.delete(ws);
      continue;
    }
    ws.isAlive = false;
    try {
      ws.ping();
    } catch (_) {
      /* ignore */
    }
  }
}, 30000);

/* Background sampling. Probes are slow on some hosts, so they run on their own
 * cadence and in-flight guards stop a slow probe from stacking up. */
const statsTimer = setInterval(async () => {
  try {
    await refreshStats();
    if (clients.size > 0 && metrics.stats) broadcast({ type: 'stats', stats: metrics.stats });
  } catch (_) {
    /* never let a measurement error kill the timer */
  }
}, 5000);

const infoTimer = setInterval(() => {
  if (!metrics.info) refreshSystemInfo().catch(() => {});
}, 15000);

const diskTimer = setInterval(() => {
  refreshDisk().catch(() => {});
}, 60000);

/* Warm the cache immediately so the first dashboard load has data. */
ensureMetrics();

/* ------------------------------------------------------------------ *
 * Boot
 * ------------------------------------------------------------------ */
(async function startPanel() {
await hydrateFromStore().catch((err) => {
  console.error(`[db] Persistence bootstrap failed (${err.message}) — continuing on JSON files.`);
});

server.listen(PORT, HOST, () => {
  /* 0.0.0.0 / :: are bind addresses, not something a browser can open — show a
   * usable URL (localhost) plus the LAN address when bound to all interfaces. */
  const boundAll = HOST === '0.0.0.0' || HOST === '::' || HOST === '' || HOST === '*';
  const viewHost = boundAll ? 'localhost' : HOST;

  console.log('');
  console.log(`  ${settings.panel.name}`);
  console.log(`  Panel:          http://${viewHost}:${PORT}`);
  if (boundAll) {
    const lan = Object.values(os.networkInterfaces())
      .flat()
      .find((nic) => nic && nic.family === 'IPv4' && !nic.internal);
    if (lan) console.log(`  On your LAN:    http://${lan.address}:${PORT}`);
  }
  console.log(`  Server root:    ${serverRoot()}`);
  console.log(`  Managed cmd:    ${settings.server.command} ${settings.server.args.join(' ')}`);
  console.log(`  Data directory: ${DATA_DIR}`);
  console.log(`  Storage:        ${store.describe()}`);
  console.log(`  bcrypt backend: ${bcrypt === require('bcryptjs') ? 'bcryptjs (pure JS fallback)' : 'bcrypt (native)'}`);
  console.log('');
  console.log('  Expose it with router port forwarding (TCP ' + PORT + ') or a tunnel.');
  console.log('  Set JWT_SECRET in .env before exposing this to the internet.');
  console.log('');

  if (settings.server.autoStart) {
    pushSystemConsole('[panel] autoStart is enabled — starting the server process.');
    try {
      startProcess();
    } catch (err) {
      pushSystemConsole(`[panel] autoStart failed: ${err.message}`);
    }
  }
});
})();

function shutdown(signal) {
  console.log(`\n[panel] ${signal} received — shutting down.`);
  clearInterval(heartbeat);
  clearInterval(statsTimer);
  clearInterval(infoTimer);
  clearInterval(diskTimer);
  clearTimeout(proc.restartTimer);

  if (proc.child) {
    proc.intentionalStop = true;
    const stopCommand = String(settings.server.stopCommand || '').trim();
    try {
      if (stopCommand && proc.child.stdin && proc.child.stdin.writable) proc.child.stdin.write(`${stopCommand}\n`);
    } catch (_) {
      /* ignore */
    }
    killTree(proc.child.pid, 'SIGTERM');
  }

  if (logStream) logStream.end();
  writeJsonAtomicSync(SETTINGS_FILE, settings);
  writeJsonAtomicSync(USERS_FILE, users);
  writeJsonAtomicSync(AUDIT_FILE, auditLog);
  store.close().catch(() => {}); // best-effort flush of queued DB writes

  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 3000).unref();
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('unhandledRejection', (reason) => console.error('[panel] Unhandled rejection:', reason));
process.on('uncaughtException', (err) => console.error('[panel] Uncaught exception:', err));

module.exports = { app, server };
