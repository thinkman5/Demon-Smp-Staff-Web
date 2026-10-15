# DEMON SMP — Run & Test Tutorial

A hands-on guide to **running** the panel and **testing** everything that was
changed: the light/dark themes, the animated background, the redesigned UI, and
the optional database.

> This document is the practical companion to `README.md` (which covers the
> security hardening, router/port-forward setup and deployment in depth).

---

## 0. Read this first — what can run where

The panel is a **stateful Node service**. It spawns and supervises your game
server process, reads/writes files on the host, and keeps a persistent
WebSocket console. That means:

| Host | Can run the panel? | Notes |
|---|---|---|
| Your PC (`npm start`) | ✅ Yes | Normal self-hosted use |
| Docker / docker-compose | ✅ Yes | Recommended for servers |
| Render / Railway / Fly / VPS | ✅ Yes | Long-lived process + disk |
| **Netlify** | ❌ **No (backend)** | Netlify is static + serverless: no long-lived process, no process spawning, no durable WebSocket, no persistent filesystem |

**Netlify can host the *frontend* only**, pointing at a Node backend
(`public/config.js` → `apiBase`). The bundled `netlify.toml` documents this.
"Netlify DB" (Neon Postgres) *is* supported — you set its connection string on
the **backend** host; see §5.

---

## 1. Prerequisites

- **Node.js 18 or newer** (verified here on Node 24). Check: `node -v`
- npm (ships with Node). Check: `npm -v`
- Optional, for the database section: a Postgres connection string
  (Netlify DB / Neon / Supabase / local) **or** Docker.

---

## 2. Quick start (local)

```bash
# 1. From the project folder ("DEMON SMP")
npm install

# 2. Optional but recommended: copy the env template
cp .env.example .env        # Windows Git Bash / macOS / Linux
#   (PowerShell users: copy .env.example .env)

# 3. Start the panel
npm start                   # production-style
# or, with auto-restart on file changes:
npm run dev
```

Open <http://localhost:8080>.

### First run — get your login

On the very first start (empty store) the panel prints a bootstrap admin **once**
to the terminal:

```
================================================================
  First run — bootstrap administrator created.
  Username: admin
  Password: <random>
  Change this password on the "Login System" page immediately.
================================================================
```

To choose the credentials yourself, set them in `.env` **before** the first start:

```ini
ADMIN_USERNAME=admin
ADMIN_PASSWORD=MyStrongPassw0rd
```

Sign in, then immediately go to **Login System → Change password**.

### Point it at your game server

**Server Options** controls the managed process:

| Field | Example |
|---|---|
| Executable / command | `java` |
| Startup arguments | `-Xmx4G -Xms2G -jar server.jar nogui` |
| Working directory | `server` (created by you, holds `server.jar`) |
| Graceful stop command | `stop` |

The working directory is the root the **Files Access** page is confined to.

---

## 3. What changed in this redesign (what to look at)

Open the panel and try these:

1. **Theme toggle** — the ☀/🌙 button in the header (and top-right of the login
   page). Click it to switch **dark ⇄ light**. Your choice is saved in
   `localStorage` under `demon-smp.theme` and restored on reload with **no
   flash**. On first visit it follows your OS `prefers-color-scheme`.
2. **Animated background** — a canvas particle field with proximity links, plus
   drifting aurora blobs and a slow-panning grid. It **re-tints live** when you
   toggle the theme and gently reacts to the cursor.
3. **Motion & polish** — views fade/slide in with a stagger, cards lift with a
   glow on hover, progress bars have a moving sheen, the logo badge bobs with a
   light sweep, the login card has an animated conic border, toasts slide in.
4. **Respects accessibility** — with the OS setting "reduce motion" enabled, all
   animations and the canvas are disabled automatically.

New frontend files:

```
public/styles.css      # theme variables + all animation/animation CSS
public/theme.js        # light/dark controller (persists + binds toggles)
public/background.js   # canvas particle background (theme-reactive)
public/config.js       # optional apiBase for split deployments
public/index.html      # redesigned shell (same IDs as before)
public/app.js          # unchanged behaviour + optional API base
```

---

## 4. Automated smoke test

With the panel running, open a **second terminal** and run:

```bash
npm run smoke
```

It checks (no dependencies, uses built-in `fetch`):

- `/api/health` returns `ok: true`
- static assets `/`, `/styles.css`, `/theme.js`, `/background.js`, `/config.js`,
  `/app.js` are served with the right content types
- `index.html` actually references the redesign assets
- unknown `/api/*` routes return 404 and protected routes reject anonymous
  access with 401
- **with credentials**: login, then `/api/auth/me`, `/api/process/status`,
  `/api/players`, `/api/system/stats`, `/api/options`, `/api/player-settings`,
  `/api/logs`

### Run the full version (including login)

```bash
# default target is http://127.0.0.1:8080
PANEL_URL=http://127.0.0.1:8080 \
SMOKE_USER=admin \
SMOKE_PASS='your-admin-password' \
npm run smoke
```

Expected tail:

```
18 passed, 0 failed, 0 skipped
```

Exit code is `0` on success and `1` if any check failed (usable in CI). Without
`SMOKE_PASS` the login section is **skipped** and reported as such.

---

## 5. Database (optional Postgres — Netlify DB / Neon / Supabase)

By default the panel stores state in JSON files under `data/`. Set a
`DATABASE_URL` and it stores **users, settings and the audit trail** in Postgres
instead — while still keeping the JSON files as a local cache/fallback.

### a) With Docker Compose (easiest local Postgres)

1. Uncomment the two lines in `docker-compose.yml`:
   ```yaml
   environment:
     DATABASE_URL: postgres://panel:panel@db:5432/panel
   ```
2. Run:
   ```bash
   docker compose up --build
   docker compose logs -f panel      # storage line + bootstrap credentials
   ```

### b) With a hosted provider

Copy the connection string (examples):

| Provider | `DATABASE_URL` shape |
|---|---|
| **Netlify DB** (Neon) | `postgresql://user:pass@ep-xxx.neon.tech/neondb?sslmode=require` |
| Neon | `postgresql://user:pass@ep-xxx.neon.tech/db?sslmode=require` |
| Supabase | `postgresql://postgres:pass@db.xxx.supabase.co:5432/postgres` |

Put it in `.env` (aliases `NETLIFY_DATABASE_URL`, `POSTGRES_URL`,
`NEON_DATABASE_URL` also work) and restart:

```bash
DATABASE_URL='postgresql://...' npm start
```

**Recognised aliases:** `DATABASE_URL`, `NETLIFY_DATABASE_URL`,
`NETLIFY_DB_URL`, `POSTGRES_URL`, `POSTGRES_PRISMA_URL`, `NEON_DATABASE_URL`.
TLS is enabled automatically for non-local hosts (override with `PGSSLMODE`).

### How to tell it worked

Startup banner shows the storage backend:

```
  Storage:        postgres (DATABASE_URL)
```

`GET /api/health` also reports it:

```bash
curl -s http://127.0.0.1:8080/api/health
# {"ok":true,...,"storage":"postgres (DATABASE_URL)","storageReady":true,"storageError":null}
```

Verify the data physically landed in Postgres:

```sql
-- psql "$DATABASE_URL"
SELECT key, jsonb_array_length(value) AS n, updated_at FROM panel_kv WHERE key = 'users';
SELECT key, updated_at FROM panel_kv;   -- expect keys: users, settings, audit
```

### Safety guarantee

If `DATABASE_URL` is wrong or the database is down, the panel **still starts**
and keeps working on JSON files. You'll see:

```
[db] Could not use Postgres (connect ECONNREFUSED ...) — falling back to JSON files.
```

…and `/api/health` returns `"storageReady": false` with the error. This was
verified end-to-end (see §7).

---

## 6. Manual browser checklist

Run `npm start`, open <http://localhost:8080>, then walk through:

**Login**
- [ ] The page renders with the animated aurora/grid/particles (no blank screen).
- [ ] Click the ☀/🌙 button top-right → the whole page switches theme instantly.
- [ ] Reload → the theme persists with no flash.
- [ ] Sign in with the bootstrap credentials → app shell appears.

**Shell**
- [ ] Sidebar items highlight with an animated indicator on hover/active.
- [ ] Header shows status pill and Start / Restart / Stop.
- [ ] Toggle the theme again → cards, tables, inputs and the console all re-theme
      (no unreadable text on either theme).

**Views** (click each in the sidebar)
- [ ] Dashboard — stat cards animate in; CPU/Memory/Disk bars fill with sheen.
- [ ] Console — type `list` (needs a running server) and see live output.
- [ ] Player Control — table renders; actions open the modal.
- [ ] Files Access — navigate folders; open a text file in the editor.
- [ ] Login System — session info + change-password form.
- [ ] User Management — create a login (admin only).
- [ ] Server Options / Players Settings / Log — forms load from the API.

**Connectivity**
- [ ] The sidebar WebSocket dot turns green ("Live"). Stop the panel → it shows
      "Disconnected" and auto-reconnects.

**Accessibility**
- [ ] Enable "reduce motion" in your OS and reload → animations stop.

---

## 7. Verification performed (what was actually tested)

| Check | Result |
|---|---|
| `node -c` syntax on `server.js`, `db.js`, `app.js`, `theme.js`, `background.js` | ✅ pass |
| Cold boot with a clean `DATA_DIR` (JSON backend) | ✅ serves, bootstrap admin created |
| `npm run smoke` (full, with login) on JSON backend | ✅ **18 passed, 0 failed, 0 skipped** |
| Boot with an unreachable `DATABASE_URL` | ✅ logs fallback, still serves |
| `npm run smoke` (full) on the DB-fallback instance | ✅ **18 passed, 0 failed, 0 skipped** |
| Headless Chrome load of `/` | ✅ `data-theme` applied, `#login-view` un-hidden (JS ran), no CSP/JS errors |
| **Postgres success path (insert/read `panel_kv`)** | ⚠️ **Not run here** — no Postgres/Docker available in this environment. Code path is `db.js` `init()/load()/queueSave()`; verify with the SQL in §5 after connecting a real database. |

---

## 8. Troubleshooting

| Symptom | Fix |
|---|---|
| `Error: listen EADDRINUSE :::8080` | Port busy. `PORT=8090 npm start` or stop the other process. The panel now prints the exact `netstat`/`taskkill` commands. |
| Browser: `ERR_ADDRESS_INVALID` for `http://0.0.0.0:8080/` | `0.0.0.0` is a **bind** address (listen on all interfaces), not a browsable one. Open **http://localhost:8080/** or the `On your LAN` address printed at startup. |
| Forgot the bootstrap password | Delete `data/users.json` (JSON mode) and restart — a new admin is generated. **With Postgres**, delete the `users` row in `panel_kv`. |
| `[db] pg module is not installed` | `npm install pg`, or unset `DATABASE_URL`. |
| `[db] Could not use Postgres ...` | Wrong/unreachable `DATABASE_URL`, or TLS. Managed hosts need `?sslmode=require`; for local Postgres set `PGSSLMODE=disable`. |
| Theme doesn't persist | Browser storage blocked (private mode); the toggle still works per-session. |
| No animations | OS "reduce motion" is enabled — this is intentional. |
| Login page is blank | Hard-refresh (Ctrl+F5). Confirm `/styles.css` and `/theme.js` return 200. |
| Console never says "Live" | The WebSocket was blocked — behind a reverse proxy set `TRUST_PROXY=true`, and ensure `ALLOWED_ORIGINS` includes your site. |

---

## 9. Deploying

- **Docker / VPS:** `docker build -t demon-smp-panel . && docker run -p 8080:8080 -v panel-data:/data --env-file .env demon-smp-panel`
- **Render:** push to GitHub → New → Blueprint (uses `render.yaml`).
- **Railway / Heroku-style:** `Procfile` is included (`web: node server.js`).
- **Netlify (frontend only):** publish `public/`, set
  `window.DEMON_PANEL = { apiBase: 'https://your-backend' }` in
  `public/config.js`, and add the Netlify origin to `ALLOWED_ORIGINS` on the
  backend. See `netlify.toml` for details and the WebSocket caveat.

Always set a strong `JWT_SECRET` in production.

---

## 10. Configuration reference (`.env`)

See `.env.example` for the annotated list. The essentials:

| Variable | Default | Purpose |
|---|---|---|
| `PORT` / `HOST` | `8080` / `0.0.0.0` | Listen address |
| `JWT_SECRET` | auto-generated | **Set in production** |
| `ADMIN_USERNAME` / `ADMIN_PASSWORD` | `admin` / random | First-run admin |
| `SESSION_HOURS` | `12` | Session lifetime |
| `ALLOWED_ORIGINS` | any | CORS/WebSocket allow-list (comma separated) |
| `TRUST_PROXY` | `false` | `true` behind a proxy/tunnel |
| `DATA_DIR` | `./data` | JSON store location |
| `DATABASE_URL` | *unset* | Enables the Postgres backend |
| `PGSSLMODE` | auto | `disable` for local Postgres |
