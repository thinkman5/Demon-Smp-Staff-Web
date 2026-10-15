# DEMON SMP — Server Control Panel

A self-hosted web control panel for a game server process running on your own PC.
It gives remote administrators a live console, process control, player administration,
a file manager, user management and log tooling — all over a normal HTTP port that you
expose with **router port forwarding**.

```
┌───────────────┐   internet    ┌──────────────────┐   localhost   ┌─────────────────┐
│  Admin browser│ ───────────▶  │ Router port fwd  │ ───────────▶  │ Panel (Node.js) │
│  (HTTPS/HTTP) │               │ TCP 8080         │               │  spawns ────────┼──▶ server.jar
└───────────────┘               └──────────────────┘               │  WebSocket /ws  │
                                                                   └─────────────────┘
```

---

## 1. Directory structure

```
DEMON SMP/
├── server.js              # Express API + WebSocket relay + child_process manager
├── db.js                  # Persistence: JSON files (default) or Postgres (optional)
├── package.json           # Dependencies and start scripts
├── .env.example           # Copy to .env and adjust
├── .gitignore
├── README.md              # Security, hardening and deployment guide
├── TUTORIAL.md            # Step-by-step run & test guide
├── Dockerfile             # Production image (docker build -t demon-smp-panel .)
├── docker-compose.yml     # Panel + optional Postgres stack
├── render.yaml / Procfile # One-click deploy to Render / Railway / Heroku-style
├── netlify.toml           # Static-frontend-only config (see the note inside)
├── scripts/smoke-test.js  # Dependency-free end-to-end HTTP smoke test
├── public/
│   ├── index.html         # SPA shell: sidebar, all 9 views, editor modal
│   ├── app.js             # Auth, routing, WebSocket reconnect, every API call
│   ├── styles.css         # Light/dark theme variables + animations/design system
│   ├── theme.js           # Light/dark theme controller (persisted, no flash)
│   ├── background.js      # Canvas particle + aurora animated background
│   └── config.js          # Optional apiBase for split (static-frontend) deploys
└── data/                  # Created automatically on first run (git-ignored)
    ├── users.json         # Local JSON user database (bcrypt password hashes)
    ├── settings.json      # Panel + server + gameplay settings
    ├── audit.json         # Authentication and action audit trail
    ├── console.jsonl      # Persistent console log (rotates at 5 MB)
    └── .jwt-secret        # Generated signing secret when JWT_SECRET is unset
```

> **New here?** `TUTORIAL.md` walks through running the panel, testing the
> themes/animations, the full smoke test, and the optional database.

### Themes & interface

The frontend ships **two themes — dark (default) and light — selectable by the
user** with the ☀/🌙 button (header, and top-right of the login page). The choice
is persisted in `localStorage` and applied before first paint, so there is no
flash; on a first visit it follows the OS `prefers-color-scheme`. An animated
background (canvas particle field + drifting aurora + grid), staggered view
transitions and card/toast micro-interactions run throughout, and everything is
disabled automatically when the OS asks for reduced motion.

### Database

State is stored in the `data/` JSON files by default — **no database required**.
Set `DATABASE_URL` (Netlify DB / Neon / Supabase / any Postgres) and the panel
stores users, settings and the audit trail in Postgres instead, keeping the JSON
files as a local cache. See `TUTORIAL.md` §5. Note that *Netlify cannot host the
panel backend* — it is a stateful process supervisor; see `netlify.toml`.

The panel manages the server process from a **working directory** you configure
(`Server Options → Working directory`). That directory — e.g. `./server` — holds
`server.jar`, `server.properties`, `world/`, `plugins/`, and is the root that the
Files Access browser is confined to.

---

## 2. Install & run locally

Requires **Node.js 18 or newer** (tested on Node 24).

```bash
cd "DEMON SMP"
npm install
cp .env.example .env      # optional but recommended
npm start                 # or: npm run dev  (auto-restart on file changes)
```

Open <http://localhost:8080>. On the very first run the panel creates a bootstrap
administrator and prints the credentials to the console once:

```
================================================================
  First run — bootstrap administrator created.
  Username: admin
  Password: <random>
  Change this password on the "Login System" page immediately.
================================================================
```

Sign in, then go straight to **Login System → Change password**. To choose the
bootstrap credentials yourself, set `ADMIN_USERNAME` / `ADMIN_PASSWORD` in `.env`
before the first start.

### Point the panel at your server

**Server Options** controls everything about the managed process:

| Field | Example | Notes |
|---|---|---|
| Executable / command | `java` | Must be on `PATH`, or an absolute path |
| Startup arguments | `-Xmx4G -Xms2G -jar server.jar nogui` | Click **Apply Aikar's JVM flags** for a tuned preset |
| Working directory | `server` | Relative to the panel folder, or absolute |
| Graceful stop command | `stop` | Written to the process stdin on Stop |
| Kill timeout | `20000` | Force-kills the process tree after this long |

Then use **Save options**, and **Write to server.properties** to push the gameplay
properties (port, max players, difficulty, MOTD, view distance, whitelist…) into
`server.properties`. Port and gameplay changes apply after a restart.

### Notes on dependencies

* **bcrypt** — the panel loads the native `bcrypt` addon when it is available and
  transparently falls back to the pure-JS `bcryptjs` (identical algorithm and API).
  Native `bcrypt` requires a compiled addon that is frequently unavailable on
  Windows or blocked by npm install-script policies; the panel prints which backend
  it is using at startup. No action is needed either way.
* **Tailwind CSS** ships from the CDN and is themed via CSS variables
  (`public/styles.css`), so both light and dark themes use the same utility
  classes. To run fully offline, replace the
  `<script src="https://cdn.tailwindcss.com">` tag with a local build and add it
  to the CSP `script-src` list in `server.js`.
* **pg** — the optional PostgreSQL driver used only when `DATABASE_URL` is set.
  If it is missing or the database is unreachable, the panel logs a warning and
  keeps running on the JSON files.

---

## 3. Deployment guide — exposing the panel to the internet

> Do this only if you need remote access. While the panel is reachable from the
> internet, anyone who finds it sees a login page — the mitigations in section 4
> are not optional.

### Step 1 — Give this PC a static local IP

A port-forward rule targets an IP address, so the address must not change when
the machine reboots.

**Option A — Router reservation (recommended).** In your router admin page, find
*DHCP Reservation* / *Static Leases*, pick this PC's MAC address and assign a fixed
address (e.g. `192.168.1.50`). This survives reinstalls and needs nothing on the PC.

**Option B — Static IP on Windows.**

GUI: `Settings → Network & Internet → Ethernet (or Wi-Fi) → Edit (IP assignment) →
Manual → IPv4 on`, then enter:

```
IP address:      192.168.1.50
Subnet mask:     255.255.255.0
Gateway:         192.168.1.1      (your router's address)
Preferred DNS:   1.1.1.1
Alternate DNS:   8.8.8.8
```

Command line (run **as Administrator**, replace the adapter name and addresses):

```powershell
netsh interface ip set address name="Ethernet" static 192.168.1.50 255.255.255.0 192.168.1.1
netsh interface ip set dns name="Ethernet" static 1.1.1.1
netsh interface ip add dns name="Ethernet" 8.8.8.8 index=2
```

Check it with `ipconfig` and confirm the default gateway. To undo:

```powershell
netsh interface ip set address name="Ethernet" source=dhcp
netsh interface ip set dns name="Ethernet" source=dhcp
```

### Step 2 — Create the Windows Firewall inbound rules

The panel binds to `0.0.0.0:8080`; Windows will prompt for network access the first
time you start it. Allow it **on private networks**. To add the rules explicitly
(Administrator PowerShell or Command Prompt):

```powershell
:: Panel (HTTP/WebSocket)
netsh advfirewall firewall add rule name="DEMON SMP Panel" dir=in action=allow protocol=TCP localport=8080 profile=private

:: Game server port (only if players connect directly, not through a tunnel)
netsh advfirewall firewall add rule name="DEMON SMP Game" dir=in action=allow protocol=TCP localport=25565 profile=private
```

`profile=private` (not `any`) keeps the rules off on untrusted public networks.
Verify and manage them in `Windows Security → Firewall & network protection →
Advanced settings → Inbound Rules`. Remove a rule with:

```powershell
netsh advfirewall firewall delete rule name="DEMON SMP Panel"
```

### Step 3 — Forward the port on your router

1. Note this PC's local IP (`ipconfig` → IPv4 Address), e.g. `192.168.1.50`.
2. Find the router admin page — usually `http://192.168.1.1` or `http://192.168.0.1`.
3. Locate **Port Forwarding** / *Virtual Server* / *NAT* / *Applications*.
4. Add a rule:

   | Setting | Value |
   |---|---|
   | Name | DEMON SMP Panel |
   | Protocol | TCP |
   | External / WAN port | `8080` |
   | Internal / LAN port | `8080` |
   | Internal IP | `192.168.1.50` |
   | Enable | ✔ |

5. Add a second rule for the game port (`25565` → `192.168.1.50:25565`) if players
   connect to your server directly.
6. Save. Some routers need a reboot.

**Avoid port conflicts.** Web panels are often blocked on port 80/443 by the ISP or
already used by the router. `8080` is a safe choice — and if your ISP blocks inbound
80, forward the external port to whatever you like, e.g. WAN `9000` → LAN `8080`.
Note the panel port is TCP/HTTP, so it also covers the WebSocket upgrade on
`/ws/console`, which uses the same port and needs no extra rule.

### Step 4 — Find your public IP and connect

```bash
curl https://api.ipify.org
```

Then browse to `http://<public-ip>:8080` from any device not on your LAN (test from
mobile data — from inside your own network you may hit router NAT loopback instead).
Share `http://<public-ip>:8080` with your other admins and create separate logins
for them on the **User Management** page.

If your ISP uses **CGNAT** (a public IP that is not yours, or the router's WAN
address differs from `ipify`), inbound forwarding will not work. Options: ask the ISP
for a public IP, or put the PC behind a tunnel such as Playit.gg / Cloudflare Tunnel
and point the panel at that instead. Set `TRUST_PROXY=true` in `.env` when a proxy or
tunnel sits in front of the panel, so rate limiting sees real client IPs.

---

## 4. Security checklist (do these before exposing the port)

- [ ] Set a long random `JWT_SECRET` in `.env`. Without it, a generated secret is
      stored in `data/.jwt-secret`; deleting that file signs everyone out.
- [ ] Change the bootstrap admin password on the **Login System** page.
- [ ] Give every teammate their own account on **User Management** — no shared logins.
      The audit trail records who did what.
- [ ] Keep `TRUST_PROXY` unset (`false`) for direct port forwarding. Set it to `true`
      only behind a tunnel/reverse proxy.
- [ ] Never point the port-forward at port 22/3389 or any other service.
- [ ] Back up `data/` (users, settings, audit) and your `server/` directory.

Built-in protections: helmet security headers and a strict CSP, CORS origin policy
(configure `ALLOWED_ORIGINS` to lock it down), `express-rate-limit` on the API
(300/min), on logins (10 failures / 15 min), on commands (120/min) and on writes
(90/min), bcrypt password hashing at cost 12, JWT verification on every REST route
and every WebSocket handshake, per-user token revocation (changing a password or
role immediately invalidates that user's other sessions), timing-safe login that does
not reveal whether a username exists, path-traversal protection on the file manager,
and a persistent audit log.

> **No TLS by default.** The panel speaks plain HTTP. On an untrusted network, put it
> behind a reverse proxy with a certificate (Caddy/Nginx) or a Cloudflare Tunnel so
> credentials are not sent in clear text. `helmet`'s HSTS is intentionally disabled
> because TLS is expected to terminate upstream.

---

## 5. Using the panel

| View | What it does |
|---|---|
| **Dashboard** | Live CPU, memory and disk (via `systeminformation`), host information, process state, PID, uptime, last exit code, player count, and recent console output. |
| **Console** | WebSocket-streamed terminal with a stdin command box, autoscroll toggle and reconnect handling. History survives page reloads from the server's ring buffer. |
| **Player Control** | Tracked player list (from join/leave events and the `list` command) with Kick, Ban, Mute/Unmute and Teleport. |
| **Files Access** | Browse the server directory; open and save text files (2 MB limit) with conflict detection; create, rename, delete and download. |
| **Login System** | Your session details, password change (signs out other sessions), and recent authentication activity. |
| **User Management** | Create admins or read-only viewers, reset passwords, change roles, delete accounts. |
| **Server Options** | Process command, working directory, startup flags (incl. Aikar's flags preset), stop command, auto-start/auto-restart, whole `server.properties` editor, session/console settings. |
| **Players Settings** | Whitelist, operator list, muted list, default gamemode, spawn coordinates, mute strike limit, and the command templates used by Player Control. |
| **Log** | Filterable console or audit log with level/search filtering, line count, download and buffer clearing. |

### Player tracking and mute, explained

Player names are derived from console events (`X joined the game`, `X left the game`)
and from the `list` command, so **Query server (list)** gives an authoritative
snapshot. Kick, Ban, Teleport and the whitelist/op apply dispatch real server
commands using the templates on the Players Settings page — edit them if your
server is not Minecraft.

Vanilla Minecraft has no mute command, so Mute is enforced by the panel: muted
players' chat lines are detected in the console, they get a warning tell, and after
`muteStrikes` warnings they are kicked automatically. If your setup has a real mute
plugin, put its command in the **Mute** template and the panel will dispatch it too.

---

## 6. API reference

All routes except `/api/health` and `/api/auth/login` require
`Authorization: Bearer <jwt>`. Admin-only routes are marked **(A)**.

```
POST   /api/auth/login                            {username, password} -> {token, expiresAt, user}
POST   /api/auth/logout
GET    /api/auth/me
POST   /api/auth/password                         {currentPassword, newPassword}
GET    /api/auth/activity

GET    /api/users                                        (A)
POST   /api/users                                 {username, password, role}   (A)
PATCH  /api/users/:id                             {username?, password?, role?} (A)
DELETE /api/users/:id                                                    (A)

GET    /api/system/stats | /api/system/info
GET    /api/process/status
POST   /api/process/start | /api/process/stop | /api/process/restart     (A)
POST   /api/process/command                       {command}              (A)

GET    /api/players
POST   /api/players/refresh
POST   /api/players/:name/kick|ban|unban          {reason?}              (A)
POST   /api/players/:name/mute                    {mute}                 (A)
POST   /api/players/:name/teleport                {target} | {x,y,z}     (A)

GET    /api/player-settings
PUT    /api/player-settings                                              (A)
POST   /api/player-settings/apply                                        (A)

GET    /api/options | /api/options/properties
PUT    /api/options                                                      (A)
POST   /api/options/apply                         {properties?}          (A)

GET    /api/files?path=DIR
GET    /api/files/content?path=FILE
PUT    /api/files/content                         {path, content, expectedModifiedAt?} (A)
POST   /api/files/create                          {path, type}           (A)
POST   /api/files/rename                          {from, to}             (A)
DELETE /api/files?path=FILE                                              (A)
GET    /api/files/download?path=FILE

GET    /api/logs?source=console|audit&level=&q=&lines=&since=
DELETE /api/logs?source=console|audit                                    (A)
GET    /api/logs/download?source=console|audit
```

WebSocket: connect to `/ws/console` and send `{"type":"auth","token":"<jwt>"}` as the
first frame (a `bearer,<jwt>` subprotocol also works). The server replies with an
`init` frame (`status`, `players`, console `buffer`), then streams `console`,
`status`, `players` and `stats` events. Send `{"type":"command","command":"list"}`
to run a command.

---

## 7. Troubleshooting

| Symptom | Fix |
|---|---|
| `Port 8080 is already in use` | Change `PORT` in `.env`, or forward a different external port. |
| Panel loads but the console says *Disconnected* | Something is stripping WebSocket upgrades — a proxy needs `Upgrade`/`Connection` headers passed through. Direct port forwarding works as-is. |
| Server will not start | Check the console output: a wrong `cwd`, missing `server.jar`, or `eula=false` in `eula.txt`. The panel warns about the last two. |
| Everyone is rate limited | You are behind a proxy without `TRUST_PROXY=true`, so all clients share one IP bucket. |
| Forgot the admin password | Stop the panel, delete `data/users.json`, restart — a new bootstrap admin is printed. Other accounts are removed too. |
| Files missing from the browser | The file root is the *Working directory* set in Server Options. |
