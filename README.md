# VaultDrop

A private, encrypted file vault you host yourself. Upload and download any file from any device, protected by a vault key (and optionally a second factor).

**Code layout (deliberately tiny):** `server.js` is the whole backend, `public/index.html` is the whole interface. There are no npm dependencies. Everything else is deployment or tests.

## One vault, every device

There is exactly **one vault: the server**. Phone, laptop and tablet all just open the **same web address** and enter the same vault key; they never need their own setup. If a second device shows the **"First run / Create vault"** screen, it is looking at a *different* or *empty* server. The usual causes:

1. It opened a different address (for example `localhost`, which only exists on the PC running it). Always use the one public `https://...` address.
2. The host's disk is not persistent, so the server restarted and forgot everything. On Render/Railway the **disk must be attached and `DATA_DIR` must equal its mount path** (for example disk at `/var/data` and `DATA_DIR=/var/data`). If this is wrong, VaultDrop now shows a **red warning banner** in the app and prints a warning in the logs. Treat that banner as "do not upload yet".

## 1. Try it on your own computer (2 minutes)

You need **Node 22.13 or newer** (`node -v`).

    npm start

The console prints a **setup code**. Open http://localhost:3000, enter the code, and choose your vault key (12+ characters; a long phrase is best). Data goes into the `data/` folder.

## 2. Put it online so you can reach it from anywhere

You need a small server (a VPS with 1 GB RAM is enough; disk size = your storage) and a domain name.

1. Point a DNS **A record** (for example `vault.yourdomain.com`) at the server's IP address.
2. Install Docker on the server (https://docs.docker.com/engine/install/), then copy this folder to it.
3. Create your settings:

       cp .env.example .env
       openssl rand -base64 36        # paste the output as MASTER_SECRET in .env
       nano .env                      # also set DOMAIN=vault.yourdomain.com

   **Save MASTER_SECRET in a password manager now.** Without it, your files cannot be decrypted, even from a backup.
4. Open ports 80 and 443 in the server firewall, then start:

       mkdir -p backups && sudo chown 1000:1000 backups
       docker compose up -d --build
       docker compose logs vault        # shows the one-time SETUP CODE

5. Visit `https://vault.yourdomain.com`, enter the setup code, choose your vault key. Then open **Settings → Two-step login → Turn on** (strongly recommended) and save the backup codes.

**Render / Railway:** these hosts give you HTTPS and a disk, so you do not use Caddy or `docker-compose.yml`. Use `Dockerfile.cloud` (set the service's Dockerfile path to it), set `MASTER_SECRET` and `DATA_DIR` (equal to the disk's mount path), and attach a persistent disk. Never run more than one instance.

**No server? Use your own PC:** run `npm start` and expose it with a Cloudflare Tunnel (`cloudflared tunnel`) or Tailscale Funnel. Set `TRUST_PROXY=1` and `MASTER_SECRET` in the environment first. Uploads only work while the PC is on.

## 3. Everyday use

- **Upload:** drag files onto the page, or *Upload files*. Progress, speed and time left show in the bottom panel. Uploads keep going while you browse folders. If your connection drops they retry by themselves; if you close the tab, pick the same file again and it continues where it stopped. Keep the tab open for big transfers.
- **Share files without giving access to the vault:** tick one or more files, press *Share link* (or use the **⋯** menu on a file), choose how long it works (1 hour to 30 days) and an optional download limit. You get one link. The person who opens it sees only a small page listing those files, with *Download* buttons and *Download all as ZIP*. They never see the vault, other files or folders. Revoke any link in *Settings*. Links cannot be shown again after creation, so copy them right away. Folders cannot be shared as a link (download the folder as a ZIP and share the files instead).
- **Move and copy files:** select items, press **Cut** or **Copy** (or Ctrl/Cmd+X, Ctrl/Cmd+C), open the destination folder, press **Paste** (or Ctrl/Cmd+V). Cut moves; Copy makes an independent copy (it uses extra disk space). Name clashes get a free name such as `report (1).pdf`; nothing is overwritten. Other shortcuts: Ctrl/Cmd+A selects all, Delete removes the selection, Esc clears.
- **Preview:** click an image, video, audio, PDF or text file to open it without downloading.
- **Download many:** tick files or folders, then *Download as ZIP* (limit 4 GB total and 4 GB per file; download bigger files one by one).
- **Lock:** *Lock now*, or it locks itself after 15 idle minutes.

## 4. Backups (do this, then schedule it)

    docker compose exec vault node --disable-warning=ExperimentalWarning server.js backup /backups

This writes a consistent database snapshot plus the encrypted files into `./backups/`. It is incremental, so repeat runs are fast. Copy `./backups/` somewhere else (another machine, cloud storage, an external drive): for example `rsync -a backups/ user@other-machine:vault-backup/`. Run it daily with `cron`.

**Restore:** put the backup's `vault.db` and `files/` folder into a new data folder, start the vault with the **same MASTER_SECRET**, and log in with your usual vault key. (The backup is encrypted file data; it is useless without MASTER_SECRET, and that is by design.)

## 5. Updating

Replace `server.js` and/or `public/index.html`, then:

    docker compose up -d --build

Your data lives in a Docker volume and is not touched. Without Docker: stop the server and run `npm start` again.

## 6. Settings (environment variables in `.env`)

| Variable | Default | Meaning |
|---|---|---|
| `DOMAIN` | | Your domain (Docker only) |
| `MASTER_SECRET` | key file in data folder | Master encryption secret. Strongly recommended to set. |
| `MAX_FILE_SIZE` | 200 GB | Largest single file, bytes |
| `STORAGE_QUOTA` | unlimited | Total storage cap, bytes |
| `IDLE_MINUTES` | 15 | Auto-logout when unused |
| `SESSION_HOURS` | 12 | Longest a login lasts |
| `TRUST_PROXY` | 1 in Docker | Trust the proxy's client IP (needed for correct lockouts) |
| `CLIENT_IP_HEADER` | unset | If your host sets a header with the real visitor IP (for example `x-real-ip`), put its name here. Check *Settings → Recent activity* shows your real IP after logging in |
| `PORT`, `HOST`, `DATA_DIR` | 3000, 0.0.0.0, ./data | Where it listens and stores data |

## 7. Tests

    npm test                 # about 22 tests, under a minute
    BIG=1 npm test           # adds a 2 GB upload that checks server memory stays flat

## 8. How it protects your files, and where that stops

**What it does**
- Every file is encrypted on the server with its own random AES-256-GCM key; those keys are locked by `MASTER_SECRET`. Stored files have random names. Tampering with stored bytes is detected.
- The vault key is stored only as a salted scrypt hash. Wrong guesses are slowed and locked out per IP (1 minute, doubling up to 1 hour).
- Optional two-step login (authenticator app). Each code works once.
- Sessions use a protected cookie, expire when idle, and can be ended on all devices. Everything sensitive is recorded in the activity log (Settings).
- HTTPS is automatic through Caddy. Strict browser security headers; uploaded HTML or SVG can never run in your browser.
- Share links are 256-bit random; only a hash of each link is stored, so even a stolen database cannot reveal live links.

**What it cannot do**
- File **names and dates** are stored unencrypted in the database. Use full-disk encryption on the server if that matters.
- Anyone with root on your server can read `MASTER_SECRET` from the running process. This protects against stolen disks, stolen backups and the network, not against a fully compromised server. Keep the server updated and use SSH keys, not passwords.
- There is no "forgot password" email, by design. If you forget the vault key, someone with shell access to the server can run `docker compose exec vault node --disable-warning=ExperimentalWarning server.js reset-key` (or `node server.js reset-key` without Docker), restart, and choose a new key; your files stay intact. If you lose `MASTER_SECRET`, files are gone for good.
- No software is "100% secure". A long, unique vault key plus two-step login is the single biggest protection you control.
- A web page cannot keep uploading after you close the tab. Interrupted uploads resume when you pick the file again.
