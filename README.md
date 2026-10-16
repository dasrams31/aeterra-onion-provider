# Aeterra .onion Provider

Web service that bruteforces custom vanity Tor v3 (`.onion`) addresses.
A user requests a prefix (e.g. `myshop`), the server runs `mkp224o` in a
background worker (FIFO, one job at a time), and the requester downloads a
tar.gz containing `hostname`, `hs_ed25519_secret_key`, `hs_ed25519_public_key`.

## Run

```bash
PORT=18093 python3 app.py
```

Binds `127.0.0.1` only. To serve over Tor, point a hidden service at
`127.0.0.1:18093`:

```
HiddenServiceDir /var/lib/tor/aeterra-provider/
HiddenServicePort 80 127.0.0.1:18093
```

## Env vars

| Var | Default | Description |
|---|---|---|
| `PORT` | `18093` | Listen port (127.0.0.1 only) |
| `MKP224O_BIN` | `/home/hatch/workspace/mkp224o-build/mkp224o/mkp224o` | Path to mkp224o binary |
| `KEYS_PER_SEC` | `20000000` | Assumed bruteforce speed, for time estimates |

## Data layout

- `data/provider.db` — SQLite (WAL): `jobs`, `sessions` tables
- `jobs/<token>/` — per-job output (mode 0700): `<addr>.onion/` dir + `aeterra-<filter>.tar.gz`

On startup, jobs left in `queued`/`running` by an unclean shutdown
(e.g. VM reset) are re-queued automatically, and stale job dirs are
cleaned before a re-run.

## Security model

- **No accounts.** Each job gets a random `secrets.token_urlsafe(32)` token;
  the `/job/<token>` URL is the capability — anyone holding the link can
  download the keys. Do not share your job link.
- **The operator can see the keys** (files live on the server disk). Do not
  use this service for anything that must stay secret from the operator.
- Rate limits: max 1 active (queued/running) job per IP, max 5 jobs per
  24h per IP. Note: behind a Tor hidden service all clients appear as
  127.0.0.1, so these limits are effectively global.
- Per-session CSRF token on all POST forms, `html.escape` on all user
  content, parameterized SQL, 16KB body limit.
- Prefix validation: `^[a-z2-7]{1,7}$` (onion v3 address charset, max 7
  chars to keep bruteforce realistic).

## Flow

1. `GET /` — request form + time estimates per prefix length.
2. `POST /request` — validate, rate-limit, create job → redirect `/job/<token>`.
3. Worker thread picks the oldest queued job → `mkp224o -d jobs/<token> -n 1 <filter>`.
4. `GET /job/<token>` — status (auto-refresh every 5s while active),
   cancel/delete buttons, download button when done.
5. `GET /job/<token>/download` — tar.gz as attachment.

## Instant domains

`POST /instant` generates a fresh random v3 `.onion` address immediately —
no prefix, no bruteforce wait. Key generation uses a pure-Python Ed25519
implementation (`ed25519.py`, stdlib only, verified against OpenSSL and
against `mkp224o` output format). The result reuses the normal job page
(`kind=instant`) with instant download.

Tor secret key file layout (this is what Tor actually accepts — it is NOT
the libsodium `seed||pubkey` layout):

```
32-byte header "== ed25519v1-secret: type0 ==" + NUL*3
32-byte clamped scalar a = clamp(SHA512(seed)[0:32])
32-byte SHA512(seed)[32:64]
```

## Onion hosting

`GET /hosting` — upload a static website as a `.zip` (max 10 MB, 500 files,
50 MB uncompressed). Each project:

- gets its own freshly generated v3 `.onion` address (instant, via `ed25519.py`),
- is stored under `hosting/<token>/` (`public/` for site files, `keys/` for
  onion keys) — separate from job data,
- is served by the same app process, routed by the HTTP `Host` header,
- gets a Tor hidden service deployed automatically: keys are copied to
  `/var/lib/tor/aeterra-host-<token>/` (owned by `debian-tor`) and a managed
  block is maintained in `/etc/tor/torrc` between
  `Aeterra hosting projects BEGIN/END` markers, followed by `tor --verify-config`
  and a key-validity self-check before `systemctl reload tor@default`.

Management: `GET /hosting/<token>` (dashboard with file list),
`POST /hosting/<token>/delete` (removes project, keys, hidden service, and
torrc entry). On startup the app re-deploys all hosting hidden services and
regenerates the torrc block, so hosting survives VM resets.

Static serving: path-traversal safe, dotfiles blocked, `index.html`/`index.htm`
directory index, MIME types by extension, `X-Content-Type-Options: nosniff`.
