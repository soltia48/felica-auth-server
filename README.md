# felica-auth-server

A remote **FeliCa crypto oracle** written in Rust. The server holds the secret
keys and drives the FeliCa Standard mutual-authentication and secure-messaging
protocol, while a separate **client owns the physical reader**. For each protocol
step the server returns the exact command frame the client must relay to the card,
and consumes the card's response on the following request. Keys never leave the
server.

The FeliCa cryptography (challenge math, MACs, secure framing) is reused verbatim
from the [`felica-rs`](https://github.com/soltia48/felica-rs) library. A per-session worker thread drives
`felica_rs::felica_standard::FelicaStandard` through a custom relay
`FelicaDriver` whose `transceive` bounces each frame to the HTTP client and blocks
for the reply.

```
   client (owns reader)                    felica-auth-server (owns keys)
   ─────────────────────                    ──────────────────────────────
   poll card → IDm/PMm
        │  POST /mutual-authentication ────────▶ derive keys, build Auth1 frame
        │  ◀──────────────── { command.frame } ─┘
   send frame to card
        │  POST /mutual-authentication ────────▶ verify, build Auth2 frame
        │      { card_response } ◀── { frame } ─┘
   send frame to card
        │  POST /mutual-authentication ────────▶ verify → issue_id / issue_parameter
        │      { card_response } ◀ { complete } ┘
   ... then POST /encryption-exchange to run encrypted Read/Write commands ...
```

## Build & run

Requires a recent Rust toolchain (the `felica-rs` dependency uses edition 2024). The
`felica-rs` crate is pulled from git
(`github.com/soltia48/felica-rs`), so the build needs GitHub access. This project
sets `net.git-fetch-with-cli = true` (see [`.cargo/config.toml`](.cargo/config.toml))
so cargo uses your system git credentials; for the private repo, an SSH key plus a
`url."ssh://git@github.com/".insteadOf "https://github.com/"` git rewrite works.

```bash
cargo build --release
./target/release/felica-auth-server --keys keys.jsonl --host 127.0.0.1 --port 8000
```

Options (all also settable via environment variables):

| Flag | Env | Default | Purpose |
|------|-----|---------|---------|
| `--host` | `FELICA_HOST` | `127.0.0.1` | Bind address |
| `--port` | `FELICA_PORT` | `8000` | Listen port |
| `--keys` | `FELICA_KEYS` | `keys.jsonl` | Path to the keys JSONL file |
| `--log-level` | `FELICA_LOG_LEVEL` | `info` | Log verbosity (`RUST_LOG` overrides) |
| `--allowed-cmd-code` | `FELICA_ALLOWED_CMD_CODES` | *(unset = all)* | Restrict encrypted-exchange command codes (repeatable; comma-separated in env; decimal or `0x` hex) |
| `--session-ttl` | `FELICA_SESSION_TTL` | `300` | Idle seconds before a session is reaped |
| `--max-sessions` | `FELICA_MAX_SESSIONS` | `1024` | Max concurrent sessions |

## Keys file (`keys.jsonl`)

One JSON object per line, matching `felica-rs`'s `keys.jsonl` shape:

```json
{"system_code":"0003","node":"FFFF","algo":"DES","version":"0003","idm":null,"key":"00112233445566FF"}
```

- `system_code` / `node` — hex integers. Node `FFFF` is the **system key**.
- `algo` — `"DES"` (8-byte key) or `"AES"` (16-byte key). This server authenticates
  over DES; AES records are ignored.
- `version` — key version (informational; ignored for lookup).
- `idm` — `null` for a system-wide key, or an 8-byte hex IDm for a **card-specific
  key**. When a card is authenticated, a key whose `idm` matches that card is
  preferred, otherwise the system-wide key is used.
- `key` — the key, hex-encoded.

See [`keys.jsonl.example`](keys.jsonl.example). **Never commit real keys.**

## HTTP API

All request/response bodies are JSON. Byte fields (`idm`, `pmm`, `card_response`,
`payload`, `frame`, `response`) are hex strings. Integer fields accept a JSON number
or a decimal/`0x`-hex string.

### `GET /healthz`

```json
{ "status": "ok" }
```

### `POST /mutual-authentication`

A three-step exchange keyed by `session_id`.

**Step 1 — start** (no `session_id`; supply `idm`/`pmm` and the nodes to authenticate):

```json
{ "idm": "0101010101010101", "pmm": "0100000000000000",
  "system_code": "0x0003", "areas": ["0x0000"], "services": ["0x0048"] }
```

Response — relay `command.frame` to the card:

```json
{ "phase": "mutual_authentication", "step": "auth1",
  "command": { "code": 16, "frame": "10....", "timeout": 0.003 },
  "session_id": "…", "session_created": true }
```

**Step 2 & 3 — feed the card response back** using the returned `session_id`:

```json
{ "session_id": "…", "card_response": "…" }
```

Step 2 returns the `auth2` command; step 3 completes:

```json
{ "phase": "mutual_authentication", "step": "complete",
  "result": { "issue_id": "…", "issue_parameter": "…" }, "session_id": "…" }
```

### `POST /encryption-exchange`

A two-step exchange over an authenticated session.

**Start** — supply the FeliCa command code and its secure payload:

```json
{ "session_id": "…", "cmd_code": 20, "payload": "018000" }
```

(`cmd_code` 20 = `0x14` Read; payload `01 80 00` = read 1 block, service-list index 0,
block 0.) Response — relay `command.frame` to the card:

```json
{ "phase": "encryption_exchange",
  "command": { "code": 20, "frame": "14….", "timeout": 0.003 }, "session_id": "…" }
```

**Complete** — feed the card response back:

```json
{ "session_id": "…", "card_response": "…" }
```

```json
{ "phase": "encryption_exchange", "response": "0000011011…", "session_id": "…" }
```

`response` is the decrypted secure-response payload (e.g. `SF1 SF2 block_count
block…`), returned raw including DES block padding — the secure response carries no
length field, so the client interprets the structure.

### Errors

```json
{ "error": { "message": "…", "code": 41220 } }
```

`code` is present for FeliCa status-flag failures (`SF1 << 8 | SF2`). HTTP status is
`400` for protocol/validation errors, `403` for a disallowed command code, `404` for
an unknown session, `503` when the session cap is reached, `500` otherwise.

## Session lifecycle

Sessions live in memory, keyed by a random `session_id`, each backed by a worker
thread. Idle sessions are reaped after `--session-ttl` seconds and the total is
bounded by `--max-sessions`.

## Docker

The `felica-rs` git dependency is fetched over SSH during the build, so BuildKit
must forward your SSH agent. See [`Dockerfile`](Dockerfile) and
[`compose.yaml`](compose.yaml):

```bash
docker compose up --build          # compose forwards the agent (ssh: default)
# or, plain docker:
DOCKER_BUILDKIT=1 docker build --ssh default -t felica-auth-server .
```

The compose file mounts `keys.jsonl` as a **Docker secret** (at
`/run/secrets/felica_keys`, readable only by the app user) rather than a bind
mount, since it holds key material. Place your `keys.jsonl` next to `compose.yaml`.

## Tests

```bash
cargo test
```

Includes unit tests for the key store and an end-to-end test that drives the full
mutual authentication and an encrypted Read against `felica-rs`'s in-memory card
emulator.
