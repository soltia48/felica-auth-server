# felica-auth-server

A remote **FeliCa authentication server** written in Rust. The server holds the
long-term keys and performs **FeliCa Standard mutual authentication only**, while a
separate **client owns the physical reader**. For each authentication step the
server returns the exact command frame the client must relay to the card, and
consumes the card's response on the following request.

When authentication succeeds the server hands back the **ephemeral session
material** (DES session key, transaction ID, transaction counter) and immediately
forgets the session. The client then runs the encrypted Read/Write commands
itself — so **card data never passes through the server**, and the long-term
system/area/service keys never leave it.

The FeliCa cryptography (challenge math, MACs, secure framing) is reused verbatim
from the [`felica-rs`](https://github.com/soltia48/felica-rs) library. A per-session
worker thread drives `felica_rs::felica_standard::FelicaStandard` through a custom
relay `FelicaDriver` whose `transceive` bounces each frame to the HTTP client and
blocks for the reply.

```
   client (owns reader + data)             felica-auth-server (owns long-term keys)
   ───────────────────────────             ────────────────────────────────────────
   poll card → IDm/PMm
        │  POST /mutual-authentication ────────▶ derive keys, build Auth1 frame
        │  ◀──────────────── { command.frame } ─┘
   send frame to card
        │  POST /mutual-authentication ────────▶ verify, build Auth2 frame
        │      { card_response } ◀── { frame } ─┘
   send frame to card
        │  POST /mutual-authentication ────────▶ verify → issue_id + session material,
        │      { card_response } ◀ { complete } ┘   then the session is discarded
        │
   ── from here the server is not involved ──
   rebuild the secure session locally from { session.key, transaction_id,
   transaction_number } and run encrypted Read / Write straight against the card.
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
| `--read-only-nodes` | `FELICA_READ_ONLY_NODES` | off | Only authenticate read-only services (see below) |
| `--session-ttl` | `FELICA_SESSION_TTL` | `300` | Idle seconds before an unfinished authentication is reaped |
| `--max-sessions` | `FELICA_MAX_SESSIONS` | `1024` | Max concurrent in-flight authentications |

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
`frame`, `key`, `transaction_id`) are hex strings. Integer fields accept a JSON
number or a decimal/`0x`-hex string.

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

Step 2 returns the `auth2` command; step 3 completes and returns the session
material:

```json
{ "phase": "mutual_authentication", "step": "complete",
  "result": {
    "issue_id": "…", "issue_parameter": "…",
    "session": {
      "scheme": "des",
      "key": "<8-byte hex session key>",
      "transaction_id": "<6-byte hex>",
      "transaction_number": 0
    }
  },
  "session_id": "…" }
```

The server discards the session at this point — a further request with that
`session_id` returns `404`.

## Running commands from the client

The `session` block is everything needed to keep talking to the card securely. With
`felica-rs` on the client side:

```rust
use felica_rs::felica_standard::{
    AuthenticatedContext, BlockListElement, FelicaStandard, SecureSessionCredentials,
};

let (mut felica, _) = FelicaStandard::polling(reader.driver_mut(), "212F", 0x0003, 0, 0)?;
felica.set_authenticated_context(AuthenticatedContext::new(
    transaction_number,                       // from session.transaction_number
    transaction_id,                           // from session.transaction_id
    SecureSessionCredentials::Des(session_key) // from session.key
));

// Encrypted, straight against the card — the server sees none of this.
let blocks = felica.read(&[BlockListElement::new(0, 0, 0)])?;
felica.write(&[BlockListElement::new(0, 0, 0)], &new_block)?;
```

`felica.secure_transceive(cmd_code, payload, timeout_ms)` is available for arbitrary
secure commands.

## Errors

```json
{ "error": { "message": "…", "code": 41220 } }
```

`code` is present for FeliCa status-flag failures (`SF1 << 8 | SF2`). HTTP status is
`400` for protocol/validation errors, `404` for an unknown session, `503` when the
session cap is reached, `500` otherwise.

## Session lifecycle

A session exists only for the duration of one authentication: it is created on the
first request, keyed by a random `session_id`, backed by a worker thread, and
**destroyed as soon as the session material is returned** — no key state lingers on
the server. Authentications abandoned midway are reaped after `--session-ttl`
seconds, and the number in flight is bounded by `--max-sessions`.

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

It also sets `FELICA_READ_ONLY_NODES: "true"` as a safe default, so a compose
deployment only authenticates read-only services (see below). Set it to `"false"`
if the deployment needs to authenticate writable nodes.

## Restricting to read-only nodes

`--read-only-nodes` makes the server refuse to authenticate anything but read-only
services, so the session key it hands out cannot be used to modify the card — the
card itself rejects a Write on a read-only service.

Accepted service attributes (both the "with key" and "without key" variants):

| Attribute  | Meaning                       |
|------------|-------------------------------|
| `0b001010` | Random read-only with key     |
| `0b001011` | Random read-only without key  |
| `0b001110` | Cyclic read-only with key     |
| `0b001111` | Cyclic read-only without key  |
| `0b010110` | Purse read-only with key      |
| `0b010111` | Purse read-only without key   |

Anything else — read/write, purse direct/cashback/decrement — is rejected with
`403`. The mode also validates the list the way the card does, so you get a clear
`400` instead of an opaque failure: a service list must contain **at least one node
that requires a key**, and key-requiring nodes must be listed **before** key-free
ones (e.g. `["0x008A", "0x00CB"]`).

A session can only access the services named in the authentication, so this bounds
the whole session to reads. FeliCa also requires at least one area node in the
request: it takes part in the key derivation and does not widen data access, so
areas are accepted as usual.

Which nodes can be authenticated at all is additionally bounded by the key file —
the server can only authenticate nodes it holds a key for, and returns `400` for
anything else.

## Security model

What the split buys you, and what it does not:

- **Long-term keys stay on the server.** The system, area and service keys are only
  ever used here, to derive the authentication keys. A client never sees them.
- **Card data never reaches the server.** Read/Write are executed by the client
  against the card, so block contents are not exposed to (or logged by) this
  service.
- **The client does receive the session key.** It is ephemeral — scoped to one
  authenticated card session — but within that session it lets the client issue any
  encrypted command the authenticated services allow. That is inherent: the client
  cannot read or write data without it. The server cannot restrict which commands
  are issued, only **which nodes it authenticates** — so bound a session with
  `--read-only-nodes`, and by provisioning keys only for the nodes a caller should
  ever reach.
- **There is no request authentication.** Any client that can reach the port can ask
  for an authentication with the configured keys. Bind it to a trusted network or
  front it with your own authenticating proxy; do not expose it to the internet.

## Tests

```bash
cargo test
```

Unit tests cover the key store; the end-to-end tests drive the full mutual
authentication against `felica-rs`'s in-memory card emulator, then use the returned
session material to perform an encrypted Read **client-side**, asserting the real
block data comes back — and that the server dropped the session.
