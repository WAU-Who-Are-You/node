# wau-node

A node of the WAU decentralized realtime network. Anyone can run one: it relays end-to-end encrypted traffic for clients and links with other nodes. A node never sees plaintext, never stores chat, and keeps all room state in RAM.

## What a node does

- **Client relay** (`/socket.io`): forwards E2EE ciphertext, presence, and join requests/approvals.
- **Identity**: an Ed25519 keypair in `data/node-key.json`, with `nodeId = b64url(SHA-256(publicKey))`.
- **Registry**: on boot the node registers its public endpoint. The registry calls `GET /v1/node/challenge` back, so you can only register a domain you actually serve. After that the node sends a signed heartbeat with its load every 30 s.
- **Peer links** (`/peer`): mutual signed handshake. Every frame is signed and bound to its recipient, with replay, size and rate limits, ping/pong, and reconnect with backoff. Peers revoked in the registry are dropped.

## Run

Requires [Bun](https://bun.sh) ≥ 1.1.

```bash
bun install
cp .env.example .env      # set NODE_PUBLIC_URL to your domain
bun run start
```

Or ship a single file without `node_modules`:

```bash
bun run build             # → dist/wau-node.js   (run with: bun dist/wau-node.js)
bun run compile           # → dist/wau-node      (standalone binary, no Bun needed)
```

Put TLS in front and let WebSocket upgrades through for `/socket.io` and `/peer`. With Caddy:

```
node.example.com {
  reverse_proxy localhost:3003
}
```

On start the node prints its `nodeId` and registry status:

```
[node] nodeId    IkEdC9stwEtsXj-4KYDz8J_hFbI9iCdQrKpKRLD34UI
[registry-client] registered as active
```

**Back up `data/node-key.json`.** Losing it makes you a new node with a new nodeId.

## Configuration (`.env`)

| Variable | Default | |
|---|---|---|
| `NODE_PORT` | `3003` | listen port |
| `NODE_PUBLIC_URL` | (required) | public **https** origin. The node refuses to start otherwise |
| `NODE_NAME` | | display name |
| `NODE_DATA_DIR` | `./data` | where the node key lives |
| `NODE_REGISTRY_URL` | | registry; empty = standalone |
| `NODE_PEERS` | | comma-separated peer origins to keep linked |
| `NODE_PEER_POLICY` | `registered` with a registry, else `open` | who may link to you |
| `NODE_MAX_CLIENTS` | `5000` | refuse new clients above this |
| `NODE_MAX_CLIENTS_PER_IP` | `20` | client sockets per source IP |
| `NODE_MAX_PEERS` | `256` | peer links |
| `NODE_TRUST_PROXY` | `false` | read client IPs from `X-Forwarded-For`: `true` (every peer is your proxy) or `loopback` (only a proxy on this host). Never `true` on a directly exposed port |
| `NODE_FEDERATION` | `on` | `off` = standalone relay: no `/peer`, no registry, no outbound links |
| `NODE_ALLOW_INSECURE` | `false` | allow `http://` peers (dev/LAN) |
| `NODE_DEBUG` | `false` | expose `debug.dump` (leaks metadata, dev only) |

## Federation: home-node routing

A client connects to **one** node (its *entry* node). Every room has a **home** node, which is named in the invite link as `nodeId` + endpoint. The entry node routes the room there:

- Client room events carry `home`. The entry node remembers it **per socket**, so one client can't redirect another's room, and forwards events up (`room.up`) over the signed peer link.
- The home node treats each remote client as a session (`r:<nodeId>:<sid>`) through the same handlers as local sockets: same authorization, rate limits and presence.
- Deliveries come back as **one `room.down` frame per node**, listing that node's recipients, never one frame per client. The entry node only accepts a room's `room.down` from the home that socket chose.
- If the link to a home drops, its clients get `room.presence` inactive and the entry node keeps re-dialing with backoff. When the link is back, clients get `room.rehome` and re-subscribe themselves (fresh proof-of-possession, real ack, self-recovery if demoted).
- Concurrent events share one in-flight dial. `NODE_FEDERATION=off` refuses any non-local `home`.

## Discovery: finding a node by id

When a room's home isn't linked yet, the entry node tries these in order. Each is only a **hint**, because every dial verifies `nodeId == hash(publicKey)` in the signed handshake:

1. the endpoint in the invite
2. its address book (bounded; endpoints from its own links and peer answers)
3. the registry (the node's self-signed record is re-verified)
4. **peer exchange**: ask up to 8 linked peers `peers.request { want: nodeId }`. This works with no registry at all.

A wrong or hostile answer can only make a dial fail, and a stale address-book entry is dropped after a failed dial. Outside dev mode (`NODE_ALLOW_INSECURE`), the node **refuses to dial hosts that resolve to private, loopback, link-local or metadata addresses**, because both invites and peers choose endpoints.

With `NODE_PEER_POLICY=registered`, a node never seen before must be active in the registry. If the registry is down, **new** links fail closed. Existing links keep working, and the `open` policy and peer exchange still work.

`GET /v1/node/info` also returns `registry`, which clients use to list nodes (`GET {registry}/v1/nodes`, least loaded first).

## Security model

A node is **untrusted by design**. Clients and other nodes must assume any node may be malicious. What a node is prevented from doing:

- **Impersonating another node**: identities are keys (`nodeId = hash(pubkey)`). The handshake signs the full transcript (version, ids, endpoints, nonces), and frames are signed and bound to their recipient.
- **Registering a domain it doesn't serve**: the registry challenges the endpoint back. Private, loopback and metadata addresses are refused (SSRF), and errors stay generic.
- **Replay**: fresh nonces in handshakes, `(id, ts)` per frame, and `aud`-bound registrations and heartbeats.
- **Resource exhaustion**: caps on pending handshakes (64 total / 4 per IP), peers, clients per IP, frame size (256 KB, enough for one relayed file chunk) and rate (5000 frames / 10 s per peer), send backpressure, bounded caches, and HTTP header/request timeouts.
- **Reading chat**: it only ever handles E2EE ciphertext. Ciphertext and membership commits go to authenticated members only, never to observers.

**Enforced by the clients, not by nodes** (the app's `src/lib/trust.ts`):

- Each room's root of trust is the owner's ECDSA key. Its fingerprint rides in the invite link fragment (`wau2_….<fp>` / `wau3_….<fp>`), which never reaches a server.
- Join requests are signed over **both** identity keys, so a node can't swap the ECDH key the room key gets wrapped to. Answers are signed too.
- Challenges, decisions, membership commits and key envelopes are signed by the owner and checked against the pinned fingerprint. Envelopes are bound to room, epoch and recipient, and carry an owner-signed roster.
- Chat messages are signed by the sender and verified against the member list. Forged or unverifiable input is dropped, never acted on.
- Secret self-recovery only ever yields keys from members who already know that identity.

**Known limits:**

1. Every node sees metadata: room ids, timing, sizes, and connecting IPs.
2. A node can still **drop, delay or reorder** traffic (availability isn't something E2EE can provide).
3. Rooms joined via a pre-anchor link pin the owner key on first use (TOFU) during that join.
4. Relay-level secret recovery still admits anyone holding a v2 link to the relay's member set. They only receive ciphertext they can't read and can't get anything verified.
5. Group crypto is a custom epoch scheme. MLS is the planned replacement.
6. Client rate limits are per socket. Reconnecting resets them (per-IP connection caps limit the impact).

## HTTP

| Route | |
|---|---|
| `GET /v1/health` | liveness |
| `GET /v1/node/info` | nodeId, public key, endpoint, version |
| `GET /v1/node/challenge?nonce=&aud=` | signed proof of endpoint ownership |
| `GET /v1/node/peers` | currently linked peers |

## Development

```bash
bun run typecheck
# two local nodes linked without a registry
NODE_PORT=4101 NODE_PUBLIC_URL=http://localhost:4101 NODE_DATA_DIR=./data/a NODE_ALLOW_INSECURE=true bun run start
NODE_PORT=4102 NODE_PUBLIC_URL=http://localhost:4102 NODE_DATA_DIR=./data/b NODE_ALLOW_INSECURE=true NODE_PEERS=http://localhost:4101 bun run start
# abuse checks (needs a registry running too)
WAU_REGISTRY=http://localhost:4000 WAU_NODE=http://localhost:4101 bun run smoke
```

`src/protocol/` is the source of truth for the wire protocol (`network.ts` for node↔registry and node↔node, `client.ts` for client↔node, `crypto.ts` for signatures).
