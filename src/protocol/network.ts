/**
 * WAU network protocol v1 — node ↔ registry and node ↔ node.
 *
 * Every message that asserts something about a node is signed by that
 * node's Ed25519 key (see ./crypto.ts). The registry and peers verify
 * `nodeIdFromPublicKey(publicKey) === nodeId` + signature + freshness; they
 * never trust an endpoint or name just because someone relayed it.
 */
export const NETWORK_PROTOCOL_VERSION = 1

/** signature domain tags — one per message kind */
export const SIG = {
  register: 'wau/registry/register/v1',
  heartbeat: 'wau/registry/heartbeat/v1',
  challenge: 'wau/node/challenge/v1',
  peerHelloResp: 'wau/peer/hello-resp/v1',
  peerAuth: 'wau/peer/auth/v1',
  peerFrame: 'wau/peer/frame/v1',
} as const

/** max clock skew tolerated on signed timestamps */
export const MAX_CLOCK_SKEW_MS = 5 * 60_000
export const REGISTRY_HEARTBEAT_INTERVAL_MS = 30_000
/** no heartbeat for this long → registry stops recommending the node */
export const REGISTRY_STALE_AFTER_MS = 90_000
export const PEER_PING_INTERVAL_MS = 15_000
/** fits one relayed E2EE file chunk (≤96k b64 chars) + routing envelope + signature */
export const PEER_FRAME_MAX_BYTES = 256 * 1024
export const PEER_FRAME_SKEW_MS = 60_000
/** generous: one busy entry node carries many clients' room traffic over a single link */
export const PEER_MAX_FRAMES_PER_WINDOW = 5_000
export const PEER_RATE_WINDOW_MS = 10_000

export interface NodeLoad {
  clients: number
  maxClients: number
  rooms: number
}

/** body signed by the node for POST /v1/nodes/register */
export interface RegisterBody {
  v: number
  nodeId: string
  publicKey: string
  /** public base URL, e.g. https://node.example.com (http allowed in dev) */
  endpoint: string
  name?: string
  software: string
  /** registry origin this registration is meant for — not replayable elsewhere */
  aud: string
  ts: number
  nonce: string
}

export interface HeartbeatBody {
  v: number
  nodeId: string
  aud: string
  ts: number
  nonce: string
  load: NodeLoad
}

/** what the registry hands out — clients/peers re-verify `registration.sig` */
export interface NodeRecord {
  nodeId: string
  publicKey: string
  endpoint: string
  name?: string
  software: string
  protocolVersion: number
  status: 'active' | 'stale' | 'pending_approval' | 'revoked'
  lastSeenAt: number
  createdAt: number
  load?: NodeLoad
  registration: { body: RegisterBody; sig: string }
}

/** GET {endpoint}/v1/node/challenge?nonce=…&aud=… — proves the node controls the endpoint */
export interface ChallengeResponseBody {
  nodeId: string
  publicKey: string
  nonce: string
  aud: string
  ts: number
}

// ---------- node ↔ node (WebSocket at {endpoint}/peer) ----------
export type PeerMessage =
  | { t: 'hello'; v: number; nodeId: string; publicKey: string; endpoint: string; nonce: string; ts: number }
  | {
      t: 'hello-resp'
      v: number
      nodeId: string
      publicKey: string
      endpoint: string
      nonce: string
      ts: number
      sig: string
    }
  | { t: 'auth'; sig: string }
  | { t: 'ready' }
  | { t: 'frame'; id: string; ts: number; body: PeerFrameBody; sig: string }
  | { t: 'error'; code: string; message: string }

/** application payloads carried between authenticated peers */
export type PeerFrameBody =
  | { kind: 'ping'; at: number }
  | { kind: 'pong'; at: number }
  /** `want`: ask for one node by id (peer exchange — the answer is only a hint; the handshake verifies it) */
  | { kind: 'peers.request'; want?: string }
  | { kind: 'peers.response'; peers: Array<{ nodeId: string; publicKey: string; endpoint: string }> }
  // ---- home-node routing (entry node ⇄ room's home node) ----
  /** entry → home: a client event for a room homed there. `sid` = the client's socket id on the entry node */
  | { kind: 'room.up'; sid: string; roomId: string; event: string; data: unknown; ackId?: string }
  /** home → entry: result of a forwarded event */
  | { kind: 'room.ack'; ackId: string; res: { ok: boolean; code?: string; message?: string } }
  /** home → entry: deliver one event to several of the entry node's clients (one frame per node, not per client) */
  | { kind: 'room.down'; sids: string[]; roomId: string; event: string; data: unknown }
  /** entry → home: that client disconnected */
  | { kind: 'room.gone'; sid: string }

/**
 * Handshake transcript both signatures cover: protocol version, both node
 * ids, both nonces and both claimed endpoints — nothing either side relies on
 * is left unsigned (a MITM on a plain-ws dev link can't rewrite endpoints).
 */
export interface PeerTranscript {
  v: number
  initiatorId: string
  initiatorEndpoint: string
  initiatorNonce: string
  responderId: string
  responderEndpoint: string
  responderNonce: string
}
export const peerHelloRespPayload = (t: PeerTranscript) => ({ role: 'responder', ...t })
export const peerAuthPayload = (t: PeerTranscript) => ({ role: 'initiator', ...t })

/** normalize + validate a public endpoint URL; returns origin without trailing slash */
export function normalizeEndpoint(raw: unknown, allowInsecure: boolean): string | null {
  if (typeof raw !== 'string' || raw.length > 255) return null
  try {
    const u = new URL(raw)
    if (u.protocol !== 'https:' && !(allowInsecure && u.protocol === 'http:')) return null
    if (u.username || u.password || u.search || u.hash) return null
    if (u.pathname !== '/' && u.pathname !== '') return null
    return u.origin
  } catch {
    return null
  }
}

export const peerWsUrl = (endpoint: string) => endpoint.replace(/^http/, 'ws') + '/peer'
