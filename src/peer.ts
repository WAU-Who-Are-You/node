/**
 * Node ↔ node links over WebSocket at {endpoint}/peer.
 *
 * Handshake (mutual, Ed25519, both signatures over the full transcript —
 * version, both ids, both endpoints, both nonces):
 *   I → R  hello      { nodeId, publicKey, endpoint, nonce nI }
 *   R → I  hello-resp { nodeId, publicKey, endpoint, nonce nR, sig_R(transcript) }
 *   I → R  auth       { sig_I(transcript) }
 *   R → I  ready
 * Each side checks nodeId == hash(publicKey). The initiator also checks the
 * responder is the nodeId it meant to reach (from link/registry). Fresh
 * nonces on both sides make recorded handshakes useless.
 *
 * After `ready`, every frame is signed, bound to its recipient, carries
 * (id, ts) for replay defence, and is size- and rate-limited per peer.
 *
 * Abuse limits: pending (unauthenticated) handshakes are capped globally and
 * per source IP; total links are capped; registry lookups are cached and
 * bounded. Admission is re-checked periodically (revocation).
 */
import { WebSocket, WebSocketServer, type RawData } from 'ws'
import type { IncomingMessage } from 'node:http'
import type { Duplex } from 'node:stream'
import { isValidPublicKey, nodeIdFromPublicKey, randomNonce, signBody, verifyBody, type NodeKeyPair } from './protocol/crypto'
import {
  NETWORK_PROTOCOL_VERSION,
  PEER_FRAME_MAX_BYTES,
  PEER_FRAME_SKEW_MS,
  PEER_MAX_FRAMES_PER_WINDOW,
  PEER_PING_INTERVAL_MS,
  PEER_RATE_WINDOW_MS,
  SIG,
  normalizeEndpoint,
  peerAuthPayload,
  peerHelloRespPayload,
  peerWsUrl,
  type PeerFrameBody,
  type PeerMessage,
  type PeerTranscript,
} from './protocol/network'
import type { NodeConfig } from './config'
import { requestIp } from './net'
import { assertPublicHost } from './net-guard'
import type { RegistryClient } from './registry-client'

const log = (...a: unknown[]) => console.log('[peer]', ...a)
const HANDSHAKE_TIMEOUT_MS = 10_000
const MAX_PENDING_HANDSHAKES = 64
const MAX_PENDING_PER_IP = 4
const MAX_KNOWN_PEERS = 2_000
const DISCOVERY_TIMEOUT_MS = 3_000
const DISCOVERY_FANOUT = 8
const FRAME_KINDS = new Set<PeerFrameBody['kind']>(['ping', 'pong', 'peers.request', 'peers.response', 'room.up', 'room.ack', 'room.down', 'room.gone'])
const short = (id: string) => id.slice(0, 10)

export interface PeerLink {
  nodeId: string
  publicKey: string
  endpoint: string
  direction: 'inbound' | 'outbound'
  connectedAt: number
  ws: WebSocket
}

type FrameHandler = (from: PeerLink, body: PeerFrameBody) => void
type LinkHandler = (link: PeerLink, up: boolean) => void
type Hello = Extract<PeerMessage, { t: 'hello' | 'hello-resp' }>

export function createPeerManager(cfg: NodeConfig, id: NodeKeyPair, registry: RegistryClient) {
  const links = new Map<string, PeerLink>()
  const wss = new WebSocketServer({ noServer: true, maxPayload: PEER_FRAME_MAX_BYTES, perMessageDeflate: false })
  const handlers = new Set<FrameHandler>()
  const linkHandlers = new Set<LinkHandler>()
  const notifyLink = (link: PeerLink, up: boolean) => {
    for (const h of linkHandlers) {
      try {
        h(link, up)
      } catch (e) {
        log('link handler error', (e as Error).message)
      }
    }
  }
  /** endpoints we keep dialing (static peers + on-demand), endpoint → expected nodeId */
  const wanted = new Map<string, string | undefined>()
  /**
   * Address book: nodeId → last endpoint seen (our links + peer-exchange answers).
   * Only ever a HINT — every dial still verifies nodeId == hash(publicKey) in the
   * signed handshake, so a lying peer can make a dial fail, never impersonate.
   */
  const knownPeers = new Map<string, { publicKey: string; endpoint: string; at: number }>()
  const learn = (nodeId: string, publicKey: string, endpoint: string) => {
    if (nodeId === id.nodeId) return
    knownPeers.delete(nodeId)
    if (knownPeers.size >= MAX_KNOWN_PEERS) knownPeers.delete(knownPeers.keys().next().value!)
    knownPeers.set(nodeId, { publicKey, endpoint, at: Date.now() })
  }
  /** discovery waiters: nodeId → resolvers waiting for a peer-exchange answer */
  const discoveryWaiters = new Map<string, Array<(endpoint: string) => void>>()
  /** in-flight dials — concurrent callers share ONE attempt instead of being turned away */
  const dialing = new Map<string, Promise<PeerLink | null>>()
  /** failed dials back off exponentially (5s → 5min) so a refused node isn't hammered */
  const retry = new Map<string, { at: number; delay: number }>()
  const seenFrames = new Map<string, number>()
  const frameRate = new Map<string, number[]>()
  const pendingByIp = new Map<string, number>()
  let pendingTotal = 0

  // ---------- helpers ----------
  function send(ws: WebSocket, msg: PeerMessage) {
    if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(msg))
  }
  function reject(ws: WebSocket, code: string, message: string) {
    send(ws, { t: 'error', code, message })
    ws.close(4000, code)
  }
  function parse(raw: RawData): PeerMessage | null {
    try {
      const m = JSON.parse(raw.toString()) as PeerMessage
      return m && typeof m === 'object' && !Array.isArray(m) && typeof m.t === 'string' ? m : null
    } catch {
      return null
    }
  }
  function validHello(m: Hello): string | null {
    if (m.v !== NETWORK_PROTOCOL_VERSION) return 'unsupported protocol version'
    if (!isValidPublicKey(m.publicKey)) return 'bad public key'
    if (typeof m.nodeId !== 'string' || m.nodeId !== nodeIdFromPublicKey(m.publicKey)) return 'nodeId != hash(publicKey)'
    if (m.nodeId === id.nodeId) return 'refusing to link to self'
    if (typeof m.nonce !== 'string' || !/^[A-Za-z0-9_-]{16,64}$/.test(m.nonce)) return 'bad nonce'
    if (normalizeEndpoint(m.endpoint, cfg.allowInsecure) !== m.endpoint) return 'bad endpoint'
    return null
  }
  const transcript = (i: { id: string; ep: string; n: string }, r: { id: string; ep: string; n: string }): PeerTranscript => ({
    v: NETWORK_PROTOCOL_VERSION,
    initiatorId: i.id,
    initiatorEndpoint: i.ep,
    initiatorNonce: i.n,
    responderId: r.id,
    responderEndpoint: r.ep,
    responderNonce: r.n,
  })

  /** registry policy: the peer must be an active registered node at that endpoint */
  async function admit(nodeId: string, endpoint: string): Promise<string | null> {
    if (cfg.peerPolicy === 'open') return null
    const rec = await registry.lookup(nodeId)
    if (!rec) return 'not registered'
    if (rec.status !== 'active') return `registry status ${rec.status}`
    if (rec.endpoint !== endpoint) return 'endpoint does not match registry'
    return null
  }

  // ---------- inbound ----------
  function handleInbound(ws: WebSocket, ip: string) {
    const myNonce = randomNonce()
    let state: 'await-hello' | 'checking' | 'await-auth' | 'done' = 'await-hello'
    let peer: { nodeId: string; publicKey: string; endpoint: string; nonce: string } | null = null
    let released = false
    const release = () => {
      if (released) return
      released = true
      pendingTotal--
      const n = (pendingByIp.get(ip) ?? 1) - 1
      if (n <= 0) pendingByIp.delete(ip)
      else pendingByIp.set(ip, n)
    }
    const timeout = setTimeout(() => reject(ws, 'timeout', 'handshake timeout'), HANDSHAKE_TIMEOUT_MS)

    const onMessage = async (raw: RawData) => {
      const m = parse(raw)
      if (!m) return reject(ws, 'bad-message', 'unparseable')
      if (state === 'await-hello' && m.t === 'hello') {
        const err = validHello(m)
        if (err) return reject(ws, 'bad-hello', err)
        state = 'checking' // anything arriving while we consult the registry is a protocol violation
        const denied = await admit(m.nodeId, m.endpoint)
        if (ws.readyState !== WebSocket.OPEN) return
        if (denied) {
          log('inbound refused', short(m.nodeId), denied)
          return reject(ws, 'forbidden', denied)
        }
        if (links.size >= cfg.maxPeers && !links.has(m.nodeId)) return reject(ws, 'full', 'peer capacity reached')
        peer = { nodeId: m.nodeId, publicKey: m.publicKey, endpoint: m.endpoint, nonce: m.nonce }
        const tr = transcript({ id: m.nodeId, ep: m.endpoint, n: m.nonce }, { id: id.nodeId, ep: cfg.publicUrl, n: myNonce })
        state = 'await-auth'
        send(ws, {
          t: 'hello-resp',
          v: NETWORK_PROTOCOL_VERSION,
          nodeId: id.nodeId,
          publicKey: id.publicKey,
          endpoint: cfg.publicUrl,
          nonce: myNonce,
          ts: Date.now(),
          sig: signBody(id.privateKey, SIG.peerHelloResp, peerHelloRespPayload(tr)),
        })
        return
      }
      if (state === 'await-auth' && peer && m.t === 'auth') {
        const tr = transcript({ id: peer.nodeId, ep: peer.endpoint, n: peer.nonce }, { id: id.nodeId, ep: cfg.publicUrl, n: myNonce })
        if (!verifyBody(peer.publicKey, SIG.peerAuth, peerAuthPayload(tr), m.sig)) return reject(ws, 'bad-auth', 'auth signature invalid')
        state = 'done'
        clearTimeout(timeout)
        release()
        ws.off('message', onMessage)
        send(ws, { t: 'ready' })
        attach({ ...peer, direction: 'inbound', connectedAt: Date.now(), ws })
        return
      }
      reject(ws, 'bad-sequence', `unexpected ${m.t} in state ${state}`)
    }
    ws.on('message', onMessage)
    ws.on('close', () => {
      clearTimeout(timeout)
      release()
    })
    ws.on('error', () => ws.terminate())
  }

  // ---------- outbound ----------
  function dial(endpoint: string, expectedNodeId?: string): Promise<PeerLink | null> {
    const existing = [...links.values()].find((l) => l.endpoint === endpoint)
    if (existing) return Promise.resolve(existing)
    const inflight = dialing.get(endpoint)
    if (inflight) return inflight.then((l) => (l && expectedNodeId && l.nodeId !== expectedNodeId ? null : l))
    if (links.size >= cfg.maxPeers) return Promise.resolve(null)

    const attempt = new Promise<PeerLink | null>((resolve) => {
      // endpoints come from invites and peer answers — never dial into our own network
      // (dev/LAN mode is the explicit exception)
      if (!cfg.allowInsecure) {
        assertPublicHost(endpoint).then(
          () => open(),
          () => {
            log('refusing to dial non-public host', endpoint)
            dialing.delete(endpoint)
            resolve(null)
          },
        )
      } else open()

      function open() {
      const ws = new WebSocket(peerWsUrl(endpoint), {
        maxPayload: PEER_FRAME_MAX_BYTES,
        handshakeTimeout: HANDSHAKE_TIMEOUT_MS,
        perMessageDeflate: false,
        followRedirects: false,
      })
      const myNonce = randomNonce()
      let peer: { nodeId: string; publicKey: string; endpoint: string; nonce: string } | null = null
      let settled = false
      const done = (link: PeerLink | null) => {
        if (settled) return
        settled = true
        dialing.delete(endpoint)
        if (link) retry.delete(endpoint)
        else {
          const delay = Math.min((retry.get(endpoint)?.delay ?? 2_500) * 2, 5 * 60_000)
          retry.set(endpoint, { at: Date.now() + delay, delay })
        }
        clearTimeout(timeout)
        resolve(link)
      }
      const timeout = setTimeout(() => {
        ws.terminate()
        done(null)
      }, HANDSHAKE_TIMEOUT_MS)

      ws.on('open', () =>
        send(ws, {
          t: 'hello',
          v: NETWORK_PROTOCOL_VERSION,
          nodeId: id.nodeId,
          publicKey: id.publicKey,
          endpoint: cfg.publicUrl,
          nonce: myNonce,
          ts: Date.now(),
        }),
      )
      const onMessage = async (raw: RawData) => {
        const m = parse(raw)
        if (!m) return ws.close(4000, 'bad-message')
        if (m.t === 'error') {
          log('dial refused by', endpoint, String(m.code).slice(0, 40))
          return ws.close()
        }
        if (!peer && m.t === 'hello-resp') {
          const err = validHello(m)
          if (err) return ws.close(4000, 'bad-hello')
          // the responder must be who we meant to reach, at the endpoint we dialed
          if (expectedNodeId && m.nodeId !== expectedNodeId) {
            log('dial', endpoint, 'answered by unexpected node', short(m.nodeId))
            return ws.close(4000, 'unexpected-node')
          }
          if (m.endpoint !== endpoint) return ws.close(4000, 'endpoint-mismatch')
          const tr = transcript({ id: id.nodeId, ep: cfg.publicUrl, n: myNonce }, { id: m.nodeId, ep: m.endpoint, n: m.nonce })
          if (!verifyBody(m.publicKey, SIG.peerHelloResp, peerHelloRespPayload(tr), m.sig)) return ws.close(4000, 'bad-signature')
          // outbound links obey the same registry policy as inbound ones
          peer = { nodeId: m.nodeId, publicKey: m.publicKey, endpoint, nonce: m.nonce }
          const denied = await admit(m.nodeId, endpoint)
          if (denied) {
            log('dial', endpoint, 'refused by policy:', denied)
            return ws.close(4003, 'policy')
          }
          send(ws, { t: 'auth', sig: signBody(id.privateKey, SIG.peerAuth, peerAuthPayload(tr)) })
          return
        }
        if (peer && m.t === 'ready') {
          ws.off('message', onMessage)
          return done(attach({ ...peer, direction: 'outbound', connectedAt: Date.now(), ws }))
        }
        ws.close(4000, 'bad-sequence')
      }
      ws.on('message', onMessage)
      ws.on('error', (e) => log('dial error', endpoint, e.message))
      ws.on('close', () => done(null))
      }
    })
    dialing.set(endpoint, attempt)
    return attempt
  }

  // ---------- established link ----------
  function attach(link: PeerLink): PeerLink | null {
    const dup = links.get(link.nodeId)
    if (dup && dup.ws.readyState === WebSocket.OPEN) {
      // both sides dialed each other: deterministic tie-break keeps exactly
      // one link — the one initiated by the smaller nodeId
      const initiator = (l: PeerLink) => (l.direction === 'outbound' ? id.nodeId : l.nodeId)
      const keepNew = initiator(link) < initiator(dup)
      const loser = keepNew ? dup : link
      loser.ws.close(4001, 'duplicate-link')
      if (!keepNew) return dup
      links.delete(dup.nodeId)
    }
    links.set(link.nodeId, link)
    learn(link.nodeId, link.publicKey, link.endpoint)
    log('linked', link.direction, short(link.nodeId), link.endpoint)
    queueMicrotask(() => notifyLink(link, true))

    let alive = true
    const ping = setInterval(() => {
      if (!alive) {
        log('peer timeout', short(link.nodeId))
        return link.ws.terminate()
      }
      alive = false
      link.ws.ping()
    }, PEER_PING_INTERVAL_MS)
    link.ws.on('pong', () => (alive = true))
    link.ws.on('message', (raw) => onFrame(link, raw))
    link.ws.on('error', () => link.ws.terminate())
    link.ws.on('close', (code) => {
      clearInterval(ping)
      if (links.get(link.nodeId) === link) {
        links.delete(link.nodeId)
        frameRate.delete(link.nodeId)
        log('unlinked', short(link.nodeId), code)
        notifyLink(link, false)
      }
    })
    return link
  }

  function onFrame(link: PeerLink, raw: RawData) {
    const t = Date.now()
    const arr = (frameRate.get(link.nodeId) ?? []).filter((x) => x > t - PEER_RATE_WINDOW_MS)
    if (arr.length >= PEER_MAX_FRAMES_PER_WINDOW) {
      log('peer rate limit exceeded, dropping link', short(link.nodeId))
      return link.ws.close(4002, 'rate-limited')
    }
    arr.push(t)
    frameRate.set(link.nodeId, arr)

    const m = parse(raw)
    if (!m || m.t !== 'frame' || typeof m.id !== 'string' || !/^[A-Za-z0-9_-]{8,64}$/.test(m.id)) return
    if (typeof m.ts !== 'number' || Math.abs(t - m.ts) > PEER_FRAME_SKEW_MS) return
    const body = m.body as PeerFrameBody | undefined
    if (!body || typeof body !== 'object' || !FRAME_KINDS.has(body.kind)) return
    const replayKey = `${link.nodeId}:${m.id}`
    if (seenFrames.has(replayKey)) return
    if (!verifyBody(link.publicKey, SIG.peerFrame, { id: m.id, ts: m.ts, to: id.nodeId, body }, m.sig)) {
      log('bad frame signature from', short(link.nodeId))
      return
    }
    seenFrames.set(replayKey, t)

    if (body.kind === 'peers.request') {
      const want = typeof body.want === 'string' && /^[A-Za-z0-9_-]{43}$/.test(body.want) ? body.want : null
      let peers: Array<{ nodeId: string; publicKey: string; endpoint: string }>
      if (want) {
        // a targeted lookup: answer only for that node (from a live link first, else the address book)
        const l = links.get(want)
        const k = knownPeers.get(want)
        peers = l ? [{ nodeId: l.nodeId, publicKey: l.publicKey, endpoint: l.endpoint }] : k ? [{ nodeId: want, ...k }] : []
      } else {
        peers = [...links.values()]
          .filter((l) => l.nodeId !== link.nodeId)
          .slice(0, 64)
          .map((l) => ({ nodeId: l.nodeId, publicKey: l.publicKey, endpoint: l.endpoint }))
      }
      sendFrame(link.nodeId, { kind: 'peers.response', peers })
      return
    }
    if (body.kind === 'peers.response') {
      if (!Array.isArray(body.peers)) return
      for (const p of body.peers.slice(0, 64)) {
        // self-consistent entries only; the endpoint itself is checked when (if) we dial it
        if (!p || !isValidPublicKey(p.publicKey) || p.nodeId !== nodeIdFromPublicKey(p.publicKey)) continue
        const ep = normalizeEndpoint(p.endpoint, cfg.allowInsecure)
        if (!ep) continue
        learn(p.nodeId, p.publicKey, ep)
        const waiters = discoveryWaiters.get(p.nodeId)
        if (waiters) {
          discoveryWaiters.delete(p.nodeId)
          for (const w of waiters) w(ep)
        }
      }
      // fall through: other handlers may want to see peer exchange too
    }
    for (const h of handlers) {
      try {
        h(link, body)
      } catch (e) {
        log('frame handler error', (e as Error).message)
      }
    }
  }

  function sendFrame(nodeId: string, body: PeerFrameBody): boolean {
    const link = links.get(nodeId)
    if (!link || link.ws.readyState !== WebSocket.OPEN) return false
    const frameId = randomNonce(12)
    const ts = Date.now()
    // `to` binds the frame to this recipient — it can't be replayed to another node
    const sig = signBody(id.privateKey, SIG.peerFrame, { id: frameId, ts, to: nodeId, body })
    const wire = JSON.stringify({ t: 'frame', id: frameId, ts, body, sig } satisfies PeerMessage)
    if (Buffer.byteLength(wire) > PEER_FRAME_MAX_BYTES) return false
    // backpressure: a peer that stops reading must not grow our memory unbounded
    if (link.ws.bufferedAmount > 4 * 1024 * 1024) {
      log('peer send buffer full, dropping link', short(nodeId))
      link.ws.terminate()
      return false
    }
    link.ws.send(wire)
    return true
  }

  /** peer exchange: ask a few linked peers where `nodeId` lives (works with the registry down) */
  function discover(nodeId: string): Promise<string | null> {
    const asked = [...links.values()].filter((l) => l.nodeId !== nodeId).slice(0, DISCOVERY_FANOUT)
    if (asked.length === 0) return Promise.resolve(null)
    return new Promise((resolve) => {
      let settled = false
      const finish = (ep: string | null) => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        resolve(ep)
      }
      const timer = setTimeout(() => {
        const list = discoveryWaiters.get(nodeId)?.filter((w) => w !== finish)
        if (list?.length) discoveryWaiters.set(nodeId, list)
        else discoveryWaiters.delete(nodeId)
        finish(null)
      }, DISCOVERY_TIMEOUT_MS)
      const list = discoveryWaiters.get(nodeId) ?? []
      list.push(finish)
      discoveryWaiters.set(nodeId, list)
      for (const l of asked) sendFrame(l.nodeId, { kind: 'peers.request', want: nodeId })
    })
  }

  // ---------- maintenance ----------
  const maintain = setInterval(() => {
    for (const [endpoint, expected] of wanted) {
      const linked = [...links.values()].some((l) => l.endpoint === endpoint)
      if (!linked && (retry.get(endpoint)?.at ?? 0) <= Date.now()) void dial(endpoint, expected)
    }
    const t = Date.now()
    for (const [k, at] of seenFrames) if (t - at > PEER_FRAME_SKEW_MS * 2) seenFrames.delete(k)
  }, 5_000)

  // admission is not one-shot: a peer revoked (or gone stale) in the registry
  // after linking gets dropped. Lookups are cached ~60s, so this is cheap.
  // 'not registered' is tolerated only because it is also what an unreachable
  // registry looks like — existing links must survive a registry outage.
  const recheck = setInterval(async () => {
    if (cfg.peerPolicy !== 'registered') return
    for (const link of [...links.values()]) {
      const denied = await admit(link.nodeId, link.endpoint)
      if (denied && denied !== 'not registered') {
        log('dropping peer', short(link.nodeId), denied)
        link.ws.close(4003, 'revoked')
      }
    }
  }, 30_000)

  return {
    /** hook into the HTTP server's upgrade event; returns true if handled */
    handleUpgrade(req: IncomingMessage, socket: Duplex, head: Buffer): boolean {
      if (req.url !== '/peer') return false
      const ip = requestIp(req, cfg.trustProxy)
      const perIp = pendingByIp.get(ip) ?? 0
      if (pendingTotal >= MAX_PENDING_HANDSHAKES || perIp >= MAX_PENDING_PER_IP) {
        socket.end('HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n')
        return true
      }
      pendingTotal++
      pendingByIp.set(ip, perIp + 1)
      wss.handleUpgrade(req, socket, head, (ws) => handleInbound(ws, ip))
      return true
    },
    /** keep a persistent link to this endpoint (reconnects automatically) */
    want(endpoint: string, expectedNodeId?: string) {
      const ep = normalizeEndpoint(endpoint, cfg.allowInsecure)
      if (!ep || ep === cfg.publicUrl) {
        log('ignoring invalid peer endpoint', endpoint)
        return
      }
      wanted.set(ep, expectedNodeId)
      void dial(ep, expectedNodeId)
    },
    /** find + link a node by id: endpoint hint → registry lookup → dial → verify identity */
    /**
     * Find + link a node by id. Each source is only a hint — dial() verifies the
     * identity — so we just try them in order of cost:
     *   live link → caller's hint (invite) → address book → registry → peer exchange
     */
    async connectTo(nodeId: string, endpointHint?: string): Promise<PeerLink | null> {
      const have = links.get(nodeId)
      if (have) return have
      const tried = new Set<string>()
      const attempt = async (ep: string | null | undefined) => {
        if (!ep || tried.has(ep)) return null
        tried.add(ep)
        const l = await dial(ep, nodeId)
        // a stale/poisoned address-book entry must not be tried again
        if (!l && knownPeers.get(nodeId)?.endpoint === ep) knownPeers.delete(nodeId)
        return l
      }
      const hint = endpointHint ? normalizeEndpoint(endpointHint, cfg.allowInsecure) : null
      return (
        (await attempt(hint)) ??
        (await attempt(knownPeers.get(nodeId)?.endpoint)) ??
        (await (async () => {
          const rec = await registry.lookup(nodeId)
          return rec && rec.status === 'active' ? attempt(rec.endpoint) : null
        })()) ??
        (await attempt(await discover(nodeId)))
      )
    },
    sendFrame,
    onFrame(h: FrameHandler) {
      handlers.add(h)
      return () => handlers.delete(h)
    },
    /** link established (up=true) or lost (up=false) */
    onLink(h: LinkHandler) {
      linkHandlers.add(h)
      return () => linkHandlers.delete(h)
    },
    isLinked: (nodeId: string) => links.get(nodeId)?.ws.readyState === WebSocket.OPEN,
    links: () => [...links.values()],
    knownPeers: () => [...knownPeers.entries()].map(([nodeId, k]) => ({ nodeId, endpoint: k.endpoint })),
    close() {
      clearInterval(maintain)
      clearInterval(recheck)
      for (const l of links.values()) l.ws.close(1001, 'shutdown')
      wss.close()
    },
  }
}

export type PeerManager = ReturnType<typeof createPeerManager>
