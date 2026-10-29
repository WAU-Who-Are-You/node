/**
 * WAU node — one participant of the decentralized realtime network.
 *
 *  - client relay (socket.io /socket.io) — E2EE ciphertext only, RAM state
 *  - node identity (Ed25519, data/node-key.json)
 *  - registry: register (endpoint proven by challenge) + signed heartbeats
 *  - peer links (WebSocket /peer) with mutual signed handshake
 *
 * HTTP:
 *  GET /v1/health
 *  GET /v1/node/info                         public identity of this node
 *  GET /v1/node/challenge?nonce=&aud=        signed proof we control this endpoint
 *  GET /v1/node/peers                        currently linked peers
 */
import { createServer } from 'node:http'
import { signBody } from './protocol/crypto'
import { NETWORK_PROTOCOL_VERSION, SIG, type ChallengeResponseBody } from './protocol/network'
import { config } from './config'
import { loadOrCreateIdentity } from './identity'
import { createPeerManager } from './peer'
import { createRegistryClient } from './registry-client'
import { createRateLimiter, requestIp } from './net'
import { attachRelay } from './relay'

const log = (...a: unknown[]) => console.log('[node]', ...a)
const identity = loadOrCreateIdentity(config.dataDir)

const json = (res: import('node:http').ServerResponse, status: number, body: unknown) => {
  res.writeHead(status, { 'content-type': 'application/json', 'access-control-allow-origin': '*' })
  res.end(JSON.stringify(body))
}

const httpLimiter = createRateLimiter()

const httpServer = createServer((req, res) => {
  const url = new URL(req.url ?? '/', 'http://local')
  if (url.pathname.startsWith('/socket.io/')) return // handled by socket.io
  if (req.method !== 'GET') return json(res, 405, { ok: false, code: 'method-not-allowed' })
  // the challenge route makes us sign — cap it so it can't be used to burn CPU
  const ip = requestIp(req, config.trustProxy)
  const max = url.pathname === '/v1/node/challenge' ? 30 : 300
  if (!httpLimiter.ok(`${url.pathname === '/v1/node/challenge' ? 'ch' : 'get'}:${ip}`, max))
    return json(res, 429, { ok: false, code: 'rate-limited' })

  switch (url.pathname) {
    case '/':
    case '/v1/health':
      return json(res, 200, { ok: true, service: 'wau-node', nodeId: identity.nodeId, ts: Date.now() })
    case '/v1/node/info':
      return json(res, 200, {
        ok: true,
        nodeId: identity.nodeId,
        publicKey: identity.publicKey,
        endpoint: config.publicUrl,
        name: config.name,
        software: config.software,
        protocolVersion: NETWORK_PROTOCOL_VERSION,
        /** false = standalone relay: clients must not advertise it as a room's home */
        federation: config.federation,
        /** where clients can list other nodes (null = none configured) */
        registry: config.registryUrl || null,
      })
    case '/v1/node/challenge': {
      const nonce = url.searchParams.get('nonce') ?? ''
      const aud = url.searchParams.get('aud') ?? ''
      if (!/^[A-Za-z0-9_-]{16,64}$/.test(nonce) || aud.length === 0 || aud.length > 255)
        return json(res, 400, { ok: false, code: 'bad-request' })
      const body: ChallengeResponseBody = { nodeId: identity.nodeId, publicKey: identity.publicKey, nonce, aud, ts: Date.now() }
      return json(res, 200, { body, sig: signBody(identity.privateKey, SIG.challenge, body) })
    }
    case '/v1/node/peers':
      return json(res, 200, {
        ok: true,
        peers: peers.links().map((l) => ({ nodeId: l.nodeId, endpoint: l.endpoint, direction: l.direction, connectedAt: l.connectedAt })),
      })
    default:
      return json(res, 404, { ok: false, code: 'not-found' })
  }
})

// relay needs peers (federation), registry needs relay stats (load) — resolve lazily
let relay: ReturnType<typeof attachRelay> | null = null
const registry = createRegistryClient(config, identity, () => ({
  ...(relay?.stats() ?? { clients: 0, rooms: 0 }),
  maxClients: config.maxClients,
}))
const peers = createPeerManager(config, identity, registry)
relay = attachRelay(httpServer, config, peers, identity.nodeId)

httpServer.on('upgrade', (req, socket, head) => {
  if (config.federation && peers.handleUpgrade(req, socket, head)) return
  // anything that isn't /peer or /socket.io gets dropped
  if (!req.url?.startsWith('/socket.io/')) socket.destroy()
})
setInterval(() => httpLimiter.sweep(), 60_000).unref()
// slowloris / idle-socket hygiene for the plain HTTP side
httpServer.headersTimeout = 15_000
httpServer.requestTimeout = 30_000

peers.onFrame((from, body) => {
  if (body.kind === 'peers.response') log('peer exchange from', from.nodeId.slice(0, 10), '→', body.peers.length, 'peers')
})

httpServer.listen(config.port, async () => {
  log(`listening on :${config.port}`)
  log(`nodeId    ${identity.nodeId}`)
  log(`endpoint  ${config.publicUrl}`)
  log(`registry  ${config.registryUrl || '(none — standalone)'} · peerPolicy=${config.peerPolicy} · trustProxy=${config.trustProxy}`)
  if (config.allowInsecure)
    console.warn(
      config.federation
        ? '[node] WARNING insecure mode: http:// peers allowed (dev only)'
        : '[node] plain-http relay — put TLS (a reverse proxy) in front of it',
    )
  if (config.debug) console.warn('[node] WARNING debug.dump enabled — leaks room metadata to any client')
  if (!config.federation) {
    log('federation OFF — standalone relay (no /peer, no registry, no outbound links)')
    return
  }
  await registry.start()
  for (const p of config.staticPeers) peers.want(p)
})

const shutdown = () => {
  log('shutting down')
  registry.stop()
  peers.close()
  relay?.close()
  httpServer.close(() => process.exit(0))
  setTimeout(() => process.exit(0), 2_000).unref()
}
process.on('SIGINT', shutdown)
process.on('SIGTERM', shutdown)
