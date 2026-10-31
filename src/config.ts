// SPDX-License-Identifier: AGPL-3.0-only
import type { TrustProxy } from './net'
import { normalizeEndpoint } from './protocol/network'

const env = process.env

// NODE_PORT wins; PaaS hosts (Railway, Render, Fly…) inject PORT
const port = Number(env.NODE_PORT ?? env.PORT ?? 3003)
if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('NODE_PORT / PORT invalid')
const allowInsecure = env.NODE_ALLOW_INSECURE === 'true'
const publicUrl = normalizeEndpoint(env.NODE_PUBLIC_URL ?? `http://localhost:${port}`, allowInsecure)
if (!publicUrl)
  throw new Error(
    allowInsecure
      ? 'NODE_PUBLIC_URL must be a bare origin, e.g. https://node.example.com'
      : 'NODE_PUBLIC_URL must be a bare https:// origin (set NODE_ALLOW_INSECURE=true only for local dev)',
  )
const registryUrl = env.NODE_REGISTRY_URL ? normalizeEndpoint(env.NODE_REGISTRY_URL, allowInsecure) : ''
if (registryUrl === null) throw new Error('NODE_REGISTRY_URL must be a bare https:// origin')
const peerPolicy = env.NODE_PEER_POLICY ?? (registryUrl ? 'registered' : 'open')
if (peerPolicy !== 'registered' && peerPolicy !== 'open') throw new Error('NODE_PEER_POLICY must be registered|open')
if (peerPolicy === 'registered' && !registryUrl) throw new Error('NODE_PEER_POLICY=registered needs NODE_REGISTRY_URL')
const int = (v: string | undefined, def: number, min: number, max: number) => {
  const n = v === undefined ? def : Number(v)
  if (!Number.isInteger(n) || n < min || n > max) throw new Error(`config value out of range: ${v}`)
  return n
}

const trustProxyRaw = env.NODE_TRUST_PROXY ?? 'false'
const trustProxy = trustProxyRaw === 'true' ? 'all' : trustProxyRaw === 'loopback' ? 'loopback' : trustProxyRaw === 'false' ? 'off' : null
if (!trustProxy) throw new Error('NODE_TRUST_PROXY must be true|false|loopback')
const federation = (env.NODE_FEDERATION ?? 'on') === 'on'
if (!['on', 'off'].includes(env.NODE_FEDERATION ?? 'on')) throw new Error('NODE_FEDERATION must be on|off')
if (!federation && (registryUrl || env.NODE_PEERS)) throw new Error('NODE_FEDERATION=off cannot be combined with NODE_REGISTRY_URL / NODE_PEERS')

// AGPL-3.0 §13: a MODIFIED node must offer its source to the users it serves over the network
const sourceUrl = env.NODE_SOURCE_URL || null
if (sourceUrl) {
  let ok = false
  try {
    const u = new URL(sourceUrl)
    ok = (u.protocol === 'https:' || (allowInsecure && u.protocol === 'http:')) && !u.username && !u.password && sourceUrl.length <= 255
  } catch {
    ok = false
  }
  if (!ok) throw new Error('NODE_SOURCE_URL must be an https:// URL (max 255 chars)')
}

const nodeName = env.NODE_NAME || undefined
if (nodeName && !/^[\p{L}\p{N} ._-]{1,64}$/u.test(nodeName)) throw new Error('NODE_NAME: 1-64 letters, digits, space . _ -')

export const config = {
  port,
  /** public origin this node is reachable at (registered + used by peers) */
  publicUrl,
  name: nodeName,
  dataDir: env.NODE_DATA_DIR ?? './data',
  /** registry origin; empty = run standalone (static peers only) */
  registryUrl,
  /** comma-separated peer endpoints to keep linked, e.g. https://a.example,https://b.example */
  staticPeers: (env.NODE_PEERS ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean),
  /**
   * who may open an inbound peer link:
   *  registered — must be an active node in the registry (default when a registry is set)
   *  open       — any node with a valid signed handshake
   */
  peerPolicy: peerPolicy as 'registered' | 'open',
  /** allow http:// peers (dev / LAN) */
  allowInsecure,
  maxClients: int(env.NODE_MAX_CLIENTS, 5000, 1, 1_000_000),
  /** max client sockets from one IP (stops one host taking every slot) */
  maxClientsPerIp: int(env.NODE_MAX_CLIENTS_PER_IP, 20, 1, 10_000),
  maxPeers: int(env.NODE_MAX_PEERS, 256, 1, 10_000),
  /** read client IPs from X-Forwarded-For: off | all (any peer is our proxy) | loopback (proxy on this host) */
  trustProxy: trustProxy as TrustProxy,
  /** off = standalone relay: no /peer endpoint, no registry, no outbound links */
  federation,
  /** expose debug.dump to clients (dev only — leaks room metadata) */
  debug: env.NODE_DEBUG === 'true',
  /** where users can get this node's source (AGPL-3.0 §13) — required if you run a modified node */
  sourceUrl,
  software: 'wau-node/0.1.0',
}

export type NodeConfig = typeof config
