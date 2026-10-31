// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Registry client: register on boot (registry calls our /v1/node/challenge
 * back to prove we own the endpoint), then signed heartbeats with load.
 * Registry being down never stops the node — existing peer links keep going.
 *
 * Lookups re-verify the node's OWN signature on its registration, so the
 * registry can't forge endpoints/keys; it can only lie about status
 * (revoked/active), which is the one thing we delegate to it.
 */
import { nodeIdFromPublicKey, randomNonce, signBody, verifyBody, type NodeKeyPair } from './protocol/crypto'
import {
  NETWORK_PROTOCOL_VERSION,
  REGISTRY_HEARTBEAT_INTERVAL_MS,
  SIG,
  type HeartbeatBody,
  type NodeLoad,
  type NodeRecord,
  type RegisterBody,
} from './protocol/network'
import type { NodeConfig } from './config'

const log = (...a: unknown[]) => console.log('[registry-client]', ...a)
const CACHE_TTL_MS = 60_000
const MAX_CACHE = 2_000
const MAX_RESPONSE_BYTES = 64 * 1024
const NODE_ID_RE = /^[A-Za-z0-9_-]{43}$/
const STATUSES = new Set<NodeRecord['status']>(['active', 'stale', 'pending_approval', 'revoked'])

async function readJson(res: Response): Promise<Record<string, unknown>> {
  const len = Number(res.headers.get('content-length') ?? 0)
  if (len > MAX_RESPONSE_BYTES) throw new Error('registry response too large')
  const text = await res.text()
  if (text.length > MAX_RESPONSE_BYTES) throw new Error('registry response too large')
  return JSON.parse(text) as Record<string, unknown>
}

export function createRegistryClient(cfg: NodeConfig, id: NodeKeyPair, getLoad: () => NodeLoad) {
  let registered = false
  let timer: ReturnType<typeof setInterval> | null = null
  /** bounded lookup cache — attacker-chosen nodeIds (from hellos) can't grow it forever */
  const cache = new Map<string, { record: NodeRecord | null; at: number }>()
  const inflight = new Map<string, Promise<NodeRecord | null>>()

  async function post(path: string, payload: unknown) {
    const res = await fetch(`${cfg.registryUrl}${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(10_000),
      redirect: 'error',
    })
    return { status: res.status, data: await readJson(res).catch(() => ({}) as Record<string, unknown>) }
  }

  async function register(): Promise<boolean> {
    const body: RegisterBody = {
      v: NETWORK_PROTOCOL_VERSION,
      nodeId: id.nodeId,
      publicKey: id.publicKey,
      endpoint: cfg.publicUrl,
      name: cfg.name,
      software: cfg.software,
      aud: cfg.registryUrl,
      ts: Date.now(),
      nonce: randomNonce(),
    }
    try {
      const { status, data } = await post('/v1/nodes/register', { body, sig: signBody(id.privateKey, SIG.register, body) })
      if (status === 200) {
        registered = true
        log('registered as', (data.record as NodeRecord | undefined)?.status ?? '?')
        return true
      }
      log('register failed', status, String(data.code ?? ''), String(data.message ?? '').slice(0, 200))
    } catch (e) {
      log('registry unreachable', (e as Error).message)
    }
    return false
  }

  async function heartbeat() {
    if (!registered) {
      await register()
      return
    }
    const body: HeartbeatBody = {
      v: NETWORK_PROTOCOL_VERSION,
      nodeId: id.nodeId,
      aud: cfg.registryUrl,
      ts: Date.now(),
      nonce: randomNonce(),
      load: getLoad(),
    }
    try {
      const { status } = await post('/v1/nodes/heartbeat', { body, sig: signBody(id.privateKey, SIG.heartbeat, body) })
      if (status === 404) registered = false // registry lost us (fresh DB) → re-register next tick
    } catch {
      // registry down: keep serving, retry next tick
    }
  }

  function remember(nodeId: string, record: NodeRecord | null) {
    if (cache.size >= MAX_CACHE) {
      const t = Date.now()
      for (const [k, v] of cache) if (t - v.at > CACHE_TTL_MS) cache.delete(k)
      // still full: evict oldest insertion (Map keeps insertion order)
      while (cache.size >= MAX_CACHE) cache.delete(cache.keys().next().value!)
    }
    cache.delete(nodeId)
    cache.set(nodeId, { record, at: Date.now() })
  }

  function validRecord(r: NodeRecord, nodeId: string): boolean {
    const reg = r?.registration
    return (
      !!reg &&
      typeof reg === 'object' &&
      r.nodeId === nodeId &&
      typeof r.publicKey === 'string' &&
      nodeIdFromPublicKey(r.publicKey) === nodeId &&
      STATUSES.has(r.status) &&
      reg.body?.nodeId === nodeId &&
      reg.body.publicKey === r.publicKey &&
      reg.body.endpoint === r.endpoint &&
      verifyBody(r.publicKey, SIG.register, reg.body, reg.sig)
    )
  }

  async function fetchRecord(nodeId: string): Promise<NodeRecord | null> {
    const hit = cache.get(nodeId)
    try {
      const res = await fetch(`${cfg.registryUrl}/v1/nodes/${nodeId}`, { signal: AbortSignal.timeout(5_000), redirect: 'error' })
      if (res.status === 404) {
        remember(nodeId, null)
        return null
      }
      if (!res.ok) return hit?.record ?? null // registry trouble: keep last known answer
      const r = (await readJson(res)).record as NodeRecord
      const record = validRecord(r, nodeId) ? r : null
      if (!record) log('registry returned a record that fails self-signature check', nodeId.slice(0, 10))
      remember(nodeId, record)
      return record
    } catch {
      return hit?.record ?? null
    }
  }

  async function lookup(nodeId: string): Promise<NodeRecord | null> {
    if (!cfg.registryUrl || !NODE_ID_RE.test(nodeId)) return null
    const hit = cache.get(nodeId)
    if (hit && Date.now() - hit.at < CACHE_TTL_MS) return hit.record
    // collapse concurrent lookups for the same id into one request
    const pending = inflight.get(nodeId)
    if (pending) return pending
    const p = fetchRecord(nodeId).finally(() => inflight.delete(nodeId))
    inflight.set(nodeId, p)
    return p
  }

  return {
    enabled: !!cfg.registryUrl,
    async start() {
      if (!cfg.registryUrl) return
      await register()
      timer = setInterval(heartbeat, REGISTRY_HEARTBEAT_INTERVAL_MS)
    },
    stop() {
      if (timer) clearInterval(timer)
    },
    lookup,
  }
}

export type RegistryClient = ReturnType<typeof createRegistryClient>
