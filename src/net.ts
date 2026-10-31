// SPDX-License-Identifier: AGPL-3.0-only
import type { IncomingMessage } from 'node:http'

export type TrustProxy = 'off' | 'all' | 'loopback'

const LOOPBACK = new Set(['127.0.0.1', '::1', '::ffff:127.0.0.1'])

/**
 * Client IP for limits. X-Forwarded-For is attacker-controlled unless our own
 * reverse proxy sets it. 'all': every peer is our proxy. 'loopback': only a
 * proxy on this host is trusted (Caddy/nginx in front of the node) — direct
 * remote clients can't spoof the header. We take the LAST hop (the one our
 * proxy appended), never the first.
 */
export function ipFrom(xff: string | string[] | undefined, socketIp: string | undefined, trustProxy: TrustProxy): string {
  const header = Array.isArray(xff) ? xff.join(',') : xff
  const trusted = trustProxy === 'all' || (trustProxy === 'loopback' && !!socketIp && LOOPBACK.has(socketIp))
  if (trusted && header) {
    const hops = header.split(',').map((s) => s.trim()).filter(Boolean)
    if (hops.length) return hops[hops.length - 1]
  }
  return socketIp ?? 'unknown'
}

export const requestIp = (req: IncomingMessage, trustProxy: TrustProxy) =>
  ipFrom(req.headers['x-forwarded-for'], req.socket.remoteAddress, trustProxy)

/** bounded fixed-window limiter (key map can't grow without limit) */
export function createRateLimiter(maxKeys = 50_000) {
  const hits = new Map<string, { n: number; reset: number }>()
  return {
    ok(key: string, max: number, windowMs = 60_000): boolean {
      const t = Date.now()
      const e = hits.get(key)
      if (!e || e.reset < t) {
        if (hits.size >= maxKeys) {
          for (const [k, v] of hits) if (v.reset < t) hits.delete(k)
          if (hits.size >= maxKeys) return false
        }
        hits.set(key, { n: 1, reset: t + windowMs })
        return true
      }
      return ++e.n <= max
    },
    sweep() {
      const t = Date.now()
      for (const [k, v] of hits) if (v.reset < t) hits.delete(k)
    },
  }
}
