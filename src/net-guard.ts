/**
 * Refuse to dial hosts that are (or resolve to) loopback, private, link-local
 * (cloud metadata), CGNAT, multicast or reserved addresses. Used wherever a
 * URL chosen by someone else gets dialed: invite home hints and peer-exchange
 * answers (node), registration endpoint challenges (registry).
 *
 * Residual risk: DNS rebinding between this lookup and the connect's own
 * lookup. Impact is limited — the peer must still pass the signed handshake.
 */
import { lookup } from 'node:dns/promises'
import { isIP } from 'node:net'

function v4ToInt(ip: string): number {
  return ip.split('.').reduce((acc, o) => (acc << 8) + Number(o), 0) >>> 0
}
const inV4 = (ip: number, base: string, bits: number) => {
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0
  return (ip & mask) === (v4ToInt(base) & mask)
}
const V4_BLOCKED: Array<[string, number]> = [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10], // CGNAT
  ['127.0.0.0', 8],
  ['169.254.0.0', 16], // link-local / cloud metadata
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['198.51.100.0', 24],
  ['203.0.113.0', 24],
  ['224.0.0.0', 4], // multicast
  ['240.0.0.0', 4], // reserved + broadcast
]

export function isNonPublicIp(ip: string): boolean {
  const fam = isIP(ip)
  if (fam === 4) {
    const n = v4ToInt(ip)
    return V4_BLOCKED.some(([b, bits]) => inV4(n, b, bits))
  }
  if (fam === 6) {
    const a = ip.toLowerCase()
    if (a === '::' || a === '::1') return true
    const mapped = a.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/)
    if (mapped) return isNonPublicIp(mapped[1])
    const first = parseInt(a.split(':')[0] || '0', 16)
    if ((first & 0xfe00) === 0xfc00) return true // fc00::/7 ULA
    if ((first & 0xffc0) === 0xfe80) return true // fe80::/10 link-local
    if ((first & 0xff00) === 0xff00) return true // ff00::/8 multicast
    if (a.startsWith('64:ff9b:') || a.startsWith('2001:db8:')) return true
    return false
  }
  return true // not an IP at all → treat as unsafe
}

/** throws if `url`'s host is (or resolves to) a non-public address */
export async function assertPublicHost(url: string): Promise<void> {
  const host = new URL(url).hostname.replace(/^\[|\]$/g, '')
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal'))
    throw new Error('non-public host')
  const addrs = isIP(host) ? [{ address: host }] : await lookup(host, { all: true, verbatim: true })
  if (addrs.length === 0 || addrs.some((a) => isNonPublicIp(a.address))) throw new Error('non-public host')
}
