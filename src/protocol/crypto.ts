/**
 * WAU network — crypto primitives (node identity, signatures).
 * Public source of truth for the protocol; the registry imports from here.
 *
 * Node identity = Ed25519 keypair. nodeId = b64url(SHA-256(raw public key)),
 * so anyone holding a nodeId can verify a presented public key without
 * trusting whoever handed them the address (link, registry, peer).
 */
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  sign as edSign,
  verify as edVerify,
  type KeyObject,
} from 'node:crypto'

export const b64url = (buf: Buffer | Uint8Array) => Buffer.from(buf).toString('base64url')
export const fromB64url = (s: string) => Buffer.from(s, 'base64url')

export function randomNonce(bytes = 16): string {
  return b64url(randomBytes(bytes))
}

/** nodeId from a raw Ed25519 public key (b64url, 32 bytes) */
export function nodeIdFromPublicKey(publicKeyB64: string): string {
  return b64url(createHash('sha256').update(fromB64url(publicKeyB64)).digest())
}

export function isValidPublicKey(publicKeyB64: unknown): publicKeyB64 is string {
  return typeof publicKeyB64 === 'string' && /^[A-Za-z0-9_-]{43}$/.test(publicKeyB64)
}

export interface NodeKeyPair {
  nodeId: string
  publicKey: string // raw 32 bytes, b64url
  privateKey: KeyObject
  privateJwk: JsonWebKey
}

export function generateNodeKeyPair(): NodeKeyPair {
  const { privateKey } = generateKeyPairSync('ed25519')
  return keyPairFromPrivateJwk(privateKey.export({ format: 'jwk' }) as JsonWebKey)
}

export function keyPairFromPrivateJwk(jwk: JsonWebKey): NodeKeyPair {
  const privateKey = createPrivateKey({ key: jwk as never, format: 'jwk' })
  const pubJwk = createPublicKey(privateKey).export({ format: 'jwk' }) as JsonWebKey
  const publicKey = pubJwk.x!
  return { nodeId: nodeIdFromPublicKey(publicKey), publicKey, privateKey, privateJwk: jwk }
}

function publicKeyObject(publicKeyB64: string): KeyObject {
  return createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: publicKeyB64 }, format: 'jwk' })
}

/**
 * Deterministic JSON: object keys sorted recursively, so signer and verifier
 * hash byte-identical input regardless of property order on the wire.
 */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`
  const obj = value as Record<string, unknown>
  const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort()
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(',')}}`
}

/** sign `${domain}\n${canonicalJson(body)}` — the domain tag prevents cross-protocol reuse */
export function signBody(privateKey: KeyObject, domain: string, body: unknown): string {
  return b64url(edSign(null, Buffer.from(`${domain}\n${canonicalJson(body)}`), privateKey))
}

export function verifyBody(publicKeyB64: string, domain: string, body: unknown, sigB64: unknown): boolean {
  if (typeof sigB64 !== 'string' || sigB64.length > 128) return false
  try {
    return edVerify(null, Buffer.from(`${domain}\n${canonicalJson(body)}`), publicKeyObject(publicKeyB64), fromB64url(sigB64))
  } catch {
    return false
  }
}
