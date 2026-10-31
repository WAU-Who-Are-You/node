// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Node identity: Ed25519 keypair persisted at {dataDir}/node-key.json (0600).
 * Losing this file = becoming a different node (new nodeId).
 */
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { generateNodeKeyPair, keyPairFromPrivateJwk, type NodeKeyPair } from './protocol/crypto'

export function loadOrCreateIdentity(dataDir: string): NodeKeyPair {
  const file = join(dataDir, 'node-key.json')
  if (existsSync(file)) {
    const { privateJwk } = JSON.parse(readFileSync(file, 'utf8')) as { privateJwk: JsonWebKey }
    return keyPairFromPrivateJwk(privateJwk)
  }
  mkdirSync(dataDir, { recursive: true })
  const kp = generateNodeKeyPair()
  writeFileSync(file, JSON.stringify({ nodeId: kp.nodeId, privateJwk: kp.privateJwk }, null, 2), { mode: 0o600 })
  chmodSync(file, 0o600)
  return kp
}
