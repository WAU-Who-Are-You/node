// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Node discovery: how an entry node finds a room's home by nodeId.
 *   S1  stale endpoint in the invite → registry lookup (self-signed record) → routed
 *   S2  registered peer policy + registry DOWN → new links fail closed
 *   S3  no registry at all → peer exchange (ask a linked peer) → routed
 *   S4  a peer answers with a WRONG endpoint → the dial fails identity check, nothing routed elsewhere
 * Spawns its own registry + nodes on :4000 / :42xx.   bun run discovery-test
 */
import { spawn, type ChildProcess } from 'node:child_process'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { io, type Socket } from 'socket.io-client'

const ROOT = resolve(import.meta.dir, '..')
const REGISTRY_DIR = resolve(ROOT, '../registry')
const TMP = mkdtempSync(join(tmpdir(), 'wau-disc-'))
const procs: ChildProcess[] = []
let failed = 0
const check = (name: string, ok: boolean, detail = '') => {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? `  (${detail})` : ''}`)
  if (!ok) failed++
}
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

async function waitHealth(url: string) {
  for (let i = 0; i < 80; i++) {
    try {
      if ((await fetch(`${url}/v1/health`)).ok) return
    } catch {
      /* booting */
    }
    await sleep(250)
  }
  throw new Error(`${url} did not start`)
}
function run(cwd: string, env: Record<string, string>): ChildProcess {
  const p = spawn('bun', ['src/index.ts'], { cwd, env: { ...process.env, ...env }, stdio: 'ignore' })
  procs.push(p)
  return p
}
async function startRegistry(port: number) {
  const p = run(REGISTRY_DIR, {
    REGISTRY_PORT: String(port),
    REGISTRY_PUBLIC_URL: `http://localhost:${port}`,
    REGISTRY_DB: join(TMP, `reg-${port}.sqlite`),
    REGISTRY_ALLOW_INSECURE: 'true',
  })
  await waitHealth(`http://localhost:${port}`)
  return p
}
async function startNode(port: number, extra: Record<string, string> = {}) {
  const p = run(ROOT, {
    NODE_PORT: String(port),
    NODE_PUBLIC_URL: `http://localhost:${port}`,
    NODE_ALLOW_INSECURE: 'true',
    NODE_DATA_DIR: join(TMP, `n${port}`),
    ...extra,
  })
  const url = `http://localhost:${port}`
  await waitHealth(url)
  const info = (await (await fetch(`${url}/v1/node/info`)).json()) as { nodeId: string }
  return { p, url, nodeId: info.nodeId }
}
const connect = (url: string) =>
  new Promise<Socket>((res, rej) => {
    const s = io(url, { transports: ['websocket'], reconnection: false })
    s.once('connect', () => res(s))
    s.once('connect_error', rej)
  })
const emit = (s: Socket, ev: string, d: unknown) =>
  new Promise<{ ok: boolean; code?: string }>((r) => s.emit(ev, d, (a: { ok: boolean; code?: string }) => r(a)))

/** a room living on `home`, observed from a client attached to `entry` with a given home hint */
async function observeVia(home: { url: string; nodeId: string }, entryUrl: string, hintEndpoint: string) {
  const owner = await connect(home.url)
  const roomId = 'disc' + Math.random().toString(36).slice(2, 12)
  const created = await emit(owner, 'room.create', {
    type: 'room.create',
    roomId,
    memberId: 'own',
    nickname: 'o',
    identityPublicKey: { ecdh: 'A', ecdsa: 'A' },
  })
  const viewer = await connect(entryUrl)
  const ack = await emit(viewer, 'room.subscribe', {
    type: 'room.subscribe',
    roomId,
    home: { nodeId: home.nodeId, endpoint: hintEndpoint },
  })
  owner.disconnect()
  viewer.disconnect()
  return { created: created.ok, ack }
}

try {
  // ---------- S1: registry lookup heals a stale invite endpoint ----------
  const registry = await startRegistry(4000)
  const reg = { NODE_REGISTRY_URL: 'http://localhost:4000' }
  const A = await startNode(4201, reg)
  const B = await startNode(4202, reg)
  await sleep(1500) // both registered
  const s1 = await observeVia(A, B.url, 'http://localhost:4299')
  check('S1 stale invite endpoint → registry lookup → routed to the home', s1.created && s1.ack.ok && s1.ack.code === 'observer', JSON.stringify(s1.ack))

  // ---------- S2: registered policy fails closed without the registry ----------
  const C = await startNode(4203, reg)
  await sleep(1500)
  registry.kill()
  await sleep(500)
  // C has never linked to A and can't ask the registry → refuse (no unvetted links)
  const s2 = await observeVia(A, C.url, A.url)
  check('S2 registered policy + registry down → new link refused', !s2.ack.ok && s2.ack.code === 'home-unreachable', JSON.stringify(s2.ack))

  // ---------- S3: peer exchange, no registry anywhere ----------
  const D = await startNode(4211)
  const E = await startNode(4212, { NODE_PEERS: D.url })
  const F = await startNode(4213, { NODE_PEERS: E.url })
  await sleep(2500) // F↔E, E↔D linked; F knows nothing about D
  const fBefore = (await (await fetch(`${F.url}/v1/node/peers`)).json()) as { peers: Array<{ nodeId: string }> }
  check('S3 setup: F is not linked to D', !fBefore.peers.some((p) => p.nodeId === D.nodeId))
  const s3 = await observeVia(D, F.url, 'http://localhost:4299')
  check('S3 no registry: F asks E where D is → links D → routed', s3.ack.ok && s3.ack.code === 'observer', JSON.stringify(s3.ack))
  const fAfter = (await (await fetch(`${F.url}/v1/node/peers`)).json()) as { peers: Array<{ nodeId: string }> }
  check('S3 F now holds a verified link to D', fAfter.peers.some((p) => p.nodeId === D.nodeId))

  // ---------- S4: a wrong answer can only fail ----------
  // G knows only E. Ask G for a node id nobody has: every source is empty/wrong → clean failure,
  // and a hint pointing at a DIFFERENT real node (E) is rejected by the identity check.
  const G = await startNode(4214, { NODE_PEERS: E.url })
  await sleep(2000)
  const ghost = { url: D.url, nodeId: 'X'.repeat(43) }
  const viewer = await connect(G.url)
  const s4 = await emit(viewer, 'room.subscribe', { type: 'room.subscribe', roomId: 'ghostroom1', home: { nodeId: ghost.nodeId, endpoint: E.url } })
  viewer.disconnect()
  check('S4 hint points at the wrong node → identity check fails → home-unreachable', !s4.ok && s4.code === 'home-unreachable', JSON.stringify(s4))
  const gPeers = (await (await fetch(`${G.url}/v1/node/peers`)).json()) as { peers: Array<{ nodeId: string }> }
  check('S4 no link was created to the impostor id', !gPeers.peers.some((p) => p.nodeId === ghost.nodeId))
} finally {
  for (const p of procs) p.kill()
  await sleep(300)
  rmSync(TMP, { recursive: true, force: true })
}
console.log(failed ? `\n${failed} check(s) failed` : '\nall checks passed')
process.exit(failed ? 1 : 0)
