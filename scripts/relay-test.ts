/**
 * Client-relay checks against a running node (protocol used by the frontend).
 *   WAU_NODE=http://localhost:4101 bun run relay-test
 * Start the node with NODE_MAX_CLIENTS_PER_IP=6 to exercise the per-IP cap.
 */
import { io, type Socket } from 'socket.io-client'

const URL = process.env.WAU_NODE ?? 'http://localhost:4101'
let failed = 0
const check = (name: string, ok: boolean, detail = '') => {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? `  (${detail})` : ''}`)
  if (!ok) failed++
}
const connect = () =>
  new Promise<Socket>((resolve, reject) => {
    const s = io(URL, { transports: ['websocket'], reconnection: false })
    s.once('connect', () => resolve(s))
    s.once('connect_error', reject)
  })
const emit = (s: Socket, ev: string, d: unknown) => new Promise<{ ok: boolean; code?: string }>((r) => s.emit(ev, d, r))
/** resolves with the payload, or null if nothing arrives within `ms` */
const next = <T>(s: Socket, ev: string, ms = 1_500) =>
  new Promise<T | null>((r) => {
    const t = setTimeout(() => r(null), ms)
    s.once(ev, (d: T) => {
      clearTimeout(t)
      r(d)
    })
  })

const owner = await connect()
const guest = await connect()
const snoop = await connect()
const roomId = 'relaytest' + Date.now()
const keyA = { ecdh: 'A', ecdsa: 'A' }

check('owner creates room', (await emit(owner, 'room.create', { type: 'room.create', roomId, memberId: 'own', nickname: 'owner', identityPublicKey: keyA })).ok)
check('snoop can only observe', (await emit(snoop, 'room.subscribe', { type: 'room.subscribe', roomId })).code === 'observer')
await emit(guest, 'room.subscribe', { type: 'room.subscribe', roomId })

// full join flow
const now = Date.now()
const req = next<{ nickname: string }>(owner, 'join.request.received')
await emit(guest, 'join.request', {
  type: 'join.request', roomId, requestId: 'r1', memberId: 'g1', nickname: 'guest',
  identityPublicKey: { ecdh: 'G', ecdsa: 'G' }, ephemeralPublicKey: 'E', nonce: 'n'.repeat(16),
  createdAt: now, expiresAt: now + 60_000, signature: 'S',
})
check('owner receives join request', (await req)?.nickname === 'guest')
const q = next<{ payload: string }>(guest, 'join.challenge.received')
await emit(owner, 'join.challenge', { type: 'join.challenge', roomId, requestId: 'r1', payload: 'question?' })
check('guest receives challenge', (await q)?.payload === 'question?')
const a = next<{ payload: string }>(owner, 'join.answer.received')
await emit(guest, 'join.answer', { type: 'join.answer', roomId, requestId: 'r1', payload: 'answer', signature: 'x' })
check('owner receives answer', (await a)?.payload === 'answer')
const d = next<{ decision: string }>(guest, 'join.decision.received')
await emit(owner, 'join.decision', { type: 'join.decision', roomId, requestId: 'r1', decision: 'accept', signedPayload: 'p.s' })
check('guest accepted', (await d)?.decision === 'accept')

// member-only delivery
{
  const toOwner = next<{ ciphertext: string }>(owner, 'chat.message.received')
  const toSnoop = next(snoop, 'chat.message.received')
  const unsigned = await emit(guest, 'chat.message', { type: 'chat.message', roomId, messageId: 'm0', epoch: 1, ciphertext: 'CT' })
  check('relay refuses unsigned chat message', unsigned.ok === false && unsigned.code === 'bad-request', String(unsigned.code))
  await emit(guest, 'chat.message', { type: 'chat.message', roomId, messageId: 'm1', epoch: 1, ciphertext: 'CT', sig: 'S' })
  check('member receives ciphertext', (await toOwner)?.ciphertext === 'CT')
  check('observer does NOT receive ciphertext', (await toSnoop) === null)
}
{
  const commit = Buffer.from(JSON.stringify({ v: 1, epoch: 1, action: 'add', memberId: 'g1', nickname: 'guest' })).toString('base64url')
  const toGuest = next(guest, 'membership.commit.received')
  const toSnoop = next(snoop, 'membership.commit.received')
  await emit(owner, 'membership.commit', { type: 'membership.commit', roomId, payload: commit })
  check('member receives membership commit', (await toGuest) !== null)
  check('observer does NOT receive membership commit', (await toSnoop) === null)
}
{
  const commit = Buffer.from(JSON.stringify({ v: 1, epoch: 2, action: 'remove', memberId: 'g1' })).toString('base64url')
  const toGuest = next(guest, 'membership.commit.received')
  await emit(owner, 'membership.commit', { type: 'membership.commit', roomId, payload: commit })
  check('removed member still learns of own removal', (await toGuest) !== null)
  const after = await emit(guest, 'chat.message', { type: 'chat.message', roomId, messageId: 'm2', epoch: 2, ciphertext: 'CT2', sig: 'S' })
  check('removed member can no longer send', after.ok === false && after.code === 'forbidden', String(after.code))
}
{
  const leaked = next(snoop, 'debug.state', 800)
  snoop.emit('debug.dump')
  check('debug.dump disabled', (await leaked) === null)
}
// per-IP cap (only meaningful when node runs with NODE_MAX_CLIENTS_PER_IP=6)
if (process.env.WAU_EXPECT_IP_CAP) {
  const cap = Number(process.env.WAU_EXPECT_IP_CAP)
  const extra: Socket[] = []
  let refused = 0
  for (let i = 0; i < cap; i++) {
    try {
      extra.push(await connect())
    } catch {
      refused++
    }
  }
  check(`per-IP connection cap (${cap}) enforced`, refused > 0, `${refused} refused`)
  extra.forEach((s) => s.disconnect())
}

for (const s of [owner, guest, snoop]) s.disconnect()
console.log(failed ? `\n${failed} check(s) failed` : '\nall checks passed')
process.exit(failed ? 1 : 0)
