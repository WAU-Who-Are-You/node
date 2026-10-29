/**
 * WAU node — client relay (ported from source/mini-services/relay-service)
 *
 * Ephemeral in-memory state ONLY:
 *  - presence per room (connection-based, TTL + heartbeat)
 *  - pending join requests (TTL, rate limited, cooldown on reject)
 *  - runtime membership set used to authorize relay
 *
 * The server never sees plaintext chat, never persists messages,
 * never holds room keys. Restart wipes all state.
 *
 * Sessions: a "session" is either a local socket.io client or a REMOTE client
 * of another node (entry node) using a room homed here. Both run through the
 * same handlers (bindSession) — authorization, rate limits and presence don't
 * care where the client is attached. See federation section at the bottom.
 *
 * Security controls implemented here:
 *  - ECDSA proof-of-possession on member subscribe (roomId|memberId|socketId)
 *  - join request TTL + nonce + per-socket rate limit + reject cooldown
 *  - challenge TTL; only runtime members may challenge/approve/commit/relay
 *  - membership.commit 'remove' demotes the removed member's connections
 *  - key.wrapped routed per target memberId (only target can unwrap)
 *  - payload size caps + message rate limiting
 */
import type { Server as HttpServer } from 'node:http'
import { Server, Socket } from 'socket.io'
import {
  ClientEvent,
  IdentityPublicKeyBundle,
  MembershipCommitPayload,
  CHALLENGE_TTL_MS,
  JOIN_REQUEST_TTL_MS,
  MAX_CIPHERTEXT_CHARS,
  MAX_MEMBERS_PER_ROOM,
  MAX_MESSAGES_PER_WINDOW,
  MAX_NICKNAME_LENGTH,
  MAX_PAYLOAD_B64_CHARS,
  MAX_PENDING_REQUESTS_PER_ROOM,
  MESSAGE_RATE_WINDOW_MS,
  MAX_JOIN_REQUESTS_PER_WINDOW,
  PRESENCE_SWEEP_INTERVAL_MS,
  RATE_WINDOW_MS,
  REJECT_COOLDOWN_MS,
  FILE_RATE_WINDOW_MS,
  MAX_FILE_CHUNKS,
  MAX_FILE_CHUNK_B64,
  MAX_FILE_CHUNKS_PER_WINDOW,
  MAX_FILE_NAME_CHARS,
} from './protocol/client'
import type { NodeConfig } from './config'
import { ipFrom } from './net'
import type { PeerManager } from './peer'
import { randomNonce } from './protocol/crypto'
import { normalizeEndpoint } from './protocol/network'

type Ack = (res: { ok: boolean; code?: string; message?: string }) => void

// ---------- runtime state ----------
interface MemberRuntime {
  memberId: string
  nickname: string
  identityPublicKey: IdentityPublicKeyBundle
  approvedBy: string
  joinedAt: number
}

interface PendingRequest {
  roomId: string
  requestId: string
  memberId: string
  nickname: string
  identityPublicKey: IdentityPublicKeyBundle
  ephemeralPublicKey: string
  nonce: string
  createdAt: number
  expiresAt: number
  signature: string
  pwdProof?: string
  fromSocketId: string
  challengePayload?: string
  challengeAt?: number
}

interface SubEntry {
  role: 'observer' | 'member'
  memberId?: string
  lastHeartbeat: number
}

interface RoomRuntime {
  roomId: string
  creatorMemberId: string
  /** b64url(SHA-256(`${roomId}|${secret}`)) committed at creation — lets the
   *  relay verify secret possession later WITHOUT ever knowing the secret. */
  secretHash?: string
  members: Map<string, MemberRuntime>
  requests: Map<string, PendingRequest>
  /** reject cooldown keyed by requester ECDSA public key */
  lastRejectedAt: Map<string, number>
}

const rooms = new Map<string, RoomRuntime>()
/** socketId -> roomId -> subscription */
const sockets = new Map<string, Map<string, SubEntry>>()
const joinRate = new Map<string, number[]>()
const chatRate = new Map<string, number[]>()
const fileRate = new Map<string, number[]>()
/** fileId → session that streamed it (routes delivery acks). Bounded + TTL — routing metadata only. */
const fileSenders = new Map<string, { sid: string; at: number }>()
const MAX_TRACKED_FILES = 20_000
const FILE_SENDER_TTL_MS = 30 * 60_000
function rememberFileSender(fileId: string, sid: string) {
  fileSenders.delete(fileId)
  if (fileSenders.size >= MAX_TRACKED_FILES) fileSenders.delete(fileSenders.keys().next().value!)
  fileSenders.set(fileId, { sid, at: now() })
}

const now = () => Date.now()
const log = (...a: unknown[]) => console.log('[relay]', ...a)

/** constant-time-ish string compare for secret-hash equality */
function timingSafeEq(a: string, b: string): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i)
  return diff === 0
}

function onlineMemberCount(room: RoomRuntime): number {
  let count = 0
  for (const [socketId, subs] of sockets) {
    const sub = subs.get(room.roomId)
    // presence truth = a live socket.io connection (engine.io ping/pong), NOT
    // client heartbeats — browsers throttle background tabs (mobile!), so
    // heartbeat staleness must never demote an online member
    if (sub && sub.role === 'member' && sessions.get(socketId)?.alive()) count++
  }
  return count
}

/**
 * Deliver to MEMBER subscriptions only. Observers (anyone who knows a roomId)
 * must not receive ciphertext or membership commits — commits carry member
 * nicknames + identity keys, and ciphertext leaks timing/size metadata.
 */
function emitToMembers(roomId: string, event: string, payload: unknown, opts: { except?: string; alsoSockets?: string[] } = {}) {
  const targets = new Set(opts.alsoSockets ?? [])
  for (const [socketId, subs] of sockets) {
    if (subs.get(roomId)?.role === 'member') targets.add(socketId)
  }
  if (opts.except) targets.delete(opts.except)
  deliverMany(targets, roomId, event, payload)
}

/** presence goes to every subscriber (observers included — it's how they see a room come alive) */
function broadcastPresence(roomId: string) {
  const room = rooms.get(roomId)
  const online = room ? onlineMemberCount(room) : 0
  const status = online > 0 ? 'active' : 'inactive'
  const subscribers: string[] = []
  for (const [id, subs] of sockets) if (subs.has(roomId)) subscribers.push(id)
  deliverMany(subscribers, roomId, 'room.presence', { roomId, status, onlineCount: online })
}

function sweepExpired() {
  const t = now()
  for (const [fileId, f] of fileSenders) if (t - f.at > FILE_SENDER_TTL_MS) fileSenders.delete(fileId)
  for (const room of rooms.values()) {
    let changed = false
    for (const [reqId, req] of room.requests) {
      if (req.expiresAt <= t) {
        room.requests.delete(reqId)
        changed = true
      }
    }
    // NOTE: subscriptions are cleaned up by the socket 'disconnect' handler —
    // never by heartbeat staleness (throttled background tabs stay online)
    if (changed) broadcastPresence(room.roomId)
  }
}

async function verifySignatureB64(spkiB64: string, data: string, sigB64: string): Promise<boolean> {
  try {
    const pub = await crypto.subtle.importKey(
      'spki',
      Buffer.from(spkiB64, 'base64'),
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['verify'],
    )
    return await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      pub,
      Buffer.from(sigB64, 'base64'),
      new TextEncoder().encode(data),
    )
  } catch (e) {
    log('verify error', (e as Error).message)
    return false
  }
}

/**
 * A client of this relay. Local: socket.io socket. Remote: a client of a peer
 * node, keyed `r:<nodeId>:<sid>`; `signId` is the socket id the client itself
 * signed on its entry node (subscribe proof-of-possession).
 */
interface Session {
  id: string
  signId: string
  /** remote sessions: entry node id */
  via?: string
  alive(): boolean
}
const sessions = new Map<string, Session>()
/** per-session delivery; remote deliveries are batched per node by deliverMany */
let sendLocal: (sid: string, event: string, payload: unknown) => void = () => {}
let sendRemote: (nodeId: string, sids: string[], roomId: string, event: string, payload: unknown) => void = () => {}

const MAX_ROOMS_PER_SESSION = 200
const MAX_ROOMS_TOTAL = 50_000

function deliverMany(ids: Iterable<string>, roomId: string, event: string, payload: unknown) {
  const remote = new Map<string, string[]>()
  for (const id of ids) {
    const s = sessions.get(id)
    if (!s) continue
    if (s.via) {
      const list = remote.get(s.via) ?? []
      list.push(s.signId)
      remote.set(s.via, list)
    } else sendLocal(s.id, event, payload)
  }
  for (const [nodeId, sids] of remote) sendRemote(nodeId, sids, roomId, event, payload)
}
const deliver = (id: string, roomId: string, event: string, payload: unknown) => deliverMany([id], roomId, event, payload)

/** forget a session everywhere (socket disconnect, remote gone, peer link lost) */
function dropSession(id: string) {
  const subs = sockets.get(id)
  sockets.delete(id)
  sessions.delete(id)
  joinRate.delete(id)
  for (const k of chatRate.keys()) if (k.startsWith(`${id}:`)) chatRate.delete(k)
  for (const k of fileRate.keys()) if (k.startsWith(`${id}:`)) fileRate.delete(k)
  for (const [fileId, f] of fileSenders) if (f.sid === id) fileSenders.delete(fileId)
  if (subs) for (const roomId of subs.keys()) broadcastPresence(roomId)
}

type OnFn = (event: string, fn: (data: never, ack?: Ack) => void) => void

/**
 * All room handlers for ONE session (local socket or remote client). `on`
 * registers each handler with whatever transport carries that session.
 */
function bindSession(s: Session, on: OnFn) {
  // ---------- room lifecycle ----------
  on(
    'room.create',
    (
      data: ClientEvent & { type: 'room.create' },
      ack?: Ack,
    ) => {
      const { roomId, memberId, nickname, identityPublicKey } = data
      const secretHash = typeof data.secretHash === 'string' ? data.secretHash : undefined
      const bad = (m: string) => ack?.({ ok: false, code: 'bad-request', message: m })
      if (typeof roomId !== 'string' || roomId.length > 64) return bad('roomId không hợp lệ')
      if (typeof memberId !== 'string' || memberId.length > 64) return bad('memberId không hợp lệ')
      if (typeof nickname !== 'string' || nickname.length > MAX_NICKNAME_LENGTH) return bad('nickname không hợp lệ')
      if (
        !identityPublicKey ||
        typeof identityPublicKey.ecdh !== 'string' ||
        typeof identityPublicKey.ecdsa !== 'string'
      )
        return bad('identityPublicKey không hợp lệ')
      if (secretHash !== undefined && !/^[A-Za-z0-9_-]{40,128}$/.test(secretHash))
        return bad('secretHash không hợp lệ')

      const mySubs = sockets.get(s.id)!
      if (!mySubs.has(roomId) && mySubs.size >= MAX_ROOMS_PER_SESSION)
        return ack?.({ ok: false, code: 'too-many-rooms', message: 'Too many rooms on this connection' })
      let room = rooms.get(roomId)
      if (!room && rooms.size >= MAX_ROOMS_TOTAL) return ack?.({ ok: false, code: 'node-full', message: 'Node room capacity reached' })
      if (!room) {
        room = {
          roomId,
          creatorMemberId: memberId,
          members: new Map(),
          requests: new Map(),
          lastRejectedAt: new Map(),
        }
        if (secretHash) room.secretHash = secretHash
        rooms.set(roomId, room)
        log('room created', roomId, secretHash ? '(secret-attested)' : '(unattested)')
        room.members.set(memberId, { memberId, nickname, identityPublicKey, approvedBy: 'self', joinedAt: now() })
      } else if (room.members.has(memberId)) {
        // idempotent re-claim (owner rebuild after restart): the memberId is
        // already registered — identity keys MUST match, otherwise someone is
        // trying to hijack that member slot
        const existing = room.members.get(memberId)!
        if (existing.identityPublicKey.ecdsa !== identityPublicKey.ecdsa) {
          log('room.create identity mismatch', roomId, memberId)
          return ack?.({ ok: false, code: 'forbidden', message: 'memberId đã đăng ký với định danh khác' })
        }
      } else if (room.secretHash && secretHash && timingSafeEq(room.secretHash, secretHash)) {
        // SECRET SELF-RECOVERY: the sender proved possession of the room
        // secret (blind — hash comparison only). Grant membership without
        // requiring an online member to approve.
        room.members.set(memberId, {
          memberId,
          nickname,
          identityPublicKey,
          approvedBy: 'secret-recovery',
          joinedAt: now(),
        })
        log('secret recovery', roomId, memberId)
      } else {
        log('room.create rejected', roomId, memberId, room.secretHash ? '(hash mismatch)' : '(no hash committed)')
        return ack?.({
          ok: false,
          code: 'forbidden',
          message: room.secretHash
            ? 'Cần room secret đúng để tham gia phòng này'
            : 'Phòng không chấp nhận room.create từ thiết bị mới',
        })
      }
      const subs = sockets.get(s.id)!
      subs.set(roomId, { role: 'member', memberId, lastHeartbeat: now() })
      ack?.({ ok: true })
      log('room.create', roomId, 'by', s.id)
      broadcastPresence(roomId)
    },
  )

  on(
    'room.subscribe',
    async (
      data: ClientEvent & { type: 'room.subscribe' },
      ack?: Ack,
    ) => {
      const { roomId, memberId, identityPublicKey, signature } = data
      const bad = (m: string) => ack?.({ ok: false, code: 'bad-request', message: m })
      if (typeof roomId !== 'string' || roomId.length > 64) return bad('roomId không hợp lệ')
      const room = rooms.get(roomId)
      if (!room) {
        ack?.({ ok: false, code: 'room-not-found', message: 'Phòng chưa có runtime trên máy chủ' })
        return
      }

      let role: 'observer' | 'member' = 'observer'
      if (memberId && identityPublicKey && signature) {
        const member = room.members.get(memberId)
        if (member) {
          const okSig = await verifySignatureB64(
            member.identityPublicKey.ecdsa,
            `${roomId}|${memberId}|${s.signId}`,
            signature,
          )
          if (okSig) role = 'member'
          else log('subscribe signature rejected', roomId, memberId)
        }
      }
      const subs = sockets.get(s.id)!
      if (!subs.has(roomId) && subs.size >= MAX_ROOMS_PER_SESSION)
        return ack?.({ ok: false, code: 'too-many-rooms', message: 'Too many rooms on this connection' })
      // never downgrade: an existing member sub stays member even if a
      // duplicate observer subscribe arrives for the same socket
      const prev = subs.get(roomId)
      const effectiveRole: 'observer' | 'member' =
        role === 'observer' && prev?.role === 'member' ? 'member' : role
      subs.set(roomId, {
        role: effectiveRole,
        memberId: effectiveRole === 'member' ? (memberId ?? prev?.memberId) : undefined,
        lastHeartbeat: now(),
      })
      ack?.({ ok: true, code: effectiveRole })
      log('subscribe', roomId, role, memberId ?? '-')
      broadcastPresence(roomId)
    },
  )

  on(
    'room.unsubscribe',
    (data: ClientEvent & { type: 'room.unsubscribe' }, ack?: Ack) => {
      const { roomId } = data
      if (typeof roomId === 'string') {
        log('unsubscribe', roomId, 'by', s.id)
        sockets.get(s.id)?.delete(roomId)
        broadcastPresence(roomId)
      }
      ack?.({ ok: true })
    },
  )

  on(
    'presence.heartbeat',
    (data: ClientEvent & { type: 'presence.heartbeat' }, ack?: Ack) => {
      const { roomId } = data
      if (typeof roomId === 'string') {
        const sub = sockets.get(s.id)?.get(roomId)
        if (sub) {
          if (now() - sub.lastHeartbeat > 20_000) log('heartbeat', roomId, 'role=' + sub.role)
          sub.lastHeartbeat = now()
        } else {
          // heartbeat for an un-registered room sub — normal during the
          // subscribe race right after (re)connect; nothing to do
        }
      }
      ack?.({ ok: true })
    },
  )

  // ---------- join flow ----------
  on(
    'join.request',
    (data: ClientEvent & { type: 'join.request' }, ack?: Ack) => {
      const room = rooms.get(data.roomId)
      if (!room) {
        ack?.({ ok: false, code: 'room-not-found', message: 'Phòng chưa hoạt động' })
        return
      }
      const bad = (m: string) => ack?.({ ok: false, code: 'bad-request', message: m })
      if (typeof data.requestId !== 'string' || data.requestId.length > 64) return bad('requestId không hợp lệ')
      if (typeof data.memberId !== 'string' || data.memberId.length > 64) return bad('memberId không hợp lệ')
      if (typeof data.nickname !== 'string' || data.nickname.length > MAX_NICKNAME_LENGTH) return bad('nickname không hợp lệ')
      if (
        !data.identityPublicKey ||
        typeof data.identityPublicKey.ecdh !== 'string' ||
        typeof data.identityPublicKey.ecdsa !== 'string'
      )
        return bad('identityPublicKey không hợp lệ')
      if (typeof data.ephemeralPublicKey !== 'string' || data.ephemeralPublicKey.length > MAX_PAYLOAD_B64_CHARS)
        return bad('ephemeralPublicKey không hợp lệ')
      if (typeof data.nonce !== 'string' || data.nonce.length > 128) return bad('nonce không hợp lệ')
      if (typeof data.signature !== 'string' || data.signature.length > MAX_PAYLOAD_B64_CHARS)
        return bad('signature không hợp lệ')
      if (data.pwdProof !== undefined && (typeof data.pwdProof !== 'string' || data.pwdProof.length > 256))
        return bad('pwdProof không hợp lệ')
      if (!Number.isFinite(data.createdAt) || !Number.isFinite(data.expiresAt)) return bad('thời gian không hợp lệ')
      if (data.expiresAt < now() || data.expiresAt - data.createdAt > JOIN_REQUEST_TTL_MS) {
        ack?.({ ok: false, code: 'expired', message: 'Yêu cầu đã hết hạn' })
        return
      }
      if (room.members.has(data.memberId)) {
        ack?.({ ok: false, code: 'already-member', message: 'Thiết bị này đã là thành viên' })
        return
      }
      if (room.members.size >= MAX_MEMBERS_PER_ROOM) {
        ack?.({ ok: false, code: 'room-full', message: 'Phòng đã đầy' })
        return
      }
      if (room.requests.size >= MAX_PENDING_REQUESTS_PER_ROOM) {
        ack?.({ ok: false, code: 'too-many-requests', message: 'Quá nhiều yêu cầu đang chờ' })
        return
      }

      const t = now()
      const arr = (joinRate.get(s.id) ?? []).filter((ts) => ts > t - RATE_WINDOW_MS)
      if (arr.length >= MAX_JOIN_REQUESTS_PER_WINDOW) {
        ack?.({ ok: false, code: 'rate-limited', message: 'Bạn gửi yêu cầu quá nhiều, thử lại sau' })
        return
      }
      arr.push(t)
      joinRate.set(s.id, arr)

      const idKey = data.identityPublicKey.ecdsa
      const rejectedAt = room.lastRejectedAt.get(idKey)
      if (rejectedAt && t - rejectedAt < REJECT_COOLDOWN_MS) {
        ack?.({ ok: false, code: 'cooldown', message: 'Yêu cầu bị từ chối gần đây, vui lòng chờ rồi thử lại' })
        return
      }

      room.requests.set(data.requestId, {
        roomId: data.roomId,
        requestId: data.requestId,
        memberId: data.memberId,
        nickname: data.nickname,
        identityPublicKey: data.identityPublicKey,
        ephemeralPublicKey: data.ephemeralPublicKey,
        nonce: data.nonce,
        createdAt: data.createdAt,
        expiresAt: data.expiresAt,
        signature: data.signature,
        pwdProof: typeof data.pwdProof === 'string' ? data.pwdProof : undefined,
        fromSocketId: s.id,
      })
      log('join.request', data.roomId, data.requestId)
      ack?.({ ok: true })
      for (const [socketId, subs] of sockets) {
        if (socketId === s.id) continue
        if (subs.get(data.roomId)?.role === 'member') {
          deliver(socketId, data.roomId, 'join.request.received', {
            roomId: data.roomId,
            requestId: data.requestId,
            memberId: data.memberId,
            nickname: data.nickname,
            identityPublicKey: data.identityPublicKey,
            ephemeralPublicKey: data.ephemeralPublicKey,
            nonce: data.nonce,
            createdAt: data.createdAt,
            expiresAt: data.expiresAt,
            // forwarded so approvers can verify the request themselves
            signature: data.signature,
            pwdProof: typeof data.pwdProof === 'string' ? data.pwdProof : undefined,
          })
        }
      }
    },
  )

  on(
    'join.challenge',
    (data: ClientEvent & { type: 'join.challenge' }, ack?: Ack) => {
      const room = rooms.get(data.roomId)
      if (!room) {
        ack?.({ ok: false, code: 'room-not-found', message: 'Phòng không tồn tại' })
        return
      }
      const sub = sockets.get(s.id)?.get(data.roomId)
      if (!sub || sub.role !== 'member') {
        ack?.({ ok: false, code: 'forbidden', message: 'Chỉ thành viên mới được duyệt' })
        return
      }
      const req = room.requests.get(data.requestId)
      if (!req) {
        ack?.({ ok: false, code: 'not-found', message: 'Yêu cầu không tồn tại hoặc đã hết hạn' })
        return
      }
      // signed blob: question (≤512 chars) + owner key + signature
      if (typeof data.payload !== 'string' || data.payload.length === 0 || data.payload.length > 4096) {
        ack?.({ ok: false, code: 'bad-request', message: 'payload không hợp lệ' })
        return
      }
      req.challengePayload = data.payload
      req.challengeAt = now()
      ack?.({ ok: true })
      deliver(req.fromSocketId, data.roomId, 'join.challenge.received', { requestId: data.requestId, payload: data.payload })
    },
  )

  on(
    'join.answer',
    (data: ClientEvent & { type: 'join.answer' }, ack?: Ack) => {
      const room = rooms.get(data.roomId)
      if (!room) {
        ack?.({ ok: false, code: 'room-not-found', message: 'Phòng không tồn tại' })
        return
      }
      const req = room.requests.get(data.requestId)
      if (!req || req.fromSocketId !== s.id) {
        ack?.({ ok: false, code: 'not-found', message: 'Yêu cầu không tồn tại' })
        return
      }
      if (!req.challengePayload || now() - (req.challengeAt ?? 0) > CHALLENGE_TTL_MS) {
        ack?.({ ok: false, code: 'challenge-expired', message: 'Câu hỏi thử thách đã hết hạn' })
        return
      }
      if (typeof data.payload !== 'string' || data.payload.length === 0 || data.payload.length > 512)
        return
      if (typeof data.signature !== 'string' || data.signature.length > MAX_PAYLOAD_B64_CHARS) return
      ack?.({ ok: true })
      for (const [socketId, subs] of sockets) {
        if (socketId === s.id) continue
        if (subs.get(data.roomId)?.role === 'member') {
          deliver(socketId, data.roomId, 'join.answer.received', {
            requestId: data.requestId,
            payload: data.payload,
            signature: data.signature,
          })
        }
      }
    },
  )

  on(
    'join.decision',
    (data: ClientEvent & { type: 'join.decision' }, ack?: Ack) => {
      const room = rooms.get(data.roomId)
      if (!room) {
        ack?.({ ok: false, code: 'room-not-found', message: 'Phòng không tồn tại' })
        return
      }
      const sub = sockets.get(s.id)?.get(data.roomId)
      if (!sub || sub.role !== 'member') {
        ack?.({ ok: false, code: 'forbidden', message: 'Chỉ thành viên mới được duyệt' })
        return
      }
      const req = room.requests.get(data.requestId)
      if (!req) {
        ack?.({ ok: false, code: 'not-found', message: 'Yêu cầu không tồn tại hoặc đã hết hạn' })
        return
      }
      if (typeof data.signedPayload !== 'string' || data.signedPayload.length > MAX_PAYLOAD_B64_CHARS) {
        ack?.({ ok: false, code: 'bad-request', message: 'payload không hợp lệ' })
        return
      }

      if (data.decision === 'reject') {
        room.requests.delete(data.requestId)
        room.lastRejectedAt.set(req.identityPublicKey.ecdsa, now())
        ack?.({ ok: true })
        deliver(req.fromSocketId, data.roomId, 'join.decision.received', {
          roomId: data.roomId,
          requestId: data.requestId,
          decision: 'reject',
          signedPayload: data.signedPayload,
        })
        return
      }

      room.requests.delete(data.requestId)
      if (!room.members.has(req.memberId)) {
        room.members.set(req.memberId, {
          memberId: req.memberId,
          nickname: req.nickname,
          identityPublicKey: req.identityPublicKey,
          approvedBy: sub.memberId ?? 'runtime-approver',
          joinedAt: now(),
        })
      }
      const requesterSubs = sockets.get(req.fromSocketId)
      if (requesterSubs) {
        requesterSubs.set(data.roomId, { role: 'member', memberId: req.memberId, lastHeartbeat: now() })
      }
      ack?.({ ok: true })
      deliver(req.fromSocketId, data.roomId, 'join.decision.received', {
        roomId: data.roomId,
        requestId: data.requestId,
        decision: 'accept',
        signedPayload: data.signedPayload,
      })
      broadcastPresence(data.roomId)
      log('join accepted', data.roomId, req.memberId)
    },
  )

  // ---------- membership & key distribution ----------
  on(
    'membership.commit',
    (data: ClientEvent & { type: 'membership.commit' }, ack?: Ack) => {
      const room = rooms.get(data.roomId)
      if (!room) {
        ack?.({ ok: false, code: 'room-not-found', message: 'Phòng không tồn tại' })
        return
      }
      const sub = sockets.get(s.id)?.get(data.roomId)
      if (!sub || sub.role !== 'member') {
        ack?.({ ok: false, code: 'forbidden', message: 'Chỉ thành viên mới được commit membership' })
        return
      }
      if (typeof data.payload !== 'string' || data.payload.length > MAX_PAYLOAD_B64_CHARS) {
        ack?.({ ok: false, code: 'bad-request', message: 'payload không hợp lệ' })
        return
      }
      // the removed member must still hear about their own removal
      const removedSockets: string[] = []
      try {
        // `${b64url(body)}.${sig}` — the relay only peeks at the body; clients verify the signature
        const commit = JSON.parse(Buffer.from(data.payload.split('.')[0], 'base64url').toString('utf8')) as MembershipCommitPayload
        if (commit.action === 'remove' && room.members.has(commit.memberId)) {
          room.members.delete(commit.memberId)
          // demote all connections of the removed member
          for (const [sid, subs] of sockets) {
            const victim = subs.get(data.roomId)
            if (victim && victim.memberId === commit.memberId) {
              victim.role = 'observer'
              victim.memberId = undefined
              removedSockets.push(sid)
            }
          }
          log('member removed', data.roomId, commit.memberId)
        }
      } catch {
        // opaque payload; relay does not need to understand it
      }
      ack?.({ ok: true })
      emitToMembers(
        data.roomId,
        'membership.commit.received',
        { roomId: data.roomId, payload: data.payload },
        { except: s.id, alsoSockets: removedSockets },
      )
    },
  )

  on(
    'key.wrapped',
    (data: ClientEvent & { type: 'key.wrapped' }, ack?: Ack) => {
      const room = rooms.get(data.roomId)
      if (!room) {
        ack?.({ ok: false, code: 'room-not-found', message: 'Phòng không tồn tại' })
        return
      }
      const sub = sockets.get(s.id)?.get(data.roomId)
      if (!sub || sub.role !== 'member') {
        ack?.({ ok: false, code: 'forbidden', message: 'Chỉ thành viên mới được phân phối khóa' })
        return
      }
      if (typeof data.targetMemberId !== 'string' || data.targetMemberId.length > 64) {
        ack?.({ ok: false, code: 'bad-request', message: 'target không hợp lệ' })
        return
      }
      if (!Number.isFinite(data.epoch)) {
        ack?.({ ok: false, code: 'bad-request', message: 'epoch không hợp lệ' })
        return
      }
      if (typeof data.wrappedKey !== 'string' || data.wrappedKey.length > MAX_PAYLOAD_B64_CHARS) {
        ack?.({ ok: false, code: 'bad-request', message: 'wrappedKey không hợp lệ' })
        return
      }
      // route only to the target member's connections (only they can unwrap)
      let delivered = 0
      for (const [socketId, subs] of sockets) {
        if (socketId === s.id) continue
        const target = subs.get(data.roomId)
        if (target && target.role === 'member' && target.memberId === data.targetMemberId) {
          deliver(socketId, data.roomId, 'key.delivered', { roomId: data.roomId, epoch: data.epoch, wrappedKey: data.wrappedKey })
          delivered++
        }
      }
      ack?.({ ok: true, message: delivered > 0 ? 'delivered' : 'target-offline' })
    },
  )

  // ---------- chat relay ----------
  on(
    'chat.message',
    (data: ClientEvent & { type: 'chat.message' }, ack?: Ack) => {
      const room = rooms.get(data.roomId)
      if (!room) {
        ack?.({ ok: false, code: 'room-not-found', message: 'Phòng không tồn tại' })
        return
      }
      const sub = sockets.get(s.id)?.get(data.roomId)
      if (!sub || sub.role !== 'member') {
        ack?.({ ok: false, code: 'forbidden', message: 'Chỉ thành viên đã xác thực mới được nhắn tin' })
        return
      }
      if (typeof data.messageId !== 'string' || data.messageId.length > 64) {
        ack?.({ ok: false, code: 'bad-request', message: 'messageId không hợp lệ' })
        return
      }
      if (!Number.isFinite(data.epoch)) {
        ack?.({ ok: false, code: 'bad-request', message: 'epoch không hợp lệ' })
        return
      }
      if (typeof data.ciphertext !== 'string' || data.ciphertext.length === 0 || data.ciphertext.length > MAX_CIPHERTEXT_CHARS) {
        ack?.({ ok: false, code: 'bad-request', message: 'Tin nhắn vượt giới hạn kích thước' })
        return
      }
      if (typeof data.sig !== 'string' || data.sig.length === 0 || data.sig.length > 256) {
        ack?.({ ok: false, code: 'bad-request', message: 'Thiếu chữ ký tin nhắn' })
        return
      }

      const key = `${s.id}:${data.roomId}`
      const t = now()
      const arr = (chatRate.get(key) ?? []).filter((ts) => ts > t - MESSAGE_RATE_WINDOW_MS)
      if (arr.length >= MAX_MESSAGES_PER_WINDOW) {
        ack?.({ ok: false, code: 'rate-limited', message: 'Bạn gửi tin quá nhanh' })
        return
      }
      arr.push(t)
      chatRate.set(key, arr)

      ack?.({ ok: true })
      emitToMembers(
        data.roomId,
        'chat.message.received',
        {
          roomId: data.roomId,
          messageId: data.messageId,
          epoch: data.epoch,
          ciphertext: data.ciphertext,
          sig: data.sig,
          senderMemberId: sub.memberId ?? 'unknown',
        },
        { except: s.id },
      )
    },
  )
  // ---------- E2EE file transfer + P2P signaling (blind routing) ----------
  // Chunks are b64(IV ‖ AES-GCM(per-file key)); the per-file key only travels
  // inside the signed, E2EE chat descriptor. rtc.sig / room.meta payloads are
  // AES-GCM(room key). Everything here is member-only — observers (anyone who
  // knows a roomId) must not learn that files or peers exist.
  const memberSub = (roomId: unknown, ack?: Ack) => {
    if (typeof roomId !== 'string' || roomId.length > 64 || !rooms.has(roomId)) {
      ack?.({ ok: false, code: 'room-not-found', message: 'Room not found' })
      return null
    }
    const sub = sockets.get(s.id)?.get(roomId)
    if (!sub || sub.role !== 'member' || !sub.memberId) {
      ack?.({ ok: false, code: 'forbidden', message: 'Members only' })
      return null
    }
    return sub
  }
  const validId = (v: unknown, max = 64): v is string => typeof v === 'string' && v.length > 0 && v.length <= max
  /** sessions of one member in a room (excluding the caller) */
  const sessionsOfMember = (roomId: string, memberId: string) => {
    const out: string[] = []
    for (const [sid, subs] of sockets) {
      if (sid === s.id) continue
      const t = subs.get(roomId)
      if (t && t.role === 'member' && t.memberId === memberId) out.push(sid)
    }
    return out
  }

  on('file.chunk', (data: ClientEvent & { type: 'file.chunk' }, ack?: Ack) => {
    const sub = memberSub(data.roomId, ack)
    if (!sub) return
    if (!validId(data.fileId, MAX_FILE_NAME_CHARS)) return ack?.({ ok: false, code: 'bad-request', message: 'fileId invalid' })
    if (
      !Number.isInteger(data.idx) ||
      !Number.isInteger(data.total) ||
      data.total < 1 ||
      data.total > MAX_FILE_CHUNKS ||
      data.idx < 0 ||
      data.idx >= data.total
    )
      return ack?.({ ok: false, code: 'bad-request', message: 'chunk index invalid' })
    if (typeof data.data !== 'string' || data.data.length === 0 || data.data.length > MAX_FILE_CHUNK_B64)
      return ack?.({ ok: false, code: 'bad-request', message: 'chunk too large' })
    if (data.targetMemberId !== undefined && !validId(data.targetMemberId))
      return ack?.({ ok: false, code: 'bad-request', message: 'target invalid' })

    const key = `${s.id}:${data.roomId}`
    const t = now()
    const arr = (fileRate.get(key) ?? []).filter((ts) => ts > t - FILE_RATE_WINDOW_MS)
    if (arr.length >= MAX_FILE_CHUNKS_PER_WINDOW) return ack?.({ ok: false, code: 'rate-limited', message: 'Sending files too fast' })
    arr.push(t)
    fileRate.set(key, arr)
    rememberFileSender(data.fileId, s.id)

    ack?.({ ok: true })
    const chunk = {
      roomId: data.roomId,
      fileId: data.fileId,
      idx: data.idx,
      total: data.total,
      data: data.data,
      senderMemberId: sub.memberId,
    }
    if (data.targetMemberId) deliverMany(sessionsOfMember(data.roomId, data.targetMemberId), data.roomId, 'file.chunk.received', chunk)
    else emitToMembers(data.roomId, 'file.chunk.received', chunk, { except: s.id })
  })

  on('file.ack', (data: ClientEvent & { type: 'file.ack' }, ack?: Ack) => {
    const sub = memberSub(data.roomId, ack)
    if (!sub) return
    if (!validId(data.fileId, MAX_FILE_NAME_CHARS)) return ack?.({ ok: false, code: 'bad-request', message: 'fileId invalid' })
    if (data.senderMemberId !== undefined && !validId(data.senderMemberId))
      return ack?.({ ok: false, code: 'bad-request', message: 'sender invalid' })
    // the session that streamed chunks; else route by the original sender's memberId
    // (pure P2P transfer — no chunk ever crossed the relay)
    const streamed = fileSenders.get(data.fileId)?.sid
    const targets =
      streamed && streamed !== s.id && sessions.get(streamed)?.alive()
        ? [streamed]
        : data.senderMemberId
          ? sessionsOfMember(data.roomId, data.senderMemberId).slice(0, 1)
          : []
    ack?.(targets.length ? { ok: true } : { ok: false, code: 'no-sender' })
    // the acking member is who the relay authenticated, not what the payload claims
    deliverMany(targets, data.roomId, 'file.ack.received', { roomId: data.roomId, fileId: data.fileId, memberId: sub.memberId })
  })

  on('file.pull', (data: ClientEvent & { type: 'file.pull' }, ack?: Ack) => {
    const sub = memberSub(data.roomId, ack)
    if (!sub) return
    if (!validId(data.fileId, MAX_FILE_NAME_CHARS)) return ack?.({ ok: false, code: 'bad-request', message: 'fileId invalid' })
    if (!validId(data.senderMemberId)) return ack?.({ ok: false, code: 'bad-request', message: 'sender invalid' })
    const key = `${s.id}:${data.roomId}`
    const t = now()
    const arr = (chatRate.get(key) ?? []).filter((ts) => ts > t - MESSAGE_RATE_WINDOW_MS)
    if (arr.length >= MAX_MESSAGES_PER_WINDOW) return ack?.({ ok: false, code: 'rate-limited', message: 'Too fast' })
    arr.push(t)
    chatRate.set(key, arr)
    const targets = sessionsOfMember(data.roomId, data.senderMemberId)
    // the puller is the authenticated member — a client can't pull "as" someone else
    deliverMany(targets, data.roomId, 'file.pull.received', { roomId: data.roomId, fileId: data.fileId, memberId: sub.memberId })
    ack?.({ ok: true, message: targets.length ? 'routed' : 'sender-offline' })
  })

  on('rtc.sig', (data: ClientEvent & { type: 'rtc.sig' }, ack?: Ack) => {
    const sub = memberSub(data.roomId, ack)
    if (!sub) return
    if (!validId(data.targetMemberId)) return ack?.({ ok: false, code: 'bad-request', message: 'target invalid' })
    if (typeof data.payload !== 'string' || data.payload.length === 0 || data.payload.length > MAX_PAYLOAD_B64_CHARS)
      return ack?.({ ok: false, code: 'bad-request', message: 'payload invalid' })
    const key = `${s.id}:${data.roomId}:rtc`
    const t = now()
    const arr = (chatRate.get(key) ?? []).filter((ts) => ts > t - MESSAGE_RATE_WINDOW_MS)
    // ICE trickles a burst of candidates — allow a larger budget than chat
    if (arr.length >= MAX_MESSAGES_PER_WINDOW * 5) return ack?.({ ok: false, code: 'rate-limited', message: 'Too fast' })
    arr.push(t)
    chatRate.set(key, arr)
    const targets = sessionsOfMember(data.roomId, data.targetMemberId)
    deliverMany(targets, data.roomId, 'rtc.sig.received', { roomId: data.roomId, fromMemberId: sub.memberId, payload: data.payload })
    ack?.({ ok: true, message: targets.length ? 'delivered' : 'target-offline' })
  })

  on('room.meta', (data: ClientEvent & { type: 'room.meta' }, ack?: Ack) => {
    const sub = memberSub(data.roomId, ack)
    if (!sub) return
    if (typeof data.payload !== 'string' || data.payload.length === 0 || data.payload.length > MAX_PAYLOAD_B64_CHARS)
      return ack?.({ ok: false, code: 'bad-request', message: 'payload invalid' })
    const key = `${s.id}:${data.roomId}`
    const t = now()
    const arr = (chatRate.get(key) ?? []).filter((ts) => ts > t - MESSAGE_RATE_WINDOW_MS)
    if (arr.length >= MAX_MESSAGES_PER_WINDOW) return ack?.({ ok: false, code: 'rate-limited', message: 'Too fast' })
    arr.push(t)
    chatRate.set(key, arr)
    ack?.({ ok: true })
    emitToMembers(data.roomId, 'room.meta.received', { roomId: data.roomId, senderMemberId: sub.memberId, payload: data.payload }, { except: s.id })
  })

}

let io: Server

/**
 * Client-facing relay (socket.io at /socket.io). Protocol unchanged from
 * source/mini-services/relay-service so the current frontend keeps working.
 */
export function attachRelay(httpServer: HttpServer, cfg: NodeConfig, peers: PeerManager, selfNodeId: string) {
io = new Server(httpServer, {
  path: '/socket.io',
  cors: { origin: '*', methods: ['GET', 'POST'] },
  pingTimeout: 30_000,
  pingInterval: 15_000,
  // one b64 file chunk (≤ MAX_FILE_CHUNK_B64 chars) + JSON envelope must fit
  maxHttpBufferSize: 128 * 1024,
  // /peer upgrades belong to the node-to-node WebSocket server
  destroyUpgrade: false,
})

const perIp = new Map<string, number>()
io.use((socket, next) => {
  const ip = ipFrom(socket.handshake.headers['x-forwarded-for'], socket.handshake.address, cfg.trustProxy)
  const n = perIp.get(ip) ?? 0
  if (n >= cfg.maxClientsPerIp) return next(new Error('too many connections from this address'))
  perIp.set(ip, n + 1)
  socket.once('disconnect', () => {
    const left = (perIp.get(ip) ?? 1) - 1
    if (left <= 0) perIp.delete(ip)
    else perIp.set(ip, left)
  })
  next()
})

io.on('connection', (socket) => {
  if (io.of('/').sockets.size > cfg.maxClients) {
    socket.emit('error', { code: 'node-full', message: 'Node is at capacity, try another node' })
    socket.disconnect(true)
    return
  }
  log('connected', socket.id)
  sockets.set(socket.id, new Map())

  // debug: dump runtime state — dev only, leaks room metadata to any client
  if (cfg.debug) socket.on('debug.dump', () => {
    const sockDump: Record<string, unknown> = {}
    for (const [sid, subs] of sockets) {
      sockDump[sid] = {
        live: sessions.get(sid)?.alive() ?? false,
        subs: Object.fromEntries([...subs.entries()].map(([rid, s]) => [rid, { role: s.role, hb: now() - s.lastHeartbeat }])),
      }
    }
    socket.emit('debug.state', {
      rooms: [...rooms.keys()],
      sockets: sockDump,
    })
  })

  const session: Session = { id: socket.id, signId: socket.id, alive: () => socket.connected }
  sessions.set(session.id, session)
  const local = new Map<string, (data: never, ack?: Ack) => void>()
  bindSession(session, (event, fn) => local.set(event, fn))
  for (const [event, fn] of local) {
    socket.on(event, (data: unknown, ack?: unknown) => {
      const safeAck: Ack | undefined = typeof ack === 'function' ? (ack as Ack) : undefined
      if (!data || typeof data !== 'object') return safeAck?.({ ok: false, code: 'bad-request', message: 'payload must be an object' })
      routeLocal(socket, event, data as Record<string, unknown>, safeAck, fn)
    })
  }

  socket.on('disconnect', () => {
    dropSession(socket.id)
    federation.clientGone(socket.id)
    log('disconnected', socket.id)
  })
})

// ======================= federation: home-node routing =======================
//
// Entry side (a local client uses a room homed elsewhere): the client names the
// room's home `{ nodeId, endpoint }` (from the invite). We remember it PER
// SOCKET — one client can't redirect another client's room — forward its room
// events up over the authenticated peer link, and accept `room.down` for that
// socket+room ONLY from that exact home node.
//
// Home side: a peer's client becomes a remote Session (`r:<nodeId>:<sid>`) and
// runs through the very same handlers as a local socket.
const ACK_TIMEOUT_MS = 10_000
const MAX_REMOTE_SESSIONS_PER_PEER = 5_000
const MAX_SIDS_PER_DOWN_FRAME = 500
const NODE_ID_RE = /^[A-Za-z0-9_-]{43}$/
const SID_RE = /^[A-Za-z0-9_-]{1,64}$/
const UP_EVENTS = new Set([
  'room.create',
  'room.subscribe',
  'room.unsubscribe',
  'presence.heartbeat',
  'join.request',
  'join.challenge',
  'join.answer',
  'join.decision',
  'membership.commit',
  'key.wrapped',
  'chat.message',
  'file.chunk',
  'file.ack',
  'file.pull',
  'rtc.sig',
  'room.meta',
])
const DOWN_EVENTS = new Set([
  'room.presence',
  'join.request.received',
  'join.challenge.received',
  'join.answer.received',
  'join.decision.received',
  'membership.commit.received',
  'key.delivered',
  'chat.message.received',
  'file.chunk.received',
  'file.ack.received',
  'file.pull.received',
  'rtc.sig.received',
  'room.meta.received',
])

/** entry: socketId → roomId → home nodeId (remote homes only) */
const homes = new Map<string, Map<string, string>>()
/** entry: last known endpoint per home node (dial hint) */
const homeEndpoints = new Map<string, string>()
/** entry: homes whose link dropped — on reconnect our clients are told to re-subscribe */
const lostHomes = new Set<string>()
const pendingAcks = new Map<string, { ack?: Ack; nodeId: string; timer: ReturnType<typeof setTimeout> }>()
/** home: handlers bound to each remote session */
const remoteHandlers = new Map<string, Map<string, (data: never, ack?: Ack) => void>>()

function parseHome(v: unknown): { nodeId: string; endpoint: string } | null {
  const h = v as { nodeId?: unknown; endpoint?: unknown }
  if (!h || typeof h !== 'object' || typeof h.nodeId !== 'string' || !NODE_ID_RE.test(h.nodeId)) return null
  const endpoint = normalizeEndpoint(h.endpoint, cfg.allowInsecure)
  return endpoint ? { nodeId: h.nodeId, endpoint } : null
}

async function forwardUp(homeId: string, sid: string, roomId: string, event: string, data: Record<string, unknown>, ack?: Ack) {
  if (!peers.isLinked(homeId)) await peers.connectTo(homeId, homeEndpoints.get(homeId))
  let ackId: string | undefined
  if (ack) {
    ackId = randomNonce(12)
    const timer = setTimeout(() => {
      pendingAcks.delete(ackId!)
      ack({ ok: false, code: 'home-timeout', message: 'Home node did not answer' })
    }, ACK_TIMEOUT_MS)
    pendingAcks.set(ackId, { ack, nodeId: homeId, timer })
  }
  const sent = peers.sendFrame(homeId, { kind: 'room.up', sid, roomId, event, data, ackId })
  if (!sent && ackId) {
    const p = pendingAcks.get(ackId)
    if (p) {
      clearTimeout(p.timer)
      pendingAcks.delete(ackId)
      p.ack?.({ ok: false, code: 'home-unreachable', message: "Can't reach this room's home node" })
    }
  }
}

function routeLocal(
  socket: Socket,
  event: string,
  data: Record<string, unknown>,
  ack: Ack | undefined,
  fn: (data: never, ack?: Ack) => void,
) {
  const roomId = typeof data.roomId === 'string' && data.roomId.length <= 64 ? data.roomId : null
  const { home: rawHome, ...clean } = data
  if (!roomId) return fn(clean as never, ack)
  let byRoom = homes.get(socket.id)
  if (rawHome !== undefined) {
    const home = parseHome(rawHome)
    if (!home) return ack?.({ ok: false, code: 'bad-request', message: 'invalid home' })
    if (home.nodeId === selfNodeId) byRoom?.delete(roomId)
    else if (!cfg.federation) {
      // standalone relay: never dial out on a client's say-so
      return ack?.({ ok: false, code: 'federation-off', message: 'This node does not route to other nodes' })
    } else {
      if (!byRoom) homes.set(socket.id, (byRoom = new Map()))
      if (!byRoom.has(roomId) && byRoom.size >= MAX_ROOMS_PER_SESSION)
        return ack?.({ ok: false, code: 'too-many-rooms', message: 'Too many rooms on this connection' })
      byRoom.set(roomId, home.nodeId)
      homeEndpoints.set(home.nodeId, home.endpoint)
    }
  }
  const homeId = byRoom?.get(roomId)
  if (!homeId) return fn(clean as never, ack)

  void forwardUp(homeId, socket.id, roomId, event, clean, ack)
  if (event === 'room.unsubscribe') byRoom!.delete(roomId)
}

function remoteSession(nodeId: string, sid: string): string | null {
  const id = `r:${nodeId}:${sid}`
  if (sessions.has(id)) return id
  let count = 0
  for (const s of sessions.values()) if (s.via === nodeId) count++
  if (count >= MAX_REMOTE_SESSIONS_PER_PEER) return null
  const session: Session = { id, signId: sid, via: nodeId, alive: () => peers.isLinked(nodeId) }
  sessions.set(id, session)
  sockets.set(id, new Map())
  const handlers = new Map<string, (data: never, ack?: Ack) => void>()
  bindSession(session, (event, fn) => handlers.set(event, fn))
  remoteHandlers.set(id, handlers)
  return id
}

function dropRemote(id: string) {
  remoteHandlers.delete(id)
  dropSession(id)
}

peers.onFrame((link, body) => {
  switch (body.kind) {
    case 'room.up': {
      // we are the home node for this room
      const { sid, roomId, event, data, ackId } = body
      if (typeof sid !== 'string' || !SID_RE.test(sid) || !UP_EVENTS.has(event)) return
      if (typeof roomId !== 'string' || roomId.length > 64 || !data || typeof data !== 'object') return
      const payload = data as Record<string, unknown>
      if (payload.roomId !== roomId || 'home' in payload) return
      const id = remoteSession(link.nodeId, sid)
      const reply = (res: { ok: boolean; code?: string; message?: string }) => {
        if (typeof ackId === 'string' && ackId.length <= 64) peers.sendFrame(link.nodeId, { kind: 'room.ack', ackId, res })
      }
      if (!id) return reply({ ok: false, code: 'node-full', message: 'Too many remote clients from your node' })
      remoteHandlers.get(id)?.get(event)?.(payload as never, reply)
      return
    }
    case 'room.ack': {
      // only the node we forwarded to may answer
      const p = pendingAcks.get(body.ackId)
      if (!p || p.nodeId !== link.nodeId) return
      clearTimeout(p.timer)
      pendingAcks.delete(body.ackId)
      const r = body.res
      p.ack?.({
        ok: r?.ok === true,
        code: typeof r?.code === 'string' ? r.code.slice(0, 40) : undefined,
        message: typeof r?.message === 'string' ? r.message.slice(0, 200) : undefined,
      })
      return
    }
    case 'room.down': {
      // we are the entry node: deliver only what the socket's chosen home sends for that room
      const { sids, roomId, event, data } = body
      if (!Array.isArray(sids) || sids.length > MAX_SIDS_PER_DOWN_FRAME || typeof roomId !== 'string' || !DOWN_EVENTS.has(event)) return
      if (!data || typeof data !== 'object') return
      const claimed = (data as { roomId?: unknown }).roomId
      if (claimed !== undefined && claimed !== roomId) return
      for (const sid of sids) {
        if (typeof sid !== 'string' || homes.get(sid)?.get(roomId) !== link.nodeId) continue
        io.to(sid).emit(event, data)
      }
      return
    }
    case 'room.gone': {
      if (typeof body.sid === 'string' && SID_RE.test(body.sid)) dropRemote(`r:${link.nodeId}:${body.sid}`)
      return
    }
  }
})

/** our local sockets that route `roomId`s through home `nodeId` */
function clientsOfHome(nodeId: string): Array<{ sid: string; roomId: string }> {
  const out: Array<{ sid: string; roomId: string }> = []
  for (const [sid, byRoom] of homes) {
    if (!io.of('/').sockets.has(sid)) continue
    for (const [roomId, homeId] of byRoom) if (homeId === nodeId) out.push({ sid, roomId })
  }
  return out
}

peers.onLink((link, up) => {
  if (!up) {
    // home side: that node's clients are gone; entry side: fail what we were waiting for
    for (const s of [...sessions.values()]) if (s.via === link.nodeId) dropRemote(s.id)
    for (const [ackId, p] of pendingAcks) {
      if (p.nodeId !== link.nodeId) continue
      clearTimeout(p.timer)
      pendingAcks.delete(ackId)
      p.ack?.({ ok: false, code: 'home-unreachable', message: "Lost the link to this room's home node" })
    }
    // entry side: our clients' rooms there just went dark — say so, and keep re-dialing
    // (with backoff) while anyone still depends on that home
    const affected = clientsOfHome(link.nodeId)
    if (affected.length) {
      lostHomes.add(link.nodeId)
      for (const { sid, roomId } of affected) io.to(sid).emit('room.presence', { roomId, status: 'inactive', onlineCount: 0 })
      const ep = homeEndpoints.get(link.nodeId)
      if (ep) peers.want(ep, link.nodeId)
    }
    return
  }
  // entry side: a lost home is back. Its runtime state for our clients is gone
  // (link drop = sessions dropped there), so each client must re-subscribe
  // ITSELF — fresh proof-of-possession, real ack, self-recovery if demoted.
  if (!lostHomes.delete(link.nodeId)) return
  for (const { sid, roomId } of clientsOfHome(link.nodeId)) io.to(sid).emit('room.rehome', { roomId })
})

sendLocal = (sid, event, payload) => {
  io.to(sid).emit(event, payload)
}
sendRemote = (nodeId, sids, roomId, event, payload) => {
  for (let i = 0; i < sids.length; i += MAX_SIDS_PER_DOWN_FRAME) {
    const ok = peers.sendFrame(nodeId, { kind: 'room.down', sids: sids.slice(i, i + MAX_SIDS_PER_DOWN_FRAME), roomId, event, data: payload })
    if (!ok) log('down frame not sent (link down or too large)', nodeId.slice(0, 10), event)
  }
}

const federation = {
  /** a local socket disconnected: tell every home it was using */
  clientGone(sid: string) {
    const byRoom = homes.get(sid)
    if (byRoom) for (const homeId of new Set(byRoom.values())) peers.sendFrame(homeId, { kind: 'room.gone', sid })
    homes.delete(sid)
  },
}

const sweep = setInterval(() => sweepExpired(), PRESENCE_SWEEP_INTERVAL_MS)

return {
  io,
  stats: () => ({ clients: io.of('/').sockets.size, rooms: rooms.size }),
  remoteSessions: () => [...sessions.values()].filter((x) => x.via).length,
  close() {
    clearInterval(sweep)
    io.close()
  },
}
}
