/**
 * Shared protocol contract between web client and relay service.
 * Server NEVER stores chat content — it only relays ciphertext and manages
 * ephemeral runtime state (presence, pending join requests).
 */

// ---------- Runtime constants ----------
export const PROTOCOL_VERSION = 1

export const HEARTBEAT_INTERVAL_MS = 10_000
export const PRESENCE_TTL_MS = 35_000
export const PRESENCE_SWEEP_INTERVAL_MS = 5_000

export const JOIN_REQUEST_TTL_MS = 5 * 60_000
export const REJECT_COOLDOWN_MS = 60_000
export const CHALLENGE_TTL_MS = 2 * 60_000

export const MAX_NICKNAME_LENGTH = 32
export const MAX_ROOM_NAME_LENGTH = 64
export const MAX_TEXT_LENGTH = 4_000
export const MAX_CIPHERTEXT_CHARS = 16_384
export const MAX_PAYLOAD_B64_CHARS = 8_192
/** a key envelope carries the sealed member roster (≤ MAX_MEMBERS_PER_ROOM entries) */
export const MAX_KEY_ENVELOPE_CHARS = 48_000
/** sealed join answer (≤ 512 chars of text after AES-GCM + b64) */
export const MAX_JOIN_ANSWER_CHARS = 4_096

export const MAX_JOIN_REQUESTS_PER_WINDOW = 5
export const RATE_WINDOW_MS = 10 * 60_000
export const MAX_PENDING_REQUESTS_PER_ROOM = 20
export const MAX_MESSAGES_PER_WINDOW = 20
export const MESSAGE_RATE_WINDOW_MS = 10_000
export const MAX_MEMBERS_PER_ROOM = 32

// ---------- E2EE file transfer ----------
/** Raw bytes per ciphertext chunk (before base64). ~1.33x b64 inflation keeps
 *  every frame well under socket.io's 1 MB default maxHttpBufferSize. */
export const FILE_CHUNK_BYTES = 48 * 1024
/** Hard cap per file — keeps a device's memory + IndexedDB sane. */
export const MAX_FILE_BYTES = 25 * 1024 * 1024
export const MAX_FILE_CHUNKS = Math.ceil(MAX_FILE_BYTES / FILE_CHUNK_BYTES)
/** b64 chars of one encrypted chunk: 12B IV + 48KB ct, base64-encoded. */
export const MAX_FILE_CHUNK_B64 = 96_000
/** Generous chunk rate (separate from chat messages): ~55 MB/min ceiling. */
export const MAX_FILE_CHUNKS_PER_WINDOW = 1_200
export const FILE_RATE_WINDOW_MS = 60_000
export const MAX_FILE_NAME_CHARS = 128

// ---------- Shared helpers ----------
export interface IdentityPublicKeyBundle {
  /** base64 SPKI of ECDH P-256 public key */
  ecdh: string
  /** base64 SPKI of ECDSA P-256 public key */
  ecdsa: string
}

export type RoomPresenceStatus = 'active' | 'inactive'

// ---------- Client → Server events ----------
export type ClientEvent =
  | {
      type: 'room.create'
      roomId: string
      memberId: string
      nickname: string
      identityPublicKey: IdentityPublicKeyBundle
      /** b64url(SHA-256(`${roomId}|${secret}`)) — commits/attests secret possession.
       *  Stored by the relay at creation; a matching hash later re-attests the
       *  sender knows the room secret (self-recovery without an online member).
       *  The relay is still blind: it only ever sees the hash. */
      secretHash?: string
    }
  | {
      type: 'room.subscribe'
      roomId: string
      /** present when the device already holds membership */
      memberId?: string
      nickname?: string
      identityPublicKey?: IdentityPublicKeyBundle
      /** ECDSA signature over `roomId|memberId|socketId` proving key possession */
      signature?: string
    }
  | { type: 'room.unsubscribe'; roomId: string }
  | { type: 'presence.heartbeat'; roomId: string }
  | {
      type: 'join.request'
      roomId: string
      requestId: string
      memberId: string
      nickname: string
      identityPublicKey: IdentityPublicKeyBundle
      ephemeralPublicKey: string
      nonce: string
      createdAt: number
      expiresAt: number
      /** ECDSA over JoinRequestBody (src/lib/trust.ts) — binds BOTH identity keys */
      signature: string
      /** PWD rooms: opaque HMAC proving the joiner knows the room PWD (relay is blind to it) */
      pwdProof?: string
      /** display name sealed under the room secret — `nickname` is sent empty */
      sealedNickname?: string
    }
  | { type: 'join.challenge'; roomId: string; requestId: string; payload: string }
  | { type: 'join.answer'; roomId: string; requestId: string; payload: string; signature: string }
  | {
      type: 'join.decision'
      roomId: string
      requestId: string
      decision: 'accept' | 'reject'
      signedPayload: string
    }
  /** payload = `${b64url(MembershipCommitPayload)}.${sig}` — opaque to the relay except for the body */
  | { type: 'membership.commit'; roomId: string; payload: string }
  | {
      type: 'key.wrapped'
      roomId: string
      targetMemberId: string
      epoch: number
      wrappedKey: string
    }
  | {
      type: 'chat.message'
      roomId: string
      messageId: string
      epoch: number
      ciphertext: string
      /** sender ECDSA over ChatSigBody — receivers verify against the member list */
      sig: string
    }
  | {
      type: 'file.chunk'
      roomId: string
      fileId: string
      idx: number
      total: number
      /** b64(random 12B IV ‖ AES-GCM(fileKey, raw chunk)) — opaque to the relay */
      data: string
      /** present when answering a file.pull — unicast to ONE member instead
       *  of the whole room (P2P failed for that member; relay is the fallback) */
      targetMemberId?: string
    }
  | {
      /** receiver → relay → original sender: blob assembled + verified */
      type: 'file.ack'
      roomId: string
      fileId: string
      memberId: string
      /** lets the relay route the ack even when no file.chunk ever passed
       *  through it (pure-P2P transfer — sender learned via DataChannel) */
      senderMemberId?: string
    }
  | {
      /** receiver → original sender: deliver this file to me (relay fallback
       *  after P2P failed). Relay routes by senderMemberId — blind as ever. */
      type: 'file.pull'
      roomId: string
      fileId: string
      memberId: string
      senderMemberId: string
    }
  | {
      /** E2EE WebRTC signaling (offer/answer/ICE) — payload is
       *  AES-GCM(roomKey, sdp|candidate). The relay routes opaque blobs
       *  between members and never sees SDPs or candidate IPs. */
      type: 'rtc.sig'
      roomId: string
      targetMemberId: string
      payload: string
    }
  | {
      /** E2EE room metadata (e.g. name sync) — payload is AES-GCM(roomKey, ...) */
      type: 'room.meta'
      roomId: string
      payload: string
    }

// ---------- Server → Client events ----------
export type ServerEvent =
  | {
      type: 'room.created'
      roomId: string
      onlineCount: number
    }
  | {
      type: 'room.subscribed'
      roomId: string
      role: 'observer' | 'member'
      onlineCount: number
    }
  | {
      type: 'room.presence'
      roomId: string
      status: RoomPresenceStatus
      onlineCount: number
    }
  | {
      type: 'join.request.received'
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
      sealedNickname?: string
    }
  | { type: 'join.challenge.received'; requestId: string; payload: string }
  | {
      type: 'join.answer.received'
      requestId: string
      payload: string
      signature: string
    }
  | {
      type: 'join.decision.received'
      roomId: string
      requestId: string
      decision: 'accept' | 'reject'
      signedPayload: string
    }
  | { type: 'membership.commit.received'; roomId: string; payload: string }
  | {
      type: 'key.delivered'
      roomId: string
      epoch: number
      wrappedKey: string
    }
  | {
      type: 'chat.message.received'
      roomId: string
      messageId: string
      epoch: number
      ciphertext: string
      sig: string
      /** relay-asserted, untrusted — clients use the signed sender inside */
      senderMemberId: string
    }
  | {
      type: 'file.chunk.received'
      roomId: string
      fileId: string
      idx: number
      total: number
      data: string
      senderMemberId: string
    }
  | {
      type: 'file.ack.received'
      roomId: string
      fileId: string
      memberId: string
    }
  | {
      type: 'file.pull.received'
      roomId: string
      fileId: string
      /** the member asking for the file */
      memberId: string
    }
  | {
      type: 'rtc.sig.received'
      roomId: string
      fromMemberId: string
      payload: string
    }
  | {
      type: 'room.meta.received'
      roomId: string
      senderMemberId: string
      payload: string
    }
  /** entry node: the link to this room's home came back — re-subscribe (fresh proof, real ack) */
  | { type: 'room.rehome'; roomId: string }
  | { type: 'error'; code: string; message: string }

/** Structured payload carried (signed) inside membership.commit */
export interface MembershipCommitPayload {
  v: number
  epoch: number
  action: 'add' | 'remove'
  memberId: string
  identityPublicKey?: IdentityPublicKeyBundle
  /** legacy plaintext name — new clients send `sealedNickname` instead */
  nickname?: string
  /** name sealed with sealed.ts memberNameKey(room key of `epoch`) — an epoch every recipient holds */
  sealedNickname?: { epoch: number; c: string }
  issuedBy: string
  /** issuer's ECDSA public key — must be the pinned owner, or (recovery) the member itself */
  issuerEcdsa: string
  issuedAt: number
  /** 'recovery' = the added member self-recovered via room secret — online
   *  members may then wrap their latest epoch key for them (secret holders
   *  already have epoch-0 authority). Normal joins stay 'join' (default) and
   *  receive ONLY the fresh epoch key (forward secrecy preserved). */
  via?: 'join' | 'recovery'
}

/** Structured payload signed by the approver for join.decision */
export interface DecisionSignedPayload {
  v: number
  requestId: string
  roomId: string
  memberId: string
  decision: 'accept' | 'reject'
  issuedBy: string
  /** issuer's ECDSA public key — joiner checks its fingerprint against the invite */
  issuerEcdsa: string
  issuedAt: number
}

/** Decrypted chat message envelope (never leaves the client in clear) */
export interface ChatPlaintext {
  v: number
  t: string
  s: string
  n: string
  at: number
  /** present when this message announces an E2EE file attachment */
  file?: FileMetaPlaintext
}

/** File attachment descriptor carried INSIDE the encrypted chat envelope.
 *  The relay never sees any of it. `key` is the per-file AES key wrapped
 *  under the room key of `epoch` — only epoch key holders can unwrap. */
export interface FileMetaPlaintext {
  id: string
  name: string
  mime: string
  size: number
  /** b64(iv ‖ AES-GCM(roomKey, raw fileKey)) */
  key: string
  /** hex SHA-256 of the PLAINTEXT file — integrity check after assembly */
  sha256: string
  total: number
}

/** Decrypted room-metadata envelope (E2EE — the relay is blind to it). */
export interface RoomMetaPlaintext {
  v: number
  /** canonical room name — members with a non-owner role adopt it */
  n: string
  /** owner's ECDSA key + signature over RoomMetaSigBody — only the owner names the room */
  issuerEcdsa: string
  sig: string
}

export function isNonEmptyString(v: unknown, max: number): v is string {
  return typeof v === 'string' && v.length > 0 && v.length <= max
}

export function isBase64(v: unknown, maxChars: number): v is string {
  if (typeof v !== 'string' || v.length === 0 || v.length > maxChars) return false
  return /^[A-Za-z0-9+/=_-]+$/.test(v)
}
