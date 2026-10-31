// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Negative/abuse checks against a running registry + node.
 *   WAU_REGISTRY=http://localhost:4000 WAU_NODE=http://localhost:4101 bun run smoke
 * Optional WAU_STRICT_REGISTRY = a registry started WITHOUT insecure mode, to
 * exercise the SSRF guard.
 */
import { WebSocket } from 'ws'
import { generateNodeKeyPair, randomNonce, signBody } from '../src/protocol/crypto'
import { NETWORK_PROTOCOL_VERSION, SIG, peerWsUrl, type RegisterBody } from '../src/protocol/network'

const REGISTRY = process.env.WAU_REGISTRY ?? 'http://localhost:4000'
const NODE = process.env.WAU_NODE ?? 'http://localhost:4101'
const STRICT = process.env.WAU_STRICT_REGISTRY
let failed = 0
const check = (name: string, ok: boolean, detail = '') => {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? `  (${detail})` : ''}`)
  if (!ok) failed++
}

async function register(body: RegisterBody, sig: string, registry = REGISTRY) {
  const res = await fetch(`${registry}/v1/nodes/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ body, sig }),
  })
  return { status: res.status, data: (await res.json()) as { code?: string; message?: string } }
}

const impostor = generateNodeKeyPair()
const body = (): RegisterBody => ({
  v: NETWORK_PROTOCOL_VERSION,
  nodeId: impostor.nodeId,
  publicKey: impostor.publicKey,
  endpoint: NODE, // claims an endpoint it does not control
  software: 'smoke',
  aud: REGISTRY,
  ts: Date.now(),
  nonce: randomNonce(),
})

// 1. hijack someone else's endpoint
{
  const b = body()
  const r = await register(b, signBody(impostor.privateKey, SIG.register, b))
  check('registry rejects endpoint the key does not control', r.status === 422, `${r.status} ${r.data.code}`)
}
// 2. forged signature
{
  const b = body()
  const r = await register(b, signBody(generateNodeKeyPair().privateKey, SIG.register, b))
  check('registry rejects forged signature', r.status === 401, `${r.status} ${r.data.code}`)
}
// 3. nodeId not derived from key
{
  const b = { ...body(), nodeId: generateNodeKeyPair().nodeId }
  const r = await register(b, signBody(impostor.privateKey, SIG.register, b))
  check('registry rejects nodeId != hash(publicKey)', r.status === 400, `${r.status} ${r.data.code}`)
}
// 4. stale timestamp
{
  const b = { ...body(), ts: Date.now() - 60 * 60_000 }
  const r = await register(b, signBody(impostor.privateKey, SIG.register, b))
  check('registry rejects stale timestamp', r.status === 400, `${r.status} ${r.data.code}`)
}
// 5. replayed request
{
  const b = { ...body(), endpoint: 'http://127.0.0.1:1' }
  const sig = signBody(impostor.privateKey, SIG.register, b)
  await register(b, sig)
  const r = await register(b, sig)
  check('registry rejects replayed nonce', r.status === 409, `${r.status} ${r.data.code}`)
}
// 5b. registration addressed to another registry
{
  const b = { ...body(), aud: 'https://other-registry.example' }
  const r = await register(b, signBody(impostor.privateKey, SIG.register, b))
  check('registry rejects registration for another audience', r.status === 400 && r.data.code === 'wrong-audience', `${r.status} ${r.data.code}`)
}
// 5c. SSRF: endpoints pointing at internal addresses, errors must stay generic
if (STRICT) {
  for (const ep of ['https://169.254.169.254', 'https://127.0.0.1:4101', 'https://localhost', 'https://10.0.0.1']) {
    const kp = generateNodeKeyPair()
    const b: RegisterBody = { ...body(), nodeId: kp.nodeId, publicKey: kp.publicKey, endpoint: ep, aud: STRICT }
    const r = await register(b, signBody(kp.privateKey, SIG.register, b), STRICT)
    check(
      `strict registry refuses internal endpoint ${ep} with a generic error`,
      r.status === 422 && r.data.message === 'endpoint did not answer the ownership challenge',
      `${r.status} ${r.data.message}`,
    )
  }
}
// 6. unregistered node tries to open a peer link
{
  const code = await new Promise<string>((resolve) => {
    const ws = new WebSocket(peerWsUrl(NODE))
    ws.on('open', () =>
      ws.send(
        JSON.stringify({
          t: 'hello',
          v: NETWORK_PROTOCOL_VERSION,
          nodeId: impostor.nodeId,
          publicKey: impostor.publicKey,
          endpoint: 'http://localhost:4999',
          nonce: randomNonce(),
          ts: Date.now(),
        }),
      ),
    )
    ws.on('message', (raw) => {
      const m = JSON.parse(raw.toString())
      if (m.t === 'error') resolve(m.code)
      else resolve(m.t)
    })
    ws.on('error', () => resolve('ws-error'))
    setTimeout(() => resolve('timeout'), 5_000)
  })
  check('node refuses peer link from unregistered node', code === 'forbidden', code)
}
// 7. hello claiming someone else's nodeId with our key
{
  const info = (await (await fetch(`${NODE}/v1/node/info`)).json()) as { nodeId: string }
  const code = await new Promise<string>((resolve) => {
    const ws = new WebSocket(peerWsUrl(NODE))
    ws.on('open', () =>
      ws.send(
        JSON.stringify({
          t: 'hello',
          v: NETWORK_PROTOCOL_VERSION,
          nodeId: info.nodeId.replace(/^./, (c) => (c === 'A' ? 'B' : 'A')),
          publicKey: impostor.publicKey,
          endpoint: 'http://localhost:4999',
          nonce: randomNonce(),
          ts: Date.now(),
        }),
      ),
    )
    ws.on('message', (raw) => resolve(JSON.parse(raw.toString()).code ?? 'ok'))
    ws.on('error', () => resolve('ws-error'))
    setTimeout(() => resolve('timeout'), 5_000)
  })
  check('node refuses hello whose nodeId != hash(publicKey)', code === 'bad-hello', code)
}
// 7b. flood of idle unauthenticated peer sockets from one IP is capped
{
  const socks: WebSocket[] = []
  const results = await Promise.all(
    Array.from({ length: 6 }, () =>
      new Promise<string>((resolve) => {
        const ws = new WebSocket(peerWsUrl(NODE))
        socks.push(ws)
        ws.on('open', () => resolve('open'))
        ws.on('unexpected-response', (_req, res) => resolve(String(res.statusCode)))
        ws.on('error', () => resolve('error'))
        setTimeout(() => resolve('timeout'), 3_000)
      }),
    ),
  )
  socks.forEach((s) => s.terminate())
  const opened = results.filter((r) => r === 'open').length
  check('node caps pending handshakes per IP (4)', opened === 4 && results.length - opened === 2, results.join(','))
}
// 7c. challenge endpoint rejects malformed nonce
{
  const res = await fetch(`${NODE}/v1/node/challenge?nonce=${encodeURIComponent('<script>')}&aud=x`)
  check('node challenge rejects malformed nonce', res.status === 400, String(res.status))
}
// 8. client relay still answers socket.io handshakes
{
  const res = await fetch(`${NODE}/socket.io/?EIO=4&transport=polling`)
  const text = await res.text()
  check('client relay (socket.io) reachable on node', res.ok && text.includes('"sid"'), String(res.status))
}

console.log(failed ? `\n${failed} check(s) failed` : '\nall checks passed')
process.exit(failed ? 1 : 0)
