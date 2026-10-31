# Contributing to wau-node

Thanks for helping build the WAU network.

## License of contributions

Each file declares its license on its first line (`SPDX-License-Identifier`). By contributing, you agree that your change is licensed under **the license of the file(s) it touches**:

- `src/protocol/*` and `src/net-guard.ts`: MIT (`LICENSE-MIT`)
- everything else: AGPL-3.0-only (`LICENSE`)

New files must start with an SPDX line. Protocol and spec code is MIT; node implementation code is AGPL-3.0-only.

## Developer Certificate of Origin (DCO)

Every commit must be signed off. This certifies that you wrote the change or otherwise have the right to submit it under the file's license, as described in the Developer Certificate of Origin 1.1 (https://developercertificate.org).

```bash
git commit -s -m "your message"
```

This adds a trailer that must match the commit author:

```
Signed-off-by: Your Name <you@example.com>
```

Commits without a valid sign-off can't be merged.

## Before opening a PR

```bash
bun run typecheck
bun run discovery-test          # spawns its own registry + nodes
# with a node (and registry) running:
WAU_NODE=http://localhost:3003 bun run relay-test
WAU_REGISTRY=… WAU_NODE=… bun run smoke
```

Security-relevant changes (handshake, frame signing, routing, limits) must keep the threat model in README → *Security model*: **every node is untrusted**.
