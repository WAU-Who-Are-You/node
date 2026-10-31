# syntax=docker/dockerfile:1.7
# WAU node — bundled into one file, run by an unprivileged user.
#
#   docker build -t wau-node .
#   docker run -v wau-node-data:/data -e NODE_PUBLIC_URL=https://node.example.com wau-node
#
# Secure defaults apply: NODE_PUBLIC_URL must be https (put TLS in front, see
# docker-compose.yml). Local http testing needs NODE_ALLOW_INSECURE=true.

ARG BUN_VERSION=1.3.14

# ---------- build: bundle the node + its deps ----------
FROM oven/bun:${BUN_VERSION}-alpine AS build
WORKDIR /src
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile --production
COPY src ./src
RUN bun build src/index.ts --target=bun --minify --outfile /out/wau-node.js

# ---------- runtime ----------
FROM oven/bun:${BUN_VERSION}-alpine
WORKDIR /app
COPY --from=build /out/wau-node.js ./wau-node.js
COPY LICENSE LICENSE-MIT ./
# the node's Ed25519 identity lives in /data — losing it = becoming a new node
# port: NODE_PORT, else the platform's PORT, else 3003 (see src/config.ts)
ENV NODE_DATA_DIR=/data
# su-exec: the entrypoint starts as root only to fix /data ownership (platform
# volumes mount root-owned), then drops to `bun` before the app runs.
# compose runs it as `user: bun` directly, so root is never used there.
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN apk add --no-cache su-exec && chmod 0755 /usr/local/bin/docker-entrypoint.sh \
 && mkdir -p /data && chown bun:bun /data && chmod 700 /data
# no VOLUME instruction: some platforms (Railway) reject it — mount /data via
# compose / `docker run -v` / the platform's volume feature instead
EXPOSE 3003
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD bun -e "fetch('http://127.0.0.1:'+(process.env.NODE_PORT||process.env.PORT||3003)+'/v1/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["bun", "wau-node.js"]
