#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Platform volumes (Railway, some k8s setups) mount /data owned by root, but the
# app must not run as root. When started as root: hand /data to the unprivileged
# `bun` user, then DROP root (su-exec) before the app starts. When already
# started unprivileged (docker compose `user: bun`, cap_drop ALL) → run as is.
set -eu
DATA=/data
if [ "$(id -u)" = "0" ]; then
  mkdir -p "$DATA"
  # only fix what's wrong; -h: never follow symlinks out of the volume
  find "$DATA" -xdev \( ! -user bun -o ! -group bun \) -exec chown -h bun:bun {} +
  chmod 700 "$DATA"
  exec su-exec bun:bun "$@"
fi
exec "$@"
