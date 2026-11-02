#!/usr/bin/env bash
# Runs the opt-in end-to-end tests (crates/netcatty-e2e) against a throwaway
# OpenSSH container: user `tester`, password `testpass`, plus a freshly
# generated ed25519 key authorized for publickey tests.
#
#   rust/scripts/e2e-sshd/run.sh            # build image, start, test, stop
#   KEEP=1 rust/scripts/e2e-sshd/run.sh     # leave the container running
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"; [ "${KEEP:-0}" = 1 ] || docker rm -f netcatty-e2e-sshd >/dev/null 2>&1 || true' EXIT

ssh-keygen -q -t ed25519 -N "" -f "$work/e2e_key" -C netcatty-e2e
cp "$here/Dockerfile" "$work/Dockerfile"
docker build -q -t netcatty-e2e-sshd "$work"
docker rm -f netcatty-e2e-sshd >/dev/null 2>&1 || true
docker run -d --name netcatty-e2e-sshd -p "127.0.0.1:${NETCATTY_E2E_SSH_PORT:-2222}:22" netcatty-e2e-sshd >/dev/null
for _ in $(seq 1 30); do
  nc -z 127.0.0.1 "${NETCATTY_E2E_SSH_PORT:-2222}" 2>/dev/null && break
  sleep 0.5
done

cd "$root"
NETCATTY_E2E_SSH_HOST=127.0.0.1 \
NETCATTY_E2E_SSH_PORT="${NETCATTY_E2E_SSH_PORT:-2222}" \
NETCATTY_E2E_SSH_KEY="$work/e2e_key" \
cargo test -p netcatty-e2e "$@"
