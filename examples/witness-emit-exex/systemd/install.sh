#!/usr/bin/env bash
# Idempotent installer for the witness-emit production layout.
#
# Run as root from the repo root. Expects:
#   target/release/reth-witness-emit-node
#   target/release/witness-uploader
#   target/release/witness-follower
# already built.

set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "must run as root" >&2
    exit 1
fi

# Repo layout: resolve from this script's location.
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../../.." && pwd)"

# 1. Binaries.
install -m 0755 "${repo_root}/target/release/reth-witness-emit-node" /usr/local/bin/
install -m 0755 "${repo_root}/target/release/witness-uploader"        /usr/local/bin/
install -m 0755 "${repo_root}/target/release/witness-follower"        /usr/local/bin/

# 2. Wrappers + preflights.
mkdir -p /usr/local/libexec
install -m 0755 "${script_dir}/start-reth-witness-emit-node"    /usr/local/libexec/
install -m 0755 "${script_dir}/reth-witness-emit-preflight"     /usr/local/libexec/
install -m 0755 "${script_dir}/start-witness-uploader"          /usr/local/libexec/
install -m 0755 "${script_dir}/witness-uploader-preflight"      /usr/local/libexec/
install -m 0755 "${repo_root}/examples/witness-exec-spike/systemd/start-witness-follower" \
    /usr/local/libexec/

# 3. Units.
install -m 0644 "${script_dir}/reth-witness-emit-node.service" /etc/systemd/system/
install -m 0644 "${script_dir}/witness-uploader.service"       /etc/systemd/system/
install -m 0644 "${repo_root}/examples/witness-exec-spike/systemd/witness-follower@.service" \
    /etc/systemd/system/

# 4. Env-file templates — only install if not already present (don't
#    clobber operator-edited config).
install -m 0644 -b "${script_dir}/witness-emit-node.env.example"     /etc/default/witness-emit-node.example
install -m 0644 -b "${script_dir}/witness-emit-uploader.env.example" /etc/default/witness-emit-uploader.example
install -m 0644 -b "${repo_root}/examples/witness-exec-spike/systemd/witness-follower.env.example" \
    /etc/default/witness-follower.env.example

for src in /etc/default/witness-emit-node.example /etc/default/witness-emit-uploader.example; do
    dst="${src%.example}"
    if [[ ! -f "${dst}" ]]; then
        cp "${src}" "${dst}"
        chmod 0644 "${dst}"
        echo "installed default config: ${dst} (please edit before starting)"
    fi
done

# 5. State directories.
#
# These MUST exist before systemd evaluates `ReadWritePaths=` — namespace
# setup happens before any ExecStartPre runs.
mkdir -p /var/lib/witness-emit/inbox
mkdir -p /var/lib/witness-followers
mkdir -p /var/log/reth-witness-emit

# 6. Reload systemd.
systemctl daemon-reload

echo "install complete. Next:"
echo "  sudo systemctl enable --now reth-witness-emit-node"
echo "  sudo systemctl enable --now witness-uploader"
echo "  # for each follower instance:"
echo "  sudo cp /etc/default/witness-follower.env.example /etc/default/witness-follower-<NAME>"
echo "  sudo \$EDITOR /etc/default/witness-follower-<NAME>"
echo "  sudo systemctl enable --now witness-follower@<NAME>"
