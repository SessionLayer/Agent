#!/bin/sh
# Start the node's own sshd (root, foreground-logging to stderr so the VERBOSE
# cert key-id lands in `docker logs` — the tamper-independent second trail,
# FR-AUD-4), then drop to a NON-ROOT account and exec the Agent.
#
# Arguments after the image name are passed straight to `sessionlayer-agent run`.
set -eu

if [ -n "${TRUSTED_USER_CA:-}" ]; then
	printf '%s\n' "$TRUSTED_USER_CA" >/etc/ssh/trusted_user_ca.pub
	chmod 644 /etc/ssh/trusted_user_ca.pub
fi

ssh-keygen -A >/dev/null 2>&1 || true
mkdir -p /run/sshd

# LogLevel VERBOSE comes from the vendored sshd_config; -e keeps the log on stderr.
/usr/sbin/sshd -D -e -p "${SSHD_PORT:-22}" &

# The Agent NEVER runs as root: it would be one hop from the node's host key.
# `require_non_root()` refuses euid 0 anyway — this is the structural half.
exec setpriv --reuid=65532 --regid=65532 --clear-groups /agent run "$@"
