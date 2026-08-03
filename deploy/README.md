# Agent deployment assets

Kubernetes DaemonSet manifest, a hardened systemd unit for the bare-metal and
VM model, and Prometheus alert rules for the Agent's Tier-0 hardening and
exit-code alerting. The systemd unit sets `RestartPreventExitStatus=3 4`, which
Kubernetes has no equivalent for — a DaemonSet pod restarts on any exit code, so
there the alert rules are what stop a terminal identity outcome from becoming
restart noise. See `docs/installation/agent.md` in
the [Documentation](https://github.com/SessionLayer/Documentation) repo for
the hardening model, the read-only rootfs posture, and the exit-code contract
these assets implement.
