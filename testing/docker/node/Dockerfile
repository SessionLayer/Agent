# A SessionLayer test NODE: the canonical sshd fixture (testing/docker/sshd/,
# vendored byte-identical) plus a dedicated **non-root** account for the Agent.
#
# One container running BOTH the node's real `sshd` AND the real Agent binary is
# the only faithful shape for the S14 splice: the Agent connects to its own node's
# sshd over loopback, inside the node's own network namespace.
#
# The Agent account (uid 65532) deliberately cannot read /etc/ssh/ssh_host_* —
# host keys are root-only (FR-CONN-6 / Design §9.3). That is what makes the
# Gateway's no-TOFU host verification meaningful in the agent model: spoofing the
# node's host identity needs node-ROOT, not merely a compromised Agent.
ARG SSHD_IMAGE=sessionlayer-agent-test-sshd:latest
FROM ${SSHD_IMAGE}

RUN useradd --create-home --shell /bin/bash --uid 65532 agent

COPY node-entrypoint.sh /usr/local/bin/node-entrypoint.sh
RUN chmod +x /usr/local/bin/node-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/node-entrypoint.sh"]
