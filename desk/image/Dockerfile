# The EKKA desk image: the agent's toolchain and nothing else.
#
# Not here, on purpose: no firewall, no sudo, no ekka CLI, no credentials, no
# project code. Run as a desk, OpenShell enforces its sandbox policy from
# outside the container, and credentials reach the desk as placeholders through
# OpenShell providers. This image holds neither the policy nor the providers.
# Project code lives in a volume mounted at /sandbox/ekka-workspace.
#
# Claude Code is the native binary, not the npm package. OpenShell allows a
# network connection per program, by the real path of the executable that
# opens it. The npm package is JavaScript, so its connections come from node,
# and allowing node to reach Anthropic would allow every node process to. The
# native binary connects as /usr/local/bin/claude, the path the desk's Claude
# Code provider names.
FROM node:20

ARG CLAUDE_CODE_VERSION=2.1.294
# The SHA-256 of that exact version's binary, per architecture, from Anthropic's release manifest
# (downloads.claude.ai/claude-code-releases/2.1.294/manifest.json). A changed version without new hashes fails.
ARG CLAUDE_CODE_SHA256_X64=27122ca7b624f537546fbef35b80c66370d974ff258f3d9b10ac50bb8771f262
ARG CLAUDE_CODE_SHA256_ARM64=e5d2df19f30a6d63bf11188121f7edb2775249b57352a69269509a4b1496e763
ARG DESK_UID=1000
# A Mac folder keeps its owner's UID. Use that non-root UID for local development.
RUN test "$DESK_UID" -gt 0 && usermod -u "$DESK_UID" node && chown -R node:node /home/node

# git and gh for the GitHub provider. iproute2 and nftables are optional:
# NVIDIA's reference image lists them for bypass detection.
RUN apt-get update && apt-get install -y --no-install-recommends \
      git gh ca-certificates curl less procps jq iproute2 nftables \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# The pinned Claude Code binary, fetched directly and checked against the hash above. Anthropic's download
# server answers 429 (over its bandwidth quota) for minutes at a time, and its install.sh gives up on the first
# one, so the fetch retries; the hash, not the server, decides what is installed.
RUN set -eu; \
    case "$(dpkg --print-architecture)" in \
      amd64) platform=linux-x64;   want="$CLAUDE_CODE_SHA256_X64" ;; \
      arm64) platform=linux-arm64; want="$CLAUDE_CODE_SHA256_ARM64" ;; \
      *) echo "no pinned Claude Code binary for $(dpkg --print-architecture)" >&2; exit 1 ;; \
    esac; \
    curl -fsSL --retry 30 --retry-all-errors --retry-delay 10 --retry-max-time 900 \
      -o /tmp/claude "https://downloads.claude.ai/claude-code-releases/${CLAUDE_CODE_VERSION}/${platform}/claude"; \
    echo "${want}  /tmp/claude" | sha256sum -c -; \
    install -m 0755 /tmp/claude /usr/local/bin/claude; \
    rm -f /tmp/claude; \
    /usr/local/bin/claude --version

# Git's credential helper for the desk's GitHub connection, as a root-owned file. A clone names it with
# -c credential.helper=...; an inline shell-function helper is held for approval, and nobody can approve one.
COPY ekka-git-credential /usr/local/bin/ekka-git-credential
RUN chown root:root /usr/local/bin/ekka-git-credential && chmod 0755 /usr/local/bin/ekka-git-credential

# The agent's main model is set here, on the desk, never by a prompt. Claude Code reads
# its managed settings from this path whatever the agent's home folder is, and
# they win over any other settings file.
# Disposable server checkouts permit unattended edits and ordinary Git commands.
# On a desk, the OpenShell policy enforces filesystem and network access, including any push refusal.
COPY managed-settings.json /etc/claude-code/managed-settings.json

# /sandbox itself is the default workspace; the Docker driver creates it and
# owns it to the sandbox identity. The two folders under it are ours.
RUN mkdir -p /sandbox/ekka-workspace /sandbox/.ekka-inputs \
    && chown -R node:node /sandbox/ekka-workspace /sandbox/.ekka-inputs

# No ENV lines on purpose. OpenShell starts every sandbox process with a cleared
# environment, so an ENV set here never reaches the agent. Settings such as
# Claude Code's telemetry switches are set on the sandbox at creation with
# `openshell sandbox create --env KEY=VALUE`.

USER node
WORKDIR /sandbox
