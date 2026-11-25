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
# Node 24 LTS on Debian trixie, pinned by digest. Node 20 reached end of life in April
# 2026, and bookworm's GLIBC 2.36 cannot start binaries built on current Ubuntu (APM 0.35.0 needs 2.38). A tag alone
# is whatever was last pushed under it; the digest is the image we tested.
# The slim variant: no compiler, no make, no Python and no SSH client. The full image brings the Debian build tools
# (453 packages against 79), and most desks never run them. A project whose packages must compile adds a compiler
# in its own project image, where it can say why.
FROM node:24-trixie-slim@sha256:af02d57b57719b9657a45199a79264a9437940cd55b3c7b3fc99615654f124a0

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

# ekka-session: the wall every shared job on this desk starts inside. It gives each job its own folder and keeps it out
# of every other job's. It comes from EKKA's signed runner release, pinned by version and by the release tarball's
# SHA-256 for each architecture (published beside it as <tarball>.sha256 on get.ekka.ai). The hash, not the server,
# decides what is installed. A changed version without new hashes fails.
ARG EKKA_VERSION=0.6.19
ARG EKKA_TARBALL_SHA256_X64=9aa8f1aa52dc2fa4f0955a744e32b1c19b89107a9bdf9a1e94e825b3816755e9
ARG EKKA_TARBALL_SHA256_ARM64=d3f7892b6518b54ff8bd77c77049549588e6d963a50ccff2542bb6da52e9b1a9
RUN set -eu; \
    case "$(dpkg --print-architecture)" in \
      amd64) target=x86_64-unknown-linux-musl;  want="$EKKA_TARBALL_SHA256_X64" ;; \
      arm64) target=aarch64-unknown-linux-musl; want="$EKKA_TARBALL_SHA256_ARM64" ;; \
      *) echo "no pinned ekka-session for $(dpkg --print-architecture)" >&2; exit 1 ;; \
    esac; \
    pkg="ekka-${EKKA_VERSION}-${target}"; \
    curl -fsSL --retry 10 --retry-all-errors --retry-delay 10 --retry-max-time 600 \
      -o /tmp/ekka.tar.gz "https://get.ekka.ai/runner/v${EKKA_VERSION}/${pkg}.tar.gz"; \
    echo "${want}  /tmp/ekka.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/ekka.tar.gz -C /tmp "${pkg}/bin/ekka-session"; \
    install -o root -g root -m 0755 "/tmp/${pkg}/bin/ekka-session" /usr/local/bin/ekka-session; \
    rm -rf /tmp/ekka.tar.gz "/tmp/${pkg}"; \
    rc=0; /usr/local/bin/ekka-session read-job >/dev/null 2>&1 || rc=$?; \
    [ "$rc" -eq 10 ] || { echo "ekka-session ${EKKA_VERSION} answered read-job with ${rc}, not 10" >&2; exit 1; }

# Git's credential helper for the desk's GitHub and Bitbucket connections, as a root-owned file. A clone names it with
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

# Yarn where a desk can read it. The Node image keeps it in /opt/yarn-v<version> and links it from /usr/local/bin, and a
# desk's policy does not let it read /opt, so `yarn` failed on every desk made from this image.
RUN set -eu; \
    src=$(readlink -f /usr/local/bin/yarn); src=${src%/bin/yarn}; \
    case "$src" in /opt/yarn-v*) ;; *) echo "yarn is not where the Node image keeps it: $src" >&2; exit 1 ;; esac; \
    mv "$src" /usr/local/lib/yarn; \
    ln -sfn /usr/local/lib/yarn/bin/yarn /usr/local/bin/yarn; \
    ln -sfn /usr/local/lib/yarn/bin/yarnpkg /usr/local/bin/yarnpkg; \
    yarn --version

# No setuid or setgid program: it is how an ordinary user becomes root or another user, and nothing on a desk needs
# one. The Node image ships thirteen (su, mount, passwd and ssh-keysign among them). Last as root,
# so nothing installed after it brings one back, and the build fails if any is left.
RUN find / -xdev -type f -perm /6000 -exec chmod ug-s {} + \
    && left=$(find / -xdev -type f -perm /6000) \
    && { [ -z "$left" ] || { echo "setuid or setgid files remain: $left" >&2; exit 1; }; }

# No ENV lines on purpose. OpenShell starts every sandbox process with a cleared
# environment, so an ENV set here never reaches the agent. Settings such as
# Claude Code's telemetry switches are set on the sandbox at creation with
# `openshell sandbox create --env KEY=VALUE`.

USER node
WORKDIR /sandbox
