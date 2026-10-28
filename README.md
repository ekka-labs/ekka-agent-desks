# EKKA Agent Desks

Runs on NVIDIA OpenShell.

An agent desk is a sandbox where an AI coding agent works on your code, within
permissions you control. This repository will hold the open source setup for
EKKA agent desks: one command that installs NVIDIA OpenShell and EKKA together,
on one machine or on a server your team reaches over your VPN.

**The full setup is coming soon.** This first release is the desk base image.

## The desk base image

`desk/image/` builds the container image every desk starts from. It holds the
agent's toolchain and nothing else.

What is in it:

| Part | What it is for |
|---|---|
| `node:20` | the base: Debian with Node.js 20 |
| `git`, `gh`, `curl`, `jq`, `less`, `procps`, `ca-certificates` | the tools the agent uses on your code |
| `iproute2`, `nftables` | optional; NVIDIA's reference image lists them for bypass detection |
| Claude Code, the native binary, at `/usr/local/bin/claude` | the agent; a pinned version, checked against its SHA-256 for each architecture |
| `/usr/local/bin/ekka-git-credential` | Git's credential helper for the desk's GitHub connection |
| `/etc/claude-code/managed-settings.json` | the agent's model and a short list of allowed and refused commands |
| `/sandbox/ekka-workspace`, `/sandbox/.ekka-inputs` | the folders the desk works in, owned by the non-root `node` user |

What is not in it, on purpose: no firewall, no `sudo`, no EKKA command line, no
credentials and no project code. Project code lives in a volume mounted at
`/sandbox/ekka-workspace`.

This repository is the image only. It holds no OpenShell policy and no provider
configuration. Use the image with an OpenShell policy and provider
configuration to enforce network access and keep credentials in the gateway.
With a GitHub provider, the desk sees only a placeholder token, and the gateway
swaps in the real key on the way out. Run with plain Docker, the image has none
of those protections, and the Git helper passes on whatever `GITHUB_TOKEN`
holds.

Why the native Claude Code binary and not the npm package: OpenShell allows a
network connection per program, by the real path of the executable that opens
it. The npm package runs as `node`, so allowing it to reach Anthropic would
allow every Node.js process to. The native binary connects as
`/usr/local/bin/claude` and can be allowed on its own.

## Build it

From a clone of this repository:

```sh
git clone https://github.com/ekka-labs/ekka-agent-desks.git
cd ekka-agent-desks
docker build -t ekka-desk-base desk/image
```

On a Mac, build with your own user ID so files in a mounted folder keep their
owner:

```sh
docker build --build-arg DESK_UID="$(id -u)" -t ekka-desk-base desk/image
```

`DESK_UID` must not be 0; the build refuses root.

To change the Claude Code version, set `CLAUDE_CODE_VERSION` together with
`CLAUDE_CODE_SHA256_X64` and `CLAUDE_CODE_SHA256_ARM64` from that version's
release manifest. A version without matching hashes fails the build.

This Dockerfile adds no environment variables. OpenShell starts every sandbox
process with a cleared environment, so settings such as Claude Code's
telemetry switches are given when the desk is created:
`openshell sandbox create --env KEY=VALUE`.

## Learn more

- How desks work: [Agent desks](https://docs.ekka.ai/agent-desks/)
- EKKA documentation: [docs.ekka.ai](https://docs.ekka.ai/)

## License

The files in this repository are under the Apache License 2.0 (`LICENSE`).

Building the image downloads software that is not part of this repository and
keeps its own terms: the `node:20` image and its Debian packages under their
licenses, and Claude Code under
[Anthropic's terms](https://code.claude.com/docs/en/legal-and-compliance). This repository does not
include or redistribute Claude Code.

NVIDIA and OpenShell are trademarks of NVIDIA Corporation in the U.S. and other
countries. Claude and Claude Code are trademarks of Anthropic, PBC.
