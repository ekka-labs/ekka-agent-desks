<p><a href="https://ekka.ai"><img src="docs/assets/ekka-wordmark.png" alt="EKKA" width="180"></a></p>

# EKKA Agent Desks

**Run a coding agent on your Linux server, with EKKA permissions and execution receipts.**

This repository holds EKKA's desk base image and the setup that runs desks on your own server with [NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell). The included workflow prepares a repository, asks Claude Code a question, and records the result for verification.

[Get started](docs/SERVER.md) · [How it works](docs/HOW-IT-WORKS.md) · [Security](docs/SECURITY.md)

## What each part does

| Part | Responsibility |
|---|---|
| **NVIDIA OpenShell** | Isolates the agent workspace, enforces network policy, and supplies credentials to authorized requests. |
| **EKKA** | Checks permission for the workflow and desk actions, runs the approved work through its Enclave, and records execution receipts. |
| **This repository** | The desk base image, and the installation scripts, provider profiles, policies and example plans that connect the components. |

A **desk** is the agent's isolated workspace. A **plan** is the workflow it runs. A **grant** gives an agent permission to use a resource.

## Get started

You need:

- An Ubuntu 24.04 server (x86_64 or aarch64) with SSH and sudo access. Start with 8 GB RAM and 50 GB disk; storage needs depend on your repositories.
- An EKKA organization you own or administer.
- A workspace-scoped Anthropic API key. An organization-scoped key is not supported.

On the server:

```sh
git clone https://github.com/ekka-labs/ekka-agent-desks.git
cd ekka-agent-desks
```

Follow the **[server installation guide](docs/SERVER.md)** to configure access, install the services, connect the model, and create `code-desk`. It explains which commands run on the server and which run on your computer.

## Try the example

After installation, run these commands **on the server, as root** (`sudo -i` first). They work from any folder: `ekka` there is this server's Enclave.

Wait until `ekka desk list` shows the desk as pinned, about a minute or two.

### 1. Prepare a public repository

```sh
ekka plan run ekka.example.desk.setup.codeDesk.v1 \
  --input 'repos=["https://github.com/octocat/Hello-World"]'
```

No GitHub token is needed for this public repository.

### 2. Ask about its code

```sh
ekka plan run ekka.example.desk.ask.codeDesk.v1 \
  --input 'question=What does the README say? Cite its file and line.'
```

The answer should cite `Hello-World/README`, line 1, containing `Hello World!`. Check the citation against the file. Keep the run ID printed by the command.

### 3. Verify the execution record

```sh
ekka receipts verify
```

Receipt verification checks the execution record. It does not establish that the model's answer is correct. See [answers and records](docs/ASK-YOUR-CODE.md) for how to inspect a run.

## Scope and data handling

The included workflow covers repository setup and code questions. The default GitHub policy allows clone and fetch, with push blocked. A complete issue-to-PR workflow is outside this quick start.

Repository copies live on your server. The model provider receives the code context sent by the agent. EKKA receives run inputs, including your question, and execution records. Read [security and data handling](docs/SECURITY.md) before using private code.

## Documentation

| Guide | What you will learn |
|---|---|
| [Install the server](docs/SERVER.md) | Prepare the machine, connect credentials, and create a desk. |
| [Set up repositories](docs/SET-UP-YOUR-DESK.md) | Use public or private repositories. |
| [Ask your code](docs/ASK-YOUR-CODE.md) | Submit questions, read answers, and inspect run records. |
| [How it works](docs/HOW-IT-WORKS.md) | Understand the components and execution flow. |
| [Command reference](docs/COMMANDS.md) | Find desk and credential commands. |
| [Operations](docs/OPERATIONS.md) | Upgrade, back up, and troubleshoot the installation. |
| [Documentation index](docs/OVERVIEW.md) | Find advanced configuration and component licenses. |

## The desk base image

`desk/image/` builds the container image every desk starts from. It holds the
agent's toolchain and nothing else.

What is in it:

| Part | What it is for |
|---|---|
| `node:24-trixie-slim`, pinned by digest | the base: Debian trixie with Node.js 24, without the Debian build tools; Yarn moved to `/usr/local/lib/yarn`, which a desk can read |
| `git`, `gh`, `curl`, `jq`, `less`, `procps`, `ca-certificates` | the tools the agent uses on your code |
| `iproute2`, `nftables` | optional; NVIDIA's reference image lists them for bypass detection |
| Claude Code, the native binary, at `/usr/local/bin/claude` | the agent; a pinned version, checked against its SHA-256 for each architecture |
| `/usr/local/bin/ekka-git-credential` | Git's credential helper for the desk's GitHub and Bitbucket connections |
| `/etc/claude-code/managed-settings.json` | the agent's model and a short list of allowed and refused commands |
| `/sandbox/ekka-workspace`, `/sandbox/.ekka-inputs` | the folders the desk works in, owned by the non-root `node` user |

What is not in it, on purpose: no firewall, no `sudo`, no setuid or setgid
program (the build fails if one is left), no compiler, `make`, Python or SSH
client, no EKKA command line, no credentials and no project code. A project that
needs a compiler adds it in its own image. Project code lives in a volume mounted at
`/sandbox/ekka-workspace`.

The image alone holds no OpenShell policy and no provider configuration; this
repository's setup supplies both (`desk/policy.json`, `providers/`). They are what
enforce network access and keep credentials in the gateway.
With a GitHub provider, the desk sees only a placeholder token, and the gateway
swaps in the real key on the way out. Run with plain Docker, the image has none
of those protections, and the Git helper passes on whatever `GITHUB_TOKEN`
holds.

Why the native Claude Code binary and not the npm package: OpenShell allows a
network connection per program, by the real path of the executable that opens
it. The npm package runs as `node`, so allowing it to reach Anthropic would
allow every Node.js process to. The native binary connects as
`/usr/local/bin/claude` and can be allowed on its own.

The installer builds it on the server from this checkout (`ekka-desk:local`).

## Development

The offline checks use Python's standard library:

```sh
python3 -m unittest discover -s tests
```

These checks validate this repository's configuration and helpers. They do not replace a live installation test.

## License and help

This repository is licensed under [Apache-2.0](LICENSE). Included third-party files retain their [notices](THIRD-PARTY-NOTICES.md). EKKA services and release binaries have separate terms.

For installation problems, start with [troubleshooting](docs/OPERATIONS.md#when-something-fails). Include the command, expected result, actual result, and run ID. Remove credentials before sharing output.

[EKKA](https://ekka.ai) · [EKKA documentation](https://docs.ekka.ai)
