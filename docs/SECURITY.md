# Security and data

[Back to the start](../README.md)

EKKA governs the work; NVIDIA OpenShell enforces the desk's execution policy. The server administrator operates the host and its credentials. This page describes the supplied server configuration.

## Permissions and desk changes

- **Job permission:** EKKA checks each plan step against the executing agent's grant before it runs.
- **Administration:** desk changes run as governed plans through the Enclave and backend adapter. Govern signs authorization for the request; the adapter checks its limits, including allowed image, policy and provider digests.
- **Separate identities:** the Enclave's job identity runs approved work. The adapter uses a separate credential for authorized desk changes. Team gateway sign-ins are read-only.
- **Requester evidence:** receipts verify the identity in Govern's signed dispatch. Server commands use the configured EKKA sign-in; that identity is not necessarily the person currently typing at the server terminal.
- **Desk identity:** jobs resolve the pinned backend ID and check the desk before commands. OpenShell 0.1.4 executes by name, so a replacement between that check and command remains a race. [Operations](OPERATIONS.md#upgrades) documents the release behavior.
- **Several jobs on one desk:** a desk can run more than one job at a time (`ekka desk create --max-sessions N`; the default is one). Each job runs inside its own `ekka-session` wall, built on Linux Landlock: it cannot list or read another job's folder or the desk's `.ekka` records, and it cannot read another job's environment, working folder or open files. One thing stays visible: the command lines of the desk's other processes, under `/proc`. NVIDIA OpenShell runs every job on a desk in one sandbox with one shared process list, Landlock cannot hide a process's command line, and narrowing `/proc` further stops Claude Code and Node from starting. EKKA never puts a job's data on a command line, and the desk image's Claude Code settings refuse reads of `/proc`. A program an agent starts can still put data on its own command line, so run work that must stay apart on separate desks, or on a desk that runs one job at a time.

The shipped desk grant is bounded. Root and people with sudo on the server remain trusted administrators. Follow [server hardening](SERVER.md#3-harden-it) and [change a desk](OPERATIONS.md#change-a-desk).

## Credentials and network access

The gateway stores connected credentials outside the desk. For the shipped Anthropic profile, Claude Code sees a placeholder; the gateway supplies the key to its authorized request to `api.anthropic.com`. Provider profiles name the destinations and programs that may use each credential.

Public GitHub repositories need no token. The shipped policy lets `git` clone and fetch over HTTPS and blocks Git push. Private repositories use the connected read-only GitHub token. The GitHub rule permits repository reads across GitHub; it is not a repository-specific allowlist.

Read the profiles in [Provider profiles](../providers/README.md), and the policy behavior in [How it works](HOW-IT-WORKS.md#what-a-desk-can-reach).

## Files and retained state

Desk programs run as a normal user. The shipped policy keeps system folders read-only and allows writes to the workspace, `/tmp` and `/dev/shm`. `/dev/shm` is a memory-backed folder that PostgreSQL and Chromium use by default.

A server question asks the agent to refresh the repository copies before answering. This is a prompt instruction, not a whole-desk wipe. Agent home state and files outside those copies can persist. Choose which agents and workloads share a desk accordingly. [Answer storage and refresh](ASK-YOUR-CODE.md#what-was-kept-and-where) describes what remains.

## Where data goes

| Data | Where it is handled |
|---|---|
| Repository files | Your server; relevant code context goes to your selected model provider for inference |
| Connected API keys | OpenShell gateway on your server; supplied to authorized provider requests |
| Question and other run inputs | EKKA Govern, as part of the workflow |
| Answer file | Desk and Enclave's local run store |
| Run evidence | Signed instructions, requester identity, outcome and output digests in the run's records |
| Optional requester name/email snapshot | Retained in local receipts and exports; it grants no authority |

`ekka receipts verify` checks the signed record chain. The answer displayed by `run show` is the Enclave's local copy; its display does not independently compare its bytes with the signed output digest.

## Server and supply chain

The server guide restricts inbound access to your selected network addresses, configures a private certificate authority and uses separate team sign-ins. Gateway startup checks require the Enclave and the pinned supervisor configuration.

Infrastructure images are pinned by digest. The backend adapter image is signature-verified. The Enclave is the EKKA release installed by EKKA's own installer, which checks the release's checksum and signature with cosign and refuses without them. The agent image is built from the committed Dockerfile. See [source and licenses](OVERVIEW.md#source-and-licenses).

These controls and signed records support your security and audit processes. Compliance depends on your organization's configuration, operations and obligations.

The Enclave runs as a systemd service on the server, not in a container: EKKA's own unit (`ekka enclave install-service`)
with no new privileges, a read-only system, an empty capability set and no setuid, as the `ekka` user, which is in no
Docker or sudo group. It shares nothing with the gateway but one socket folder, `/run/ekka`, through the `openshell` group.
Because it runs on the host's network, the unit's protections, not a container, decide what it can read and reach; Docker's
default seccomp profile does not apply to it. The vault under `/var/lib/ekka/.ekka` is readable by root, by the `ekka`
user, and by anyone holding the Docker socket, which is root-equivalent on this machine. The rest of the stack runs under
`ekka-desks.service`, bound to the Enclave, from a root-owned copy of `deploy/`; it never executes a person's checkout.
See [restart recovery](OPERATIONS.md#the-enclave-as-a-service-and-restart-recovery).
