# Commands

[Back to the start](../README.md)

Everything you do with desks is an `ekka` command, and EKKA checks each one ([How it works](HOW-IT-WORKS.md)). Add `--help` to any command for every option.

## Where to run commands

| Task | Run it here |
|---|---|
| Read desk lists, logs, policies, or connections | Any computer signed in with `ekka desk login`. |
| Read pins with `show`, check live status, or change a desk | The installed server, as root (`sudo -i`), using `ekka desk <command>`. |
| Run the example setup or question plan | The installed server, using its configured EKKA sign-in. |

[Desk administration](OPERATIONS.md#change-a-desk) explains the permissions and sign-in used for changes.

## Sign in

| Command | What it does |
|---|---|
| `ekka desk login` | Sign in to the desks server. Opens your browser. |
| `ekka desk logout` | Remove your sign-in from this computer. |
| `ekka desk backend show` | Which desks server this computer uses, and how you sign in there. |
| `ekka desk backend set <file.json>` | Point this computer at a desks server. The people bundle's `install.sh` does this for you. |

```sh
./install.sh desks        # once, from the bundle your server's administrator gives you
ekka desk login
```

## Keys

A *provider profile* says which programs on a desk may use a key, and which hosts the key may be sent to. Keys belong to the company: one person connects each key once, and every desk on the server can be given it. One key per command, read from standard input, never typed as an argument.

| Command | What it does |
|---|---|
| `ekka desk profile list` | The kinds of connection the server knows (`claude-code`, `github`, ...). |
| `ekka desk profile show <profile>` | One profile in plain words: the key it takes, which programs may use it, which hosts it reaches. |
| `ekka desk connect` | The kinds of connection this server knows. Naming one (`ekka desk connect <profile>`) is refused: a key is set on the server, `<key> \| sudo ekka desk connect <profile>` ([Operations](OPERATIONS.md#connect-a-providers-key)). |
| `ekka desk connections` | The keys your desks may use (names only, never values). |
| `ekka desk disconnect <name>` | On the installed machine: detach a key from every desk that uses it. |
| `ekka desk profile add <file.json>` | Refused. A kind of connection is added on the server: its `.yaml` in `/var/lib/ekka-agent-desks/providers.local/`, then `sudo ./up.sh profiles`. |

```sh
ekka desk profile show claude-code
ekka desk connect                   # the kinds of connection this server knows
```

What `ekka desk profile show claude-code` says about the key, before anyone sets it:

```text
claude-code: Claude Code
  api_key: Anthropic API key used by Claude Code, sent in header x-api-key
    may reach api.anthropic.com
    used only by /usr/bin/claude, /usr/local/bin/claude
```

The key itself is set on the server, from a pipe: `sudo cat /root/anthropic.key | sudo ekka desk connect claude-code`. It is never an argument, so it never shows up in your shell history or the process list. `up.sh connect` takes a profile with one key; one with several, such as `codex`, is refused there. A profile with `credentials: []` takes none: `sudo ekka desk connect <profile> </dev/null`.

## Desks

| Command | What it does |
|---|---|
| `ekka desk create <name> --provider <profile> ...` | On the installed machine: make a desk with the keys it may use. It gets the setup's desk image and policy; `--policy <file>` sets another policy. |
| `ekka desk list` | The desks on the server. |
| `ekka desk show <name>` | On the installed machine: one desk's folders, pins and required grant. |
| `ekka desk stop <name>` | On the installed machine: stop a desk. Its files stay. |
| `ekka desk start <name>` | On the installed machine: start it again, and wait until it is ready. |
| `ekka desk status <name>` | On the installed machine: the desk's live state, read through EKKA. While a change is still running it says so. |
| `ekka desk logs <name> [-f]` | A desk's recent log lines; `-f` follows them. |
| `ekka desk delete <name>` | On the installed machine: delete a desk and its work folder. Deletion retires its old pin; a new desk of that name is registered and pinned anew. An unexpected replacement of a still-pinned desk needs approval (`repin`, below) before work runs. |

```sh
ekka desk create code-desk --provider claude-code   # on the installed machine
ekka desk show code-desk                             # the Enclave's pins and details
```

Connect the keys **before** you make the desk: a desk names the keys it may use when it is made.

## Files on a desk

Nothing runs in a desk outside EKKA, and a person's `ekka` copies nothing. The first two are refused, and the third is
no longer a command. The server's administrator can copy files with the two commands under the table:

| Command | What it does |
|---|---|
| `ekka desk upload <name> <local> [<folder>]` | Refused. Put the files in the repository the desk clones. |
| `ekka desk download <name> <path> [<folder>]` | Refused. |
| `ekka desk shell <name> [-- <command>]` | Not a command since ekka 0.1.119: `ekka` answers "unrecognized subcommand". To work with a desk's agent, run a plan whose job step names the desk: `ekka plan run <plan>`. |

| On the server, as its administrator | What it does |
|---|---|
| `sudo ./up.sh openshell sandbox upload <desk> <local path> [/sandbox/<folder>/]` | Copies a file or a folder from this machine into the desk, with NVIDIA OpenShell's own upload. The folder on the desk is under `/sandbox`. `--no-git-ignore` uploads everything; without it, a folder that is a git checkout is filtered by its `.gitignore`. |
| `sudo ./up.sh openshell sandbox download <desk> /sandbox/<path> <empty folder>` | Copies a file or a folder out of the desk into a folder on this machine that exists, is empty, is the administrator's and that nobody else can write (`sudo install -d -m 0700 <folder>`). Afterwards every link and special file the desk sent is removed and every setuid, setgid and write-by-others bit is cleared, and the command says what it removed. |

Both name the desk, take no other flag, and are written to `/var/lib/ekka-agent-desks/openshell-admin.log` with the
person who ran sudo. They are outside EKKA's record: no receipt is written. What comes out of a desk was packed
inside it; read it as you would read a file from a stranger ([Operations](OPERATIONS.md#copy-files-into-and-out-of-a-desk)).

## What a desk may reach

| Command | What it does |
|---|---|
| `ekka desk policy show <name>` | The desk's policy in plain words. |
| `ekka desk policy check <file>` | Check a policy file exactly as `ekka desk create` reads it. |
| `ekka desk policy set <name> <file>` | On the installed machine: replace a live desk's policy. |
| `ekka desk allow <name> --program <path> --host <host>` | On the installed machine: let one program reach one host. Add `--read-only`, `--port`, `--path` to narrow it. |
| `ekka desk deny <name> --program <path> --host <host>` | On the installed machine: stop one program reaching one host. |

```sh
ekka desk allow code-desk --program /usr/bin/curl --host registry.npmjs.org --read-only
ekka desk policy show code-desk
```

A policy change runs on the installed machine like every desk change, and never while a job is running on that desk. It first reads the desk's current policy, so the Enclave needs its own read-only desk sign-in, once ([Change a desk](OPERATIONS.md#change-a-desk)). A change is stored at once and takes effect when the desk loads it, a few seconds later (`policy show` says "pending" until then). **Work on that desk then waits** until a person approves the new policy. The Enclave notices the change within about a minute; then approve it on the installed machine: `ekka desk repin <name>`.

Policy files in a server command are read **inside the Enclave**, not from your host's working directory. The installer sets its default policy there. To use a policy file on the host, pass it on standard input:

```sh
cat policy.json | ekka desk policy set code-desk /dev/stdin --yes
```

Read the file before running this command; `--yes` confirms the change without an interactive prompt. The same input path works with `desk create --policy /dev/stdin`.

### Onboarding a project: the discovery window

The desks grant allows the install's one image and one policy, plus those of each project added to it (below).
The installer writes the input records, ensures plain API read access, and calls `ekka desk grant update --yes`
(EKKA 0.6.12 or newer) to build and apply the limits. It confirms and saves the CLI's `keep` answer;
see [Updating the desks grant](OPERATIONS.md#updating-the-desks-grant). To learn what a new project's build needs, the server's administrator
opens a window for disposable discovery desks, created from the project's own image with the shipped policy. While the window
is open, the backend adapter may switch eligible desks to NVIDIA OpenShell's auto approval mode: the
build's network requests are approved as they arrive, except those OpenShell holds as risky, and every one is recorded.
The adapter turns auto mode on only after it reads the setting back as applied, and only then writes a permit for that
desk; the Enclave's gateway interceptor lets the desk's proposals through only while that permit is valid. The records
become the project's recommended policy, which a person reviews before any desk uses it. No policy file, address range
or port is added for the window.

| Command | What it does |
|---|---|
| `<token> \| sudo ekka desk registry login <host> <user>` | A registry's read-only credential, kept root-only on the server for image pulls. For GitHub Packages the token must be classic with the scope `read:packages` only, and that is checked before it is kept. |
| `sudo ekka desk registry show`, `sudo ekka desk registry logout <host>` | The registries with a kept credential; forget one. |
| `sudo ekka desk image pull <registry>/<name>@sha256:<64 hex> [--signed-by <identity> --issuer <url>]` | The project image onto this machine, by digest, through a throwaway Docker login that is deleted after; with `--signed-by`, cosign checks the signature first. |
| `ekka desk grant discovery --image <ref> --providers <a,b> [--minutes 60] [--yes] [--json]` | Opens the window in the grant itself. The image must be `<registry>/<name>@sha256:<64 lowercase hex>`. Name 1 to 8 distinct providers already in this server's limits; minutes range from 1 to 240. As root on the server, confirm with the literal word `yes`, or pass `--yes`. |
| `ekka desk grant show [--json]` | Reads live facts and previews an update, including the open window's image digests, providers and expiry from the active grant. Changes nothing. |
| `ekka desk grant restore [--yes] [--json]` | Rebuilds the limits without the discovery block, including an expired one, and without images supplied only by that block. Keeps project records. Uses the same confirmation as discovery. With no block, succeeds without changing a grant. |

An update carries an unexpired window unchanged, including its original expiry. An expired window is dropped on the
next update. A window restricts eligible desks; it does not enforce a one-desk quota. Restore does not revoke
already-issued desk permits: return the desk to manual approval mode or delete it at the end of discovery.
Run these CLI commands as root on the installed server (`sudo -i`).

### A project's own desk: its image and its policy

A project's desk runs the project's own image (the desk image plus the project's tools) and may have its own policy.
Both are added to the grant, beside the shipped image and policy, until they are removed. A window is temporary and ends; a project is for the desks the project works on and stays through an installer run.

| Command | What it does |
|---|---|
| `sudo ekka desk grant project add <name> --image sha256:<64 hex> --policy <file>` | Adds the project to the grant: its image, by the content ID of an image already on this machine (`docker image inspect --format '{{.Id}}' <tag>`), and its policy, by its digest. Refused, with nothing changed, when the image is not on this machine, when the policy breaks the [file safety floors](OPERATIONS.md#project-file-safety-floors), changes the user or Landlock setting, or opens a host outside the server's ceiling. Prints the line that creates the project's desk. Run it again after a rebuild of the image or a change to the policy. |
| `sudo ekka desk grant project remove <name>` | Takes the project out of the grant: no new desk may be created from its image or with its policy. Its desks are not deleted. |

A project owns its network rules within the server's host ceiling and its file rules within the safety floors.
For example, project `acme` can copy `desk/policy.json`, add `/opt/project-tools` to `filesystem.readOnly` and
`/var/cache/acme` to `filesystem.readWrite`, then pass that file to `project add`; prepare those folders in its image.
Keep every shipped read-only entry, `includeWorkdir`, the non-root user/group, Landlock and the policy version.

## Who may use the desks

Give a person a sign-in account and a place in the desk workspace, on the server:

```sh
sudo ekka desk invite member member@example.com
```

| Command | What it does |
|---|---|
| `ekka desk access list` | The workspace's members and their roles. |
| `ekka desk access add <person>` | Refused. A person is added on the server: `sudo ekka desk invite <username> <email>`. |
| `ekka desk access remove <person>` | Refused. A person is removed on the server: `sudo ekka desk revoke <username>`. |

## Plans, grants and records

Work on a desk is a *plan*: steps EKKA checks, runs on your Enclave, and signs.

| Command | What it does |
|---|---|
| `ekka plan list` | The plans you can run. |
| `ekka plan run <plan> --input <key>=<value>` | Run a plan and wait for it. |
| `ekka plan validate <file>` | Check a plan file; prints any grant it still needs. |
| `ekka plan create <file>` | Create a plan from a file. |
| `ekka plan schedule <plan> --every 1h` | Run it on a schedule. |
| `ekka plan schedules` | Every schedule, with its next and last run. |
| `ekka plan unschedule <id>` | Stop a schedule. |
| `ekka gate grant list` | The grants your organization has issued. |
| `ekka gate grant revoke <id>` | Take one back. |
| `ekka decide list` | The decisions waiting on you. |
| `ekka decide answer <id>` | Answer one. `ekka decide show <id>` first shows everything about it. |
| `ekka run list` | What your organization has run, newest first. |
| `ekka run show <id>` | EKKA's recorded decisions for one run. |
| `ekka receipts list` | Recent runs with a signed record. |
| `ekka receipts show <run>` | What EKKA recorded for one run, in plain English. |
| `ekka receipts verify` | Check that nothing in the signed record was changed after the fact. |

**Where to run them.** Running a plan goes through your Enclave, on the machine you installed on: `sudo -i`, then `ekka plan run ...` there. The other commands talk to EKKA directly, so they work from any computer signed in with `ekka login`.

```sh
ekka plan run ekka.example.desk.ask.codeDesk.v1 --input question="Where do we retry failed payments?"
sudo ekka desk plans business-desk     # the setup and ask plans for one more desk
ekka receipts list
```

## On the installed machine

Rarely needed: desks register themselves. Run these on the machine you installed on, through `up.sh`.

| Command | What it does |
|---|---|
| `ekka desk repin <name>` | Approve the desk now holding a name, after it was replaced. Until then, no work runs on it. |
| `ekka desk add <file.json>` | Register a desk that was not made with `ekka desk create`. |

## Related workflow commands

- On the server, as root (`sudo -i`): `ekka run show --output <run-id>` shows a run's answer, `ekka receipts show <run-id>` its record. This setup serves no downloads to laptops.
- `ekka agent deny desks --everyone` removes shared permission to run the desks agent's plans. Use it only when you intend to restrict team access.
