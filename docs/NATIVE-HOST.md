# Native EKKA host administration (development preview)

`ekka-desk-host` is a Python 3.9+ command for the machine that hosts EKKA desks. It calls systemd directly;
it does not execute or source `up.sh`. This first slice supports the existing default installation only.
It is not installed automatically and does not remove the existing installer or its wrapper.

As root it runs only from the root-owned copy the installer keeps, `/usr/local/lib/ekka-desks/` (refreshed by
every `up.sh` install or upgrade). Run as root from a checkout, it refuses before importing anything: a checkout that
another user can change would otherwise choose the code root runs.

```sh
sudo /usr/local/lib/ekka-desks/ekka-desk-host status
sudo /usr/local/lib/ekka-desks/ekka-desk-host stack start
sudo /usr/local/lib/ekka-desks/ekka-desk-host stack stop
sudo /usr/local/lib/ekka-desks/ekka-desk-host emergency-stop code-desk
sudo /usr/local/lib/ekka-desks/ekka-desk-host image pull registry.example/team/desk@sha256:<64-hex-digest>
sudo /usr/local/lib/ekka-desks/ekka-desk-host settle code-desk --operation <request-uuid>
sudo /usr/local/lib/ekka-desks/ekka-desk-host unhold code-desk --operation <request-uuid>
```

Help works without sudo, from a checkout too: `./ekka-desk-host --help` and `./ekka-desk-host stack --help`.

Status checks that `ekka.service` and `ekka-desks.service` are loaded and active and that the interceptor path is a
socket. It is a host-service check; it does not exercise a desk, verify a model response, or check camera processing.
It fails if the installation is incomplete or either service cannot be read.

Start requires an active Enclave and an interceptor socket. It does not unmask an emergency stop or reset a start
limit. Stop affects the desks stack and its containers, including work running there; the Enclave stays running.
Neither command changes boot enablement. Each prints the system command and reads the resulting service state;
a successful systemctl exit alone is not reported as success. A timeout is reported as unverified and never retried
automatically.

Changes are recorded before execution and after verification in `/var/log/ekka-desk-host.jsonl`, a root-owned file
with mode 0600. If the initial record cannot be written, no change runs. A symlink, hard link, non-regular file or
log with group/other permissions is refused. Tool commands receive a clean environment and no shell evaluation.

Exit codes: 0 means the requested check or service change passed, 1 means refused/failed/unverified, and 2 means
invalid arguments or a desk action requested through the host command. Desk actions are refused with their intended
native EKKA command; that message does not enable commands absent from the installed runner.

## Registry credentials

`registry login <host> <user>` validates and keeps one image-pull credential. Input is hidden at a terminal or read
from stdin; it is never a command argument. A terminal that cannot hide input is refused; pipe the credential instead. For GitHub Packages (`ghcr.io` or `*.pkg.github.com`, with
or without a port) the helper requires a classic token with exactly `read:packages` scope and checks the response from GitHub's API before attempting Docker login. A failed validation
or login preserves the previous credential. A successful credential is written atomically with mode 0600 below the
root-owned state directory, in the existing registry-file format. Docker login uses a temporary configuration that
is removed after each command. That configuration names the registry, so Docker keeps the credential in it and never
in a host credential helper (`pass` or `secretservice`), which Docker otherwise selects for an empty configuration.

`registry show` prints host and username only. `registry logout <host>` removes that host's local credential; it does
not revoke the token at its issuer. All changes require a writable root audit log before execution.

## Pulling an image

`image pull <registry>/<repository>@sha256:<digest>` pulls one immutable image and checks that Docker reports its
digest. Tags are refused. `--signed-by <certificate-identity> --issuer <https-issuer>` optionally checks the signature
before pulling; both options are required together, each with a value. Either option given, even empty, means a
signature check is required. cosign is used from `/usr/local/bin/cosign`, else `/usr/bin/cosign`, and must be
root-owned; PATH is never searched. A configured registry credential is read only from its private
root-owned file and reaches Docker login through stdin. Each command uses a fresh private Docker configuration,
removed before success is reported. An unsuccessful signature check prevents the pull. A pull acknowledgement
without the requested digest is an unverified result. No EKKA desk grant is created or changed by pulling an image.

## Recovering one unfinished change

`settle <desk> --operation <request-uuid> [--backend-id <sandbox-uuid>]` invokes the existing Python settlement
procedure directly. It requires the default stack to be active and unmasked, writes a hold before restarting the
gateway, observes the desk containers until they stop changing, and then writes one settle marker. **Restarting the
gateway stops every running desk on this host, not only the named one, and interrupts the jobs on them**: NVIDIA's
gateway stops the sandboxes it manages when it shuts down. Settle when that interruption is acceptable. The next
governed `ekka desk status <desk>` consumes the marker and determines the change's outcome; completing the host
procedure alone does not establish that outcome.

If settlement stops, the hold stays. Inspect the desk before using `unhold <desk> --operation <request-uuid>`:
removing a hold can permit the backend to reissue that operation. Unhold removes a hold only while that desk's lock
still names the operation, and one settle or unhold runs at a time on the host. A missing desk lock means nothing
holds the desk; a lock that is a link, a special file or more than one short line is refused, never printed. Neither command retries automatically. Settings
come from fixed root-owned files and the existing state folder. The host command reads desk locks as the Enclave
user and sends neither a caller's environment nor a shell expression to the host tools. Both commands audit before
execution and after completion or failure. They do not invoke `up.sh`.

## Emergency stop

`emergency-stop <desk>` is the named kill switch when governed control is unreachable. It uses the installed,
version-matched NVIDIA CLI against this installation's gateway, and names the desks' workspace (`desks`) explicitly,
so a desk of the same name in another workspace is never the one stopped. It requires root-owned settings and code,
takes the same lock as `up.sh`'s gateway administrator sessions, audits before enabling its temporary setup client,
and keeps that client's credential out of arguments and printed output. Its private sign-in folder carries an empty
system registry folder, and the registration NVIDIA's CLI kept is read back (endpoint, issuer, client) before the
secret is used to sign in. The folder is removed after the call. Failures, keyboard interrupts, SIGTERM, SIGHUP and a
closed console still disable the client and read its state back; the disable itself ignores those signals and prints
nothing. A failed or unapplied disable is reported explicitly. If the process is killed outright, the next
emergency stop first switches the client off and removes the old sign-in, and `status` reports the unfinished
session until then. Disabling the client and deleting the local sign-in do not promise immediate revocation of every
previously issued token. The stop acknowledgement alone does not prove that the desk has stopped: confirm its state.
Ordinary desk and provider changes remain governed EKKA commands. This preview does not expose arbitrary NVIDIA
commands or replace the old recovery entry point yet.

## Remaining migration

Installation, upgrades, named instances, the full walk and the allow-listed
NVIDIA recovery CLI still need native host implementations. Provider keys, people and grants belong in governed
`ekka desk` commands. The old script and shadowing wrapper can be retired once all their actions have working
replacements and the upgrade path preserves installed state. Do not use this preview to provision a second
organization on an existing host.

## Provider adapter permission during migration

The new governed provider adapter requires the gateway permission `provider:write` on its dedicated
`ekka-desk-admin` service account. The provisioning helper accepts `admin-client on --provider-writes` for that
matching adapter. Default provisioning retains the legacy scope set, and person and Enclave clients do not receive
this permission. Native installation/upgrade must select this option only with a compatible adapter and must keep
selecting it on later reconciliations. Running legacy `admin-client on` reconciles back to the old scope set.
No installed realm is changed by this source update, and the existing installer does not enable the option yet.
