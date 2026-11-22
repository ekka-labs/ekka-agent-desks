# Native EKKA host administration (development preview)

`ekka-desk-host` is a Python 3.9+ command for the machine that hosts EKKA desks. It calls systemd directly;
it does not execute or source `up.sh`. This first slice supports the existing default installation only.
It is not installed automatically and does not remove the existing installer or its wrapper.

From a trusted checkout on the installed Linux host:

```sh
sudo ./ekka-desk-host status
sudo ./ekka-desk-host stack start
sudo ./ekka-desk-host stack stop
```

Help works without sudo: `./ekka-desk-host --help` and `./ekka-desk-host stack --help`.

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

## Remaining migration

Installation, upgrades, named instances, registry/image management, settlement, the full walk and the allow-listed
NVIDIA recovery CLI still need native host implementations. Provider keys, people and grants belong in governed
`ekka desk` commands. The old script and shadowing wrapper can be retired once all their actions have working
replacements and the upgrade path preserves installed state. Do not use this preview to provision a second
organization on an existing host.
