# ekka-desk-host

`ekka-desk-host` installs and checks one EKKA desk host. This release installs a native Apple Silicon Mac for the
developer running it: NVIDIA OpenShell's gateway and EKKA's backend adapter as verified programs, the root-owned
records EKKA's desk commands read, and the Enclave, the gateway and the adapter as that developer's own services.
With `ekka`, it is the whole installation: no shell script, no Python, no Compose and no OpenShell command line.

## Place it, once

`ekka-desk-host` asks for your password only when it runs from its root-owned copy at
`/usr/local/libexec/ekka-desk-host/ekka-desk-host`. Place that copy with this one command. `sudo` is named by its full path, and root starts
from an empty environment, so nothing of yours (your PATH, HOME or curl settings) reaches it. It first checks, as root,
that every folder down to `/usr/local/libexec/ekka-desk-host` is a real folder that only root can change (making the
missing ones). It works inside a folder root makes for it, using only the system's own programs, https only, and a
cosign it fetches into that folder and checks against its published sha256. It checks the release archive
against its sha256 file, and against its keyless signature by this repository's release workflow for exactly that
tag. Then it installs the program from those same bytes, atomically.

```sh
/usr/bin/sudo /usr/bin/env -i PATH=/usr/bin:/bin HOME=/var/root /bin/sh -euc '
v=0.1.0
L=/usr/local/libexec/ekka-desk-host
for p in /usr /usr/local /usr/local/libexec "$L"; do
  [ -e "$p" ] || /bin/mkdir -m 0755 "$p"
  if [ -L "$p" ] || [ ! -d "$p" ]; then echo "$p is a link or not a folder; make it a real folder" >&2; exit 1; fi
  m=$(/usr/bin/stat -f %Lp "$p")
  if [ "$(/usr/bin/stat -f %u "$p")" != 0 ] || [ $((0$m & 022)) != 0 ]; then
    echo "$p must be root-owned and writable only by root: /usr/sbin/chown root:wheel $p; /bin/chmod go-w $p" >&2; exit 1; fi
  if [ "$(/bin/ls -led "$p" | /usr/bin/wc -l)" -ne 1 ]; then echo "$p has an access control list; remove it: /bin/chmod -N $p" >&2; exit 1; fi
done
d=$(/usr/bin/mktemp -d /private/tmp/ekka-desk-host.XXXXXXXX); cd "$d"
r=https://github.com/ekka-labs/ekka-agent-desks/releases/download/host-v$v
f=ekka-desk-host-$v-aarch64-apple-darwin.tar.gz
for x in "$f" "$f.sha256" "$f.sig" "$f.crt"; do /usr/bin/curl -q --proto =https -fsSLo "$x" "$r/$x"; done
/usr/bin/curl -q --proto =https -fsSLo cosign https://github.com/sigstore/cosign/releases/download/v2.6.5/cosign-darwin-arm64
echo "4d41cc18f0563907c0c785b51db76e1d1af10db4422b605ba876b1758e1771ab  cosign" | /usr/bin/shasum -a 256 -c -
/bin/chmod 0700 cosign
/usr/bin/shasum -a 256 -c "$f.sha256"
./cosign verify-blob --certificate "$f.crt" --signature "$f.sig" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity "https://github.com/ekka-labs/ekka-agent-desks/.github/workflows/release-host.yml@refs/tags/host-v$v" "$f"
/usr/bin/tar -xzf "$f" ekka-desk-host
/usr/bin/install -o root -g wheel -m 0755 ekka-desk-host "$L/.ekka-desk-host.new"
/bin/mv -f "$L/.ekka-desk-host.new" /usr/local/libexec/ekka-desk-host/ekka-desk-host
cd /; /bin/rm -rf "$d"'
```

## Install and check

```sh
/usr/local/libexec/ekka-desk-host/ekka-desk-host install --profile developer-native --runtime docker-desktop \
    --env <dev|staging|prod> --org <tenant id> --identity-profile <file>
/usr/local/libexec/ekka-desk-host/ekka-desk-host status --json
/usr/local/libexec/ekka-desk-host/ekka-desk-host doctor --json
```

Desks on a developer's Mac have no CPU or memory limit of their own in this release. Docker Desktop's VM size
bounds them, and EKKA's room check still holds jobs while the VM is short of memory. `status` and `doctor` say so,
and `--desk-cpu-millicores` and `--desk-memory-mib` are refused. A later release gives a desk on a Mac its own CPU
and memory limit.

## The adapter's signing key

`install` makes one ES256 (P-256) key for the backend adapter at `/private/var/db/ekka-dev/<uid>/backend/adapter-key.pem`,
yours alone (mode 0600), once. It is never replaced silently: a key that is not safe to use, or not the one Govern
registered, is reported and left as it is, and only `install --rotate-adapter-key` replaces it (then register the new
key). `status --json` shows its public half and thumbprint as `adapter_public_jwk` and `adapter_kid`, for registering
the gateway; it never shows the key.

The adapter's configuration gets the desk-pass sign-in (`backend_gateway.signin`) only when the gateway's
registration is this installation's, Govern registered this key, and the pinned adapter release reads it. No adapter
release reads it yet, so this release never writes it, and `status` says why (`adapter_signin`).

## The gateway's one-time setup

```sh
<one-time setup authorization> | /usr/local/libexec/ekka-desk-host/ekka-desk-host gateway-setup --json
```

`ekka desk setup --local` opens the authorization (`ekds_...`) at Govern and passes it on stdin, the only place it is
read: an argument, an environment variable or a terminal is refused. The command checks the gateway answers before
it redeems the authorization once for a two-minute setup pass, then makes the `desks` workspace, adds the Enclave and
the adapter as members and imports the provider profiles, reading each back. A second run changes nothing; a run the
pass outlives stops, and a fresh authorization finishes it. Exit 0 means set up, 4 waiting, 3 refused, 1 failed.
It speaks the gateway's admin API (OpenShell v0.1.9's gRPC, from its `.proto` files vendored in
`vendor/openshell`) over TLS that trusts only this installation's CA, with the setup pass as the bearer.

## A local build (dev only)

```sh
ekka-desk-host install ... --env dev --local-build <dir>
```

`<dir>/local-build.json` names your own builds of `ekka`, the backend adapter and the desk image by sha256 (or image
id), in place of the signed releases; any part it leaves out is the release. It is refused for staging and prod.
Every check made before a program runs stays; only the release's signature is replaced by the hash. Root hashes the
adapter itself before it changes anything. `status` and `doctor` print `LOCAL BUILD, NOT A SIGNED RELEASE (dev only)`
for each replaced part, and root keeps a `local-build.json` marker beside the records.

The identity profile is `deploy/macos/identity-profile.sample.json` in shape. It holds the organization, and,
once the gateway is registered, Govern's answer to that registration. The security boundary of a developer's Mac is in
[Security and data](../docs/SECURITY.md#a-developers-mac).
