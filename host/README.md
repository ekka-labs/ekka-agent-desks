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

The identity profile is `deploy/macos/identity-profile.sample.json` in shape. It holds the organization, and,
once the gateway is registered, Govern's answer to that registration. The security boundary of a developer's Mac is in
[Security and data](../docs/SECURITY.md#a-developers-mac).
