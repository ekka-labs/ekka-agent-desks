# ekka-desk-host

`ekka-desk-host` installs and checks one EKKA desk host. This release installs a native Apple Silicon Mac for the
developer running it: NVIDIA OpenShell's gateway and EKKA's backend adapter as verified programs, the root-owned
records EKKA's desk commands read, and the Enclave, the gateway and the adapter as that developer's own services.
With `ekka`, it is the whole installation: no shell script, no Python, no Compose and no OpenShell command line.

## Place it, once

`ekka-desk-host` asks for your password only when it runs from its root-owned copy at
`/usr/local/libexec/ekka-desk-host/ekka-desk-host`. Place that copy with this one command. It runs as root inside a
folder root makes for it, so nothing else on the Mac can change what it checks. It uses only the system's own programs
and a cosign it fetches into that folder and checks against its published sha256. It checks the release archive
against its sha256 file, and against its keyless signature by this repository's release workflow for exactly that
tag. Then it installs the program from those same bytes, atomically.

```sh
sudo /bin/sh -euc '
v=0.1.0
d=$(/usr/bin/mktemp -d /private/tmp/ekka-desk-host.XXXXXXXX); cd "$d"
r=https://github.com/ekka-labs/ekka-agent-desks/releases/download/host-v$v
f=ekka-desk-host-$v-aarch64-apple-darwin.tar.gz
for x in "$f" "$f.sha256" "$f.sig" "$f.crt"; do /usr/bin/curl -fsSLo "$x" "$r/$x"; done
/usr/bin/curl -fsSLo cosign https://github.com/sigstore/cosign/releases/download/v2.6.5/cosign-darwin-arm64
echo "4d41cc18f0563907c0c785b51db76e1d1af10db4422b605ba876b1758e1771ab  cosign" | /usr/bin/shasum -a 256 -c -
/bin/chmod 0700 cosign
/usr/bin/shasum -a 256 -c "$f.sha256"
./cosign verify-blob --certificate "$f.crt" --signature "$f.sig" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity "https://github.com/ekka-labs/ekka-agent-desks/.github/workflows/release-host.yml@refs/tags/host-v$v" "$f"
/usr/bin/tar -xzf "$f" ekka-desk-host
/usr/bin/install -d -o root -g wheel -m 0755 /usr/local/libexec/ekka-desk-host
/usr/bin/install -o root -g wheel -m 0755 ekka-desk-host /usr/local/libexec/ekka-desk-host/.ekka-desk-host.new
/bin/mv -f /usr/local/libexec/ekka-desk-host/.ekka-desk-host.new /usr/local/libexec/ekka-desk-host/ekka-desk-host
cd /; /bin/rm -rf "$d"'
```

## Install and check

```sh
/usr/local/libexec/ekka-desk-host/ekka-desk-host install --profile developer-native --runtime docker-desktop \
    --env <dev|staging|prod> --org <tenant id> --identity-profile <file>
/usr/local/libexec/ekka-desk-host/ekka-desk-host status --json
/usr/local/libexec/ekka-desk-host/ekka-desk-host doctor --json
```

The identity profile is `deploy/macos/identity-profile.sample.json` in shape. It holds the organization, and,
once the gateway is registered, Govern's answer to that registration. The security boundary of a developer's Mac is in
[Security and data](../docs/SECURITY.md#a-developers-mac).
