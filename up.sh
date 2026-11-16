#!/usr/bin/env bash
# EKKA Agent Desks, on NVIDIA OpenShell: one command from a clean Linux machine to a working desk.
#
#   sudo ./up.sh server <name>         one machine others reach by <name> (DNS points <name> here)
#   sudo ./up.sh status                what is done, and what is next
#   sudo ./up.sh profiles              put providers/ into the gateway again (after an update of this repository);
#                                      a profile in $DESKS_STATE/providers.local/ wins and is never replaced
#   sudo ekka desk invite <user> <email>  one more person who uses desks: a sign-in and a place in the desk workspace
#   sudo ekka desk revoke <user>        that person taken off: sign-in disabled, signed out, out of the desk workspace
#   sudo ekka desk plans <desk>         the setup and ask plans for one more desk (code-desk has them from the install)
#   sudo -i, then ekka <command>       this machine's Enclave, as its own user (the installed /usr/local/sbin/ekka);
#                                      `sudo ./up.sh ekka <command>` is the same call for scripts
#   <key> | sudo ekka desk connect <provider>  set a provider's key on this machine, read from stdin only
#   sudo ekka desk connect <provider> </dev/null  a profile with `credentials: []` (public hosts): its provider, no key
#   (each of the four above is this script's verb, run by the installed ekka wrapper from its root-owned snapshot)
#   sudo ./up.sh openshell <command>   NVIDIA's openshell CLI as the gateway's administrator, e.g. sudo ./up.sh openshell provider list
#   sudo ./up.sh walk                  run every documented command against this installation, and check each
#   sudo ./up.sh desks settle <desk> --operation <request id>  settle ONE unfinished desk change after the desk
#                                      stopped changing; see docs/OPERATIONS.md
#   sudo ./up.sh desks unhold <desk> --operation <request id>  remove the hold a settle that stopped left, after
#                                      checking the desk
#
# Run it again at any time: every step checks first and skips what is done. It stops once, for your EKKA
# sign-in, prints the exact command, and carries on from there the next time you run it.
#
# Settings (environment): EKKA_ENV       the EKKA service this desk machine joins (empty: the ekka CLI default)
#                         EKKA_VERSION   the Enclave release (default below)
#                         AGENT          the provider profile of your desk's agent: claude-code (default) or codex;
#                                        see providers/README.md
#                         OPENSHELL_TELEMETRY  off (default) or on: NVIDIA OpenShell's usage reporting
#                         ADMIN_EMAIL    the desk gateway's first administrator (asked for when needed)
#                         EKKA_ORG       the EKKA organization this server's Enclave joins (asked for when needed)
#                         DESKS_AGENT    the agent that owns desk plans (default: desks)
#                         DESKS_ADDRESS  server mode: the address people reach this machine at (default: its own;
#                                        set it on a cloud machine behind NAT, such as its Elastic IP on AWS)
set -euo pipefail
cd "$(dirname "$0")"; ROOT=$PWD
# shellcheck source=deploy/lib.sh
. deploy/lib.sh                      # enclave_ekka, ENCLAVE_HOME: the one way scripts reach the native Enclave
SNAPSHOT=/usr/local/lib/ekka-desks   # root-owned copy of deploy/ and tools/ the supervisor unit runs from
export DESKS_STATE=${DESKS_STATE:-/var/lib/ekka-agent-desks}
# A folder-mode rerun must keep this installation's environment and release, not reset them.
EKKA_VERSION=${EKKA_VERSION:-$(python3 tools/workspace_policy.py retained "$DESKS_STATE" EKKA_VERSION 0.6.8)}
EKKA_ENV=${EKKA_ENV:-$(python3 tools/workspace_policy.py retained "$DESKS_STATE" EKKA_ENV prod)}
export EKKA_ENV
AGENT=${AGENT:-claude-code}
OPENSHELL_TELEMETRY=${OPENSHELL_TELEMETRY:-off}
OPENSHELL_TAG=v0.1.4
# EKKA desk administration requires the compatible Enclave release below.
# Upgrade the integration and Enclave together. The release must support governed desk
# changes through the two general plans, per-run output collection, verified requester identities,
# and conversation leases.
# OpenShell addresses commands by desk name. Identity checks narrow the replacement race
# before dispatch but do not eliminate it. See docs/SECURITY.md for the trust boundaries.
DESK_ADMIN_MIN_EKKA=0.6.8
COMPOSE_VER=v5.6.0
BUILDX_VER=v0.38.0
# Every download, by this machine's processor type: the publisher's own file name, and the sha256 the publisher
# lists for that exact file (Docker: checksums.txt beside each release; NVIDIA: openshell-checksums-sha256.txt).
# Any other processor type has no pins and step_preflight stops it.
MACHINE=$(uname -m)
case $MACHINE in
  x86_64)
    COMPOSE_FILE=docker-compose-linux-x86_64
    COMPOSE_SHA=40343e21ca777173e69cff5dbafeb37c6f81f3b0d57d9e597f036e95eb63e76a
    BUILDX_FILE=buildx-$BUILDX_VER.linux-amd64
    BUILDX_SHA=4fe4cc38adf48169132749b6ca22a990928db0118e3407584ee553723115d287
    OPENSHELL_CLI_FILE=openshell-x86_64-unknown-linux-musl.tar.gz
    OPENSHELL_CLI_SHA=2b65178e62e1ece1d90d482555e9f1f98ff0296e058409b33418104b6333df07
    COSIGN_FILE=cosign-linux-amd64 ;;
  aarch64)
    COMPOSE_FILE=docker-compose-linux-aarch64
    COMPOSE_SHA=733ec76717ceb59052a9609b9dadfb523b2df8eab57a54212872d10a58078ea2
    BUILDX_FILE=buildx-$BUILDX_VER.linux-arm64
    BUILDX_SHA=38e890e1a162bfdbf32fbe91404991dc4fc28e55b0de901b34374a061bab4d2c
    OPENSHELL_CLI_FILE=openshell-aarch64-unknown-linux-musl.tar.gz
    OPENSHELL_CLI_SHA=1cd6e63597e1947c44a753bf5352f949e8d8d02e344af92ab899b7c111112d95
    COSIGN_FILE=cosign-linux-arm64 ;;
  *) COMPOSE_FILE=; COMPOSE_SHA=; BUILDX_FILE=; BUILDX_SHA=; OPENSHELL_CLI_FILE=; OPENSHELL_CLI_SHA=; COSIGN_FILE= ;;
esac
PLUGINS=/usr/local/lib/docker/cli-plugins
DONE=$DESKS_STATE/up
DESKS_AGENT=${DESKS_AGENT:-desks}   # the agent that owns desk plans; never the organization's core agent
OS=$DESKS_STATE/bin/openshell   # NVIDIA's CLI, pinned; never whatever is on the PATH

say()  { printf '\033[1m==\033[0m %s\n' "$*"; }
ok()   { printf '   ok: %s\n' "$*"; }
die()  { printf 'up: %s\n' "$*" >&2; exit 1; }
done_() { install -d -m 0700 "$DONE"; date -u +%FT%TZ > "$DONE/$1"; }
is_done() { [[ -f $DONE/$1 ]]; }
stop_for_person() {  # prints what a person must do, then stops; the next run continues
  printf '\n\033[1m-- ACTION NEEDED --\033[0m\n%s\n\nThen run this again: sudo ./up.sh %s\n' "$1" "$MODE_ARGS"; exit 0; }
# A terminal is attached when a person runs this; a script or an agent has none. Tests set INTERACTIVE themselves.
# Never inside `$( )`: there stdout is the capture pipe and `-t 1` is always false (measured 2026-10-31: the sign-in
# stopped for a person sitting at the terminal).
detect_interactive() {
  [[ -n ${INTERACTIVE+x} ]] && return 0
  if [[ -t 0 && -t 1 ]]; then INTERACTIVE=1; else INTERACTIVE=; fi
}
detect_interactive
# A wait that shows it is alive: `wait_for "<what>" <seconds> <command...>` prints the reason and the limit, a dot every
# try, then how long it took; the caller decides what a timeout means. Measured 2026-10-31: silent waits of a minute or
# two read as a hang.
wait_for() {
  local what=$1 limit=$2 step=${WAIT_STEP:-2}; shift 2
  local start=$SECONDS
  "$@" && return 0   # answers at once: nothing to say
  printf '   waiting for %s (up to %s s) ' "$what" "$limit"
  while :; do
    (( SECONDS - start >= limit )) && { printf ' not yet after %s s\n' "$limit"; return 1; }
    printf '.'; sleep "$step"
    if "$@"; then printf ' ok (%s s)\n' "$(( SECONDS - start ))"; return 0; fi
  done
}

fetch_pinned() {  # url dest sha256 mode
  local tmp; tmp=$(mktemp)
  curl -fsSL "$1" -o "$tmp" || { rm -f "$tmp"; die "could not download $1"; }
  echo "$3  $tmp" | sha256sum -c - >/dev/null 2>&1 || { rm -f "$tmp"; die "$1 does not match its pinned sha256; nothing installed"; }
  install -m "$4" "$tmp" "$2"; rm -f "$tmp"
}

landlock_abi() {
  python3 -c 'import ctypes; print(ctypes.CDLL(None, use_errno=True).syscall(444, None, 0, 1))' 2>/dev/null || echo -1
}

step_preflight() {
  say "this machine"
  [[ $(uname -s) == Linux ]] || die "desks run on Linux (NVIDIA OpenShell's sandbox needs Linux Landlock)"
  [[ $(id -u) == 0 ]] || die "run with sudo: setup gives each key to the one user that reads it"
  [[ -n $OPENSHELL_CLI_SHA ]] || die "this machine's processor type is $MACHINE; desks install on x86_64 and aarch64 only"
  for t in curl python3 openssl sha256sum runuser systemctl; do command -v $t >/dev/null || die "$t is missing"; done
  [[ -d /run/systemd/system ]] || die "systemd is not running this machine; the Enclave runs as a systemd service"
  refuse_if_renamed  # before anything is written: a new name would reach up.env and /etc/hosts and nothing init made
  refuse_if_masked   # first, so "nothing was changed" is true: measured on the walk box, the check inside step_start came after every earlier step
  command -v cosign >/dev/null || die "cosign is missing: the EKKA installer checks the release signature with it. Install it first:
  sudo curl -fsSLo /usr/local/bin/cosign https://github.com/sigstore/cosign/releases/latest/download/$COSIGN_FILE && sudo chmod +x /usr/local/bin/cosign"
  local abi; abi=$(landlock_abi)
  (( abi >= 3 )) || die "the kernel's Landlock ABI is $abi; NVIDIA OpenShell needs 3 or newer (Linux 6.2+). On Amazon Linux 2023, install kernel6.18 and reboot"
  ok "Linux $(uname -r), Landlock ABI $abi"
  docker info >/dev/null 2>&1 || die "Docker is not running"
  install -d -m 0755 "$PLUGINS"
  docker compose version >/dev/null 2>&1 || { fetch_pinned "https://github.com/docker/compose/releases/download/$COMPOSE_VER/$COMPOSE_FILE" "$PLUGINS/docker-compose" "$COMPOSE_SHA" 0755; ok "installed Docker Compose $COMPOSE_VER ($MACHINE)"; }
  docker buildx version >/dev/null 2>&1 || { fetch_pinned "https://github.com/docker/buildx/releases/download/$BUILDX_VER/$BUILDX_FILE" "$PLUGINS/docker-buildx" "$BUILDX_SHA" 0755; ok "installed Docker buildx $BUILDX_VER ($MACHINE)"; }
  ok "$(docker --version | cut -d, -f1), $(docker compose version --short 2>/dev/null | sed 's/^/compose /'), buildx $(docker buildx version | awk '{print $2}')"
  [[ -f providers/$AGENT.json ]] || die "no provider profile for AGENT=$AGENT; see providers/README.md"
  python3 -m unittest tests.test_providers >/dev/null 2>&1 || die "providers/ does not match providers/PIN.json; nothing was changed"
  ok "agent profile: $AGENT (NVIDIA OpenShell $OPENSHELL_TAG, pinned)"
  release_gate
}

release_gate() {  # the Enclave release must run desk changes through EKKA; this setup works with nothing older
  [[ -n $DESK_ADMIN_MIN_EKKA ]] \
    || die "this setup needs the EKKA release that runs desk changes through EKKA, and up.sh names none yet"
  local rc=0; python3 tools/release_gate.py "$EKKA_VERSION" "$DESK_ADMIN_MIN_EKKA" || rc=$?
  (( rc == 2 )) && die "the Enclave release '$EKKA_VERSION' is not a release number"
  (( rc == 1 )) && die "this setup needs EKKA $DESK_ADMIN_MIN_EKKA or newer, and this machine runs $EKKA_VERSION. This setup and the Enclave upgrade together: run again with EKKA_VERSION=$DESK_ADMIN_MIN_EKKA"
  ok "EKKA $EKKA_VERSION runs desk changes through EKKA (needs $DESK_ADMIN_MIN_EKKA or newer)"
}

step_host_accounts() {  # the Enclave's user and the shared group, made by systemd from deploy/host; refused by name when unsafe
  say "the Enclave's account"
  local uid name
  if uid=$(id -u ekka 2>/dev/null); then
    [[ $uid == 2000 ]] || die "a user 'ekka' exists with uid $uid, not 2000; this setup's Enclave runs as uid 2000. Remove or rename it first"
  fi
  if name=$(getent passwd 2000 | cut -d: -f1) && [[ -n $name && $name != ekka ]]; then
    die "uid 2000 belongs to '$name', not 'ekka'; this setup's Enclave runs as uid 2000. Move that account first"
  fi
  local g; for g in docker sudo; do
    id -nG ekka 2>/dev/null | tr ' ' '\n' | grep -qx "$g" && die "the 'ekka' user is in group '$g'; the Enclave never holds Docker or sudo. Remove it from '$g' first"
  done
  local ogid; if ogid=$(getent group openshell | cut -d: -f3) && [[ -n $ogid && $ogid == 1000 ]]; then
    die "group 'openshell' has gid 1000, the first person's gid on Ubuntu; it must be its own group. Remove it and run again"
  fi
  # Ubuntu ships neither folder until something needs it (measured on a fresh 24.04 server).
  install -d -m 0755 /etc/sysusers.d /etc/tmpfiles.d
  install -m 0644 -o root -g root deploy/host/sysusers.d/ekka-desks.conf /etc/sysusers.d/ekka-desks.conf
  install -m 0644 -o root -g root deploy/host/tmpfiles.d/ekka-desks.conf /etc/tmpfiles.d/ekka-desks.conf
  systemd-sysusers ekka-desks.conf >/dev/null || die "systemd-sysusers could not make the ekka user and the openshell group"
  systemd-tmpfiles --create ekka-desks.conf >/dev/null || die "systemd-tmpfiles could not make the Enclave's folders"
  [[ $(id -u ekka) == 2000 ]] || die "the ekka user is not uid 2000 after systemd-sysusers"
  getent group openshell >/dev/null || die "the openshell group is missing after systemd-sysusers"
  [[ $(stat -c '%U:%G %a' /var/lib/ekka/.ekka) == "ekka:ekka 700" ]] || die "/var/lib/ekka/.ekka is not ekka:ekka 0700"
  [[ $(stat -c '%U:%G %a' /run/ekka) == "ekka:openshell 750" ]] || die "/run/ekka is not ekka:openshell 0750"
  id -nG ubuntu 2>/dev/null | tr ' ' '\n' | grep -qx openshell && die "the 'ubuntu' user is in group 'openshell': it could reach the Enclave's interceptor socket. Remove it from the group"
  ok "user ekka (uid 2000), group openshell (gid $(getent group openshell | cut -d: -f3)), folders /var/lib/ekka/.ekka, /run/ekka, /run/ekka-backend"
}

openshell_gid() { getent group openshell | cut -d: -f3; }

host_env_files() {  # what the native Enclave and the installed `ekka` wrapper read: root-owned, no secret in either
  install -d -m 0755 /etc/ekka
  printf 'EKKA_ENV=%s\n' "${EKKA_ENV:-prod}" > /etc/ekka/desks.env.new && chmod 0644 /etc/ekka/desks.env.new && mv -f /etc/ekka/desks.env.new /etc/ekka/desks.env
  # The Enclave reaches the issuer and the gateway by this machine's public name, through the edge on this machine.
  grep -q " $NAME\$" /etc/hosts 2>/dev/null || getent hosts "$NAME" >/dev/null || echo "127.0.0.1 $NAME" >> /etc/hosts
}

step_settings() {
  install -d -m 0755 "$DESKS_STATE"
  local bind=0.0.0.0
  # The address people's computers use. This machine's own address is right on a server with a public address on its
  # network card (OVH), and wrong on a cloud machine behind NAT (AWS, GCP, Azure), whose card holds a private address.
  local addr=${DESKS_ADDRESS:-$(ip -4 route get 1.1.1.1 | awk '{for(i=1;i<NF;i++) if($i=="src") print $(i+1)}')}
  if [[ $MODE == server && -z ${DESKS_ADDRESS:-} && $addr =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.) ]]; then
    printf '   note: people will reach this server at %s, a private address. Behind a cloud NAT, run again with\n' "$addr"
    printf '         DESKS_ADDRESS=<the address your VPN reaches it at>, for example its Elastic IP on AWS.\n'
  fi
  # The backend adapter's image, pinned by digest. Read before up.env is written: a missing pin stops here.
  local backend_image
  # Derived from the pin's one registry value and its digest (tools/backend_image.py); refused while unpinned.
  backend_image=$(python3 tools/backend_image.py image 2>/dev/null) \
    || die "deploy/pins.json names no ekka-backend image; this setup installs the backend adapter"
  # Read by deploy/setup.sh and by every compose call through `setup.sh compose`.
  { echo "DESKS_NAME=$NAME"; echo "DESKS_EDGE_BIND=$bind"; echo "DESKS_GATEWAY_BIND=$bind"
    echo "DESKS_DOCKER_GID=$(stat -c %g /var/run/docker.sock)"
    echo "DESKS_OPENSHELL_GID=$(openshell_gid)"   # compose group_add: the gateway reaches the interceptor socket
    # The long-lived services ekka-desks.service runs in the foreground; the adapter joins once desk administration is on.
    # Quoted: setup.sh sources up.env, and an unquoted list would run `keycloak` as a command (measured on the walk box).
    if [[ -f $DESKS_STATE/backend/config.json ]]; then echo 'DESKS_STACK_SERVICES="keycloak-db keycloak edge gateway ekka-backend"'
    else echo 'DESKS_STACK_SERVICES="keycloak-db keycloak edge gateway"'; fi
    echo "EKKA_VERSION=$EKKA_VERSION"; echo "EKKA_ENV=${EKKA_ENV:-prod}"
    # The backend adapter is on only once its configuration exists. step_desk_admin writes it after this
    # machine is enrolled; turned on before that, the first `up` would start the adapter on a missing file
    # (Compose honors COMPOSE_PROFILES from --env-file: measured, Compose 5.5.1; regression review).
    [[ -f $DESKS_STATE/backend/config.json ]] && echo "COMPOSE_PROFILES=desk-admin"
    echo "EKKA_BACKEND_IMAGE=$backend_image"
    # the address people's computers map the name to (no public DNS needed)
    echo "DESKS_ADDRESS=$addr"
    [[ $OPENSHELL_TELEMETRY == on ]] && echo "OPENSHELL_TELEMETRY_ENABLED=true" || echo "OPENSHELL_TELEMETRY_ENABLED=false"
  } > "$DESKS_STATE/up.env"
  host_env_files
  ok "$MODE: $NAME, listening on $bind; NVIDIA OpenShell telemetry $OPENSHELL_TELEMETRY"
  [[ -f $DESKS_STATE/backend/config.json ]] \
    || echo "   the backend adapter starts once its configuration is written, after this machine is enrolled"
  ok 'desk files use separate storage; no host folders'
}

step_workspace_policy() {
  local result
  install -d -m 0700 "$DONE"
  result=$(python3 tools/workspace_policy.py configure "$DESKS_STATE/gateway.toml" false "$DESKS_STATE/workspace-policy.pending") \
    || die 'the gateway folder settings were not applied; see the error above'
}

step_workspace_restart() {
  if [[ -f $DESKS_STATE/workspace-policy.pending ]]; then
    (cd deploy && bash setup.sh compose restart gateway) \
      || die 'the gateway could not reload its folder settings; see: sudo ./up.sh status'
    ok 'gateway restarted with the selected folder settings'
    rm -- "$DESKS_STATE/workspace-policy.pending"
  fi
}

step_backend_image() {  # the backend adapter's image: pulled by digest, and its signature checked, before anything runs it
  python3 tools/backend_image.py pinned || return 0     # no release pinned yet: the desk-admin profile stays off
  say "backend adapter image"
  local image identity issuer cosign
  image=$(python3 tools/backend_image.py image) && identity=$(python3 tools/backend_image.py identity) \
    && issuer=$(python3 tools/backend_image.py issuer) && cosign=$(python3 tools/backend_image.py cosign-image) \
    || die "deploy/pins.json does not name the backend adapter's image"
  # A public package (owner, 2026-10-17: ekka-labs): no login, and cosign is given none of this machine's.
  docker pull -q "$image" >/dev/null || die "could not pull $image; does this machine reach ghcr.io?"
  docker run --rm --network host \
    "$cosign" verify --certificate-identity-regexp "$identity" --certificate-oidc-issuer "$issuer" "$image" >/dev/null 2>&1 \
    || die "the backend adapter's image is not signed by EKKA's release workflow; it will not run"
  # A pinned image with no build for this processor type pulls anyway (docker warns) and then cannot start.
  local want_arch got_arch; want_arch=$(docker version --format '{{.Server.Arch}}' 2>/dev/null) || want_arch=
  got_arch=$(docker image inspect --format '{{.Architecture}}' "$image" 2>/dev/null) || got_arch=
  [[ -n $want_arch && $got_arch == "$want_arch" ]] \
    || die "the pinned backend adapter image is built for '${got_arch:-unknown}', and this machine runs '${want_arch:-unknown}' images; deploy/pins.json must name an ekka-backend release published for ${want_arch:-this machine}"
  ok "backend adapter $image, signed by EKKA's release workflow"
  # The reviewed baseline policy the adapter answers grant_facts from: before anything can start the adapter, which
  # mounts it read-only and refuses a missing one by name. Root's, from / down (tools/desk_records.py).
  python3 tools/desk_records.py baseline desk/policy.json "$DESKS_STATE/backend/baseline-policy.json" \
    || die "the baseline policy record could not be confirmed; see the line above"
}

step_images() {
  say "images"
  echo "   NVIDIA OpenShell $OPENSHELL_TAG: pulled from ghcr.io/nvidia by digest (Apache-2.0; notices:"
  echo "   https://github.com/NVIDIA/OpenShell/blob/$OPENSHELL_TAG/THIRD-PARTY-NOTICES). EKKA does not host them."
  # The desk image's recipe is this repository's own desk/image, at this commit.
  local image_dir="$ROOT/desk/image" src have
  [[ -f $image_dir/Dockerfile ]] || die "the EKKA desk image source is missing: $image_dir/Dockerfile"
  src=$( { find "$image_dir" -type f | LC_ALL=C sort | xargs cat; } | sha256sum | cut -c1-16)
  have=$(docker image inspect -f '{{index .Config.Labels "ekka.desk.source"}}' ekka-desk:local 2>/dev/null || true)
  if [[ $have != "$src" ]]; then
    docker build -q --label "ekka.desk.source=$src" -t ekka-desk:local "$image_dir" >/dev/null \
      || die "the desk image did not build: docker build -t ekka-desk:local desk/image"
    ok "built the desk image on this machine (ekka-desk:local, $src); a desk made before keeps its image until it is made again"
  else ok "desk image ekka-desk:local ($src)"; fi
  # The desk image EKKA's desk commands grant, by its content id: root's, from / down (tools/desk_records.py). Written
  # after a build and when unchanged, so an installed box gets one on its next run. Only with an adapter pinned.
  if python3 tools/backend_image.py pinned; then
    local id; id=$(docker image inspect --format '{{.Id}}' ekka-desk:local) || die "the desk image is not built; run again"
    python3 tools/desk_records.py image "$id" "$DESKS_STATE/backend/desk-image.json" \
      || die "the desk image record could not be confirmed; see the line above"
  fi
}

step_enclave_install() {  # the signed EKKA release on this machine, through EKKA's own installer, cosign REQUIRED
  say "the EKKA release"
  local have="" want=$EKKA_VERSION
  [[ -x /usr/local/bin/ekka ]] && have=$(/usr/local/bin/ekka --version 2>/dev/null | head -1 | awk '{print $2}' || true)   # `ekka 0.1.126` then commit and build lines
  if [[ $have == "$want" ]]; then ok "ekka $want at /usr/local/bin/ekka"
  else
    local t; t=$(mktemp -d)
    curl -fsSL https://get.ekka.ai/install.sh -o "$t/install.sh" || { rm -rf "$t"; die "could not download EKKA's installer"; }
    curl -fsSL https://get.ekka.ai/install.sh.sha256 -o "$t/install.sh.sha256" || { rm -rf "$t"; die "could not download the installer's checksum"; }
    (cd "$t" && sed 's#  .*#  install.sh#' install.sh.sha256 | sha256sum -c - >/dev/null 2>&1) || { rm -rf "$t"; die "EKKA's installer does not match its published checksum; nothing installed"; }
    [[ -n $have ]] && cp -p /usr/local/bin/ekka "/usr/local/bin/ekka.before-$have"
    # A controlled PATH so nothing shadows /usr/local/bin (the wrapper lives in /usr/local/sbin, not on this PATH); the
    # signature check is never skipped: a refusal here is the installer's own sentence.
    # EKKA_ALLOW_DOWNGRADE=1 on the up.sh command is the ONE way to roll back: the installer refuses an older release otherwise.
    local -a downgrade=(); [[ ${EKKA_ALLOW_DOWNGRADE:-} == 1 ]] && downgrade=(--allow-downgrade)
    env -i PATH=/usr/local/bin:/usr/bin:/bin HOME=/root EKKA_VERSION="$want" EKKA_INSTALL_DIR=/usr/local/bin sh "$t/install.sh" "${downgrade[@]}" >"$DESKS_STATE/ekka-install.log" 2>&1 \
      || { rm -rf "$t"; die "EKKA $want did not install; see $DESKS_STATE/ekka-install.log (an older release needs EKKA_ALLOW_DOWNGRADE=1 on this command)"; }
    rm -rf "$t"
    [[ $(/usr/local/bin/ekka --version 2>/dev/null | head -1 | awk '{print $2}') == "$want" ]] || die "/usr/local/bin/ekka is not $want after the install"
    ok "ekka $want installed (signature checked by EKKA's installer)${have:+; the previous binary is /usr/local/bin/ekka.before-$have}"
  fi
  # `ekka` for administrators: after `sudo -i`, the same command as everywhere, run as the Enclave's user.
  render deploy/host/sbin/ekka /usr/local/sbin/ekka 0755 "SNAPSHOT=$SNAPSHOT"
  ok "sudo -i, then ekka <command>: this machine's Enclave (/usr/local/sbin/ekka)"
}

step_init() {
  is_done init && { ok "certificates, secrets, sign-in service: done"; return; }
  say "certificates, secrets and the sign-in service"
  (cd deploy && bash setup.sh init "$NAME" </dev/null)
  done_ init
}

step_first_admin() {
  is_done first-admin && { ok "the first administrator exists"; return; }
  [[ -n ${ADMIN_EMAIL:-} ]] || stop_for_person "Name the desk gateway's first administrator: run again with ADMIN_EMAIL=you@example.com
  (sudo ADMIN_EMAIL=you@example.com ./up.sh $MODE_ARGS). up.sh makes a one-time password that you change at first sign-in."
  local pf=$DESKS_STATE/secrets/first-admin-password
  ( umask 077; openssl rand -base64 24 | tr -d '\n' > "$pf" )
  (cd deploy && KC_URL=https://127.0.0.1:8443 KC_CA=$DESKS_STATE/tls/ca.crt KC_ADMIN_USER=desks-bootstrap \
     KC_ADMIN_PASSWORD_FILE=$DESKS_STATE/secrets/keycloak-admin-password KC_FIRST_ADMIN_PASSWORD_FILE=$pf \
     python3 keycloak/apply_realm.py first-admin desks-admin "$ADMIN_EMAIL")
  done_ first-admin
  ok "first administrator desks-admin ($ADMIN_EMAIL); one-time password: sudo cat $pf (changed at first sign-in)"
}

env_dir() {  # where the Enclave keeps an environment's files in its home: prod at the top, the others in a folder
  local e=${EKKA_ENV:-prod}; [[ $e == prod ]] && echo . || echo "$e"; }

enrolled() { [[ -f $ENCLAVE_HOME/$(env_dir)/enclave.env ]]; }   # what `enclave start <id>` writes once the machine is claimed
# The claim's transient unit (ekka-enroll), queried by name. `systemctl show` answers for a unit systemd no longer holds
# too (LoadState=not-found, ActiveState=inactive, exit 0: measured on systemd 255), so an unloaded transient unit is a
# REPORTED end state; a query that fails is an error of its own and never reads as "it stopped".
claim_state() { local s; s=$(systemctl show -p ActiveState --value ekka-enroll.service 2>/dev/null) && [[ -n $s ]] || return 1; echo "$s"; }
claim_gone() {  # the claim unit stopped: the stop's own exit status checked, then the end state read back
  local load state
  load=$(systemctl show -p LoadState --value ekka-enroll.service 2>/dev/null) && [[ -n $load ]] \
    || die "systemd could not report the claim unit; nothing else was started. See: systemctl status ekka-enroll"
  if [[ $load == loaded ]]; then
    systemctl stop ekka-enroll.service \
      || die "the claim process could not be stopped (systemctl stop failed); nothing else was started. See: systemctl status ekka-enroll"
  fi
  state=$(claim_state) || die "systemd could not report the claim's state after the stop; nothing else was started. See: systemctl status ekka-enroll"
  [[ $state == inactive || $state == failed ]] \
    || die "the claim process is still '$state' after the stop; nothing else was started. See: systemctl status ekka-enroll"
  systemctl reset-failed ekka-enroll.service >/dev/null 2>&1 || true   # a failed transient unit lingers until this
}

ekka_in() { enclave_ekka "$@"; }   # the Enclave's own user and home (deploy/lib.sh); kept as the name the steps use

step_enroll() {
  local env=${EKKA_ENV:-prod}
  if enrolled 2>/dev/null; then ok "the Enclave is enrolled"; return; fi
  say "enrolling this machine's Enclave"
  # whoami exits non-zero until this machine is enrolled, even when signed in: read what it says instead.
  local who; who=$(ekka_in whoami 2>&1 || true)
  if ! grep -q "Signed in as" <<<"$who"; then
    local mail=${ADMIN_EMAIL:-}
    if [[ -n $INTERACTIVE ]]; then
      # A person is at this terminal: ask here, run the sign-in here, and go on in this same run.
      printf '\n\033[1m-- sign in to EKKA --\033[0m\n'
      if [[ -n $mail ]]; then
        printf 'This server needs the EKKA account of the person who owns organization %s.\nA sign-in link goes to %s now; click it and this install continues by itself.\n\n' "${EKKA_ORG:-<your organization>}" "$mail"
        ekka_in login --email "$mail" || true
      else
        printf 'This server needs the EKKA account of the person who owns organization %s.\nEnter that email; a sign-in link goes to it, click it and this install continues by itself.\n\n' "${EKKA_ORG:-<your organization>}"
        ekka_in login || true
      fi
      who=$(ekka_in whoami 2>&1 || true)
      grep -q "Signed in as" <<<"$who" || die "the EKKA sign-in did not complete (the link was not clicked, or it was refused). Run again: sudo ./up.sh $MODE_ARGS"
    else
      stop_for_person "Sign in to EKKA, as the person who owns organization ${EKKA_ORG:-<your organization>}:
  1. sudo -i
  2. ekka login --email ${mail:-<your email>}
  3. click the link in the email it sends
  4. exit"
    fi
  fi
  if grep -q "not in an organization" <<<"$who"; then
    stop_for_person "Your EKKA account is in no organization yet. Create one, or ask the organization's admin for an invite:
  1. sudo -i
  2. ekka org create <name>
  3. exit"
  fi
  # An account can belong to several organizations, and "current" is whichever was used last: never create the
  # Enclave there by default. Name it, switch to it, and check the switch took before anything is created.
  local orgs; orgs=$(ekka_in org list 2>&1 || true)
  [[ -n ${EKKA_ORG:-} ]] || stop_for_person "Name the EKKA organization this server's Enclave joins, then run again with EKKA_ORG=<slug>.
Your organizations:
$(grep -E '^[[:space:]]*[*]?[[:space:]]*[a-z0-9-]+[[:space:]]' <<<"$orgs" | sed 's/^/  /')"
  ekka_in org switch "$EKKA_ORG" >/dev/null 2>&1 || die "could not switch to organization $EKKA_ORG; is the signed-in person a member?"
  ekka_in org list 2>&1 | grep -qE "^[[:space:]]*[*][[:space:]]*$EKKA_ORG[[:space:]]" \
    || die "the current organization is not $EKKA_ORG after switching; nothing was created"
  ok "organization: $EKKA_ORG"
  # The output is kept BEFORE the id is looked for, so a refusal reaches the person: with `set -e`, a pipeline
  # whose grep finds nothing stopped this script with exit 1 and no message at all (an organization with no
  # Enclave slot left, measured 2026-10-31). EKKA's own sentence is what the person needs.
  local created id create_rc=0
  created=$(ekka_in enclave create --name "desks $(hostname -s)" 2>&1) || create_rc=$?
  (( create_rc == 0 )) || die "EKKA did not create an Enclave: $created"
  id=$(grep -o -E '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' <<<"$created" | head -1 || true)
  [[ -n $id ]] || die "EKKA did not create an Enclave: $(grep -v -E '^\s*$|Container |Network |Volume ' <<<"$created" | head -4 | tr '\n' ' ')"
  ok "Enclave $id created"
  # The first start claims this machine, keeps the vault key in a file (a server has no keychain), then keeps
  # running. It runs as a TRANSIENT systemd unit, as the Enclave's user, so it has a managed lifecycle: stopped by
  # name with a deadline once claimed, never a backgrounded shell signalled through a wrapper (a review
  # reproduced the hang). Its output is in the journal. The permanent unit runs it for good from then on (step_start).
  claim_gone   # a claim unit left by an earlier run is stopped first, and that stop must succeed
  systemd-run --unit=ekka-enroll --uid=ekka --gid=ekka -p TimeoutStopSec=30 -p KillMode=mixed \
    --setenv=PATH=/usr/local/bin:/usr/bin:/bin --setenv=HOME=/var/lib/ekka --setenv=EKKA_HOME="$ENCLAVE_HOME" --setenv=EKKA_ENV="$env" \
    /usr/local/bin/ekka enclave start "$id" --custody file >/dev/null 2>&1 \
    || die "the claim could not be started as a transient unit; see: journalctl -u ekka-enroll"
  # The wait reads the unit's state by name, and a state systemd cannot report is an error, never "it exited":
  # A review ran this function with the status query failing and watched it report the machine claimed.
  local i state; printf '   waiting for EKKA to confirm the claim (up to 120 s) '
  for i in $(seq 1 60); do
    enrolled 2>/dev/null && break
    state=$(claim_state) || { echo; die "systemd could not report the claim's state; nothing else was started. See: systemctl status ekka-enroll"; }
    case $state in
      active|activating|reloading|deactivating) printf '.'; sleep 2 ;;
      inactive|failed) break ;;   # it exited: the journal says why
      *) echo; die "the claim unit is in state '$state', which this installer does not expect; nothing else was started. See: systemctl status ekka-enroll" ;;
    esac
  done; echo
  journalctl -u ekka-enroll.service --no-pager -o cat >"$DESKS_STATE/enclave-claim.log" 2>/dev/null || true
  claim_gone   # SIGTERM, then SIGKILL after TimeoutStopSec; a stop that fails is a refusal, never a claimed machine
  enrolled || die "the Enclave did not finish enrolling; see $DESKS_STATE/enclave-claim.log"
  ok "this machine is claimed by Enclave $id (vault key kept in a file)"
  # A new Enclave (a first install, or after `ekka enclave reset`) has none of what three marks say the old one had:
  # its executor URL in enclave.env (started), its gateway membership (admin), its job gate's grant (grant). Measured
  # on the integration test server 2026-10-24: after a reset the kept `started` mark ran the migration on a URL-less enclave.env.
  rm -f "$DONE/started" "$DONE/admin" "$DONE/grant"
}

kc() {  # the realm script against this machine's Keycloak admin listener
  (cd deploy && KC_URL=https://127.0.0.1:8443 KC_CA=$DESKS_STATE/tls/ca.crt KC_ADMIN_USER=desks-bootstrap \
     KC_ADMIN_PASSWORD_FILE=$DESKS_STATE/secrets/keycloak-admin-password python3 keycloak/apply_realm.py "$@")
}

# The backend adapter's credential, from Keycloak into the Enclave's vault through a pipe only: never a
# file, an argument or a terminal. The connection is the `desks` catalog row: the adapter's socket, this machine only.
connect_desk_admin() {
  local err
  if err=$(kc admin-client on | ekka_in api connect desks --input socket=/run/ekka-backend/backend.sock --reach loopback --stdin 2>&1 >/dev/null); then
    ok "the backend adapter's credential is in the Enclave's vault (connection desks, this machine only)"; return 0
  fi
  # EKKA's desks catalog entry widened the paths the adapter's connection may reach (1.1.0: the adapter's whole /v1/
  # space; the adapter itself refuses any route its contract does not name). The Enclave refuses to replace a
  # connection whose paths changed, so when the paths are the ONLY difference it is replaced on purpose: disconnect,
  # then connect again. The desks grant names the resource apis/desks, and a disconnect never revokes it. This
  # connection is the installer's own (one destination, one setting, its own credential), so replacing it can only
  # put back these values; a different destination, sign-in or setting is still refused below.
  if [[ $(grep -c '^  what differs: ' <<<"$err") == 1 ]] && grep -qx '  what differs: the paths it may reach' <<<"$err"; then
    local derr
    derr=$(ekka_in api disconnect desks --yes 2>&1 >/dev/null) || {
      printf '%s\n' "$derr" >&2
      die "the desks API did not disconnect cleanly to take the paths EKKA's catalog now gives it (reason above); it may already be removed: run sudo ./up.sh again to connect it"
    }
    kc admin-client on | ekka_in api connect desks --input socket=/run/ekka-backend/backend.sock --reach loopback --stdin >/dev/null \
      || die "the desks API was disconnected and did not connect again with its new paths; run sudo ./up.sh again"
    ok "the desks API reconnected with the paths EKKA's catalog now gives it (the adapter's whole route space)"
    ok "the backend adapter's credential is in the Enclave's vault (connection desks, this machine only)"; return 0
  fi
  printf '%s\n' "$err" >&2
  die "the backend adapter's credential did not reach the Enclave's vault; nothing was stored on disk"
}

install_cli() {  # always NVIDIA's pinned CLI at our own path: a different openshell already on the PATH is never used
  "$OS" --version 2>/dev/null | grep -q " ${OPENSHELL_TAG#v}\$" && return
  local t; t=$(mktemp -d)
  [[ -n $OPENSHELL_CLI_SHA ]] || die "no openshell CLI is pinned for this machine's processor type ($MACHINE)"
  fetch_pinned "https://github.com/NVIDIA/OpenShell/releases/download/$OPENSHELL_TAG/$OPENSHELL_CLI_FILE" "$t/os.tgz" "$OPENSHELL_CLI_SHA" 0644
  tar -xzf "$t/os.tgz" -C "$t"; install -D -m 0755 "$(find "$t" -type f -name openshell | head -1)" "$OS"; rm -rf "$t"
  ok "installed NVIDIA's openshell CLI $OPENSHELL_TAG ($MACHINE, pinned sha256) at $OS"
}

as_gateway_admin() {  # run "$@" as the gateway's administrator, then switch that identity off again
  # A confidential client with only the openshell-admin role, enabled for these few calls and disabled after.
  # NVIDIA's CLI uses client credentials when OPENSHELL_OIDC_CLIENT_SECRET is set (commands/gateway.rs, login).
  install_cli
  # `compose up -d` returns before NVIDIA's gateway listens; a call before then fails with "tls handshake eof".
  local i; for i in $(seq 1 60); do
    openssl s_client -connect 127.0.0.1:8080 -servername "$NAME" </dev/null >/dev/null 2>&1 && break; sleep 2; done
  (( i < 60 )) || die "NVIDIA's gateway is not answering on 8080; see: sudo ./deploy/setup.sh compose logs gateway"
  grep -q " $NAME\$" /etc/hosts 2>/dev/null || getent hosts "$NAME" >/dev/null || echo "127.0.0.1 $NAME" >> /etc/hosts
  # Each step is checked by hand: a caller runs this with `||`, which switches set -e off inside it.
  local setup_client_secret rc=0
  # `on` enables the client before it reads the secret, so a failed `on` may have left it enabled: it is switched off
  # again, and a failure there too is said, never "nothing was changed".
  setup_client_secret=$(kc setup-client on) && [[ -n $setup_client_secret ]] || {
    kc setup-client off >/dev/null 2>&1 \
      || die "Keycloak did not switch the gateway's setup client on, and it may still be switched on; run the same command again"
    die "Keycloak did not switch the gateway's setup client on; nothing was changed"; }
  # NVIDIA's gateway flags read these too; one kept by `sudo -E` would send the calls, and this sign-in, elsewhere.
  ( unset OPENSHELL_GATEWAY OPENSHELL_GATEWAY_ENDPOINT OPENSHELL_GATEWAY_INSECURE
    export OPENSHELL_OIDC_CLIENT_SECRET=$setup_client_secret SSL_CERT_FILE=$DESKS_STATE/tls/ca.crt HOME=$DESKS_STATE/openshell-admin
    install -d -m 0700 "$HOME"
    "$OS" gateway add "https://$NAME:8080" --name ekka-agent-desks --oidc-issuer "https://$NAME/realms/ekka-desks" \
      --oidc-client-id desks-setup --oidc-audience ekka-desks >/dev/null 2>&1 || true
    "$OS" gateway login ekka-agent-desks >/dev/null || exit 97  # 97: never an answer of the call it guards
    "$@"
  ) || rc=$?
  unset setup_client_secret
  kc setup-client off >/dev/null || die "the gateway's setup client may still be switched on; run the same command again"
  rm -rf "$DESKS_STATE/openshell-admin"
  (( rc != 97 )) || die "could not sign in to NVIDIA's gateway as its administrator; nothing was changed there"
  return $rc
}

# An install's own profile wins over the shipped one of the same name, and `up.sh profiles` never replaces it:
# $DESKS_STATE/providers.local/<name>.yaml. It decides how an agent signs in and which hosts its key may
# reach, so it must be a real file in a real folder, owned by whoever runs up.sh (root, under sudo), writable
# by no group and no other user. The public repository carries no such profile.
profile_source() {  # profile_source <name>: the profile file sync_profiles uses for <name>
  local own=$DESKS_STATE/providers.local/$1.yaml
  if [[ -e $own || -L $own ]]; then
    python3 - "$own" <<'PY' || die "$own is not safe to use; see the line above"
import os, stat, sys
own = sys.argv[1]
for path, want in ((os.path.dirname(own), stat.S_ISDIR), (own, stat.S_ISREG)):
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode) or not want(st.st_mode):
        sys.exit(f"   REFUSED: {path} must be a real {'folder' if want is stat.S_ISDIR else 'file'}, not a link")
    if st.st_uid not in (0, os.geteuid()):
        sys.exit(f"   REFUSED: {path} belongs to uid {st.st_uid}, not root. Fix: chown root {path}")
    if st.st_mode & 0o022:
        sys.exit(f"   REFUSED: {path} is writable by group or others ({st.st_mode & 0o777:o}). Fix: chmod go-w {path}")
PY
    echo "$own"
  else
    echo "providers/$1.yaml"
  fi
}

profile_names() {  # every profile this install puts in the gateway: the shipped ones and its own
  local file
  { for file in providers/*.yaml "$DESKS_STATE"/providers.local/*.yaml; do
      [[ -f $file ]] || continue
      basename "$file" .yaml
    done; } | sort -u
}

connect_cmd() {  # connect_cmd <provider>: a provider's one key, read from stdin only, set on this machine
  # The key is never an argument, never printed and never logged. It is read from a pipe (a terminal is refused, so
  # it never sits on a screen) into a variable no other process sees, and handed to NVIDIA's CLI alone, in the
  # environment variable the provider's profile names. An argument is never echoed back: it may be a key.
  local p key secret
  (( $# == 1 )) || die "usage: <key source> | sudo ekka desk connect <provider>   (the key comes on stdin, never as an argument)"
  p=$1
  profile_names | grep -qxF -- "$p" || die "that is not a provider this install knows; they are: $(profile_names | tr '\n' ' ')"
  # A profile that declares no credential at all (`credentials: []`, for example public package registries) makes a
  # provider with no key, so none is read: a key piped in anyway is refused, as a mistake, and nothing is made. The
  # provider still exists only because a person ran this, and a desk still reaches its hosts only when the desks grant
  # lists it and the desk names it (the backend refuses a live desk any program it was not created with).
  if python3 tools/provider_connect.py keyless "$(profile_source "$p")" </dev/null; then
    if [[ ! -t 0 ]]; then IFS= read -r -t 1 -d '' secret || true; fi
    [[ -z ${secret:-} ]] || { secret=; die "$p takes no key; nothing was changed. Run it with nothing on stdin: sudo ekka desk connect $p </dev/null"; }
    OPENSHELL_WORKSPACE=desks as_gateway_admin connect_keyless "$p" || die "the provider $p was not made; nothing else was changed"
    ok "$p is connected: it takes no key"
    ( step_desk_grant ) || die "the provider $p IS made; the desks grant was not refreshed, so a desk naming $p is refused until it is: sudo ./up.sh server $NAME"
    return 0
  fi
  [[ -t 0 ]] && die "the key comes from a pipe, never typed at a terminal: <key source> | sudo ekka desk connect <provider>"
  key=$(python3 tools/provider_connect.py key "$(profile_source "$p")" </dev/null) || exit 1
  IFS= read -r -d '' secret || true
  secret=${secret%$'\n'}
  [[ -n $secret && $secret != *[[:space:]]* && ${#secret} -le 8192 ]] \
    || { secret=; die "stdin must carry exactly one key: no spaces, no second line; nothing was changed"; }
  OPENSHELL_WORKSPACE=desks as_gateway_admin connect_provider "$p" "$key" \
    || { secret=; die "the key for $p was not set; nothing else was changed"; }
  secret=
  ok "$p is connected: its key is in the gateway"
  # The desks grant names each provider this gateway holds, by its digest (desk_provider_args). Refreshed now, add
  # first and revoke after, or a desk naming $p is refused CONSTRAINT_PROVIDERS until the next `up.sh server`.
  # A refusal there must not read as "connect failed": the key IS set by then (regression review).
  ( step_desk_grant ) || die "the key for $p IS set; the desks grant was not refreshed, so a desk naming $p is refused until it is: sudo ./up.sh server $NAME"
}

connect_provider() {  # inside as_gateway_admin: create the provider with its key, or replace the key it has
  local p=$1 key=$2 log=$DESKS_STATE/openshell-admin.log
  local -a cmd
  if "$OS" -g ekka-agent-desks provider get "$p" >/dev/null 2>&1; then
    cmd=(provider update "$p" --credential "$key")
  else
    cmd=(provider create --name "$p" --type "$p" --global-profile --credential "$key")
  fi
  python3 tools/openshell_allow.py "$log" "${cmd[@]}" </dev/null || return 1   # the same allow-list and log as every gateway admin call
  ( export "$key=$secret"; "$OS" -g ekka-agent-desks "${cmd[@]}" </dev/null >/dev/null )
}

connect_keyless() {  # inside as_gateway_admin: the provider of a profile with no credential, made once, with no key
  local p=$1 log=$DESKS_STATE/openshell-admin.log
  "$OS" -g ekka-agent-desks provider get "$p" >/dev/null 2>&1 && return 0   # already made: nothing to replace
  python3 tools/openshell_allow.py "$log" provider create --name "$p" --type "$p" --global-profile </dev/null || return 1
  "$OS" -g ekka-agent-desks provider create --name "$p" --type "$p" --global-profile </dev/null >/dev/null
}

sync_profiles() {  # the gateway's profiles = providers/, or this install's own; imported once and updated after
  local p v t src from
  # Every profile's file is checked BEFORE any is imported: an unsafe local profile stops the whole sync,
  # so the gateway is never left half updated.
  for p in $(profile_names); do profile_source "$p" >/dev/null || exit 1; done
  for p in $(profile_names); do
    src=$(profile_source "$p") || exit 1
    if [[ $src == providers/* ]]; then from="providers/"; else from="$src (this install's own)"; fi
    if ! v=$("$OS" -g ekka-agent-desks provider profile export --global "$p" 2>/dev/null | sed -n 's/^resource_version: *//p'); then v=; fi
    if [[ -z $v ]]; then
      "$OS" -g ekka-agent-desks provider profile import --global --file "$src" >/dev/null && ok "profile $p imported from $from"
    else
      t=$(mktemp --suffix .yaml); sed "0,/^id: .*/s//&\nresource_version: $v/" "$src" > "$t"
      "$OS" -g ekka-agent-desks provider profile update --global --file "$t" "$p" >/dev/null && ok "profile $p updated from $from"
      rm -f "$t"
    fi
  done
}

admin_setup() {
  "$OS" -g ekka-agent-desks workspace create --name desks 2>&1 | grep -v -i "already exists" || true
  "$OS" -g ekka-agent-desks workspace member add --workspace desks --subject "$1" --role user 2>&1 | grep -v -i "already" || true
  sync_profiles
}

# The backend adapter's one configuration file (the vendored backend/adapter-config.v1). Only the
# Enclave's organization, node and Govern URL lines leave its container; enclave.env holds a secret too, and that
# line never does. The file holds no credential, and compose mounts it read-only into the adapter.
write_adapter_config() {
  enclave_home_read "$(env_dir)/enclave.env" | grep -E "^EKKA_(TENANT_ID|NODE_ID|GOVERN_URL)=" \
    | python3 tools/adapter_config.py write "$DESKS_STATE/backend/config.json" "$NAME" \
    || die "the backend adapter's configuration was not written; see the line above"
}

# The discovery permits (contracts backend/discovery-permit.v1): the backend adapter writes one, for one discovery desk,
# only after it read OpenShell's auto approval mode back as applied, and deletes it before it sets manual again; the
# Enclave's gateway interceptor lets that desk's proposals through only while it holds. The adapter runs as the
# Enclave's user (compose `user: 2000`), and the Enclave reads it natively as that user, so the folder is theirs, 0750,
# group the Enclave's: nobody else reads or plants a permit. Bound read-write into the adapter's container only
# (compose.yml); made before anything can start the adapter, because compose never creates it (create_host_path: false).
backend_permits_dir() {
  local d=$DESKS_STATE/backend/permits
  [[ -L $d || -L $DESKS_STATE/backend ]] && die "$d (or its folder) is a link; it must be a real folder. Remove the link and run again"
  install -d -m 0755 "$DESKS_STATE/backend"
  install -d -m 0750 -o "$ENCLAVE_USER" -g "$ENCLAVE_USER" "$d" || die "the discovery permits folder $d could not be made"
  [[ $(stat -c '%U:%G %a' "$d") == "$ENCLAVE_USER:$ENCLAVE_USER 750" ]] || die "$d is not $ENCLAVE_USER:$ENCLAVE_USER 0750"
}

step_desk_admin() {  # desk administration through EKKA: only once up.env runs the backend adapter
  grep -q '^EKKA_BACKEND_IMAGE=.' "$DESKS_STATE/up.env" 2>/dev/null || return 0
  say "desk administration through EKKA"
  connect_desk_admin
  write_adapter_config
  backend_permits_dir
  # The Enclave's interceptor learns who the adapter is (the ekka-desk-admin client's subject, which exists only once
  # connect_desk_admin made it) and where the permits are. Both lines unset is the interceptor's old behaviour, so a
  # changed file restarts the Enclave, below, and an unchanged one changes nothing.
  local enclave_env; enclave_env=$(cd deploy && bash setup.sh enclave-backend "${EKKA_ENV:-prod}") \
    || die "the Enclave's settings for the backend adapter were not written; run again"
  # Only now, with its configuration in place, the adapter's profile goes on and the adapter starts.
  grep -q '^COMPOSE_PROFILES=desk-admin$' "$DESKS_STATE/up.env" || echo "COMPOSE_PROFILES=desk-admin" >> "$DESKS_STATE/up.env"
  sed -i 's/^DESKS_STACK_SERVICES=.*/DESKS_STACK_SERVICES="keycloak-db keycloak edge gateway ekka-backend"/' "$DESKS_STATE/up.env"
  (cd deploy && bash setup.sh backend-preflight)   # its files are real files, whatever this Compose does
  # The adapter is one more long-lived service of the supervised stack: the unit reads the list from up.env.
  systemctl restart ekka-desks || die "the desks stack did not restart with the adapter; see: journalctl -u ekka-desks"
  local i; for i in $(seq 1 60); do
    [[ $(docker inspect -f '{{.State.Health.Status}}' ekka-desks-ekka-backend-1 2>/dev/null) == healthy ]] && break; sleep 2; done
  (( i < 60 )) || die "the backend adapter did not become healthy; see: sudo ./deploy/setup.sh compose logs ekka-backend"
  ok "the backend adapter is running, with its configuration"
  if [[ $enclave_env == changed ]]; then
    systemctl restart ekka || die "the Enclave did not restart onto its new settings; see: journalctl -u ekka"
    # Restarting the Enclave stops and starts the desks stack too (ekka-desks is bound to it). The gateway answers only
    # after the unit's ExecStartPre has Keycloak and the edge healthy, and the next step reads Keycloak through the
    # edge: without this wait it got "connection refused" (a box, 5 Nov 2026).
    wait_enclave; wait_gateway
    ok "the Enclave restarted: its gateway interceptor knows the backend adapter and the discovery permits"
  fi
}

step_admin() {
  is_done admin && { ok "desk workspace, Enclave membership and profiles: done"; return; }
  say "the gateway's one-time setup (workspace, the Enclave's membership, provider profiles)"
  local sub; sub=$(cd deploy && bash setup.sh enclave-subject)
  as_gateway_admin admin_setup "$sub" || die "the gateway's setup did not finish; desks-setup is disabled again. Re-run to retry"
  done_ admin
  ok "workspace desks, the Enclave as a member, the profiles in providers/; desks-setup disabled again"
}

step_people_scopes() {  # people's sign-ins read-only: every run, so an installed box migrates on upgrade
  say "people's desk sign-ins: read-only"
  (cd deploy && bash setup.sh people-scopes) || die "people's sign-ins could not be checked; re-run to retry"
}

gateway_answers() { openssl s_client -connect 127.0.0.1:8080 -servername "$NAME" </dev/null >/dev/null 2>&1; }
wait_gateway() {  # NVIDIA's gateway answers TLS on this machine's 8080, where the native Enclave reaches it
  wait_for "the desk gateway to answer on this machine" 120 gateway_answers \
    || die "NVIDIA's gateway is not answering on 127.0.0.1:8080; see: journalctl -u ekka-desks, sudo ./deploy/setup.sh compose logs gateway"
}

enclave_answers() { ekka_in enclave status >/dev/null 2>&1; }
wait_enclave() {  # the Enclave's control socket answers (ekka enclave status), as its own user
  wait_for "the Enclave to answer" 60 enclave_answers || die "the Enclave did not come up; see: journalctl -u ekka"
}

render() {  # render <template> <dest> <mode> KEY=VALUE...: @@KEY@@ replaced; root-owned
  local tpl=$1 dest=$2 mode=$3; shift 3
  local text; text=$(cat "$tpl")
  local kv; for kv in "$@"; do text=${text//"@@${kv%%=*}@@"/${kv#*=}}; done
  printf '%s\n' "$text" > "$dest.new" && chown root:root "$dest.new" && chmod "$mode" "$dest.new" && mv -f "$dest.new" "$dest"
}

snapshot_stack() {  # a ROOT-OWNED copy of deploy/, tools/, providers/ and this script: the supervisor unit and the
  # wrapper's `ekka desk connect|invite|revoke|plans` run from it, never from a person's checkout
  rm -rf "$SNAPSHOT.new"; install -d -m 0755 "$SNAPSHOT.new"
  cp -a deploy tools providers desk ekka vendor up.sh "$SNAPSHOT.new/"   # every folder a routed verb reads (test_server_cli)
  chown -R root:root "$SNAPSHOT.new"; chmod -R u+rwX,go+rX,go-w "$SNAPSHOT.new"
  rm -rf "$SNAPSHOT.old"; [[ -d $SNAPSHOT ]] && mv "$SNAPSHOT" "$SNAPSHOT.old"; mv "$SNAPSHOT.new" "$SNAPSHOT"; rm -rf "$SNAPSHOT.old"
  install -D -m 0755 -o root -g root deploy/host/libexec/wait-interceptor /usr/local/libexec/ekka-desks/wait-interceptor
}

refuse_if_renamed() {  # the public name is bound at init, and a run under another name skipped init and changed nothing it binds
  # The CA is name-constrained to the first name (deploy/certs.sh), so no certificate for a second name verifies; Keycloak's
  # issuer and gateway.toml carry the first name too. Before this, such a run went on and pointed up.env, /etc/hosts, the
  # gateway's registration and the adapter at the new name: a server that half-answered to each.
  local was=""; [[ -f $DESKS_STATE/desks.env ]] && was=$(sed -n 's/^DESKS_NAME=//p' "$DESKS_STATE/desks.env")
  [[ -n $was && $was != "$NAME" && -f $DESKS_STATE/tls/ca.crt ]] || return 0
  die "this server was set up as $was, and you asked for $NAME; nothing was changed.
  The name is fixed when the server is first set up: its certificate authority may only ever vouch for $was.
  To keep it:            ./up.sh server $was
  To use $NAME instead:  remove this server's desks first (docs/OPERATIONS.md, \"Remove the server's desks\"),
                         then ./up.sh server $NAME. Everyone who installed for $was installs again."
}

refuse_if_masked() {  # a masked stack is a stop somebody meant (docs/OPERATIONS.md); an install never un-masks it
  if [[ -L /etc/systemd/system/ekka-desks.service && $(readlink /etc/systemd/system/ekka-desks.service) == /dev/null ]]; then
    die "ekka-desks is masked (the emergency stop in docs/OPERATIONS.md); nothing was changed. To continue: sudo systemctl unmask ekka-desks, then run this again"
  fi
}

enclave_units() {  # the Enclave's unit from EKKA's own generator, this setup's drop-in, and the stack's unit
  # `ekka enclave install-service` writes /etc/systemd/system/ekka.service from the ENROLLED home and its owner, and
  # enables it. Run with the Enclave's home named, as root (it writes the unit), after enrollment.
  # A clean environment (no EKKA_HOME_OVERRIDE, no proxy); `--no-start`: this step enables and starts the units itself. The
  # generator writes the ENVIRONMENT'S state folder as EKKA_HOME (prod: the home; staging: home/staging); the drop-in below
  # pins EKKA_HOME back to the base home, or a non-prod daemon would look in home/staging/staging.
  env -i PATH=/usr/local/bin:/usr/bin:/bin HOME=/root EKKA_HOME=$ENCLAVE_HOME EKKA_ENV=${EKKA_ENV:-prod} /usr/local/bin/ekka enclave install-service --no-start >"$DESKS_STATE/install-service.log" 2>&1 \
    || die "ekka enclave install-service refused; see $DESKS_STATE/install-service.log"
  install -d -m 0755 /etc/systemd/system/ekka.service.d
  render deploy/host/ekka.service.d/desks.conf.template /etc/systemd/system/ekka.service.d/desks.conf 0644 "EKKA_ENV=${EKKA_ENV:-prod}" "ENCLAVE_HOME=$ENCLAVE_HOME"
  # The stack's unit goes in the folder for units an administrator installs, NOT /etc/systemd/system: `systemctl mask`
  # (the emergency stop in docs/OPERATIONS.md) places its /dev/null link at /etc/systemd/system/ekka-desks.service, and a
  # regular unit file there could never be masked. A masked stack is a deliberate stop: refused here.
  refuse_if_masked
  [[ -f /etc/systemd/system/ekka-desks.service && ! -L /etc/systemd/system/ekka-desks.service ]] && rm -f /etc/systemd/system/ekka-desks.service   # where an earlier install of this setup put it
  install -d -m 0755 /usr/local/lib/systemd/system
  render deploy/host/ekka-desks.service.template /usr/local/lib/systemd/system/ekka-desks.service 0644 "SNAPSHOT=$SNAPSHOT" "DESKS_STATE=$DESKS_STATE"
  systemctl daemon-reload
  systemctl enable ekka ekka-desks >/dev/null 2>&1 || die "the units could not be enabled"
}

# nginx reads its config only when it starts, and `git pull` replaces deploy/edge/nginx.conf with a new file the
# running edge never sees, so an upgrade that changes a route would keep serving the old one. The edge is
# restarted when its config differs from the one it was last started with, and only then: a brief pause in
# sign-ins, in the upgrade's window.
edge_conf_sha() { sha256sum <deploy/edge/nginx.conf | cut -c1-64; }
edge_current() {
  local want; want=$(edge_conf_sha)
  [[ $want == "$(cat "$DESKS_STATE/edge-conf.sha" 2>/dev/null)" ]] && return 0
  (cd deploy && bash setup.sh compose restart edge >/dev/null) \
    || die "the edge did not restart on its new config; see: sudo ./deploy/setup.sh compose logs edge"
  echo "$want" >"$DESKS_STATE/edge-conf.sha"
  ok "the edge restarted on its new config"
}

step_start() {
  (cd deploy && DESKS_STATE=$DESKS_STATE bash ./certs.sh bundle >/dev/null) || die "the gateway's CA bundle could not be built"   # system roots + desks CA, and /etc/ekka/desks-ca.crt
  # A pin bump applies whole or not at all: the supervisor first, then nothing starts the gateway able to hand
  # desk credentials out.
  (cd deploy && bash setup.sh supervisor >/dev/null) || die "the supervisor binary could not be put in place"
  (cd deploy && bash setup.sh preflight) || die "the gateway preflight refused (above); nothing was started"
  backend_permits_dir   # the adapter's permits folder, before any start (compose never creates it)
  (cd deploy && bash setup.sh backend-preflight)   # with desk-admin on, the stack starts the adapter too
  local stack_sha; stack_sha=$( { cat deploy/compose.yml deploy/pins.json deploy/edge/nginx.conf deploy/host/ekka-desks.service.template "$DESKS_STATE/up.env"; } | sha256sum | cut -c1-16)
  if is_done started; then
    snapshot_stack; enclave_units
    rm -f "$DESKS_STATE/stack.hold"; systemctl reset-failed ekka-desks >/dev/null 2>&1 || true   # a first install that died while held
    # The Enclave: the installed release runs, or it is restarted onto it (an upgrade is the binary first, then this).
    systemctl start ekka >/dev/null 2>&1 || die "the Enclave did not start; see: journalctl -u ekka"
    wait_enclave
    local running; running=$(ekka_in enclave status --json 2>/dev/null | python3 -c 'import json,sys; t=sys.stdin.read(); i=t.find("{"); print(json.JSONDecoder().raw_decode(t[i:])[0].get("runner_version","") if i>=0 else "")' 2>/dev/null || true)
    if [[ -n $running && $running != "$EKKA_VERSION" ]]; then
      systemctl restart ekka || die "the Enclave did not restart onto $EKKA_VERSION; see: journalctl -u ekka"
      wait_enclave; ok "Enclave restarted onto $EKKA_VERSION (was $running)"
    fi
    # The stack: a changed compose, pin, edge config or settings restarts it (a pause for desks); otherwise only started.
    if [[ $stack_sha != "$(cat "$DESKS_STATE/stack.sha" 2>/dev/null)" ]]; then
      systemctl restart ekka-desks || die "the desks stack did not restart; see: journalctl -u ekka-desks"
      echo "$stack_sha" >"$DESKS_STATE/stack.sha"; ok "the desks stack restarted on its new configuration"
    else
      systemctl start ekka-desks >/dev/null 2>&1 || die "the desks stack did not start; see: journalctl -u ekka-desks"
    fi
    wait_gateway
    edge_current
    ok "Enclave $EKKA_VERSION (systemd: ekka) and the desks stack (systemd: ekka-desks) are running"; return; fi
  say "starting the Enclave and NVIDIA's gateway"
  local env=${EKKA_ENV:-prod}
  # The Enclave's unit Wants the stack, and the stack's gateway cannot start before the Enclave holds its client secret
  # (measured: the stack looped on a gateway that could not sign in, and knocked Keycloak over while the config and the
  # secret were being fetched). So a HOLD file keeps the stack unit from starting for the whole first start (its first
  # ExecStartPre tests for it), and the hold is removed once the secret is in the vault. The sign-in service is brought up
  # by itself where a step needs it (setup.sh wait_keycloak).
  touch "$DESKS_STATE/stack.hold"
  systemctl stop ekka-desks >/dev/null 2>&1 || true; systemctl reset-failed ekka-desks >/dev/null 2>&1 || true
  (cd deploy && bash setup.sh enclave-config "$env" desks)
  snapshot_stack; enclave_units
  # `ekka secret put` talks to a running Enclave, so: start it, store the secret, restart it so it reads the secret.
  systemctl restart ekka || die "the Enclave did not start; see: journalctl -u ekka"
  wait_enclave
  (cd deploy && bash setup.sh enclave-secret "$env")
  systemctl restart ekka || die "the Enclave did not restart; see: journalctl -u ekka"
  wait_enclave
  rm -f "$DESKS_STATE/stack.hold"; systemctl reset-failed ekka-desks >/dev/null 2>&1 || true
  systemctl restart ekka-desks || die "the desks stack did not start; see: journalctl -u ekka-desks"
  wait_gateway
  echo "$stack_sha" >"$DESKS_STATE/stack.sha"
  edge_conf_sha >"$DESKS_STATE/edge-conf.sha"   # the edge was just started on this config
  done_ started
  ok "Enclave $EKKA_VERSION (systemd: ekka) and the desks stack (systemd: ekka-desks) are running"
}

# The setup and ask plans for one desk, owned by the desks agent: create_desk_plans <desk> <agent id>.
# A plan names its desk as a literal resource, so each desk has its own copy, made from ekka/plans/ by
# tools/desk_plans.py (example.desk.ask.<deskName>.v1). Created only when it changed (install_plans): EKKA never
# refuses an identical plan, it makes a patch version on every create, and a changed template becomes the newer
# version a bare plan code runs. ANY refusal stops here with EKKA's reason: treating one as "kept"
# would leave this machine running the old plan after an upgrade it never got.
# Shared by default: every member of the organization may run them (the desk installation checks), so a second
# member asks a desk without the administrator. `private` keeps them the administrator's alone.
create_desk_plans() {
  local desk=$1 agent=$2 sharing=${3:-shared} dir=$DESKS_STATE/plans made
  install -d -m 0755 "$dir"
  made=$(python3 tools/desk_plans.py "$desk" "$dir" "$agent") || die "no plans for desk '$desk'; see the line above"
  install_plans "$made" "$sharing"
}

# The two general desk administration plans, owned by the desks agent: create_desk_admin_plans <api gate> <agent id>.
# Runner 0.6.8 or newer runs desk commands through ekka.desk.read.v1 and ekka.desk.write.v1.
# Creating them declares api.read/api.write on the desks agent before the desks grant is asked for.
# The route is an input, so one pair serves every desk. Created only when changed, as above.
# The installer stops creating the nine per-operation plans; it never deletes or archives ones an organization holds.
create_desk_admin_plans() {
  local gate=$1 agent=$2 dir=$DESKS_STATE/plans made
  install -d -m 0755 "$dir"
  made=$(python3 tools/desk_plans.py --admin "$gate" "$dir" "$agent") || die "no desk administration plans; see the line above"
  install_plans "$made" private   # never offered: only the administrator changes desks
}

# Copies each plan tools/desk_plans.py wrote into the Enclave and creates it there:
# install_plans "<path> <code>"... shared|private. A shared plan is offered to the organization and accepted (share_plan).
install_plans() {
  local sharing=${2:-private}
  local path code out identity rung listed newest
  # `ekka plan create` makes a new version on every call, so a plan that is already EKKA's newest version, with the
  # same definition, name and agent, is not created again (tools/plan_same.py). Anything unreadable creates one.
  listed=$(ekka_in plan list --all --json 2>/dev/null </dev/null || true)
  # Every command in this loop gets /dev/null as input: otherwise the first one swallows the rest of the list.
  while read -r path code; do
    newest=""; rung=""   # nothing printed (no version held, or one unreadable) leaves both empty: create
    read -r newest rung < <(python3 tools/plan_same.py latest "$path" "$DESKS_AGENT" <<<"$listed" 2>/dev/null || true) || true
    if [[ -n ${newest:-} ]] && ekka_in plan show "$newest" --definition --json 2>/dev/null </dev/null \
         | python3 tools/plan_same.py same "$path" "$DESKS_AGENT" >/dev/null 2>&1; then
      ok "plan $newest, owned by $DESKS_AGENT (unchanged, no new version)"
      # A shared plan must also be offered to the organization: a version an earlier run made but could not share
      # is shared now (share_plan offers only an `unlisted` version, never one already at `org`).
      [[ $sharing == shared ]] && share_plan "$newest" "${rung:-}"
      continue
    fi
    enclave_home_file "plans/$(basename "$path")" 0600 < "$path"   # a file the Enclave's user may read
    out=$(ekka_in plan create "$ENCLAVE_HOME/plans/$(basename "$path")" 2>&1 </dev/null) \
      || die "the plan $code was not created: $(grep -v -E '^\s*$|STAGING|rehearsal' <<<"$out" | head -3 | tr '\n' ' ')
   see it again: sudo -i; ekka plan create $ENCLAVE_HOME/plans/$(basename "$path")"
    ok "plan $(grep -o -E "${code//./\\.}@[0-9.]+" <<<"$out" | head -1 || echo "$code"), owned by $DESKS_AGENT"
    if [[ $sharing == shared ]]; then
      # `ekka plan create` prints "✓ Plan created: <identity> · <rung>", the rung being EKKA's own answer.
      identity=$(grep -o -E "Plan created: ([a-z0-9-]+\\.)?${code//./\\.}@[0-9.]+" <<<"$out" | head -1 | sed 's/^Plan created: //' || true)
      rung=$(grep -o -E "Plan created: ([a-z0-9-]+\\.)?${code//./\\.}@[0-9.]+ · [a-z]+" <<<"$out" | head -1 | sed 's/.* · //' || true)
      share_plan "$identity" "$rung"
    fi
  done <<<"$1"
}

# Offer one plan version to the organization and accept it, so every member may run it: share_plan <identity> <rung>.
# ⛔ ONLY A VERSION EKKA JUST REPORTED `unlisted`. `ekka plan publish` on a version already at `org` offers it to
# EKKA's PUBLIC catalog, and up.sh runs again on every upgrade. So nothing else is ever offered, and the approval
# runs only when EKKA answered that the offer is for the organization.
share_plan() {
  local identity=$1 rung=$2 out
  if [[ -z $identity || $rung != unlisted ]]; then
    ok "plan ${identity:-?} is ${rung:-of unknown standing}: not offered (an offer of an org plan would go to EKKA's public catalog)"
    return 0
  fi
  out=$(ekka_in plan publish "$identity" 2>&1 </dev/null) \
    || die "the plan $identity was not offered to the organization: $(grep -v -E '^\s*$|STAGING|rehearsal' <<<"$out" | head -2 | tr '\n' ' ')"
  grep -q "requested for org" <<<"$out" \
    || die "the plan $identity was offered somewhere other than this organization, so it was not approved: $(grep -v -E '^\s*$' <<<"$out" | head -2 | tr '\n' ' ')"
  out=$(ekka_in plan approve "$identity" 2>&1 </dev/null) \
    || die "the plan $identity was offered but not approved: $(grep -v -E '^\s*$|STAGING|rehearsal' <<<"$out" | head -2 | tr '\n' ' ')"
  grep -q "is now org" <<<"$out" || die "the plan $identity was approved to something other than this organization: $(head -1 <<<"$out")"
  ok "plan $identity: every member of this organization may run it"
}

desks_agent_id() {
  ekka_in agent list --json 2>/dev/null \
    | DESKS_AGENT=$DESKS_AGENT python3 -c '
import json, os, sys
t = sys.stdin.read(); i = t.find("{")
# The first JSON document only: the ekka CLI prints a tier banner around it.
d = json.JSONDecoder().raw_decode(t[i:])[0] if i >= 0 else {"agents": []}
a = [x["agent_id"] for x in d["agents"] if x["agent_code"] == os.environ["DESKS_AGENT"]]
print(a[0] if a else "")' 2>/dev/null
}

step_grant() {  # a desks-only agent owns the desk plans and may work on every desk in this workspace
  is_done grant && { ok "the $DESKS_AGENT agent may work on this server's desks"; return; }
  say "a desks agent for your organization ($DESKS_AGENT)"
  # Its own agent, not the organization's core one: widening a published core agent is a new major version
  # that everyone who installed it must approve again, and desk work should not ride on other plans' agent.
  local ids id gate p
  ekka_in agent create "$DESKS_AGENT" --name "Desks" >/dev/null 2>&1 || true   # an agent that exists is kept
  ids=$( { ekka_in enclave status --json; echo; ekka_in agent list --json; echo; ekka_in gate list --json; } 2>/dev/null | DESKS_AGENT=$DESKS_AGENT python3 -c '
import json, os, sys
docs, buf = [], ""
for line in sys.stdin.read().splitlines():
    if not buf and not line.lstrip().startswith(("{", "[")): continue   # banners and blank lines
    buf += line + "\n"
    try: docs.append(json.loads(buf)); buf = ""
    except ValueError: pass
status, agents, gates = (d for d in docs[:3])
node = status["node_id"]
agent = [a["agent_id"] for a in agents["agents"] if a["agent_code"] == os.environ["DESKS_AGENT"]]
job = [g["instance_id"] for g in gates if g.get("connector_type") == "job" and g.get("node_id") == node]
print(agent[0] if agent else "", job[0] if job else "")') || true
  read -r id gate <<<"$ids"
  [[ -n $id && -n $gate ]] || die "could not find agent $DESKS_AGENT or this Enclave's job gate; see: sudo -i; ekka agent list"
  # The example plans for code-desk, owned by that agent (plan.agent): creating them declares job.run on it,
  # and only on it. Another desk gets its own: sudo ekka desk plans <desk>.
  create_desk_plans code-desk "$id"
  if ekka_in gate grant list 2>/dev/null | grep -q "job.run $gate/desks/\*  agent $id "; then
    ok "$DESKS_AGENT already may work on desks/* (kept)"
  else
    ekka_in gate grant add --agent "$DESKS_AGENT" --type job --instance "$gate" --resource 'desks/*' --capability job.run --no-fingerprint \
      | grep -E "Granted|take it back" || die "the grant was refused; is your organization's edition allowed to run jobs (job.run)?"
  fi
  done_ grant
}

step_agent_open() {  # every member may RUN the desks agent's shared plans; writing plans under it stays listed
  is_done agent_open && { ok "every member may run the plans of $DESKS_AGENT"; return; }
  # Since a change in Govern, a new agent is `listed`: only its creator, owners and admins may run its plans, so
  # a member's run of a shared desk plan (create_desk_plans offers them to the organization) is refused. Use only:
  # a member still cannot RUN an unshared plan (the admin plans are never offered, and each requires the admin
  # role), and nobody writes a plan under this agent unless an owner appoints them (`--as author`).
  # The floor (DESK_ADMIN_MIN_EKKA, 0.6.8) has `ekka agent allow`; the read-back below
  # stops the install on any EKKA where it did not take, whatever the reason.
  local out mode
  out=$(ekka_in agent allow "$DESKS_AGENT" --everyone --as use 2>&1 </dev/null) \
    || die "EKKA refused to let every member run the plans of $DESKS_AGENT: $(grep -v -E '^\s*$|STAGING|rehearsal' <<<"$out" | head -2 | tr '\n' ' ')"
  # Confirmed from Govern's own record, not from the sentence `allow` prints: `agent show --json` names the mode
  # as access.use, and a mode Govern could not read is "unknown (refused)", never open.
  mode=$(ekka_in agent show "$DESKS_AGENT" --json 2>/dev/null </dev/null | python3 -c '
import json, sys
t = sys.stdin.read(); i = t.find("{")
# The first JSON document only: the ekka CLI prints a tier banner around it.
d = json.JSONDecoder().raw_decode(t[i:])[0] if i >= 0 else {}
print((d.get("access") or {}).get("use", ""))' 2>/dev/null) || true
  [[ $mode == open ]] || die "EKKA accepted the change, but $DESKS_AGENT reads as '${mode:-nothing}', not open. As root (sudo -i): ekka agent show $DESKS_AGENT"
  ok "every member may run the plans of $DESKS_AGENT; writing plans under it still needs an owner (--as author)"
  done_ agent_open
}

# The provider digests the desks grant holds: `--provider <name>=<digest>` for each provider this gateway holds,
# computed by the adapter from the gateway's own records (ekka-backend `digest provider`). None yet: a
# grant with no provider lets a desk attach none, which is the closed side.
desk_provider_args() {  # --provider <name>=<digest>, one per provider this gateway holds
  # The adapter reads each provider from the gateway itself, `digest provider --from-gateway`, with the same calls
  # and the same function it enforces with, so the grant and the check share one source. It runs as the adapter's
  # own service (its image, mounts, user and network) and signs in as the desk-admin client, whose secret goes from
  # Keycloak to its stdin and nowhere else. It runs INSIDE the adapter that is already running (`compose exec`), never
  # as a throwaway container (`compose run`): the stack's unit runs `compose up --abort-on-container-exit` in the
  # foreground, which attached to each throwaway container and stopped the whole stack when it exited. A shipped provider is named after its profile (`ekka desk connect`), so each
  # profile name is asked: PROVIDER_NOT_FOUND means it is not connected here and is left out (a create naming it is
  # then refused CONSTRAINT_PROVIDERS, closed). Any other refusal stops the grant.
  local p out err why
  err=$(mktemp)
  (cd deploy && bash setup.sh backend-preflight --always) || return 1   # the adapter runs by name below
  # The running adapter, healthy: the digest is asked of it. Not running means no digest and no grant change.
  local i healthy=""; for i in $(seq 1 30); do
    [[ $(docker inspect -f '{{.State.Health.Status}}' ekka-desks-ekka-backend-1 2>/dev/null) == healthy ]] && { healthy=1; break; }
    sleep 2; done
  [[ -n $healthy ]] || { rm -f "$err"; echo "the backend adapter is not running and healthy, so no provider could be read; see: sudo ./deploy/setup.sh compose logs ekka-backend" >&2; return 1; }
  # Keycloak first, on its own: inside the pipe below its failure reaches the adapter as an empty stdin, which the
  # adapter can only report as SECRET_INVALID against whichever provider came first.
  kc admin-client on >/dev/null 2>"$err" || {
    why=$(tail -n1 "$err" | cut -c1-200); rm -f "$err"
    echo "the sign-in service (Keycloak) did not give the adapter its secret (${why:-no reason given}); see: journalctl -u ekka-desks" >&2
    return 1; }
  for p in $(profile_names); do
    if out=$( { kc admin-client on | (cd deploy && docker compose -f compose.yml --env-file "$DESKS_STATE/up.env" \
          exec -T ekka-backend /usr/local/bin/ekka-backend digest provider --from-gateway "$p" --config /etc/ekka-backend/config.json); } 2>"$err"); then
      [[ $out =~ ^sha256:[0-9a-f]{64}$ ]] || { rm -f "$err"; echo "provider $p's digest is not sha256:<64 hex>" >&2; return 1; }
      printf -- '--provider %s=%s\n' "$p" "$out"
    elif grep -q '^PROVIDER_NOT_FOUND' "$err"; then
      continue
    else
      why=$(grep -m1 -E '^[A-Z][A-Z_]+' "$err" | cut -c1-200); rm -f "$err"
      echo "the adapter could not read provider $p (${why:-no reason given})" >&2; return 1
    fi
  done
  rm -f "$err"
}

step_desk_grant() {  # the desks grant with its limits: only once up.env runs the backend adapter
  grep -q '^EKKA_BACKEND_IMAGE=.' "$DESKS_STATE/up.env" 2>/dev/null || return 0
  say "the desks grant, with its limits"
  local image desk_id pdig ids id gate limits=$DESKS_STATE/backend/desks-grant.json decision g
  image=$(sed -n 's/^EKKA_BACKEND_IMAGE=//p' "$DESKS_STATE/up.env")
  # The content ID of the image built from the pinned EKKA image repository.
  desk_id=$(docker image inspect --format '{{.Id}}' ekka-desk:local 2>/dev/null) || die "the desk image is not built; run again"
  # The reviewed baseline's digest, by the adapter's own code from its pinned image, with no network.
  pdig=$(docker run --rm -i --network none "$image" digest policy - < desk/policy.json) \
    || die "the backend adapter could not digest desk/policy.json; no grant was changed"
  ids=$( { ekka_in enclave status --json; echo; ekka_in agent list --json; echo; ekka_in gate list --json; } 2>/dev/null | DESKS_AGENT=$DESKS_AGENT python3 -c '
import json, os, sys
docs, buf = [], ""
for line in sys.stdin.read().splitlines():
    if not buf and not line.lstrip().startswith(("{", "[")): continue
    buf += line + "\n"
    try: docs.append(json.loads(buf)); buf = ""
    except ValueError: pass
status, agents, gates = (d for d in docs[:3])
node = status["node_id"]
agent = [a["agent_id"] for a in agents["agents"] if a["agent_code"] == os.environ["DESKS_AGENT"]]
api = [g["instance_id"] for g in gates if g.get("connector_type") == "api" and g.get("node_id") == node]
print(agent[0] if agent else "", api[0] if api else "")') || true
  read -r id gate <<<"$ids"
  [[ -n $id && -n $gate ]] || die "could not find agent $DESKS_AGENT or this Enclave's API gate; no grant was changed"
  # The plans first, every run: EKKA refuses the grant to an agent no plan declares api.write on, and a box whose
  # grant is already in place still gets an upgrade's plans (the "kept" return below would otherwise skip them).
  create_desk_admin_plans "$gate" "$id"
  install -d -m 0755 "$(dirname "$limits")"
  # Collected FIRST, so a refusal stops here: inside $(...) on the limits line a failure would be lost.
  local providers; providers=$(desk_provider_args) || die "the providers' digests could not be read; no grant was changed"
  # A discovery window (sudo ekka desk grant discovery …) adds its image and the grant's `discovery` block, from the
  # window file it wrote; `restore` removes that file, and this step writes the shipped limits again.
  local extras_file=$DESKS_STATE/backend/desks-grant.extras.json extra_args=()
  [[ -f $extras_file ]] && extra_args=(--window "$extras_file")
  # The ceiling comes from the very profile files the gateway holds (sync_profiles imports the same ones), so a
  # profile can never sit outside it: an install's own providers.local file in place of the shipped one.
  local profile_args=() profile_files=() pname psrc
  for pname in $(profile_names); do
    psrc=$(profile_source "$pname") || die "profile $pname could not be read; no grant was changed"
    profile_args+=(--profile "$psrc"); profile_files+=("$psrc")
  done
  # The same ceiling as a record EKKA's desk commands read (each profile's hosts): root's, from / down.
  python3 tools/desk_records.py ceiling "$DESKS_STATE/backend/provider-ceiling.json" "${profile_files[@]}" \
    || die "the provider ceiling record could not be confirmed; no grant was changed"
  # A project (sudo ekka desk grant project add …) adds its own image and its own policy, from the record it wrote;
  # `project remove` deletes that record. Unlike a window it has no end, so every run of this step keeps it.
  local project_args=() pfile
  for pfile in "$DESKS_STATE"/backend/projects/*.project.json; do
    [[ -f $pfile && ! -L $pfile ]] && project_args+=(--project "$pfile")
  done
  # shellcheck disable=SC2086  # one --provider word and one name=digest word per provider; the window and the projects expand to nothing when absent
  python3 tools/desk_grant.py limits --image-id "$desk_id" --policy-digest "$pdig" $providers "${profile_args[@]}" ${extra_args[@]+"${extra_args[@]}"} ${project_args[@]+"${project_args[@]}"} > "$limits.new" \
    || die "the desks grant's limits could not be written; no grant was changed"
  mv "$limits.new" "$limits"
  decision=$(ekka_in gate grant list --json | python3 tools/desk_grant.py decide "$id" "$gate" "$limits") \
    || die "could not read this organization's grants; no grant was changed"
  if [[ $decision == keep* ]]; then ok "the desks grant already holds these limits (kept)"; return; fi
  # ADD FIRST, revoke after: desks are never left without a grant. The limits reach the CLI in the Enclave's
  # container on stdin, as a file only inside it, removed after.
  local grant_out
  # Drain the command before checking its words: grep -q can close stdout early,
  # making a successful CLI write fail with SIGPIPE under pipefail.
  enclave_home_file desks-grant.json 0600 < "$limits"   # the limits, as a file the Enclave's user may read
  grant_out=$(ekka_in gate grant add --agent "$DESKS_AGENT" --type api --instance "$gate" --resource apis/desks \
      --capability api.write --ttl 31536000 --constraint "$ENCLAVE_HOME/desks-grant.json") \
    || { rm -f "$ENCLAVE_HOME/desks-grant.json"; die "the desks grant outcome could not be confirmed; the previous grant, if any, is kept"; }
  rm -f "$ENCLAVE_HOME/desks-grant.json"
  grep -q "Granted" <<<"$grant_out" \
    || die "the desks grant outcome could not be confirmed; the previous grant, if any, is kept"
  for g in ${decision#replace}; do
    [[ $decision == replace* ]] || break
    ekka_in gate grant revoke "$g" >/dev/null || die "the new desks grant is in place, but $g was not revoked"
  done
  ok "the $DESKS_AGENT agent may administer desks within the limits in $limits"
}

configure_enclave_cli() {
  # Public defaults only: never import a person's sign-in, token or client secret.
  enclave_home_file desks-ca.pem 0644 < "$DESKS_STATE/people/desks-ca.pem" \
    && enclave_home_file desk-policy.json 0644 < "$DESKS_STATE/people/desk-policy.json" \
    && enclave_home_file backend.json 0600 < "$DESKS_STATE/enclave-cli/backend.json" \
    && ekka_in desk backend set "$ENCLAVE_HOME/backend.json"
}

server_ekka() {
  local a
  for a in "$@"; do
    case $a in
      --token|--token=*|--access-token|--access-token=*|--refresh-token|--refresh-token=*|--id-token|--id-token=*|--password|--password=*|--client-secret|--client-secret=*|--api-key|--api-key=*|--secret|--secret=*)
        die "do not pass a credential as an argument; use the command's sign-in or hidden-input flow" ;;
    esac
  done
  enclave_ekka "$@"
}

# A registry's read-only credential. OpenShell creates a desk from an image already on
# this machine and pulls with no login (NVIDIA/OpenShell#2676), and `ekka` has no image command on purpose (the Enclave
# never holds Docker, which is root here). So the pull is this installer's, as root, through the `ekka` wrapper. The
# token comes on stdin only, is checked before it is kept, lives root-only under the install's secrets, and is used
# through a throwaway Docker config that is deleted after each pull: no login is ever saved on this machine.
registry_dir() { install -d -m 0700 -o root -g root "$DESKS_STATE/secrets/registry"; echo "$DESKS_STATE/secrets/registry"; }
registry_login() {
  local host=$1 user=$2 token scopes cfg
  [[ $host =~ ^[a-z0-9.-]+(:[0-9]+)?$ && -n $user && $user =~ ^[A-Za-z0-9._-]+$ ]] \
    || die "usage: <token> | sudo ekka desk registry login <host> <user>   (the token comes on stdin, never as an argument)"
  [[ -t 0 ]] && die "the token comes from a pipe, never typed at a terminal: <token source> | sudo ekka desk registry login $host $user"
  IFS= read -r -d '' token || true; token=${token%$'\n'}
  [[ -n $token && $token != *[[:space:]]* && ${#token} -le 8192 ]] || { token=; die "stdin must carry exactly one token: no spaces, no second line; nothing was kept"; }
  cfg=$(mktemp -d "$DESKS_STATE/secrets/.registry-login.XXXXXX"); chmod 0700 "$cfg"
  # shellcheck disable=SC2064  # expanded now on purpose: the folder's name
  trap "rm -rf '$cfg'" EXIT
  if [[ $host == ghcr.io || $host == *.pkg.github.com ]]; then
    # GitHub Packages: a CLASSIC token whose scopes are exactly read:packages. Its npm registry refuses fine-grained tokens,
    # and anything wider than read:packages is more than a pull needs. The header reaches curl from a file, never argv.
    [[ $token == ghp_* ]] || { token=; die "GitHub Packages needs a classic token (ghp_…) with the scope read:packages only; nothing was kept"; }
    printf 'header = "Authorization: token %s"\n' "$token" > "$cfg/curl.cfg"; chmod 0600 "$cfg/curl.cfg"
    scopes=$(curl -fsS -K "$cfg/curl.cfg" -o /dev/null -D - https://api.github.com/user 2>/dev/null | tr -d '\r' | sed -n 's/^x-oauth-scopes: *//Ip' | head -1)
    [[ $scopes == "read:packages" ]] || { token=; die "the token's scopes are '${scopes:-none}', not exactly read:packages; nothing was kept"; }
    ok "GitHub token: scope read:packages only"
  fi
  mkdir -p "$cfg/docker"
  printf '%s' "$token" | docker --config "$cfg/docker" login "$host" -u "$user" --password-stdin >/dev/null 2>&1 \
    || { token=; die "$host refused the credential for $user; nothing was kept"; }
  docker --config "$cfg/docker" logout "$host" >/dev/null 2>&1 || true
  local dir; dir=$(registry_dir)
  ( umask 077; printf 'REGISTRY_USER=%s\nREGISTRY_TOKEN=%s\n' "$user" "$token" > "$dir/$host.env.new" ) && mv -f "$dir/$host.env.new" "$dir/$host.env"
  token=
  ok "$host: read credential for $user kept (root only, $dir/$host.env). Pull with: sudo ekka desk image pull $host/<name>@sha256:<64 hex>"
}
registry_show() {
  local f n=0
  for f in "$DESKS_STATE"/secrets/registry/*.env; do
    [[ -f $f ]] || continue; n=$((n+1))
    printf '%s  as %s\n' "$(basename "${f%.env}")" "$(sed -n 's/^REGISTRY_USER=//p' "$f")"
  done
  (( n > 0 )) || echo "no registry credential kept; public images need none"
}
image_pull() {  # image_pull <ref@sha256:…> [--signed-by <identity> --issuer <url>]: by digest, signature checked when asked, no login saved
  local ref="" identity="" issuer=""
  while (( $# )); do case "$1" in
    --signed-by) identity=${2:-}; shift 2 ;; --issuer) issuer=${2:-}; shift 2 ;;
    --*) die "usage: sudo ekka desk image pull <registry>/<name>@sha256:<64 hex> [--signed-by <certificate identity> --issuer <oidc issuer>]" ;;
    *) [[ -z $ref ]] || die "one image at a time"; ref=$1; shift ;; esac; done
  [[ $ref =~ ^[a-z0-9.-]+(:[0-9]+)?(/[a-z0-9._-]+)+@sha256:[0-9a-f]{64}$ ]] \
    || die "the image must be <registry>/<name>@sha256:<64 hex>: a digest names exactly one image, a tag can move"
  [[ -z $identity && -z $issuer || -n $identity && -n $issuer ]] || die "--signed-by and --issuer go together"
  local host=${ref%%/*} digest=${ref##*@} cfg cred
  cfg=$(mktemp -d "$DESKS_STATE/secrets/.image-pull.XXXXXX"); chmod 0700 "$cfg"; mkdir -p "$cfg/docker"
  # shellcheck disable=SC2064
  trap "docker --config '$cfg/docker' logout '$host' >/dev/null 2>&1 || true; rm -rf '$cfg'" EXIT
  cred=$DESKS_STATE/secrets/registry/$host.env
  if [[ -f $cred ]]; then
    sed -n 's/^REGISTRY_TOKEN=//p' "$cred" | docker --config "$cfg/docker" login "$host" -u "$(sed -n 's/^REGISTRY_USER=//p' "$cred")" --password-stdin >/dev/null 2>&1 \
      || die "$host refused the kept credential; renew it: <token> | sudo ekka desk registry login $host <user>"
  fi
  if [[ -n $identity ]]; then
    command -v cosign >/dev/null || die "cosign is missing, so the signature cannot be checked; nothing was pulled"
    DOCKER_CONFIG="$cfg/docker" cosign verify --certificate-identity "$identity" --certificate-oidc-issuer "$issuer" "$ref" >/dev/null 2>&1 \
      || die "$ref is not signed by $identity ($issuer); nothing was pulled"
    ok "signature: built by $identity"
  fi
  docker --config "$cfg/docker" pull -q "$ref" >/dev/null \
    || die "could not pull $ref: does this machine reach $host, and is the kept credential allowed to read it?"
  docker image inspect --format '{{join .RepoDigests "\n"}}' "$ref" 2>/dev/null | grep -q -F "@$digest" \
    || die "the pulled image does not carry $digest; nothing to use"
  ok "pulled $ref"
  echo "   next, to let one desk be made from it for discovery: sudo ekka desk grant discovery --image $ref --providers <provider>,<provider>"
}

step_people() {
  (cd deploy && bash setup.sh people >/dev/null)
  configure_enclave_cli || die "the Enclave's public desk defaults could not be set; run the install again"
  local fp; fp=$(openssl x509 -in "$DESKS_STATE/people/desks-ca.pem" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2) || fp="see docs/OPERATIONS.md, Certificates"
  # Written for the person at the terminal: numbered, in the order an administrator does them, one command per line.
  # Every line a person types is an `ekka` command: the server's administration verbs (key, people, a desk's plans) are
  # this script's, reached through the installed wrapper's `ekka desk connect|invite|revoke|plans`. The browser trust
  # command is printed by install.sh on the person's own computer.
  printf '\n\033[1m-- installed --\033[0m\n'
  printf '%s\n' "The server is ready. Its sign-in page is https://$NAME

What to do next, in this order:

1. Connect the company's $AGENT key, once, on this server. Pipe it in; never type it as an argument:
     <your $AGENT key> | sudo ekka desk connect $AGENT
   Private repositories need a read-only GitHub token as well:
     <your GitHub token> | sudo ekka desk connect github

2. Make the first desk, as root on this server:
     sudo -i
     ekka desk login
     ekka desk create code-desk --provider $AGENT
     exit
   For private repositories, add: --provider github

3. Add each person who will use desks:
     sudo ekka desk invite <username> <email>
   It prints their one-time password. Give them that, and the folder $DESKS_STATE/people/

4. Each person, on their own computer, from that folder:
     ./install.sh desks
     ekka desk login
   install.sh prints the one command that makes their browser trust this server's certificate.
   Before they run it, they check the certificate's fingerprint against this one:
     $fp

More desks: sudo ekka desk plans <desk>, then as root: ekka desk create <desk> --provider $AGENT
Guides: docs/SERVER.md, docs/SET-UP-YOUR-DESK.md, docs/ASK-YOUR-CODE.md"
}

case "${1:-}" in
  server) MODE=server; NAME=${2:-}; [[ $# == 2 && $NAME =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ ]] || die "usage: ./up.sh server <dns-name>"; MODE_ARGS="server $NAME" ;;
  status)
    ls -1 "$DONE" 2>/dev/null | sed 's/^/done: /' || echo "nothing done yet"
    if is_done started; then
      echo "ekka (the Enclave): $(systemctl is-active ekka 2>/dev/null)   ekka-desks (the stack): $(systemctl is-active ekka-desks 2>/dev/null)"
      [[ $(systemctl is-enabled ekka-desks 2>/dev/null) == masked ]] && echo "ekka-desks is MASKED: the emergency stop (docs/OPERATIONS.md). Resume: sudo systemctl unmask ekka-desks && sudo systemctl enable --now ekka-desks"
      [[ $(systemctl show -p Result --value ekka-desks 2>/dev/null) == start-limit-hit ]] && echo "ekka-desks hit its start limit (ten starts in five minutes): sudo journalctl -u ekka-desks -n 50, then sudo systemctl reset-failed ekka-desks && sudo systemctl start ekka-desks"
      [[ -S /run/ekka/openshell-interceptor.sock ]] && echo "interceptor socket: present" || { echo "interceptor socket: MISSING"; exit 1; }
      docker ps --format '  {{.Names}}: {{.Status}}' --filter label=com.docker.compose.project=ekka-desks
      [[ $(systemctl is-active ekka) == active && $(systemctl is-active ekka-desks) == active ]] || exit 1
    fi
    exit 0 ;;
  invite)  # one more person who uses desks: sudo ekka desk invite <username> <email> (the wrapper runs this verb)
    [[ $(id -u) == 0 ]] || die "run with sudo"
    NAME=$(sed -n 's/^DESKS_NAME=//p' "$DESKS_STATE/up.env" 2>/dev/null); [[ -n $NAME ]] || die "not installed yet"
    who=${2:-}; mail=${3:-}
    [[ $who =~ ^[a-z0-9][a-z0-9._-]{1,40}$ && $mail == *@*.* ]] || die "usage: sudo ekka desk invite <username> <email>"
    pf=$DESKS_STATE/secrets/people/$who-password; install -d -m 0700 "$(dirname "$pf")"
    if [[ -e $pf ]]; then
      # Invited before. If that invite made the account and then failed to add the person to the workspace, this run
      # finishes it with the same account and one-time password; someone the workspace holds is refused, as before.
      sub=$( (cd deploy && KC_URL=https://127.0.0.1:8443 KC_CA=$DESKS_STATE/tls/ca.crt KC_ADMIN_USER=desks-bootstrap \
        KC_ADMIN_PASSWORD_FILE=$DESKS_STATE/secrets/keycloak-admin-password \
        python3 keycloak/apply_realm.py person-id "$who") | tail -1) || die "$who has a one-time password file but no account to finish; see the line above"
      [[ $sub =~ ^[0-9a-f-]{36}$ ]] || die "Keycloak did not name $who's id; nothing was changed"
      is_member() {  # 0: the workspace holds the person; 1: a list that ANSWERED does not; 2: failed or unreadable
        local found  # the list piped straight in (pipefail): a variable would drop a NUL byte; either failing is 2
        found=$("$OS" -g ekka-agent-desks workspace member list --workspace desks --page-size 10000 -o json \
          | python3 tools/workspace_member.py "$1") || return 2
        case $found in named) return 0 ;; absent) return 1 ;; *) return 2 ;; esac  # only the printed word counts
      }
      rc=0; as_gateway_admin is_member "$sub" || rc=$?
      case $rc in
        0) die "$who was invited already; their one-time password: sudo cat $pf" ;;
        1) ;;
        *) die "the desk workspace could not be read, so $who was not added; nothing was changed" ;;
      esac
    else
      ( umask 077; openssl rand -base64 24 | tr -d '\n' > "$pf" )
      sub=$( (cd deploy && KC_URL=https://127.0.0.1:8443 KC_CA=$DESKS_STATE/tls/ca.crt KC_ADMIN_USER=desks-bootstrap \
        KC_ADMIN_PASSWORD_FILE=$DESKS_STATE/secrets/keycloak-admin-password KC_PERSON_PASSWORD_FILE=$pf \
        python3 keycloak/apply_realm.py person "$who" "$mail") | tail -1) || { rm -f "$pf"; die "the sign-in account was not created"; }
    fi
    add_member() { "$OS" -g ekka-agent-desks workspace member add --workspace desks --subject "$1" --role user; }
    as_gateway_admin add_member "$sub" >/dev/null || die "$who can sign in but is not in the desk workspace yet; run invite again after fixing the gateway"
    ok "$who ($mail) may use desks"
    echo "   Give them: the people bundle ($DESKS_STATE/people/) and their one-time password, changed at first sign-in:"
    echo "     sudo cat $pf"
    echo "   Read them this fingerprint, so they can check the CA in the bundle before their browser trusts it:"
    echo "     $(openssl x509 -in "$DESKS_STATE/people/desks-ca.pem" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)"
    exit 0 ;;
  revoke)  # that person taken off again: sudo ekka desk revoke <username>. Running it twice changes nothing.
    [[ $(id -u) == 0 ]] || die "run with sudo"
    NAME=$(sed -n 's/^DESKS_NAME=//p' "$DESKS_STATE/up.env" 2>/dev/null); [[ -n $NAME ]] || die "not installed yet"
    who=${2:-}
    [[ $# == 2 && $who =~ ^[a-z0-9][a-z0-9._-]{1,40}$ ]] || die "usage: sudo ekka desk revoke <username>"
    # Keycloak first: the sign-in is disabled and every session ended, so the person cannot start a new one while
    # the gateway is changed. It refuses a name that is not here and an administrator, changing nothing.
    sub=$( (cd deploy && KC_URL=https://127.0.0.1:8443 KC_CA=$DESKS_STATE/tls/ca.crt KC_ADMIN_USER=desks-bootstrap \
      KC_ADMIN_PASSWORD_FILE=$DESKS_STATE/secrets/keycloak-admin-password python3 keycloak/apply_realm.py revoke "$who") \
      | tail -1) || die "$who was not revoked; see the line above"
    [[ $sub =~ ^[0-9a-f-]{36}$ ]] || die "Keycloak did not name $who's id; nothing more was changed"
    remove_member() {  # removed, or already not a member. A failed remove counts as done only when a list that
      # ANSWERED and parsed does not name the person: a list that fails or cannot be read is never "not a member".
      local found
      "$OS" -g ekka-agent-desks workspace member remove --workspace desks --subject "$1" >/dev/null 2>&1 && return 0
      found=$("$OS" -g ekka-agent-desks workspace member list --workspace desks --page-size 10000 -o json \
        | python3 tools/workspace_member.py "$1") || return 1
      [[ $found == absent ]]  # only the printed word counts: a crash or an unreadable list is never "absent"
    }
    as_gateway_admin remove_member "$sub" \
      || die "$who can no longer sign in, but may still be in the desk workspace; run revoke again after fixing the gateway"
    rm -f "$DESKS_STATE/secrets/people/$who-password"
    ok "$who may no longer use desks: their sign-in is disabled, every session ended, and they are out of the desk workspace"
    exit 0 ;;
  desks)  # one unfinished desk change, settled on this machine: sudo ./up.sh desks settle <desk> --operation <request id>
    [[ $(id -u) == 0 ]] || die "run with sudo"
    case ${2:-} in
      settle) exec python3 tools/desks_settle.py "${@:3}" ;;
      unhold) exec python3 tools/desks_settle.py --unhold "${@:3}" ;;  # after a settle that stopped, and a look at the desk
      *) die "usage: sudo ./up.sh desks settle <desk> --operation <request id> [--backend-id <uuid>] | desks unhold <desk> --operation <request id>" ;;
    esac ;;
  walk)  # every documented command, run against this installation: sudo ./up.sh walk
    exec bash tools/walk.sh ;;
  ekka)  # the ekka CLI of this server's Enclave, signed in as the person who installed it: ./up.sh ekka plan list
    [[ $(id -u) == 0 ]] || die "run with sudo"
    # Its own exit: enclave_ekka RETURNS (the container version exec'd into compose and never came back), and without
    # this the install sequence below ran after every `./up.sh ekka` (measured on the walk: "MODE: unbound variable").
    shift; rc=0; server_ekka "$@" || rc=$?; exit $rc ;;
  desk-plans)  # the setup and ask plans for one more desk: sudo ekka desk plans <desk> [--private]
    [[ $(id -u) == 0 ]] || die "run with sudo"
    [[ -f $DESKS_STATE/up.env ]] || die "not installed yet"
    desk=${2:-}; [[ -n $desk && $desk != --* ]] || die "usage: sudo ekka desk plans <desk> [--private]"
    case "${3:-}" in "") sharing=shared ;; --private) sharing=private ;; *) die "usage: sudo ekka desk plans <desk> [--private]" ;; esac
    id=$(desks_agent_id); [[ -n $id ]] || die "no agent $DESKS_AGENT yet; run the install first"
    create_desk_plans "$desk" "$id" "$sharing"; exit 0 ;;
  profiles)  # after an upgrade of providers/: put this repository's profiles into the gateway
    [[ $(id -u) == 0 ]] || die "run with sudo"
    NAME=$(sed -n 's/^DESKS_NAME=//p' "$DESKS_STATE/up.env" 2>/dev/null); [[ -n $NAME ]] || die "not installed yet"
    python3 -m unittest tests.test_providers >/dev/null 2>&1 || die "providers/ does not match providers/PIN.json; nothing was changed"
    say "provider profiles"; as_gateway_admin sync_profiles || die "the profiles were not updated"; exit 0 ;;
  connect)  # a provider's key, set on this machine: gh auth token | sudo ekka desk connect github
    [[ $(id -u) == 0 ]] || die "run with sudo"
    NAME=$(sed -n 's/^DESKS_NAME=//p' "$DESKS_STATE/up.env" 2>/dev/null); [[ -n $NAME ]] || die "not installed yet"
    connect_cmd "${@:2}"; exit $? ;;
  registry)  # a registry's read-only credential, for pulling project images: <token> | sudo ekka desk registry login <host> <user>
    [[ $(id -u) == 0 ]] || die "run with sudo"; [[ -f $DESKS_STATE/up.env ]] || die "not installed yet"
    case "${2:-}" in
      login) registry_login "${3:-}" "${4:-}"; exit $? ;;
      show) registry_show; exit 0 ;;
      logout) [[ ${3:-} =~ ^[a-z0-9.-]+(:[0-9]+)?$ ]] || die "usage: sudo ekka desk registry logout <host>"
              rm -f "$DESKS_STATE/secrets/registry/${3}.env" && ok "no credential kept for ${3}"; exit 0 ;;
      *) die "usage: <token> | sudo ekka desk registry login <host> <user>   |   sudo ekka desk registry show | logout <host>" ;;
    esac ;;
  image)  # a project image onto this machine, by digest: sudo ekka desk image pull <registry>/<name>@sha256:<64 hex> [--signed-by <identity> --issuer <url>]
    [[ $(id -u) == 0 ]] || die "run with sudo"; [[ -f $DESKS_STATE/up.env ]] || die "not installed yet"
    case "${2:-}" in
      pull) image_pull "${@:3}"; exit $? ;;
      *) die "usage: sudo ekka desk image pull <registry>/<name>@sha256:<64 hex> [--signed-by <certificate identity> --issuer <oidc issuer>]" ;;
    esac ;;
  grant)  # the desks grant's limits: sudo ekka desk grant show | discovery --image <ref@sha256:…> --providers <a,b> [--minutes 60] | restore | project add <name> --image sha256:<id> --policy <file> | project remove <name>
    [[ $(id -u) == 0 ]] || die "run with sudo"; [[ -f $DESKS_STATE/up.env ]] || die "not installed yet"
    limits=$DESKS_STATE/backend/desks-grant.json; extras=$DESKS_STATE/backend/desks-grant.extras.json
    projects=$DESKS_STATE/backend/projects
    grant_projects=()   # every project's record, for `show` to name its image and policy
    for pfile in "$projects"/*.project.json; do [[ -f $pfile && ! -L $pfile ]] && grant_projects+=(--project "$pfile"); done
    case "${2:-}" in
      show)
        [[ -f $limits ]] || die "no desks grant yet: the install writes it once the backend adapter is on"
        python3 tools/desk_grant.py show "$limits" "$extras" --profiles "$(profile_names | paste -sd, -)" ${grant_projects[@]+"${grant_projects[@]}"}; exit 0 ;;
      project)  # a project's own desk: its image, built on this server, and its own policy, added to the grant until removed
        project_usage="usage: sudo ekka desk grant project add <name> --image sha256:<64 hex> --policy <file> | project remove <name>"
        verb=${3:-}; pname=${4:-}
        [[ $verb == add || $verb == remove ]] || die "$project_usage"
        [[ $pname =~ ^[a-z0-9][a-z0-9._-]{0,62}$ ]] || die "a project's name is lowercase letters, digits, '.', '_' and '-'. $project_usage"
        [[ -f $limits ]] || die "no desks grant yet: the install writes it once the backend adapter is on"
        rec=$projects/$pname.project.json; kept=$projects/$pname.policy.json
        if [[ $verb == remove ]]; then
          (( $# == 4 )) || die "$project_usage"
          [[ -f $rec ]] || { echo "no project $pname is in the grant; nothing was changed"; exit 0; }
          mv "$rec" "$rec.old"
          if ! ( step_desk_grant ); then
            mv "$rec.old" "$rec"; ( step_desk_grant ) >/dev/null 2>&1 || true
            die "the desks grant was not changed; project $pname is still in it. Check: sudo ekka desk grant show"
          fi
          rm -f "$rec.old" "$kept"
          ok "project $pname is out of the grant: no new desk may be created from its image or with its policy. Its desks are not deleted"; exit 0
        fi
        shift 4; pimg=""; ppol=""
        while (( $# )); do case "$1" in --image) pimg=${2:-}; shift 2 ;; --policy) ppol=${2:-}; shift 2 ;; *) die "$project_usage" ;; esac; done
        [[ $pimg =~ ^sha256:[0-9a-f]{64}$ ]] \
          || die "--image must be sha256:<64 hex>, the content ID of an image built on this server (docker image inspect --format '{{.Id}}' <tag>); a tag can move, an ID cannot"
        [[ -n $ppol && -f $ppol && ! -L $ppol ]] || die "--policy must name the project's policy file (a real file, not a link)"
        # OpenShell creates a desk only from an image already on this machine (it never pulls), so one that is not here
        # could never make a desk: refused before anything is written.
        [[ $(docker image inspect --format '{{.Id}}' "$pimg" 2>/dev/null) == "$pimg" ]] \
          || die "image $pimg is not on this server; build it here first. Nothing was changed"
        adapter=$(sed -n 's/^EKKA_BACKEND_IMAGE=//p' "$DESKS_STATE/up.env")
        [[ -n $adapter ]] || die "the backend adapter is not on yet; nothing was changed"
        # The policy's digest, by the adapter's own code from its pinned image, with no network: the very digest a
        # create of this policy is held to. A file the adapter does not read as a policy stops here.
        # ONE copy is taken first, root-owned, and everything below reads that copy: the digest, the checks and the
        # file a desk is created with are then the same bytes, whatever happens to the file that was named.
        install -d -m 0755 "$projects"
        install -m 0644 "$ppol" "$kept.new" || die "$ppol could not be read; nothing was changed"
        ppdig=$(docker run --rm -i --network none "$adapter" digest policy - < "$kept.new") \
          || { rm -f "$kept.new"; die "the backend adapter does not read $ppol as a desk policy; nothing was changed"; }
        pprof=()
        for pn in $(profile_names); do
          psrc=$(profile_source "$pn") || { rm -f "$kept.new"; die "profile $pn could not be read; nothing was changed"; }
          pprof+=(--profile "$psrc")
        done
        python3 tools/desk_grant.py project --name "$pname" --image-id "$pimg" --policy-digest "$ppdig" --policy "$kept.new" "${pprof[@]}" > "$rec.new" \
          || { rm -f "$rec.new" "$kept.new"; die "project $pname was not added; nothing was changed"; }
        had=""; [[ -f $rec ]] && { had=1; cp -p "$rec" "$rec.old"; [[ -f $kept ]] && cp -p "$kept" "$kept.old"; }
        mv "$rec.new" "$rec"; mv "$kept.new" "$kept"
        if ! ( step_desk_grant ); then
          if [[ -n $had ]]; then mv "$rec.old" "$rec"; [[ -f $kept.old ]] && mv "$kept.old" "$kept"; else rm -f "$rec" "$kept"; fi
          ( step_desk_grant ) >/dev/null 2>&1 || true
          die "the desks grant was not changed; project $pname was not added. Check: sudo ekka desk grant show"
        fi
        rm -f "$rec.old" "$kept.old"
        # The copy `ekka desk create --policy` reads, where the Enclave's user may read it. The grant holds the
        # policy's digest, so a changed copy is refused at create: the root-owned one beside the record is the original.
        enclave_home_file "projects/$pname.policy.json" 0644 < "$kept" \
          || die "project $pname IS in the grant, but its policy could not be copied for the Enclave; run the same command again"
        grant_projects=()
        for pfile in "$projects"/*.project.json; do [[ -f $pfile && ! -L $pfile ]] && grant_projects+=(--project "$pfile"); done
        python3 tools/desk_grant.py show "$limits" "$extras" "${grant_projects[@]}"
        echo
        echo "Project $pname is in the grant. Create its desk, as root on this server:"
        echo "  ekka desk create <desk> --image $pimg --policy $ENCLAVE_HOME/projects/$pname.policy.json --provider <provider> [--provider <provider> ...]"
        echo "After a rebuild of the image or a change to the policy, run this command again with the new ID or file."
        exit 0 ;;
      discovery)  # open the grant for ONE project's discovery desk: its image, its providers, until it expires or `restore`
        shift 2; ref=""; providers=""; minutes=60
        while (( $# )); do case "$1" in --image) ref=${2:-}; shift 2 ;; --providers) providers=${2:-}; shift 2 ;; --minutes) minutes=${2:-}; shift 2 ;;
          *) die "usage: sudo ekka desk grant discovery --image <registry>/<name>@sha256:<64 hex> --providers <provider>,<provider> [--minutes 60, at most 240]" ;; esac; done
        [[ $ref =~ ^[a-z0-9.-]+(:[0-9]+)?(/[a-z0-9._-]+)+@sha256:[0-9a-f]{64}$ ]] \
          || die "--image must be <registry>/<name>@sha256:<64 hex>, the exact image the desk is created from (a tag can move; a digest cannot)"
        [[ -n $providers ]] || die "--providers must name the providers the discovery desk may hold, for example github,bitbucket"
        [[ -f $extras ]] && die "a discovery window is already open ($(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get("image_ref"), "since", d.get("since"))' "$extras")); end it first: sudo ekka desk grant restore"
        [[ -f $limits ]] || die "no desks grant yet: the install writes it once the backend adapter is on"
        python3 tools/desk_grant.py window --image-ref "$ref" --providers "$providers" --minutes "$minutes" --limits "$limits" > "$extras.new" \
          || { rm -f "$extras.new"; die "the window could not be written; nothing was changed"; }
        mv "$extras.new" "$extras"
        ( step_desk_grant ) || { rm -f "$extras"; die "the desks grant was not changed; the window is not open"; }
        python3 tools/desk_grant.py show "$limits" "$extras" ${grant_projects[@]+"${grant_projects[@]}"}
        echo
        echo "The window is open. One desk, named discover-<anything>, created from exactly this image with only these"
        echo "providers before the window closes, may be switched to NVIDIA OpenShell's auto approval mode through the"
        echo "desks API (approval_mode), which writes its permit. When the discovery run is done and its desk deleted:"
        echo "  sudo ekka desk grant restore"
        exit 0 ;;
      restore)
        # Nothing to end when neither the window file nor the grant in force holds a window.
        [[ -f $extras ]] || python3 -c 'import json,sys; sys.exit(0 if "discovery" in json.load(open(sys.argv[1])) else 1)' "$limits" 2>/dev/null \
          || { echo "no discovery window is open; the shipped limits are in force"; exit 0; }
        # the window file, and what a window from before this release kept beside it
        rm -f "$extras" "$DESKS_STATE/backend/discovery-policy.json" "$DESKS_STATE/backend/discovery-composed.json"
        ( step_desk_grant ) || die "the shipped limits could not be written back; check: sudo ekka desk grant show"
        ok "the discovery window is closed: the shipped limits are back"; exit 0 ;;
      *) die "usage: sudo ekka desk grant show | discovery --image <ref@sha256:…> --providers <a,b> [--minutes 60] | restore | project add <name> --image sha256:<64 hex> --policy <file> | project remove <name>" ;;
    esac ;;
  desk-grant)  # the desks grant again, for the installed base image: sudo ./up.sh desk-grant
    # Recomputes the installed image and policy limits and installs the admin plans; this is not a preview.
    [[ $(id -u) == 0 ]] || die "run with sudo"; [[ -f $DESKS_STATE/up.env ]] || die "not installed yet"
    old=$(python3 -c 'import json,sys; print(" ".join(json.load(open(sys.argv[1])).get("image_digests", [])))' \
      "$DESKS_STATE/backend/desks-grant.json" 2>/dev/null || true)
    ( step_desk_grant ) || die "the desks grant was not changed"
    echo "   image_digests before: ${old:-none}"
    echo "   image_digests after:  $(python3 -c 'import json,sys; print(" ".join(json.load(open(sys.argv[1]))["image_digests"]))' "$DESKS_STATE/backend/desks-grant.json")"
    exit 0 ;;
  openshell)  # NVIDIA's own CLI as the gateway's administrator, for what NVIDIA documents: sudo ./up.sh openshell provider list
    # Secret material reaches it through the environment only, never an argument:
    #   sudo --preserve-env=SECRET ./up.sh openshell provider refresh configure ... --secret-material-env key=SECRET
    [[ $(id -u) == 0 ]] || die "run with sudo"
    NAME=$(sed -n 's/^DESKS_NAME=//p' "$DESKS_STATE/up.env" 2>/dev/null); [[ -n $NAME ]] || die "not installed yet"
    shift; python3 tools/openshell_allow.py "$DESKS_STATE/openshell-admin.log" "$@" || exit 1   # an allow-list, logged
    if [[ "${1:-} ${2:-}" == "sandbox download" ]]; then
      # What a download brings was packed inside the desk. Whatever the copy's result, the folder is made safe before
      # anybody reads it: links and special files removed, setuid and write-by-others bits cleared (the tool says why).
      rc=0; OPENSHELL_WORKSPACE=${OPENSHELL_WORKSPACE:-desks} as_gateway_admin "$OS" -g ekka-agent-desks "$@" || rc=$?
      python3 tools/openshell_allow.py --settle-download "${@: -1}" || rc=1
      exit $rc
    fi
    OPENSHELL_WORKSPACE=${OPENSHELL_WORKSPACE:-desks} as_gateway_admin "$OS" -g ekka-agent-desks "$@"; exit $? ;;   # the desks' workspace unless told otherwise
  *) sed -n '2,/^set -euo pipefail/p' "$0" | sed '$d'; exit 2 ;;
esac
step_preflight; step_host_accounts; step_settings; step_images; step_backend_image; step_enclave_install; step_init; step_workspace_policy; step_first_admin; step_enroll; step_start; step_people_scopes; step_workspace_restart; step_admin; step_desk_admin; step_grant; step_agent_open; step_desk_grant; step_people
