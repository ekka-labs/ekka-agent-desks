#!/usr/bin/env bash
# This setup's backup and restore (docs/OPERATIONS.md, "Backup and restore"). Run as root from deploy/.
#
#   backup.sh backup  [<dir>]     one dated folder under <dir> (default $DESKS_STATE/backups), mode 0700
#   backup.sh restore <folder>    this setup back from one such folder, onto this machine
#
# What is in a backup: Keycloak's database (pg_dump), the gateway's database volume, the backend adapter's
# operation-recovery volume (when this server runs the adapter), the Enclave's home
# /var/lib/ekka/.ekka (vault, desk files, attempt journal; the native Enclave's, owned by the ekka user) and
# $DESKS_STATE (certificates, secrets, gateway.toml, desks.env).
# Desk workspaces are NOT backed up: they are working state.
# A backup is a SECRET: the Enclave's home holds its vault AND, with custody "file", the vault's unlock key.
set -euo pipefail
cd "$(dirname "$0")"
export DESKS_STATE=${DESKS_STATE:-/var/lib/ekka-agent-desks}
ALPINE=alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
# ⛔ up.env FIRST, AS setup.sh DOES: it holds the Enclave version, the binds and telemetry that
# `up.sh` chose. Without it, every restart below came back on compose.yml's DEFAULTS, so a backup on
# 2026-10-14 restarted a 0.1.108 Enclave on 0.1.105, below the release that cannot be rolled back.
P() {
  local envs=()
  [[ -f $DESKS_STATE/up.env ]] && envs+=(--env-file "$DESKS_STATE/up.env")
  docker compose -f compose.yml ${envs[@]+"${envs[@]}"} --env-file "$DESKS_STATE/desks.env" "$@"
}
die() { echo "backup: $*" >&2; exit 1; }
# The gateway never starts able to hand desk credentials out, from here either.
preflight() { P config --format json | python3 ../tools/gateway_preflight.py; }
say() { echo "backup: $*"; }
stop_writers() {  # the stack, then the Enclave; PROVEN stopped before any state is copied or replaced
  systemctl stop ekka-desks.service ekka.service 2>/dev/null || die "the units did not stop; nothing was copied or changed"
  local u; for u in ekka-desks ekka; do
    systemctl is-active --quiet "$u" 2>/dev/null && die "$u is still active after stop; nothing was copied or changed"
  done
  local running; running=$(docker ps -q --filter label=com.docker.compose.project=ekka-desks | wc -l | tr -d ' ')
  [[ $running == 0 ]] || die "$running stack container(s) still running after stop; nothing was copied or changed"
}
[[ $(id -u) == 0 ]] || die "run as root: the backup holds root-only secrets"
[[ -f $DESKS_STATE/desks.env ]] || die "no $DESKS_STATE/desks.env: this machine has no desks setup"
vol() { docker run --rm -v "ekka-desks_$1:/v" -v "$2:/b" "$ALPINE" sh -eu -c "$3"; }
# The adapter's recovery store (open operations, settlement holds) must travel with the gateway and the Enclave it
# was written beside: restored without it, the adapter would keep newer state next to older state.
backend_volume() {  # yes or no: does this server have the adapter's volume? Stops when Docker cannot answer, since
  # an error read as "no" would make a backup without the adapter's state, and restoring it would empty the store.
  local found
  found=$(docker volume ls -q --filter "name=^ekka-desks_ekka-backend-state\$") \
    || die "Docker did not answer whether the adapter's volume exists; nothing was copied or changed"
  if [[ $found == ekka-desks_ekka-backend-state ]]; then echo yes; else echo no; fi
}
save_backend_state() {  # save_backend_state <dir> <yes|no>: the adapter volume as <dir>/ekka-backend-state.tgz
  [[ $2 == yes ]] || { say "this server runs no backend adapter (no ekka-backend-state volume): none to back up"; return 0; }
  vol ekka-backend-state "$1" "tar -C /v -czpf /b/ekka-backend-state.tgz ."
}
trust_restored_ca() {  # the Enclave's own copy of the desks CA (/etc/ekka/desks-ca.crt) and the gateway's bundle, from the
  # RESTORED $DESKS_STATE. Both live outside what is restored. On the machine the backup was made on they already
  # match; on a machine set up again since, they are the NEW setup's, the Enclave refuses the restored certificates,
  # and every desk reads "issuer did not answer".
  DESKS_STATE=$DESKS_STATE bash ./certs.sh bundle >/dev/null || die "the restored certificate authority could not be put in place (certs.sh bundle); nothing was started"
}
restore_backend_state() {  # restore_backend_state <dir>: the backup's copy, or an empty volume when it holds none
  docker volume rm -f ekka-desks_ekka-backend-state >/dev/null
  if [[ -f $1/ekka-backend-state.tgz ]]; then
    docker volume create ekka-desks_ekka-backend-state >/dev/null
    vol ekka-backend-state "$1" "tar -C /v -xzpf /b/ekka-backend-state.tgz"
  else
    say "this backup holds no adapter state (older than this script, or no adapter): it starts empty"
  fi
}

case "${1:-}" in
  backup)
    root=${2:-$DESKS_STATE/backups}; d=$root/$(date -u +%Y%m%dT%H%M%SZ)
    install -d -m 0700 "$root" "$d"
    say "Keycloak's database"
    P exec -T keycloak-db pg_dump -U keycloak -d keycloak --format=custom > "$d/keycloak.pgdump"
    was=""; systemctl is-active --quiet ekka 2>/dev/null && was=ekka
    adapter=$(backend_volume)   # asked before anything stops: a Docker that cannot answer stops the backup here
    say "stopping the desks stack, then the Enclave (reverse start order), to copy their state consistently"
    stop_writers   # refuses, touching nothing, if either unit or a stack container is still running
    vol gateway-state "$d" "tar -C /v -czf /b/gateway-state.tgz ."
    save_backend_state "$d" "$adapter"
    tar -C /var/lib/ekka -czpf "$d/ekka-home.tgz" .ekka   # owners and modes kept: the Enclave refuses files another user owns
    if [[ -n $was ]]; then   # only what was running before: an unenrolled Enclave is not started here
      say "starting again: the Enclave, and the desks stack it wants"
      preflight || say "the gateway preflight refused (above): the stack will not start the gateway; the backup itself is complete"
      systemctl start ekka >/dev/null 2>&1 || say "the Enclave did not start; see: journalctl -u ekka"
    fi
    tar -C "$DESKS_STATE" --exclude=./backups -czf "$d/desks-state.tgz" .
    ( cd "$d" && sha256sum ./*.tgz ./*.pgdump > SHA256SUMS )
    chmod 0600 "$d"/*
    say "done: $d"; ls -l "$d" | tail -n +2
    ;;
  restore)
    d=${2:-}; [[ -d $d && -f $d/SHA256SUMS ]] || die "usage: restore <a folder this script wrote>"
    ( cd "$d" && sha256sum -c --quiet SHA256SUMS ) || die "the backup does not match its SHA256SUMS; nothing restored"
    say "stopping this setup (the Enclave's home and the data volumes are replaced, the images stay)"
    stop_writers   # refuses, touching nothing, if either unit or a stack container is still running
    P down >/dev/null 2>&1 || true
    tar -C "$DESKS_STATE" -xzf "$d/desks-state.tgz"
    trust_restored_ca
    docker volume rm -f ekka-desks_gateway-state >/dev/null; docker volume create ekka-desks_gateway-state >/dev/null
    vol gateway-state "$d" "tar -C /v -xzpf /b/gateway-state.tgz"
    restore_backend_state "$d"
    rm -rf /var/lib/ekka/.ekka.restoring && mkdir -m 0700 /var/lib/ekka/.ekka.restoring
    tar -C /var/lib/ekka/.ekka.restoring -xzpf "$d/ekka-home.tgz" --strip-components=1
    rm -rf /var/lib/ekka/.ekka && mv /var/lib/ekka/.ekka.restoring /var/lib/ekka/.ekka && chown -R ekka:ekka /var/lib/ekka/.ekka
    docker volume rm -f ekka-desks_keycloak-db >/dev/null
    P up -d keycloak-db >/dev/null
    for _ in $(seq 1 30); do P exec -T keycloak-db pg_isready -U keycloak -d keycloak >/dev/null 2>&1 && break; sleep 2; done
    P exec -T keycloak-db pg_restore -U keycloak -d keycloak --clean --if-exists --no-owner < "$d/keycloak.pgdump"
    P stop keycloak-db >/dev/null 2>&1 || true   # the stack's unit starts it again below
    envdir=$(sed -n 's/^EKKA_ENV=//p' /etc/ekka/desks.env 2>/dev/null | head -1); envdir=${envdir:-prod}; [[ $envdir == prod ]] && envdir=.
    if [[ -f /var/lib/ekka/.ekka/$envdir/enclave.env ]]; then   # this server's environment, the same file the daemon reads
      preflight || die "the gateway preflight refused the restored setup (above); the data is restored, nothing else started"
      say "the restored home holds an enrolled Enclave: starting the Enclave, and the desks stack it wants"
      systemctl start ekka >/dev/null 2>&1 || die "the Enclave did not start; see: journalctl -u ekka"
    else
      say "the restored home has no enrolled Enclave: enroll (sudo ./up.sh server <name>), which starts the stack"
    fi
    say "restored from $d; check: sudo ./up.sh status; deploy/keycloak/apply_realm.py apply (says nothing to do)"
    ;;
  *) sed -n '2,11p' "$0"; exit 2 ;;
esac
