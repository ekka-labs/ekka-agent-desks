#!/usr/bin/env bash
# Save before harden changes the firewall; the scheduled copy restores this snapshot unless confirmed.
set -euo pipefail
mode=$1
state=$2
unit=desks-docker-user.service
paths=(/usr/local/sbin/desks-docker-user /etc/systemd/system/desks-docker-user.service)

# Bounded retries retain each failed attempt in the journal, even if a later attempt succeeds.
retry() {
  local label=$1 attempt; shift
  for attempt in 1 2 3; do
    if "$@"; then return 0; fi
    echo "desks-harden: failed step $label (attempt $attempt/3)" >&2
    logger -t desks-harden "failed step $label (attempt $attempt/3)" || true
  done
  return 1
}
failed=()
step() {
  local label=$1; shift
  retry "$label" "$@" || failed+=("$label")
  return 0
}
remove_guard() {
  [[ -e $saved/guard-owned ]] || return 0
  # Listing all tables distinguishes an absent guard from a failed netlink query.
  local tables
  tables=$(nft list tables) || return 1
  if grep -qx 'table inet desks_harden_guard' <<<"$tables"; then
    nft delete table inet desks_harden_guard || return 1
  fi
  rm -f "$saved/guard-owned"
}
open_firewall_lock() {
  exec 8>"$state/firewall.lock" || return 1
  flock 8
}
restore_docker_rules() {
  iptables-restore --wait 10 --noflush < "$saved/docker-user.rules"
}
verify_ufw() {
  local status expected
  status=$(LC_ALL=C ufw status) || return 1
  expected=$(grep -E '^Status: (active|inactive)$' "$saved/ufw-status") || return 1
  grep -qxF "$expected" <<<"$status"
}
verify_docker_rules() {
  local rules
  rules=$(iptables-save -t filter) || return 1
  # Ignore counters and other live Docker chains; compare the ordered rules of DOCKER-USER only.
  local expected actual
  expected=$(sed -n '/^-A DOCKER-USER /p' "$saved/docker-user.rules") || return 1
  actual=$(sed -n '/^-A DOCKER-USER /p' <<<"$rules") || return 1
  [[ $expected == "$actual" ]]
}
report_failure() {
  local message="firewall restore FAILED; failed steps: ${failed[*]}"
  echo "$message; see $state/restore-failed" >&2
  logger -t desks-harden "$message" || true
  if ! printf '%s\n' "${failed[@]}" > "$state/restore-failed"; then
    echo 'desks-harden: could not write the restore-failed marker' >&2
  fi
}

case $mode in
  prepare)
    if systemctl is-active --quiet desks-harden-rollback.timer; then
      echo 'harden: a firewall rollback timer already exists; check systemctl status desks-harden-rollback.timer before retrying' >&2
      exit 1
    fi
    saved=$(mktemp -d "$state/firewall.XXXXXX")
    # Save all of UFW's files, including IPv6 rules, before/after rules, defaults and enable-on-boot setting.
    LC_ALL=C ufw status > "$saved/ufw-status"
    grep -Eq '^Status: (active|inactive)$' "$saved/ufw-status"
    cp -a /etc/ufw "$saved/ufw"
    cp -a /etc/default/ufw "$saved/default-ufw"
    # iptables-save has no chain selector. Keep only this chain, never restore Docker's other live chains.
    iptables-save -t filter > "$saved/filter"
    awk 'BEGIN { print "*filter"; print ":DOCKER-USER - [0:0]" }
         /^-A DOCKER-USER / { print }
         END { print "COMMIT" }' "$saved/filter" > "$saved/docker-user.rules"
    for i in "${!paths[@]}"; do
      [[ ! -e ${paths[$i]} && ! -L ${paths[$i]} ]] || cp -a "${paths[$i]}" "$saved/file.$i"
    done
    if systemctl is-enabled --quiet "$unit"; then touch "$saved/docker-enabled"; fi
    if systemctl is-active --quiet "$unit"; then touch "$saved/docker-active"; fi
    cp "$0" "$saved/restore.sh"
    rm -f "$state/confirmed"
    if ! systemd-run --quiet --collect --unit=desks-harden-rollback --on-active=300 \
        --timer-property=AccuracySec=1s --timer-property=RemainAfterElapse=no \
        /bin/bash "$saved/restore.sh" restore "$state" "$saved"; then
      echo 'harden: could not schedule the 5-minute firewall rollback; no firewall rules were changed' >&2
      exit 1
    fi
    printf '%s\n' "$saved"
    ;;
  guard)
    saved=$3
    allow_from=$4
    # A separate inet table survives UFW reset on both iptables backends. One nft batch installs both families.
    # Existing SSH connections and IPv6 neighbour discovery must keep working throughout replacement.
    tables=$(nft list tables)
    if grep -qx 'table inet desks_harden_guard' <<<"$tables"; then
      echo 'harden: an existing desks_harden_guard table needs operator inspection' >&2
      exit 1
    fi
    touch "$saved/guard-owned"
    nft -f - <<RULES
add table inet desks_harden_guard
add chain inet desks_harden_guard input { type filter hook input priority -10; policy drop; }
add rule inet desks_harden_guard input ct state established,related accept
add rule inet desks_harden_guard input iifname "lo" accept
add rule inet desks_harden_guard input meta l4proto ipv6-icmp icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert } ip6 hoplimit 255 accept
$(for a in $allow_from; do
  family=ip; [[ $a != *:* ]] || family=ip6
  echo "add rule inet desks_harden_guard input $family saddr $a tcp dport { 22, 443, 8080 } accept"
done)
RULES
    ;;
  unguard)
    saved=$3
    step remove-guard remove_guard
    if (( ${#failed[@]} )); then report_failure; exit 1; fi
    ;;
  restore|restore-now)
    saved=$3
    # Keep restoring after a failed step, but never turn a partial restoration into a success report.
    if ! retry firewall-lock open_firewall_lock; then
      failed+=(firewall-lock)
      step remove-guard remove_guard
      report_failure
      exit 1
    fi
    [[ $mode == restore-now || ! -f $state/confirmed ]] || exit 0
    step rollback-marker touch "$state/rolled-back"
    # Stop the new persistent rule writer too, so a Docker restart cannot undo the rollback.
    if [[ -e ${paths[1]} ]]; then step stop-docker-writer systemctl disable --now "$unit"; fi
    for i in "${!paths[@]}"; do
      step "remove-writer-$i" rm -f "${paths[$i]}"
      if [[ -e $saved/file.$i || -L $saved/file.$i ]]; then
        step "restore-writer-$i" cp -a "$saved/file.$i" "${paths[$i]}"
      fi
    done
    step daemon-reload systemctl daemon-reload
    [[ ! -f $saved/docker-enabled ]] || step enable-docker-writer systemctl enable "$unit"
    [[ ! -f $saved/docker-active ]] || step start-docker-writer systemctl start "$unit"
    step ufw-files cp -a "$saved/ufw/." /etc/ufw/
    step ufw-defaults cp -a "$saved/default-ufw" /etc/default/ufw
    if grep -qx 'Status: active' "$saved/ufw-status"; then
      step ufw-enable ufw --force enable
      step ufw-reload ufw reload
    else
      step ufw-disable ufw --force disable
    fi
    step docker-rules restore_docker_rules
    step verify-ufw verify_ufw
    step verify-docker-rules verify_docker_rules
    # Access recovery and guard cleanup are attempted even when another restore step failed.
    step remove-guard remove_guard
    if (( ${#failed[@]} )); then report_failure; exit 1; fi
    step clear-failure-marker rm -f "$state/restore-failed"
    if (( ${#failed[@]} )); then report_failure; exit 1; fi
    message='firewall restored to its saved state (read-back verified)'
    echo "$message"
    logger -t desks-harden "$message"
    ;;
  *) echo 'usage: firewall-state.sh prepare <state> | restore[-now] <state> <snapshot> | guard <state> <snapshot> <addresses> | unguard <state> <snapshot>' >&2; exit 2 ;;
esac
