#!/usr/bin/env bash
# Save before harden changes the firewall; the scheduled copy restores this snapshot unless confirmed.
set -euo pipefail
mode=$1
state=$2
unit=desks-docker-user.service
paths=(/usr/local/sbin/desks-docker-user /etc/systemd/system/desks-docker-user.service)

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
    ;;
  restore)
    saved=$3
    # Restoring access matters more than any one step: keep going past a failed step, and report it.
    set +e
    # Serialize with harden's rule writes, including a Docker install that outlasts the confirmation window.
    exec 8>"$state/firewall.lock"
    flock 8
    [[ ! -f $state/confirmed ]] || exit 0
    touch "$state/rolled-back"
    # Stop the new persistent rule writer too, so a Docker restart cannot undo the rollback.
    if [[ -e ${paths[1]} ]]; then systemctl disable --now "$unit"; fi
    for i in "${!paths[@]}"; do
      rm -f "${paths[$i]}"
      [[ ! -e $saved/file.$i && ! -L $saved/file.$i ]] || cp -a "$saved/file.$i" "${paths[$i]}"
    done
    systemctl daemon-reload
    [[ ! -f $saved/docker-enabled ]] || systemctl enable "$unit"
    [[ ! -f $saved/docker-active ]] || systemctl start "$unit"
    cp -a "$saved/ufw/." /etc/ufw/
    cp -a "$saved/default-ufw" /etc/default/ufw
    if grep -qx 'Status: active' "$saved/ufw-status"; then
      ufw --force enable
      ufw reload
    else
      ufw --force disable
    fi
    iptables-restore --noflush < "$saved/docker-user.rules"
    logger -t desks-harden 'firewall restored to its saved state: not confirmed within 5 minutes'
    ;;
  *) echo 'usage: firewall-state.sh prepare <state> | restore <state> <snapshot>' >&2; exit 2 ;;
esac
