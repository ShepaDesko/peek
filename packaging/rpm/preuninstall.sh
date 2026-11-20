#!/bin/sh
# Stop the service before files disappear. An upgrade keeps it running: the
# post-install step restarts it once the new binary is in place.
set -e

# RPM passes 0 on removal and 1 on upgrade: only stop on a real removal.
case "$1" in
    0)
        if systemctl is-active --quiet peek.service; then
            systemctl stop peek.service || true
        fi
        systemctl disable peek-backup.timer >/dev/null 2>&1 || true
        ;;
esac

exit 0
