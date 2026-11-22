#!/bin/sh
# RHEL/Rocky/Alma post-installation. Idempotent: it runs on install and upgrade.
#
# The account is created with shadow-utils, not with Debian's adduser. This
# file used to be a copy of the Debian script, and on RHEL that meant
# `addgroup` (which does not exist there) aborting the whole scriptlet under
# `set -e`: no service account, no directories, nothing. `adduser` does exist,
# but only as a symlink to `useradd`, which rejects --ingroup, --home and
# --gecos. Hence the explicit short options below, which are the same on every
# shadow-utils release.
set -e

PEEK_USER=peek
PEEK_HOME=/var/lib/peek

create_user() {
    if ! getent group "$PEEK_USER" >/dev/null; then
        groupadd --system "$PEEK_USER"
    fi
    if ! getent passwd "$PEEK_USER" >/dev/null; then
        useradd --system \
            -g "$PEEK_USER" \
            -d "$PEEK_HOME" \
            -M \
            -s /sbin/nologin \
            -c "Peek service account" \
            "$PEEK_USER"
    fi
}

prepare_dirs() {
    install -d -o "$PEEK_USER" -g "$PEEK_USER" -m 0750 "$PEEK_HOME"
    install -d -o "$PEEK_USER" -g "$PEEK_USER" -m 0750 "$PEEK_HOME/files"
    install -d -o "$PEEK_USER" -g "$PEEK_USER" -m 0750 /var/backups/peek
    install -d -o root -g "$PEEK_USER" -m 0750 /etc/peek
    install -d -o root -g "$PEEK_USER" -m 0750 /etc/peek/tls

    if [ -f /etc/peek/peek.toml ]; then
        chown root:"$PEEK_USER" /etc/peek/peek.toml
        chmod 0640 /etc/peek/peek.toml
    fi
    if [ -f /etc/peek/master.key ]; then
        chown "$PEEK_USER":"$PEEK_USER" /etc/peek/master.key
        chmod 0400 /etc/peek/master.key
    fi
}

# RPM passes 1 on install and 2 on upgrade.
case "$1" in
    1|2)
        create_user
        prepare_dirs
        systemctl daemon-reload >/dev/null 2>&1 || true

        if [ -f /etc/peek/peek.toml ]; then
            # Upgrade: migrations run at startup, so a restart is the upgrade.
            if systemctl is-active --quiet peek.service; then
                systemctl restart peek.service || true
                sleep 2
                if ! systemctl is-active --quiet peek.service; then
                    echo "peek: the service did not come back up. Check: journalctl -u peek -n 50" >&2
                fi
            fi
            systemctl enable peek-backup.timer >/dev/null 2>&1 || true
        else
            echo ""
            echo "Peek is installed. Finish the setup with:"
            echo "    sudo peek setup"
            echo ""
        fi
        ;;
esac

exit 0
