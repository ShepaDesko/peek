#!/bin/sh
# Debian/Ubuntu post-installation. Idempotent: it runs on install and upgrade.
#
# adduser and addgroup come from the `adduser` package, which this .deb now
# depends on — but it is not essential, and a minimal image (debootstrap
# --variant=minbase, the bare ubuntu container) does not have it. Found
# exactly there: `addgroup: not found`, exit 127 under `set -e`, so no service
# account, no directories, and a package left half configured. The same shape
# as the RPM scriptlet that used to call Debian's addgroup on RHEL.
#
# So: Debian's tools when they are there, shadow-utils otherwise. useradd and
# groupadd come from `passwd`, which is essential, so the fallback cannot
# itself be missing.
set -e

PEEK_USER=peek
PEEK_HOME=/var/lib/peek

create_user() {
    if ! getent group "$PEEK_USER" >/dev/null; then
        if command -v addgroup >/dev/null 2>&1; then
            addgroup --system "$PEEK_USER"
        else
            groupadd --system "$PEEK_USER"
        fi
    fi
    if ! getent passwd "$PEEK_USER" >/dev/null; then
        if command -v adduser >/dev/null 2>&1; then
            adduser --system --ingroup "$PEEK_USER" --home "$PEEK_HOME" \
                --no-create-home --shell /usr/sbin/nologin \
                --gecos "Peek service account" "$PEEK_USER"
        else
            # The short options are the ones every shadow-utils release has,
            # for the same reason the RPM script uses them.
            useradd --system \
                -g "$PEEK_USER" \
                -d "$PEEK_HOME" \
                -M \
                -s /usr/sbin/nologin \
                -c "Peek service account" \
                "$PEEK_USER"
        fi
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

case "$1" in
    configure)
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
