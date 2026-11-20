#!/bin/sh
# Debian/Ubuntu post-installation. Idempotent: it runs on install and upgrade.
set -e

PEEK_USER=peek
PEEK_HOME=/var/lib/peek

create_user() {
    if ! getent group "$PEEK_USER" >/dev/null; then
        addgroup --system "$PEEK_USER"
    fi
    if ! getent passwd "$PEEK_USER" >/dev/null; then
        adduser --system --ingroup "$PEEK_USER" --home "$PEEK_HOME" \
            --no-create-home --shell /usr/sbin/nologin \
            --gecos "Peek service account" "$PEEK_USER"
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
