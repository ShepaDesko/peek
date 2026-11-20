#!/bin/sh
# Removal never deletes data: /etc/peek (configuration and master key),
# /var/lib/peek (database and encrypted blobs) and /var/backups/peek stay.
# Deleting them is an explicit, documented operator decision.
set -e

case "$1" in
    0)
        systemctl daemon-reload >/dev/null 2>&1 || true
        echo ""
        echo "Peek has been removed. Data kept on purpose:"
        echo "    /etc/peek        configuration and master key"
        echo "    /var/lib/peek    database and encrypted files"
        echo "    /var/backups/peek"
        echo "Delete them by hand if you really mean to."
        echo ""
        ;;
    1)
        systemctl daemon-reload >/dev/null 2>&1 || true
        ;;
esac

exit 0
