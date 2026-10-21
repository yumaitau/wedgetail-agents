#!/bin/bash
# Remove the Wedgetail agent from macOS. Run with sudo. Pass --purge to also delete the
# configuration, state (disk buffer, enrolment), the host credential and logs.
set -euo pipefail
LABEL=au.com.yumait.wedgetail-agent
launchctl bootout system "/Library/LaunchDaemons/$LABEL.plist" 2>/dev/null || true
rm -f "/Library/LaunchDaemons/$LABEL.plist" /usr/local/bin/wedgetail-agent
if [ "${1:-}" = "--purge" ]; then
    rm -rf "/Library/Application Support/Wedgetail" /Library/Logs/Wedgetail
    # The host credential (System keychain item); revoke the host in the console too.
    security delete-generic-password -s "$LABEL" -a host-credential \
        /Library/Keychains/System.keychain >/dev/null 2>&1 || true
fi
pkgutil --forget "$LABEL" >/dev/null 2>&1 || true
echo "wedgetail-agent removed"
