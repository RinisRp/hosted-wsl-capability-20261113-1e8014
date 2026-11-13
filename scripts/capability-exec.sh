#!/bin/sh
set -eu
# Command substitution cannot finish until the interactive input reaches EOF.
# Refuse a failing read even if it happened to emit the expected bytes.
value=$(/bin/cat) || exit 32
# Command substitution strips LF; tolerate one terminal Windows CR only.
cr=$(/bin/printf '\r')
case "$value" in *"$cr") value=${value%"$cr"};; esac
[ "$value" = "$1" ] || exit 31
/bin/sleep 1
/bin/printf '%s' "$value"
