#!/bin/sh
set -eu
child=
terminating=0
shutdown() {
  terminating=1
  if [ -n "$child" ]; then
    trap '' TERM INT
    kill -TERM "$child" || exit 21
    code=0
    wait "$child" || code=$?
    [ "$code" -eq 0 ] || [ "$code" -eq 143 ] || exit "$code"
    exit 0
  fi
}
trap shutdown TERM INT
/bin/busybox httpd -f -p 8080 -h / &
child=$!
[ "$terminating" -eq 0 ] || shutdown
code=0
wait "$child" || code=$?
exit "$code"
