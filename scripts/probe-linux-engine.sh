#!/bin/ash
set -eu
nonce=${1-}
case "$nonce" in *[!0-9a-f]*|'') echo INVALID_NONCE >&2; exit 2;; esac
[ "${#nonce}" -eq 32 ] || exit 2
[ "$(id -u)" -eq 0 ] || exit 2
[ ! -e /var/run/docker.sock ] || { echo FRESH_OWNED_DOCKER_SOCKET_REQUIRED >&2; exit 2; }
export HOME=/root
export DOCKER_HOST=unix:///var/run/docker.sock
export DOCKER_CONFIG=/root/.docker
apk add --no-cache --repository https://dl-cdn.alpinelinux.org/alpine/v3.24/main --repository https://dl-cdn.alpinelinux.org/alpine/v3.24/community docker-engine=29.9.3-r1 docker-cli=29.9.3-r1
mkdir -p /var/lib/capability-docker /run/capability-docker
dockerd --host=unix:///var/run/docker.sock --pidfile=/run/capability-docker/daemon.pid --data-root=/var/lib/capability-docker > /run/capability-docker/daemon.stdout 2> /run/capability-docker/daemon.stderr &
# The daemon stays only in this newly owned distribution; the Windows owner
# unregisters that exact distribution after measurement, including on failure.
i=0
while ! docker info >/dev/null 2>&1; do
  i=$((i + 1))
  [ "$i" -lt 90 ] || { echo OWN_DOCKER_START_TIMEOUT >&2; tail -n 40 /run/capability-docker/daemon.stderr >&2; exit 3; }
  sleep 1
done
ostype=$(docker info --format '{{.OSType}}')
version=$(docker info --format '{{.ServerVersion}}')
engine=$(docker info --format '{{.ID}}')
[ "$ostype" = linux ] && [ "$version" = 29.9.3 ] || exit 3
case "$engine" in *[!0-9a-zA-Z:._-]*|'') echo BOUNDED_ENGINE_ID_REQUIRED >&2; exit 3;; esac
[ "${#engine}" -le 128 ] || exit 3
initial_ids=$(docker ps -aq) || { echo INITIAL_CONTAINER_CENSUS_FAILED >&2; exit 3; }
[ -z "$initial_ids" ] || { echo FRESH_ENGINE_WITHOUT_CONTAINERS_REQUIRED >&2; exit 3; }
image=busybox@sha256:66a6306db78bf2dbf3487f293aa8d6990d8e506fdffab9cc43fe422becf886e4
name=capability-$nonce
cid=
remove_attempted=0
cleanup() {
  status=$?
  trap - EXIT
  if [ -n "$cid" ]; then
    [ "$remove_attempted" -eq 0 ] || { echo OWN_CONTAINER_REMOVE_FAILED_NO_RETRY >&2; exit 4; }
    case "$cid" in *[!0-9a-f]*) echo UNKNOWN_CONTAINER_ID_NO_REMOVE >&2; exit 4;; esac
    [ "${#cid}" -eq 64 ] || exit 4
    observed=$(docker inspect --format '{{.Id}}|{{index .Config.Labels "capability.nonce"}}|{{.State.Running}}' "$cid") || exit 4
    [ "$observed" = "$cid|$nonce|false" ] || { echo OWN_STOPPED_CONTAINER_IDENTITY_REQUIRED >&2; exit 4; }
    remove_attempted=1
    docker rm "$cid" >/dev/null || exit 4
  fi
  exit "$status"
}
trap cleanup EXIT
cid=$(docker create --name "$name" --label capability.nonce=$nonce --network none "$image" /bin/echo "$nonce")
case "$cid" in *[!0-9a-f]*|'') echo EXACT_CREATED_CONTAINER_ID_REQUIRED >&2; exit 4;; esac
[ "${#cid}" -eq 64 ] || exit 4
output=$(docker start --attach "$cid")
[ "$output" = "$nonce" ] || exit 4
state=$(docker inspect --format '{{.State.ExitCode}}|{{.State.Running}}|{{index .Config.Labels "capability.nonce"}}' "$cid")
[ "$state" = "0|false|$nonce" ] || exit 4
created_id=$cid
remove_attempted=1
docker rm "$cid" >/dev/null
cid=
final_ids=$(docker ps -aq) || { echo FINAL_CONTAINER_CENSUS_FAILED >&2; exit 4; }
[ -z "$final_ids" ] || { echo NO_REMAINING_CONTAINERS_REQUIRED >&2; exit 4; }
final_engine=$(docker info --format '{{.ID}}/{{.OSType}}/{{.ServerVersion}}') || { echo FINAL_ENGINE_READINESS_FAILED >&2; exit 4; }
[ "$final_engine" = "$engine/linux/29.9.3" ] || { echo SAME_LIVE_ENGINE_REQUIRED >&2; exit 4; }
trap - EXIT
printf 'HOSTED_LINUX_ENGINE_JSON={"schema":1,"nonce":"%s","ostype":"linux","endpoint":"unix:///var/run/docker.sock","engineId":"%s","dockerVersion":"%s","image":"%s","containerId":"%s","containerExitCode":0,"containerOutput":"%s","initialContainers":0,"finalContainers":0,"containerRemoved":true,"onlyOwnedContainerTouched":true}\n' "$nonce" "$engine" "$version" "$image" "$created_id" "$output"
