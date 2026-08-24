#!/usr/bin/env bash
# End-to-end demonstration on one machine.
#
# A bash loop stands in for systemd or launchd: it restarts the shim whenever it
# exits, which is exactly the contract a real supervisor provides. Without a
# supervisor an update stages and never installs, so the loop is not a shortcut
# here — it is the missing half of the design.
#
#   1. install 1.0.0, publish 1.0.1     -> staged, installed at the next start
#   2. publish a mislabelled 1.0.2      -> preflight rejects it, install untouched
#   3. publish a 1.0.3 that never stays -> boots, fails, rolls back to 1.0.1
#
# Exit code 2 from the program means "below the minimum supported version"; the
# loop honours it and stops, the same way RestartPreventExitStatus does.

set -euo pipefail
cd "$(dirname "$0")/.."

DEMO=.demo
INSTALL="$DEMO/install"
DATA="$DEMO/data"
DIST="$DEMO/dist"
PORT=${PORT:-8099}
CHANNEL="http://127.0.0.1:$PORT/manifest.json"
FLEET="http://127.0.0.1:$PORT/v1"

export AGENT_DATA_DIR="$PWD/$DATA"
export AGENT_REPORT_URL="http://127.0.0.1:${PORT:-8099}/v1/events"

GOOS_=$(go env GOOS)
GOARCH_=$(go env GOARCH)
EXT=""; [ "$GOOS_" = "windows" ] && EXT=".exe"
ARTIFACT="agent-app_${GOOS_}_${GOARCH_}${EXT}"

rule() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

# show prints matching log lines. grep exits 1 when nothing matches, which under
# `set -e` would kill the script, so a miss is reported rather than fatal.
show() {
  echo "--- agent log ---"
  grep -E "$1" "$DEMO/agent.log" | tail -"$2" || echo "(nothing matched yet)"
}

cleanup() {
  # Stop the supervisor before the agent, or it would start it again.
  #
  # Each background job is killed and then waited on. The wait is what keeps the
  # output clean: bash announces terminated background jobs when it reaps them,
  # and those notices would otherwise print after the final summary and look
  # like the run failed. Reaping them here does it quietly.
  for pid in "${SUPERVISOR_PID:-}" "${SERVER_PID:-}"; do
    [ -n "$pid" ] || continue
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  pkill -f "$PWD/$INSTALL/agent" 2>/dev/null || true
}
trap cleanup EXIT

rm -rf "$DEMO"
mkdir -p "$INSTALL" "$DATA" "$DIST"

go build -o "$DEMO/releasectl" ./cmd/releasectl
go build -o "$DEMO/updateserver" ./cmd/updateserver
"$DEMO/releasectl" keygen -out "$DEMO/release" >/dev/null
PUB=$(cat "$DEMO/release.pub")

# build_app VERSION OUTPUT [STAMPED] [MODE]
#   STAMPED lets a binary lie about its version, which is what step 2 needs.
#   MODE=crash builds a program that starts and then dies, for step 3.
build_app() {
  local out=$2 stamped=${3:-$1} mode=${4:-normal} tags=""
  [ "$mode" = "crash" ] && tags="-tags democrash"
  # shellcheck disable=SC2086
  go build -trimpath $tags \
    -ldflags "-X github.com/dbuslaev/selfupdate-agent/internal/version.Version=$stamped -X main.releaseKeys=$PUB" \
    -o "$out" ./cmd/app
}

# No -next-check here: the client clamps it to a 30s floor, which would override
# the fast -interval the demo runs with.
publish() { "$DEMO/releasectl" sign -key "$DEMO/release.key" -version "$1" -dir "$DIST" -rollout 100; }

# supervise restarts the shim whenever it exits, honouring exit code 2.
supervise() {
  while true; do
    "$INSTALL/agent$EXT" -manifest "$CHANNEL" \
      -interval 2s -healthy-after 4s -heartbeat 1s >>"$DEMO/agent.log" 2>&1 || true
    code=$?
    if [ "$code" = "2" ]; then
      echo "supervisor: agent reported it is no longer supported; not restarting" >>"$DEMO/agent.log"
      break
    fi
    sleep 1
  done
}

rule "building and installing 1.0.0"
go build -trimpath -ldflags "-X github.com/dbuslaev/selfupdate-agent/internal/version.Version=1.0.0" \
  -o "$DEMO/agent$EXT" ./cmd/shim
build_app 1.0.0 "$DEMO/agent-app$EXT"
go build -o "$DEMO/installer" ./cmd/installer

"$DEMO/updateserver" -addr "127.0.0.1:$PORT" -dir "$DIST" >"$DEMO/server.log" 2>&1 &
SERVER_PID=$!
sleep 0.5

# The installer normally registers with launchd or systemd. Here it only places
# the binaries and enrolls; the bash loop below plays the supervisor.
AGENT_INSTALL_DIR="$PWD/$INSTALL" "$DEMO/installer" install \
  -from "$DEMO" -to "$INSTALL" -manifest "$CHANNEL" \
  -enroll "$FLEET/enroll" -code DEMO-CODE-123 -report "$FLEET/events" 2>&1 | grep -v autostart || true

rule "publishing 1.0.1"
build_app 1.0.1 "$DIST/$ARTIFACT"
publish 1.0.1

supervise & SUPERVISOR_PID=$!
sleep 16
show 'staged|installed|committed|heartbeat' 8
echo "installed: $("$INSTALL/agent-app$EXT" --self-check)"

rule "publishing a mislabelled 1.0.2 (the binary reports 9.9.9)"
build_app 1.0.2 "$DIST/$ARTIFACT" 9.9.9
publish 1.0.2
sleep 14
show 'rejected' 3
echo "installed: $("$INSTALL/agent-app$EXT" --self-check)  (unchanged)"

rule "publishing 1.0.3, which starts but never becomes healthy"
build_app 1.0.3 "$DIST/$ARTIFACT" 1.0.3 crash
publish 1.0.3
sleep 30
show 'trial|rolling back|installed staged' 8

rule "result"
echo "installed: $("$INSTALL/agent-app$EXT" --self-check)"
echo
AGENT_INSTALL_DIR="$PWD/$INSTALL" "$INSTALL/agent-app$EXT" --status || true
echo
echo "install directory:"; ls -1 "$INSTALL"
