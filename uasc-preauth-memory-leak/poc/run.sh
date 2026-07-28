#!/usr/bin/env bash
#
# UASC pre-authentication memory-leak PoC -- one-command reproduction of both scenarios
# plus their 1.1.5 negative controls.
#
# What this does:
#   1. Builds the standalone victim-server jar twice, offline, against the local
#      ~/.m2 cache: once with -Dmilo.version=1.1.4 (vulnerable, default) and once
#      with -Dmilo.version=1.1.5 (fixed -- same source code, different Milo jars).
#      Records the exact Milo jar versions and their sha256 hashes used for each build.
#   2. Builds the Docker images used by Scenario B (skipped if Docker is unavailable).
#   3. Runs Scenario A (bounded -XX:MaxDirectMemorySize, host-only, no Docker
#      required) for both versions.
#   4. Runs Scenario B HEADLINE: a SINGLE source IP driving the vulnerable server to an
#      actual OOM-kill (ExitCode 137), then the fixed 1.1.5 build run through the
#      IDENTICAL attack sequence (same single IP, same chunk pattern, same duration,
#      required to accept at least as many connections as killed 1.1.4).
#   5. Runs Scenario B ACCELERATION COMPARISON (multi-IP, clearly labeled secondary --
#      not the headline claim) against the vulnerable build only.
#   6. Prints a machine-checked verdict (PASS/FAIL, matching process exit code) per
#      scenario per version and writes full transcripts to evidence/.
#
# Every scenarioA.sh / scenarioB.sh invocation exits nonzero if any of its checks fail,
# and this script propagates that into its own final exit code.
#
# Usage: ./run.sh [--skip-docker]
set -u
cd "$(dirname "$0")"

SKIP_DOCKER=0
[ "${1:-}" = "--skip-docker" ] && SKIP_DOCKER=1

EVIDENCE_DIR="../evidence"
mkdir -p "$EVIDENCE_DIR"
OVERALL_RC=0

JAVA_HOME="${JAVA_HOME:-}"
if [ -z "$JAVA_HOME" ]; then
  for c in "$(mise where java 2>/dev/null)" "/Users/abhinavagarwal/.local/share/mise/installs/java/temurin-17.0.19+10"; do
    if [ -n "$c" ] && [ -x "$c/bin/java" ]; then JAVA_HOME="$c"; break; fi
  done
fi
if [ -z "$JAVA_HOME" ]; then
  echo "ERROR: could not locate a JDK 17. Set JAVA_HOME and re-run."
  exit 1
fi
export JAVA_HOME
export PATH="$JAVA_HOME/bin:$PATH"

echo "== [1/6] Build victim-server jars offline against local ~/.m2 (1.1.4 vulnerable, 1.1.5 fixed) =="
echo "environment: $(uname -s) $(uname -r), $(java -version 2>&1 | head -1), $(mvn -v 2>&1 | head -1)"
( cd victim-server && mvn -o -q clean package -Dmilo.version=1.1.4 -DskipTests ) || { echo "1.1.4 build failed"; exit 1; }
mkdir -p victim-server/target-versions
cp victim-server/target/victim-server.jar victim-server/target-versions/victim-server-1.1.4.jar
( cd victim-server && mvn -o -q clean package -Dmilo.version=1.1.5 -DskipTests ) || { echo "1.1.5 build failed"; exit 1; }
cp victim-server/target/victim-server.jar victim-server/target-versions/victim-server-1.1.5.jar
ls -la victim-server/target-versions/

echo ""
echo "-- exact Milo dependency artifact hashes used (from ~/.m2) --"
for v in 1.1.4 1.1.5; do
  for a in milo-sdk-server milo-sdk-client milo-stack-core; do
    jar="$HOME/.m2/repository/org/eclipse/milo/${a}/${v}/${a}-${v}.jar"
    if [ -f "$jar" ]; then
      echo "  ${a}-${v}.jar  sha256=$(shasum -a 256 "$jar" | cut -d' ' -f1)"
    fi
  done
done
echo "  poc/victim-server 1.1.4 shaded jar  sha256=$(shasum -a 256 victim-server/target-versions/victim-server-1.1.4.jar | cut -d' ' -f1)"
echo "  poc/victim-server 1.1.5 shaded jar  sha256=$(shasum -a 256 victim-server/target-versions/victim-server-1.1.5.jar | cut -d' ' -f1)"

DOCKER_OK=0
if [ "$SKIP_DOCKER" -eq 0 ] && docker info >/dev/null 2>&1; then
  DOCKER_OK=1
  echo ""; echo "== [2/6] Build Docker images (Scenario B) =="
  docker build -f Dockerfile.app --build-arg JAR_PATH=victim-server/target-versions/victim-server-1.1.4.jar -t memory-leak-app:1.1.4 . || DOCKER_OK=0
  docker build -f Dockerfile.app --build-arg JAR_PATH=victim-server/target-versions/victim-server-1.1.5.jar -t memory-leak-app:1.1.5 . || DOCKER_OK=0
  docker build -f Dockerfile.attacker -t memory-leak-attacker:latest . || DOCKER_OK=0
else
  echo ""; echo "== [2/6] Docker unavailable or --skip-docker given -- Scenario B will be skipped =="
fi

echo ""; echo "== [3/6] Scenario A -- vulnerable 1.1.4 (bounded direct-memory cap, host-only) =="
./scenarioA.sh victim-server/target-versions/victim-server-1.1.4.jar vulnerable-1.1.4 "$EVIDENCE_DIR/scenarioA-vulnerable-1.1.4.log"
grep "Scenario A remote A:H verdict" "$EVIDENCE_DIR/scenarioA-vulnerable-1.1.4.log"

echo ""; echo "== [3/6] Scenario A -- fixed 1.1.5 negative control =="
./scenarioA.sh victim-server/target-versions/victim-server-1.1.5.jar fixed-1.1.5 "$EVIDENCE_DIR/scenarioA-fixed-1.1.5.log"
grep "Scenario A remote A:H verdict" "$EVIDENCE_DIR/scenarioA-fixed-1.1.5.log"

if [ "$DOCKER_OK" -eq 1 ]; then
  echo ""; echo "== [4/6] Scenario B HEADLINE -- single source IP, vulnerable 1.1.4 (expect OOM-kill) =="
  ./scenarioB.sh memory-leak-app:1.1.4 vulnerable-1.1.4 "$EVIDENCE_DIR/scenarioB-vulnerable-1.1.4-single-ip.log" 550m single 180 0
  RC=$?; OVERALL_RC=$((OVERALL_RC + RC))
  grep -A2 "^SCREENSHOT SUMMARY" "$EVIDENCE_DIR/scenarioB-vulnerable-1.1.4-single-ip.log" | tail -n +2

  # Identical-sequence 1.1.5 control: same single IP, same duration, same chunk pattern,
  # required to accept at least as many connections as the ones that killed 1.1.4.
  KILLED_AT=$(grep -Eo 'acceptedConns=[0-9]+' "$EVIDENCE_DIR/scenarioB-vulnerable-1.1.4-single-ip.log" | tail -1 | cut -d= -f2)
  KILLED_AT=${KILLED_AT:-0}
  echo ""; echo "== [5/6] Scenario B IDENTICAL-SEQUENCE CONTROL -- fixed 1.1.5, same single-IP attack, must accept >= ${KILLED_AT} connections =="
  ./scenarioB.sh memory-leak-app:1.1.5 fixed-1.1.5 "$EVIDENCE_DIR/scenarioB-fixed-1.1.5-single-ip.log" 550m single 180 "$KILLED_AT"
  RC=$?; OVERALL_RC=$((OVERALL_RC + RC))
  grep -A2 "^SCREENSHOT SUMMARY" "$EVIDENCE_DIR/scenarioB-fixed-1.1.5-single-ip.log" | tail -n +2

  echo ""; echo "== [6/6] Scenario B ACCELERATION COMPARISON (multi-IP, labeled secondary -- NOT the headline claim) =="
  ./scenarioB.sh memory-leak-app:1.1.4 vulnerable-1.1.4-multi-ip-acceleration "$EVIDENCE_DIR/scenarioB-vulnerable-1.1.4-multi-ip.log" 550m multi 120 0
  RC=$?; OVERALL_RC=$((OVERALL_RC + RC))
  grep -A2 "^SCREENSHOT SUMMARY" "$EVIDENCE_DIR/scenarioB-vulnerable-1.1.4-multi-ip.log" | tail -n +2
else
  echo ""; echo "== [4-6/6] Scenario B SKIPPED (Docker unavailable) =="
fi

echo ""; echo "== FINAL SUMMARY =="
echo "-- Scenario A (bounded -XX:MaxDirectMemorySize=64m) --"
grep "Scenario A remote A:H verdict" "$EVIDENCE_DIR"/scenarioA-*.log 2>/dev/null
if [ "$DOCKER_OK" -eq 1 ]; then
  echo "-- Scenario B (container memory limit; machine-checked PASS/FAIL) --"
  grep "^MACHINE-CHECKED VERDICT" "$EVIDENCE_DIR"/scenarioB-*.log 2>/dev/null
fi
echo ""
echo "Full transcripts: $(cd "$EVIDENCE_DIR" && pwd)/"
[ "$OVERALL_RC" -ne 0 ] && echo "WARNING: one or more Scenario B checks FAILED -- see MACHINE-CHECKED VERDICT lines above"
exit $OVERALL_RC
