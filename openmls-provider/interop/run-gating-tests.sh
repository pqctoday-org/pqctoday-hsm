#!/usr/bin/env bash
# Runs the IETF MLS gating tests pqctoday-vs-{openmls,mls-rs} and writes
# each JSON report into interop/reports/.
#
# Usage:
#   ./run-gating-tests.sh             # all known healthy peers
#   ./run-gating-tests.sh openmls     # only pqctoday-vs-openmls
#   ./run-gating-tests.sh openmls mls-rs
#
# Output naming: reports/{peer}_{scenario}_{UTC-timestamp}.json

set -e
cd "$(dirname "$0")"

REPORTS_DIR="reports"
mkdir -p "$REPORTS_DIR"

TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
SCENARIOS="welcome_join commit external_join"

peer_addr() {
  case "$1" in
    openmls) echo "openmls:50051" ;;
    mls-rs)  echo "mls-rs:50054" ;;
    *)       echo "" ;;
  esac
}

PEERS="$*"
if [ -z "$PEERS" ]; then
  PEERS="openmls mls-rs"
fi

PASSED=0
FAILED=0
SKIPPED=0

for peer in $PEERS; do
  addr="$(peer_addr "$peer")"
  if [ -z "$addr" ]; then
    echo "Unknown peer '$peer'; valid: openmls mls-rs"
    exit 2
  fi
  if ! docker compose -f docker/docker-compose.yml ps "$peer" 2>/dev/null | grep -q "healthy"; then
    echo "  skip pqctoday vs $peer (service not healthy)"
    for s in $SCENARIOS; do SKIPPED=$((SKIPPED + 1)); done
    continue
  fi

  for scenario in $SCENARIOS; do
    out="$REPORTS_DIR/${peer}_${scenario}_${TIMESTAMP}.json"
    echo "==> pqctoday vs $peer / $scenario  ($out)"
    if docker compose -f docker/docker-compose.yml run --rm --no-deps -T test-runner \
         -client pqctoday:50053 -client "$addr" -config "/configs/${scenario}.json" \
         > "$out" 2>&1; then
      echo "    PASS"
      PASSED=$((PASSED + 1))
    else
      ec=$?
      echo "    FAIL (exit $ec)"
      FAILED=$((FAILED + 1))
    fi
  done
done

echo ""
echo "Summary: $PASSED passed, $FAILED failed, $SKIPPED skipped"
exit $FAILED
