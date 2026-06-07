#!/usr/bin/env bash
# gateway/bench/harness.sh — benchmark orchestrator (WI-4yaa.BENCH-0)
#
# Usage:
#   bash bench/harness.sh <plugin-name>
#
# Example:
#   bash bench/harness.sh tokenvalidator
#
# Environment overrides:
#   BENCH_DURATION   vegeta attack duration  (default: 60s)
#   BENCH_RPS        requests per second     (default: 100)
#   BENCH_SECRET     HS256 JWT secret        (default: bench-secret)
#   BENCH_AUDIENCE   JWT audience            (default: bench-gateway)
#   BENCH_RESULTS_DIR output directory       (default: bench/results)
#
# Tool selection: vegeta (pure Go binary; installed via `go install`)
# Rationale: same toolchain as gateway — no Docker-in-Docker, no Node.js,
# no extra runner dependencies. k6 would require Node/npm; wrk requires C.
# vegeta `attack | report -type=json` pipeline gives structured JSON natively.
#
# Algorithm:
#   1. Validate plugin config and targets files exist.
#   2. Install vegeta if absent.
#   3. Mint a JWT for the attack (HS256 via bench/cmd/benchtoken).
#   4. Inject token into a tmp targets file (replaces {{TOKEN}}).
#   5. For EACH variant (plugin-enabled, baseline):
#      a. Write active-plugins.yaml from configs/<variant>.yaml.
#      b. Bring up compose stack; wait for gateway health.
#      c. Run vegeta attack -> parse JSON report.
#      d. Tear down compose stack.
#   6. Compute overhead delta (plugin p99 − baseline p99).
#   7. Write JSON result to results/.
#   8. Invoke regression-check.sh; propagate exit code.
#
# exit 0 → bench passed (no regression or no baseline yet)
# exit 1 → regression detected (overhead_delta_p99_ms > threshold)
# exit 2 → harness setup error (missing file, compose fail, etc.)

set -euo pipefail

# ── constants ────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATEWAY_DIR="$(dirname "$SCRIPT_DIR")"   # gateway/
COMPOSE_FILE="$SCRIPT_DIR/compose.bench.yml"
RESULTS_DIR="${BENCH_RESULTS_DIR:-$SCRIPT_DIR/results}"

DURATION="${BENCH_DURATION:-60s}"
RPS="${BENCH_RPS:-100}"
SECRET="${BENCH_SECRET:-bench-secret}"
AUDIENCE="${BENCH_AUDIENCE:-bench-gateway}"

# ── argument ─────────────────────────────────────────────────────────────────
if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <plugin-name>" >&2
  exit 2
fi
PLUGIN="$1"

# ── prerequisite checks ──────────────────────────────────────────────────────
PLUGIN_CFG="$SCRIPT_DIR/configs/${PLUGIN}.yaml"
BASELINE_CFG="$SCRIPT_DIR/configs/baseline.yaml"
TARGETS_FILE="$SCRIPT_DIR/targets/${PLUGIN}.txt"

for f in "$PLUGIN_CFG" "$BASELINE_CFG" "$TARGETS_FILE" "$COMPOSE_FILE"; do
  if [[ ! -f "$f" ]]; then
    echo "ERROR: required file not found: $f" >&2
    exit 2
  fi
done

mkdir -p "$RESULTS_DIR"

# ── ensure vegeta is available ───────────────────────────────────────────────
if ! command -v vegeta &>/dev/null; then
  echo "INFO: vegeta not found; installing via go install..."
  go install github.com/tsenart/vegeta@latest
  # go install puts binaries in $(go env GOPATH)/bin
  export PATH="$(go env GOPATH)/bin:$PATH"
fi
if ! command -v vegeta &>/dev/null; then
  echo "ERROR: vegeta still not found after install; check GOPATH/bin is on PATH" >&2
  exit 2
fi
echo "INFO: vegeta $(vegeta -version 2>&1 | head -1)"

# ── compute git SHA ──────────────────────────────────────────────────────────
SHA="$(git -C "$GATEWAY_DIR" rev-parse --short HEAD 2>/dev/null || echo "unknown")"
TIMESTAMP="$(date -u '+%Y%m%dT%H%MZ')"
RESULT_FILE="$RESULTS_DIR/bench-${PLUGIN}-${SHA}.json"

echo "INFO: bench plugin=$PLUGIN sha=$SHA duration=$DURATION rps=$RPS"

# ── mint JWT ─────────────────────────────────────────────────────────────────
# Build benchtoken in a temp dir to avoid polluting source.
echo "INFO: building benchtoken..."
BENCHTOKEN_BIN="$(mktemp -d)/benchtoken"
go build -o "$BENCHTOKEN_BIN" "$GATEWAY_DIR/bench/cmd/benchtoken" 2>&1 || {
  echo "ERROR: failed to build bench/cmd/benchtoken" >&2
  exit 2
}

TOKEN="$("$BENCHTOKEN_BIN" -secret "$SECRET" -subject "bench-user" \
          -audience "$AUDIENCE" -exp 86400 2>/dev/null)"
if [[ -z "$TOKEN" ]]; then
  echo "ERROR: benchtoken produced empty output" >&2
  exit 2
fi
echo "INFO: JWT minted (sub=bench-user, exp=86400s)"

# ── build targets file with token injected ───────────────────────────────────
TMP_TARGETS="$(mktemp /tmp/bench-targets-XXXXXX.txt)"
trap 'rm -f "$TMP_TARGETS"' EXIT
sed "s|{{TOKEN}}|Bearer ${TOKEN}|g" "$TARGETS_FILE" > "$TMP_TARGETS"

# ── helper: run one attack variant ───────────────────────────────────────────
# run_attack <label> <active_plugins_src>
# Sets active-plugins.yaml, brings up compose, attacks, tears down.
# Writes attack report to stdout as JSON; caller captures.
run_attack() {
  local label="$1"
  local cfg_src="$2"
  local project="bench-${PLUGIN}-${label}"

  echo "INFO: [$label] writing active-plugins.yaml from $cfg_src"
  cp "$cfg_src" "$SCRIPT_DIR/active-plugins.yaml"

  echo "INFO: [$label] starting compose stack (project=$project)..."
  docker compose \
    -f "$COMPOSE_FILE" \
    --project-name "$project" \
    up -d --build --wait \
    2>&1 | sed "s/^/  [$label] /"

  # Extra readiness wait — compose --wait checks healthcheck, but give the
  # gateway 1 s after healthy before load starts.
  sleep 1

  echo "INFO: [$label] attacking for $DURATION @ ${RPS} rps..."
  local report_json
  report_json="$(vegeta attack \
    -targets "$TMP_TARGETS" \
    -rate="${RPS}/s" \
    -duration="$DURATION" \
    -timeout=5s \
    | vegeta report -type=json)"

  echo "INFO: [$label] tearing down compose stack..."
  docker compose \
    -f "$COMPOSE_FILE" \
    --project-name "$project" \
    down --remove-orphans \
    2>&1 | sed "s/^/  [$label] /"

  # Remove the active-plugins.yaml sentinel so a stale run cannot accidentally
  # pick up the previous variant's config.
  rm -f "$SCRIPT_DIR/active-plugins.yaml"

  echo "$report_json"
}

# ── run both variants ─────────────────────────────────────────────────────────
echo "=== variant: plugin-enabled ==="
ENABLED_JSON="$(run_attack "enabled" "$PLUGIN_CFG")"

echo "=== variant: baseline ==="
BASELINE_JSON="$(run_attack "baseline" "$BASELINE_CFG")"

# ── parse and compute result ──────────────────────────────────────────────────
# vegeta JSON report shape (latencies in nanoseconds):
# {
#   "latencies": {"total":…,"mean":…,"50th":…,"90th":…,"95th":…,"99th":…,"max":…,"min":…},
#   "requests":  <int>,
#   "rate":      <float>,  // achieved RPS
#   "success":   <float>,  // 0.0–1.0
#   "status_codes": {...},
#   "duration":  <int>     // nanoseconds
# }

echo "INFO: computing result JSON..."
python3 - <<PYEOF
import json, sys

def ns_to_ms(ns):
    return round(ns / 1_000_000.0, 3)

enabled_raw  = json.loads(r"""${ENABLED_JSON}""")
baseline_raw = json.loads(r"""${BASELINE_JSON}""")

def parse_variant(raw):
    lat = raw.get("latencies", {})
    return {
        "requests":      raw.get("requests", 0),
        "rps":           round(raw.get("rate", 0), 2),
        "p50_ms":        ns_to_ms(lat.get("50th", 0)),
        "p95_ms":        ns_to_ms(lat.get("95th", 0)),
        "p99_ms":        ns_to_ms(lat.get("99th", 0)),
        "success_rate":  round(raw.get("success", 0), 4),
    }

ev = parse_variant(enabled_raw)
bv = parse_variant(baseline_raw)

result = {
    "plugin":                 "${PLUGIN}",
    "sha":                    "${SHA}",
    "timestamp":              "${TIMESTAMP}",
    "duration_s":             "${DURATION}".rstrip("s"),
    "target_rps":             ${RPS},
    "plugin_enabled":         ev,
    "baseline":               bv,
    "overhead_delta_p99_ms":  round(ev["p99_ms"] - bv["p99_ms"], 3),
}

out = json.dumps(result, indent=2)
print(out)

# Write to result file
with open("${RESULT_FILE}", "w") as f:
    f.write(out + "\n")
print(f"INFO: result written to ${RESULT_FILE}", file=sys.stderr)
PYEOF

# ── regression check ─────────────────────────────────────────────────────────
echo "INFO: running regression-check.sh..."
bash "$SCRIPT_DIR/regression-check.sh" "$PLUGIN" "$RESULT_FILE"
