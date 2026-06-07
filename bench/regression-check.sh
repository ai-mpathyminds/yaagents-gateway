#!/usr/bin/env bash
# gateway/bench/regression-check.sh — obvious-regression detector (WI-4yaa.BENCH-0)
#
# Usage:
#   bash bench/regression-check.sh <plugin-name> <result-json-path>
#
# Reads bench/baselines.json to find the baseline overhead_delta_p99_ms for
# the plugin. If no baseline exists, records current result as the new baseline
# and exits 0 (first-run auto-seed).
#
# Threshold: 25% regression on overhead_delta_p99_ms (or absolute +5ms
# if baseline <= 2ms — guards against noise on fast paths).
#
# Result JSON format (from harness.sh):
# {
#   "plugin": "tokenvalidator",
#   "sha": "abc1234",
#   "timestamp": "20260607T1200Z",
#   "duration_s": "60",
#   "target_rps": 100,
#   "plugin_enabled":  {"requests":…,"rps":…,"p50_ms":…,"p95_ms":…,"p99_ms":…,"success_rate":…},
#   "baseline":        {"requests":…,"rps":…,"p50_ms":…,"p95_ms":…,"p99_ms":…,"success_rate":…},
#   "overhead_delta_p99_ms": 3.2
# }
#
# baselines.json format:
# { "tokenvalidator": {"overhead_delta_p99_ms": 2.8, "sha": "abc1234", "timestamp": "…"} }
#
# exit 0 → pass (no regression, or first run — baseline seeded)
# exit 1 → regression detected
# exit 2 → usage / file error

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASELINES_FILE="$SCRIPT_DIR/baselines.json"

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <plugin-name> <result-json-path>" >&2
  exit 2
fi

PLUGIN="$1"
RESULT_FILE="$2"

if [[ ! -f "$RESULT_FILE" ]]; then
  echo "ERROR: result file not found: $RESULT_FILE" >&2
  exit 2
fi

if [[ ! -f "$BASELINES_FILE" ]]; then
  echo "ERROR: baselines.json not found at $BASELINES_FILE" >&2
  exit 2
fi

python3 - <<PYEOF
import json, sys, math

THRESHOLD_PCT  = 0.25   # 25% relative regression
ABS_FLOOR_MS   = 2.0    # if baseline <= this, use absolute threshold instead
ABS_THRESHOLD  = 5.0    # absolute ms threshold for near-zero baselines

plugin      = "${PLUGIN}"
result_path = "${RESULT_FILE}"
baselines_path = "${BASELINES_FILE}"

with open(result_path) as f:
    result = json.load(f)

with open(baselines_path) as f:
    baselines = json.load(f)

current_delta = result.get("overhead_delta_p99_ms", 0.0)
sha           = result.get("sha", "unknown")
ts            = result.get("timestamp", "unknown")

if plugin not in baselines:
    # First run — seed the baseline and pass.
    print(f"INFO [regression-check]: no baseline for '{plugin}'; seeding baseline={current_delta:.3f}ms and passing.")
    baselines[plugin] = {
        "overhead_delta_p99_ms": current_delta,
        "sha": sha,
        "timestamp": ts,
    }
    with open(baselines_path, "w") as f:
        json.dump(baselines, f, indent=2)
        f.write("\n")
    print("INFO [regression-check]: baselines.json updated.")
    sys.exit(0)

baseline_delta = baselines[plugin]["overhead_delta_p99_ms"]

if baseline_delta <= ABS_FLOOR_MS:
    # Near-zero baseline — use absolute threshold.
    threshold_ms = ABS_THRESHOLD
    violated = (current_delta - baseline_delta) > threshold_ms
    threshold_desc = f"abs +{threshold_ms}ms (baseline {baseline_delta:.3f}ms <= {ABS_FLOOR_MS}ms floor)"
else:
    threshold_ms = baseline_delta * THRESHOLD_PCT
    violated = (current_delta - baseline_delta) > threshold_ms
    threshold_desc = f"{int(THRESHOLD_PCT*100)}% of baseline {baseline_delta:.3f}ms = +{threshold_ms:.3f}ms"

print(f"INFO [regression-check] plugin={plugin}")
print(f"  baseline overhead_delta_p99_ms : {baseline_delta:.3f} ms  (sha={baselines[plugin]['sha']})")
print(f"  current  overhead_delta_p99_ms : {current_delta:.3f} ms  (sha={sha})")
print(f"  threshold                      : {threshold_desc}")

if violated:
    excess = current_delta - baseline_delta
    print(f"FAIL [regression-check]: p99 overhead regressed by +{excess:.3f}ms (> threshold)")
    print("  To update the baseline after an intentional change:")
    print(f"    python3 -c \"import json; d=json.load(open('{baselines_path}')); d['{plugin}']['overhead_delta_p99_ms']={current_delta:.3f}; d['{plugin}']['sha']='{sha}'; d['{plugin}']['timestamp']='{ts}'; open('{baselines_path}','w').write(json.dumps(d,indent=2)+'\\n')\"")
    sys.exit(1)
else:
    delta_pct = ((current_delta - baseline_delta) / max(baseline_delta, 0.001)) * 100
    print(f"PASS [regression-check]: overhead within threshold (delta={current_delta - baseline_delta:+.3f}ms, {delta_pct:+.1f}%)")
    sys.exit(0)
PYEOF
