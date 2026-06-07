# Gateway Benchmark Harness (WI-4yaa.BENCH-0)

Generic load-testing harness for the yaagents gateway plugin chain.
Produces structured JSON results and detects obvious regressions against committed baselines.

## Tool choice

**[vegeta](https://github.com/tsenart/vegeta)** — pure Go binary, same toolchain as the gateway.
No Docker-in-Docker, no Node.js, no extra runner dependencies.
`harness.sh` installs vegeta via `go install` if not already on PATH.

## Prerequisites

- Docker + Docker Compose plugin (`docker compose` v2)
- Go ≥ 1.23 (same as gateway `go.mod`)
- Python 3 (`python3`) — for JSON computation in harness.sh
- `git` — for SHA stamping results

## Quick start

```bash
# From the gateway/ directory:
bash bench/harness.sh tokenvalidator
```

This runs two 60-second attacks (plugin-enabled variant, then baseline) and writes:
- `bench/results/bench-tokenvalidator-<sha>.json` — structured result
- `bench/baselines.json` — updated if no prior baseline exists

## Environment overrides

| Variable | Default | Description |
|---|---|---|
| `BENCH_DURATION` | `60s` | vegeta attack duration |
| `BENCH_RPS` | `100` | requests per second (target rate) |
| `BENCH_SECRET` | `bench-secret` | HS256 JWT secret (must match plugin config) |
| `BENCH_AUDIENCE` | `bench-gateway` | JWT audience claim |
| `BENCH_RESULTS_DIR` | `bench/results` | output directory for result JSON |

## Result JSON format

```json
{
  "plugin": "tokenvalidator",
  "sha": "abc1234",
  "timestamp": "20260607T1200Z",
  "duration_s": "60",
  "target_rps": 100,
  "plugin_enabled": {
    "requests":     6000,
    "rps":          99.97,
    "p50_ms":       1.2,
    "p95_ms":       3.4,
    "p99_ms":       8.1,
    "success_rate": 1.0
  },
  "baseline": {
    "requests":     6000,
    "rps":          99.98,
    "p50_ms":       0.8,
    "p95_ms":       1.9,
    "p99_ms":       4.9,
    "success_rate": 1.0
  },
  "overhead_delta_p99_ms": 3.2
}
```

`overhead_delta_p99_ms` = `plugin_enabled.p99_ms` − `baseline.p99_ms`.
This isolates the plugin's own cost from gateway-level and network overhead.

## Regression detection

`regression-check.sh` compares `overhead_delta_p99_ms` against `baselines.json`:

- **First run**: no prior baseline → result is auto-seeded; exits 0.
- **Subsequent runs**: if delta exceeds 25% of the baseline (or +5ms absolute for
  near-zero baselines ≤ 2ms), the check exits 1 and prints a threshold explanation.

**Updating a baseline intentionally** (after a known regression is accepted):

```bash
PLUGIN=tokenvalidator
DELTA=5.2       # new accepted baseline value
SHA=$(git rev-parse --short HEAD)
TS=$(date -u '+%Y%m%dT%H%MZ')
python3 -c "
import json
d = json.load(open('bench/baselines.json'))
d['$PLUGIN'] = {'overhead_delta_p99_ms': $DELTA, 'sha': '$SHA', 'timestamp': '$TS'}
open('bench/baselines.json', 'w').write(json.dumps(d, indent=2) + '\n')
"
git add bench/baselines.json
git commit -m "bench: update $PLUGIN baseline to ${DELTA}ms (intentional)"
```

## Adding a new plugin bench

1. Add `bench/configs/<plugin>.yaml` with the plugin's config (must include `token-validator`).
2. Add `bench/targets/<plugin>.txt` in vegeta target-file format (`{{TOKEN}}` placeholder).
3. Run `bash bench/harness.sh <plugin>` to seed the baseline.
4. Commit `bench/baselines.json` with the seeded value.

## Directory layout

```
bench/
├── harness.sh               # main orchestrator — see inline docs
├── regression-check.sh      # 25% threshold detector
├── compose.bench.yml        # gateway + noop-upstream Docker Compose
├── Dockerfile.noop          # trivial always-200 upstream (isolates plugin cost)
├── baselines.json           # committed per-plugin baseline values
├── configs/
│   ├── bench-routes.yaml    # routes pointing at noop-upstream
│   ├── tokenvalidator.yaml  # token-validator plugin config (with propagate_claims)
│   └── baseline.yaml        # minimal token-validator config (cheapest valid state)
├── targets/
│   └── tokenvalidator.txt   # vegeta target file ({{TOKEN}} placeholder)
├── results/
│   └── .gitkeep             # tracked; actual result JSONs are .gitignored
└── cmd/
    ├── benchtoken/main.go   # mints HS256 JWT for attacks
    └── noop/main.go         # noop-upstream HTTP server
```

## CI

The bench workflow (`.github/workflows/bench.yml`) runs on pushes touching
`gateway/internal/plugins/**` or `gateway/bench/**`.
It is NOT a blocking pre-merge gate — use `workflow_dispatch` for on-demand runs.
BENCH-1 through BENCH-5 WIs will wire per-plugin gates once baselines stabilise.
