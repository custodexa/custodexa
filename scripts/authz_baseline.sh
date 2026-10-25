#!/usr/bin/env bash
# Authorization decision baseline: re-run and report.
#
#   scripts/authz_baseline.sh compare
#       Runs the backend baseline comparisons (route group, flow groups,
#       coverage, approved-difference self-check) and the front-end entry
#       group inside the dev compose stack. Exit code 0 means no unapproved
#       difference.
#
#   scripts/authz_baseline.sh report <output.json>
#       Same runs, and additionally writes every difference (scenario,
#       field, old value, new value, matching approved entry or
#       "unapproved") as JSON to <output.json> plus a Markdown summary next
#       to it (<output>.md). Exit code is the comparison result.
#
# The scenario tests use fixed local receiver ports, so never run two
# baseline invocations at the same time.
set -euo pipefail

cd "$(dirname "$0")/.."

BACKEND_TESTS='^TestAuthzBaseline(Routes|Flows|Coverage|ApprovedDiffs|ToolingCases)$'

usage() {
  sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'
  exit 2
}

run_backend() {
  local report_dir="${1:-}"
  local env_args=(-e AUTHZ_BASELINE=1)
  if [[ -n "$report_dir" ]]; then
    env_args+=(-e "AUTHZ_BASELINE_REPORT_DIR=$report_dir")
  fi
  docker compose exec -T "${env_args[@]}" backend \
    go test ./cmd/server/ -run "$BACKEND_TESTS" -count=1 -timeout 30m
}

run_frontend() {
  docker compose exec -T frontend npm run test -- authz-baseline-entries
}

cmd="${1:-}"
case "$cmd" in
  compare)
    rc=0
    run_backend || rc=1
    run_frontend || rc=1
    exit "$rc"
    ;;
  report)
    out="${2:-}"
    [[ -n "$out" ]] || usage
    container_dir="/tmp/authz-baseline-report-$$"
    docker compose exec -T backend sh -c "rm -rf '$container_dir' && mkdir -p '$container_dir'"
    rc=0
    run_backend "$container_dir" || rc=1
    fe_rc=0
    run_frontend || { fe_rc=1; rc=1; }
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    docker compose cp "backend:$container_dir/." "$tmp/" >/dev/null
    docker compose exec -T backend rm -rf "$container_dir"
    mkdir -p "$(dirname "$out")"
    python3 - "$tmp" "$out" "$fe_rc" <<'PY'
import glob, json, os, sys

src, out, fe_rc = sys.argv[1], sys.argv[2], int(sys.argv[3])
groups = {}
for path in sorted(glob.glob(os.path.join(src, "report-*.json"))):
    with open(path) as f:
        rep = json.load(f)
    groups[rep["group"]] = rep
report = {
    "groups": groups,
    "frontend_entry_group": "pass" if fe_rc == 0 else "fail",
}
with open(out, "w") as f:
    json.dump(report, f, indent=1, ensure_ascii=False)
    f.write("\n")

lines = ["# Authorization baseline report", ""]
lines.append("| Group | Differences | Approved | Failing | Stale active entries | New tables | New columns |")
lines.append("|---|---|---|---|---|---|---|")
total_bad = 0
for g in sorted(groups):
    res = groups[g].get("result", {})
    diffs = res.get("diffs") or []
    approved = sum(1 for d in diffs if d.get("verdict") == "approved")
    bad = len(diffs) - approved
    stale = (res.get("stale_active") or []) + (res.get("partial_active") or [])
    total_bad += bad + len(stale)
    proj = groups[g].get("projection") or {}
    lines.append(
        f"| {g} | {len(diffs)} | {approved} | {bad} | {len(stale)} | "
        f"{len(proj.get('new_tables') or [])} | {sum(len(v) for v in (proj.get('new_columns') or {}).values())} |"
    )
lines.append(f"| E (front end) | - | - | {'0' if fe_rc == 0 else 'see test output'} | - | - | - |")
lines.append("")
lines.append(f"Failing backend differences: {total_bad}.")
shown = 0
for g in sorted(groups):
    for d in groups[g].get("result", {}).get("diffs") or []:
        if d.get("verdict") == "approved" or shown >= 50:
            continue
        if shown == 0:
            lines += ["", "## First failing differences", ""]
        shown += 1
        lines.append(f"- `{d['id']}` field `{d['field']}`: {d['verdict']} {d.get('entry', '')}".rstrip())
md = os.path.splitext(out)[0] + ".md"
with open(md, "w") as f:
    f.write("\n".join(lines) + "\n")
print(f"report: {out}")
print(f"summary: {md}")
PY
    exit "$rc"
    ;;
  *)
    usage
    ;;
esac
