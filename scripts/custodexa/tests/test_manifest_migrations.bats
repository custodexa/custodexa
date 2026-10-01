#!/usr/bin/env bats

load helper

setup() {
  REPO=$(cd "$SRC/../.." && pwd)
  # shellcheck source=scripts/release/migrations-json.sh
  . "$REPO/scripts/release/migrations-json.sh"
  # Called by the sourced release parser.
  # shellcheck disable=SC2329
  die() { echo "$*" >&2; exit 1; }
  TREE=$BATS_TEST_TMPDIR/source
  mkdir -p "$TREE/backend/internal/database"
  printf 'const BaselineVersion = "baseline_001"\n' >"$TREE/backend/internal/database/baseline.go"
}

fixture() {
  printf 'var migrations = []Migration{\n%s\n}\n' "$1" >"$TREE/backend/internal/database/migrations.go"
}

assert_versions() {
  local expected=$1
  run migrations_json "$TREE"
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [ "$(jq -c . <<<"$output")" = "$expected" ]
}

@test "MANIFEST migrations include single-line entries" {
  fixture $'\t{Version: "one", Name: "first"},\n\t{Version: "two", Name: "second"},'
  assert_versions '["one","two"]'
}

@test "MANIFEST migrations include multi-line entries" {
  fixture $'\t{\n\t\tVersion: "one",\n\t\tName: "first",\n\t},\n\t{\n\t\tVersion: "two",\n\t},'
  assert_versions '["one","two"]'
}

@test "MANIFEST migrations resolve BaselineVersion" {
  fixture $'\t{Version: BaselineVersion, Name: "baseline"},'
  assert_versions '["baseline_001"]'
}

@test "MANIFEST migrations preserve mixed slice order" {
  fixture $'\t{Version: "first"},\n\t{\n\t\tVersion: BaselineVersion,\n\t},\n\t{Version: "last"},'
  assert_versions '["first","baseline_001","last"]'
}

@test "MANIFEST migrations reject an unrecognized Version value" {
  fixture $'\t{Version: makeVersion(), Name: "bad"},'
  run migrations_json "$TREE"
  [ "$status" -ne 0 ]
  [[ $output == *"neither a literal nor BaselineVersion"* ]]
}

@test "MANIFEST migrations reject an unrecognized entry shape" {
  fixture $'\tMigration{Version: "third_style"},'
  run migrations_json "$TREE"
  [ "$status" -ne 0 ]
  [[ $output == *"unrecognized migration entry"* ]]
}

@test "real migrations slice has one MANIFEST id per Version field" {
  run migrations_json "$REPO"
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  actual=$(jq 'length' <<<"$output")
  expected=$(sed -n '/^var migrations = \[\]Migration{$/,/^}$/p' "$REPO/backend/internal/database/migrations.go" |
    grep -c 'Version:')
  [ "$actual" -eq "$expected" ]
}
