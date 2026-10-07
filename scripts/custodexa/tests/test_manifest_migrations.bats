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

# ---------- runtime markers ----------

# markers_block <build-package.sh>: the runtime marker list and its reader, sourced alone.
markers_block() {
  # shellcheck disable=SC1090
  . <(sed -n '/^# >>> runtime markers/,/^# <<< runtime markers/p' "$1")
}

# markers_pinned <json>: the first versions of the three markers as git history dates them
# (the commit that added each constant and the first release after it).
markers_pinned() {
  [ "$(jq -r '.[] | select(.id == "20260804_ldap_env_seeded") | .first_version' <<<"$1")" = 1.0.0 ] &&
    [ "$(jq -r '.[] | select(.id == "20260825_offsite_env_seeded") | .first_version' <<<"$1")" = 1.1.0 ] &&
    [ "$(jq -r '.[] | select(.id == "20260906_credential_secrets_converted") | .first_version' <<<"$1")" = 1.6.0 ]
}

# markers_tree: the real Go sources of the database package in $TREE.
markers_tree() {
  cp "$REPO"/backend/internal/database/*.go "$TREE/backend/internal/database/"
}

@test "MANIFEST runtime_markers: the same ids as runtimeMarkerVersions, in order, each with its first version" {
  markers_block "$REPO/scripts/release/build-package.sh"
  run runtime_markers_json "$REPO"
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  # The ids the backend source lists, resolved from its constants by a reader of its own.
  local names want=""
  names=$(sed -n '/^var runtimeMarkerVersions = \[\]string{$/,/^}$/p' "$REPO/backend/internal/database/migrations.go" |
    sed 's#//.*##' | tr -d ' \t,' | grep -E '^[A-Za-z_]+$')
  for n in $names; do
    want+=$(grep -h "^const $n = " "$REPO"/backend/internal/database/*.go | cut -d'"' -f2)$'\n'
  done
  [ "$(jq -r '.[].id' <<<"$output")" = "${want%$'\n'}" ] || { echo "$output"; return 1; }
  [ "$(jq -r 'length' <<<"$output")" -ge 3 ] || return 1
  markers_pinned "$output" || return 1
  jq -e 'all(.[]; keys == ["first_version", "id"])' <<<"$output" >/dev/null
}

@test "MANIFEST runtime_markers: a row taken out of the list, or a marker the list lacks, stops the build" {
  local b=$BATS_TEST_TMPDIR/build-package.sh
  markers_tree
  sed '/^20260825_offsite_env_seeded 1.1.0$/d' "$REPO/scripts/release/build-package.sh" >"$b"
  markers_block "$b"
  run runtime_markers_json "$TREE"
  [ "$status" -ne 0 ] && [[ $output == *"20260825_offsite_env_seeded needs one row"* ]] || { echo "$output"; return 1; }
  # A marker gone from the Go source while the list keeps it: the list must cover the source exactly.
  markers_block "$REPO/scripts/release/build-package.sh"
  sed -i '/^\tOffsiteSeedMarkerVersion,$/d' "$TREE/backend/internal/database/migrations.go"
  run runtime_markers_json "$TREE"
  [ "$status" -ne 0 ] && [[ $output == *"is listed but not in the Go source"* ]] || { echo "$output"; return 1; }
}

@test "MANIFEST runtime_markers: a first version changed in the list fails the history-dated pins" {
  local b=$BATS_TEST_TMPDIR/build-package.sh
  sed 's/^20260906_credential_secrets_converted 1.6.0/20260906_credential_secrets_converted 1.7.0/' \
    "$REPO/scripts/release/build-package.sh" >"$b"
  ! cmp -s "$b" "$REPO/scripts/release/build-package.sh" || { echo "the mutation did not apply"; return 1; }
  markers_block "$b"
  run runtime_markers_json "$REPO"
  [ "$status" -eq 0 ] || return 1
  ! markers_pinned "$output"
}

@test "MANIFEST: build-package writes runtime_markers next to migrations" {
  grep -q 'markers=$(runtime_markers_json "$source")' "$REPO/scripts/release/build-package.sh"
  grep -q 'runtime_markers: $markers' "$REPO/scripts/release/build-package.sh"
}
