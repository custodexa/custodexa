# shellcheck shell=bash
# about: a real 1.15.2 deployment (its published package and offline bundle) upgraded to 1.16.90 by the 1.16.90 script: the upgrade's backup (data of 1.15.2) is refused before anything stops on that host and on a fresh host, with no download; with 1.16.90 data, a release whose VERSION alone claims a newer version, a snapshot that disagrees with the dump (member checksums recomputed) and a snapshot naming a migration the engine does not know are each refused, and no backend is ever started on the fresh host
# hosts: a b
# needs: package local-versions published
# images:

readonly CV_OLD=1.15.2 CV_NEW=1.16.90 CV_SPOOF=1.16.99
readonly CV_T=/transfer

# cv_restore <label> <file> <arguments...>: restore of that file, as an operator without a terminal.
cv_restore() {
  local label=$1 file=$2
  shift 2
  lv_cx "$label" restore "$file" --yes "$@"
}

# cv_no_download <label>: the run fetched nothing: no download line, no incoming folder.
cv_no_download() {
  it_same "$1: no download was started" 0 "$(grep -c 'Downloading' <<<"$LV_OUT" || true)"
  it_same "$1: no incoming release folder" "" "$(find "$LV_ROOT/releases" -maxdepth 1 -name '.incoming-*')"
}

# cv_said <label> <text...>: the screen (lines joined) holds each text.
cv_said() {
  local label=$1 flat t
  shift
  flat=$(tr '\n' ' ' <<<"$LV_OUT" | tr -s ' ')
  for t in "$@"; do
    it_check "$label: the screen says \"$t\"" grep -qF -- "$t" <<<"$flat"
  done
}

# cv_host_state: what a refused restore must leave as it was on the installed host.
cv_host_state() {
  (
    cd "$LV_ROOT" || exit 1
    sha256sum .env state.json
    find data -maxdepth 1 -printf '%p %i %m %U:%G\n' | sort
    ls -1A releases
    readlink current
  )
}

# cv_counts: users, sessions, audit_logs of the running database.
cv_counts() { lv_sql "SELECT (SELECT count(*) FROM users)||' '||(SELECT count(*) FROM sessions)||' '||(SELECT count(*) FROM audit_logs)"; }

# cv_repack <source file> <folder>: the member files of <folder> packed again in the source's member
# order, SHA256SUMS of the members recomputed, a matching .sha256 beside it; the new file has the
# source's name, in $CV_T/<folder name>/.
cv_repack() {
  local src=$1 dir=$2 out
  out=$CV_T/${dir##*/}/${src##*/}
  mkdir -p "${out%/*}"
  (
    cd "$dir" || exit 1
    grep -v '  SHA256SUMS$' SHA256SUMS | awk '{print $2}' | xargs sha256sum >SHA256SUMS.new
    mv SHA256SUMS.new SHA256SUMS
  )
  tar -tf "$src" >"$dir.members"
  tar --format=gnu -C "$dir" -cf "$out" -T "$dir.members"
  (cd "${out%/*}" && sha256sum "${out##*/}" >"${out##*/}.sha256")
}

# cv_unpack_backup <file> <folder>: the members of a backup file into a new folder.
cv_unpack_backup() {
  rm -rf "$2"
  mkdir -p "$2"
  tar -xf "$1" -C "$2"
}

# cv_manifest_set <manifest> <key> <value>: one key of backup-manifest.json changed in place, its
# quoting kept, nothing else touched.
cv_manifest_set() {
  local f=$1 k=${2//./\\.} v=$3
  sed -E -i "s/(\"$k\": *)\"[^\"]*\"/\\1\"$v\"/; s/(\"$k\": *)([0-9]+)([,}]|$)/\\1$v\\3/" "$f"
  it_same "manifest $2 is now $v" "$v" "$(jq -r --arg k "$2" '.[$k]' "$f")"
}

scenario_a() {
  local b0 b1 ps0 state0 counts0 x d migs
  it_step "the published $CV_OLD package and offline bundle"
  it_check "the published files match their SHA256SUMS" bash -c 'cd /published && sha256sum -c --quiet SHA256SUMS'
  mkdir -p /opt
  tar -xzf "/published/custodexa-$CV_OLD.tar.gz" -C /opt
  it_same "the published package is $CV_OLD" "$CV_OLD" "$(cat "$LV_ROOT/current/VERSION")"
  ex_preset "$LV_ROOT" KEK_PROVIDER=env
  lv_cx install install --images "$(find /published -maxdepth 1 -name "custodexa-images-$CV_OLD-*.tar")"
  it_same "install $CV_OLD exits 0" 0 "$LV_RC"
  lv_wait_version "$CV_OLD"

  it_step "upgrade to $CV_NEW with its package (the $CV_OLD script hands the upgrade to the $CV_NEW script)"
  lv_upgrade "$CV_NEW"
  lv_wait_version "$CV_NEW"
  it_same "current.version" "$CV_NEW" "$(lv_st current.version)"
  b0=$LV_ROOT/$(lv_st last_upgrade.backup)
  it_check "the upgrade's backup is a file" test -f "$b0"
  it_same "its manifest: product.version, trigger" "$CV_OLD upgrade" \
    "$(tar -xOf "$b0" backup-manifest.json | jq -r '."product.version" + " " + .trigger')"

  it_step "restore the upgrade's backup on this host (now $CV_NEW)"
  ps0=$(lv_ps)
  state0=$(cv_host_state)
  counts0=$(cv_counts)
  cv_restore same "$b0" --same-host --confirm-data-loss
  it_same "same: restore exits 3" 3 "$LV_RC"
  cv_said same "The data in this backup belongs to $CV_OLD, which is older than 1.16.0" "Nothing has been changed."
  it_same "same: the services still run, the same containers" "$ps0" "$(lv_ps)"
  it_same "same: the backend still reports $CV_NEW" "$CV_NEW" "$(lv_version)"
  it_same "same: .env, state.json, the data folders, releases and the current link are unchanged" "$state0" "$(cv_host_state)"
  it_same "same: users, sessions, audit_logs unchanged" "$counts0" "$(cv_counts)"
  it_same "same: no last_restore record" "" "$(lv_st last_restore.result)"
  cv_no_download same

  it_step "a backup of $CV_NEW data, and three files made from it"
  lv_cx backup backup --yes
  it_same "backup exits 0" 0 "$LV_RC"
  b1=$LV_ROOT/$(lv_st last_backup.file)
  it_same "its manifest: product.version" "$CV_NEW" "$(tar -xOf "$b1" backup-manifest.json | jq -r '."product.version"')"
  mkdir -p "$CV_T/upgrade" "$CV_T/new"
  cp "$b0" "$b0.sha256" "$CV_T/upgrade/"
  cp "$b1" "$b1.sha256" "$CV_T/new/"

  # A snapshot that disagrees with the dump: one more user in snapshot.txt than the dump holds.
  x=$IT_WORK/dump-differs
  cv_unpack_backup "$b1" "$x"
  d=$(sed -n 's/^count\.users=//p' "$x/snapshot.txt")
  sed -i "s/^count\\.users=$d\$/count.users=$((d + 1))/" "$x/snapshot.txt"
  cv_repack "$b1" "$x"
  it_same "dump-differs: only snapshot.txt and SHA256SUMS differ from the original" "SHA256SUMS snapshot.txt" \
    "$(cv_changed "$b1" "$CV_T/dump-differs/${b1##*/}")"

  # A snapshot naming a migration no release has; its manifest's migration count and digest
  # recomputed the way the backup computes them, so the file is consistent in itself.
  x=$IT_WORK/unknown-migration
  cv_unpack_backup "$b1" "$x"
  printf 'migration=%s\n' it_unknown_future_change >>"$x/snapshot.txt"
  migs=$(sed -n 's/^migration=//p' "$x/snapshot.txt")
  cv_manifest_set "$x/backup-manifest.json" db.migrations_count "$(grep -c . <<<"$migs")"
  cv_manifest_set "$x/backup-manifest.json" db.migrations_sha256 "$(LC_ALL=C sort <<<"$migs" | sha256sum | cut -c1-64)"
  cv_repack "$b1" "$x"
  it_same "unknown-migration: snapshot.txt, the manifest and SHA256SUMS differ from the original" \
    "SHA256SUMS backup-manifest.json snapshot.txt" "$(cv_changed "$b1" "$CV_T/unknown-migration/${b1##*/}")"
  find "$CV_T" -type f | sort | sed 's/^/   transfer: /'
}

# cv_changed <file a> <file b>: the members whose contents differ, sorted, on one line.
cv_changed() {
  local m out=""
  while IFS= read -r m; do
    cmp -s <(tar -xOf "$1" "$m") <(tar -xOf "$2" "$m") || out+=" $m"
  done < <(tar -tf "$1")
  # shellcheck disable=SC2086 # one member per word
  printf '%s\n' $out | LC_ALL=C sort | paste -sd ' '
}

# cv_fresh_state: what a refused restore must leave on the host that was never installed.
cv_fresh_state() {
  it_same "$1: docker ps -a lists no container" "" "$(docker ps -aq)"
  it_same "$1: releases/ holds only $CV_NEW" "$CV_NEW" "$(ls -1A "$LV_ROOT/releases")"
  it_same "$1: no state of an installation (current.version)" "" "$(jq -r '."current.version" // ""' "$LV_ROOT/state.json" 2>/dev/null)"
  lv_cx "$1-status" status
  it_check "$1: status says not installed" grep -qF 'Not installed yet.' <<<"$LV_OUT"
}

scenario_b() {
  local f bundle
  it_step "a fresh host: the $CV_NEW package unpacked, nothing installed"
  it_unpack /opt "$CV_NEW"
  bundle=$(it_bundle_file "$CV_NEW")
  cv_fresh_state fresh

  it_step "restore the $CV_OLD upgrade backup on the fresh host"
  f=$(find "$CV_T/upgrade" -name '*.tar' | head -n1)
  cv_restore new "$f" --new-host
  it_same "new: restore exits 3" 3 "$LV_RC"
  cv_said new "The data in this backup belongs to $CV_OLD, which is older than 1.16.0" "Nothing has been changed."
  cv_fresh_state new
  cv_no_download new

  # Reading a backup of 1.16.0 or later needs the data release's database image (its grants are
  # checked before anything stops); an offline host loads that release's bundle first.
  it_step "the $CV_NEW offline bundle loaded (nothing installed)"
  lv_cx load load "$bundle"
  it_same "load exits 0" 0 "$LV_RC"
  cv_fresh_state loaded

  it_step "a snapshot naming a migration the engine does not know"
  f=$(find "$CV_T/unknown-migration" -name '*.tar' | head -n1)
  cv_restore unknown "$f" --new-host --images "$bundle"
  it_same "unknown: restore exits 3" 3 "$LV_RC"
  cv_said unknown "The backup's data has a structure change that $CV_NEW does not know" \
    "it_unknown_future_change (not in the $CV_NEW release manifest)" "Nothing has been changed."
  cv_fresh_state unknown

  it_step "the $CV_NEW release's VERSION file alone says $CV_SPOOF"
  f=$(find "$CV_T/new" -name '*.tar' | head -n1)
  cp "$LV_ROOT/releases/$CV_NEW/VERSION" "$IT_WORK/VERSION.orig"
  printf '%s\n' "$CV_SPOOF" >"$LV_ROOT/releases/$CV_NEW/VERSION"
  cv_restore spoof "$f" --new-host --images "$bundle"
  cp "$IT_WORK/VERSION.orig" "$LV_ROOT/releases/$CV_NEW/VERSION"
  it_check "spoof: restore fails (exit $LV_RC)" test "$LV_RC" -ne 0
  it_same "spoof: no backend container was ever created" "" "$(docker ps -aq --filter name=backend)"
  it_same "spoof: no restore record past the checks" "" "$(jq -r '."last_restore.phase" // ""' "$LV_ROOT/state.json" 2>/dev/null)"
  cv_said spoof "Nothing has been changed."
  cv_fresh_state spoof

  it_step "a snapshot that disagrees with the dump"
  f=$(find "$CV_T/dump-differs" -name '*.tar' | head -n1)
  cv_restore differs "$f" --new-host --images "$bundle"
  it_check "differs: restore fails (exit $LV_RC)" test "$LV_RC" -ne 0
  cv_said differs "Check the database: users row count differs"
  it_same "differs: stopped at the check after the import (last_restore.phase)" imported "$(lv_st last_restore.phase)"
  it_same "differs: no backend container was ever created" "" "$(docker ps -aq --filter name=backend)"
  docker ps -a --format '   containers: {{.Names}} {{.Status}}'
}
