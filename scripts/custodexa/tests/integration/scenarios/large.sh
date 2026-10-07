# shellcheck shell=bash
# about: a backup file holding a member over 8 GiB (a sparse 9 GiB db.dump) is put together, read back and committed by the script's own pack step, and GNU tar lists and extracts that member at full size
# needs:
# images:

readonly LG_SIZE=$((9 * 1024 * 1024 * 1024)) # over 8 GiB - 1, the most a ustar header can hold
readonly LG_TAIL='the last bytes of the large member'

# lg_pack <deployment folder> <name>: the script's pack step (cx_pb_pack: SHA256SUMS, tar
# --format=gnu --remove-files, the read-back, the checksum file, the commit) on the members in
# backups/.partial-<ts>/. Only the manifest writer is replaced: it needs a deployment, and this
# scenario is about the size of a member.
lg_pack() {
  bash -c '
    set -euo pipefail
    CX_DIR=/src/scripts/custodexa
    . "$CX_DIR/lib/common.sh"
    cx_load_libs "$CX_DIR"
    . "$CX_DIR/lib/health.sh"
    . "$CX_DIR/lib/backup.sh"
    . "$CX_DIR/lib/portable.sh"
    CX_ROOT=$1
    CX_LOG_FILE=$1/logs/large.log
    CX_BK_DIR=$1/backups/.partial-$3
    CX_PB_NAME=$2
    CX_PB_FINAL=$1/backups/$2
    CX_PB_ENC=0
    CX_PB_WITH_REC=0
    cx_pb_manifest_write() { printf "{\n  \"format\": \"it-large\"\n}\n" >"$1"; }
    cx_pb_manifest_ok() { return 0; }
    cx_pb_pack
    printf "commit=%s size=%s\n" "$CX_PB_COMMIT" "$CX_PB_SIZE"
  ' _ "$@"
}

scenario() {
  local root=$IT_WORK/large ts=20261005-120000 name d f sum out size
  name=custodexa-backup-0.0.0-$ts.tar
  d=$root/backups/.partial-$ts
  mkdir -p "$root/logs"
  mkdir -m 700 "$root/backups" "$d"
  it_step "the members, db.dump sparse: $LG_SIZE bytes of holes, then $(printf '%s' "$LG_TAIL" | wc -c) bytes"
  (
    umask 077
    printf '{"version": "0.0.0"}\n' >"$d/release-MANIFEST.json"
    printf '{"version": "0.0.0"}\n' >"$d/tool-MANIFEST.json"
    printf 'format=1\n' >"$d/snapshot.txt"
    printf 'KEY=value\n' >"$d/env.bak"
    mkdir -p "$IT_WORK/src/audit" "$IT_WORK/src/tls"
    printf 'audit\n' >"$IT_WORK/src/audit/a.log"
    printf 'tls\n' >"$IT_WORK/src/tls/t.pem"
    tar -czf "$d/audit.tar.gz" -C "$IT_WORK/src" audit
    tar -czf "$d/tls.tar.gz" -C "$IT_WORK/src" tls
    truncate -s "$LG_SIZE" "$d/db.dump"
    printf '%s' "$LG_TAIL" >>"$d/db.dump"
  )
  size=$(stat -c %s "$d/db.dump")
  it_check "db.dump is over 8 GiB ($size bytes) and takes almost no disk ($(du -k "$d/db.dump" | cut -f1) KiB)" \
    test "$size" -gt 8589934591 -a "$(du -k "$d/db.dump" | cut -f1)" -lt 1024
  sum=$(sha256sum <"$d/db.dump" | cut -d' ' -f1)
  it_say "   db.dump sha256: $sum"

  it_step "the script's pack step"
  out=$(lg_pack "$root" "$name" "$ts")
  it_say "   $out"
  f=$root/backups/$name
  it_same "the file is committed" "commit=committed" "${out%% *}"
  it_check "the backup file and its checksum file are in place, 0600" \
    test "$(stat -c %a "$f")" = 600 -a "$(stat -c %a "$f.sha256")" = 600
  it_check "the checksum file matches" bash -c 'cd "$1" && sha256sum -c --quiet "$2.sha256"' _ "$root/backups" "$name"
  it_check "the members were removed from the temporary folder as they were stored" \
    test -z "$(find "$d" -mindepth 1 -name db.dump)"
  it_say "   backup file: $(stat -c %s "$f") bytes"

  it_step "GNU tar reads the member at full size"
  out=$(tar -tvf "$f" db.dump)
  it_say "   $out"
  it_same "tar -tv gives the member's full size" "$size" "$(awk '{print $3}' <<<"$out")"
  it_same "the member extracts to the same bytes" "$sum" "$(tar -xOf "$f" db.dump | sha256sum | cut -d' ' -f1)"
  it_same "the members, in order" "backup-manifest.json release-MANIFEST.json tool-MANIFEST.json snapshot.txt db.dump audit.tar.gz env.bak tls.tar.gz SHA256SUMS" \
    "$(tar -tf "$f" | tr '\n' ' ' | sed 's/ $//')"
  mkdir -p "$IT_WORK/x"
  tar -xf "$f" -C "$IT_WORK/x" SHA256SUMS
  it_same "SHA256SUMS in the file holds the member's hash" "$sum" "$(awk '$2 == "db.dump" {print $1}' "$IT_WORK/x/SHA256SUMS")"
  rm -rf "$root"
}
