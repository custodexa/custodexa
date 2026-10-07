# shellcheck shell=bash
# Read an untrusted portable backup without extracting archive paths. The first pass hashes
# every regular member and keeps only metadata; the second writes only validated member names.
# Every validation chain fails if any of its operands fails.
# shellcheck disable=SC2034,SC2015
# The package helpers and backup libraries share readonly definitions. Load their common
# dependency tree once; sourcing the command defines functions but does not run an upgrade.
# shellcheck source=lib/cmd_upgrade.sh
. "${BASH_SOURCE[0]%/*}/cmd_upgrade.sh"

readonly CX_RS_MEMBERS='backup-manifest.json release-MANIFEST.json tool-MANIFEST.json snapshot.txt db.dump audit.tar.gz recordings.tar.gz env.bak tls.tar.gz nginx-tls.conf.template db-ca.pem state.json SHA256SUMS'
readonly CX_RS_REQUIRED='backup-manifest.json release-MANIFEST.json tool-MANIFEST.json snapshot.txt db.dump audit.tar.gz env.bak SHA256SUMS'
declare -gA CX_RS_MAP=()
declare -ga CX_RS_KEYS=()
CX_RS_DIR="" CX_RS_FILE="" CX_RS_TS="" CX_RS_ENC=0 CX_RS_CHECKSUM="" CX_RS_BAD=""
CX_RS_VERIFY_ONLY=0
CX_RS_BYTES=0 CX_RS_ENGINE="" CX_RS_VERSION="" CX_RS_OPENSSL="" CX_RS_DEC_RC=0 CX_RS_EXTRACT_TIME=0

cx_rs_get() { printf '%s' "${CX_RS_MAP[$1]:-}"; }
cx_rs_par() { printf '%s\n' "$1" | sed 's/^/  /'; }
cx_rs_unchanged() { printf '%s\n' "$(cx_msg rs_unchanged)"; }
cx_rs_bad() {
  local key=$1
  shift
  CX_RS_BAD=$key
  cx_line FAIL "$(cx_msg rs_bad)"
  cx_rs_par "$(cx_msg "rs_bad_$key" "$@")"
  cx_rs_par "$(cx_msg rs_copy_again)"
  cx_rs_unchanged
  return 1
}
cx_rs_cleanup() {
  CX_PB_PASS=""
  if [ "$(cx_state_get last_restore.staging)" != "$CX_RS_DIR" ]; then
    [ -z "$CX_RS_DIR" ] || rm -rf -- "$CX_RS_DIR"
  fi
  [ -z "${CX_RS_INCOMING:-}" ] || rm -rf -- "$CX_RS_INCOMING"
}
cx_rs_signal() {
  local rc=$CX_EXIT_REFUSED
  trap - INT TERM HUP
  if [ "$(cx_state_get last_restore.result)" = in_progress ] && declare -F cx_rs_interrupted >/dev/null; then
    cx_rs_interrupted
    cx_rs_cleanup
    exit "$CX_EXIT_FAILED"
  fi
  if [ "$CX_PB_MODE" = restore-safety ]; then
    cx_pb_interrupt_cleanup
    cx_log END "result=interrupted safety_step=$CX_BK_STEP_NOW commit=$(cx_pb_commit_state)"
    rc=$CX_EXIT_FAILED
  fi
  docker rm -f "custodexa-restore-tool-$CX_RS_TS-dec" "custodexa-restore-tool-$CX_RS_TS-grants" \
    "custodexa-restore-tool-$CX_RS_TS-cert" >/dev/null 2>&1 || true
  cx_rs_cleanup
  exit "$rc"
}
cx_rs_read_setup() {
  umask 077
  cx_lock
  cx_state_load "$CX_ROOT/state.json"
  cx_log_open restore || return 1
  CX_RS_TS=$(date '+%Y%m%d-%H%M%S')
  (umask 077 && mkdir -p "$CX_ROOT/restore") || return 1
  CX_RS_DIR=$(umask 077 && mktemp -d "$CX_ROOT/restore/$CX_RS_TS-XXXXXX") || return 1
  trap cx_rs_cleanup EXIT
  trap cx_rs_signal INT TERM HUP
  CX_RS_ENGINE=$(cat "$CX_DIR/VERSION")
}
cx_rs_old_file() {
  cx_line FAIL "$(cx_msg rs_old_file)"
  if [ -d "$CX_RS_FILE" ]; then
    cx_rs_par "$(cx_msg rs_old_folder "$CX_RS_FILE")"
  else
    cx_rs_par "$(cx_msg rs_no_manifest)"
  fi
  cx_rs_par "$(cx_msg rs_old_guide)"
  cx_rs_unchanged
  return 1
}

cx_rs_sidecar() {
  local sum name extra answer
  if [ -f "$CX_RS_FILE.sha256" ]; then
    read -r sum name extra <"$CX_RS_FILE.sha256" || true
    name=${name#\*}
    if ! [[ $sum =~ ^[0-9a-f]{64}$ ]] || [ "$name" != "${CX_RS_FILE##*/}" ] || [ -n "$extra" ] ||
      [ "$(wc -l <"$CX_RS_FILE.sha256")" -ne 1 ] || [ "$sum" != "$(cx_pb_sha "$CX_RS_FILE")" ]; then
      cx_rs_bad sidecar; return 1
    fi
    CX_RS_CHECKSUM=matched
    cx_line OK "$(cx_msg rs_sum_ok)"
    return 0
  fi
  CX_RS_CHECKSUM=absent
  if [ "${CX_RS_NO_CHECKSUM:-0}" != 1 ]; then
    if [ ! -t 0 ]; then
      cx_line FAIL "$(cx_msg rs_no_sum "$CX_RS_FILE.sha256")"
      cx_rs_unchanged
      return 1
    fi
    cx_line WARN "$(cx_msg rs_missing_sum "${CX_RS_FILE##*/}.sha256")"
    cx_rs_par "$(cx_msg rs_missing_sum_checks)"
    [[ $CX_RS_FILE != *.tar.enc ]] || cx_rs_par "$(cx_msg rs_missing_sum_enc)"
    printf '\n%s ' "$(cx_msg rs_missing_sum_ask)"
    IFS= read -r answer || answer=""
    case $answer in y|Y) ;; *) cx_rs_unchanged; return 1 ;; esac
  fi
  cx_line WARN "$(cx_msg rs_sum_absent)"
}

# Use only image identities pinned by the engine, including a classic store's config digest.
cx_rs_openssl_image() {
  local CX_IMG_ARCH
  CX_IMG_ARCH=$(cx_arch) || return 1
  cx_manifest_load "$CX_DIR/MANIFEST.json" >/dev/null || return 1
  # The engine's openssl as install accepts it on this host (offline bundles on containerd too).
  if CX_RS_OPENSSL=$(cx_img_held_id openssl); then return 0; fi
  cx_line FAIL "$(cx_msg rs_no_openssl "$CX_RS_ENGINE")"
  return 1
}
cx_rs_decrypt() {
  local -a ps=()
  printf '%s\n' "$CX_PB_PASS" | docker run --rm -i --pull never --network none --log-driver none \
    --name "custodexa-restore-tool-$CX_RS_TS-dec" -v "${CX_RS_FILE%/*}:/backup:ro" \
    --entrypoint openssl "$CX_RS_OPENSSL" enc -d -aes-256-cbc -saltlen 8 -pbkdf2 -md sha256 \
    -iter "$CX_PB_ITER" -pass stdin -in "/backup/${CX_RS_FILE##*/}"
  ps=("${PIPESTATUS[@]}")
  return "${ps[1]}"
}
cx_rs_pass_file() {
  local q
  if cx_pb_pass_file "$CX_PASSPHRASE_FILE"; then return 0; fi
  case $CX_PB_PF_WHY in
    read) cx_line FAIL "$(cx_msg pb_pf_read "$CX_PB_PF_PATH")" ;;
    line) cx_line FAIL "$(cx_msg pb_pf_line "$CX_PB_PF_PATH")" ;;
    *)
      cx_line FAIL "$(cx_msg pb_pf_perm "$CX_PB_PF_PATH" "$CX_PB_PF_MODE")"
      q=$(printf '%q' "$CX_PB_PF_PATH")
      cx_cmd "sudo chown root $q"
      cx_cmd "sudo chmod 600 $q"
      [ "$CX_PB_PF_ACL" != 1 ] || cx_cmd "sudo setfacl -b $q" ;;
  esac
  return 1
}

# The helper sees only a private output directory and a pass number, never a secret.
cx_rs_reader() {
  cat >"$CX_RS_DIR/reader" <<'READER'
#!/bin/sh
umask 077
case $TAR_FILENAME in
  backup-manifest.json|release-MANIFEST.json|tool-MANIFEST.json|snapshot.txt|env.bak|state.json|SHA256SUMS) keep=1 ;;
  db.dump|audit.tar.gz|recordings.tar.gz|tls.tar.gz|nginx-tls.conf.template|db-ca.pem) keep=$CX_RS_PASS ;;
  *) cat >/dev/null; exit 0 ;;
esac
if [ "$keep" = 1 ]; then
  tee "$CX_RS_OUT/$TAR_FILENAME" | sha256sum | sed "s/  -$/  $TAR_FILENAME/"
else
  sha256sum | sed "s/  -$/  $TAR_FILENAME/"
fi
READER
  chmod 700 "$CX_RS_DIR/reader"
}
cx_rs_tar_stream() {
  dd bs=512 count=1 iflag=fullblock status=none of="$CX_RS_DIR/tar-head" || return 1
  cat "$CX_RS_DIR/tar-head"
  cat
}
cx_rs_pass() {
  local pass=$1 rc=0
  local -a ps=()
  (umask 077 && mkdir -p "$CX_RS_DIR/pass$pass") || return 1
  export CX_RS_OUT=$CX_RS_DIR/pass$pass CX_RS_PASS=$((pass - 1))
  if [ "$CX_RS_ENC" = 1 ]; then
    cx_rs_decrypt 2>"$CX_RS_DIR/decrypt.err" | cx_rs_tar_stream |
      tar -x -vv -B -C "$CX_RS_DIR/pass$pass" --numeric-owner --full-time --index-file="$CX_RS_DIR/list$pass" \
        --to-command="\"$CX_RS_DIR/reader\"" -f - >"$CX_RS_DIR/sums$pass" 2>"$CX_RS_DIR/tar.err"
    ps=("${PIPESTATUS[@]}")
    CX_RS_DEC_RC=${ps[0]}
    [ "${ps[0]}" = 0 ] && [ "${ps[1]}" = 0 ] && [ "${ps[2]}" = 0 ] || rc=1
  else
    tar -x -vv -C "$CX_RS_DIR/pass$pass" --numeric-owner --full-time --index-file="$CX_RS_DIR/list$pass" \
      --to-command="\"$CX_RS_DIR/reader\"" -f "$CX_RS_FILE" >"$CX_RS_DIR/sums$pass" 2>"$CX_RS_DIR/tar.err" || rc=1
  fi
  unset CX_RS_OUT CX_RS_PASS
  return "$rc"
}
cx_rs_decrypt_broken() {
  if [ "$CX_RS_DEC_RC" -ge 125 ]; then cx_rs_bad decrypt_tool; return 0; fi
  if [ "$(dd if="$CX_RS_DIR/tar-head" bs=1 skip=257 count=5 status=none)" = ustar ]; then
    cx_rs_bad decrypt; return 0
  fi
  return 1
}
cx_rs_first_pass() {
  local n pass="" size
  if [ "$CX_RS_ENC" = 0 ]; then cx_rs_pass 1 || { cx_rs_bad type; return 1; }; return 0; fi
  size=$(stat -c %s "$CX_RS_FILE")
  if [ "$size" -le 16 ] || [ $(((size - 16) % 16)) -ne 0 ]; then cx_rs_bad decrypt; return 1; fi
  cx_rs_openssl_image || return 1
  if [ -n "${CX_PASSPHRASE_FILE:-}" ]; then
    cx_rs_pass_file || return 1
    cx_rs_pass 1 && return 0
    cx_rs_decrypt_broken && return 1
    cx_line FAIL "$(cx_msg "rs_decrypt_$CX_RS_CHECKSUM" 0)"
    return 1
  fi
  [ -t 0 ] || { cx_line FAIL "$(cx_msg rs_pass_needed)"; return 1; }
  printf '%s\n' "$(cx_msg rs_pass_intro)"
  for n in 1 2 3; do
    printf '%s' "$(cx_msg rs_pass_prompt)"
    IFS= read -r -s pass || return 1
    printf '\n'
    cx_pb_pass_set "$pass"
    cx_rs_pass 1 && return 0
    cx_rs_decrypt_broken && return 1
    [ "$n" = 3 ] || cx_line FAIL "$(cx_msg "rs_decrypt_$CX_RS_CHECKSUM" "$((3 - n))")"
  done
  cx_line FAIL "$(cx_msg rs_decrypt_cancel)"
  return 1
}
cx_rs_member_check() {
  local line mode owner size day time name rest m
  local -A seen=()
  CX_RS_BYTES=0
  awk '$6 == "backup-manifest.json" {found=1} END {exit !found}' "$CX_RS_DIR/list1" || { cx_rs_old_file; return 1; }
  while read -r mode owner size day time name rest; do
    [ -n "$name" ] || { cx_rs_bad type; return 1; }
    [ -z "${seen[$name]+x}" ] || { cx_rs_bad members; return 1; }
    [ "${mode:0:1}" = - ] && [ -z "$rest" ] && [[ $name != */* && $name != *..* ]] || { cx_rs_bad type; return 1; }
    cx_pb_in "$name" "$CX_RS_MEMBERS" && [ -z "${seen[$name]+x}" ] || { cx_rs_bad members; return 1; }
    seen[$name]=1
    [[ $size =~ ^[0-9]+$ ]] || { cx_rs_bad type; return 1; }
    CX_RS_BYTES=$((CX_RS_BYTES + size))
  done <"$CX_RS_DIR/list1"
  [ -n "${seen[backup-manifest.json]+x}" ] || { cx_rs_old_file; return 1; }
  for m in $CX_RS_REQUIRED; do [ -n "${seen[$m]+x}" ] || { cx_rs_bad members; return 1; }; done
  cx_flat_parse "$CX_RS_DIR/pass1/backup-manifest.json" CX_RS_MAP CX_RS_KEYS && cx_pb_manifest_check CX_RS_MAP || {
    cx_rs_bad manifest "${CX_PB_BAD_KEY:-backup-manifest.json}"; return 1;
  }
  CX_RS_VERSION=$(cx_rs_get product.version)
  local actual expected
  actual=$(printf '%s\n' "${!seen[@]}" | LC_ALL=C sort)
  expected=$(printf '%s\n' "${CX_RS_MAP[contents.members]}" | tr ' ' '\n' | LC_ALL=C sort)
  [ "$actual" = "$expected" ] || { cx_rs_bad members; return 1; }
  [ "$(cx_rs_get encryption.enabled)" = "$([ "$CX_RS_ENC" = 1 ] && echo true || echo false)" ] || { cx_rs_bad name; return 1; }
  seen=()
  while IFS= read -r line; do
    if ! [[ $line =~ ^([0-9a-f]{64})\ \ ([a-zA-Z0-9.-]+)$ ]]; then cx_rs_bad sums; return 1; fi
    m=${BASH_REMATCH[2]}
    [ "$m" != SHA256SUMS ] && cx_pb_in "$m" "$CX_RS_MEMBERS" && [ -z "${seen[$m]+x}" ] || { cx_rs_bad sums; return 1; }
    seen[$m]=1
    grep -qxF -- "$line" "$CX_RS_DIR/sums1" || { cx_rs_bad hash "$m"; return 1; }
  done <"$CX_RS_DIR/pass1/SHA256SUMS"
  [ "$(printf '%s\n' "${!seen[@]}" SHA256SUMS | LC_ALL=C sort)" = "$actual" ] || { cx_rs_bad sums; return 1; }
}
cx_rs_cross() {
  local d=$CX_RS_DIR/pass1 mf version key digest migs n
  for mf in release tool; do
    key=product version=product.version
    [ "$mf" != tool ] || { key=tool; version=product.script_version; }
    [ "$(cx_pb_sha "$d/$mf-MANIFEST.json")" = "$(cx_rs_get "$key.manifest_sha256")" ] || { cx_rs_bad release; return 1; }
    cx_manifest_load "$d/$mf-MANIFEST.json" >/dev/null && [ "$(cx_mf version)" = "$(cx_rs_get "$version")" ] || { cx_rs_bad release; return 1; }
    if [ "$mf" = "$(cx_rs_get tool.dump_manifest)" ]; then
      digest=$(cx_mf "images.$(cx_rs_get tool.dump_image).index_digest")
      [ "$digest" = "$(cx_rs_get tool.dump_image_digest)" ] || { cx_rs_bad release; return 1; }
    fi
  done
  migs=$(cx_snap_migrations "$d/snapshot.txt" | LC_ALL=C sort)
  n=$(printf '%s\n' "$migs" | grep -c .) || true
  digest=$(printf '%s\n' "$migs" | sha256sum)
  [ "$n" = "$(cx_rs_get db.migrations_count)" ] && [ "${digest%% *}" = "$(cx_rs_get db.migrations_sha256)" ] || { cx_rs_bad migrations; return 1; }
  [ "$(cx_snap_get "$d/snapshot.txt" fp.kek)" = "$(cx_rs_get kek.fingerprint)" ] || { cx_rs_bad fingerprint; return 1; }
  if [ "$(cx_rs_get trigger)" = upgrade ]; then
    local -A old=()
    local -a keys=()
    cx_flat_parse "$d/state.json" old keys && [ "${old[current.version]:-}" = "$CX_RS_VERSION" ] || { cx_rs_bad state; return 1; }
  fi
}
# Metadata is kept by the first pass even when verification does not extract the payload.
cx_rs_metadata() {
  if [ "$CX_RS_VERIFY_ONLY" = 1 ]; then printf '%s/pass1' "$CX_RS_DIR"
  else printf '%s/pass2' "$CX_RS_DIR"; fi
}
# Stream a validated member. pipefail propagates decryption, archive and consumer failures.
cx_rs_member_stream() (
  set -o pipefail
  if [ "$CX_RS_VERIFY_ONLY" != 1 ]; then cat -- "$CX_RS_DIR/pass2/$1"
  elif [ "$CX_RS_ENC" = 1 ]; then cx_rs_decrypt | tar -xO -B -f - -- "$1"
  else tar -xO -f "$CX_RS_FILE" -- "$1"; fi
)
cx_rs_inner() {
  local f mode owner size day time name rest
  for f in audit recordings tls; do
    cx_pb_in "$f.tar.gz" "$(cx_rs_get contents.members)" || continue
    (set -o pipefail; cx_rs_member_stream "$f.tar.gz" |
      tar -tzvv --numeric-owner --full-time -Pf -) >"$CX_RS_DIR/inner-list" 2>/dev/null || { cx_rs_bad inner; return 1; }
    while read -r mode owner size day time name rest; do
      [[ ${mode:0:1} == - || ${mode:0:1} == d ]] && [[ $name == "$f/"* ]] &&
        [[ /$name/ != */../* && $name != /* ]] && [ -z "$rest" ] || { cx_rs_bad inner; return 1; }
    done <"$CX_RS_DIR/inner-list"
  done
}
# pg_restore may finish after reading only the table of contents. Drain the rest of its
# input before waiting on the archive stream, without treating a legitimate early exit as SIGPIPE.
cx_rs_grant_tool() {
  local rc=0
  docker run --rm -i --pull never --network none --name "custodexa-restore-tool-$CX_RS_TS-grants" \
    -v "$CX_RS_DIR:/w:ro" --entrypoint pg_restore "$@" || rc=$?
  cat >/dev/null || return 1
  return "$rc"
}
cx_rs_grants() {
  local id roles CX_IMG_ARCH
  cx_manifest_load "$(cx_rs_metadata)/release-MANIFEST.json" >/dev/null || { cx_rs_bad release; return 1; }
  # The data release's database image as install accepts it on this host: an offline bundle
  # loaded on the containerd store leaves it under an ID that no digest of the manifest names.
  CX_IMG_ARCH=$(cx_arch) || { cx_rs_bad grants_read; return 1; }
  if ! id=$(cx_img_held_id "$(cx_rs_get tool.dump_image)"); then
    cx_line FAIL "$(cx_msg rs_no_dbtool "$(cx_mf version)")"
    cx_rs_unchanged
    return 1
  fi
  (set -o pipefail; cx_rs_member_stream db.dump |
    cx_rs_grant_tool "$id" -l) \
    >"$CX_RS_DIR/toc" 2>"$CX_RS_DIR/pg.err" || { cx_rs_bad grants_read; return 1; }
  sed -n '/ ACL /p' "$CX_RS_DIR/toc" >"$CX_RS_DIR/acl"
  [ -s "$CX_RS_DIR/acl" ] || return 0
  (set -o pipefail; cx_rs_member_stream db.dump |
    cx_rs_grant_tool "$id" -L /w/acl -f -) >"$CX_RS_DIR/grants" 2>"$CX_RS_DIR/pg.err" || { cx_rs_bad grants_read; return 1; }
  roles=$(sed -n 's/^GRANT .* TO \(.*\);$/\1/p' "$CX_RS_DIR/grants" | sed 's/ WITH GRANT OPTION$//' | tr ',' '\n' |
    sed 's/^ *//; s/ *$//; s/^"//; s/"$//' | LC_ALL=C sort -u)
  local role bad=""
  while IFS= read -r role; do
    case $role in ""|PUBLIC|pg_*) continue ;; esac
    [ "$role" = "$(cx_rs_get db.user)" ] || bad+="${bad:+, }$role"
  done <<<"$roles"
  [ -z "$bad" ] || { cx_rs_bad grants "$bad"; return 1; }
}
cx_rs_open() {
  local t0 at partkey=rs_parts
  CX_RS_VERIFY_ONLY=0
  if [ "${1:-}" = --verify-only ]; then CX_RS_VERIFY_ONLY=1; shift; fi
  if [ "${2:-}" = --verify-only ]; then CX_RS_VERIFY_ONLY=1; fi
  CX_RS_FILE=$1
  [[ $CX_RS_FILE == /* ]] || CX_RS_FILE=$PWD/$CX_RS_FILE
  [ ! -d "$CX_RS_FILE" ] || { cx_rs_old_file; return 1; }
  [ -f "$CX_RS_FILE" ] && [ -r "$CX_RS_FILE" ] || { cx_rs_bad read; return 1; }
  printf '%s\n' "$(cx_msg rs_reading "$CX_RS_FILE")"
  cx_rs_sidecar || return 1
  CX_RS_ENC=0
  if [ "$(head -c 8 "$CX_RS_FILE")" = Salted__ ]; then CX_RS_ENC=1; fi
  if { [[ $CX_RS_FILE == *.tar.enc ]] && [ "$CX_RS_ENC" != 1 ]; } ||
    { [[ $CX_RS_FILE != *.tar.enc ]] && [ "$CX_RS_ENC" = 1 ]; }; then cx_rs_bad name; return 1; fi
  cx_rs_reader || return 1
  t0=$(cx_now)
  cx_rs_first_pass && cx_rs_member_check && cx_rs_cross || return 1
  [ "$CX_RS_ENC" = 0 ] || partkey=rs_parts_enc
  cx_rs_read_timed parts "$(cx_msg "$partkey" "$(wc -l <"$CX_RS_DIR/list1")")" "$(cx_duration "$(($(cx_now) - t0))")"
  at=$(cx_rs_get created_at); at="${at:0:10} ${at:11:5}"
  cx_line OK "$(cx_msg rs_manifest "$CX_RS_VERSION" "$at")"
  cx_line OK "$(cx_msg rs_cross_ok)"
  t0=$(cx_now)
  if [ "$CX_RS_VERIFY_ONLY" != 1 ]; then
    cx_rs_pass 2 || { cx_rs_bad read; return 1; }
    cmp -s "$CX_RS_DIR/list1" "$CX_RS_DIR/list2" && cmp -s "$CX_RS_DIR/sums1" "$CX_RS_DIR/sums2" &&
      (cd "$CX_RS_DIR/pass2" && sha256sum -c SHA256SUMS >/dev/null 2>&1) || { cx_rs_bad sums; return 1; }
  fi
  cx_rs_inner || return 1
  CX_RS_EXTRACT_TIME=$(($(cx_now) - t0))
  cx_secrets_from_env "$(cx_rs_metadata)/env.bak"
}
