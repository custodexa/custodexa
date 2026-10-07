# shellcheck shell=bash
# CX_PB_* are read by lib/cmd_backup.sh, which sources this file after lib/backup.sh and
# lib/health.sh.
# shellcheck disable=SC2034
# The portable backup: one file, backups/custodexa-backup-<version>-<YYYYMMDD-HHMMSS>.tar, and its
# checksum file <name>.sha256 next to it. The members are built in backups/.partial-<ts>/ (0700,
# every member 0600 from the moment it exists), put together with tar, read back once and only
# then given their final names: the checksum file first, the backup file last. Linking the backup
# file into place is the commit point; before it there is no backup file under a final name.
#   7 steps: stop, db, files, conf, start (and wait until ready), verify, pack
# The commit state (CX_PB_COMMIT) is pre-commit until the backup file is in place, committed once
# it is, recorded once state.json points at it.
# Step 7 of upgrade makes the same file with the services already stopped (lib/backup.sh
# cx_bk_take upgrade: db files conf verify pack): CX_PB_TRIGGER=upgrade, the recordings always in,
# not encrypted, the snapshot taken before (kept outside the file as well) and state.json as the
# upgrade found it as one more member (CX_PB_STATE=1).
# shellcheck source=lib/dbext.sh
. "${BASH_SOURCE[0]%/*}/dbext.sh"
# shellcheck source=lib/backup_manifest.sh
. "${BASH_SOURCE[0]%/*}/backup_manifest.sh"
# shellcheck source=lib/backup_crypt.sh
. "${BASH_SOURCE[0]%/*}/backup_crypt.sh"

CX_PB_KEK="" CX_PB_KEK_DECLARED=false CX_PB_KEK_REFUSE="" CX_PB_KEK_SHOWN=""
CX_PB_VERSION="" CX_PB_MF_VERSION="" CX_PB_SCRIPT_VERSION="" CX_PB_TOOL_MF="" CX_PB_TOOL_VERSION=""
CX_PB_PG_DIGEST="" CX_PB_NAME="" CX_PB_FINAL="" CX_PB_COMMIT=pre-commit CX_PB_SVC=running
CX_PB_HEALTH="" CX_PB_CREATED_AT="" CX_PB_WITH_REC=0 CX_PB_SIZE=0 CX_PB_SUMS=""
CX_PB_FP="" CX_PB_FP_STATUS="" CX_PB_DB_VERSION="" CX_PB_DB_MAJOR="" CX_PB_DUMP_VERSION=""
CX_PB_DB_ENCODING="" CX_PB_DB_COLLATE="" CX_PB_DB_CTYPE="" CX_PB_FILE_EST=0
CX_PB_JOB="" # the step command running in the background now (cx_pb_job)
# CX_PB_TLS: tls/ goes into the file (cx_pb_parts). CX_PB_TPL: TLS_NGINX_TEMPLATE as .env has it,
# empty when not set; CX_PB_TPL_FILE: the file it names, which goes into the file.
CX_PB_TLS=1 CX_PB_TPL="" CX_PB_TPL_FILE=""
CX_PB_TRIGGER=manual CX_PB_STATE=0 CX_PB_MODE=""
readonly CX_PB_TPL_MEMBER=nginx-tls.conf.template
# The CA file an external database's server is checked against (PGSSLROOTCERT): public, kept so a
# restore can check the server the same way.
readonly CX_PB_CA_MEMBER=db-ca.pem

# cx_pb_parts: what the deployment has besides the data, read before anything stops: whether it
# has a tls/, and the proxy template .env points at. Fails when TLS_NGINX_TEMPLATE is set and
#   2  the path has a character the manifest cannot hold (it keeps the path for a restore)
#   1  the file it names is not a regular file that can be read (CX_PB_TPL_FILE names it)
cx_pb_parts() {
  CX_PB_TLS=0
  ! cx_bk_has_tls || CX_PB_TLS=1
  CX_PB_TPL=$(cx_bk_env TLS_NGINX_TEMPLATE)
  CX_PB_TPL_FILE=""
  cx_log CHECK "tls=$([ "$CX_PB_TLS" = 1 ] && echo present || echo absent) nginx_template=${CX_PB_TPL:-unset}"
  [ -n "$CX_PB_TPL" ] || return 0
  # The manifest stores source.tls_nginx_template by its value rules; a path it cannot hold would
  # only fail at the last step, after the services were stopped.
  cx_state_valid_value "$CX_PB_TPL" || return 2
  # Relative to the deployment folder, as compose resolves it.
  case $CX_PB_TPL in
    /*) CX_PB_TPL_FILE=$CX_PB_TPL ;;
    *) CX_PB_TPL_FILE=$CX_ROOT/${CX_PB_TPL#./} ;;
  esac
  [ -f "$CX_PB_TPL_FILE" ] && { : <"$CX_PB_TPL_FILE"; } 2>/dev/null
}

# cx_pb_trim <text>: without leading and trailing white space (what the backend trims).
cx_pb_trim() {
  local s=$1
  s=${s#"${s%%[![:space:]]*}"}
  s=${s%"${s##*[![:space:]]}"}
  printf '%s' "$s"
}

# cx_pb_space <0|1>: the space a backup without (0) or with (1) the recordings needs, from the
# sizes cx_bk_estimate read: the file (database, audit files, the recordings when they go in,
# tls/), the largest of those again (tar stores a member in the file while it is still in the
# temporary folder) and 1 GB spare. Sets CX_PB_FILE_EST (the file) and CX_BK_NEED.
cx_pb_space() {
  local file big=$CX_BK_SIZE_DB m
  local -a parts=("$CX_BK_SIZE_AUDIT" "$CX_BK_SIZE_TLS")
  file=$((CX_BK_SIZE_DB + CX_BK_SIZE_AUDIT + CX_BK_SIZE_TLS))
  if [ "$1" = 1 ]; then
    file=$((file + CX_BK_SIZE_REC))
    parts+=("$CX_BK_SIZE_REC")
  fi
  for m in "${parts[@]}"; do [ "$m" -le "$big" ] || big=$m; done
  CX_PB_FILE_EST=$file
  CX_BK_NEED=$((file + big + CX_BK_SLACK))
}

# cx_pb_minutes: the pause shown in the preview, whole minutes (at least 1): the data of the file
# taken at the assumed rate while the services are stopped.
cx_pb_minutes() {
  local m=$(((CX_PB_FILE_EST + CX_BK_RATE * 60 - 1) / (CX_BK_RATE * 60)))
  [ "$m" -ge 1 ] || m=1
  printf '%s' "$m"
}

# cx_pb_kek_mode: the master key mode the backend would use, by its rules: KEK_PROVIDER and
# ENCRYPTION_KEY trimmed, an empty provider with a key is the compatible env mode. Sets CX_PB_KEK,
# CX_PB_KEK_DECLARED, and CX_PB_KEK_REFUSE (material, none, env_empty, unknown) when the backend
# would refuse the setting; CX_PB_KEK_SHOWN is the provider as written, for the refusal.
cx_pb_kek_mode() {
  local p k
  p=$(cx_pb_trim "$(cx_bk_env KEK_PROVIDER)")
  k=$(cx_pb_trim "$(cx_bk_env ENCRYPTION_KEY)")
  CX_PB_KEK="" CX_PB_KEK_REFUSE="" CX_PB_KEK_SHOWN=$p CX_PB_KEK_DECLARED=true
  [ -n "$p" ] || CX_PB_KEK_DECLARED=false
  case $p in
    "") if [ -n "$k" ]; then CX_PB_KEK='env'; else CX_PB_KEK_REFUSE=none; fi ;;
    env) if [ -n "$k" ]; then CX_PB_KEK='env'; else CX_PB_KEK_REFUSE=env_empty; fi ;;
    ui | kms | hsm) if [ -z "$k" ]; then CX_PB_KEK=$p; else CX_PB_KEK_REFUSE=material; fi ;;
    *) CX_PB_KEK_REFUSE=unknown ;;
  esac
  cx_log CHECK "master key mode=${CX_PB_KEK:-refused} declared=$CX_PB_KEK_DECLARED${CX_PB_KEK_REFUSE:+ refused=$CX_PB_KEK_REFUSE}"
}

# cx_pb_script_version: the version of the release this script belongs to.
cx_pb_script_version() {
  if [ -f "$CX_DIR/VERSION" ]; then tr -d '[:space:]' <"$CX_DIR/VERSION"; else printf 'dev'; fi
}

# cx_pb_versions: the version the data belongs to and the release the script belongs to.
#   0 both known and consistent; 1 a manifest cannot be read (its FAIL line is printed);
#   2 state.json and current/MANIFEST.json disagree (CX_PB_VERSION, CX_PB_MF_VERSION);
#   3 the script's own manifest is for another version (CX_PB_TOOL_VERSION).
cx_pb_versions() {
  local rel=$CX_ROOT/current/MANIFEST.json
  CX_PB_VERSION=$(cx_state_get current.version)
  cx_manifest_load "$rel" || return 1
  CX_PB_MF_VERSION=$(cx_mf version)
  CX_PB_PG_DIGEST=$(cx_mf images.postgres.index_digest)
  [ "$CX_PB_VERSION" = "$CX_PB_MF_VERSION" ] || return 2
  if ! [[ $CX_PB_PG_DIGEST =~ ^sha256:[0-9a-f]{64}$ ]]; then
    cx_manifest_bad "$rel" "$(wc -l <"$rel")"
    return 1
  fi
  CX_PB_TOOL_MF=$CX_DIR/MANIFEST.json
  CX_PB_SCRIPT_VERSION=$(cx_pb_script_version)
  cx_manifest_load "$CX_PB_TOOL_MF" || return 1
  CX_PB_TOOL_VERSION=$(cx_mf version)
  [ "$CX_PB_TOOL_VERSION" = "$CX_PB_SCRIPT_VERSION" ] || return 3
}

# cx_pb_taken <ts>: a backup file, checksum file or temporary folder of that second exists.
cx_pb_taken() {
  local b=$CX_ROOT/backups f=custodexa-backup-$CX_PB_VERSION-$1.tar
  [ -e "$b/$f" ] || [ -e "$b/$f.sha256" ] || [ -e "$b/$f.enc" ] || [ -e "$b/$f.enc.sha256" ] \
    || [ -e "$b/.partial-$1" ]
}

# cx_pb_safety_options: fixed settings for the backup taken while a restore holds its lock.
cx_pb_safety_options() {
  CX_PB_WITH_REC=0 CX_PB_ENC=0 CX_PB_PASS="" CX_PB_TRIGGER=manual CX_PB_STATE=0
}

# cx_pb_open [portable|upgrade|restore-safety]: the timestamp (the next second, twice at most,
# when this one is taken) and the temporary folder. 2 = every second tried is taken;
# 1 = the folder cannot be created.
# A restore keeps last_backup intact, including an unfinished backup's partial pointer.
cx_pb_open() {
  local ts tries=0 t
  CX_PB_MODE=${1:-}
  [ "$CX_PB_MODE" != restore-safety ] || cx_pb_safety_options
  ts=$(date '+%Y%m%d-%H%M%S')
  while cx_pb_taken "$ts"; do
    tries=$((tries + 1))
    if [ "$tries" -gt 2 ]; then
      CX_BK_TS=$ts
      return 2
    fi
    t=$(date -d "${ts:0:4}-${ts:4:2}-${ts:6:2} ${ts:9:2}:${ts:11:2}:${ts:13:2}" +%s) || return 1
    ts=$(date -d "@$((t + 1))" '+%Y%m%d-%H%M%S') || return 1
  done
  CX_BK_TS=$ts
  CX_PB_NAME=custodexa-backup-$CX_PB_VERSION-$ts.tar
  # An encrypted file is named for it: a restore tells it by the name and its first bytes.
  [ "$CX_PB_ENC" != 1 ] || CX_PB_NAME+=.enc
  CX_PB_FINAL=$CX_ROOT/backups/$CX_PB_NAME
  CX_BK_DIR=$CX_ROOT/backups/.partial-$ts
  (umask 077 && mkdir -p "$CX_ROOT/backups" && mkdir "$CX_BK_DIR") || return 1
  chmod 0700 "$CX_ROOT/backups" "$CX_BK_DIR" || return 1
  # Where this run keeps its parts, for the next run when this one never finishes.
  if [ "$CX_PB_MODE" != restore-safety ]; then
    cx_state_set last_backup.partial "backups/.partial-$ts"
    cx_state_save "$CX_ROOT/state.json" || return 1
  fi
  cx_log BACKUP "partial=${CX_BK_DIR#"$CX_ROOT"/} file=backups/$CX_PB_NAME"
}

# ---------- the steps (each returns non-zero on failure and leaves what it wrote) ----------

# cx_pb_job <command...>: a step's long command, run in the background (umask 077) and waited for.
# A signal then reaches the handler at once, not after the command ends; the handler stops the
# command and what it started (cx_pb_stop_jobs). Returns the command's exit code.
cx_pb_job() {
  local rc=0
  (
    umask 077
    "$@" || exit "$?"
  ) <&0 &
  CX_PB_JOB=$!
  wait "$CX_PB_JOB" || rc=$?
  CX_PB_JOB=""
  return "$rc"
}

cx_pb_stop() {
  CX_PB_SVC=stopped # also when the stop fails part way: some may be stopped
  cx_pb_job cx_bk_stop || return 1
  CX_PB_CREATED_AT=$(date '+%Y-%m-%dT%H:%M:%S%z')
}

cx_pb_db() {
  cx_pb_job cx_bk_quiet "$CX_BK_DIR/db.dump" cx_db dump || return 1
  [ -s "$CX_BK_DIR/db.dump" ] || return 1
  # An upgrade took the snapshot before (step 7 of upgrade) and put it here already.
  if [ "$CX_PB_TRIGGER" != upgrade ]; then
    cx_snap_take "$CX_BK_DIR/snapshot.txt" "$(cx_bk_env JWT_SECRET)" || return 1
    cx_log SNAPSHOT "usable=$CX_SNAP_USABLE${CX_SNAP_REASONS:+ reasons=\"$CX_SNAP_REASONS\"}"
  fi
  [ -s "$CX_BK_DIR/snapshot.txt" ] || return 1
  cx_pb_fp_status "$CX_BK_DIR/snapshot.txt"
  cx_pb_db_facts
}

# cx_pb_db_facts: the server and dump tool versions and the database's encoding, for the manifest.
cx_pb_db_facts() {
  local v n row tool
  v=$(cx_db sql 'SHOW server_version' 2>/dev/null) || return 1
  n=$(cx_db sql 'SHOW server_version_num' 2>/dev/null) || return 1
  row=$(cx_db sql "SELECT pg_encoding_to_char(encoding), datcollate, datctype FROM pg_database WHERE datname = current_database()" 2>/dev/null) || return 1
  tool=$(cx_db dump-version 2>/dev/null) || return 1
  CX_PB_DB_VERSION=${v%%[[:space:]]*}
  [[ $n =~ ^[0-9]+$ ]] || return 1
  CX_PB_DB_MAJOR=$((n / 10000))
  [[ $tool =~ \(PostgreSQL\)\ ([0-9][0-9.]*) ]] || return 1
  CX_PB_DUMP_VERSION=${BASH_REMATCH[1]}
  IFS='|' read -r CX_PB_DB_ENCODING CX_PB_DB_COLLATE CX_PB_DB_CTYPE <<<"$row"
  cx_log CHECK "database server=$CX_PB_DB_VERSION dump=$CX_PB_DUMP_VERSION encoding=$CX_PB_DB_ENCODING"
}

cx_pb_files() {
  cx_pb_job cx_bk_quiet /dev/null tar -czf "$CX_BK_DIR/audit.tar.gz" -C "$CX_BK_DATA" audit || return 1
  [ "$CX_PB_WITH_REC" = 1 ] || return 0
  cx_pb_job cx_bk_quiet /dev/null tar -czf "$CX_BK_DIR/recordings.tar.gz" -C "$CX_BK_DATA" recordings
}

cx_pb_conf() {
  (umask 077 && cp -- "$CX_ROOT/.env" "$CX_BK_DIR/env.bak") || return 1
  chmod 0600 "$CX_BK_DIR/env.bak" || return 1
  if [ "$CX_PB_TLS" = 1 ]; then
    cx_pb_job cx_bk_quiet /dev/null tar -czf "$CX_BK_DIR/tls.tar.gz" -C "$CX_ROOT" tls || return 1
  fi
  if [ -n "$CX_PB_TPL" ]; then
    (umask 077 && cp -- "$CX_PB_TPL_FILE" "$CX_BK_DIR/$CX_PB_TPL_MEMBER") || return 1
    chmod 0600 "$CX_BK_DIR/$CX_PB_TPL_MEMBER" || return 1
  fi
  if cx_pb_has_ca; then
    (umask 077 && cp -- "$CX_DB_CA_HOST" "$CX_BK_DIR/$CX_PB_CA_MEMBER") || return 1
    chmod 0600 "$CX_BK_DIR/$CX_PB_CA_MEMBER" || return 1
  fi
  (umask 077 && cp -- "$CX_ROOT/current/MANIFEST.json" "$CX_BK_DIR/release-MANIFEST.json") || return 1
  (umask 077 && cp -- "$CX_PB_TOOL_MF" "$CX_BK_DIR/tool-MANIFEST.json")
}

# cx_pb_start: start the services and wait for the backend. A backend that is not ready in time
# leaves the step a warning (CX_PB_HEALTH=timeout); the data is taken, so the backup goes on.
cx_pb_start() {
  # Recorded here and not in the job: the job is a subshell, and its state would be lost.
  cx_new_started_mark || return 1
  cx_pb_job cx_bk_start || return 1
  CX_PB_SVC=started
  if cx_wait_backend_health; then
    CX_PB_HEALTH=ready
  else
    CX_PB_HEALTH=timeout
    CX_BK_STEP_MARK=WARN
    cx_log WARN "backend not ready within $(cx_ready_seconds)s"
  fi
}

cx_pb_verify() {
  local listing f
  listing=$(mktemp)
  cx_pb_job cx_bk_quiet "$listing" cx_db restore-list <"$CX_BK_DIR/db.dump" || { rm -f "$listing"; return 1; }
  grep -q . "$listing" || { rm -f "$listing"; return 1; }
  rm -f "$listing"
  for f in audit tls; do
    [ "$f$CX_PB_TLS" != tls0 ] || continue
    cx_pb_job cx_bk_quiet /dev/null tar -tzf "$CX_BK_DIR/$f.tar.gz" || return 1
  done
  [ "$CX_PB_WITH_REC" = 1 ] || return 0
  cx_pb_job cx_bk_quiet /dev/null tar -tzf "$CX_BK_DIR/recordings.tar.gz"
}

# cx_pb_has_ca: the backup carries the CA file of an external database (its trust anchor is a file).
cx_pb_has_ca() { cx_db_external && [ "$CX_DB_TLS_TRUST" = file ]; }

# cx_pb_members: the members in the order they are stored.
cx_pb_members() {
  printf '%s\n' backup-manifest.json release-MANIFEST.json tool-MANIFEST.json snapshot.txt db.dump \
    audit.tar.gz
  [ "$CX_PB_WITH_REC" != 1 ] || printf '%s\n' recordings.tar.gz
  printf '%s\n' env.bak
  [ "$CX_PB_TLS" != 1 ] || printf '%s\n' tls.tar.gz
  [ -z "$CX_PB_TPL" ] || printf '%s\n' "$CX_PB_TPL_MEMBER"
  ! cx_pb_has_ca || printf '%s\n' "$CX_PB_CA_MEMBER"
  [ "$CX_PB_STATE" != 1 ] || printf '%s\n' state.json
  printf '%s\n' SHA256SUMS
}

# cx_pb_pack: the manifest and SHA256SUMS, the file, the read-back, the checksum file, then the
# commit: the checksum file and the backup file linked into backups/ without replacing anything.
cx_pb_pack() {
  local d=$CX_BK_DIR members
  local -a list=()
  mapfile -t list < <(cx_pb_members)
  members=${list[*]}
  (umask 077 && cx_pb_manifest_write "$d/backup-manifest.json" "$members") || return 1
  cx_pb_manifest_ok "$d/backup-manifest.json" || { cx_log FAIL "manifest: $CX_PB_BAD_KEY"; return 1; }
  cx_pb_job cx_pb_sums "$d" "${list[@]:0:${#list[@]}-1}" || return 1
  CX_PB_SUMS=$(cat -- "$d/SHA256SUMS") || return 1
  if [ "$CX_PB_ENC" = 1 ]; then
    cx_pb_job cx_pb_encrypt "${list[@]}" || return 1
  else
    cx_pb_job cx_bk_quiet /dev/null tar --format=gnu -cf "$d/$CX_PB_NAME" --remove-files -C "$d" -- "${list[@]}" \
      || return 1
  fi
  cx_pb_job cx_pb_readback "$d/$CX_PB_NAME" "${list[@]}" || return 1
  ln -- "$d/$CX_PB_NAME.sha256" "$CX_PB_FINAL.sha256" || return 1
  if ! ln -- "$d/$CX_PB_NAME" "$CX_PB_FINAL"; then
    [ ! "$CX_PB_FINAL.sha256" -ef "$d/$CX_PB_NAME.sha256" ] || rm -f "$CX_PB_FINAL.sha256"
    return 1
  fi
  CX_PB_COMMIT=committed
  CX_PB_SIZE=$(cx_bk_du "$CX_PB_FINAL")
  cx_log BACKUP "committed file=backups/$CX_PB_NAME size=$CX_PB_SIZE"
}

# cx_pb_sums <folder> <members...>: SHA256SUMS of the members, written in that folder.
cx_pb_sums() {
  local d=$1
  shift
  cd -- "$d" && sha256sum -- "$@" >SHA256SUMS
}

# cx_pb_readback <file> <members...>: read the file once: every member's SHA-256 (tar runs the
# hash per member), the member list in order, and the SHA-256 of the whole file for the checksum
# file. An encrypted file is decrypted on the way (cx_pb_readback_enc); its checksum file is that
# of the encrypted bytes. Fails unless the members are exactly the list, each once, and match
# SHA256SUMS.
cx_pb_readback() {
  local f=$1 d=$CX_BK_DIR whole m h want="" got err rc=0 sub pipe
  shift
  local -a ps=()
  err=$d/.readback-err
  pipe=$d/.readback-pipe
  # shellcheck disable=SC2016
  local cmd='h=$(sha256sum) && printf "%s  %s\n" "${h%% *}" "$TAR_FILENAME"'
  [ -r "$f" ] || return 1
  (umask 077 && : >"$d/.readback-sums" && : >"$d/.readback-list" && : >"$d/.readback-whole") || return 1
  if [ "$CX_PB_ENC" = 1 ]; then
    cx_pb_readback_enc "$f" "$cmd" "$err" || rc=1
  else
    (umask 077 && mkfifo -m 0600 -- "$pipe") || return 1
    # The whole-file hash reads a copy of the stream through a named pipe (0600) beside the tar that
    # hashes each member. Both ends of the pipe are checked, and the hash is waited for.
    sha256sum <"$pipe" >"$d/.readback-whole" 2>>"$err" &
    sub=$!
    tee -- "$pipe" <"$f" 2>>"$err" \
      | tar -x -v --index-file="$d/.readback-list" --to-command="$cmd" -f - >"$d/.readback-sums" 2>>"$err"
    ps=("${PIPESTATUS[@]}")
    # When tee never opened the pipe, the hash still waits to open it: a writer that closes at once
    # lets it end.
    cx_pb_pipe_release "$pipe"
    wait "$sub" || rc=1
    rm -f -- "$pipe"
    [ "${ps[0]}" = 0 ] && [ "${ps[1]}" = 0 ] || rc=1
  fi
  [ -f "$err" ] && while IFS= read -r m; do cx_log OUT "$m"; done <"$err"
  got=$(cat "$d/.readback-list")
  [ "$got" = "$(printf '%s\n' "$@")" ] || { cx_log FAIL "read back: members differ"; rc=1; }
  for m in "$@"; do
    if [ "$m" = SHA256SUMS ]; then
      h=$(printf '%s\n' "$CX_PB_SUMS" | sha256sum) || rc=1
      want+="${h%% *}  SHA256SUMS"$'\n'
    else
      h=$(printf '%s\n' "$CX_PB_SUMS" | awk -v m="$m" '$2 == m { print $1 }')
      want+="$h  $m"$'\n'
    fi
  done
  [ "$(cat "$d/.readback-sums")" = "${want%$'\n'}" ] || { cx_log FAIL "read back: checksums differ"; rc=1; }
  whole=$(cat "$d/.readback-whole")
  whole=${whole%% *}
  [[ $whole =~ ^[0-9a-f]{64}$ ]] || rc=1
  rm -f "$err" "$d/.readback-sums" "$d/.readback-list" "$d/.readback-whole"
  [ "$rc" = 0 ] || return 1
  (umask 077 && printf '%s  %s\n' "$whole" "$CX_PB_NAME" >"$d/$CX_PB_NAME.sha256")
}

# ---------- after the commit ----------

# cx_pb_record: state.json points at the new file (the other kinds of record are dropped) and the
# run is recorded as succeeded, in one write. On failure the record in memory is the one on disk.
cx_pb_record() {
  cx_pb_record_file
  # A finished backup closes what an earlier interrupted one left open (lib/run.sh).
  cx_state_unset last_backup.unfinished_at
  cx_state_unset last_backup.unfinished_partial
  cx_state_set last_backup.result succeeded
  cx_state_set last_backup.finished_at "$(date '+%Y-%m-%dT%H:%M:%S%z')"
  if ! cx_state_save "$CX_ROOT/state.json"; then
    cx_log FAIL "state.json not written after the commit"
    cx_state_load "$CX_ROOT/state.json"
    return 1
  fi
  CX_PB_COMMIT=recorded
}

# cx_pb_record_file: the last_backup.* keys that point at the new file (the other kinds of
# record dropped), in memory. The upgrade records its backup with these alone: the run that made
# it is the upgrade (last_upgrade.*), not a backup run.
cx_pb_record_file() {
  cx_state_set last_backup.id "$CX_BK_TS"
  cx_state_set last_backup.kind script
  cx_state_set last_backup.taken_at "$CX_PB_CREATED_AT"
  cx_state_set last_backup.file "backups/$CX_PB_NAME"
  cx_state_set last_backup.encrypted "$([ "$CX_PB_ENC" = 1 ] && echo true || echo false)"
  cx_state_set last_backup.size_bytes "$CX_PB_SIZE"
  cx_state_set last_backup.snapshot_usable "$CX_SNAP_USABLE"
  cx_state_unset last_backup.dir
  cx_state_unset last_backup.external_ref
  cx_state_unset last_backup.partial
}

# cx_pb_cleanup: remove the temporary folder (the links to the committed files and the folder).
cx_pb_cleanup() {
  rm -f -- "$CX_BK_DIR/$CX_PB_NAME" "$CX_BK_DIR/$CX_PB_NAME.sha256" || return 1
  rmdir -- "$CX_BK_DIR"
}

# cx_pb_commit_state: where the run stands, from what is on disk (a signal may arrive between a
# link or a write and the line after it): pre-commit, committed or recorded.
cx_pb_commit_state() {
  if [ -z "$CX_PB_NAME" ] || [ ! -f "$CX_PB_FINAL" ]; then
    printf 'pre-commit'
  elif [ "$CX_PB_COMMIT" = pre-commit ] && [ ! "$CX_PB_FINAL" -ef "$CX_BK_DIR/$CX_PB_NAME" ]; then
    printf 'pre-commit'
  elif grep -qF "\"last_backup.file\": \"backups/$CX_PB_NAME\"" "$CX_ROOT/state.json" 2>/dev/null; then
    printf 'recorded'
  else
    printf 'committed'
  fi
}

# ---------- when the run is interrupted ----------

# cx_pb_children <pid>: its child processes, one per line.
cx_pb_children() {
  local f line want=$1
  if command -v pgrep >/dev/null 2>&1; then
    pgrep -P "$want" || true
    return 0
  fi
  for f in /proc/[0-9]*/stat; do
    { read -r line <"$f"; } 2>/dev/null || continue
    # pid (name) state ppid ...: the name may hold spaces, so read after its closing parenthesis.
    line=${line##*) }
    line=${line#* }
    [ "${line%% *}" != "$want" ] || { f=${f#/proc/}; printf '%s\n' "${f%/stat}"; }
  done
}

# cx_pb_tree <pid>: the process and every process under it, parents first.
cx_pb_tree() {
  local c
  printf '%s\n' "$1"
  for c in $(cx_pb_children "$1"); do cx_pb_tree "$c"; done
}

# cx_pb_stop_jobs: stop the step command running now and everything it started (TERM, then KILL
# for what is still there after 5 seconds), and wait for it.
cx_pb_stop_jobs() {
  local p i left
  local -a ps=()
  [ -n "$CX_PB_JOB" ] || return 0
  mapfile -t ps < <(cx_pb_tree "$CX_PB_JOB")
  kill -TERM "${ps[@]}" 2>/dev/null || true
  wait "$CX_PB_JOB" 2>/dev/null || true
  for i in $(seq 1 50); do
    left=""
    for p in "${ps[@]}"; do ! kill -0 "$p" 2>/dev/null || left+=" $p"; done
    [ -n "$left" ] || break
    # shellcheck disable=SC2086 # one process ID per word
    [ "$i" -lt 50 ] || { kill -KILL $left 2>/dev/null || true; break; }
    sleep 0.1
  done
  cx_log STOP "processes ${ps[*]}"
  CX_PB_JOB=""
}

# cx_pb_tools_rm: remove this run's tool containers (named custodexa-backup-tool-<ts>-<role>),
# also one whose docker client was stopped before it could remove it.
cx_pb_tools_rm() {
  local pre=custodexa-backup-tool-$CX_BK_TS- n
  local -a names=()
  [ -n "$CX_BK_TS" ] || return 0
  while IFS= read -r n; do
    [[ $n != "$pre"* ]] || names+=("$n")
  done < <(docker ps -a --filter "name=$pre" --format '{{.Names}}' 2>/dev/null || true)
  [ "${#names[@]}" -gt 0 ] || return 0
  docker rm -f "${names[@]}" >/dev/null 2>&1 || true
  cx_log STOP "containers ${names[*]}"
}

# cx_pb_pipes_rm: remove the named pipes this run made in its temporary folder.
cx_pb_pipes_rm() {
  [ -n "$CX_BK_DIR" ] && [ -d "$CX_BK_DIR" ] || return 0
  find "$CX_BK_DIR" -maxdepth 1 -type p -delete 2>/dev/null || true
}

# The backup and restore signal handlers share the same cleanup, before printing their own
# recovery instructions. This never changes the backup record or restarts services.
cx_pb_interrupt_cleanup() {
  cx_pb_stop_jobs
  cx_pb_tools_rm
  cx_pb_pipes_rm
  cx_db_pgpass_rm
}
