# shellcheck shell=bash
# The recordings after a restore. A backup without them leaves the recordings where they are: on
# the same host the folder is not touched; on a new host the restored database still lists every
# session that had a recording, while the files stay on the source host. For a new host the
# restore writes the recordings that have no file here into a list beside its other kept lists,
# so the operator knows what to copy over, and the finished screen says how many there are.
#
# Needs the database helpers (cx_db, cx_bk_vars: lib/backup.sh), which the restore loads with its
# reader. Defines functions only.

# Where the backend writes recordings, inside its container (RECORDING_PATH in docker-compose.yml);
# the same folder is DATA_PATH/recordings on the host. The database keeps each recording as this
# folder followed by the file's place inside it (sessions.recording_path).
CX_RS_REC_CTR=/var/lib/custodexa/recordings
CX_RS_REC_LIST_NAME='missing-recordings.txt'

# Set by cx_rs_recordings_missing.
CX_RS_REC_TOTAL=0    # recordings the database lists
CX_RS_REC_MISSING=0  # of those, without a file on this host
CX_RS_REC_OFFSITE=0  # 1 when offsite storage is in use (a current storage generation)
CX_RS_REC_FILE=""    # the list written

# The sessions with a recording, in the order they were made. Retention clears the path and the
# flag together when it removes a recording, so an empty path is a recording that is gone on
# purpose; keeping only a local copy's removal after an offsite upload leaves both as they were.
CX_RS_REC_SQL="SELECT recording_path FROM sessions WHERE has_recording AND recording_path <> '' ORDER BY id"
CX_RS_REC_OFFSITE_SQL="SELECT count(*) FROM offsite_profiles WHERE retired_at IS NULL"

# cx_rs_rec_relative <path in the database>: CX_RS_REC_REL, the path inside the recordings folder,
# or empty when the path is not one under that folder (it is then listed as it is in the database).
# A path that climbs out of the folder is never looked up on this host.
CX_RS_REC_REL=""
cx_rs_rec_relative() {
  local p=$1 rel
  CX_RS_REC_REL=""
  case $p in
    "$CX_RS_REC_CTR"/?*) rel=${p#"$CX_RS_REC_CTR"/} ;;
    *) return 0 ;;
  esac
  case /$rel/ in
    */../* | */./* | *//*) return 0 ;;
  esac
  CX_RS_REC_REL=$rel
}

# cx_rs_recordings_missing <folder for the list>: read the restored database, write
# <folder>/missing-recordings.txt with the recordings that have no file under DATA_PATH/recordings
# here (one per line, as a path inside the recordings folder), and set CX_RS_REC_*. The list is
# written even when it is empty. Fails, writing nothing, when the database cannot be read.
cx_rs_recordings_missing() {
  local dir=$1 rows offsite p rel tmp
  local -a missing=()
  cx_bk_vars
  rows=$(cx_db sql "$CX_RS_REC_SQL") || return 1
  offsite=$(cx_db sql "$CX_RS_REC_OFFSITE_SQL") || return 1
  [[ $offsite =~ ^[0-9]+$ ]] || return 1
  CX_RS_REC_TOTAL=0 CX_RS_REC_MISSING=0 CX_RS_REC_OFFSITE=0
  [ "$offsite" -eq 0 ] || CX_RS_REC_OFFSITE=1
  while IFS= read -r p; do
    [ -n "$p" ] || continue
    CX_RS_REC_TOTAL=$((CX_RS_REC_TOTAL + 1))
    # In this shell, not a subshell per row: a database can list a great many recordings.
    cx_rs_rec_relative "$p"
    rel=$CX_RS_REC_REL
    if [ -n "$rel" ] && [ -f "$CX_BK_DATA/recordings/$rel" ]; then continue; fi
    missing+=("${rel:-$p}")
  done <<<"$rows"
  CX_RS_REC_MISSING=${#missing[@]}
  CX_RS_REC_FILE=$dir/$CX_RS_REC_LIST_NAME
  tmp=$CX_RS_REC_FILE.tmp
  if ! { [ "$CX_RS_REC_MISSING" -eq 0 ] || printf '%s\n' "${missing[@]}"; } >"$tmp" ||
    ! mv -f -- "$tmp" "$CX_RS_REC_FILE"; then
    rm -f -- "$tmp"
    CX_RS_REC_FILE=""
    return 1
  fi
  cx_log REC "recordings total=$CX_RS_REC_TOTAL missing=$CX_RS_REC_MISSING offsite=$CX_RS_REC_OFFSITE list=$CX_RS_REC_FILE" 2>/dev/null || true
}

# cx_rs_rec_count <whole number>: with a comma between thousands (1,204), as on the screens.
cx_rs_rec_count() {
  local n=$1 out=""
  while [ "${#n}" -gt 3 ]; do
    out=,${n: -3}$out
    n=${n:0:${#n}-3}
  done
  printf '%s' "$n$out"
}

# cx_rs_rec_line <mark> <text>: a line of the finished screen, 2 columns in, later lines under the
# text.
cx_rs_rec_line() { printf '  %s %s\n' "$(cx_mark "$1")" "${2//$'\n'/$'\n'         }"; }

# cx_rs_rec_section <same | new> <true | false: the backup has the recordings> <source DATA_PATH>
# [files put back from the backup]: the recordings part of the finished screen. For a new host
# without recordings in the backup, cx_rs_recordings_missing has run first.
cx_rs_rec_section() {
  local flow=$1 with=$2 source=$3 put=${4:-0} text
  if [ "$with" = true ]; then
    cx_rs_rec_line OK "$(cx_msg rs_rec_put_back "$(cx_rs_rec_count "$put")")"
  elif [ "$flow" = same ]; then
    cx_rs_rec_line WARN "$(cx_msg rs_rec_same_kept)"
  elif [ "$CX_RS_REC_MISSING" -eq 0 ]; then
    cx_rs_rec_line OK "$(cx_msg rs_rec_all_here)"
  else
    text=$(cx_msg rs_rec_missing "$(cx_rs_rec_count "$CX_RS_REC_MISSING")" "$CX_RS_REC_FILE" "${source%/}/recordings/")
    [ "$CX_RS_REC_OFFSITE" = 0 ] || text+=$'\n'$(cx_msg rs_rec_offsite)
    cx_rs_rec_line WARN "$text"
  fi
}
