# shellcheck shell=bash
# The reader and host-value merge supply CX_RS_*; estimates are grouped by file system.
# shellcheck disable=SC2034,SC2153
declare -ga CX_RS_SPACE_MOUNTS=()
declare -gA CX_RS_SPACE_NEED=() CX_RS_SPACE_FREE=() CX_RS_SPACE_KIND=()
CX_RS_SAFETY_BYTES=0 CX_RS_SAFETY_MIN=0 CX_RS_IMPORT_MIN=0 CX_RS_IMAGES_MISSING=0
cx_rs_space_add() {
  local path=$1 bytes=$2 kind=$3 mount free
  mount=$(cx_mount_of "$path") free=$(cx_free_bytes "$path")
  [[ -n "$mount" && $free =~ ^[0-9]+$ ]] || { cx_rs_refuse rs_space_unknown "$path"; return 1; }
  if [ -z "${CX_RS_SPACE_NEED[$mount]+x}" ]; then
    CX_RS_SPACE_MOUNTS+=("$mount")
    CX_RS_SPACE_NEED[$mount]=0 CX_RS_SPACE_FREE[$mount]=$free CX_RS_SPACE_KIND[$mount]=""
  fi
  CX_RS_SPACE_NEED[$mount]=$((${CX_RS_SPACE_NEED[$mount]} + bytes))
  [ "$free" -ge "${CX_RS_SPACE_FREE[$mount]}" ] || CX_RS_SPACE_FREE[$mount]=$free
  if [ -n "${CX_RS_SPACE_KIND[$mount]}" ]; then
    CX_RS_SPACE_KIND[$mount]=$(cx_msg rs_space_join "${CX_RS_SPACE_KIND[$mount]}" "$(cx_msg "$kind")")
  else CX_RS_SPACE_KIND[$mount]=$(cx_msg "$kind"); fi
}
cx_rs_space_lines() {
  local m key
  for m in "${CX_RS_SPACE_MOUNTS[@]}"; do
    key=rs_space_row
    [ "${CX_RS_SPACE_NEED[$m]}" -le "${CX_RS_SPACE_FREE[$m]}" ] || key=rs_space_short_row
    cx_rs_par "$(cx_msg "$key" "$m" "${CX_RS_SPACE_KIND[$m]}" \
      "$(cx_gb_up "${CX_RS_SPACE_NEED[$m]}")" "$(cx_gb_down "${CX_RS_SPACE_FREE[$m]}")")"
  done
}
cx_rs_space() {
  local need db dump n got want idx docker_dir image_bytes=0 missing=0 failed=0
  CX_RS_SPACE_MOUNTS=() CX_RS_SPACE_NEED=() CX_RS_SPACE_FREE=() CX_RS_SPACE_KIND=()
  CX_RS_SAFETY_BYTES=0 CX_RS_SAFETY_MIN=0
  cx_rs_space_add "$CX_ROOT" "$(((CX_RS_BYTES * 11 + 9) / 10))" rs_space_work || return 1
  if [ "$CX_RS_FLOW" = same ] && [ -z "${CX_BACKUP_REF:-}" ]; then
    cx_bk_vars
    # The deployment's own form decides where the database is asked (an external one through the
    # client the external database checks chose).
    CX_OVERLAYS=$(cx_state_get current.overlays)
    cx_bk_estimate || { cx_rs_refuse rs_space_estimate; return 1; }
    cx_pb_space 0
    CX_RS_SAFETY_BYTES=$CX_BK_NEED CX_RS_SAFETY_MIN=$(cx_bk_minutes)
    cx_rs_space_add "$CX_ROOT/backups" "$CX_RS_SAFETY_BYTES" rs_space_safety || return 1
  fi
  db=$((($(cx_rs_get size.db_bytes) * 12 + 9) / 10))
  need=$(($(cx_rs_get size.audit_bytes) + CX_GIB))
  if cx_rs_ext; then
    # An external database's import is SQL text under restore/<ts> in the deployment root, and on
    # a new host a database that holds data is exported there first (its size as the server tells it,
    # else the backup's).
    if [ "$CX_RS_FLOW" = new ] && [ "${CX_RS_EXT_EMPTY:-}" = 0 ]; then
      dump=$(cx_dbx_rows "SELECT pg_database_size(current_database())" 2>/dev/null) || dump=""
      [[ $dump =~ ^[0-9]+$ ]] || dump=$(cx_rs_get size.db_bytes)
      db=$((db + dump))
    fi
    cx_rs_space_add "$CX_ROOT" "$db" rs_space_work || return 1
  else
    need=$((need + db))
  fi
  [ "$(cx_rs_get contents.recordings)" != true ] || need=$((need + $(cx_rs_get size.recordings_bytes)))
  cx_rs_space_add "$CX_RS_DATA" "$need" rs_space_data || return 1
  CX_RS_IMPORT_MIN=$((($(cx_rs_get size.db_bytes) + CX_BK_RATE * 60 - 1) / (CX_BK_RATE * 60)))
  [ "$CX_RS_IMPORT_MIN" -ge 1 ] || CX_RS_IMPORT_MIN=1
  cx_manifest_load "$CX_RS_DIR/pass2/release-MANIFEST.json" || return 1
  CX_IMG_ARCH=$(cx_arch) || return 1
  cx_img_needed "$(cx_rs_get deploy.overlays)"
  for n in "${CX_IMG_NAMES[@]}"; do
    idx=$(cx_mf "images.$n.index_digest") want=$(cx_mf "images.$n.platforms.$CX_IMG_ARCH.config_digest")
    got=$(cx_img_id "$(cx_mf "images.$n.ref")@$idx") || got=""
    if [ -z "$got" ] || { [ "$got" != "$want" ] && [ "$got" != "$idx" ]; }; then
      missing=1
      image_bytes=$((image_bytes + ${CX_MF[images.$n.platforms.$CX_IMG_ARCH.size]:-0} * 3))
    fi
  done
  if [ "$missing" = 1 ]; then
    docker_dir=$(docker info --format '{{.DockerRootDir}}' 2>/dev/null) || docker_dir=""
    docker_dir=${docker_dir:-/var/lib/docker}
    cx_rs_space_add "$docker_dir" "$((image_bytes + CX_DOCKER_FREE_EXTRA))" rs_space_images || return 1
  fi
  CX_RS_IMAGES_MISSING=$missing
  for n in "${CX_RS_SPACE_MOUNTS[@]}"; do
    [ "${CX_RS_SPACE_NEED[$n]}" -le "${CX_RS_SPACE_FREE[$n]}" ] || failed=1
  done
  if [ "$failed" = 1 ]; then
    cx_line FAIL "$(cx_msg rs_space_bad)"
    cx_rs_space_lines
    cx_rs_par "$(cx_msg rs_space_margin)"
    cx_rs_unchanged
    return 1
  fi
}
