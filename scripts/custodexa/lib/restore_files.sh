# shellcheck shell=bash
# Expand checked archives only in the private work folder. Every destination write then uses
# the durable journal, so a partially placed tree is safe to carry on.
# shellcheck disable=SC2034
CX_RS_REC_PUT=0 CX_RS_TEMPLATE_UNCHANGED=0
cx_rs_place_tree() {
  local name=$1 parent=$2 keep=${3:-0} source path rel dest id mode
  source=$CX_RS_DIR/files-$name
  if [ ! -f "$source.ready" ]; then
    rm -rf -- "$source"
    (umask 077; mkdir "$source") && tar --same-permissions -xzf "$CX_RS_DIR/pass2/$name.tar.gz" -C "$source" || return 1
    sync -f "$source" && touch "$source.ready" && sync -f "$source.ready" || return 1
  fi
  while IFS= read -r -d '' path; do
    rel=${path#"$source/"} dest=$parent/${path#"$source/"}
    id=$(printf '%s' "$rel" | sha256sum); id=$name-${id%% *}
    cx_rs_journal_load || return 1
    if [ -d "$path" ]; then
      if ! cx_rs_exists "$dest" || [ -n "${CX_RS_J_IDS[$id]:-}" ]; then
        mode=$(stat -c %a "$path")
        cx_rs_journal "$id" mkdir "$dest" "0$mode" || return 1
      fi
    elif [ "$keep" = 1 ] && cx_rs_exists "$dest" && [ -z "${CX_RS_J_IDS[$id]:-}" ]; then
      continue
    else
      mode=$(stat -c %a "$path")
      cx_rs_journal_put "$id" "$path" "$dest" "0$mode" || return 1
      [ "$name" != recordings ] || CX_RS_REC_PUT=$((CX_RS_REC_PUT + 1))
    fi
  done < <(find "$source/$name" -print0 | LC_ALL=C sort -z)
}
cx_rs_recordings_permissions() {
  local dir=$CX_RS_DATA/recordings file id
  if ! cx_rs_exists "$dir"; then cx_rs_journal recordings-folder mkdir "$dir" 2770 || return 1; fi
  cx_rs_journal recordings-mode mode "$dir" 1000:0 2770 || return 1
  while IFS= read -r -d '' file; do
    id=$(printf '%s' "$file" | sha256sum)
    cx_rs_journal "recordings-mode-${id%% *}" mode "$file" "$(stat -c %u "$file"):0" "$(stat -c %a "$file")" || return 1
  done < <(find "$dir" -mindepth 1 -maxdepth 1 -type f -group 1000 -print0)
}
cx_rs_files_place() {
  local key ids="" sources="" release=$CX_ROOT/releases/$CX_RS_VERSION
  [ "$(cx_rs_phase_value)" = db_checked ] || return 1
  CX_OVERLAYS=$(cx_rs_get deploy.overlays)
  cx_rs_recovery_route resume || return 1
  # Stop even the temporary database before changing the files or current release.
  cx_rs_services all-stopped && cx_compose_release "$release" stop >/dev/null 2>&1 || return 1
  [ "$(cx_rs_actual_services)" = stopped ] || return 1
  cx_rs_place_tree audit "$CX_RS_DATA" || return 1
  if [ "$(cx_rs_get contents.tls)" = true ]; then
    cx_rs_place_tree tls "$CX_ROOT" || return 1
    if [ "$CX_RS_REISSUE" = 1 ]; then
      cx_rs_leaf_keep || return 1
      # tls-init preserves the restored CA and issues only the missing leaf.
      cx_rs_journal leaf-issue leaf "$release" "$CX_ROOT/tls" || return 1
    fi
  fi
  CX_RS_REC_PUT=0
  if [ "$(cx_rs_get contents.recordings)" = true ]; then
    cx_rs_place_tree recordings "$CX_RS_DATA" 1 && cx_rs_recordings_permissions || return 1
  elif [ "$CX_RS_FLOW" = new ]; then
    cx_rs_recordings_permissions || return 1
  fi
  cx_rs_template_place || return 1
  if [ -n "$CX_RS_TEMPLATE" ] && [ "$CX_RS_TEMPLATE_UNCHANGED" != 1 ]; then
    cx_rs_journal template-mode mode "$CX_RS_TEMPLATE" 0:0 0644 || return 1
  fi
  cx_rs_switch_release "$CX_RS_VERSION" || return 1
  for key in "${CX_IMG_NAMES[@]}"; do
    ids+="${ids:+ }$key=${CX_IMG_ID[$key]}"
    sources+="${sources:+ }$key=${CX_IMG_SRC[$key]:-local}"
  done
  cx_rs_current_set kind package && cx_rs_current_set version "$CX_RS_VERSION" &&
    cx_rs_current_set overlays "$CX_OVERLAYS" && cx_rs_current_set release_dir "releases/$CX_RS_VERSION" &&
    cx_rs_current_set images_env "releases/$CX_RS_VERSION/images.env" && cx_rs_current_set image_ids "$ids" &&
    cx_rs_current_set tool_image_ids "$(cx_tools_ids_text)" && cx_rs_current_set image_source "$sources" &&
    cx_rs_current_set verification "$(cx_trust_state)" &&
    cx_rs_current_set since "$(date '+%Y-%m-%dT%H:%M:%S%z')" && cx_rs_phase placed
}
