# shellcheck shell=bash
# CX_IR_* are read by the closing screen of upgrade and by the tests.
# shellcheck disable=SC2034
# Old images after an upgrade. Once the upgrade is recorded as succeeded, the product's own images
# (backend, frontend) that no longer serve the version now running or the one before it are
# removed; every other image is left alone.
#   candidates  images with a reference in the repositories of the own images: the release
#               manifest's references and mirrors, local builds (custodexa-local/<name>) and the
#               names of the earlier source-tree deployments (custodexa/<name>). Upstream images
#               (database, gateway, certificate and proxy tools, database clients) are never listed.
#   kept        by image ID: current.*, previous.*, load.*, last_rollback.{from,to}.* (service and
#               tool images), the images of this run, the upstream images of the release manifest,
#               and the image of every container, stopped ones included.
#   removed     one reference at a time, never forced: the image goes with its last reference. An
#               image that still has a reference of another repository afterwards (one the operator
#               made) stays and is not a failure. A reference that cannot be removed is reported
#               with the command to remove it by hand; the upgrade result does not change.
# Image IDs only, never tags or digests: an image pulled by digest has no tag, and an image loaded
# from a bundle on the containerd store has an ID no digest of the manifest names. The listing takes
# hidden images as well (-a): the classic store does not list an image without a tag otherwise.

CX_IR_SKIPPED=0  # --keep-images was given
CX_IR_REMOVED=0  # images removed
CX_IR_FREED=""   # bytes freed on the Docker data folder's file system; "" when not known
declare -ga CX_IR_FAILED=() # references that could not be removed

readonly CX_IR_STATE_KEYS="current.image_ids current.tool_image_ids previous.image_ids
  previous.tool_image_ids load.image_ids last_rollback.from.image_ids last_rollback.from.tool_image_ids
  last_rollback.to.image_ids last_rollback.to.tool_image_ids"

# cx_ir_repo <reference>: its repository in the short form docker prints (no tag, no digest).
cx_ir_repo() {
  local r=$1
  if [[ $r == *@* ]]; then
    r=${r%%@*}
  elif [[ ${r##*/} == *:* ]]; then
    r=${r%:*}
  fi
  cx_img_familiar "$r"
}

# cx_ir_repos: the repositories of the own images, one per word, padded with spaces.
cx_ir_repos() {
  local n r out=" "
  for n in backend frontend; do
    for r in $(cx_mf "images.$n.ref") $(cx_mf "images.$n.mirror") "$CX_LOCAL_PREFIX/$n" "custodexa/$n"; do
      out+="$(cx_img_familiar "$r") "
    done
  done
  printf '%s' "$out"
}

# cx_ir_keep_ids: the IDs recorded in state.json, of this run and of the upstream images.
cx_ir_keep_ids() {
  local k kv n
  for k in $CX_IR_STATE_KEYS; do
    for kv in $(cx_state_get "$k"); do printf '%s ' "${kv#*=}"; done
  done
  for n in "${!CX_IMG_ID[@]}"; do printf '%s ' "${CX_IMG_ID[$n]}"; done
  if [ -n "${CX_IMG_ARCH:-}" ]; then
    for n in "${CX_MF_IMAGES[@]}"; do
      ! cx_img_upstream "$n" || printf '%s ' "$(cx_img_registry_id "$n")"
    done
  fi
}

# cx_ir_container_ids: the image of every container on this host, stopped ones included. Returns
# 1 when the containers cannot be listed. A container gone between the listing and its inspection
# (a --rm container, for one) uses no image any more and is skipped.
cx_ir_container_ids() {
  local c cs
  cs=$(docker ps -aq --no-trunc 2>/dev/null) || return 1
  for c in $cs; do
    docker inspect --format '{{.Image}}' "$c" 2>/dev/null | tr '\n' ' ' ||
      cx_log IMAGE "container $c skipped: it cannot be inspected (gone)"
  done
  return 0
}

# cx_ir_refs <ID> <repositories>: the references of the image in those repositories, tags first.
# Returns 1 when the image is not there (any more).
cx_ir_refs() {
  local id=$1 repos=$2 all r
  all=$(docker image inspect --format '{{range .RepoTags}}{{.}} {{end}}{{range .RepoDigests}}{{.}} {{end}}' \
    "$id" 2>/dev/null) || return 1
  for r in $all; do
    [[ $repos != *" $(cx_ir_repo "$r") "* ]] || printf '%s ' "$r"
  done
  return 0
}

# cx_ir_remove <ID> <repositories>: 0 removed, 1 a reference could not be removed (CX_IR_FAILED),
# 2 kept for a reference of another repository. The references are read again after each removal:
# on the containerd store a tag carries a repository@digest reference that goes with it.
cx_ir_remove() {
  local id=$1 repos=$2 refs ref i
  for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16; do
    refs=$(cx_ir_refs "$id" "$repos") || return 0
    [ -n "$refs" ] || { cx_log IMAGE "keep $id reason=\"other references\""; return 2; }
    ref=${refs%% *}
    if ! cx_log_run docker rmi "$ref" >/dev/null; then
      CX_IR_FAILED+=("$ref")
      return 1
    fi
  done
  cx_log IMAGE "keep $id reason=\"references left after $i removals\""
  return 2
}

# cx_ir_prune: after step 13. Fills CX_IR_*; never fails the upgrade. The upgrade calls it under
# set -e outside any condition, so every command here that can fail is either tested or followed
# by || (a failure that would shrink what is kept stops the removals instead).
cx_ir_prune() {
  local ids id repos keep dir before="" after="" rc
  local -a todo=() left=()
  CX_IR_REMOVED=0 CX_IR_FREED="" CX_IR_FAILED=() CX_IR_SKIPPED=0
  if [ "${CX_KEEP_IMAGES:-0}" = 1 ]; then
    CX_IR_SKIPPED=1
    cx_log IMAGE "old images kept: --keep-images"
    return 0
  fi
  if ! ids=$(docker image ls -a -q --no-trunc 2>/dev/null | sort -u); then
    cx_log WARN "old images not removed: the image list cannot be read"
    return 0
  fi
  repos=$(cx_ir_repos) || repos=" "
  if ! keep=" $(cx_ir_keep_ids)"; then
    cx_log WARN "old images not removed: the images to keep cannot be read"
    return 0
  fi
  for id in $ids; do
    [[ $keep != *" $id "* ]] || continue
    [ -n "$(cx_ir_refs "$id" "$repos")" ] || continue
    todo+=("$id")
  done
  [ "${#todo[@]}" -gt 0 ] || return 0
  # Containers are asked only when there is something to remove.
  if ! keep+="$(cx_ir_container_ids) "; then
    cx_log WARN "old images not removed: the containers cannot be listed"
    return 0
  fi
  for id in "${todo[@]}"; do
    [[ $keep == *" $id "* ]] || left+=("$id")
  done
  [ "${#left[@]}" -gt 0 ] || return 0
  dir=$(docker info --format '{{.DockerRootDir}}' 2>/dev/null) || dir=""
  # Free space that cannot be read leaves CX_IR_FREED empty: the screen shows the number alone.
  [ -z "$dir" ] || before=$(cx_free_bytes "$dir") || before=""
  for id in "${left[@]}"; do
    rc=0
    cx_ir_remove "$id" "$repos" || rc=$?
    [ "$rc" != 0 ] || CX_IR_REMOVED=$((CX_IR_REMOVED + 1))
  done
  [ -z "$dir" ] || after=$(cx_free_bytes "$dir") || after=""
  if [[ $before =~ ^[0-9]+$ && $after =~ ^[0-9]+$ ]] && [ "$after" -ge "$before" ]; then
    CX_IR_FREED=$((after - before))
  fi
  cx_log IMAGE "old images removed=$CX_IR_REMOVED failed=${#CX_IR_FAILED[@]} freed=${CX_IR_FREED:-unknown}"
  return 0
}

# cx_ir_print: the lines of the closing screen; nothing when nothing was to remove.
cx_ir_print() {
  local r
  if [ "$CX_IR_SKIPPED" = 1 ]; then
    cx_line SKIP "$(cx_msg ir_skipped)"
    return 0
  fi
  if [ "$CX_IR_REMOVED" -gt 0 ]; then
    if [ -n "$CX_IR_FREED" ]; then
      cx_line OK "$(cx_msg ir_removed "$CX_IR_REMOVED" "$(cx_size_human "$CX_IR_FREED")")"
    else
      cx_line OK "$(cx_msg ir_removed_count "$CX_IR_REMOVED")"
    fi
  fi
  [ "${#CX_IR_FAILED[@]}" -gt 0 ] || return 0
  cx_line WARN "$(cx_msg ir_failed "${#CX_IR_FAILED[@]}")"
  for r in "${CX_IR_FAILED[@]}"; do cx_cmd "sudo docker rmi $r"; done
}
