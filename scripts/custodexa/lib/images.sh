# shellcheck shell=bash
# The CX_IMG_* results are read by the install, load and status commands.
# shellcheck disable=SC2034
# Getting the program images. Each image is tried in a fixed order, and every attempt says where it
# looked and why it moved on:
#   1 this host   2 offline bundle   3 GHCR (own images)   4 Docker Hub / the upstream registry
#   5 build from source (own images)
# Nothing is pulled by compose (pull_policy: never): the reference that was checked here is written
# to releases/<version>/images.env, and the local image ID to releases/<version>/image-ids.env, so
# the running containers can be compared with exactly what was checked.
#
# What "matches the release manifest" means depends on where the image came from and on the image
# store (docker info, DriverStatus):
#   registry pull by index digest    classic store: Id = config digest of this architecture
#                                    containerd store: Id = index digest
#   offline bundle (docker load)     classic store: Id = config digest of this architecture
#                                    containerd store: Id = digest of the manifest inside the bundle,
#                                    computed here from its bytes (index.json is only used to find it)
# The config digest is always compared with the MANIFEST before anything is loaded.

declare -gA CX_IMG_REF=() CX_IMG_ID=() CX_IMG_SRC=()
declare -ga CX_IMG_NAMES=() CX_TOOL_NAMES=() CX_IMG_ALL=()
CX_IMG_STORE=""
CX_IMG_ARCH=""
CX_IMG_BUNDLE=""        # the offline bundle in use, once found
CX_IMG_BUNDLE_STATE=""  # "", none, bad, loaded
declare -gA CX_IMG_BUNDLE_ID=()  # name -> expected Id after load (filled before loading)
declare -gA CX_IMG_DOWN=()       # registry host -> reason, once it failed to connect
declare -gA CX_IMG_SAID=()       # SKIP messages already printed (each once per run)
readonly CX_LOCAL_PREFIX=custodexa-local

# cx_img_store: classic or containerd, from the daemon's DriverStatus.
cx_img_store() {
  if [ -z "$CX_IMG_STORE" ]; then
    if docker info --format '{{json .DriverStatus}}' 2>/dev/null | grep -q 'io.containerd.snapshotter'; then
      CX_IMG_STORE=containerd
    else
      CX_IMG_STORE=classic
    fi
  fi
  printf '%s' "$CX_IMG_STORE"
}

# cx_img_familiar <ref>: the short name people know (docker.io/library/postgres -> postgres).
cx_img_familiar() {
  local r=${1#docker.io/}
  printf '%s' "${r#library/}"
}

# cx_img_short <digest>: sha256:3f9a...c21e, for reading; commands to copy always get the full digest.
cx_img_short() {
  local h=${1#sha256:}
  printf 'sha256:%s...%s' "${h:0:4}" "${h: -4}"
}

cx_img_id() { docker image inspect --format '{{.Id}}' "$1" 2>/dev/null; }

cx_img_upstream() { [ "$(cx_mf "images.$1.upstream")" = true ]; }

# cx_img_registry_id <name>: the Id an image pulled by its index digest has on this store.
cx_img_registry_id() {
  if [ "$(cx_img_store)" = containerd ]; then
    cx_mf "images.$1.index_digest"
  else
    cx_mf "images.$1.platforms.$CX_IMG_ARCH.config_digest"
  fi
}

# cx_img_needed <overlays> [all]: the images to obtain for the deployment form, in MANIFEST order:
#   CX_IMG_NAMES   service images: the form runs a container of each, checked after the start
#   CX_TOOL_NAMES  tool images: images of the release this script runs itself, which the form does
#                  not run as a service: openssl (backup encryption) when the form has no
#                  certificate initializer (external ingress), and the PostgreSQL clients
#                  (pgclientNN, the backup of an external database) when the database is external.
#                  Obtained and checked like the others, recorded in current.tool_image_ids, never
#                  checked as a container.
#   CX_IMG_ALL     both, the ones to obtain
# With "all" every image of the MANIFEST is named (an offline bundle holds them all, and load
# checks each one it loads): the PostgreSQL clients as service names too.
cx_img_needed() {
  local ov=" $1 " n every=${2:-}
  CX_IMG_NAMES=() CX_TOOL_NAMES=() CX_IMG_ALL=()
  for n in "${CX_MF_IMAGES[@]}"; do
    case $n in
      postgres) [[ $ov == *" external-database "* ]] && continue ;;
      nginx) [[ $ov == *" external-ingress "* ]] && continue ;;
      openssl)
        if [[ $ov == *" external-ingress "* ]]; then
          CX_TOOL_NAMES+=("$n")
          CX_IMG_ALL+=("$n")
          continue
        fi
        ;;
      pgclient[0-9]*)
        if [ "$every" != all ]; then
          [[ $ov == *" external-database "* ]] || continue
          CX_TOOL_NAMES+=("$n")
          CX_IMG_ALL+=("$n")
          continue
        fi
        ;;
    esac
    CX_IMG_NAMES+=("$n")
    CX_IMG_ALL+=("$n")
  done
}

# cx_img_is_tool <name>: the image is a tool image of this deployment form (cx_img_needed).
cx_img_is_tool() { [[ " ${CX_TOOL_NAMES[*]+"${CX_TOOL_NAMES[*]}"} " == *" $1 "* ]]; }

# ---------- per-image output ----------
readonly CX_IMG_ONCE="img_offline_bad img_build_note"
cx_img_say() { # <mark> <message id> [args...]
  local mark=$1 id=$2 message
  shift 2
  # Skips, and the notes that concern every image alike, are said once per run.
  if [ "$mark" = SKIP ] || [[ " $CX_IMG_ONCE " == *" $id "* ]]; then
    [ -z "${CX_IMG_SAID[$id]+x}" ] || return 0
    CX_IMG_SAID[$id]=1
  fi
  message=$(cx_msg "$id" "$@")
  printf '         %s %s\n' "$(cx_mark "$mark")" "${message//$'\n'/$'\n'                }"
}
cx_img_wait() { # <message id> [args...]: visible before a Docker call can block
  local id=$1
  shift
  printf '         %s %s\n' "$(cx_mark RUN)" "$(cx_msg "$id" "$@")"
}

# cx_img_reason <docker error text>: why a registry attempt failed, in words.
cx_img_reason() {
  local e=$1
  case $e in
    *"i/o timeout"* | *"Timeout exceeded"* | *"deadline exceeded"* | *"TLS handshake timeout"*) cx_msg img_reason_timeout ;;
    *"manifest unknown"* | *"not found"* | *"No such image"*) cx_msg img_reason_notfound ;;
    *) cx_msg img_reason_other "$(printf '%s' "$e" | tail -n1 | cut -c1-40)" ;;
  esac
}

# ---------- 1. this host ----------
cx_img_try_local() {
  local n=$1 ref d tag id want r
  cx_img_wait img_wait_local "$n"
  ref=$(cx_mf "images.$n.ref") d=$(cx_mf "images.$n.index_digest") tag=$(cx_mf "images.$n.tag")
  want=$(cx_img_registry_id "$n")
  for r in "$ref" $(cx_mf "images.$n.mirror"); do
    id=$(cx_img_id "$r@$d") || continue
    if [ "$id" = "$want" ]; then
      cx_img_found "$n" local "$r@$d" "$id"
      cx_img_say OK img_local_ok
      return 0
    fi
  done
  # A tag alone proves nothing: it must carry the content the MANIFEST names (on containerd, the
  # content recorded when the offline bundle was checked and loaded, or installed for this release).
  if id=$(cx_img_id "$ref:$tag"); then
    if [ "$id" = "$(cx_mf "images.$n.platforms.$CX_IMG_ARCH.config_digest")" ] ||
      { [ "$(cx_img_store)" = containerd ] && [[ " $(cx_img_loaded_id "$n") $(cx_img_installed_ids "$n") " == *" $id "* ]]; }; then
      cx_img_found "$n" local "$ref:$tag" "$id"
      cx_img_say OK img_local_ok
      return 0
    fi
    cx_img_say WARN img_local_mismatch "$(cx_img_familiar "$ref"):$tag"
    cx_log IMAGE "$n source=local WARN reason=\"digest differs\" id=$id"
    return 1
  fi
  cx_img_say SKIP img_local_absent
  cx_log IMAGE "$n source=local SKIP reason=\"not present\""
  return 1
}

# The Id recorded for an image when `load` checked and loaded it (state key load.image_ids).
cx_img_loaded_id() {
  local kv
  [ "$(cx_state_get load.version)" = "$(cx_mf version)" ] || return 0
  for kv in $(cx_state_get load.image_ids); do
    [ "${kv%%=*}" = "$1" ] && printf '%s' "${kv#*=}"
  done
  return 0
}
# The Id install or upgrade recorded for an image of this host's current release, or of the release
# an upgrade left (previous.*: a restore of the upgrade's backup reads that release), when the loaded
# MANIFEST is that release's (state keys <current|previous>.image_ids, .tool_image_ids).
cx_img_installed_ids() {
  local kv at
  for at in current previous; do
    [ "$(cx_state_get "$at.version")" = "$(cx_mf version)" ] || continue
    for kv in $(cx_state_get "$at.image_ids") $(cx_state_get "$at.tool_image_ids"); do
      [ "${kv%%=*}" = "$1" ] && printf '%s ' "${kv#*=}"
    done
  done
  return 0
}

# cx_img_held_id <name>: the ID of image <name> of the loaded release manifest when this host holds
# exactly that content (CX_IMG_ARCH set), found by ID alone, without a word on screen: the index
# digest (pulled on the containerd image store) or this architecture's config digest (the classic
# store); on the containerd store also the ID recorded when `load` checked and loaded this
# release's bundle, or by install or upgrade for this host's current release. An image loaded
# from an offline bundle on containerd has an ID of its own, which no digest of the manifest finds.
# An ID recorded for another release counts when that release's manifest names the same index
# digest for the image: the same image (cx_img_peer_ids).
cx_img_held_id() {
  local n=$1
  cx_img_held_try "$(cx_mf "images.$n.index_digest")" "$(cx_mf "images.$n.platforms.$CX_IMG_ARCH.config_digest")" && return 0
  [ "$(cx_img_store)" = containerd ] || return 1
  # shellcheck disable=SC2046 # one ID per word
  cx_img_held_try "$(cx_img_loaded_id "$n")" $(cx_img_installed_ids "$n") $(cx_img_peer_ids "$n")
}

# cx_img_peer_ids <name>: the IDs `load` (load.image_ids) and install or upgrade (current.image_ids,
# current.tool_image_ids) recorded for image <name> of a release other than the loaded manifest's,
# when that release's manifest names the index digest the loaded manifest names for <name>. That
# release's manifest is the unpacked package's (releases/<version>/MANIFEST.json); for a load, else
# the index digests `load` recorded from the manifest it checked the bundle against.
cx_img_peer_ids() {
  local n=$1 want v kv
  want=$(cx_mf "images.$n.index_digest")
  [[ $want =~ ^sha256:[0-9a-f]{64}$ ]] || return 0
  v=$(cx_state_get load.version)
  if [ -n "$v" ] && [ "$v" != "$(cx_mf version)" ] && [ "$(cx_img_peer_digest "$v" "$n" load)" = "$want" ]; then
    for kv in $(cx_state_get load.image_ids); do
      [ "${kv%%=*}" = "$n" ] && printf '%s ' "${kv#*=}"
    done
  fi
  v=$(cx_state_get current.version)
  if [ -n "$v" ] && [ "$v" != "$(cx_mf version)" ] && [ "$(cx_img_peer_digest "$v" "$n" current)" = "$want" ]; then
    for kv in $(cx_state_get current.image_ids) $(cx_state_get current.tool_image_ids); do
      [ "${kv%%=*}" = "$n" ] && printf '%s ' "${kv#*=}"
    done
  fi
  return 0
}
cx_img_peer_digest() { # <version> <name> <load|current>: index digest of <name> in that release's manifest
  local v=$1 n=$2 f=$CX_ROOT/releases/$1/MANIFEST.json kv
  if [ -f "$f" ]; then
    # A subshell: the loaded manifest (CX_MF) stays the caller's.
    (cx_manifest_load "$f" >/dev/null 2>&1 && [ "$(cx_mf version)" = "$v" ] && cx_mf "images.$n.index_digest")
    return 0
  fi
  [ "$3" = load ] || return 0
  for kv in $(cx_state_get load.index_digests); do
    [ "${kv%%=*}" = "$n" ] && printf '%s' "${kv#*=}"
  done
  return 0
}
cx_img_held_try() { # <ID>...: print the first one this host has as an image of that ID
  local id
  for id in "$@"; do
    [[ $id =~ ^sha256:[0-9a-f]{64}$ ]] || continue
    if [ "$(cx_img_id "$id")" = "$id" ]; then printf '%s' "$id"; return 0; fi
  done
  return 1
}

cx_img_found() { # <name> <source> <reference> <id>
  CX_IMG_SRC[$1]=$2 CX_IMG_REF[$1]=$3 CX_IMG_ID[$1]=$4
  cx_log IMAGE "$1 source=$2 ref=$3 id=$4 OK"
}

# ---------- 2. offline bundle ----------
# cx_bundle_candidates: --images, else the deployment folder and the current folder.
cx_bundle_file() { printf 'custodexa-images-%s-%s.tar' "$(cx_mf version)" "$CX_IMG_ARCH"; }
cx_bundle_dirs() {
  local d seen=" "
  for d in "$CX_ROOT" "$PWD"; do
    [[ $seen == *" $d "* ]] && continue
    seen+="$d "
    printf '%s\n' "$d"
  done
}

# cx_bundle_sha_ok <bundle>: the bundle's line in SHA256SUMS next to it matches. 0 ok, 1 no list,
# 2 not listed, 3 mismatch.
cx_bundle_sha_ok() {
  local b=$1 dir sums want got
  dir=$(dirname -- "$b")
  sums=$dir/SHA256SUMS
  [ -f "$sums" ] || return 1
  want=$(awk -v f="$(basename -- "$b")" '($2 == f || $2 == "*" f) { print $1; exit }' "$sums")
  [ -n "$want" ] || return 2
  got=$(sha256sum -- "$b" | cut -d' ' -f1)
  [ "$got" = "$want" ] || return 3
}

cx_sha256_file() { sha256sum -- "$1" | cut -d' ' -f1; }

# cx_bundle_check <bundle>: read index.json, manifest.json and the blobs they name, before loading.
# For every image of the MANIFEST held by the bundle: the manifest blob's own sha256 equals the name
# it is stored under, the config it names equals the MANIFEST's config digest for this architecture
# (and the config blob hashes to it), and manifest.json points the same tag at that config.
# Fills CX_IMG_BUNDLE_ID[name] with the Id the image must have after loading. Returns 1 and sets
# CX_BUNDLE_ERR on the first inconsistency; images not in the bundle are simply absent.
CX_BUNDLE_ERR=""
cx_bundle_check() {
  local b=$1 tmp n ref tag want entry m name cfg mjson store
  local -A mdig=()
  store=$(cx_img_store)
  CX_IMG_BUNDLE_ID=()
  CX_BUNDLE_ERR=""
  tmp=$(mktemp -d) || return 1
  tar -xf "$b" -C "$tmp" index.json manifest.json 2>/dev/null
  if [ ! -f "$tmp/index.json" ] || [ ! -f "$tmp/manifest.json" ]; then
    CX_BUNDLE_ERR=$(cx_msg img_bundle_unreadable)
    rm -rf "$tmp"
    return 1
  fi
  local -a members=()
  while IFS= read -r entry; do
    [[ $entry =~ \"digest\":\"sha256:([0-9a-f]{64})\" ]] || continue
    m=${BASH_REMATCH[1]}
    [[ $entry =~ \"io.containerd.image.name\":\"([^\"]+)\" ]] || continue
    mdig[${BASH_REMATCH[1]}]=$m
  done < <(grep -oE '"digest":"sha256:[0-9a-f]{64}"[^{}]*"annotations":\{[^{}]*\}' "$tmp/index.json")
  for n in "${CX_IMG_ALL[@]}"; do
    ref=$(cx_mf "images.$n.ref") tag=$(cx_mf "images.$n.tag")
    [ -n "${mdig[$ref:$tag]+x}" ] || continue
    want=$(cx_mf "images.$n.platforms.$CX_IMG_ARCH.config_digest")
    members+=("blobs/sha256/${mdig[$ref:$tag]}" "blobs/sha256/${want#sha256:}")
  done
  [ "${#members[@]}" -eq 0 ] || tar -xf "$b" -C "$tmp" "${members[@]}" 2>/dev/null
  mjson=$(tr -d ' \n\t' <"$tmp/manifest.json")
  for n in "${CX_IMG_ALL[@]}"; do
    ref=$(cx_mf "images.$n.ref") tag=$(cx_mf "images.$n.tag")
    [ -n "${mdig[$ref:$tag]+x}" ] || continue
    name=$(cx_img_familiar "$ref"):$tag
    want=$(cx_mf "images.$n.platforms.$CX_IMG_ARCH.config_digest")
    m=$tmp/blobs/sha256/${mdig[$ref:$tag]}
    # The manifest: found through index.json, trusted only for what its bytes hash to.
    if [ ! -f "$m" ] || [ "sha256:$(cx_sha256_file "$m")" != "sha256:${mdig[$ref:$tag]}" ]; then
      CX_BUNDLE_ERR=$(cx_msg img_bundle_manifest_bad "$name")
      break
    fi
    cfg=$(tr -d ' \n\t' <"$m")
    if [[ ! $cfg =~ \"config\":\{[^}]*\"digest\":\"(sha256:[0-9a-f]{64})\" ]] || [ "${BASH_REMATCH[1]}" != "$want" ]; then
      CX_BUNDLE_ERR=$(cx_msg img_bundle_config_bad "$name")
      break
    fi
    if [ ! -f "$tmp/blobs/sha256/${want#sha256:}" ] || [ "sha256:$(cx_sha256_file "$tmp/blobs/sha256/${want#sha256:}")" != "$want" ]; then
      CX_BUNDLE_ERR=$(cx_msg img_bundle_config_bad "$name")
      break
    fi
    # manifest.json (what the classic store loads) must name the same config for this tag.
    if ! grep -qE "\"Config\":\"blobs/sha256/${want#sha256:}\",\"RepoTags\":\[[^]]*\"($name|$ref:$tag)\"" <<<"$mjson"; then
      CX_BUNDLE_ERR=$(cx_msg img_bundle_config_bad "$name")
      break
    fi
    if [ "$store" = containerd ]; then
      CX_IMG_BUNDLE_ID[$n]=sha256:$(cx_sha256_file "$m")
    else
      CX_IMG_BUNDLE_ID[$n]=$want
    fi
  done
  rm -rf "$tmp"
  [ -z "$CX_BUNDLE_ERR" ]
}

# cx_bundle_load <bundle>: checksum, check, load; then every image of the bundle must carry the Id
# computed before loading. Sets CX_IMG_BUNDLE_STATE (loaded or bad) and CX_BUNDLE_ERR.
cx_bundle_load() {
  local b=$1 rc
  CX_IMG_BUNDLE=$b
  cx_img_wait img_wait_bundle_check "$b"
  cx_bundle_sha_ok "$b" && rc=0 || rc=$?
  case $rc in
    1) CX_BUNDLE_ERR=$(cx_msg img_bundle_no_sums "$(dirname -- "$b")") ;;
    2) CX_BUNDLE_ERR=$(cx_msg img_bundle_not_listed) ;;
    3) CX_BUNDLE_ERR=$(cx_msg img_bundle_sum_bad) ;;
  esac
  if [ "$rc" -ne 0 ]; then
    [ "$rc" -ne 3 ] || CX_IMG_BUNDLE_INTEGRITY_BAD=1
    CX_IMG_BUNDLE_STATE=bad
    cx_log IMAGE "bundle=$b FAIL reason=\"$CX_BUNDLE_ERR\""
    return 1
  fi
  if ! cx_bundle_check "$b"; then
    CX_IMG_BUNDLE_INTEGRITY_BAD=1
    CX_IMG_BUNDLE_STATE=bad
    cx_log IMAGE "bundle=$b FAIL reason=\"$CX_BUNDLE_ERR\""
    return 1
  fi
  cx_img_wait img_wait_bundle_load "$b"
  if ! cx_log_run docker load -q -i "$b" >/dev/null; then
    CX_BUNDLE_ERR=$(cx_msg img_bundle_load_failed)
    CX_IMG_BUNDLE_STATE=bad
    return 1
  fi
  if ! cx_bundle_verify_loaded; then
    CX_IMG_BUNDLE_INTEGRITY_BAD=1
    CX_IMG_BUNDLE_STATE=bad
    return 1
  fi
  CX_IMG_BUNDLE_STATE=loaded
}

# cx_bundle_verify_loaded: after docker load, every image of the bundle carries the Id computed
# before loading. On the first that does not: CX_BUNDLE_ERR, CX_BUNDLE_BAD (its name:tag), return 1.
CX_BUNDLE_BAD=""
cx_bundle_verify_loaded() {
  local n ref tag id
  for n in "${CX_IMG_ALL[@]}"; do
    [ -n "${CX_IMG_BUNDLE_ID[$n]+x}" ] || continue
    ref=$(cx_mf "images.$n.ref") tag=$(cx_mf "images.$n.tag")
    id=$(cx_img_id "$ref:$tag") || id=""
    if [ "$id" != "${CX_IMG_BUNDLE_ID[$n]}" ]; then
      CX_BUNDLE_BAD=$(cx_img_familiar "$ref"):$tag
      CX_BUNDLE_ERR=$(cx_msg img_bundle_id_bad "$CX_BUNDLE_BAD")
      cx_log IMAGE "$n source=offline FAIL id=$id want=${CX_IMG_BUNDLE_ID[$n]}"
      return 1
    fi
  done
}

cx_img_try_offline() {
  local n=$1 d ref tag
  local -a found=()
  if [ -z "$CX_IMG_BUNDLE_STATE" ]; then
    if [ -n "${CX_IMAGES:-}" ]; then
      found=("$CX_IMAGES")
    else
      while IFS= read -r d; do
        [ -f "$d/$(cx_bundle_file)" ] && found+=("$d/$(cx_bundle_file)")
      done < <(cx_bundle_dirs)
    fi
    if [ "${#found[@]}" -eq 0 ] || [ ! -f "${found[0]}" ]; then
      CX_IMG_BUNDLE_STATE=none
    else
      cx_bundle_load "${found[0]}" || true
    fi
  fi
  case $CX_IMG_BUNDLE_STATE in
    none)
      local dirs
      local -a dl=()
      mapfile -t dl < <(cx_bundle_dirs)
      dirs=$(cx_join "$(cx_msg img_and)" "${dl[@]}")
      [ -z "${CX_IMAGES:-}" ] || dirs=$CX_IMAGES
      cx_img_say SKIP img_offline_none "$(cx_bundle_file)" "$dirs"
      cx_log IMAGE "$n source=offline SKIP reason=\"not found\""
      return 1
      ;;
    bad)
      if [ "${CX_IMG_BUNDLE_INTEGRITY_BAD:-0}" = 1 ]; then
        cx_img_say FAIL img_offline_bad "$CX_IMG_BUNDLE" "$CX_BUNDLE_ERR"
        return 2
      fi
      cx_img_say WARN img_offline_bad "$CX_IMG_BUNDLE" "$CX_BUNDLE_ERR"
      return 1
      ;;
  esac
  if [ -z "${CX_IMG_BUNDLE_ID[$n]+x}" ]; then
    cx_img_say SKIP img_offline_absent
    cx_log IMAGE "$n source=offline SKIP reason=\"not in bundle\""
    return 1
  fi
  ref=$(cx_mf "images.$n.ref") tag=$(cx_mf "images.$n.tag")
  cx_img_found "$n" offline "$ref:$tag" "${CX_IMG_BUNDLE_ID[$n]}"
  cx_img_say OK img_offline_ok "$CX_IMG_BUNDLE"
}

# ---------- 3, 4. registries ----------
cx_img_label() { # <ref>: GHCR, Docker Hub, or the registry host
  case $1 in
    ghcr.io/*) printf 'GHCR' ;;
    docker.io/*) printf 'Docker Hub' ;;
    *) printf '%s' "${1%%/*}" ;;
  esac
}

# cx_img_try_registry <name> <repository>
cx_img_try_registry() {
  local n=$1 repo=$2 d host err id
  d=$(cx_mf "images.$n.index_digest")
  host=${repo%%/*}
  [ -n "$host" ] || return 1
  if [ -n "${CX_IMG_DOWN[$host]+x}" ]; then
    cx_log IMAGE "$n source=$host SKIP reason=\"unreachable earlier in this run\""
    return 1
  fi
  cx_img_wait img_wait_registry "$n" "$(cx_img_label "$repo")"
  if ! err=$(docker pull -q --platform "linux/$CX_IMG_ARCH" "$repo@$d" 2>&1 >/dev/null); then
    local why
    why=$(cx_img_reason "$err")
    [ "$why" != "$(cx_msg img_reason_timeout)" ] || CX_IMG_DOWN[$host]=$why
    cx_img_say WARN img_try_failed "$(cx_img_label "$repo")" "$repo" "$why"
    if ! cx_img_upstream "$n" && [ "$host" = ghcr.io ]; then
      printf '         %s %s\n' "$(cx_mark WARN)" "$(cx_msg img_wait_fallback "$why")"
    fi
    cx_log IMAGE "$n source=$host ref=$repo@$d WARN reason=\"$(printf '%s' "$err" | tail -n1)\""
    return 1
  fi
  cx_img_wait img_wait_digest "$n"
  id=$(cx_img_id "$repo@$d") || id=""
  if [ "$id" != "$(cx_img_registry_id "$n")" ]; then
    cx_img_say FAIL img_pulled_mismatch "$(cx_img_label "$repo")" "$repo@$(cx_img_short "$d")"
    cx_log IMAGE "$n source=$host FAIL id=$id want=$(cx_img_registry_id "$n")"
    return 2
  fi
  cx_img_found "$n" "$host" "$repo@$d" "$id"
  if cx_img_upstream "$n"; then
    cx_img_say OK img_pulled_up "$(cx_img_label "$repo")" "$repo@$(cx_img_short "$d")"
  else
    cx_img_say OK img_pulled_own "$(cx_img_label "$repo")" "$repo@$(cx_img_short "$d")"
  fi
}

# ---------- 5. build from source ----------
cx_img_try_build() {
  local n=$1 ver want got ref id release
  release=${CX_DIR:-$CX_ROOT/current}
  ver=$(cx_mf version)
  ref=$CX_LOCAL_PREFIX/$n:$ver
  want=$(cx_mf source.sha256)
  [ "${CX_IMAGES_FROM:-auto}" != auto ] || cx_img_wait img_source_check
  got=$(cx_tree_sha256 "$release/source" 2>/dev/null) || got=""
  if [ -z "$want" ] || [ "$got" != "$want" ]; then
    cx_img_say FAIL img_build_source_bad
    cx_log IMAGE "$n source=build FAIL reason=\"source checksum\""
    return 2
  fi
  cx_img_say RUN img_build_note
  cx_img_wait img_wait_build "$n"
  CX_IMG_REF[$n]=$ref
  cx_images_write_env "$release/images.env"
  if ! cx_compose_release "$release" build "$n" >>"${CX_LOG_FILE:-/dev/null}" 2>&1; then
    unset 'CX_IMG_REF[$n]'
    cx_img_say FAIL img_build_failed
    return 1
  fi
  id=$(cx_img_id "$ref") || id=""
  cx_img_found "$n" build "$ref" "$id"
  cx_img_say OK img_build_ok "$ref"
}

# ---------- all images ----------
# cx_images_resolve <overlays> [name...]: resolve every image the deployment runs (or only the
# images named: upgrade obtains the PostgreSQL clients before its checks); prints the step body
# (between the "[ .. ] 3/7" line and the closing line). Returns 1 when some image has no source.
cx_images_resolve() {
  local n ver failed=0 ref tag want got release
  local -a only=("${@:2}")
  release=${CX_DIR:-$CX_ROOT/current}
  CX_IMG_ARCH=$(cx_arch) || return 1
  CX_IMG_REF=() CX_IMG_ID=() CX_IMG_SRC=() CX_IMG_SAID=() CX_IMG_DOWN=()
  CX_IMG_BUNDLE_STATE="" CX_IMG_BUNDLE="" CX_IMG_BUNDLE_INTEGRITY_BAD=0 CX_IMG_INTEGRITY_BAD=0
  cx_img_needed "$1"
  ver=$(cx_mf version)
  if [ "${CX_IMAGES_FROM:-auto}" = source ]; then
    printf '       %s\n' "$(cx_msg img_source_mode)"
    cx_sub RUN "$(cx_msg img_source_check)"
    want=$(cx_mf source.sha256)
    got=$(cx_tree_sha256 "$release/source" 2>/dev/null) || got=""
    if [ -z "$want" ] || [ "$want" != "$got" ]; then
      cx_sub FAIL "$(cx_msg img_build_source_bad)"
      cx_log IMAGE 'source=build FAIL reason="source checksum"'
      return 1
    fi
    cx_sub OK "$(cx_msg img_source_ok)"
  else
    printf '       %s\n' "$(cx_msg img_order | sed '2,$s/^/       /')"
  fi
  [ "${#only[@]}" -gt 0 ] || only=("${CX_IMG_ALL[@]}")
  for n in "${only[@]}"; do
    ref=$(cx_mf "images.$n.ref") tag=$(cx_mf "images.$n.tag")
    if cx_img_upstream "$n"; then
      printf '       %s\n' "$(cx_msg img_head_upstream "$n" "$tag" "$(cx_img_familiar "$ref")")"
    else
      printf '       %s\n' "$(cx_msg img_head_own "$n" "$ver")"
    fi
    cx_img_resolve_one "$n" || failed=1
    [ "$CX_IMG_INTEGRITY_BAD" != 1 ] || break
  done
  return "$failed"
}

cx_img_resolve_one() {
  local n=$1 k rc
  if [ "${CX_IMAGES_FROM:-auto}" = source ] && ! cx_img_upstream "$n"; then
    cx_img_try_build "$n" && return 0
    CX_IMG_INTEGRITY_BAD=1
    return 1
  fi
  cx_img_try_local "$n" && return 0
  cx_img_try_offline "$n" && return 0
  rc=$?
  [ "$rc" -ne 2 ] || { CX_IMG_INTEGRITY_BAD=1; return 1; }
  if ! cx_img_upstream "$n"; then
    cx_img_try_registry "$n" "$(cx_mf "images.$n.ref")" && return 0
    rc=$?
    [ "$rc" -ne 2 ] || { CX_IMG_INTEGRITY_BAD=1; return 1; }
    for k in $(cx_mf "images.$n.mirror"); do
      if cx_img_try_registry "$n" "$k"; then
        return 0
      else
        rc=$?
        [ "$rc" -ne 2 ] || { CX_IMG_INTEGRITY_BAD=1; return 1; }
      fi
    done
    cx_img_try_build "$n" && return 0
    rc=$?
    [ "$rc" -ne 2 ] || { CX_IMG_INTEGRITY_BAD=1; return 1; }
  else
    cx_img_try_registry "$n" "$(cx_mf "images.$n.ref")" && return 0
    rc=$?
    [ "$rc" -ne 2 ] || { CX_IMG_INTEGRITY_BAD=1; return 1; }
  fi
  cx_img_say FAIL img_none "$n"
  return 1
}

# cx_images_write_env <file>: CUSTODEXA_IMAGE_<NAME>=<reference>, the references checked above, for
# compose: the service images only.
cx_images_write_env() {
  local f=$1 n tmp
  tmp=$(mktemp "$f.tmp-XXXXXX") || return 1
  for n in "${CX_MF_IMAGES[@]}"; do
    [ -n "${CX_IMG_REF[$n]:-}" ] || continue
    ! cx_img_is_tool "$n" || continue
    printf 'CUSTODEXA_IMAGE_%s=%s\n' "${n^^}" "${CX_IMG_REF[$n]}"
  done >"$tmp"
  mv -f "$tmp" "$f"
}

# cx_images_write_ids <file>: <name>=<image ID> of the service images, compared with the running
# containers after start.
cx_images_write_ids() {
  local f=$1 n tmp
  tmp=$(mktemp "$f.tmp-XXXXXX") || return 1
  for n in "${CX_MF_IMAGES[@]}"; do
    [ -n "${CX_IMG_ID[$n]:-}" ] || continue
    ! cx_img_is_tool "$n" || continue
    printf '%s=%s\n' "$n" "${CX_IMG_ID[$n]}"
  done >"$tmp"
  mv -f "$tmp" "$f"
}

# cx_images_ids_text: "backend=sha256:... frontend=..." for state.json.
cx_images_ids_text() {
  local n out=""
  for n in "${CX_IMG_NAMES[@]}"; do
    [ -n "${CX_IMG_ID[$n]:-}" ] && out+="${out:+ }$n=${CX_IMG_ID[$n]}"
  done
  printf '%s' "$out"
}

# cx_tools_ids_text: "openssl=sha256:..." for state.json (current.tool_image_ids); "" when the
# form has no tool image.
cx_tools_ids_text() {
  local n out=""
  for n in "${CX_TOOL_NAMES[@]+"${CX_TOOL_NAMES[@]}"}"; do
    [ -n "${CX_IMG_ID[$n]:-}" ] && out+="${out:+ }$n=${CX_IMG_ID[$n]}"
  done
  printf '%s' "$out"
}

# cx_tools_record <prefix>: <prefix>.tool_image_ids in the state, or no such key without tools.
cx_tools_record() {
  local ids
  ids=$(cx_tools_ids_text)
  if [ -n "$ids" ]; then
    cx_state_set "$1.tool_image_ids" "$ids"
  else
    cx_state_unset "$1.tool_image_ids"
  fi
}

# Container of each image, for the check after start.
cx_img_container() {
  case $1 in
    postgres | guacd | backend | frontend) printf 'custodexa-%s' "$1" ;;
    openssl) printf 'custodexa-tls-init' ;;
    nginx) printf 'custodexa-tls-proxy' ;;
  esac
}

# cx_images_verify_running: every container runs exactly the image recorded above. Prints one FAIL
# sub-line per container that does not, and returns 1.
cx_images_verify_running() {
  local n c got bad=0
  for n in "${CX_IMG_NAMES[@]}"; do
    c=$(cx_img_container "$n")
    got=$(docker inspect --format '{{.Image}}' "$c" 2>/dev/null) || got=""
    if [ "$got" != "${CX_IMG_ID[$n]:-}" ]; then
      cx_sub FAIL "$(cx_msg img_running_bad "$c" "${got:-?}" "${CX_IMG_ID[$n]:-?}")"
      cx_log CHECK "running $c image=${got:-none} want=${CX_IMG_ID[$n]:-none} FAIL"
      bad=1
    fi
  done
  return "$bad"
}
