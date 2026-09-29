# shellcheck shell=bash
# Version rules of upgrade: never to an older version (that is a restore of the backup), never to the same version,
# and never from a version older than the target's MANIFEST min_source_version (the intermediate
# version has to be installed first). A refusal changes nothing and exits 3.
# Versions compare the way semantic versions do: MAJOR.MINOR.PATCH as numbers, and a pre-release
# (1.13.0-rc.2) sorts before its release; its dot-separated parts compare as numbers when both are
# numbers, as text otherwise, a number before text, and a shorter list first.

# cx_vr_valid <version>
cx_vr_valid() {
  local LC_ALL=C
  [[ $1 =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$ ]]
}

# cx_vr_num_cmp <a> <b>: -1, 0 or 1 for two decimal numbers of any length.
cx_vr_num_cmp() {
  local a=$1 b=$2
  if [ "${#a}" -ne "${#b}" ]; then
    [ "${#a}" -lt "${#b}" ] && printf -- '-1' || printf '1'
    return 0
  fi
  if [[ $a < $b ]]; then printf -- '-1'; elif [[ $a > $b ]]; then printf '1'; else printf '0'; fi
}

# cx_vr_cmp <a> <b>: -1, 0 or 1. Fails (status 2) when either is not a version.
cx_vr_cmp() {
  local a=$1 b=$2 ca cb i r pa pb
  cx_vr_valid "$a" && cx_vr_valid "$b" || return 2
  local -a na nb ra rb
  IFS=. read -ra na <<<"${a%%-*}"
  IFS=. read -ra nb <<<"${b%%-*}"
  for i in 0 1 2; do
    r=$(cx_vr_num_cmp "${na[i]}" "${nb[i]}")
    [ "$r" = 0 ] || { printf '%s' "$r"; return 0; }
  done
  pa="" pb=""
  [[ $a == *-* ]] && pa=${a#*-}
  [[ $b == *-* ]] && pb=${b#*-}
  # A release sorts after any of its pre-releases.
  if [ -z "$pa" ] || [ -z "$pb" ]; then
    if [ -z "$pa" ] && [ -z "$pb" ]; then printf '0'
    elif [ -z "$pa" ]; then printf '1'
    else printf -- '-1'; fi
    return 0
  fi
  IFS=. read -ra ra <<<"$pa"
  IFS=. read -ra rb <<<"$pb"
  for ((i = 0; i < ${#ra[@]} || i < ${#rb[@]}; i++)); do
    [ "$i" -lt "${#ra[@]}" ] || { printf -- '-1'; return 0; }
    [ "$i" -lt "${#rb[@]}" ] || { printf '1'; return 0; }
    ca=${ra[i]} cb=${rb[i]}
    if [[ $ca =~ ^[0-9]+$ && $cb =~ ^[0-9]+$ ]]; then
      r=$(cx_vr_num_cmp "$ca" "$cb")
    elif [[ $ca =~ ^[0-9]+$ ]]; then
      r=-1
    elif [[ $cb =~ ^[0-9]+$ ]]; then
      r=1
    else
      local LC_ALL=C
      if [[ $ca < $cb ]]; then r=-1; elif [[ $ca > $cb ]]; then r=1; else r=0; fi
    fi
    [ "$r" = 0 ] || { printf '%s' "$r"; return 0; }
  done
  printf '0'
}

# cx_vr_check <current> <target> [min_source_version]: 0 when the upgrade is allowed. Otherwise the
# refusal screen and 3 (2 when a version is not a version). Nothing is changed either way.
cx_vr_check() {
  local cur=$1 tgt=$2 min=${3:-} r
  if ! r=$(cx_vr_cmp "$tgt" "$cur"); then
    cx_line FAIL "$(cx_msg vr_bad_version "$tgt")"
    return 2
  fi
  case $r in
    -1)
      cx_line FAIL "$(cx_msg vr_older "$tgt" "$cur")"
      printf '\n%s\n' "$(cx_msg vr_older_detail | sed 's/^/  /')"
      printf '\n%s\n' "$(cx_msg pre_nothing_changed)"
      return 3
      ;;
    0)
      cx_line FAIL "$(cx_msg vr_same "$tgt")"
      printf '\n%s\n' "$(cx_msg vr_same_detail | sed 's/^/  /')"
      cx_cmd "sudo $CX_ROOT/custodexa.sh status$(cx_status_lang_arg)"
      printf '\n%s\n' "$(cx_msg pre_nothing_changed)"
      return 3
      ;;
  esac
  [ -n "$min" ] || return 0
  if ! r=$(cx_vr_cmp "$cur" "$min"); then
    cx_line FAIL "$(cx_msg vr_bad_version "$min")"
    return 2
  fi
  if [ "$r" = -1 ]; then
    cx_line FAIL "$(cx_msg vr_skip "$tgt" "$cur" "$min")"
    printf '\n%s\n' "$(cx_msg vr_skip_detail "$min" "$tgt" | sed 's/^/  /')"
    cx_cmd "sudo $CX_ROOT/custodexa.sh upgrade $min"
    printf '\n%s\n' "$(cx_msg pre_nothing_changed)"
    return 3
  fi
}
