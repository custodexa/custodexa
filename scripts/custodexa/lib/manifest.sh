# shellcheck shell=bash
# MANIFEST.json without jq. The file is written by jq with two-space indentation, so every line has
# one of a few fixed shapes; each line is matched against them and anything else stops the reading.
# Values land in CX_MF["<path>"], the path joined with dots (array items get their index):
#   CX_MF[version]=1.13.0   CX_MF[images.backend.platforms.amd64.config_digest]=sha256:...
# Strings may not contain a quote or a backslash (jq would have escaped them; the reader refuses).

declare -gA CX_MF=()
declare -ga CX_MF_IMAGES=()
readonly CX_MANIFEST_FORMAT=1

# The file is only read; the FAIL line goes to the terminal.
# shellcheck disable=SC2094
# cx_manifest_load <file>: 0 when the whole file has the expected shape; otherwise a FAIL line
# naming the file and line, and 1.
cx_manifest_load() {
  local file=$1 line n=0 depth=0 indent key val rest
  local -a stack=() kind=() idx=()
  CX_MF=()
  CX_MF_IMAGES=()
  if [ ! -f "$file" ]; then
    cx_line FAIL "$(cx_msg manifest_missing "$file")"
    return 1
  fi
  local LC_ALL=C
  while IFS= read -r line || [ -n "$line" ]; do
    n=$((n + 1))
    if [ "$n" -eq 1 ]; then
      [ "$line" = "{" ] || { cx_manifest_bad "$file" "$n"; return 1; }
      stack=("") kind=(o) idx=(0) depth=1
      continue
    fi
    [ "$depth" -gt 0 ] || { cx_manifest_bad "$file" "$n"; return 1; }
    rest=${line#"${line%%[! ]*}"}
    indent=$((${#line} - ${#rest}))
    # A closing bracket sits one level out.
    if [[ $rest =~ ^[]}],?$ ]]; then
      [ "$indent" -eq $(((depth - 1) * 2)) ] || { cx_manifest_bad "$file" "$n"; return 1; }
      depth=$((depth - 1))
      unset 'stack[depth]' 'kind[depth]' 'idx[depth]'
      continue
    fi
    [ "$indent" -eq $((depth * 2)) ] || { cx_manifest_bad "$file" "$n"; return 1; }
    local base=${stack[depth - 1]}
    if [ "${kind[depth - 1]}" = a ]; then
      key=${idx[depth - 1]}
      idx[depth - 1]=$((key + 1))
      val=$rest
    # Keys include language tags (notes."zh-TW"), so upper case is allowed.
    elif [[ $rest =~ ^\"([A-Za-z0-9_.-]+)\":\ (.*)$ ]]; then
      key=${BASH_REMATCH[1]}
      val=${BASH_REMATCH[2]}
    else
      cx_manifest_bad "$file" "$n"
      return 1
    fi
    local path=${base:+$base.}$key
    if [[ $val =~ ^\"([^\"\\]*)\",?$ || $val =~ ^(-?[0-9]+|true|false|null),?$ ]]; then
      CX_MF[$path]=${BASH_REMATCH[1]}
    elif [[ $val =~ ^(\[\]|\{\}),?$ ]]; then
      CX_MF[$path]=""
    elif [ "$val" = "{" ] || [ "$val" = "[" ]; then
      stack[depth]=$path
      kind[depth]=o
      [ "$val" = "[" ] && kind[depth]=a
      idx[depth]=0
      depth=$((depth + 1))
      [[ $path =~ ^images\.([a-z0-9_-]+)$ ]] && CX_MF_IMAGES+=("${BASH_REMATCH[1]}")
    else
      cx_manifest_bad "$file" "$n"
      return 1
    fi
  done <"$file"
  if [ "$depth" -ne 0 ] || [ "${CX_MF[format]:-}" != "$CX_MANIFEST_FORMAT" ] || [ -z "${CX_MF[version]:-}" ]; then
    cx_manifest_bad "$file" "$n"
    return 1
  fi
}

cx_manifest_bad() { cx_line FAIL "$(cx_msg manifest_bad "$1" "$2")"; }

# cx_mf <path>: the value, empty when absent.
cx_mf() { printf '%s' "${CX_MF[$1]:-}"; }

# cx_mf_needed_bytes <arch>: bytes to plan for in the Docker data folder. The MANIFEST lists
# compressed sizes; unpacked images take more, and how much more depends on the image store
# (the classic store keeps layers unpacked). Three times the compressed total is the estimate.
cx_mf_needed_bytes() {
  local arch=$1 name total=0
  for name in "${CX_MF_IMAGES[@]}"; do
    total=$((total + ${CX_MF[images.$name.platforms.$arch.size]:-0}))
  done
  printf '%s' $((total * 3))
}
