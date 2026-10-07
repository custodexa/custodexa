# shellcheck shell=bash
# state.json: a flat JSON object, one key per line, string values from a restricted character set,
# read without jq by matching every line against one fixed shape.
#
#   {
#     "format": "2",
#     "current.version": "1.13.0"
#   }
#
# Keys: [a-z0-9_.]+ (the dots are only naming). Values: printable ASCII except " and \.
# Writing: temporary file in the same folder, sync, keep the old file as state.json.prev, rename.

readonly CX_STATE_FORMAT=2
declare -gA CX_STATE=()
declare -ga CX_STATE_KEYS=()

cx_state_valid_key() { local LC_ALL=C; [[ $1 =~ ^[a-z0-9_.]+$ ]]; }
cx_state_valid_value() {
  local LC_ALL=C
  [[ $1 != *[!\ -~]* && $1 != *'"'* && $1 != *\\* ]]
}

cx_state_reset() {
  CX_STATE=()
  CX_STATE_KEYS=()
}

# cx_flat_parse <file> <map name> <keys name>: read a file of this shape into the associative
# array and the key list named, nothing else (no format check, no global state touched). Returns 1
# at the first deviation with CX_FLAT_BAD set to the line to report; a missing file is empty.
# The backup manifest (lib/portable.sh) uses the same shape and is read with this too.
CX_FLAT_BAD=0
cx_flat_parse() {
  local file=$1 n=0 line key val total last_comma=1 re
  local -n cxf_map=$2 cxf_keys=$3
  local -a lines=()
  cxf_map=()
  cxf_keys=()
  CX_FLAT_BAD=0
  [ -f "$file" ] || return 0
  mapfile -t lines <"$file"
  total=${#lines[@]}
  re='^  "([a-z0-9_.]+)": "([^"\\]*)"(,?)$'
  if [ "$total" -lt 2 ] || [ "${lines[0]}" != "{" ]; then
    CX_FLAT_BAD=1
    return 1
  fi
  for ((n = 1; n < total - 1; n++)); do
    line=${lines[n]}
    if [ "$last_comma" != 1 ]; then
      CX_FLAT_BAD=$n
      return 1
    fi
    if ! LC_ALL=C cx_state_match "$line" "$re"; then
      CX_FLAT_BAD=$((n + 1))
      return 1
    fi
    key=${BASH_REMATCH[1]}
    val=${BASH_REMATCH[2]}
    last_comma=0
    [ -n "${BASH_REMATCH[3]}" ] && last_comma=1
    if ! cx_state_valid_value "$val" || [ -n "${cxf_map[$key]+x}" ]; then
      CX_FLAT_BAD=$((n + 1))
      return 1
    fi
    cxf_map["$key"]=$val
    cxf_keys+=("$key")
  done
  if [ "${lines[total - 1]}" != "}" ]; then
    CX_FLAT_BAD=$total
    return 1
  fi
  if [ "$total" -gt 2 ] && [ "$last_comma" = 1 ]; then
    CX_FLAT_BAD=$((total - 1))
    return 1
  fi
}

# cx_state_load <file>: read and check the whole file. Any deviation stops the program (exit 5).
cx_state_load() {
  local file=$1
  cx_state_reset
  [ -f "$file" ] || return 0
  cx_flat_parse "$file" CX_STATE CX_STATE_KEYS || cx_state_bad "$file" "$CX_FLAT_BAD"
  if [ "${CX_STATE[format]:-}" != "$CX_STATE_FORMAT" ]; then
    cx_state_bad "$file" 2
  fi
}

cx_state_match() { [[ $1 =~ $2 ]]; }

# cx_state_bad <file> <line>: name the file, the line and the previous copy, then stop.
cx_state_bad() {
  local file=$1 n=$2
  cx_line FAIL "$(cx_msg state_bad "$file" "$n")" >&2
  printf '%s\n' "$(cx_msg state_bad_prev "$file.prev")" >&2
  cx_cmd "cp $file.prev $file" >&2
  exit "$CX_EXIT_STATE"
}

cx_state_get() { printf '%s' "${CX_STATE[$1]:-}"; }

# cx_state_set <key> <value>: a value outside the character set, or one holding a masked .env value
# (lib/log.sh), is a bug in the caller: stop.
cx_state_set() {
  local key=$1 val=$2
  if ! cx_state_valid_key "$key" || ! cx_state_valid_value "$val" || cx_has_secret "$val"; then
    printf 'custodexa.sh: internal error: refusing to store key %q\n' "$key" >&2
    return 1
  fi
  [ -n "${CX_STATE[$key]+x}" ] || CX_STATE_KEYS+=("$key")
  CX_STATE[$key]=$val
}

# cx_state_unset <key>: drop the key (a pointer that no longer describes the record).
cx_state_unset() {
  local key=$1 k
  local -a keep=()
  [ -n "${CX_STATE[$key]+x}" ] || return 0
  unset 'CX_STATE[$key]'
  for k in "${CX_STATE_KEYS[@]}"; do
    [ "$k" = "$key" ] || keep+=("$k")
  done
  CX_STATE_KEYS=("${keep[@]}")
}

# cx_state_save <file>: write every key in insertion order; format first.
cx_state_save() {
  local file=$1 tmp i key sep
  [ -n "${CX_STATE[format]+x}" ] || cx_state_set format "$CX_STATE_FORMAT"
  tmp="$file.tmp-$$"
  {
    printf '{\n'
    local -a keys=(format)
    for key in "${CX_STATE_KEYS[@]}"; do
      [ "$key" = format ] || keys+=("$key")
    done
    for ((i = 0; i < ${#keys[@]}; i++)); do
      sep=,
      [ "$i" -eq $((${#keys[@]} - 1)) ] && sep=
      printf '  "%s": "%s"%s\n' "${keys[i]}" "${CX_STATE[${keys[i]}]}" "$sep"
    done
    printf '}\n'
  } >"$tmp" || { rm -f "$tmp"; return 1; }
  sync "$tmp" 2>/dev/null || sync
  if [ -f "$file" ]; then
    cp -p "$file" "$file.prev.tmp-$$" && mv -f "$file.prev.tmp-$$" "$file.prev"
  fi
  mv -f "$tmp" "$file"
}
