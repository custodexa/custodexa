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

# cx_state_load <file>: read and check the whole file. Any deviation stops the program (exit 5).
cx_state_load() {
  local file=$1 n=0 line key val total last_comma=1 re
  local -a lines=()
  cx_state_reset
  if [ ! -f "$file" ]; then
    return 0
  fi
  mapfile -t lines <"$file"
  total=${#lines[@]}
  re='^  "([a-z0-9_.]+)": "([^"\\]*)"(,?)$'
  if [ "$total" -lt 2 ] || [ "${lines[0]}" != "{" ]; then
    cx_state_bad "$file" 1
  fi
  for ((n = 1; n < total - 1; n++)); do
    line=${lines[n]}
    if [ "$last_comma" != 1 ]; then
      cx_state_bad "$file" "$n"
    fi
    if ! LC_ALL=C cx_state_match "$line" "$re"; then
      cx_state_bad "$file" $((n + 1))
    fi
    key=${BASH_REMATCH[1]}
    val=${BASH_REMATCH[2]}
    last_comma=0
    [ -n "${BASH_REMATCH[3]}" ] && last_comma=1
    if ! cx_state_valid_value "$val" || [ -n "${CX_STATE[$key]+x}" ]; then
      cx_state_bad "$file" $((n + 1))
    fi
    CX_STATE[$key]=$val
    CX_STATE_KEYS+=("$key")
  done
  if [ "${lines[total - 1]}" != "}" ]; then
    cx_state_bad "$file" "$total"
  fi
  if [ "$total" -gt 2 ] && [ "$last_comma" = 1 ]; then
    cx_state_bad "$file" $((total - 1))
  fi
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
