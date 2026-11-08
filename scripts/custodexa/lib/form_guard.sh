# shellcheck shell=bash
# CX_FG_* results are read by the callers.
# shellcheck disable=SC2034
# The check that runs before an entry changes the deployment: what .env says the deployment is
# (lib/form.sh derives it from two keys) must be what the deployment is (state.json, the data
# folder). Each refusal prints what was found, why it cannot go on and what to do, leaves every file
# as it was and returns 3. A run that passes also puts the managed block of .env in place, except
# for `upgrade` (its block is written after the switch of `current`) and for a run that passed only
# because of the old notation of an external ingress.

CX_FG_EXC=0 # 1: the old notation of an external ingress was accepted; the block is not written

# cx_fg_cmd <command>: the command to run again, as it was typed.
cx_fg_cmd() {
  printf 'sudo %s/custodexa.sh %s%s%s' "$CX_ROOT" "$1" \
    "${CX_ARGS[*]:+ ${CX_ARGS[*]}}" "${CX_FLAGS_TEXT:-}"
}

# cx_fg_head <message id> [args...]: the FAIL line of a refusal.
cx_fg_head() { cx_line FAIL "$(cx_msg "$@")" >&2; }
# cx_fg_text <message id> [args...]: the lines under it, with their own indentation.
cx_fg_text() { printf '%s\n' "$(cx_msg "$@")" >&2; }
cx_fg_rerun() {
  printf '%s\n' "$(cx_msg fm_rerun)" >&2
  printf '    %s\n' "$(cx_fg_cmd "$1")" >&2
}

# cx_fg_data_root: the folder the built-in database keeps its data in.
cx_fg_data_root() {
  local d
  d=$(cx_form_trim "$(cx_env_get "$CX_ROOT/.env" DATA_PATH)")
  if [ -z "$d" ] || [ "$d" = ./data ]; then d=$CX_ROOT/data; fi
  printf '%s' "$d"
}

# cx_fg_data_dirs: the built-in database folders that hold data (1.22 and before: postgres,
# later: postgresql), one per line.
cx_fg_data_dirs() {
  local root d
  root=$(cx_fg_data_root)
  for d in postgres postgresql; do
    if [ -d "$root/$d" ] && [ -n "$(ls -A "$root/$d" 2>/dev/null)" ]; then printf '%s\n' "$root/$d"; fi
  done
}

# cx_fg_pending: the upgrade began converting .env and .env is still what it was before.
cx_fg_pending() {
  local from
  [ "$(cx_state_get last_upgrade.env_rewrite)" = pending ] || return 1
  from=$(cx_state_get last_upgrade.env_rewrite_from)
  [ -n "$from" ] && [ -f "$CX_ROOT/.env" ] || return 1
  [ "$(sha256sum "$CX_ROOT/.env" | cut -d' ' -f1)" = "$from" ]
}

# cx_form_legacy_check <env file>: a COMPOSE_FILE of the old notation must say what the two keys
# say. Return 1 and print the refusal when it lists something the keys do not (an external database
# without an address, an external ingress without TLS_MODE=external). The unknown values are
# cx_env_generate's to refuse.
cx_form_legacy_check() {
  local cf
  cf=$(cx_form_trim "$(cx_env_get "$1" COMPOSE_FILE)")
  [ -n "$cf" ] || return 0
  if [[ $cf == *compose.external-database.yml* ]] && [ -z "$(cx_form_db_host "$1")" ]; then
    cx_fg_head fm_legacy_db "$cf"
    return 1
  fi
  if [[ $cf == *compose.external-ingress.yml* ]] && [ "$(cx_form_tls_mode "$1")" != external ]; then
    cx_fg_head fm_legacy_ingress "$cf" "$(cx_form_tls_mode "$1")"
    return 1
  fi
}

# The COMPOSE_FILE of an upgrade's source lists the external database and the address is empty,
# so that deployment could not start in the version it runs now.
cx_fg_refuse_f09() {
  local host port rec value
  host=$(cx_state_get current.external_db_host)
  port=$(cx_state_get current.external_db_port)
  if [ -n "$host" ]; then
    rec=$(cx_msg fm_f09_rec "$host:${port:-5432}")
    value=$host
  else
    rec=$(cx_msg fm_f09_rec_none)
    value=$(cx_msg fm_e3_placeholder)
  fi
  cx_fg_head fm_f09_head "$(cx_state_get current.version)"
  cx_fg_text fm_f09_body "$rec" "$value"
  cx_fg_rerun upgrade
}

# cx_fg_suggest <bad value>: host and port to show for a value that carries more than a host name.
CX_FG_HOST="" CX_FG_PORT=""
cx_fg_suggest() {
  local v=$1
  v=${v//[\"\' ]/}
  v=${v#*://}
  v=${v%%/*}
  v=${v##*@}
  CX_FG_PORT=5432
  if [[ $v =~ ^([^:]+):([0-9]+)$ ]]; then
    v=${BASH_REMATCH[1]}
    CX_FG_PORT=${BASH_REMATCH[2]}
  fi
  case $v in "" | *[!A-Za-z0-9._-]*) v=db01.example.internal ;; esac
  CX_FG_HOST=$v
}

# The value of EXTERNAL_DB_HOST cannot be used.
cx_fg_refuse_host() {
  local v=$1 line
  line=$(cx_msg fm_host_head "$v")
  if [ "$(cx_width "$line")" -gt 66 ]; then cx_fg_head fm_host_head_wrap "$v"; else cx_fg_head fm_host_head "$v"; fi
  case $CX_FORM_REASON in
    service)
      cx_fg_text fm_host_why_service "$v"
      cx_fg_text fm_host_fill_service
      ;;
    loopback)
      cx_fg_text fm_host_why_loopback "$v"
      cx_fg_text fm_host_fill_loopback
      ;;
    *)
      cx_fg_suggest "$v"
      cx_fg_text fm_host_why_syntax
      cx_fg_text fm_host_fill_syntax "$CX_FG_HOST" "$CX_FG_PORT"
      ;;
  esac
  cx_fg_text fm_host_empty
  cx_fg_rerun "$2"
}

# A new install wants an external database, but this folder holds a built-in one.
cx_fg_refuse_n2() {
  local host=$1 d ver size first=""
  cx_fg_head fm_n2_head
  cx_fg_text fm_n2_found "$host"
  while IFS= read -r d; do
    [ -n "$d" ] || continue
    [ -n "$first" ] || first=$d
    ver=""
    [ ! -f "$d/PG_VERSION" ] || ver="PostgreSQL $(tr -d '[:space:]' <"$d/PG_VERSION")"
    size=$(cx_size_human "$(du -sk "$d" 2>/dev/null | cut -f1 | awk '{print $1 * 1024}')")
    printf '    %s    %s    %s\n' "$d" "$ver" "$size" >&2
  done <<<"$(cx_fg_data_dirs)"
  cx_fg_text fm_n2_paths "$first" "$CX_ROOT-old-postgres" "$(cx_fg_cmd install)"
}

# .env names an external database, the data is in the built-in one.
cx_fg_refuse_e2() {
  local host=$1 dir
  dir=$(cx_fg_data_dirs | head -n1)
  [ -n "$dir" ] || dir=$(cx_fg_data_root)/postgres
  cx_fg_head fm_e2_head
  cx_fg_text fm_e2_body "$dir" "$host" "$(cx_fg_cmd "$2")"
}

# An external database deployment whose EXTERNAL_DB_HOST was emptied.
cx_fg_refuse_e3() {
  local host port where value
  host=$(cx_state_get current.external_db_host)
  port=$(cx_state_get current.external_db_port)
  if [ -n "$host" ]; then
    where="$host:${port:-5432}"
    cx_fg_head fm_e3_head
    cx_fg_text fm_e3_body "$where" "$host" "$(cx_fg_cmd "$1")"
  else
    where=$(cx_msg fm_e3_unknown)
    value=$(cx_msg fm_e3_placeholder)
    cx_fg_head fm_e3_head
    cx_fg_text fm_e3_body "$where" "$value" "$(cx_fg_cmd "$1")"
  fi
}

# The web entry differs from the one the deployment was installed with.
cx_fg_refuse_e4() {
  local was_ing=$1 env=$CX_ROOT/.env now was orig port
  now=$(cx_form_tls_mode "$env")
  [ -n "$now" ] || now=selfsigned
  if [ "$was_ing" = 1 ]; then
    port=$(cx_form_trim "$(cx_env_get "$env" HTTP_PORT)")
    was=$(cx_msg fm_e4_was_own "${port:-80}")
    orig=external
  else
    orig=$(cx_state_get current.tls_mode)
    [ -n "$orig" ] && [ "$orig" != external ] || orig=selfsigned
    was=$(cx_msg fm_e4_was_builtin "$orig")
  fi
  cx_fg_head fm_e4_head
  if [ "$was_ing" = 1 ]; then
    cx_fg_text fm_e4_body "$was" "$now" "$(cx_msg fm_e4_now_builtin)" "$orig" "$(cx_fg_cmd "$2")"
  else
    cx_fg_text fm_e4_body "$was" "$now" "$(cx_msg fm_e4_now_own)" "$orig" "$(cx_fg_cmd "$2")"
  fi
}

# cx_form_guard <command>: install, upgrade, start, backup, restore, rollback. Return 0 to go on,
# 3 after printing a refusal. Does nothing without a .env (the entry itself stops on that).
cx_form_guard() {
  local cmd=$1 env=$CX_ROOT/.env words host port installed=0 s_db=0 s_ing=0 i_db=0 i_ing=0 sw
  CX_FG_EXC=0
  [ -f "$env" ] || return 0
  cx_state_load "$CX_ROOT/state.json"
  if [ "$(cx_state_get current.kind)" = package ] && [ -n "$(cx_state_get current.version)" ]; then
    installed=1
  fi
  [ "$cmd" = install ] || [ "$installed" = 1 ] || return 0

  if ! words=$(cx_form_derive "$env"); then
    cx_fg_head fm_tls_bad "$(cx_form_tls_mode "$env")"
    cx_fg_text fm_tls_valid
    return "$CX_EXIT_REFUSED"
  fi
  host=$(cx_form_db_host "$env")
  if [ -n "$host" ] && ! cx_form_check_host "$host"; then
    cx_fg_refuse_host "$host" "$cmd"
    return "$CX_EXIT_REFUSED"
  fi
  port=$(cx_form_trim "$(cx_env_get "$env" EXTERNAL_DB_PORT)")
  if [ -z "$host" ] && [ -n "$port" ] && [ "$port" != 5432 ]; then
    cx_fg_head fm_port_head "$port"
    cx_fg_text fm_port_body
    cx_fg_rerun "$cmd"
    return "$CX_EXIT_REFUSED"
  fi
  if [ "$cmd" = upgrade ] && [ -z "$host" ] \
    && [[ $(cx_form_trim "$(cx_env_get "$env" COMPOSE_FILE)") == *compose.external-database.yml* ]]; then
    cx_fg_refuse_f09
    return "$CX_EXIT_REFUSED"
  fi
  [[ " $words " != *" external-database "* ]] || i_db=1
  [[ " $words " != *" external-ingress "* ]] || i_ing=1

  if [ "$cmd" = install ]; then
    cx_form_legacy_check "$env" || return "$CX_EXIT_REFUSED"
    if [ "$i_db" = 1 ] && [ -z "$(cx_state_get current.version)" ] && [ -n "$(cx_fg_data_dirs)" ]; then
      cx_fg_refuse_n2 "$host"
      return "$CX_EXIT_REFUSED"
    fi
    return 0
  fi

  sw=$(cx_state_get current.overlays)
  [[ " $sw " != *" external-database "* ]] || s_db=1
  [[ " $sw " != *" external-ingress "* ]] || s_ing=1
  if [ "$s_db" = 0 ] && [ "$i_db" = 1 ]; then
    cx_fg_refuse_e2 "$host" "$cmd"
    return "$CX_EXIT_REFUSED"
  fi
  if [ "$s_db" = 1 ] && [ "$i_db" = 0 ]; then
    cx_fg_refuse_e3 "$cmd"
    return "$CX_EXIT_REFUSED"
  fi
  if [ "$s_ing" != "$i_ing" ]; then
    if [ "$s_ing" = 1 ] && { [ "$(cx_form_layout "$CX_ROOT/current")" = overlays ] || cx_fg_pending; }; then
      CX_FG_EXC=1
    else
      cx_fg_refuse_e4 "$s_ing" "$cmd"
      return "$CX_EXIT_REFUSED"
    fi
  fi

  case $cmd in
    start | backup | restore | rollback)
      [ "$CX_FG_EXC" = 0 ] || return 0
      if cx_env_sync_managed "$env" "$(cx_form_layout "$CX_ROOT/current")" "$words"; then
        if [ -n "$CX_FORM_MOVED" ]; then
          printf '%s\n' "$(cx_msg fm_moved_note "$(printf '%s' "$CX_FORM_MOVED" | paste -sd, - | sed 's/,/, /g')")"
        fi
      else
        cx_log WARN ".env managed block not written"
      fi
      ;;
  esac
  return 0
}
