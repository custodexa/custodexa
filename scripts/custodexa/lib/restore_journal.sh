# shellcheck shell=bash
# Durable, ordered filesystem intents. Parameters are base64 fields (never shell code).
# A stable operation name lets a stage be rerun without renaming its retained data again.
# shellcheck disable=SC2034,SC2015
CX_RS_J_SEQ=0 CX_RS_J_ID="" CX_RS_J_KIND="" CX_RS_J_RESULT=""
declare -ga CX_RS_J_ARGS=() CX_RS_J_LINES=()
declare -gA CX_RS_J_DONE=() CX_RS_J_IDS=()

cx_rs_journal_error() {
  cx_line FAIL "$(cx_msg rs_journal_uncertain "${CX_RS_J_KIND:-journal}")"
  cx_rs_par "${1:-${CX_RS_JOURNAL:-$CX_RS_DIR/journal}}"
  [ -z "${2:-}" ] || cx_rs_par "$2"
  cx_rs_par "$(cx_msg rs_journal_guide)"
  return 1
}
cx_rs_journal_append() {
  (umask 077; printf '%s\n' "$*" >>"${CX_RS_JOURNAL:-$CX_RS_DIR/journal}") &&
    chmod 0600 "${CX_RS_JOURNAL:-$CX_RS_DIR/journal}" && sync -f "${CX_RS_JOURNAL:-$CX_RS_DIR/journal}"
}
cx_rs_journal_parse() {
  local seq mark kind id field v
  local -a fields=()
  read -r -a fields <<<"$1"
  [ "${#fields[@]}" -ge 4 ] || return 1
  seq=${fields[0]} mark=${fields[1]} kind=${fields[2]} id=${fields[3]}
  [[ $seq =~ ^[1-9][0-9]*$ && $mark = intent && $id =~ ^[a-z0-9_.-]+$ ]] || return 1
  case $kind in
    move|mkdir|leaf) [ "${#fields[@]}" = 6 ] || return 1 ;;
    put) [ "${#fields[@]}" = 9 ] || return 1 ;;
    link|state|mode) [ "${#fields[@]}" = 7 ] || return 1 ;;
    *) return 1 ;;
  esac
  CX_RS_J_SEQ=$seq CX_RS_J_KIND=$kind CX_RS_J_ID=$id CX_RS_J_ARGS=()
  for field in "${fields[@]:4}"; do
    [[ $field =~ ^[A-Za-z0-9+/=]+$ || $field = - ]] || return 1
    if [ "$field" = - ]; then v=""
    else v=$(printf '%s' "$field" | base64 -d) || return 1; fi
    CX_RS_J_ARGS+=("$v")
  done
}
cx_rs_journal_load() {
  local line seq mark extra next=1
  CX_RS_J_LINES=() CX_RS_J_DONE=() CX_RS_J_IDS=()
  [ -f "${CX_RS_JOURNAL:-$CX_RS_DIR/journal}" ] || return 0
  while IFS= read -r line || [ -n "$line" ]; do
    read -r seq mark extra <<<"$line"
    case $mark in
      intent)
        cx_rs_journal_parse "$line" && [ "$CX_RS_J_SEQ" = "$next" ] &&
          [ -z "${CX_RS_J_IDS[$CX_RS_J_ID]:-}" ] || { cx_rs_journal_error; return 1; }
        CX_RS_J_LINES+=("$line") CX_RS_J_IDS[$CX_RS_J_ID]=$seq
        next=$((next + 1)) ;;
      done)
        [[ $seq =~ ^[1-9][0-9]*$ ]] && [ "$seq" -lt "$next" ] && [ -z "$extra" ] || {
          cx_rs_journal_error; return 1;
        }
        CX_RS_J_DONE[$seq]=1 ;;
      *) cx_rs_journal_error; return 1 ;;
    esac
  done <"${CX_RS_JOURNAL:-$CX_RS_DIR/journal}"
}
cx_rs_exists() { [ -e "$1" ] || [ -L "$1" ]; }
cx_rs_file_hash() {
  if ! cx_rs_exists "$1"; then printf 'absent'
  elif [ -f "$1" ] && [ ! -L "$1" ]; then cx_pb_sha "$1"
  else return 1; fi
}
# Read only. Pending operations are all classified before reconciliation changes anything.
cx_rs_journal_probe() {
  local a=${CX_RS_J_ARGS[0]} b=${CX_RS_J_ARGS[1]} value
  CX_RS_J_RESULT=unknown
  case $CX_RS_J_KIND in
    move)
      if cx_rs_exists "$a"; then cx_rs_exists "$b" || CX_RS_J_RESULT=pending
      elif cx_rs_exists "$b"; then CX_RS_J_RESULT='done'; fi ;;
    mkdir)
      if ! cx_rs_exists "$a"; then CX_RS_J_RESULT=pending
      elif [ -d "$a" ] && [ ! -L "$a" ] && [ "$(stat -c %a "$a")" = "${b#0}" ]; then CX_RS_J_RESULT='done'; fi ;;
    put)
      value=$(cx_rs_file_hash "$b") || return 1
      if [ "$value" = "${CX_RS_J_ARGS[3]}" ] && [ "$(stat -c %a "$b")" = "${CX_RS_J_ARGS[4]#0}" ]; then CX_RS_J_RESULT='done'
      elif [ "$value" = "${CX_RS_J_ARGS[2]}" ]; then CX_RS_J_RESULT=pending; fi ;;
    link)
      if [ -L "$a" ]; then value=$(readlink -- "$a")
      elif ! cx_rs_exists "$a"; then value=absent
      else return 1; fi
      if [ "$value" = "${CX_RS_J_ARGS[2]}" ]; then CX_RS_J_RESULT='done'
      elif [ "$value" = "$b" ]; then CX_RS_J_RESULT=pending; fi ;;
    leaf)
      if [ -s "$b/fullchain.pem" ] && [ -s "$b/privkey.pem" ]; then CX_RS_J_RESULT='done'
      else CX_RS_J_RESULT=pending; fi ;;
    mode)
      if [ -e "$a" ] && [ ! -L "$a" ]; then
        if [ "$(stat -c '%u:%g %a' "$a")" = "$b ${CX_RS_J_ARGS[2]#0}" ]; then CX_RS_J_RESULT='done'
        else CX_RS_J_RESULT=pending; fi
      fi ;;
    state)
      value=$(cx_state_get "$a")
      if [ "$value" = "${CX_RS_J_ARGS[2]}" ]; then CX_RS_J_RESULT='done'
      elif [ "$value" = "$b" ]; then CX_RS_J_RESULT=pending; fi ;;
  esac
  [ "$CX_RS_J_RESULT" != unknown ]
}
cx_rs_journal_apply() {
  local a=${CX_RS_J_ARGS[0]} b=${CX_RS_J_ARGS[1]} tmp
  case $CX_RS_J_KIND in
    move) mv -T -- "$a" "$b" && sync -f "${b%/*}" ;;
    mkdir) mkdir -m "$b" -- "$a" && sync -f "${a%/*}" ;;
    put)
      [ "$(cx_rs_file_hash "$a")" = "${CX_RS_J_ARGS[3]}" ] || return 1
      tmp=$b.restore-$CX_RS_TS-$CX_RS_J_SEQ.tmp
      (umask 077; cp -- "$a" "$tmp") && chmod "${CX_RS_J_ARGS[4]}" "$tmp" &&
        sync -f "$tmp" && mv -T -- "$tmp" "$b" && sync -f "${b%/*}" ;;
    link)
      tmp=$a.restore-$CX_RS_TS-$CX_RS_J_SEQ.tmp
      ln -sfn -- "${CX_RS_J_ARGS[2]}" "$tmp" && mv -T -- "$tmp" "$a" && sync -f "${a%/*}" ;;
    leaf)
      cx_compose_release "$a" run --rm --no-deps --name "custodexa-restore-tool-$CX_RS_TS-tls" tls-init &&
        [ -s "$b/fullchain.pem" ] && [ -s "$b/privkey.pem" ] && sync -f "$b" ;;
    mode) chown "$b" "$a" && chmod "${CX_RS_J_ARGS[2]}" "$a" && sync -f "$a" ;;
    state)
      if [ -n "${CX_RS_J_ARGS[2]}" ]; then cx_state_set "$a" "${CX_RS_J_ARGS[2]}" || return 1
      else cx_state_unset "$a"; fi
      cx_rs_save && sync -f "$CX_ROOT/state.json" ;;
  esac
}
# A crash may land after a rename but before its filesystem was flushed. Reconciliation must
# flush that filesystem too, even when the journal lives on a different mount.
cx_rs_journal_sync() {
  local path
  case $CX_RS_J_KIND in
    move|put|leaf) path=${CX_RS_J_ARGS[1]} ;;
    mkdir|link|mode) path=${CX_RS_J_ARGS[0]} ;;
    state) path=$CX_ROOT/state.json ;;
  esac
  sync -f "${path%/*}"
}
# mode=resume redoes pending intents; mode=exit leaves untouched intents alone. Completed
# operations always get their missing done record. An ambiguity refuses before any replay.
cx_rs_reconcile() {
  local mode=${1:-resume} line seq
  cx_rs_journal_load || return 1
  for line in "${CX_RS_J_LINES[@]}"; do
    cx_rs_journal_parse "$line" || return 1
    [ "${CX_RS_J_DONE[$CX_RS_J_SEQ]:-}" != 1 ] || continue
    cx_rs_journal_probe || { cx_rs_journal_error "${CX_RS_J_ARGS[0]}" "${CX_RS_J_ARGS[1]}"; return 1; }
  done
  for line in "${CX_RS_J_LINES[@]}"; do
    cx_rs_journal_parse "$line" || return 1
    seq=$CX_RS_J_SEQ
    [ "${CX_RS_J_DONE[$seq]:-}" != 1 ] || continue
    cx_rs_journal_probe || return 1
    if [ "$CX_RS_J_RESULT" = pending ]; then
      [ "$mode" = resume ] || continue
      cx_rs_journal_apply || return 1
    else
      cx_rs_journal_sync || return 1
    fi
    cx_rs_journal_append "$seq done" || return 1
    CX_RS_J_DONE[$seq]=1
  done
}
cx_rs_covering() {
  [ "$(cx_state_get last_restore.covering)" != 1 ] || return 0
  # An empty, durable journal is valid when interrupted before the first intent.
  (umask 077; : >>"${CX_RS_JOURNAL:-$CX_RS_DIR/journal}") && sync -f "${CX_RS_JOURNAL:-$CX_RS_DIR/journal}" || return 1
  cx_state_set last_restore.covering 1 && cx_rs_save && sync -f "$CX_ROOT/state.json"
}
# cx_rs_journal <stable name> <action> <parameters...>. No operation runs before its durable
# intent, and no intent runs before the durable covering flag.
cx_rs_journal() {
  local id=$1 kind=$2 line field seq
  shift 2
  cx_rs_journal_load || return 1
  if [ -n "${CX_RS_J_IDS[$id]:-}" ]; then cx_rs_reconcile resume; return "$?"; fi
  seq=$((${#CX_RS_J_LINES[@]} + 1))
  line="$seq intent $kind $id"
  for field in "$@"; do
    if [ -n "$field" ]; then line+=" $(printf '%s' "$field" | base64 -w0)"
    else line+=' -'; fi
  done
  cx_rs_journal_parse "$line" || return 1
  # Check the intended old state before claiming anything was changed.
  cx_rs_journal_probe || { cx_rs_journal_error "$1" "${2:-}"; return 1; }
  cx_rs_covering && cx_rs_journal_append "$line" || return 1
  if [ "$CX_RS_J_RESULT" = "done" ]; then cx_rs_journal_sync || return 1
  else cx_rs_journal_apply || return 1; fi
  # Checkpoint the restore state after each completed operation as well as at stage changes.
  cx_rs_journal_append "$seq done" && cx_rs_save
}
cx_rs_journal_move() {
  cx_rs_journal_load || return 1
  if [ -n "${CX_RS_J_IDS[$1]:-}" ] || cx_rs_exists "$2"; then cx_rs_journal "$1" move "$2" "$3"; fi
}
cx_rs_journal_put() {
  local old new
  cx_rs_journal_load || return 1
  if [ -n "${CX_RS_J_IDS[$1]:-}" ]; then cx_rs_reconcile resume; return "$?"; fi
  old=$(cx_rs_file_hash "$3") && new=$(cx_rs_file_hash "$2") || return 1
  [ "$new" != absent ] || return 1
  cx_rs_journal "$1" put "$2" "$3" "$old" "$new" "$4"
}
# These snapshots precede the first restore state write and are never overwritten on resume.
cx_rs_preserve_before() {
  local src dst
  umask 077
  mkdir -p -- "$CX_RS_DIR" && chmod 0700 "$CX_RS_DIR" || return 1
  for src in state.json .env; do
    case $src in state.json) dst=state-before.json ;; .env) dst=env-before-restore ;; esac
    [ ! -e "$CX_RS_DIR/$dst" ] || continue
    [ -f "$CX_ROOT/$src" ] || continue
    cp -- "$CX_ROOT/$src" "$CX_RS_DIR/$dst.tmp" && chmod 0600 "$CX_RS_DIR/$dst.tmp" &&
      sync -f "$CX_RS_DIR/$dst.tmp" && mv -- "$CX_RS_DIR/$dst.tmp" "$CX_RS_DIR/$dst" || return 1
  done
  sync -f "$CX_RS_DIR"
}
cx_rs_swapped() {
  [ "$(cx_state_get last_restore.services)" = all-stopped ] || return 1
  cx_rs_reconcile resume || return 1
  # An external database keeps no folder on this host: none is renamed or made for it.
  if ! cx_rs_ext; then
    cx_rs_journal_move postgres-before "$CX_RS_DATA/postgres" "$CX_RS_DATA/postgres.${CX_RS_KEEP_KIND:-before-restore}-$CX_RS_TS" || return 1
  fi
  cx_rs_journal_move audit-before "$CX_RS_DATA/audit" "$CX_RS_DATA/audit.${CX_RS_KEEP_KIND:-before-restore}-$CX_RS_TS" || return 1
  if [ "$(cx_rs_get contents.tls)" = true ]; then
    cx_rs_journal_move tls-before "$CX_ROOT/tls" "$CX_ROOT/tls.${CX_RS_KEEP_KIND:-before-restore}-$CX_RS_TS" || return 1
  fi
  if ! cx_rs_ext; then cx_rs_journal postgres-empty mkdir "$CX_RS_DATA/postgres" 0700 || return 1; fi
  cx_rs_journal_put env-merged "$CX_RS_DIR/env.merged" "$CX_ROOT/.env" 0600 &&
    cx_rs_phase swapped
}
# Placement primitives are shared by the file stage and exits. The file stage supplies its
# already validated paths and release state; none of these helpers advances the stage itself.
cx_rs_template_place() {
  CX_RS_TEMPLATE_UNCHANGED=0
  [ -n "$CX_RS_TEMPLATE" ] || return 0
  cx_rs_journal_load || return 1
  if [ -z "${CX_RS_J_IDS[template-place]:-}" ] && [ -f "$CX_RS_TEMPLATE" ] &&
    cmp -s "$CX_RS_TEMPLATE" "$CX_RS_DIR/pass2/nginx-tls.conf.template"; then
    CX_RS_TEMPLATE_UNCHANGED=1
    return 0
  fi
  if [ -n "${CX_RS_J_IDS[template-before]:-}" ] ||
    { [ -f "$CX_RS_TEMPLATE" ] && ! cmp -s "$CX_RS_TEMPLATE" "$CX_RS_DIR/pass2/nginx-tls.conf.template"; }; then
    cx_rs_journal_move template-before "$CX_RS_TEMPLATE" "$CX_RS_TEMPLATE.${CX_RS_KEEP_KIND:-before-restore}-$CX_RS_TS" || return 1
  fi
  cx_rs_journal_put template-place "$CX_RS_DIR/pass2/nginx-tls.conf.template" "$CX_RS_TEMPLATE" 0644
}
cx_rs_leaf_keep() {
  local name dest=$CX_ROOT/tls/leaf.before-restore-$CX_RS_TS
  cx_rs_journal leaf-folder mkdir "$dest" 0700 || return 1
  for name in fullchain.pem privkey.pem; do
    cx_rs_journal_move "leaf-$name" "$CX_ROOT/tls/$name" "$dest/$name" || return 1
  done
}
cx_rs_switch_release() {
  local old=absent
  [ ! -L "$CX_ROOT/current" ] || old=$(readlink "$CX_ROOT/current")
  cx_rs_journal current-link link "$CX_ROOT/current" "$old" "releases/$1"
}
cx_rs_current_set() { cx_rs_journal "current-$1" state "current.$1" "$(cx_state_get "current.$1")" "$2"; }

# Resolve the exit route independently of phase, before the caller enters its exit stages.
# Losing the journal cannot turn a covering restore into a restart of the original services.
cx_rs_recovery_route() {
  local action=$1
  CX_RS_RECOVERY=""
  if [ "$action" = resume ] && [ "$(cx_state_get last_restore.covering)" = 1 ] && [ ! -f "${CX_RS_JOURNAL:-$CX_RS_DIR/journal}" ]; then
    cx_line FAIL "$(cx_msg rs_journal_missing)"; cx_cmd "$(cx_rs_control_command revert)"; return 1
  fi
  if [ "$action" = resume ]; then cx_rs_reconcile resume || return 1; CX_RS_RECOVERY=resume; return 0; fi
  cx_rs_reconcile exit || return 1
  if [ "$action" = abandon ]; then CX_RS_RECOVERY=abandon; return 0; fi
  if [ "$(cx_state_get last_restore.covering)" != 1 ]; then CX_RS_RECOVERY=original
  elif [ "$(cx_state_get last_restore.safety)" = script ]; then CX_RS_RECOVERY=safety
  else CX_RS_RECOVERY=own; fi
}
