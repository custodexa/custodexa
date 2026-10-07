# shellcheck shell=bash
# The main menu: custodexa.sh without a command, on a terminal, in a package deployment.
# It lists what can be done in the deployment's state, asks only for what the chosen action needs
# and runs the matching command as its own process; the command's own confirmations stay as they
# are and the menu adds none. After the command the menu starts again from the script the
# deployment points at, so the state (and, after an upgrade, the script) is read afresh.
# Options stay for automation: without a terminal, custodexa.sh prints the help instead.

# The latest version to upgrade to comes from the check itself (lib/upgrade_query.sh cx_q_latest).
# shellcheck source=lib/version_rules.sh
. "${BASH_SOURCE[0]%/*}/version_rules.sh"
# shellcheck source=lib/upgrade_query.sh
. "${BASH_SOURCE[0]%/*}/upgrade_query.sh"

CX_MENU_SELF=""   # the script as it was started (<root>/custodexa.sh follows current/ after an upgrade)
CX_MENU_KIND=""   # none | package
CX_MENU_VERSION=""
CX_MENU_FLAGS=()  # passed on to every command: an explicit language, and --no-color when given
CX_MENU_PICK=""
CX_MENU_FILE=""
CX_MENU_IMAGE_FLAG=()

# cx_menu_applies <script as started>: 0 when the menu is for this deployment. A git clone
# deployment, or a folder that is no deployment root, keeps the help (the caller prints it).
cx_menu_applies() {
  local ver
  CX_MENU_SELF=$1
  cx_check_platform 2>/dev/null || return 1
  CX_ROOT=$(cx_resolve_root "$CX_MENU_SELF" 2>/dev/null) || return 1
  cx_check_root_path "$CX_ROOT" || return 1
  cx_state_load "$CX_ROOT/state.json"
  ver=$(cx_state_get current.version)
  if [ -z "$ver" ]; then
    CX_MENU_KIND=none
  else
    CX_MENU_KIND=package
  fi
  if [ "$(cx_state_get last_restore.result)" = in_progress ]; then CX_MENU_KIND=restore; fi
  CX_MENU_VERSION=$ver
}

# The actions of each state, in menu order; the label of <action> is MSG_menu_<action>.
cx_menu_actions() {
  case $CX_MENU_KIND in
    restore)
      case $(cx_rs_exit_action) in
        revert) printf '%s' 'rs_finish_revert status stop help' ;;
        abandon) printf '%s' 'rs_finish_abandon status stop help' ;;
        *)
          if [ "$(cx_state_get last_restore.phase)" = awaiting_unseal ]; then printf 'rs_unseal '
          else printf 'rs_resume '; fi
          printf 'status '
          ! cx_rs_start_allowed || printf 'start '
          if [ "$(cx_rs_return_action)" = revert ] && [ "$(cx_state_get last_restore.safety)" = db-dump ]; then
            printf 'stop rs_revert_export help'
          else printf 'stop rs_%s help' "$(cx_rs_return_action)"; fi ;;
      esac ;;
    none) printf '%s' "install restore_new load_first help" ;;
    package) printf '%s' "status start stop upgrade backup restore load help" ;;
  esac
}

cx_menu_item() { # <number> <label>
  printf '  [%s] %s\n' "$1" "${2//$'\n'/$'\n'      }"
}

# cx_menu_read <variable>: one answer, surrounding blanks removed. End of input (Ctrl-D) quits.
cx_menu_read() {
  if ! read -r "$1"; then
    printf '\n'
    exit "$CX_EXIT_OK"
  fi
}

# cx_menu_pick <count>: CX_MENU_PICK in 1..count; 1 = Enter, back to the main menu.
cx_menu_pick() {
  local a
  while :; do
    printf '%s' "$(cx_msg menu_choose_sub "$1")"
    cx_menu_read a
    [ -n "$a" ] || return 1
    if [[ $a =~ ^[1-9][0-9]*$ ]] && [ "$a" -le "$1" ]; then
      CX_MENU_PICK=$a
      return 0
    fi
    cx_line WARN "$(cx_msg menu_invalid)"
  done
}

# cx_menu_files <bundle | package>: the matching files in the current folder, in name order.
cx_menu_files() {
  local f
  if [ "$1" = bundle ]; then
    for f in custodexa-images-*.tar; do
      if [ -f "$f" ]; then printf '%s\n' "$f"; fi
    done
  else
    for f in custodexa-[0-9]*.tar.gz; do
      if [ -f "$f" ]; then printf '%s\n' "$f"; fi
    done
  fi
}

# cx_menu_pick_file <bundle | package>: CX_MENU_FILE, an absolute path; 1 = back to the main menu.
cx_menu_pick_file() {
  local kind=$1 f i n
  local -a files=()
  mapfile -t files < <(cx_menu_files "$kind")
  n=${#files[@]}
  if [ "$n" -gt 0 ]; then
    printf '\n%s\n' "$(cx_msg "menu_${kind}_found" "$PWD")"
    for ((i = 0; i < n; i++)); do cx_menu_item $((i + 1)) "${files[i]}"; done
    cx_menu_item $((n + 1)) "$(cx_msg menu_other_path)"
    printf '\n'
    cx_menu_pick $((n + 1)) || return 1
    if [ "$CX_MENU_PICK" -le "$n" ]; then
      CX_MENU_FILE=$PWD/${files[CX_MENU_PICK - 1]}
      return 0
    fi
  else
    printf '\n%s\n' "$(cx_msg "menu_${kind}_none" "$PWD" "$(cx_script_version)")"
  fi
  printf '%s' "$(cx_msg "menu_ask_$kind")"
  cx_menu_read f
  [ -n "$f" ] || return 1
  case $f in
    /*) CX_MENU_FILE=$f ;;
    *) CX_MENU_FILE=$PWD/$f ;;
  esac
}

# cx_menu_backups: the backup files the restore items offer, from the deployment's backups/ and
# the current folder, named as the backup command names them (custodexa-backup-*.tar and .tar.enc),
# newest first. One absolute path per line. The time in the name only tells the files apart; the
# version that counts is the one the restore reads inside the file.
cx_menu_backups() {
  local d f name key first=""
  local -a rows=()
  for d in "$CX_ROOT/backups" "$PWD"; do
    d=$(cd -P -- "$d" 2>/dev/null && pwd) || continue
    if [ "$d" = "$first" ] || [[ $d == *$'\n'* ]]; then continue; fi
    first=${first:-$d}
    for f in "$d"/custodexa-backup-*.tar "$d"/custodexa-backup-*.tar.enc; do
      [ -f "$f" ] || continue
      name=${f##*/}
      [[ $name != *[$'\t\n']* ]] || continue
      key=00000000000000
      if [[ $name =~ -([0-9]{8})-([0-9]{6})\.tar(\.enc)?$ ]]; then key=${BASH_REMATCH[1]}${BASH_REMATCH[2]}; fi
      rows+=("$key"$'\t'"$name"$'\t'"$f")
    done
  done
  [ "${#rows[@]}" -gt 0 ] || return 0
  printf '%s\n' "${rows[@]}" | sort -t $'\t' -k1,1r -k2,2 | cut -f3-
}

# cx_menu_pick_backup: CX_MENU_FILE, an absolute path, from the files found or typed; 1 = back to
# the main menu. Each file shows its size, the time in its name, and whether it is encrypted.
cx_menu_pick_backup() {
  local f i n w=0 sw=0 name t enc
  local -a files=() sizes=()
  mapfile -t files < <(cx_menu_backups)
  n=${#files[@]}
  for ((i = 0; i < n; i++)); do
    name=${files[i]##*/}
    [ "${#name}" -le "$w" ] || w=${#name}
    sizes[i]=$(cx_size_human "$(stat -c %s -- "${files[i]}" 2>/dev/null || echo 0)")
    [ "${#sizes[i]}" -le "$sw" ] || sw=${#sizes[i]}
  done
  if [ "$n" -gt 0 ]; then
    printf '\n%s\n\n' "$(cx_msg menu_restore_found "$CX_ROOT/backups/" "$PWD")"
  else
    printf '\n%s\n\n' "$(cx_msg menu_restore_none "$CX_ROOT/backups/" "$PWD")"
  fi
  for ((i = 0; i < n; i++)); do
    name=${files[i]##*/} t="" enc=""
    if [[ $name =~ -([0-9]{4})([0-9]{2})([0-9]{2})-([0-9]{2})([0-9]{2})[0-9]{2}\.tar(\.enc)?$ ]]; then
      t="  ${BASH_REMATCH[1]}-${BASH_REMATCH[2]}-${BASH_REMATCH[3]} ${BASH_REMATCH[4]}:${BASH_REMATCH[5]}"
    fi
    [[ $name != *.enc ]] || enc=$(cx_msg menu_restore_encrypted)
    cx_menu_item $((i + 1)) "$(printf '%-*s%*s%s%s' $((w + 4)) "$name" "$sw" "${sizes[i]}" "$t" "$enc")"
  done
  cx_menu_item $((n + 1)) "$(cx_msg menu_other_path)"
  printf '\n'
  cx_menu_pick $((n + 1)) || return 1
  if [ "$CX_MENU_PICK" -le "$n" ]; then
    CX_MENU_FILE=${files[CX_MENU_PICK - 1]}
    return 0
  fi
  printf '%s' "$(cx_msg menu_ask_restore)"
  cx_menu_read f
  [ -n "$f" ] || return 1
  case $f in
    /*) CX_MENU_FILE=$f ;;
    *) CX_MENU_FILE=$PWD/$f ;;
  esac
}

# cx_menu_again: the menu once more, from the script the deployment points at now.
cx_menu_again() {
  printf '\n'
  exec "$BASH" "$CX_MENU_SELF" "${CX_MENU_FLAGS[@]}"
}

# cx_menu_run <command> [arguments...]: the command as its own process, then the menu again.
cx_menu_run() {
  "$BASH" "$CX_MENU_SELF" "$@" "${CX_MENU_FLAGS[@]}" || true
  cx_menu_again
}

cx_menu_pick_images() { # [target version]: 0 auto/source selected, 1 EOF
  local answer title
  if [ -n "${1:-}" ]; then
    title=$(cx_msg menu_images_upgrade "$1")
  else
    title=$(cx_msg menu_images_install)
  fi
  printf '\n%s\n%s\n%s\n\n' "$title" "$(cx_msg menu_images_auto)" "$(cx_msg menu_images_source)"
  while :; do
    printf '%s' "$(cx_msg menu_images_choose)"
    if ! read -r answer; then printf '\n'; return 1; fi
    case $answer in
      '' | 1) CX_MENU_IMAGE_FLAG=(--images-from auto); return 0 ;;
      2) CX_MENU_IMAGE_FLAG=(--images-from source); return 0 ;;
      *) cx_line WARN "$(cx_msg menu_invalid)" ;;
    esac
  done
}

# Upgrade to the latest using the verified target from the one query.
cx_menu_upgrade_latest() {
  cx_up_query_core menu || { cx_menu_again; return; }
  if [ -n "$CX_Q_TARGET" ]; then
    cx_menu_pick_images "$CX_Q_TARGET" || return 1
    cx_menu_run upgrade "$CX_Q_TARGET" "${CX_MENU_IMAGE_FLAG[@]}"
  fi
  cx_menu_again
}

cx_menu_upgrade() {
  local v
  printf '\n%s\n' "$(cx_msg menu_up_title)"
  cx_menu_item 1 "$(cx_msg menu_up_latest)"
  cx_menu_item 2 "$(cx_msg menu_up_version)"
  cx_menu_item 3 "$(cx_msg menu_up_package)"
  printf '\n'
  cx_menu_pick 3 || return 1
  case $CX_MENU_PICK in
    1) cx_menu_upgrade_latest ;;
    2)
      printf '%s' "$(cx_msg menu_ask_version)"
      cx_menu_read v
      [ -n "$v" ] || return 1
      cx_menu_pick_images "$v" || return 1
      cx_menu_run upgrade "$v" "${CX_MENU_IMAGE_FLAG[@]}"
      ;;
    3)
      cx_menu_pick_file package || return 1
      v=${CX_MENU_FILE##*/custodexa-}
      v=${v%.tar.gz}
      cx_menu_pick_images "$v" || return 1
      cx_menu_run upgrade "$CX_MENU_FILE" "${CX_MENU_IMAGE_FLAG[@]}"
      ;;
  esac
}

# cx_menu_do <action>: returns only to show the main menu again (a question answered with Enter).
cx_menu_do() {
  case $1 in
    install)
      cx_menu_pick_images || return 0
      cx_menu_run install "${CX_MENU_IMAGE_FLAG[@]}"
      ;;
    rs_resume|rs_unseal|rs_revert|rs_revert_export|rs_abandon|rs_finish_revert|rs_finish_abandon)
      local action=${1#rs_}
      action=${action#finish_}; action=${action%_export}; [ "$action" != unseal ] || action=resume
      "$BASH" "$(cx_rs_engine_path)" restore "--$action" "${CX_MENU_FLAGS[@]}" || true
      cx_menu_again ;;
    status) cx_menu_run status ;;
    start) cx_menu_run start ;;
    stop) cx_menu_run stop ;;
    backup) cx_menu_run backup ;;
    # The item chose the kind of restore: the flag says it, and the restore refuses it if the
    # deployment has changed since the menu was shown. Its questions and confirmation are its own.
    restore_new)
      cx_menu_pick_backup || return 0
      cx_menu_run restore "$CX_MENU_FILE" --new-host
      ;;
    restore)
      cx_menu_pick_backup || return 0
      cx_menu_run restore "$CX_MENU_FILE" --same-host
      ;;
    upgrade) cx_menu_upgrade || return 0 ;;
    load | load_first)
      cx_menu_pick_file bundle || return 0
      cx_menu_run load "$CX_MENU_FILE"
      ;;
    help)
      printf '\n'
      cx_help ""
      ;;
  esac
}

cx_menu_show() {
  local a i=0
  local -a actions
  read -r -a actions <<<"$(cx_menu_actions)"
  printf '%s\n' "$(cx_msg menu_title "$(cx_script_version)" "$CX_ROOT")"
  if [ "$CX_MENU_KIND" = restore ]; then
    if [ -n "$(cx_rs_exit_action)" ]; then printf '%s\n' "$(cx_msg "menu_rs_state_$(cx_rs_exit_action)")"
    else printf '%s\n' "$(cx_msg menu_rs_state "$(cx_rs_phase_text)" "$(cx_state_get last_restore.product_version)")"; fi
  elif [ "$CX_MENU_KIND" = package ]; then
    printf '%s\n' "$(cx_msg menu_state_package "$CX_MENU_VERSION")"
  else
    printf '%s\n' "$(cx_msg menu_state_none)"
  fi
  printf '%s\n\n' "$(cx_msg menu_language)"
  for a in "${actions[@]}"; do
    i=$((i + 1))
    cx_menu_item "$i" "$(cx_msg "menu_$a")"
  done
  cx_menu_item 0 "$(cx_msg menu_quit)"
  printf '\n'
  CX_MENU_ACTIONS=("${actions[@]}")
}

# cx_menu: after cx_menu_applies. Never returns: quits with 0, or starts itself again.
CX_MENU_ACTIONS=()
cx_menu() {
  local a n
  CX_MENU_FLAGS=()
  [ -z "${CX_LANG_FLAG:-}" ] || CX_MENU_FLAGS+=(--lang "$CX_LANG_FLAG")
  if [ "${CX_NO_COLOR:-0}" = 1 ]; then CX_MENU_FLAGS+=(--no-color); fi
  while :; do
    cx_menu_show
    n=${#CX_MENU_ACTIONS[@]}
    while :; do
      printf '%s' "$(cx_msg menu_choose "$n")"
      cx_menu_read a
      [ -n "$a" ] || continue
      [ "$a" != 0 ] || exit "$CX_EXIT_OK"
      if [[ $a =~ ^[1-9][0-9]*$ ]] && [ "$a" -le "$n" ]; then break; fi
      cx_line WARN "$(cx_msg menu_invalid)"
    done
    cx_menu_do "${CX_MENU_ACTIONS[a - 1]}"
    printf '\n'
  done
}
