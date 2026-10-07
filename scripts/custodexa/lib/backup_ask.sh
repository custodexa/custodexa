# shellcheck shell=bash
# CX_PB_ENC, CX_PB_WITH_REC and CX_PB_PICK are read by lib/cmd_backup.sh and lib/portable.sh.
# shellcheck disable=SC2034
# The choices of `backup`: the recordings and the passphrase encryption. Read by lib/cmd_backup.sh,
# which sources this file and provides the output helpers (cmd_backup_par, cmd_backup_ind, ...).
# Questions are asked only when stdin is a terminal and --yes is not given:
#   recordings  --with-recordings puts them in; else asked, Enter leaves them out; else left out
#   encryption  --passphrase-file encrypts; else asked, Enter does not encrypt; else not encrypted
# Every refusal here comes before any service is stopped. End of input while asking cancels.

# cmd_backup_interactive: questions may be asked.
cmd_backup_interactive() { [ -t 0 ] && [ "${CX_YES:-0}" != 1 ]; }

# cmd_backup_cancel: the input ended while asking: nothing was changed.
cmd_backup_cancel() {
  printf '\n%s\n' "$(cx_msg pre_nothing_changed)"
  cx_finish cancelled
  exit "$CX_EXIT_REFUSED"
}

# cx_pb_dur <minutes> [more]: the time in words, hours once it reaches one. "more" is the form of
# "takes about ... more" (English puts the word inside).
cx_pb_dur() {
  local m=$1 h text
  h=$((m / 60)) m=$((m % 60))
  if [ "$h" -eq 0 ]; then
    case $m in
      1) cx_msg "pb_dur${2:+_more}_m1" ;;
      *) cx_msg "pb_dur${2:+_more}_m" "$m" ;;
    esac
    return 0
  fi
  if [ "$h" -eq 1 ]; then text=$(cx_msg pb_dur_h1); else text=$(cx_msg pb_dur_h "$h"); fi
  case $m in
    0) ;;
    1) text+=" $(cx_msg pb_dur_m1)" ;;
    *) text+=" $(cx_msg pb_dur_m "$m")" ;;
  esac
  if [ -n "${2:-}" ]; then cx_msg pb_dur_more_h "$text"; else printf '%s' "$text"; fi
}

# cmd_backup_pick: CX_PB_PICK, 1 (also Enter) or 2; asked again after anything else.
cmd_backup_pick() {
  local a
  while :; do
    printf '\n%s' "$(cx_msg pb_choose)"
    read -r a || cmd_backup_cancel
    case $a in
      "" | 1) CX_PB_PICK=1; return 0 ;;
      2) CX_PB_PICK=2; return 0 ;;
    esac
    cx_line WARN "$(cx_msg menu_invalid)"
  done
}

# cmd_backup_option <n> <text>: "  [n] text", later lines under the text.
cmd_backup_option() { printf '  [%s] %s\n' "$1" "${2//$'\n'/$'\n'      }"; }
# cmd_backup_option_note <text>: a line under an option's text.
cmd_backup_option_note() { printf '      %s\n' "$1"; }

# cmd_backup_ask_rec: whether the recordings go in, with the file and the pause of each choice and
# a note under a choice whose space need exceeds the free space.
cmd_backup_ask_rec() {
  local n key
  printf '\n'
  cx_line ASK "$(cx_msg pb_rec_q)"
  printf '\n'
  for n in 0 1; do
    cx_pb_space "$n"
    key=pb_rec_no
    [ "$n" = 0 ] || key=pb_rec_yes
    cmd_backup_option $((n + 1)) "$(cx_msg "$key" "$(cx_size_human "$CX_PB_FILE_EST")" "$(cx_pb_dur "$(cx_pb_minutes)")")"
    [ "$CX_BK_NEED" -le "$CX_BK_FREE" ] || cmd_backup_option_note "$(cx_msg pb_rec_short "$(cx_size_human "$CX_BK_NEED")")"
  done
  cmd_backup_option_note "$(cx_msg pb_rec_keep)"
  cmd_backup_pick
  CX_PB_WITH_REC=$((CX_PB_PICK - 1))
  cx_log ASK "recordings=$CX_PB_WITH_REC"
}

# cmd_backup_ask_enc: whether the file is encrypted; when it is, the image and the passphrase.
cmd_backup_ask_enc() {
  local why=pb_enc_why
  [ "$CX_PB_KEK" != env ] || why=pb_enc_why_env
  printf '\n'
  cx_line ASK "$(cx_msg pb_enc_q)"
  printf '\n'
  cmd_backup_par "$(cx_msg "$why")"
  printf '\n'
  cmd_backup_option 1 "$(cx_msg pb_enc_no)"
  cmd_backup_option 2 "$(cx_msg pb_enc_yes)"
  cmd_backup_pick
  [ "$CX_PB_PICK" = 2 ] || { cx_log ASK "encryption=0"; return 0; }
  CX_PB_ENC=1
  cx_log ASK "encryption=1"
  cmd_backup_need_openssl
  cmd_backup_ask_pass
}

# cmd_backup_read_secret <prompt id>: CX_PB_TYPED, typed without echo. End of input cancels.
cmd_backup_read_secret() {
  printf '  %s' "$(cx_msg "$1")"
  if ! IFS= read -r -s CX_PB_TYPED; then
    CX_PB_TYPED=""
    cmd_backup_cancel
  fi
  printf '\n'
}

# cmd_backup_tries_left <n>: "2 more tries", for the warning.
cmd_backup_tries_left() {
  if [ "$1" = 1 ]; then cx_msg pb_tries_1; else cx_msg pb_tries_n "$1"; fi
}

# cmd_backup_ask_pass: the passphrase, typed twice without echo; three rounds at most, a round
# ending at a passphrase that breaks the rules or a second entry that differs.
cmd_backup_ask_pass() {
  local round first key
  printf '\n'
  cmd_backup_par "$(cx_msg pb_pass_rules)"
  for round in 1 2 3; do
    cmd_backup_read_secret pb_pass_prompt
    first=$CX_PB_TYPED
    cx_pb_pass_check "$first"
    key=""
    if [ -n "$CX_PB_PASS_WHY" ]; then
      key=pb_pass_$CX_PB_PASS_WHY
    else
      cmd_backup_read_secret pb_pass_again
      [ "$first" = "$CX_PB_TYPED" ] || key=pb_pass_differ
    fi
    CX_PB_TYPED=""
    if [ -z "$key" ]; then
      cx_pb_pass_set "$first"
      cmd_backup_ind OK "$(cx_msg pb_pass_match)"
      cx_log ASK "passphrase set (round $round)"
      return 0
    fi
    cx_log ASK "passphrase round $round: ${key#pb_pass_}"
    [ "$round" = 3 ] || cmd_backup_ind WARN "$(cx_msg "$key" "$(cmd_backup_tries_left $((3 - round)))")"
  done
  cx_line FAIL "$(cx_msg pb_pass_cancel)"
  cx_finish cancelled
  exit "$CX_EXIT_REFUSED"
}

# cmd_backup_need_openssl: the encryption image is on this host, or the run stops here.
cmd_backup_need_openssl() {
  local bundle
  if cx_pb_openssl_id; then
    cx_log CHECK "encryption image $CX_PB_OPENSSL_ID"
    return 0
  fi
  cx_log FAIL "encryption image missing (recorded: ${CX_PB_OPENSSL_ID:-none})"
  bundle=custodexa-images-$CX_PB_VERSION-$(cx_arch 2>/dev/null || printf amd64).tar
  cx_line FAIL "$(cx_msg pb_no_openssl "$CX_PB_VERSION" "$bundle")"
  cmd_backup_cmd "$(cmd_backup_cmd_of "load $bundle")"
  cx_finish failed
  exit "$CX_EXIT_REFUSED"
}

# cmd_backup_pass_file: --passphrase-file: the passphrase from the file and the encryption image,
# or the reason it cannot be used with what to do.
cmd_backup_pass_file() {
  local q
  [ -n "${CX_PASSPHRASE_FILE:-}" ] || return 0
  CX_PB_ENC=1
  if cx_pb_pass_file "$CX_PASSPHRASE_FILE"; then
    cx_log CHECK "passphrase file ${CX_PB_PF_PATH} accepted"
    cmd_backup_need_openssl
    return 0
  fi
  cx_log FAIL "passphrase file ${CX_PB_PF_PATH}: $CX_PB_PF_WHY mode=${CX_PB_PF_MODE:-?} acl=$CX_PB_PF_ACL"
  case $CX_PB_PF_WHY in
    read) cx_line FAIL "$(cx_msg pb_pf_read "$CX_PB_PF_PATH")" ;;
    line) cx_line FAIL "$(cx_msg pb_pf_line "$CX_PB_PF_PATH")" ;;
    *)
      q=$(printf '%q' "$CX_PB_PF_PATH")
      cx_line FAIL "$(cx_msg pb_pf_perm "$CX_PB_PF_PATH" "$CX_PB_PF_MODE")"
      cmd_backup_cmd "sudo chown root $q"
      cmd_backup_cmd "sudo chmod 600 $q"
      [ "$CX_PB_PF_ACL" != 1 ] || cmd_backup_cmd "sudo setfacl -b $q"
      ;;
  esac
  cx_finish failed
  exit "$CX_EXIT_REFUSED"
}
