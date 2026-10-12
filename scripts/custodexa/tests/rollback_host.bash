# A deployment upgraded by the real upgrade entry and steps. Load helper, install_host,
# backup_host and upgrade_host first. Failure injection wraps the deployed copies only.
# rollback_host [upgrade outcome] [mode] [old version]: ready, backup, before-switch,
# switch-recorded, switch-linked, start, ready-failed, checks, interrupted.
rb_state() { jq -r --arg k "$1" '.[$k] // ""' "$ROOT/state.json"; }

# A host built once per test file. The deployment, the fakes and the records hold absolute paths,
# so a file whose setup calls host_workdir has every test work in one fixed folder; host_cache then
# copies a host built earlier in the file back to that same path and sets the variables its builder
# set. In a file that does not call host_workdir, host_cache simply runs the builder.
host_workdir() {
  export BATS_TEST_TMPDIR=$BATS_FILE_TMPDIR/work
  rm -rf "$BATS_TEST_TMPDIR"
  mkdir -p "$BATS_TEST_TMPDIR"
}
# host_cache <key> <builder> [arguments...]: the key names everything the builder depends on.
host_cache() {
  local hc_key=$1 hc_dir hc_n
  shift
  if [ "$BATS_TEST_TMPDIR" != "$BATS_FILE_TMPDIR/work" ]; then "$@"; return; fi
  hc_dir=$BATS_FILE_TMPDIR/cache/$(printf '%s' "$hc_key" | sha256sum | cut -c1-16)
  if [ -f "$hc_dir/vars" ]; then
    rm -rf "$BATS_TEST_TMPDIR"
    cp -a "$hc_dir/files" "$BATS_TEST_TMPDIR"
    # shellcheck disable=SC1091
    . "$hc_dir/vars"
    return 0
  fi
  "$@" || return
  rm -rf "$hc_dir"
  mkdir -p "$hc_dir"
  cp -a "$BATS_TEST_TMPDIR" "$hc_dir/files"
  # The variables in upper case, set again as globals; those of bats and the shell, and the
  # inputs a test chooses per run, are left as they are.
  for hc_n in $(compgen -v); do
    [[ $hc_n =~ ^[A-Z][A-Z0-9_]*$ ]] || continue
    case $hc_n in
      BATS_*|BASH*|HOST_CACHE_*|EPOCH*|RANDOM|SRANDOM|SECONDS|LINENO|HISTCMD|PIPESTATUS|FUNCNAME|GROUPS|DIRSTACK|PPID|UID|EUID|SHELLOPTS|SHLVL|PWD|OLDPWD|RB_LANG|RB_BASELINE|RS_X_BEFORE|LANG_RUN) continue ;;
    esac
    declare -p "$hc_n"
  done 2>/dev/null | sed -E '/^declare -[a-zA-Z]*r[a-zA-Z]* /d; s/^declare -- /declare -g /; s/^declare -([a-zA-Z]+) /declare -\1g /' >"$hc_dir/vars"
}

rollback_host() {
  local outcome=${1:-ready} mode=${2:-ui} old=${3:-1.16.1}
  RB_NEW=${4:-1.16.2}
  local -a own=()
  if [ "$outcome" = external ]; then
    outcome=ready
    own=(--backup-ref vm-snap-0217 --backup-time '2026-09-30 02:17' --backup-restore /doc)
  fi
  # The deployment of the version before with the new release fetched: the same for every outcome.
  host_cache "rb-fetched $mode $old $RB_NEW" rb_fetched "$mode" "$old" || return 1
  if [ -n "${RB_BASELINE:-}" ]; then
    cat "$RB_BASELINE" >>"$ROOT/releases/$RB_NEW/lib/upgrade_steps.sh"
  fi
  if [ ${#own[@]} -gt 0 ]; then
    printf 'false 2026-09-30T02:16:13.123456789Z\n' >"$UP/running"
  fi
  rb_upgraded "$outcome" "${own[@]}"
}
rb_fetched() {
  local mode=$1 old=$2 n ids=""
  backup_host "$mode"
  mv "$ROOT/releases/1.13.0" "$ROOT/releases/$old"
  ln -sfn "releases/$old" "$ROOT/current"
  printf '%s\n' "$old" >"$ROOT/current/VERSION"
  bk_state_set current.version "$old"
  bk_state_set current.kind package
  bk_state_set current.release_dir "releases/$old"
  bk_state_set current.images_env "releases/$old/images.env"
  bk_state_set current.since '2026-09-01T00:00:00+0000'
  jq --arg v "$old" '.version=$v' "$ROOT/current/MANIFEST.json" >"$ROOT/current/manifest.new"
  mv "$ROOT/current/manifest.new" "$ROOT/current/MANIFEST.json"
  : >"$ROOT/current/images.env"
  : >"$ROOT/current/image-ids.env"
  for n in $UP_IMG_NAMES; do
    printf 'CUSTODEXA_IMAGE_%s=%s:%s\n' "${n^^}" "${UP_IMG_REF[$n]}" "$old" >>"$ROOT/current/images.env"
    printf '%s=%s\n' "$n" "$(up_digest "old-$n")" >>"$ROOT/current/image-ids.env"
    ids+="${ids:+ }$n=$(up_digest "old-$n")"
    docker_says "image_inspect_--format_{{.Id}}_$(printf '%s:%s' "${UP_IMG_REF[$n]}" "$old" | tr '/ :@' '----')" "$(up_digest "old-$n")"
  done
  bk_state_set current.image_ids "$ids"
  fake_github
  publish "$RB_NEW" 1.12.4 20260816_schema_baseline 20260901_add_x
  upgrade_stack "$RB_NEW"
  bash "$ROOT/custodexa.sh" upgrade $RB_NEW --lang en </dev/null >"$DB/fetch.out" 2>&1 || true
  [ -d "$ROOT/releases/$RB_NEW" ] || { cat "$DB/fetch.out"; return 1; }
}
# rb_upgraded <outcome> [own backup options...]: the upgrade to RB_NEW, ending as the outcome says.
rb_upgraded() {
  local outcome=$1
  shift
  local -a own=("$@")
  case $outcome in
    ready) ;;
    backup) rb_up_wrap cx_up_at 'if [ "$1" = 8 ]; then cx_up_fail_exit; fi' ;;
    before-switch) rb_up_wrap cx_up_record_switch 'return 1' ;;
    switch-recorded) rb_up_wrap cx_up_link 'if [[ $1 == */current ]]; then return 1; fi' ;;
    switch-linked) rb_up_wrap cx_up_link 'if [[ $1 == */custodexa.sh ]]; then return 1; fi' ;;
    start) touch "$UP/up.rc" ;;
    ready-failed) touch "$UP/health.rc" ;;
    checks) printf '0\n' >"$UP/after.count.users" ;;
    interrupted-start) rb_up_wrap cx_up_start 'kill -TERM $$' ;;
    interrupted) rb_up_wrap cx_up_ready 'kill -TERM $$' ;;
    *) echo "unknown upgrade outcome: $outcome" >&2; return 1 ;;
  esac
  clock 0 3 0 41 0 4 0 11
  # Fixed wall time too: status can wrap between the date and minute in CJK languages.
  sed -i '/  \*) exec/i\  +%Y-%m-%dT%H:%M:%S%z) echo 2026-11-05T09:30:12+0800 ;;\n  +%Y-%m-%dT%H:%M:%S%:z) echo 2026-11-05T09:30:12+08:00 ;;' "$FAKES/date"
  run bash "$ROOT/releases/$RB_NEW/custodexa.sh" upgrade --lang "${RB_LANG:-en}" --yes "${own[@]}" </dev/null
  RB_UP_OUTPUT=$output RB_UP_STATUS=$status
  if [ "$outcome" = ready ]; then
    [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  else
    [ "$status" -eq 1 ] || { echo "$output"; return 1; }
  fi
  # Restore the copies of functions for future upgrades; state is never synthesized here.
  cp "$SRC/lib/upgrade_steps.sh" "$ROOT/releases/$RB_NEW/lib/upgrade_steps.sh"
  rm -f "$UP/up.rc" "$UP/health.rc" "$UP/after.count.users"
  rb_live_daemon
  : >"$DB/events"
  : >"$DB/db-calls"
  : >"$FAKE_DOCKER_LOG"
}

rb_up_wrap() {
  printf '\neval "$(declare -f %s | sed '\''1s/%s/%s_original/'\'')"\n%s() { %s; %s_original "$@"; }\n' \
    "$1" "$1" "$1" "$1" "$2" "$1" >>"$ROOT/releases/$RB_NEW/lib/upgrade_steps.sh"
}

# A running set that follows stop/up, with readiness and IDs derived from the actual link.
# Files rb.stop, rb.up, rb.health, rb.metrics make the corresponding operation fail.
rb_live_daemon() {
  cp "$FAKES/mv" "$FAKES/mv.before-rollback"
  # shellcheck disable=SC2016 # expanded by the fake executable
  fake mv '"$(dirname "$0")/mv.before-rollback" "$@" || exit $?
if [ "${*: -1}" = "$ROOT/current" ]; then printf "switch %s\n" "$(readlink "$ROOT/current")" >>"$DB/events"; fi'
  printf '%s\n' postgres guacd backend frontend >"$DB/running"
  hook_before '
case " $* " in
  *" compose "*" ps --all --services "*) printf "%s\n" postgres guacd backend frontend; exit 0 ;;
  *" compose "*" ps --status running --services "*) cat "$DB/running"; exit 0 ;;
  *" compose "*" stop "*)
    printf "stop" >>"$DB/events"; for s in "$@"; do case $s in backend|guacd|frontend|postgres) printf " %s" "$s" >>"$DB/events" ;; esac; done; printf "\n" >>"$DB/events"
    [ ! -e "$DB/rb.stop" ] || exit 1
    for s in "$@"; do case $s in backend|guacd|frontend|postgres) sed -i "/^$s\$/d" "$DB/running" ;; esac; done
    if ! grep -qx backend "$DB/running"; then printf "false 2026-09-30T02:16:13Z\n" >"$UP/running"; fi
    [ ! -e "$DB/rb.race" ] || { cat "$DB/rb.race" >>"$DB/migrations"; rm "$DB/rb.race"; }
    exit 0 ;;
  *" compose "*" up -d "*)
    printf "up %s marked=%s\n" "$(readlink "$ROOT/current")" "$(jq -r '\''."last_upgrade.new_started_at" // ""'\'' "$ROOT/state.json")" >>"$DB/events"
    [ ! -e "$DB/rb.up" ] || exit 1
    printf "%s\n" postgres guacd backend frontend >"$DB/running"
    printf "true 0001-01-01T00:00:00Z\n" >"$UP/running"; exit 0 ;;
  *" compose "*" exec -T backend wget "*)
    echo health >>"$DB/events"; [ ! -e "$DB/rb.health" ] || exit 1
    printf '\''{"status":"ok","version":"%s"}\n'\'' "$(cat "$ROOT/current/VERSION")"; exit 0 ;;
  *" exec "*"/metrics "*)
    echo drain >>"$DB/events"; [ ! -e "$DB/rb.metrics" ] || exit 1 ;;
esac
if [ "$1" = inspect ] && [[ $* == *"{{.Image}}"* ]]; then echo "id ${*: -1}" >>"$DB/events"; fi'
}

rb_run() {
  local lang=$1
  shift
  run bash "$ROOT/custodexa.sh" rollback --lang "$lang" "$@" </dev/null
}

# Interrupt the deployed function before/after its real body, once. The hook follows current
# across the switch because both installed scripts receive the same wrapper.
rb_interrupt() {
  local f=$1 when=$2 dir
  rm -f "$DB/rb.break.used"
  for dir in "$ROOT"/releases/*; do
    [ -f "$dir/lib/cmd_rollback.sh" ] || continue
    cp "$SRC/lib/cmd_rollback.sh" "$dir/lib/cmd_rollback.sh"
    cat >>"$dir/lib/cmd_rollback.sh" <<HOOK

eval "\$(declare -f $f | sed '1s/$f/${f}_uninterrupted/')"
$f() {
  if [ '$when' = before ] && [ ! -e "\$DB/rb.break.used" ]; then touch "\$DB/rb.break.used"; kill -TERM \$\$; fi
  ${f}_uninterrupted "\$@" || return \$?
  if [ '$when' = after ] && [ ! -e "\$DB/rb.break.used" ]; then touch "\$DB/rb.break.used"; kill -TERM \$\$; fi
}
HOOK
  done
}

rb_identity() {
  jq -S 'with_entries(select(.key == "last_rollback.from" or .key == "last_rollback.to" or
    .key == "last_rollback.started_at" or .key == "last_rollback.log"))' "$ROOT/state.json"
}

# rb_cached [outcome] [mode] [old version] [new version]: rollback_host in an emptied folder, built
# once per test file for each outcome, versions, language and baseline.
rb_cached() {
  rm -rf "${BATS_TEST_TMPDIR:?}"/*
  host_cache "rb $* lang=${RB_LANG:-en} baseline=${RB_BASELINE:-}" rollback_host "$@"
}
