# Hosts for the bundled database conversion tests (upgrade step 8, db-upgrade, rollback across the
# PostgreSQL major, restore). Needs helper.bash, install_host.bash, backup_host.bash and
# upgrade_host.bash loaded, and a host from upgraded_host or backup_host.
#
# What the fixture lets a test do:
#   pgc_version <16|18|missing> [data_dir] [pgdata]
#       PG_VERSION of a data folder under $ROOT/data (default: the 16 layout, data/postgres); `missing`
#       makes the folder without the file
#   pgc_manifest <release dir> <with|without> [major]
#       the MANIFEST.json of a release with or without bundled_db (the older layout has none);
#       the postgres image tag follows the major (default 18 with, 16 without)
#   pgc_free <backups|docker|data|pg|dump> <KiB|none>
#       what df answers for the place that write goes to (backups/, DockerRootDir, DATA_PATH,
#       DATA_PATH/postgresql, DATA_PATH/.pg-convert); `none` makes df fail for it. Call it after any
#       host_free, which writes the df fake anew.
#   pgc_phase_inject <fail|kill> <phase>
#       a docker call made while state.json holds last_upgrade.db_convert.phase=<phase> fails
#       (exit 1), or kills the script (SIGKILL); "before phase X" is the phase before it recorded
#       as done, "after phase X" is the next phase. Phases: prepare dump init restore verify
#       analyze done.
#   pgc_recovery_inject
#       the first docker `start` after db_convert.recovery=restart_old is recorded kills the script,
#       the failure wrap-up stopped after the old services came back and before the upgrade is
#       recorded as failed
#   pgc_dirop_inject <intent|renamed>
#       a `mv` of a data folder stops the script (SIGKILL) after the intent is recorded and before
#       the rename (intent), or after the rename and before the completion is recorded (renamed)
#   pgc_state <key>
#       a key of state.json
# The injections read state.json, not hooks in the script, so a test arranges them before the run
# and the script under test is the one a customer gets.

PGC_PHASES="prepare dump init restore verify analyze done"

# pgx_pending <file the implementation adds, relative to the script tree> <task>: a skeleton test of
# a scenario whose task is not done yet. With CX_PGX_RED=1 it fails and says which of the two
# reasons: the module is not there, or it is there and the assertion of this scenario is not
# written yet (a red run is taken that way). Without it the test is skipped with the
# same text, so the suite stays at 0 not ok while those tasks are open; a skip is counted and shown,
# it is never an ok.
pgx_pending() {
  local why
  if [ -e "$SRC/$1" ]; then
    why="skeleton: $1 exists, the assertion of this scenario is not written (task $2)"
  else
    why="skeleton: $1 does not exist (task $2)"
  fi
  if [ "${CX_PGX_RED:-0}" = 1 ]; then
    echo "$why"
    return 1
  fi
  skip "$why"
}

pgc_state() { jq -r --arg k "$1" '.[$k] // ""' "$ROOT/state.json"; }

pgc_version() {
  local v=$1 dir=${2:-postgres} pgdata=${3:-} d
  d=$ROOT/data/$dir${pgdata:+/$pgdata}
  mkdir -p "$d"
  rm -f "$d/PG_VERSION"
  [ "$v" = missing ] || printf '%s\n' "$v" >"$d/PG_VERSION"
}

pgc_manifest() {
  local rel=$1 form=$2 major=${3:-} tag
  [ -n "$major" ] || { [ "$form" = with ] && major=18 || major=16; }
  case $major in 16) tag=16.15-alpine3.24 ;; 18) tag=18.6-alpine3.24 ;; *) tag=$major.0-alpine3.24 ;; esac
  jq --arg t "$tag" --arg f "$form" --argjson m "$major" \
    '.images.postgres.tag = $t
     | if $f == "with" then .bundled_db = {major: $m, data_dir: "postgresql", pgdata: (($m | tostring) + "/docker")}
       else del(.bundled_db) end' "$rel/MANIFEST.json" >"$rel/MANIFEST.json.new"
  mv "$rel/MANIFEST.json.new" "$rel/MANIFEST.json"
}

pgc_path() {
  case $1 in
    backups) printf '%s' "$ROOT/backups" ;;
    docker) printf '%s' /var/lib/docker ;;
    data) printf '%s' "$ROOT/data" ;;
    pg) printf '%s' "$ROOT/data/postgresql" ;;
    dump) printf '%s' "$ROOT/data/.pg-convert" ;;
    *) return 1 ;;
  esac
}

pgc_free() {
  local p
  p=$(pgc_path "$1") || return 1
  if [ "$2" = none ]; then
    printf '%s\n' "$p" >>"$FAKES/df.fails"
    [ -e "$FAKES/df.real" ] || cp "$FAKES/df" "$FAKES/df.real"
    fake df 'd=${@: -1}
while read -r p; do [ "$d" = "$p" ] && { echo "df: cannot read $d" >&2; exit 1; }; done <'"$FAKES/df.fails"'
exec '"$FAKES/df.real"' "$@"'
  else
    mkdir -p "$p"
    host_free "$p" "$2"
  fi
}

pgc_phase_inject() {
  local how=$1 phase=$2 act
  case $how in
    fail) act='exit 1' ;;
    kill) act='pkill -KILL -f "custodexa.sh upgrade" ; exit 137' ;;
    *) return 1 ;;
  esac
  hook_before 'ph=$(jq -r ".\"last_upgrade.db_convert.phase\" // \"\"" "'"$ROOT"'/state.json" 2>/dev/null)
if [ "$ph" = "'"$phase"'" ]; then '"$act"'; fi'
}

pgc_recovery_inject() {
  hook_before 'rc=$(jq -r ".\"last_upgrade.db_convert.recovery\" // \"\"" "'"$ROOT"'/state.json" 2>/dev/null)
case " $* " in *" start "*) if [ "$rc" = restart_old ] && [ ! -e "'"$BATS_TEST_TMPDIR"'/recovery-killed" ]; then
  touch "'"$BATS_TEST_TMPDIR"'/recovery-killed"; "$FAKE_DOCKER_REPLAY/hook.0" "$@"; pkill -KILL -f "custodexa.sh upgrade"; exit 137; fi ;; esac'
}

pgc_dirop_inject() {
  local when=$1
  fake mv 'if [ -d "$1" ] && [[ $1 == */data/postgres* ]]; then
  ph=$(jq -r ".\"dir_op.phase\" // \"\"" "'"$ROOT"'/state.json" 2>/dev/null)
  case "'"$when"'" in
    intent) [ "$ph" = intent ] && { pkill -KILL -f "custodexa.sh" ; exit 137; } ;;
    renamed) /usr/bin/mv "$@"; [ "$ph" = intent ] && { pkill -KILL -f "custodexa.sh" ; exit 137; }; exit 0 ;;
  esac
fi
exec /usr/bin/mv "$@"'
}

# ---- screen snapshots (task 3.11) ----
# pg_shot <name> <command...>: run the command once per language and compare what it printed with
# snapshots/pg-<name>.<lang>.txt. A command that changes files is given through pg_shot_prep, which
# runs a preparation before every language. CX_SNAP_OUT=<folder> writes the screens there instead
# of comparing (to review a change; the folder must be mounted writable).
pg_norm() {
  sed -E "s/\x1b\[[0-9;]*m//g; s# --lang (en|zh-TW|ja)##g; s#$ROOT#/opt/custodexa#g; s#$BATS_TEST_TMPDIR#/tmp#g; s/[0-9]{8}-[0-9]{6}/20261120-021502/g;
    s/[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[+-][0-9:]+/2026-11-20T02:15:02+0800/g;
    s/[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}/2026-11-20 02:15/g;
    s/ [0-9]+( ?(s|秒))\$/ 0\1/"
}
pg_lang() {
  # shellcheck source=/dev/null
  . "$SRC/lang/en.sh"
  # shellcheck source=/dev/null
  [ "$1" = en ] || . "$SRC/lang/$1.sh"
  CX_LANG=$1
}
pg_emit() {
  local name=$1 l=$2 got path
  got=$(printf '%s\n' "$output" | pg_norm)
  if [ -n "${CX_SNAP_OUT:-}" ]; then
    printf '%s\n' "$got" >"$CX_SNAP_OUT/pg-$name.$l.txt"
    return 0
  fi
  path=$TESTS_DIR/snapshots/pg-$name.$l.txt
  [ -f "$path" ] || { echo "no snapshot pg-$name.$l.txt"; return 1; }
  diff <(printf '%s\n' "$got") "$path" || { echo "pg-$name.$l differs"; return 1; }
}
pg_shot_prep() {
  local name=$1 prep=$2 l rc=0
  shift 2
  for l in en zh-TW ja; do
    "$prep"
    pg_lang "$l"
    run "$@" </dev/null
    pg_emit "$name" "$l" || rc=1
  done
  return $rc
}
# pg_keep / pg_reset: the deployment folder as it was when the scenario was arranged, put back
# before each language, so a screen that renames or removes something is printed the same way.
pg_keep() {
  find "$BATS_TEST_TMPDIR/rootkeep" -mindepth 1 -delete 2>/dev/null || true
  mkdir -p "$BATS_TEST_TMPDIR/rootkeep"
  cp -a "$ROOT/." "$BATS_TEST_TMPDIR/rootkeep/"
}
pg_reset() {
  find "$ROOT" -mindepth 1 -delete
  cp -a "$BATS_TEST_TMPDIR/rootkeep/." "$ROOT/"
  rm -f "$DB/rec-at-start"
  : >"$FAKE_DOCKER_LOG"
}
pg_shot() {
  local name=$1
  shift
  pg_keep
  pg_shot_prep "$name" pg_reset "$@"
}
