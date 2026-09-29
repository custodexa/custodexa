#!/usr/bin/env bats
# Threat (A): the first conversion moves what it must not move or rewrites .env wrongly. The data
# folder, .env, tls/ and the backups stay where they are (the data folder not even renamed); .git
# and what git tracks go to releases/<old version>/; .env gets absolute host paths and the new
# COMPOSE_FILE / COMPOSE_PROJECT_NAME, with the old values kept in a copy and recorded; a work tree
# git reports as changed is refused before anything stops. A conversion that fails halfway prints
# commands that really put the clone back, and the next run offers only those.

load helper
load install_host
load backup_host
load upgrade_host

# convert_host: the 1.12.4 clone with its database and daemon, ready for the 1.13.0 script.
convert_host() {
  legacy_host
  fake_github
  export DB=$BATS_TEST_TMPDIR/db ROOT=$LROOT
  mkdir -p "$DB" "$LROOT/data/recordings" "$LROOT/data/audit" "$LROOT/data/postgres"
  printf 'pg data\n' >"$LROOT/data/postgres/PG_VERSION"
  printf 'cert\n' >"$LROOT/tls/fullchain.pem"
  : >"$DB/events"
  db_default
  write_db_hook
  upgrade_stack 1.13.0
  docker_says inspect_--format 'custodexa_old'
  host_free / 221249536
}

convert_run() { # <lang> [options...]
  local l=$1
  shift
  run env CUSTODEXA_HOME="$LROOT" bash "$PKG/custodexa.sh" upgrade 1.13.0 --lang "$l" "$@" </dev/null
}

# The deployment as the operator sees it, less what the script writes itself.
clone_view() {
  (cd "$1" && find . -mindepth 1 \( -path ./backups -o -path ./logs -o -path ./.custodexa.lock \) -prune \
    -o -printf '%y %m %p\n' | sort \
    && find . -mindepth 1 \( -path ./backups -o -path ./logs -o -path ./.git -o -path ./.custodexa.lock \) \
      -prune -o -type f -print0 | sort -z | xargs -0 -r sha256sum)
}

@test "a clean clone: converted, the data folder untouched, .git and the product files in releases/1.12.4/, .env rewritten and recorded" {
  convert_host
  # A tracked file inside the data folder (some clones keep one) does not make it a product folder.
  : >"$LROOT/data/.gitkeep"
  git -C "$LROOT" add -f data/.gitkeep
  git -C "$LROOT" -c user.name=test -c user.email=test@example.invalid commit -qm keep
  cp "$LROOT/.env" "$BATS_TEST_TMPDIR/env-before"
  data_inode=$(stat -c %i "$LROOT/data")
  tree_of "$LROOT/data" >"$BATS_TEST_TMPDIR/data-before"
  convert_run en --yes
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  printf '%s\n' "$output" | grep -q '^\[ OK \]  8/13  Reorganize the folder' || { echo "$output"; return 1; }
  # The data folder: same place, same inode, same content.
  [ "$(stat -c %i "$LROOT/data")" = "$data_inode" ] || return 1
  diff "$BATS_TEST_TMPDIR/data-before" <(tree_of "$LROOT/data") || return 1
  [ -f "$LROOT/tls/fullchain.pem" ] && [ -f "$LROOT/.env" ] || return 1
  # The old tree, whole and clean, under releases/1.12.4/; nothing of it left at the root.
  for f in .git VERSION docker-compose.yml backend/go.mod .gitignore; do
    [ -e "$LROOT/releases/1.12.4/$f" ] || { echo "missing releases/1.12.4/$f"; return 1; }
    [ ! -e "$LROOT/$f" ] || { echo "left at the root: $f"; return 1; }
  done
  # Only the file kept in the data folder is missing from the old tree.
  [ "$(git -C "$LROOT/releases/1.12.4" status --porcelain)" = ' D data/.gitkeep' ] || { git -C "$LROOT/releases/1.12.4" status; return 1; }
  [ -e "$LROOT/data/.gitkeep" ] || return 1
  [ ! -e "$LROOT/releases/1.12.4/data" ] && [ ! -e "$LROOT/releases/1.12.4/.env" ] || return 1
  # The new release in place and current.
  [ "$(readlink "$LROOT/current")" = releases/1.13.0 ] && [ -f "$LROOT/releases/1.13.0/images.env" ] || return 1
  [ "$(readlink "$LROOT/custodexa.sh")" = current/custodexa.sh ] || return 1
  # .env: only the host path and the compose keys changed; the old one kept beside the backup.
  bk=$(jq -r '."last_backup.dir"' "$LROOT/state.json")
  cmp "$BATS_TEST_TMPDIR/env-before" "$LROOT/$bk/env-before-convert.bak" || return 1
  diff <(grep -v '^\(DATA_PATH\|COMPOSE_FILE\|COMPOSE_PROJECT_NAME\)=' "$LROOT/.env") \
    <(grep -v '^DATA_PATH=' "$BATS_TEST_TMPDIR/env-before") || return 1
  grep -qx "DATA_PATH=$LROOT/data" "$LROOT/.env" || { cat "$LROOT/.env"; return 1; }
  grep -qx 'COMPOSE_FILE=current/compose.yml' "$LROOT/.env" && grep -qx 'COMPOSE_PROJECT_NAME=custodexa' "$LROOT/.env" || return 1
  [ "$(stat -c %a "$LROOT/.env")" = 600 ] || return 1
  # state.json: where it came from, the backup, the upgrade.
  st() { jq -r --arg k "$1" '.[$k] // ""' "$LROOT/state.json"; }
  [ "$(st previous.kind)" = legacy-git-clone ] && [ "$(st previous.compose_project)" = custodexa_old ] || { cat "$LROOT/state.json"; return 1; }
  [ "$(st previous.compose_files)" = "$LROOT/docker-compose.yml" ] && [ "$(st previous.version)" = 1.12.4 ] || return 1
  [ "$(st conversion.env_rewrites)" = "DATA_PATH:1:./data>$LROOT/data;COMPOSE_FILE:3:>current/compose.yml;COMPOSE_PROJECT_NAME:4:>custodexa" ] \
    || { st conversion.env_rewrites; return 1; }
  [ "$(st last_backup.kind)" = script ] && [ -s "$LROOT/$bk/SHA256SUMS" ] || return 1
  [ "$(st last_upgrade.result)" = succeeded ] && [ "$(st last_upgrade.backup)" = "$bk" ] && [ "$(st current.kind)" = package ] || return 1
  # The old containers are removed on the old project before the new version starts on its own.
  old="-p custodexa_old --project-directory $LROOT -f $LROOT/docker-compose.yml"
  grep -qF "compose $old down" "$FAKE_DOCKER_LOG" || { cat "$FAKE_DOCKER_LOG"; return 1; }
  events_in_order() { local e n=0 at; for e in "$@"; do at=$(grep -nx -m1 "$e" "$DB/events" | cut -d: -f1); [ -n "$at" ] && [ "$at" -gt "$n" ] || { cat "$DB/events"; return 1; }; n=$at; done; }
  events_in_order "stop backend guacd frontend" pg_dump down up || return 1
  grep -q "compose -p custodexa --project-directory $LROOT -f $LROOT/current/compose.yml up -d" "$FAKE_DOCKER_LOG"
}

@test "a git status that lists anything: refused before the preview, what git lists shown, nothing changed" {
  convert_host
  printf 'edited\n' >>"$LROOT/docker-compose.yml"
  printf 'mine\n' >"$LROOT/notes.txt"
  # What the script writes itself does not count.
  mkdir -p "$LROOT/backups/20260101-000000"
  tree_of "$LROOT" >"$BATS_TEST_TMPDIR/before"
  convert_run zh-TW
  [ "$status" -eq 3 ] || { echo "$output"; return 1; }
  diff <(screen_of "$output" | sed "s#/opt/custodexa#/data/custodexa#g") "$TESTS_DIR/snapshots/s08-dirty.zh-TW.txt" || return 1
  convert_run en --yes
  [ "$status" -eq 3 ] || { echo "$output"; return 1; }
  diff <(screen_of "$output" | sed "s#/opt/custodexa#/data/custodexa#g") "$TESTS_DIR/snapshots/s08-dirty.en.txt" || return 1
  diff "$BATS_TEST_TMPDIR/before" <(tree_of "$LROOT") || return 1
  ! grep -q ' stop \| down ' "$FAKE_DOCKER_LOG"
}

@test "the preview of a conversion, word for word (zh-TW, en)" {
  convert_host
  # The numbers of the reviewed screen: 6.2 GB to back up, 150 GB free, 3 structure changes.
  printf '%s\n' 5583457484 >"$DB/size"
  host_free / 157286400
  printf '%s\n' 20260816_schema_baseline >"$DB/migrations"
  rm -rf "$PKG/releases/1.13.0"
  package_release "$PKG/releases/1.13.0" 1.13.0 1.12.4 20260816_schema_baseline 20260901_add_x 20261010_report_schedule 20261012_y
  # As in the .env of a 1.12.4 clone: COMPOSE_FILE commented out on line 28, DATA_PATH on line 68.
  { for i in $(seq 1 67); do
      if [ "$i" = 28 ]; then printf '# COMPOSE_FILE=docker-compose.dev.yml\n'; else printf '# line %s\n' "$i"; fi
    done; printf 'DATA_PATH=./data\n'; } >"$LROOT/.env"
  for l in zh-TW en; do
    convert_run "$l"
    [ "$status" -eq 3 ] || { echo "$output"; return 1; }
    diff <(screen_of "$output" | sed "s#/opt/custodexa#/data/custodexa#g" | sed '/^\[FAIL\]/,$d' | sed '$d') \
      "$TESTS_DIR/snapshots/s08.$l.txt" || { echo "$output"; return 1; }
  done
}

@test "a failure halfway: the printed commands put the clone back; the next run offers only those" {
  for l in en zh-TW; do
    rm -rf "${BATS_TEST_TMPDIR:?}"/*
    convert_host
    docker_says inspect_--format custodexa
    clock
    printf 'KEK_PROVIDER=ui\n' >>"$LROOT/.env"
    clone_view "$LROOT" >"$BATS_TEST_TMPDIR/before"
    fake mv 'case " $* " in *"/backend "*) echo "mv: cannot move: Permission denied" >&2; exit 1 ;; esac; exec /bin/mv "$@"'
    convert_run "$l" --yes
    [ "$status" -eq 1 ] || { echo "$output"; return 1; }
    diff <(screen_of "$output" | sed "s#/opt/custodexa#/data/custodexa#g" | sed -n '/^\[FAIL\] \(升級停在第\|The upgrade stopped at step\) 8/,$p') \
      "$TESTS_DIR/snapshots/s12a.$l.txt" || { echo "$output"; return 1; }
  done
  [ ! -e "$LROOT/state.json" ] || return 1
  ! grep -qx up "$DB/events" || return 1
  # The next run: no state.json, the old tree half in releases/: only the way back.
  rm "$FAKES/mv"
  convert_run en --yes
  [ "$status" -eq 3 ] || { echo "$output"; return 1; }
  [[ $output == "[FAIL] The last upgrade was interrupted while reorganizing the folder."* ]] || { echo "$output"; return 1; }
  [[ $output != *"upgrade preview"* ]] || return 1
  ! grep -qx up "$DB/events" || return 1
  # The printed commands, as typed (without sudo), bring back the clone exactly.
  cmds=$(printf '%s\n' "$output" | sed -n '/^  Run these commands/,/^  Check that git/p' | grep '^    ' \
    | sed 's/^    //; s/^sudo //' | sed -e ':a' -e '/\\$/N; s/\\\n *//; ta')
  [ -n "$cmds" ] || { echo "$output"; return 1; }
  (set -e; eval "$cmds") || { echo "$cmds"; return 1; }
  diff "$BATS_TEST_TMPDIR/before" <(clone_view "$LROOT") || return 1
  diff <(git -C "$LROOT" status --porcelain) <(printf '%s\n' '?? .custodexa.lock' '?? backups/')
}

@test "a failure before anything moved: the folder is unchanged, only the old version's start command" {
  convert_host
  touch "$UP/down.rc"
  convert_run en --yes
  [ "$status" -eq 1 ] || { echo "$output"; return 1; }
  [[ $output == *"[FAIL] The upgrade stopped at step 8/13 (reorganize the folder):"*"cannot remove the old containers"* ]] || { echo "$output"; return 1; }
  [[ $output == *"The folder is not changed yet"* && $output != *"Run these commands"* ]] || { echo "$output"; return 1; }
  printf '%s\n' "$output" | grep -qxF "      -f $LROOT/docker-compose.yml up -d" || { echo "$output"; return 1; }
  [ ! -e "$LROOT/releases" ] && [ -e "$LROOT/.git" ] && [ -z "$(git -C "$LROOT" status --porcelain | grep -v '^?? \(backups/\|\.custodexa\.lock\)$')" ]
}

@test "report exports in the old backend container: copied into data/exports on the old project before its containers are removed, bytes and modes kept" {
  convert_host
  mkdir -p "$UP/exports/reports"
  printf 'report pdf\n' >"$UP/exports/reports/r-2026-09.pdf"
  printf 'evidence zip\n' >"$UP/exports/ev-1.zip"
  chmod 600 "$UP/exports/reports/r-2026-09.pdf" "$UP/exports/ev-1.zip"
  (cd "$UP/exports" && find . -type f -printf '%m %p\n' | sort && find . -type f -print0 | sort -z | xargs -0 sha256sum) >"$BATS_TEST_TMPDIR/exports-before"
  convert_run en --yes
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  diff "$BATS_TEST_TMPDIR/exports-before" \
    <(cd "$LROOT/data/exports" && find . -type f -printf '%m %p\n' | sort && find . -type f -print0 | sort -z | xargs -0 sha256sum) || return 1
  [ "$(stat -c %a "$LROOT/data/exports")" = 700 ] || { stat -c %a "$LROOT/data/exports"; return 1; }
  old="-p custodexa_old --project-directory $LROOT -f $LROOT/docker-compose.yml"
  grep -qF "compose $old cp backend:/var/lib/custodexa/exports/. $LROOT/data/exports/" "$FAKE_DOCKER_LOG" || { cat "$FAKE_DOCKER_LOG"; return 1; }
  at_cp=$(grep -nx -m1 cp-exports "$DB/events" | cut -d: -f1) at_down=$(grep -nx -m1 down "$DB/events" | cut -d: -f1)
  [ -n "$at_cp" ] && [ -n "$at_down" ] && [ "$at_cp" -lt "$at_down" ] || { cat "$DB/events"; return 1; }
  grep -q 'EXPORTS copied 2 files' "$LROOT"/logs/upgrade-*.log || { cat "$LROOT"/logs/upgrade-*.log; return 1; }
}

@test "no export folder in the old container, an empty one, or one already on the host: nothing copied, no folder made, the conversion goes on" {
  convert_host
  convert_run en --yes
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  grep -qx cp-exports "$DB/events" || return 1
  [ ! -e "$LROOT/data/exports" ] || { ls -la "$LROOT/data"; return 1; }
  rm -rf "${BATS_TEST_TMPDIR:?}"/*
  convert_host
  mkdir -p "$UP/exports"
  convert_run en --yes
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [ ! -e "$LROOT/data/exports" ] || { ls -la "$LROOT/data"; return 1; }
  # Mounted from the host already: copying would read and write the same files. Not copied.
  rm -rf "${BATS_TEST_TMPDIR:?}"/*
  convert_host
  mkdir -p "$UP/exports"
  printf 'report\n' >"$UP/exports/r.pdf"
  docker_says 'inspect_--format_{{range-.Mounts}}{{println-.Destination}}{{end}}' /var/lib/custodexa/exports
  convert_run en --yes
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  ! grep -qx cp-exports "$DB/events" || return 1
  [ ! -e "$LROOT/data/exports" ]
}

@test "the export folder cannot be copied out: stopped before the old containers are removed, the folder unchanged" {
  convert_host
  mkdir -p "$UP/exports"
  printf 'report\n' >"$UP/exports/r.pdf"
  touch "$UP/exports.rc"
  convert_run en --yes
  [ "$status" -eq 1 ] || { echo "$output"; return 1; }
  [[ $output == *"[FAIL] The upgrade stopped at step 8/13 (reorganize the folder):"*"cannot copy the report exports out of the old backend container"* ]] || { echo "$output"; return 1; }
  [[ $output == *"The folder is not changed yet"* ]] || { echo "$output"; return 1; }
  ! grep -qx down "$DB/events" || return 1
  [ ! -e "$LROOT/releases" ] && [ -e "$LROOT/.git" ]
}

@test "the preview names the exports copy and a COMPOSE_FILE line that was commented out as a rewrite of that line" {
  convert_host
  { for i in $(seq 1 27); do printf '# line %s\n' "$i"; done
    printf '# COMPOSE_FILE=docker-compose.dev.yml\n'
    printf 'DATA_PATH=./data\n'; } >"$LROOT/.env"
  convert_run en
  [ "$status" -eq 3 ] || { echo "$output"; return 1; }
  diff <(screen_of "$output" | sed "s#/opt/custodexa#/data/custodexa#g" | sed -n '/^  Stays in place/,/^                   \.env is copied aside/p') - <<'SCREEN' || { echo "$output"; return 1; }
  Stays in place   .env, tls/, data/
  Moves to         releases/1.12.4/ (the old version, kept)
                   the product files tracked by git, and .git
  Copied out       report exports in the old container -> data/exports/
  Setting change   .env line 29   DATA_PATH=./data
                              ->  DATA_PATH=/data/custodexa/data
                   .env line 28   # COMPOSE_FILE=docker-compose.dev.yml
                              ->  COMPOSE_FILE=current/compose.yml
                   one new line: COMPOSE_PROJECT_NAME
                   .env is copied aside before the change
SCREEN
  # Applied the same way: that line becomes the setting, no second COMPOSE_FILE line.
  convert_run en --yes
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [ "$(sed -n 28p "$LROOT/.env")" = COMPOSE_FILE=current/compose.yml ] && [ "$(grep -c '^COMPOSE_FILE=' "$LROOT/.env")" = 1 ] \
    || { cat -n "$LROOT/.env"; return 1; }
}
