# shellcheck shell=bash
# shellcheck disable=SC2154 # NEW_ROOT, OLD_ROOT and STAMP are set by the guide's blocks
# about: the procedure "Switching to an external database" (docs/ops/backup-and-restore.md 5.4), its ten command blocks taken from the guide at run time and run as written in one shell, on a source deployment and on a package deployment that start with the bundled database and data: the switch (the external database holds the last row written, the bundled database is kept, nothing starts on the old one), going back after the switch, a check that does not match (a package deployment goes back to the original), and going back after the data folder was set aside (a source deployment)
# needs: package
# images: pg16 openssl-3.5.4

readonly DM_DOC=/src/docs/ops/backup-and-restore.md
readonly DM_PORT=15520
readonly DM_SRC=/it/ms
readonly DM_PKG=/opt/custodexa
readonly DM_NEWP=/srv/custodexa-b
readonly DM_PWF=/it/dm-admin-password
DM_OUTF=/it/dm-out.txt
DM_RC=0
DM_N=0

# dm_block <n>: the n-th (from 1) bash code block of the section, as written.
dm_block() {
  awk -v n="$1" '
    index($0, "### 5.4") == 1 { on = 1; next }
    on && index($0, "## 6.") == 1 { exit }
    on && /^```bash$/ { k++; if (k == n) { inb = 1; next } }
    inb && /^```$/ { exit }
    inb { print }
  ' "$DM_DOC"
}

dm_count() {
  awk '
    index($0, "### 5.4") == 1 { on = 1; next }
    on && index($0, "## 6.") == 1 { exit }
    on && /^```bash$/ { k++ }
    END { print k + 0 }' "$DM_DOC"
}

# dm_adapt <root>: what changes in a block, and only this (the values the guide leaves for you to fill in,
# and "sudo -s", which is not needed as root already).
dm_adapt() {
  sed -e '/^sudo -s$/d' \
    -e "s|^cd /opt/custodexa\$|cd $1|" \
    -e "s|^X_HOST=db.example.internal\$|X_HOST=$(ex_addr)|" \
    -e "s|^X_PORT=5432\$|X_PORT=$DM_PORT|"
}

# dm_src <n> <root>: block n in the current shell (so the variables and functions stay), output to DM_OUTF
# and the screen, status in DM_RC. The caller's shell has no errexit, as an operator's.
dm_src() {
  local f=$IT_WORK/dm-blk-$1-$((++DM_N)).sh
  dm_block "$1" | dm_adapt "$2" >"$f"
  DM_RC=0
  # shellcheck disable=SC1090
  . "$f" >"$DM_OUTF" 2>&1 || DM_RC=$?
  sed 's/^/   > /' "$DM_OUTF" | tail -n 30
}

# dm_srcfile <file>: a file of block lines in the current shell, as dm_src.
dm_srcfile() {
  DM_RC=0
  # shellcheck disable=SC1090
  . "$1" >"$DM_OUTF" 2>&1 || DM_RC=$?
  sed 's/^/   > /' "$DM_OUTF" | tail -n 30
}

dm_ok() { "$@" || exit 1; }

dm_sql_b() { docker exec -i custodexa-postgres psql -X -q -At -v ON_ERROR_STOP=1 -U "$EX_USER" -d "$EX_DB" -c "$1"; }
dm_sql_x() { ex_db_sql ext "$EX_DB" "$1"; }

dm_healthy() {
  local i
  for ((i = 0; i < 120; i++)); do
    docker exec custodexa-backend wget -qO- http://localhost:8080/health >/dev/null 2>&1 && return 0
    sleep 2
  done
  docker logs custodexa-backend 2>&1 | tail -n 30 >&2
  it_die "the backend did not become healthy"
}

# dm_login <env file>: the administrator signs in over https; the first time, the initial password is changed
# (and the new one kept in DM_PWF), as the first sign-in requires. Echoes nothing; fails when no token.
dm_login() {
  local pw r new tok
  if [ -s "$DM_PWF" ]; then
    pw=$(cat "$DM_PWF")
  else
    pw=$(sed -n 's/^ADMIN_INITIAL_PASSWORD=//p' "$1" | tail -n 1)
  fi
  r=$(curl -sk --max-time 15 -H 'Content-Type: application/json' \
    -d "$(jq -cn --arg p "$pw" '{username: "admin", password: $p}')" https://localhost/api/v1/auth/login)
  if [ "$(jq -r '.password_change_required // false' <<<"$r")" = true ]; then
    new="It-$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')-9q"
    r=$(curl -sk --max-time 15 -H 'Content-Type: application/json' -H "Authorization: Bearer $(jq -r .change_token <<<"$r")" \
      -d "$(jq -cn --arg o "$pw" --arg n "$new" '{old_password: $o, new_password: $n}')" \
      https://localhost/api/v1/auth/change-password)
    printf '%s' "$new" >"$DM_PWF"
  fi
  tok=$(jq -r '.token // empty' <<<"$r")
  [ -n "$tok" ] || {
    printf 'sign-in failed: %s\n' "$(head -c 300 <<<"$r")"
    return 1
  }
}

# dm_counts <sql function>: users, sessions and audit_logs row counts of one side.
dm_users() { "$1" "SELECT count(*) FROM users"; }

dm_olddata() { # <dir>: what the guide records for the old data folder
  (cd "$1" && find . | wc -l | tr -d ' ' && du -sk . | cut -f1)
}

# dm_recorded <file>: the file the guide writes (a count, then "<KiB><tab>postgres") as "count KiB".
dm_recorded() { awk 'NR == 1 { c = $1 } NR == 2 { k = $1 } END { print c, k }' "$1"; }

dm_tree_sha() { # <root>: state file, .env and every file of the data folder
  (cd "$1" && { sha256sum state.json .env; find data -type f -print0 | sort -z | xargs -0 sha256sum; } | sha256sum | cut -d' ' -f1)
}

# dm_reset: drop everything of a path and make the external database empty again.
dm_reset() {
  ex_teardown "$DM_PKG"
  qs_down
  rm -rf "$DM_SRC" "$DM_NEWP" "$DM_PWF"
  it_pg_sql ext postgres "DROP DATABASE IF EXISTS \"$EX_DB\" WITH (FORCE)"
  it_pg_sql ext postgres "CREATE DATABASE \"$EX_DB\" OWNER $EX_USER"
}

# dm_start_source: a source deployment with the bundled database, a changed administrator password and some rows.
dm_start_source() {
  qs_tree "$DM_SRC"
  qs_env "$DM_SRC" KEK_PROVIDER=env TLS_MODE=selfsigned "DB_USER=$EX_USER" "DB_NAME=$EX_DB" "DB_PASSWORD=$EX_PASS"
  qs_run "$DM_SRC" --up
  it_same "quickstart.sh --up exits 0" 0 "$QS_RC"
  dm_healthy
}

dm_start_package() {
  it_unpack /opt
  ex_preset "$DM_PKG" KEK_PROVIDER=env "DB_USER=$EX_USER" "DB_NAME=$EX_DB" "DB_PASSWORD=$EX_PASS"
  it_cx "$DM_PKG" install --yes --images "$(it_bundle_file)" >/dev/null
  dm_healthy
  # the guide expects the release package next to the old deployment when the new folder is made
  cp "$(it_package_file)" "$DM_PKG/"
}

# dm_seed <root> <env file>: the administrator signs in (the password is changed), a second account and a last row.
dm_seed() {
  dm_login "$2"
  dm_sql_b "INSERT INTO users (username, password, active) VALUES ('it-extra', 'x', false)"
  dm_sql_b "CREATE TABLE IF NOT EXISTS it_sentinel (v text); INSERT INTO it_sentinel VALUES ('last-write-before-stop')"
  DM_USERS=$(dm_users dm_sql_b)
  it_say "   users on the bundled database: $DM_USERS"
  it_check "there are accounts to carry over" test "$DM_USERS" -ge 2
}

# one path: <form> <flow>   form: source | package   flow: forward | mismatch | aside
dm_path() {
  local form=$1 flow=$2 root env stamp old_sha n
  case $form in source) root=$DM_SRC ;; *) root=$DM_PKG ;; esac
  it_step "path: $form, $flow"
  ex_db_sql ext "$EX_DB" "SELECT 1" >/dev/null
  if [ "$form" = source ]; then dm_start_source; else dm_start_package; fi
  env=$root/.env
  dm_seed "$root" "$env"
  (
    set +e +u +o pipefail
    export PATH=$QS_BIN:$PATH QS_LOG=$QS_LOG

    it_step "step 1: check before you start"
    dm_src 1 "$root"
    dm_ok it_same "block 1 ran" 0 "$DM_RC"
    dm_ok it_check "it printed the two server versions, the empty database count and the free space" bash -c \
      '[ "$(grep -c "^PostgreSQL 16" "$1")" = 2 ] && tail -n 1 "$1" | grep -qx 0 && grep -q "^Filesystem" "$1"' _ "$DM_OUTF"
    dm_ok it_check "no command printed an error" bash -c '! grep -Eiq "error|no such|not found|denied|refused|failed" "$1"' _ "$DM_OUTF"
    dm_ok it_check "DATA_PATH is read from .env" grep -Eq '^DATA_PATH=.+' "$DM_OUTF"

    it_step "step 2: stop everything that writes (postgres stays up)"
    dm_sql_b "INSERT INTO it_sentinel VALUES ('the-very-last-row')"
    dm_src 2 "$root"
    dm_ok it_same "block 2 ran" 0 "$DM_RC"
    dm_ok it_same "the last line says postgres is the only service running" "running: postgres" "$(tail -n 1 "$DM_OUTF")"
    dm_ok it_same "docker ps: only the bundled postgres of the stack runs" "custodexa-postgres" "$(docker ps --format '{{.Names}}' --filter name=custodexa- | sort | paste -sd' ')"

    it_step "step 3: the final backup and the check numbers"
    dm_src 3 "$root"
    dm_ok it_same "block 3 ran" 0 "$DM_RC"
    stamp=$STAMP
    dm_ok it_check "the dump, the files, the .env copy and the check file are in the folder" bash -c \
      'cd "$1" && for f in custodexa-db-$2.dump custodexa-files-$2.tar.gz custodexa-env-$2.bak custodexa-check-$2.txt; do test -s "$f" || exit 1; done' _ "$PWD" "$stamp"
    dm_ok it_same "the check file lists migrations, users, sessions and audit_logs" "audit_logs migrations sessions users" \
      "$(cut -d'|' -f1 "custodexa-check-${stamp}.txt" | sort | paste -sd' ')"
    dm_ok it_same "the users line is the number counted on the bundled database" "$DM_USERS" "$(sed -n 's/^users|\([0-9]*\)|.*/\1/p' "custodexa-check-${stamp}.txt")"

    if [ "$flow" = mismatch ]; then
      it_step "step 4 with a check that does not match: the load, then one account deleted on the external database"
      dm_block 4 | dm_adapt "$root" >"$IT_WORK/dm-blk-4a.sh"
      sed -n '1,2p' "$IT_WORK/dm-blk-4a.sh" >"$IT_WORK/dm-blk-4a1.sh"
      sed -n '3,$p' "$IT_WORK/dm-blk-4a.sh" >"$IT_WORK/dm-blk-4a2.sh"
      dm_ok it_check "the block has the load and the echo, then the check and the diff" bash -c \
        'grep -q "pg_restore --dbname" "$1" && grep -q "pg_restore exit code" "$1" && grep -q "diff " "$2"' _ "$IT_WORK/dm-blk-4a1.sh" "$IT_WORK/dm-blk-4a2.sh"
      dm_srcfile "$IT_WORK/dm-blk-4a1.sh"
      dm_ok it_check "pg_restore exit code: 0" grep -qx 'pg_restore exit code: 0' "$DM_OUTF"
      dm_sql_x "DELETE FROM users WHERE username = 'it-extra'"
      dm_srcfile "$IT_WORK/dm-blk-4a2.sh"
      dm_ok it_check "the check numbers are not equal: diff prints the users line and the confirmation is absent" bash -c \
        'grep -q "users" "$1" && ! grep -q "check numbers are equal" "$1"' _ "$DM_OUTF"
      it_step "going back before step 6 (block 9), as the guide says for this case"
      dm_src 9 "$root"
      dm_ok it_same "block 9 ran" 0 "$DM_RC"
      dm_healthy
      dm_ok it_same "the bundled postgres runs again" custodexa-postgres "$(docker ps --format '{{.Names}}' --filter name=custodexa-postgres)"
      dm_ok it_same "the original deployment has the last row" "last-write-before-stop,the-very-last-row" "$(dm_sql_b 'SELECT string_agg(v, $$,$$ ORDER BY v) FROM it_sentinel')"
      dm_ok it_same "and all its accounts" "$DM_USERS" "$(dm_users dm_sql_b)"
      dm_ok it_same "the backend uses the bundled database" postgres "$(docker inspect custodexa-backend --format '{{range .Config.Env}}{{println .}}{{end}}' | sed -n 's/^DB_HOST=//p')"
      dm_ok dm_login "$env"
      exit 0
    fi

    it_step "step 4: load the dump into the external database and compare"
    dm_src 4 "$root"
    dm_ok it_same "block 4 ran" 0 "$DM_RC"
    dm_ok it_check "pg_restore exit code: 0" grep -qx 'pg_restore exit code: 0' "$DM_OUTF"
    dm_ok it_check "the check numbers are equal" grep -qx 'check numbers are equal' "$DM_OUTF"
    dm_ok it_same "the external database has the last row" "last-write-before-stop,the-very-last-row" "$(dm_sql_x 'SELECT string_agg(v, $$,$$ ORDER BY v) FROM it_sentinel')"

    it_step "step 5: keep the old data"
    dm_src 5 "$root"
    dm_ok it_same "block 5 ran" 0 "$DM_RC"
    dm_ok it_same "no container of the stack is left" "" "$(docker ps -aq --filter name=custodexa-)"
    n=$(sed 's/^/ /' "custodexa-olddata-${stamp}.txt" | paste -sd' ')
    it_say "   recorded for the old data folder (files, size in KiB):$n"
    if [ "$form" = source ]; then
      dm_ok it_check "the data folder was renamed, not copied or emptied" bash -c \
        'cd "$1/data" && test -d "postgres.before-external-$2" && ! test -e postgres' _ "$root" "$stamp"
      dm_ok it_same "renamed folder: the same file count and size" "$(dm_recorded "custodexa-olddata-${stamp}.txt")" \
        "$(dm_olddata "$root/data/postgres.before-external-$stamp" | paste -sd' ')"
    else
      old_sha=$(dm_tree_sha "$root")
      dm_ok it_check "the deployment folder keeps its data folder (not renamed)" test -d "$root/data/postgres"
    fi

    if [ "$flow" = aside ]; then
      it_step "going back before step 6 (block 9): the folder is renamed back and the original starts"
      dm_src 9 "$root"
      dm_ok it_same "block 9 ran" 0 "$DM_RC"
      dm_healthy
      dm_ok it_check "the data folder has its name again" bash -c 'test -d "$1/data/postgres" && ! test -e "$1/data/postgres.before-external-$2"' _ "$root" "$stamp"
      dm_ok it_same "the original deployment has the last row" "last-write-before-stop,the-very-last-row" "$(dm_sql_b 'SELECT string_agg(v, $$,$$ ORDER BY v) FROM it_sentinel')"
      dm_ok it_same "and all its accounts" "$DM_USERS" "$(dm_users dm_sql_b)"
      dm_ok it_same "the backend uses the bundled database" postgres "$(docker inspect custodexa-backend --format '{{range .Config.Env}}{{println .}}{{end}}' | sed -n 's/^DB_HOST=//p')"
      dm_ok dm_login "$env"
      exit 0
    fi

    it_step "step 6: switch"
    if [ "$form" = source ]; then
      dm_src 6 "$root"
      dm_ok it_same "block 6 ran (quickstart.sh --up exited 0)" 0 "$DM_RC"
    else
      dm_block 7 | dm_adapt "$root" >"$IT_WORK/dm-blk-7.sh"
      dm_ok it_check "the last line of the block is install --yes" bash -c 'tail -n 1 "$1" | grep -qx "./custodexa.sh install --yes"' _ "$IT_WORK/dm-blk-7.sh"
      sed '$d' "$IT_WORK/dm-blk-7.sh" >"$IT_WORK/dm-blk-7a.sh"
      # the guide: with no registry access add --images <bundle>
      printf './custodexa.sh install --yes --images %s\n' "$(it_bundle_file)" >"$IT_WORK/dm-blk-7b.sh"
      dm_srcfile "$IT_WORK/dm-blk-7a.sh"
      dm_ok it_same "the preparation of the new folder ran" 0 "$DM_RC"
      dm_ok it_same "no service of the stack runs before install" "" "$(docker ps -q --filter name=custodexa-)"
      dm_ok it_check "the new .env has the three keys, no DATA_PATH and no managed block" bash -c \
        'grep -q "^EXTERNAL_DB_HOST=$2" "$1" && grep -q "^EXTERNAL_DB_PORT=$3" "$1" && grep -q "^DB_SSLMODE=require" "$1" && ! grep -q "^DATA_PATH=" "$1" && ! grep -q "^# >>> managed by custodexa.sh" "$1"' _ "$NEW_ROOT/.env" "$(ex_addr)" "$DM_PORT"
      dm_srcfile "$IT_WORK/dm-blk-7b.sh"
      dm_ok it_same "install exits 0 on the database that is already loaded" 0 "$DM_RC"
    fi
    dm_healthy
    dm_ok it_same "no postgres container runs or exists" "" "$(docker ps -aq --filter name=custodexa-postgres)"
    dm_ok it_same "the backend connects to the external server" "$(ex_addr)" "$(docker inspect custodexa-backend --format '{{range .Config.Env}}{{println .}}{{end}}' | sed -n 's/^DB_HOST=//p')"
    dm_ok it_same "the external database has the last row" "last-write-before-stop,the-very-last-row" "$(dm_sql_x 'SELECT string_agg(v, $$,$$ ORDER BY v) FROM it_sentinel')"
    dm_ok it_same "users equals the number written down in step 3" "$DM_USERS" "$(dm_users dm_sql_x)"
    if [ "$form" = package ]; then
      dm_ok it_same "the old deployment folder is unchanged (state file, .env, every file of the data folder)" "$old_sha" "$(dm_tree_sha "$DM_PKG")"
    fi

    it_step "step 7: verify"
    dm_src 8 "$root"
    dm_ok it_same "block 8 ran" 0 "$DM_RC"
    dm_ok it_check "migrations and users print equal, nothing prints DIFFERENT" bash -c \
      'grep -qx "migrations: equal" "$1" && grep -qx "users: equal" "$1" && ! grep -q DIFFERENT "$1"' _ "$DM_OUTF"
    dm_ok it_same "the last command prints the sessions and audit_logs lines of both files" 4 "$(grep -cE '(sessions|audit_logs)\|' "$DM_OUTF")"
    if [ "$form" = package ]; then
      dm_ok dm_login "$NEW_ROOT/.env"
    else
      dm_ok dm_login "$env"
    fi
    echo "   (the administrator, whose password was changed on the original deployment, signs in on the new one)"
    if [ "$form" = source ]; then
      dm_ok it_same "the renamed data folder still has the recorded file count and size" "$(dm_recorded "custodexa-olddata-${stamp}.txt")" \
        "$(dm_olddata "$root/data/postgres.before-external-$stamp" | paste -sd' ')"
    else
      dm_ok it_same "the old deployment folder is still unchanged" "$old_sha" "$(dm_tree_sha "$DM_PKG")"
    fi

    it_step "going back after step 6: a row written on the new deployment is lost, the original starts"
    dm_sql_x "CREATE TABLE it_after (v text); INSERT INTO it_after VALUES ('written-after-switch')"
    dm_src 10 "$root"
    dm_ok it_same "block 10 ran" 0 "$DM_RC"
    dm_healthy
    dm_ok it_same "the new deployment no longer runs: one backend, with the bundled database" postgres \
      "$(docker inspect custodexa-backend --format '{{range .Config.Env}}{{println .}}{{end}}' | sed -n 's/^DB_HOST=//p')"
    dm_ok it_same "the bundled postgres runs again" custodexa-postgres "$(docker ps --format '{{.Names}}' --filter name=custodexa-postgres)"
    dm_ok it_same "the original deployment has the last row" "last-write-before-stop,the-very-last-row" "$(dm_sql_b 'SELECT string_agg(v, $$,$$ ORDER BY v) FROM it_sentinel')"
    dm_ok it_same "it does not have the row written after the switch" "" "$(dm_sql_b "SELECT to_regclass('it_after')")"
    dm_ok it_same "and all its accounts" "$DM_USERS" "$(dm_users dm_sql_b)"
    if [ "$form" = source ]; then
      dm_ok it_same ".env is the one copied in step 3" "$(sha256sum <"custodexa-env-${stamp}.bak" | cut -d' ' -f1)" "$(sha256sum <"$env" | cut -d' ' -f1)"
      dm_ok it_check "the data folder has its name again" bash -c 'test -d "$1/data/postgres" && ! test -e "$1/data/postgres.before-external-$2"' _ "$root" "$stamp"
    fi
    dm_ok dm_login "$env"
  ) || it_die "path $form $flow failed"
  it_say "   path $form $flow: done"
  dm_reset
}

scenario() {
  qs_images
  it_step "the guide has ten bash blocks in this section"
  it_same "block count" 10 "$(dm_count)"
  ex_pg_start ext 16 "$DM_PORT" tls-only
  ex_db_create ext
  dm_path source forward
  dm_path package forward
  dm_path package mismatch
  dm_path source aside
  it_step "clean up"
  dm_reset
  it_pg_stop ext
}
