# A package deployment for the backup, upgrade and rollback tests, with a fake database behind
# `docker compose exec -T postgres ...`. Needs helper.bash and install_host.bash loaded.
#   $DB/<name>      what psql prints for a query (size, count.users, count.sessions, count.active,
#                   count.audit_logs, migrations, kek, export, checkpoint, server_version,
#                   server_version_num, encoding); <name>.rc makes it fail
#   $DB/pg_dump_version   what `pg_dump --version` prints
#   $DB/health      what the backend's /health answers; $DB/health.rc makes every try fail
#   $DB/pg_dump.rc, $DB/pg_restore.rc, $DB/pg_dump_version.rc, $DB/stop.rc, $DB/start.rc,
#   $DB/run.rc      make that call fail
#   $DB/du.<path with / as ->   bytes du reports for that path (else the real du)
#   $DB/events      the order of what happened: stop, start, health, pg_dump, pg_restore,
#                   tar -czf <file>, tar pack <file>, tar readback, run <name>, rm -f <name>...
#   $DB/db-calls    one line per database call: "<CX_DB_ACTION or none> <what>"
#   $DB/run.argv, run.env, run.mounts, run.names   what each `docker run` was given (run.argv: one
#                   line each)
#   $DB/images      image IDs `docker image inspect` finds (one per line; others go to the replay
#                   files); bk_openssl records one
#   $DB/pause.run.<role>   that tool container stops before its command until $DB/go.run.<role>
#   $DB/run.odd     a tool container writes its output file in pieces of 1000 bytes, one at a time
#   $DB/run.tmpfs   the --tmpfs of each `docker run`
# An external database (bk_external): `docker run` of a PostgreSQL client image (entrypoint psql,
# pg_dump, pg_restore, or test for the system CA file) is answered from the same $DB files as the
# bundled service, and also from:
#   $DB/tablespaces, owners  rows "<hex name>|<objects>" (custom tablespaces; owners besides DB_USER)
#   $DB/extensions  rows "<name> <version>"     $DB/grants   rows "<hex role name>"
#   $DB/datdba      t when DB_USER owns the database
#   $DB/connections the connections of the application account (step 6 of upgrade)
#   $DB/connect.rc  every connecting call (psql, pg_dump) fails as an unreachable server does
#   $DB/sysca.absent  image IDs whose image has no system CA file (test -f fails)
#   $DB/pause.db.<tool>   that client stops before answering until $DB/go.db.<tool>
#   $DB/db-runs     "<CX_DB_ACTION> <image> <what>" per client container
#   $DB/pgpass.seen "<mode> <host path>" of the pgpass file each client was given; pgpass.content
#                   its lines
#   $DB/db-env      the environment each client's docker call was started with
# The backup's own steps, for the failure and interruption tests (lib/portable.sh):
#   $DB/tar.<member>.rc   tar -czf of <member>.tar.gz fails (audit, recordings, tls)
#   $DB/tar.pack.rc, tar.pack.dup, tar.pack.link, tar.pack.cut   building the backup file fails,
#                   gets a member a second time ($DB/dup/snapshot.txt), gets a symbolic link, or
#                   loses its end
#   $DB/tar.readback.rc   reading the backup file back fails
#   $DB/sha256.rc   sha256sum fails once the backup file is built (reading it back, the side file)
#   $DB/ln.sidecar.rc, ln.file.rc   putting the side file, or the backup file, in place fails
#   $DB/mv.state.rc       writing state.json fails once it would point at a new backup file
#   $DB/rmdir.rc          removing the temporary folder fails
#   $DB/pause.<point>     stop at that point until $DB/go.<point> exists ($DB/paused.<point> says
#                   it got there): start (after step 4), committed (backup file in place),
#                   recorded (state.json points at it)
#   $DB/tar.<member>.sleep, tar.readback.sleep   that tar call starts a long sleep and waits for it
#                   ($DB/paused.tar says so; $DB/tar.pid and $DB/tar.sleep.pid name both processes),
#                   so a signal finds a step's command running
#   $DB/tools       container names `docker ps -a --filter name=<prefix>` lists (one per line)
#   $DB/svc         stopped after the services are stopped, running after a start or `up -d`; the
#                   answer of `compose ps --status running`

# backup_host [mode]: $ROOT laid out as an installed 1.13.0 package deployment. The mode is the
# master key mode its .env describes (bk_dotenv): ui (default), env, implicit, kms or hsm.
backup_host() {
  local kek=${1:-ui}
  # A test may wipe its folder and lay the host out again: forget where ln, mv and tar were found.
  hash -r
  ROOT=$BATS_TEST_TMPDIR/opt/custodexa
  make_root "$ROOT"
  printf '1.13.0\n' >"$ROOT/releases/1.13.0/VERSION"
  use_fake_docker
  FAKES=$BATS_TEST_TMPDIR/host
  mkdir -p "$FAKES"
  export PATH="$FAKES:$PATH"
  unset LC_ALL LC_MESSAGES LANG NO_COLOR CUSTODEXA_HOME
  export DB=$BATS_TEST_TMPDIR/db ROOT
  mkdir -p "$DB"
  : >"$DB/events"
  : >"$DB/db-calls"
  bk_state_fresh
  # Test values only; they stand for secrets so the tests can look for them in logs and files.
  BK_JWT=jwt-test-value-for-masking-0001
  BK_KEK=kek-test-value-for-masking-0002
  BK_DBPW=dbpw-test-value-for-masking-03
  bk_dotenv "$kek"
  # The postgres index digest of the release (the release fixture's) and another one.
  BK_PG_DIGEST=sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea
  BK_PG_DIGEST_OTHER=sha256:1111111111111111111111111111111111111111111111111111111111111111
  bk_manifest 1.13.0 "$BK_PG_DIGEST" >"$ROOT/releases/1.13.0/MANIFEST.json"
  mkdir -p "$ROOT/data/recordings/2026" "$ROOT/data/audit" "$ROOT/data/exports" "$ROOT/tls"
  printf 'rec\n' >"$ROOT/data/recordings/2026/a.cast"
  printf 'audit\n' >"$ROOT/data/audit/fallback.log"
  printf 'plaintext evidence\n' >"$ROOT/data/exports/evidence.zip"
  printf 'cert\n' >"$ROOT/tls/server.crt"
  db_default
  write_db_hook
  bk_fakes
  host_free / 221249536 # 211 GB in KiB
}

# bk_state_fresh: state.json of the installed 1.13.0 deployment, no backup on record.
bk_state_fresh() {
  printf '{\n  "format": "2",\n  "compose_project": "custodexa",\n  "current.version": "1.13.0",\n  "current.overlays": "",\n  "install.result": "succeeded"\n}\n' >"$ROOT/state.json"
}

# bk_dotenv <mode>: a .env that is valid for the master key mode: ui, kms and hsm hold no
# ENCRYPTION_KEY (kms names its provider), env declares KEK_PROVIDER=env with a key, implicit has
# a key and no KEK_PROVIDER line (the compatible env mode).
bk_dotenv() {
  case $1 in
    ui | hsm) bk_dotenv_raw "KEK_PROVIDER=$1" ;;
    kms) bk_dotenv_raw KEK_PROVIDER=kms KEK_KMS_PROVIDER=aws ;;
    env) bk_dotenv_raw KEK_PROVIDER=env "ENCRYPTION_KEY=$BK_KEK" ;;
    implicit) bk_dotenv_raw "ENCRYPTION_KEY=$BK_KEK" ;;
    *) echo "bk_dotenv: unknown mode $1" >&2; return 1 ;;
  esac
}

# bk_dotenv_raw <line>...: the .env with these master key lines, as given. A contradictory
# setting (KEK_PROVIDER=ui with an ENCRYPTION_KEY, an unknown provider) is written this way.
bk_dotenv_raw() {
  (
    umask 077
    printf '%s\n' "DATA_PATH=./data" "DB_USER=postgres" "DB_PASSWORD=$BK_DBPW" "DB_NAME=custodexa" \
      "JWT_SECRET=$BK_JWT" "$@" "PUBLIC_BASE_URL=https://10.0.0.12" "TLS_MODE=selfsigned" \
      "TLS_DOMAIN=custodexa.example.internal" "TLS_IP_SAN=10.0.0.12" >"$ROOT/.env"
  )
}

# bk_manifest <version> <postgres index digest>: a release MANIFEST.json the way jq writes it.
bk_manifest() {
  jq -n --arg v "$1" --arg d "$2" '{format: 1, version: $v, images: {
      postgres: {ref: "docker.io/library/postgres", tag: "16.15-alpine3.24", index_digest: $d},
      openssl: {ref: "docker.io/alpine/openssl", tag: "3.5.4",
        index_digest: "sha256:42c7389ef077aed0eb4e96d0abbd094083d701bbaff1313073b061c0c9cd8278"}},
    migrations: [], rollback_compatible: []}'
}

# db_default: a database with users, sessions, audit rows, two migrations and one key of each kind.
db_default() {
  printf '%s\n' 5 >"$DB/count.users"
  printf '%s\n' 42 >"$DB/count.sessions"
  printf '%s\n' 2 >"$DB/count.active"
  printf '%s\n' 1234 >"$DB/count.audit_logs"
  printf '%s\n' 20260816_schema_baseline 20260901_add_x >"$DB/migrations"
  printf '%s\n' 5a5a5a5a5a5a5a5a >"$DB/kek"
  # 32 bytes of "A" and of "B", base64 (Ed25519 public keys are 32 bytes).
  printf '%s\n' QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE= >"$DB/export"
  printf '%s\n' QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI= >"$DB/checkpoint"
  printf '%s\n' 1073741824 >"$DB/size"
  printf '%s\n' 16.15 >"$DB/server_version"
  printf '%s\n' 160015 >"$DB/server_version_num"
  printf '%s\n' 'UTF8|en_US.utf8|en_US.utf8' >"$DB/encoding"
  printf '%s\n' 'pg_dump (PostgreSQL) 16.15' >"$DB/pg_dump_version"
  printf '%s\n' '{"status":"ok","version":"1.13.0"}' >"$DB/health"
  printf 't\n' >"$DB/datdba"
  printf '0\n' >"$DB/connections"
}

# backup_strict: a docker call that neither the hook nor a replay file answers exits 99.
backup_strict() { export FAKE_DOCKER_STRICT=1; }

write_db_hook() {
  cat >"$FAKE_DOCKER_REPLAY/hook" <<'HOOK'
#!/bin/bash
# The postgres and backend containers, the stop/start of the services and the backup's tool
# containers, for the backup tests. Anything else is not answered here (99).
all=" $* "
ev() { printf '%s\n' "$1" >>"$DB/events"; }
rc() { [ -e "$DB/$1.rc" ] && exit "$(cat "$DB/$1.rc")"; return 0; }
via() {
  printf '%s %s\n' "${CX_DB_ACTION:-none}" "$1" >>"$DB/db-calls"
  [ -z "${RUN_IMG:-}" ] || printf '%s %s %s\n' "${CX_DB_ACTION:-none}" "$RUN_IMG" "$1" >>"$DB/db-runs"
}
pause() {
  [ -e "$DB/pause.$1" ] || return 0
  rm -f "$DB/pause.$1"
  : >"$DB/paused.$1"
  until [ -e "$DB/go.$1" ]; do /usr/bin/sleep 0.05; done
}
# psql_answer <sql> [image]: what the fake database answers for a query (exit 99 when the query is
# not one it knows). Once an upgrade started the new version ($UP, tests/upgrade_host.bash), the
# reads that have an $UP/after.<name> answer from it.
psql_answer() {
  local sql=$1 f
  case $sql in
    *pg_stat_activity*) f=connections ;;
    *aclexplode*) f=grants ;;
    *pg_extension*) f=extensions ;;
    *datdba*) f=datdba ;;
    *pg_tablespace*) f=tablespaces ;;
    *relowner*) f=owners ;;
    *pg_database_size*) f=size ;;
    *server_version_num*) f=server_version_num ;;
    *"SHOW server_version"*) f=server_version ;;
    *pg_encoding_to_char*) f=encoding ;;
    *"FROM users"*) f=count.users ;;
    *"FROM sessions WHERE status = 'active'"*) f=count.active ;;
    *"FROM sessions"*) f=count.sessions ;;
    *"FROM audit_logs"*) f=count.audit_logs ;;
    *schema_migrations*) f=migrations ;;
    *data_keys*) f=kek ;;
    *export_signing_keys*) f=export ;;
    *checkpoint_signing_keys*) f=checkpoint ;;
    *) echo "fake psql: unknown query: $sql" >&2; exit 99 ;;
  esac
  if [ -n "${UP:-}" ] && [ -e "$UP/after.$f" ] && grep -qx up "$DB/events"; then
    via "psql $f after"
    cat "$UP/after.$f"
    exit 0
  fi
  ev "psql $f"
  via "psql $f"
  rc "$f"
  # The one piece of SQL the fake honours: LIMIT 1 keeps the first row.
  case $sql in
    *"LIMIT 1"*) [ -e "$DB/$f" ] && head -n 1 "$DB/$f" ;;
    *) [ -e "$DB/$f" ] && cat "$DB/$f" ;;
  esac
  exit 0
}
# unreachable: $DB/connect.rc makes a connecting client fail as libpq does.
unreachable() {
  [ -e "$DB/connect.rc" ] || return 0
  ev "connect-failed"
  echo 'psql: error: connection to server at "db.example.internal" (10.0.0.5), port 5432 failed: Connection refused' >&2
  exit "$(cat "$DB/connect.rc")"
}
# db_run <image> <tool> <arguments...>: a PostgreSQL client container (tool_run's envs and mounts).
db_run() {
  local tool=$2 e k p
  RUN_IMG=$1
  shift 2
  # The environment the docker client itself was started with (what `ps e` would show of it).
  env >>"$DB/db-env"
  for e in "${envs[@]+"${envs[@]}"}"; do
    [[ $e == PGPASSFILE=* ]] || continue
    p=${e#PGPASSFILE=}
    for k in "${mounts[@]+"${mounts[@]}"}"; do
      [ "${k#*:}" = "$p:ro" ] || continue
      printf '%s %s\n' "$(stat -c %a "${k%%:*}")" "${k%%:*}" >>"$DB/pgpass.seen"
      cat "${k%%:*}" >>"$DB/pgpass.content"
    done
  done
  pause "db.$tool"
  case $tool in
    test)
      ev "sysca $RUN_IMG"
      [ -e "$DB/sysca.absent" ] && grep -qxF -- "$RUN_IMG" "$DB/sysca.absent" && exit 1
      exit 0 ;;
    pg_restore)
      ev pg_restore; via pg_restore; cat >/dev/null; rc pg_restore; printf ';\n; Archive created at 2026-09-30\n'; exit 0 ;;
    pg_dump)
      if [ "${1:-}" = --version ]; then
        ev pg_dump_version; via pg_dump_version; rc pg_dump_version; cat "$DB/pg_dump_version"; exit 0
      fi
      unreachable
      ev pg_dump; via pg_dump; rc pg_dump; printf 'PGDMP fake custom-format dump\n'; exit 0 ;;
    psql) unreachable; psql_answer "${*: -1}" ;;
  esac
  exit 99
}
# docker run [options] <image> <command...>: the tool container, run here with its mounts mapped
# back to the host paths.
tool_run() {
  local name="" a k img
  local -a envs=() mounts=() cmd=() tmpfs=()
  shift
  # One line per container: a newline inside an argument (a query) is written as a space.
  a="$*"
  printf '%s\n' "${a//$'\n'/ }" >>"$DB/run.argv"
  while [ $# -gt 0 ]; do
    case $1 in
      --rm | -i | -t) shift ;;
      --pull | --network | --user | -u | --workdir | -w | --log-driver) shift 2 ;;
      --entrypoint) cmd=("$2"); shift 2 ;;
      --name) name=$2; shift 2 ;;
      -e) envs+=("$2"); shift 2 ;;
      -v) mounts+=("$2"); shift 2 ;;
      --tmpfs) tmpfs+=("$2"); shift 2 ;;
      -*) echo "fake docker run: unknown option $1" >&2; exit 99 ;;
      *) break ;;
    esac
  done
  img=$1
  shift # the image
  printf '%s\n' "$name" >>"$DB/run.names"
  printf '%s\n' "${envs[@]+"${envs[@]}"}" >>"$DB/run.env"
  printf '%s\n' "${mounts[@]+"${mounts[@]}"}" >>"$DB/run.mounts"
  printf '%s\n' "${tmpfs[@]+"${tmpfs[@]}"}" >>"$DB/run.tmpfs"
  case ${cmd[0]:-} in
    psql | pg_dump | pg_restore | test) db_run "$img" "${cmd[0]}" "$@" ;;
  esac
  ev "run $name"
  rc run
  pause "run.${name##*-}"
  local host ctr
  for a in "$@"; do
    for k in "${mounts[@]+"${mounts[@]}"}"; do
      host=${k%%:*} ctr=${k#*:}
      ctr=${ctr%%:*}
      case $a in "$ctr"*) a=$host${a#"$ctr"} ;; esac
    done
    cmd+=("$a")
  done
  for k in "${!envs[@]}"; do
    [[ ${envs[k]} == *=* ]] || envs[k]="${envs[k]}=${!envs[k]:-}"
  done
  # $DB/run.odd: the output file is written in pieces of 1000 bytes, as a pipe may hand them over.
  if [ -e "$DB/run.odd" ]; then
    local out="" i
    for i in "${!cmd[@]}"; do [ "${cmd[i]}" != -out ] || { out=${cmd[i + 1]}; cmd[i + 1]=/dev/stdout; }; done
    if [ -n "$out" ]; then
      env "${envs[@]+"${envs[@]}"}" "${cmd[@]}" | while :; do
        dd bs=1000 count=1 iflag=fullblock status=none >"$DB/run.piece"
        [ -s "$DB/run.piece" ] || break
        cat "$DB/run.piece" >&3
        /usr/bin/sleep 0.01
      done 3>"$out"
      exit "${PIPESTATUS[0]}"
    fi
  fi
  exec env "${envs[@]+"${envs[@]}"}" "${cmd[@]}"
}
case $1 in
  compose) ;;
  run) tool_run "$@" ;;
  image)
    # image inspect --format {{.Id}} <ID>: an ID listed in $DB/images; any other image is left to
    # the replay files of the test (99).
    [ "$2" = inspect ] && [ -e "$DB/images" ] && grep -qxF -- "${*: -1}" "$DB/images" || exit 99
    printf '%s\n' "${*: -1}"
    exit 0 ;;
  rm) ev "rm $*"; exit 0 ;;
  ps)
    f=""
    for a in "$@"; do case $a in name=*) f=${a#name=} ;; esac; done
    ev "ps $f"
    [ ! -e "$DB/tools" ] || grep -F -- "$f" "$DB/tools" || true
    exit 0 ;;
  *) exit 99 ;;
esac
case $all in
  *" exec -T postgres psql "*) psql_answer "${*: -1}" ;;
  *" exec -T postgres pg_dump --version "*)
    ev pg_dump_version; via pg_dump_version; rc pg_dump_version; cat "$DB/pg_dump_version"; exit 0 ;;
  *" exec -T postgres pg_dump "*) ev pg_dump; via pg_dump; rc pg_dump; printf 'PGDMP fake custom-format dump\n'; exit 0 ;;
  *" exec -T postgres pg_restore --list "*)
    ev pg_restore; via pg_restore; cat >/dev/null; rc pg_restore; printf ';\n; Archive created at 2026-09-30\n'; exit 0 ;;
  *" exec -T backend wget "*) ev health; rc health; cat "$DB/health"; exit 0 ;;
  *" stop "*) ev "stop ${*: -3}"; rc stop; echo stopped >"$DB/svc"; exit 0 ;;
  *" start "*) pause start; ev "start ${*: -3}"; rc start; echo running >"$DB/svc"; exit 0 ;;
  *" up -d "*) ev up; rc up; echo running >"$DB/svc"; exit 0 ;;
  *" ps --all --services "*) printf '%s\n' postgres guacd backend frontend; exit 0 ;;
  *" ps --status running --services "*)
    if [ "$(cat "$DB/svc" 2>/dev/null)" = stopped ]; then echo postgres; else printf '%s\n' postgres guacd backend frontend; fi
    exit 0 ;;
esac
exit 99
HOOK
  chmod +x "$FAKE_DOCKER_REPLAY/hook"
}

# bk_fakes: the host tools the backup uses, each passing through to the real one unless a switch
# file in $DB says otherwise.
bk_fakes() {
  fake du 'p=${@: -1}; k=$(printf "%s" "$p" | tr / -); if [ -e '"$DB"'/du.$k ]; then printf "%s\t%s\n" "$(cat '"$DB"'/du.$k)" "$p"; else exec /usr/bin/du "$@"; fi'
  fake hostname 'if [ "${1:-}" = -f ]; then echo ops-host.example.internal; else echo ops-host; fi'
  # shellcheck disable=SC2016
  fake tar 'DB='"$DB"'
ev() { printf "%s\n" "$1" >>"$DB/events"; }
sw() { [ -e "$DB/$1" ]; }
hold() { # the long-running command a signal is to find
  echo $$ >"$DB/tar.pid"
  /usr/bin/sleep 60 &
  echo $! >"$DB/tar.sleep.pid"
  : >"$DB/paused.tar"
  wait
  exit 1
}
case " $* " in
  *" --format=gnu -cf "*)
    a=""; prev=""
    for x in "$@"; do [ "$prev" = -cf ] && a=$x; prev=$x; done
    ev "tar pack ${a##*/}"
    sw tar.pack.rc && exit "$(cat "$DB/tar.pack.rc")"
    /usr/bin/tar "$@" || exit $?
    if sw tar.pack.dup; then /usr/bin/tar --format=gnu -rf "$a" -C "$DB/dup" snapshot.txt || exit $?; fi
    if sw tar.pack.link; then
      mkdir -p "$DB/dup" && /usr/bin/ln -sfn /etc/hostname "$DB/dup/link" || exit $?
      /usr/bin/tar --format=gnu -rf "$a" -C "$DB/dup" link || exit $?
    fi
    if sw tar.pack.cut; then truncate -s 10240 "$a" || exit $?; fi
    exit 0 ;;
  *" --to-command="*) ev "tar readback"; sw tar.readback.rc && exit "$(cat "$DB/tar.readback.rc")"; sw tar.readback.sleep && hold ;;
esac
case "$1" in
  -czf | -tzf)
    ev "tar $1 ${2##*/}"
    m=${2##*/}; m=${m%%.*}
    [ "$1" = -czf ] && sw "tar.$m.rc" && exit "$(cat "$DB/tar.$m.rc")"
    [ "$1" = -czf ] && sw "tar.$m.sleep" && hold ;;
esac
exec /usr/bin/tar "$@"'
  # shellcheck disable=SC2016
  fake sha256sum 'if [ -e '"$DB"'/sha256.rc ] && compgen -G '"'$ROOT'"'"/backups/.partial-*/custodexa-backup-*.tar" >/dev/null; then
  exit "$(cat '"$DB"'/sha256.rc)"
fi
exec /usr/bin/sha256sum "$@"'
  # shellcheck disable=SC2016
  fake ln 'DB='"$DB"'; t=${@: -1}
case $t in
  *.sha256) [ -e "$DB/ln.sidecar.rc" ] && exit "$(cat "$DB/ln.sidecar.rc")" ;;
  *.tar | *.tar.enc) [ -e "$DB/ln.file.rc" ] && exit "$(cat "$DB/ln.file.rc")" ;;
esac
/usr/bin/ln "$@" || exit $?
case $t in *.sha256 | *.tar | *.tar.enc) printf "ln %s\n" "${t##*/}" >>"$DB/events" ;; esac
case $t in
  *.tar | *.tar.enc)
    if [ -e "$DB/pause.committed" ]; then
      rm -f "$DB/pause.committed"; : >"$DB/paused.committed"
      until [ -e "$DB/go.committed" ]; do /usr/bin/sleep 0.05; done
    fi ;;
esac
exit 0'
  # mv to state.json: the write that would point last_backup.file at another backup file.
  # shellcheck disable=SC2016
  fake mv 'DB='"$DB"'; s=${@: -2:1}; t=${@: -1}
pointer() { sed -n "s/^  \"last_backup.file\": \"\(.*\)\",\{0,1\}\$/\1/p" "$1" 2>/dev/null; }
new=""
case $t in
  */state.json)
    new=$(pointer "$s")
    if [ -n "$new" ] && [ "$new" != "$(pointer "$t")" ]; then
      [ -e "$DB/mv.state.rc" ] && exit "$(cat "$DB/mv.state.rc")"
    else
      new=""
    fi ;;
esac
/usr/bin/mv "$@" || exit $?
if [ -n "$new" ] && [ -e "$DB/pause.recorded" ]; then
  rm -f "$DB/pause.recorded"; : >"$DB/paused.recorded"
  until [ -e "$DB/go.recorded" ]; do /usr/bin/sleep 0.05; done
fi
exit 0'
  # shellcheck disable=SC2016
  fake rmdir 'case ${@: -1} in *.partial-*) [ -e '"$DB"'/rmdir.rc ] && exit "$(cat '"$DB"'/rmdir.rc)" ;; esac
exec /usr/bin/rmdir "$@"'
}

# BK_OPENSSL_ID: the openssl image of the release fixture (its index digest, the ID on containerd).
BK_OPENSSL_ID=sha256:42c7389ef077aed0eb4e96d0abbd094083d701bbaff1313073b061c0c9cd8278

# bk_openssl [tool]: the openssl image recorded for this deployment and present on the host: a
# service image (current.image_ids, the built-in form) or, with "tool", a tool image
# (current.tool_image_ids, the external ingress form).
bk_openssl() {
  local key=current.image_ids
  [ "${1:-}" != tool ] || key=current.tool_image_ids
  jq --arg k "$key" --arg v "openssl=$BK_OPENSSL_ID" '.[$k] = $v' "$ROOT/state.json" >"$ROOT/state.json.new"
  /usr/bin/mv "$ROOT/state.json.new" "$ROOT/state.json"
  printf '%s\n' "$BK_OPENSSL_ID" >"$DB/images"
}

# bk_passfile <path> <passphrase>: a passphrase file as the help shows how to make one (0600, root).
bk_passfile() {
  (umask 077 && printf '%s\n' "$2" >"$1")
  chmod 600 "$1"
}

# bk_decrypt <file> <passphrase> <out>: the tar inside an encrypted backup file, by the
# command a restore uses (the test image's openssl, which names the salt length).
bk_decrypt() {
  printf '%s\n' "$2" | /usr/bin/openssl enc -d -aes-256-cbc -saltlen 8 -pbkdf2 -md sha256 -iter 600000 \
    -pass stdin -in "$1" -out "$3"
}

# bk_one_enc: BK_FILE is the one encrypted backup file in backups/; fails when there is none or more.
bk_one_enc() {
  local -a f=()
  mapfile -t f < <(compgen -G "$ROOT/backups/custodexa-backup-*.tar.enc" || true)
  [ "${#f[@]}" -eq 1 ] || { echo "encrypted backup files: ${#f[@]}"; ls -lA "$ROOT/backups" 2>&1; return 1; }
  BK_FILE=${f[0]}
}

# backup_run <lang> [options...]: the real script without a terminal.
backup_run() {
  local l=$1
  shift
  run bash "$ROOT/custodexa.sh" backup --lang "$l" "$@" </dev/null
}

# backup_bg <out file> [options...]: the real script in the background (BK_PID), English, --yes.
# BK_SCRIPT is the script to run (default: the deployment's).
backup_bg() {
  local out=$1
  shift
  bash "${BK_SCRIPT:-$ROOT/custodexa.sh}" backup --lang en --yes "$@" </dev/null >"$out" 2>&1 &
  BK_PID=$!
}

# release_next: releases/1.13.2 with the script tree, its VERSION and a MANIFEST.json whose postgres
# digest differs from the installed release's; BK_SCRIPT runs it. current stays 1.13.0.
release_next() {
  local d=$ROOT/releases/1.13.2
  mkdir -p "$d"
  cp -R "$SRC/custodexa.sh" "$SRC/lib" "$SRC/lang" "$d/"
  printf '1.13.2\n' >"$d/VERSION"
  bk_manifest 1.13.2 "$BK_PG_DIGEST_OTHER" >"$d/MANIFEST.json"
  BK_SCRIPT=$d/custodexa.sh
}

# bk_one: BK_FILE is the one backup file in backups/; fails when there is none or more than one.
bk_one() {
  local -a f=()
  mapfile -t f < <(compgen -G "$ROOT/backups/custodexa-backup-*.tar" || true)
  [ "${#f[@]}" -eq 1 ] || { echo "backup files: ${#f[@]}"; ls -lA "$ROOT/backups" 2>&1; return 1; }
  BK_FILE=${f[0]}
}

# bk_member <name> [file]: a member of the backup file on stdout.
bk_member() { /usr/bin/tar -xOf "${2:-$BK_FILE}" "$1"; }

# bk_mf <key>: a value of the backup manifest in BK_FILE ("MISSING" when the key is not there).
bk_mf() { bk_member backup-manifest.json | jq -r --arg k "$1" 'if has($k) then .[$k] else "MISSING" end'; }

# bk_pointer: the backup file state.json records ("" when none).
bk_pointer() { jq -r '."last_backup.file" // ""' "$ROOT/state.json"; }

# wait_for <file>: until the file exists (10 seconds at most).
wait_for() {
  local i
  for i in $(seq 1 200); do
    [ -e "$1" ] && return 0
    /usr/bin/sleep 0.05
  done
  echo "timed out waiting for ${1##*/}"
  return 1
}

# screen <file>: the output with the deployment folder shown as /opt/custodexa.
screen_of() { printf '%s\n' "$1" | sed "s#$ROOT#/opt/custodexa#g"; }

# bk_status: the backup section of `status` for $ROOT, in English, the folder shown as /opt/custodexa.
bk_status() {
  bash -c '. "$1/lib/common.sh"; CX_LANG_FLAG=en; cx_load_libs "$1"; . "$1/lib/cmd_status.sh"
    CX_ROOT=$2; cx_state_load "$2/state.json"; cmd_status_backup' _ "$SRC" "$ROOT" | sed "s#$ROOT#/opt/custodexa#g"
}

# bk_libs: the backup libraries in the test shell, as `backup` loads them, for this deployment.
bk_libs() {
  [ -f "$SRC/lib/portable.sh" ] || { echo "lib/portable.sh is not there"; return 1; }
  load_lib
  # shellcheck disable=SC1091
  . "$SRC/lib/backup.sh"
  # shellcheck disable=SC1091
  . "$SRC/lib/portable.sh"
  export CX_ROOT=$ROOT
  cx_bk_vars
}

# ---------- an external database ----------

# The PostgreSQL client tool images of the release: index digests (the pins of the release build)
# and the image IDs this host has for them.
declare -gA BK_PGC_DIGEST=(
  [16]=sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea
  [17]=sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24
  [18]=sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873)
declare -gA BK_PGC_TAG=([16]=16.15-alpine3.24 [17]=17.11-alpine3.24 [18]=18.6-alpine3.24)
declare -gA BK_PGC_ID=(
  [16]=sha256:1616161616161616161616161616161616161616161616161616161616161616
  [17]=sha256:1717171717171717171717171717171717171717171717171717171717171717
  [18]=sha256:1818181818181818181818181818181818181818181818181818181818181818)

# bk_manifest_clients <MANIFEST.json>: the three clients added to a release manifest (jq layout).
bk_manifest_clients() {
  local m
  for m in 16 17 18; do
    jq --arg n "pgclient$m" --arg t "${BK_PGC_TAG[$m]}" --arg d "${BK_PGC_DIGEST[$m]}" \
      '.images[$n] = {ref: "docker.io/library/postgres", tag: $t, index_digest: $d, upstream: true}' "$1" >"$1.new"
    /usr/bin/mv "$1.new" "$1"
  done
}

# bk_state_set <key> <value>: one value of state.json (jq, outside the script).
bk_state_set() {
  jq --arg k "$1" --arg v "$2" '.[$k] = $v' "$ROOT/state.json" >"$ROOT/state.json.new"
  /usr/bin/mv "$ROOT/state.json.new" "$ROOT/state.json"
}

# bk_env_set <key> <value | ->: set (or with -, remove) one line of .env, which stays 0600.
bk_env_set() {
  local f=$ROOT/.env
  grep -v "^$1=" "$f" >"$f.new" || true
  [ "$2" = - ] || printf '%s=%s\n' "$1" "$2" >>"$f.new"
  chmod 600 "$f.new"
  /usr/bin/mv "$f.new" "$f"
}

# bk_server <major.minor>: the version the database server reports.
bk_server() {
  printf '%s\n' "$1" >"$DB/server_version"
  printf '%s\n' "$((${1%%.*} * 10000 + ${1#*.}))" >"$DB/server_version_num"
}

# bk_external [server version]: the deployment uses an external database (PostgreSQL 17.6 unless
# given) at db.example.internal:5432 with verify-full against the system's certificate
# authorities; the release names the three clients, install recorded them and this host has them.
bk_external() {
  local m ids=""
  bk_state_set current.overlays external-database
  for m in 16 17 18; do ids+="${ids:+ }pgclient$m=${BK_PGC_ID[$m]}"; done
  bk_state_set current.tool_image_ids "$ids"
  bk_manifest_clients "$ROOT/releases/1.13.0/MANIFEST.json"
  printf '%s\n' "${BK_PGC_ID[16]}" "${BK_PGC_ID[17]}" "${BK_PGC_ID[18]}" >>"$DB/images"
  bk_env_set DB_USER custodexa_app
  bk_env_set EXTERNAL_DB_HOST db.example.internal
  bk_env_set EXTERNAL_DB_PORT 5432
  bk_env_set DB_SSLMODE verify-full
  bk_server "${1:-17.6}"
}

# bk_hex <name>: the bytes of the name as lower-case hex (what the queries for role and tablespace
# names return).
bk_hex() { printf '%s' "$1" | od -An -tx1 -v | tr -d ' \n'; }
