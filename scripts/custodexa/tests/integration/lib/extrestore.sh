# shellcheck shell=bash
# The restore of an external database deployment, for the scenarios restore-external-atomic and
# restore-external-db (needs: package local-versions; the deployments run 1.16.90, so a restore's
# readiness check sees the version it restored).
#   xr_install <root> <port>         unpack 1.16.90 to <root> (<parent>/custodexa), .env for the
#                                    external database form on ex_addr:<port>, install from its bundle
#   xr_new_host <root>               unpack 1.16.90 to <root>, not installed, its bundle loaded
#   xr_cx <label> <root> <args...>   custodexa.sh <args> --lang en without a terminal; XR_OUT, XR_RC,
#                                    the screen printed under the label; XR_INJECT (below) applies
#   xr_digest <server>               the target digest of database custodexa, by the script's own
#                                    query (CX_RS_EXT_DIGEST_SQL of lib/restore_external_import.sh)
#   xr_lines <server>                the lines that digest hashes, one per object, table, sequence
#                                    and grant (same query, the rows instead of their hash)
#   xr_quiet <server>                wait until no session of DB_USER is on the server
#   xr_gone <server>                 the deployment's containers removed (the original host is gone),
#                                    then xr_quiet
#   xr_mark <server>                 RI_T0, the server's clock now (the cutoff of xr_snap_same)
#   xr_snap_same <what> <server> <root> <snapshot.txt>
#                                    the script's own snapshot of the database now equals that of the
#                                    backup; audit rows counted up to RI_T0 (the backend writes rows
#                                    of its own once started)
#   xr_rs_dir <root>                 the working folder of the last restore
# XR_INJECT, test only, read by a docker wrapper first on the script's PATH (the script and the
# images are unchanged); each acts once per xr_cx and writes what it did to $IT_WORK/xr-injected:
#   body-prefix     the body.sql maker: its output cut before the first COPY (a valid prefix), exit 1
#   body-term       the body.sql maker run with --init (pg_restore is then not PID 1, which ignores
#                   SIGTERM) and sent SIGTERM once body.sql is not empty
#   body-kill       the body.sql maker sent SIGKILL once body.sql is not empty
#   body-error      the body.sql maker's output gets "SELECT 1/0;" after its first COPY data
#   grants-fail     the grants maker ends with 1 after its output
#   grants-filter   the grants maker's output gets a GRANT to a missing and an existing role at once
#   import-kill     the import's psql container sent SIGKILL while it copies public.it_bulk
#   import-terminate  the server ends the import's session (pg_terminate_backend) while it copies
#                   public.it_bulk
#   place-fail      the stop before the files are placed (phase db_checked) fails
# Every `docker run` the script makes is logged to $IT_WORK/xr-docker.log: "<name> <last -f>".

XR_V=1.16.90
XR_DIGEST_SQL=""

xr_digest_sql() {
  [ -n "$XR_DIGEST_SQL" ] || XR_DIGEST_SQL=$(
    # shellcheck source=scripts/custodexa/lib/dbext.sh
    . /src/scripts/custodexa/lib/dbext.sh
    # shellcheck source=scripts/custodexa/lib/restore_external_import.sh
    . /src/scripts/custodexa/lib/restore_external_import.sh
    printf '%s' "$CX_RS_EXT_DIGEST_SQL"
  )
  [ -n "$XR_DIGEST_SQL" ] || it_die "the script's digest query was not found"
  printf '%s' "$XR_DIGEST_SQL"
}

xr_digest() { it_pg_sql "$1" "$EX_DB" "$(xr_digest_sql)"; }

xr_lines() {
  local sql
  sql=$(xr_digest_sql)
  [[ $sql == *"SELECT encode(sha256("* ]] || it_die "the digest query's last SELECT changed"
  it_pg_sql "$1" "$EX_DB" "${sql%SELECT encode(sha256(*}SELECT l FROM rows ORDER BY l"
}

xr_quiet() {
  local i
  for ((i = 0; i < 120; i++)); do
    [ "$(it_pg_sql "$1" postgres "SELECT count(*) FROM pg_stat_activity WHERE usename = '$EX_USER'")" = 0 ] && return 0
    sleep 1
  done
  it_pg_sql "$1" postgres "SELECT pid, application_name, client_addr, state, query FROM pg_stat_activity WHERE usename = '$EX_USER'" >&2
  it_die "sessions of $EX_USER are still on server $1"
}

xr_gone() {
  local ids
  ids=$(docker ps -aq --filter label=com.docker.compose.project)
  # shellcheck disable=SC2086 # one ID per word
  [ -z "$ids" ] || docker rm -f $ids >/dev/null
  xr_quiet "$1"
}

xr_install() {
  local root=$1 port=$2
  it_unpack "${root%/*}" "$XR_V"
  ex_preset "$root" "COMPOSE_FILE=current/compose.yml:current/compose.external-database.yml" \
    "EXTERNAL_DB_HOST=$(ex_addr)" "EXTERNAL_DB_PORT=$port" "DB_NAME=$EX_DB" "DB_USER=$EX_USER" \
    "DB_PASSWORD=$EX_PASS" KEK_PROVIDER=env
  xr_cx install "$root" install --images "$(it_bundle_file "$XR_V")"
  it_same "install $XR_V on $(ex_addr):$port exits 0" 0 "$XR_RC"
}

xr_new_host() {
  local root=$1
  it_unpack "${root%/*}" "$XR_V"
  xr_cx load "$root" load "$(it_bundle_file "$XR_V")"
  it_same "the new host loads the offline bundle of $XR_V" 0 "$XR_RC"
  it_same "the new host is not installed" "" "$(ex_st "$root" current.version)"
}

xr_shim() {
  mkdir -p "$IT_WORK/xrshim"
  cat >"$IT_WORK/xrshim/docker" <<'EOF'
#!/usr/bin/env bash
real=/usr/local/bin/docker
mark=$XR_WORK/xr-injected
name="" w="" f="" prev=""
for a in "$@"; do
  case $prev in
    --name) name=$a ;;
    -v) case $a in *:/w | *:/w:ro) w=${a%%:/w*} ;; esac ;;
    -f) f=$a ;;
  esac
  prev=$a
done
[ "${1:-}" != run ] || [ -z "$name" ] || printf '%s %s\n' "$name" "$f" >>"$XR_WORK/xr-docker.log"
pending() { [ -n "${XR_INJECT:-}" ] && [ ! -e "$mark" ]; }
maker() { [ "${1:-}" = run ] && [[ $name == custodexa-restore-tool-*-sql ]] && [ "$f" = "$2" ]; }
if pending; then
  case $XR_INJECT in
    body-prefix)
      if maker "$1" /w/body.sql; then
        "$real" "$@" || exit
        awk '/^COPY /{exit} {print}' "$w/body.sql" >"$w/body.cut" && cat "$w/body.cut" >"$w/body.sql" && rm -f "$w/body.cut"
        printf 'body-prefix: body.sql cut to %s lines before its first COPY, exit 1\n' "$(wc -l <"$w/body.sql")" >"$mark"
        exit 1
      fi ;;
    body-term | body-kill)
      if maker "$1" /w/body.sql; then
        shift
        sig=KILL
        if [ "$XR_INJECT" = body-term ]; then sig=TERM; set -- --init "$@"; fi
        "$real" run "$@" &
        p=$!
        for ((i = 0; i < 6000; i++)); do [ -s "$w/body.sql" ] && break; sleep 0.01; done
        "$real" kill -s "$sig" "$name" >/dev/null 2>&1
        rc=0
        wait "$p" || rc=$?
        printf '%s: SIG%s at %s bytes of body.sql; maker exit %s; completion lines %s\n' "$XR_INJECT" "$sig" \
          "$(stat -c %s "$w/body.sql")" "$rc" "$(grep -c '^-- PostgreSQL database dump complete$' "$w/body.sql")" >"$mark"
        exit "$rc"
      fi ;;
    body-error)
      if maker "$1" /w/body.sql; then
        "$real" "$@" || exit
        awk 'BEGIN { c = 0 } { print } $0 == "\\." && !c { print ""; print "SELECT 1/0;"; c = 1 }' "$w/body.sql" >"$w/body.err" &&
          cat "$w/body.err" >"$w/body.sql" && rm -f "$w/body.err"
        printf 'body-error: SELECT 1/0; after the first COPY data (%s)\n' "$(grep -m1 '^COPY ' "$w/body.sql")" >"$mark"
        exit 0
      fi ;;
    grants-fail)
      if maker "$1" /w/grants.all.sql; then
        "$real" "$@"
        printf 'grants-fail: the grants maker ended with 1 after %s bytes\n' "$(stat -c %s "$w/grants.all.sql" 2>/dev/null || echo 0)" >"$mark"
        exit 1
      fi ;;
    grants-filter)
      if maker "$1" /w/grants.all.sql; then
        "$real" "$@" || exit
        awk '$0 == "-- PostgreSQL database dump complete" && !d { print "GRANT SELECT ON TABLE public.it_bulk TO \"report reader\", custodexa;"; print ""; d = 1 } { print }' \
          "$w/grants.all.sql" >"$w/grants.mix" && cat "$w/grants.mix" >"$w/grants.all.sql" && rm -f "$w/grants.mix"
        printf 'grants-filter: a GRANT to "report reader" and custodexa at once added\n' >"$mark"
        exit 0
      fi ;;
    import-kill | import-terminate)
      if [ "${1:-}" = run ] && [[ $name == custodexa-restore-tool-*-import ]]; then
        "$real" "$@" &
        p=$!
        pid=""
        q="SELECT pid FROM pg_stat_activity WHERE usename = 'custodexa' AND state = 'active' AND xact_start IS NOT NULL AND query LIKE 'COPY public.it_bulk %'"
        for ((i = 0; i < 1200; i++)); do
          pid=$("$real" exec "it-pg-$XR_SERVER" psql -X -q -At -U postgres -d postgres -c "$q" 2>/dev/null | head -n1)
          [ -z "$pid" ] || break
          kill -0 "$p" 2>/dev/null || break
          sleep 0.1
        done
        if [ -n "$pid" ]; then
          if [ "$XR_INJECT" = import-kill ]; then
            "$real" kill -s KILL "$name" >/dev/null 2>&1
          else
            "$real" exec "it-pg-$XR_SERVER" psql -X -q -At -U postgres -d postgres -c "SELECT pg_terminate_backend($pid)" >/dev/null
          fi
        fi
        rc=0
        wait "$p" || rc=$?
        printf '%s: session %s in its transaction, copying public.it_bulk; psql exit %s\n' "$XR_INJECT" "${pid:-never-seen}" "$rc" >"$mark"
        exit "$rc"
      fi ;;
    place-fail)
      if [ "${1:-}" = compose ] && [[ " $* " == *" stop "* ]] &&
        [ "$(jq -r '."last_restore.phase" // ""' "$XR_ROOT/state.json" 2>/dev/null)" = db_checked ]; then
        printf 'place-fail: the stop before the files are placed failed\n' >"$mark"
        exit 1
      fi ;;
  esac
fi
exec "$real" "$@"
EOF
  chmod +x "$IT_WORK/xrshim/docker"
}

xr_cx() {
  local label=$1 root=$2
  shift 2
  xr_shim
  rm -f "$IT_WORK/xr-injected"
  : >"$IT_WORK/xr-docker.log"
  XR_OUT=$(XR_WORK=$IT_WORK XR_INJECT=${XR_INJECT:-} XR_ROOT=$root XR_SERVER=${XR_SERVER:-} PATH=$IT_WORK/xrshim:$PATH \
    "$root/custodexa.sh" "$@" --lang en </dev/null 2>&1) && XR_RC=0 || XR_RC=$?
  printf '%s\n' "$XR_OUT" | sed "s/^/   $label> /"
  printf '   %s> (exit %s)\n' "$label" "$XR_RC"
  [ ! -e "$IT_WORK/xr-injected" ] || sed "s/^/   $label: injected /" "$IT_WORK/xr-injected"
}

xr_mark() {
  RI_T0=$(it_pg_sql "$1" postgres "SELECT to_char(clock_timestamp() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS.US') || '+00'")
}

xr_snap_same() {
  local what=$1 s=$2 root=$3 snap=$4 now=$IT_WORK/xr-snap.now
  it_snap_take "$now.all" "$(sed -n 's/^JWT_SECRET=//p' "$root/.env" | tail -n1)" \
    docker exec -i "it-pg-$s" psql -X -v ON_ERROR_STOP=1 -At -U "$EX_USER" -d "$EX_DB" -c
  sed "s/^count\.audit_logs=.*/count.audit_logs=$(ex_db_sql "$s" "$EX_DB" "SELECT count(*) FROM audit_logs WHERE created_at < '$RI_T0'")/" \
    "$now.all" >"$now"
  it_snap_same "$what" "$snap" "$now"
}

xr_rs_dir() { find "$1/restore" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' | sort -n | tail -n1 | cut -d' ' -f2-; }
