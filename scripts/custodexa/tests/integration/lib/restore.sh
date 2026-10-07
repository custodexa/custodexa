# shellcheck shell=bash
# The restore of a built-in deployment made with lib/versions.sh (lv_*), compared with what it
# held before. Database facts are read with the deployment's own PostgreSQL as DB_USER.
#   ri_data <label>              a user and an asset made through the API (usernames it-<label>)
#   ri_has <label>               1 when the user it-<label> is in the database, else 0
#   ri_mark                      RI_T0, the cutoff for the backend's own audit rows (see below)
#   ri_facts <file>              version, row counts of users, sessions and audit_logs, the
#                                migrations (count and SHA-256), a hash of the data (pg_dump
#                                --data-only, lines sorted), the last_value of every sequence and the
#                                grants (aclexplode of every relation, sorted), one per line
#   ri_same_facts <what> <file>  ri_facts now equals that file (the differing lines shown)
#   ri_backup <label>            backup --yes [extra arguments]: RI_FILE, the new file (a copy of its
#                                snapshot.txt and backup-manifest.json in $IT_WORK/<label>.*)
#   ri_snap_same <what> <label>  the script's snapshot of the database now equals that backup's
#   ri_kek_id                    the master key identity the running backend reports (seal/status)
#   ri_rec_sha                   sha256 of every file under data/recordings (sorted)
#   ri_running_same <what>       the containers of every service of current.image_ids are running
#                                that image
#   ri_doc <label> <arguments>   the management script the way backup-and-restore.md §5 gives
#                                its commands: ./custodexa.sh in the deployment folder (LV_RC, LV_OUT)
#   ri_template <path> <marker>  the deployment's own proxy template (TLS_NGINX_TEMPLATE in .env names
#                                <path>): a copy of the shipped one with the line "# <marker>"
#   ri_nginx_has <marker>        yes when the configuration the running proxy loaded (nginx -T) has
#                                the line "# <marker>", else no
#   ri_apply <label>             stop and start: the proxy loads the template .env names now
#   ri_sha <file>                its SHA-256

ri_data() {
  local n=it-$1 r
  r=$(lv_api POST /users "$(jq -cn --arg n "$n" \
    '{username: $n, password: "It-user-pass-0001", email: "\($n)@example.test", full_name: "Restore test \($n)"}')")
  jq -er '.data.id // .id' <<<"$r" >/dev/null
  r=$(lv_api POST /assets "$(jq -cn --arg n "$n" \
    '{name: $n, protocol: "ssh", host: "192.0.2.20", port: 22, description: "restore test \($n)", tags: "it,restore"}')")
  jq -er '.data.id // .id' <<<"$r" >/dev/null
}

ri_has() { lv_sql "SELECT count(*) FROM users WHERE username = 'it-$1'"; }

ri_pg() { docker exec -i custodexa-postgres "$@"; }

# The backend writes audit rows of its own each time it starts, so what a restore or a revert must
# bring back is compared up to a cutoff taken before the restore (ri_mark, on the database's clock):
# audit rows created before it, every other table whole, every sequence but the audit rows' own.
# Audit rows are queued and written in the background, so the cutoff waits until the rows before it
# stop changing. What the backend writes on its own was found by the per-table lines of ri_facts
# (restore-same-host): RI_SELF, rows its schedule adds (left out of the data hash); RI_SEEDED, the
# policy baseline its start seeds again, setting updated_at (compared without that column).
RI_SELF=" audit_chain_verify_states "
RI_SEEDED=" policy_clause_controls policy_clauses policy_groups "
ri_mark() {
  local n="" m i
  RI_T0=$(lv_sql "SELECT to_char(clock_timestamp() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS.US') || '+00'")
  for ((i = 0; i < 30; i++)); do
    sleep 2
    m=$(lv_sql "SELECT count(*) FROM audit_logs WHERE created_at < '$RI_T0'")
    [ "$m" != "$n" ] || break
    n=$m
  done
}

# ri_tables <file>: "<table> <rows> <sha256 of its rows, sorted>" for every table but audit_logs, and
# "sequence <name> <last_value>" for every sequence.
ri_tables() {
  local t q
  for t in $(lv_sql "SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename <> 'audit_logs' ORDER BY 1"); do
    q="SELECT * FROM public.\"$t\""
    [[ $RI_SEEDED != *" $t "* ]] || q="SELECT (to_jsonb(x) - 'updated_at')::text FROM public.\"$t\" x"
    printf '%s %s %s\n' "$t" "$(lv_sql "SELECT count(*) FROM public.\"$t\"")" \
      "$(lv_sql "COPY ($q) TO STDOUT" | LC_ALL=C sort | sha256sum | cut -c1-64)"
  done
  lv_sql "SELECT 'sequence ' || sequencename || ' ' || coalesce(last_value::text, '') FROM pg_sequences WHERE schemaname = 'public' ORDER BY 1"
}

ri_facts() {
  ri_tables >"$1.dump"
  {
    printf 'version=%s\n' "$(lv_st current.version)"
    printf 'count.users=%s\n' "$(lv_sql 'SELECT count(*) FROM users')"
    printf 'count.sessions=%s\n' "$(lv_sql 'SELECT count(*) FROM sessions')"
    printf 'count.audit_logs (before %s)=%s\n' "$RI_T0" "$(lv_sql "SELECT count(*) FROM audit_logs WHERE created_at < '$RI_T0'")"
    printf 'audit_logs (before the cutoff)=%s\n' "$(lv_sql "SELECT a::text FROM audit_logs a WHERE created_at < '$RI_T0' ORDER BY id" | sha256sum | cut -c1-64)"
    printf 'migrations=%s %s\n' "$(lv_sql 'SELECT count(*) FROM schema_migrations')" \
      "$(lv_sql 'SELECT version FROM schema_migrations ORDER BY version' | sha256sum | cut -c1-64)"
    printf 'data (every table but audit_logs and those the backend writes on its own)=%s\n' \
      "$(grep -v '^sequence ' "$1.dump" | awk -v s="$RI_SELF" 'index(s, " " $1 " ") == 0' | sha256sum | cut -c1-64)"
    printf 'sequences (but those of the same tables)=%s\n' \
      "$(grep '^sequence ' "$1.dump" | awk -v s="$RI_SELF audit_logs " '{t = $2; sub(/_id_seq$/, "", t)} index(s, " " t " ") == 0' | sha256sum | cut -c1-64)"
    printf 'grants=%s\n' "$(lv_sql "SELECT c.oid::regclass::text, a.grantor::regrole::text, CASE a.grantee WHEN 0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END, a.privilege_type, a.is_grantable FROM pg_class c, aclexplode(c.relacl) a WHERE c.relnamespace = 'public'::regnamespace" | LC_ALL=C sort | sha256sum | cut -c1-64)"
  } >"$1"
}

ri_same_facts() {
  local now=$IT_WORK/facts.now
  ri_facts "$now"
  it_snap_same "$1" "$2" "$now" || {
    diff "$2.dump" "$now.dump" | head -n 20 | sed 's/^/   | data: /'
    return 1
  }
}

ri_backup() {
  local label=$1 x
  shift
  touch "$IT_WORK/mark"
  sleep 1
  lv_cx "$label" backup --yes "$@"
  it_same "$label: backup exits 0" 0 "$LV_RC"
  RI_FILE=$(find "$LV_ROOT/backups" -maxdepth 1 -name 'custodexa-backup-*.tar*' ! -name '*.sha256' -newer "$IT_WORK/mark" | head -n1)
  # shellcheck disable=SC2016 # expanded by the inner shell
  it_check "$label: one new backup file, its checksum file matches" \
    bash -c 'cd "${1%/*}" && sha256sum -c --quiet "${1##*/}.sha256"' _ "$RI_FILE"
  x=$IT_WORK/$label.x
  rm -rf "$x"
  mkdir -p "$x"
  if [[ $RI_FILE != *.tar.enc ]]; then
    tar -xf "$RI_FILE" -C "$x" snapshot.txt backup-manifest.json
    cp "$x/snapshot.txt" "$IT_WORK/$label.snapshot"
    cp "$x/backup-manifest.json" "$IT_WORK/$label.manifest"
  fi
}

# ri_snap_same: the script's own snapshot code against the database now (the backend running): its
# audit row count is that of the rows created before the cutoff of ri_mark, taken before the restore.
ri_snap_same() {
  local now=$IT_WORK/snap.now
  it_snap_take "$now.all" "$(lv_env_get JWT_SECRET)" docker exec -i custodexa-postgres psql -X -v ON_ERROR_STOP=1 -At \
    -U "$(lv_env_get DB_USER)" -d "$(lv_env_get DB_NAME)" -c
  sed "s/^count\.audit_logs=.*/count.audit_logs=$(lv_sql "SELECT count(*) FROM audit_logs WHERE created_at < '$RI_T0'")/" "$now.all" >"$now"
  it_say "   audit rows now $(sed -n 's/^count\.audit_logs=//p' "$now.all"), of them before the restore began $(sed -n 's/^count\.audit_logs=//p' "$now")"
  it_snap_same "$1" "$IT_WORK/$2.snapshot" "$now"
}

ri_kek_id() {
  local ip
  ip=$(lv_backend_ip) && [ -n "$ip" ] || return 0
  curl -fsS --max-time 5 "http://$ip:8080/api/v1/seal/status" 2>/dev/null | jq -r '.kek_id // empty' 2>/dev/null || true
}

# Master key mode ui: the backend waits sealed until an administrator enters the key material.
#   ri_ui_install <version>      unpack that package, master key mode ui, install from its bundle
#   ri_seal_state                the state seal/status reports (sealed, unsealed, ...)
#   ri_unseal <material> [init] [password]   authorize as admin (the password given, else the one
#                                lv_login keeps, else ADMIN_INITIAL_PASSWORD), then unseal with the
#                                material (init: the first unseal of a new deployment); RI_HTTP and
#                                RI_BODY are the unseal's answer
ri_ui_install() {
  local v=$1
  it_step "built-in form, master key mode ui: install $v"
  it_unpack /opt "$v"
  ex_preset "$LV_ROOT" KEK_PROVIDER=ui
  lv_cx install install --images "$(it_bundle_file "$v")"
  it_same "install $v exits 0" 0 "$LV_RC"
  # shellcheck disable=SC2034 # read by lv_api
  LV_TOKEN=""
}

ri_seal_state() {
  local ip
  ip=$(lv_backend_ip) && [ -n "$ip" ] || return 0
  curl -fsS --max-time 5 "http://$ip:8080/api/v1/seal/status" 2>/dev/null | jq -r '.state // empty' 2>/dev/null || true
}

ri_is_unsealed() { [ "$(ri_seal_state)" = unsealed ]; }

ri_unseal() {
  local material=$1 init=${2:-} pw=${3:-} ip r grant body
  ip=$(lv_backend_ip)
  if [ -z "$pw" ]; then
    if [ -s "$IT_WORK/lv-admin-password" ]; then pw=$(cat "$IT_WORK/lv-admin-password"); else pw=$(lv_env_get ADMIN_INITIAL_PASSWORD); fi
  fi
  r=$(curl -sS --max-time 15 -H 'Content-Type: application/json' \
    -d "$(jq -cn --arg p "$pw" '{username: "admin", password: $p}')" "http://$ip:8080/api/v1/seal/authorize")
  grant=$(jq -r '.grant // empty' <<<"$r" 2>/dev/null)
  if [ -z "$grant" ] && [[ $r == *SEAL_BACKOFF_ACTIVE* || $r == *SEAL_COOLDOWN_ACTIVE* ]]; then
    RI_HTTP=429 RI_BODY=$r
    return 0
  fi
  [ -n "$grant" ] || { printf 'not ok - seal/authorize: %s\n' "$(head -c 300 <<<"$r")"; return 1; }
  if [ "$init" = init ]; then
    body=$(jq -cn --arg k "$material" --arg p "$pw" '{kek: $k, kek_confirm: $k, confirm_saved: true, username: "admin", password: $p}')
  else
    body=$(jq -cn --arg k "$material" '{kek: $k}')
  fi
  r=$(curl -sS --max-time 60 -w '\n%{http_code}' -H 'Content-Type: application/json' -H "Authorization: SealGrant $grant" \
    -d "$body" "http://$ip:8080/api/v1/seal/unseal")
  RI_HTTP=$(tail -n 1 <<<"$r") RI_BODY=$(sed '$d' <<<"$r")
  it_say "   seal/unseal: HTTP $RI_HTTP $(head -c 200 <<<"$RI_BODY")"
}

# ri_unseal_after_backoff <material>: ri_unseal, again while the backend holds back attempts from
# this source after a refused one (429), for at most four minutes.
ri_unseal_after_backoff() {
  local i
  for ((i = 0; i < 80; i++)); do
    ri_unseal "$@" || return 1
    [ "$RI_HTTP" = 429 ] || return 0
    sleep 3
  done
}

ri_rec_sha() {
  (cd "$LV_ROOT/data/recordings" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum)
}

ri_running_same() {
  it_same "$1: every service of the version on record runs its recorded image" "$(lv_st current.image_ids)" "$(lv_ids_running)"
  # shellcheck disable=SC2016 # expanded by the inner shell
  it_check "$1: those containers are running (the certificate initializer runs once)" bash -c '
    for pair in $1; do
      case ${pair%%=*} in openssl) continue ;; nginx) c=custodexa-tls-proxy ;; *) c=custodexa-${pair%%=*} ;; esac
      [ "$(docker inspect --format "{{.State.Running}}" "$c" 2>/dev/null)" = true ] || { echo "$c is not running"; exit 1; }
    done' _ "$(lv_st current.image_ids)"
}

# The scenario host runs as root, so the commands go without sudo; --lang en only chooses the
# language of the screens the checks read. The command line is printed with the output.
ri_doc() {
  local label=$1
  shift
  lv_shim
  printf '   %s> $ cd %s && ./custodexa.sh %s --lang en\n' "$label" "$LV_ROOT" "$*"
  LV_OUT=$(cd "$LV_ROOT" && LV_INJECT=${LV_INJECT:-} CX_READY_TRIES=${LV_READY_TRIES:-} PATH=$IT_WORK/lvshim:$PATH \
    ./custodexa.sh "$@" --lang en 2>&1) && LV_RC=0 || LV_RC=$?
  printf '%s\n' "$LV_OUT" | sed "s/^/   $label> /"
  printf '   %s> (exit %s)\n' "$label" "$LV_RC"
}

ri_template() {
  local file=$1
  [[ $file == /* ]] || file=$LV_ROOT/${file#./}
  mkdir -p "${file%/*}"
  { cat "$LV_ROOT/current/reverse-proxy/nginx-tls.conf.template"; printf '# %s\n' "$2"; } >"$file"
  # .env keeps its file (mode and owner): rewritten in place, not replaced.
  { grep -v '^TLS_NGINX_TEMPLATE=' "$LV_ROOT/.env" || true; printf 'TLS_NGINX_TEMPLATE=%s\n' "$1"; } >"$IT_WORK/env.template"
  cat "$IT_WORK/env.template" >"$LV_ROOT/.env"
  rm -f "$IT_WORK/env.template"
}

ri_nginx_has() {
  if docker exec custodexa-tls-proxy nginx -T 2>/dev/null | grep -qxF "# $1"; then echo yes; else echo no; fi
}

# ri_apply <label>: stop, then start, so the proxy loads the template .env names now (its
# configuration is made from the template when its container starts).
ri_apply() {
  lv_cx "$1-stop" stop --yes
  it_same "$1: stop exits 0" 0 "$LV_RC"
  lv_cx "$1-start" start
  it_same "$1: start exits 0" 0 "$LV_RC"
}

ri_sha() { sha256sum <"$1" | cut -c1-64; }
