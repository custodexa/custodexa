# shellcheck shell=bash
# about: the recovery drill of the permission model, once with the built-in database (host builtin) and once with an external PostgreSQL 17 (host external): the published 1.17.9 installed, users, roles, a group, an agent and three kinds of sign-in tickets made through its API; upgraded offline to 1.18.90 of the working tree (the model migration added, roles and sources kept, no new restore generation, the old tickets still work); backed up and restored on the same host (a new restore generation, the old access, refresh and agent tickets refused through the real endpoints, a new sign-in works); stop and start keep everything; rollback is refused before anything stops; the backup the upgrade took restores 1.17.9 with a new sign-in secret and every refresh, agent and temporary grant revoked
# hosts: builtin external
# needs: package local-versions published
# images: pg17
#
# Run with CX_IT_LOCAL_VERSIONS=1.18.90 CX_IT_PUBLISHED_VERSION=1.17.9. Each step prints
#   DRILL <form> step=<n> begin=<UTC> name=<name>
#   DRILL <form> step=<n> end=<UTC> result=PASS
# and its evidence as "EVID <form> step=<n> ..." lines; a step with a begin line and no end line
# is the one that failed. Reports R0-R4 are printed as "REPORT <form> <R> <key>=<value>" lines.
# Nothing secret is printed: tickets, passwords and secrets only as "accepted/refused", lengths
# or the first 8 hex digits of their SHA-256.

readonly DR_OLD=1.17.9 DR_NEW=1.18.90 DR_MODEL=20261016_authz_permission_model
readonly DR_EXT_PORT=55432 DR_SERVER=dr
DR_FORM="" DR_STEP="" DR_UPGRADE_BACKUP="" DR_BACKUP5="" DR_ADMIN_PW=$IT_WORK/lv-admin-password
# v4 rerun (2026-10-18): the offline verifier, a static linux build of tools/checkpoint-verify put in
# the ignored tmp/ of the drill worktree before the run (not part of the package).
readonly DR_VERIFY=/src/tmp/checkpoint-verify
DR_AGENT_ID=""

# ---- v4 additions: the checkpoint chain verified offline, permission alerts, agent token marks ----

# dr_cp_export <label>: the public key and every page of the checkpoint list through the API, put
# together as one list envelope in $IT_WORK/cp-<label>.json (what an auditor would export).
dr_cp_export() {
  local label=$1 f=$IT_WORK/cp-$1.json page=1 total=0 items="[]" r
  LV_TOKEN=""
  lv_api GET /audit-checkpoints/public-key >"$IT_WORK/cp-$label.key"
  while :; do
    r=$(lv_api GET "/audit-checkpoints?page=$page&page_size=200")
    total=$(jq -r '.data.total' <<<"$r")
    items=$(jq -c --argjson a "$items" '$a + .data.items' <<<"$r")
    if [ "$(jq '.data.items | length' <<<"$r")" -eq 0 ] || [ "$(jq 'length' <<<"$items")" -ge "$total" ]; then break; fi
    page=$((page + 1))
  done
  jq -cn --argjson i "$items" --argjson t "$total" '{data: {items: $i, total: $t}}' >"$f"
  dr_ev "checkpoints($label) total=$total got=$(jq '.data.items | length' "$f") seq=$(jq -r '[.data.items[].seq] | "\(min)-\(max)"' "$f") schemes=$(jq -r '[.data.items[].agg_scheme] | group_by(.) | map(.[0] + ":" + (length | tostring)) | join(",")' "$f") key_fp=$(jq -r .data.fingerprint "$IT_WORK/cp-$label.key")"
  dr_ev "checkpoints($label) v4 perm: $(jq -r '[.data.items | sort_by(.seq)[] | select(.agg_scheme == "cp-agg-v4") | "seq=\(.seq) " + (.perm | if . == null then "perm=null" else "origin=\(.origin) reconciled=\(.reconciled) event_seq=\(.event_seq)" end)] | join("; ")' "$f")"
}

# dr_cp_verify <label>: tools/checkpoint-verify on the export, offline (-input, -pubkey): every point
# passes; the same export with the origin flag of a v4 point flipped fails (the verifier really reads perm).
dr_cp_verify() {
  local label=$1 f=$IT_WORK/cp-$1.json key out rc
  key=$(jq -r .data.public_key "$IT_WORK/cp-$label.key")
  out=$("$DR_VERIFY" -input "$f" -pubkey "$key" 2>&1) && rc=0 || rc=$?
  { grep -E '^(檢查點|總計|載荷版本|結果)' <<<"$out" || true; } | sed "s/^/EVID $DR_FORM step=$DR_STEP verify($label): /"
  { grep -E 'FAIL' <<<"$out" | grep -v '^總計' || true; } | head -n 10 | sed "s/^/EVID $DR_FORM step=$DR_STEP verify($label) fail: /"
  it_same "checkpoint-verify ($label): every checkpoint passes offline (exit 0)" 0 "$rc"
  out=$("$DR_VERIFY" -input "$f" -pubkey "$key" -tamper perm-origin 2>&1) && rc=0 || rc=$?
  dr_ev "verify($label) control -tamper perm-origin exit=$rc $(grep -E '^結果' <<<"$out" || true)"
  it_same "checkpoint-verify ($label): a flipped origin flag fails (control)" 1 "$rc"
}

# dr_perm_alerts: failure events the permission reconciliation opened (any time, open or closed).
dr_perm_alerts() {
  lv_sql "SELECT count(*) FROM audit_failure_events WHERE mechanism = 'principal_state_integrity' AND cause_params LIKE '%\"table\":\"permission_state\"%'"
}
dr_open_failures() {
  lv_sql "SELECT coalesce(string_agg(mechanism||'/'||coalesce(nullif(cause_code,''),'-')||'/'||coalesce(CASE WHEN cause_params LIKE '{%' THEN cause_params::jsonb->>'table' END,'-'), ',' ORDER BY id), 'none') FROM audit_failure_events WHERE ended_at IS NULL"
}

# dr_agent_marks: the agent's tokens as the list shows them: name:restore mark:active or revoked.
dr_agent_marks() {
  lv_api GET "/users/$DR_AGENT_ID/agent-tokens" |
    jq -r '(.data | if type == "array" then . else (.items // []) end) | map("\(.name):\(if .restore_invalidated == true then "restore_invalidated" else "-" end):\(if .revoked_at == null then "active" else "revoked" end)") | join(",")'
}

# ---- the database of either form ----

lv_sql() {
  if [ "$DR_FORM" = external ]; then
    ex_db_sql "$DR_SERVER" "$EX_DB" "$1"
  else
    docker exec -i custodexa-postgres psql -X -v ON_ERROR_STOP=1 -At -U "$(lv_env_get DB_USER)" -d "$(lv_env_get DB_NAME)" -c "$1"
  fi
}
dr_has_table() { [ "$(lv_sql "SELECT to_regclass('public.$1') IS NOT NULL")" = t ]; }

# ---- steps and evidence ----

dr_now() { date -u +%FT%TZ; }
dr_begin() {
  DR_STEP=$1
  printf 'DRILL %s step=%s begin=%s name=%s\n' "$DR_FORM" "$1" "$(dr_now)" "$2"
}
dr_end() { printf 'DRILL %s step=%s end=%s result=PASS\n' "$DR_FORM" "$DR_STEP" "$(dr_now)"; }
dr_ev() { printf 'EVID %s step=%s %s\n' "$DR_FORM" "$DR_STEP" "$*"; }
dr_sha8() { sha256sum | cut -c1-8; }
dr_sha16() { sha256sum | cut -c1-16; }

# dr_keys: the first 8 hex digits of the SHA-256 of every secret-like value in .env, by name.
dr_keys() {
  local k
  for k in $(grep -oE '^[A-Z0-9_]*(SECRET|KEK|KEY|PASSWORD)[A-Z0-9_]*=' "$LV_ROOT/.env" | tr -d = | LC_ALL=C sort -u); do
    printf '%s:%s ' "$k" "$(lv_env_get "$k" | tr -d '\n' | dr_sha8)"
  done | sed 's/ $//'
}

# dr_cx <label> <args>: lv_cx with the command line and its times as evidence.
dr_cx() {
  local label=$1 t0
  shift
  t0=$(dr_now)
  lv_cx "$label" "$@"
  dr_ev "cmd=\"custodexa.sh $* --lang en\" start=$t0 end=$(dr_now) exit=$LV_RC"
}

# ---- HTTP, as a client of the deployment ----

dr_url() { printf 'http://%s:8080/api/v1%s' "$(lv_backend_ip)" "$1"; }

# dr_code <method> <path> <Authorization value|""> [cookie]: the HTTP status only.
dr_code() {
  local -a a=(-s -o /dev/null -w '%{http_code}' --max-time 15 -X "$1")
  [ -z "$3" ] || a+=(-H "Authorization: $3")
  [ -z "${4:-}" ] || a+=(-H "Cookie: custodexa_refresh=$4")
  curl "${a[@]}" "$(dr_url "$2")" || true
}

# dr_signin <user> <label>: sign in (the first time the initial password is changed once), keep
# the access ticket in tok-<label>.access and the refresh cookie in tok-<label>.refresh.
dr_signin() {
  local u=$1 label=$2 pwf=$IT_WORK/pw-$1 hdr=$IT_WORK/hdr-$2 r new
  [ "$u" != admin ] || pwf=$DR_ADMIN_PW
  [ -s "$pwf" ] || lv_env_get ADMIN_INITIAL_PASSWORD >"$pwf"
  r=$(curl -sS --max-time 15 -D "$hdr" -H 'Content-Type: application/json' \
    -d "$(jq -cn --arg u "$u" --arg p "$(cat "$pwf")" '{username: $u, password: $p}')" "$(dr_url /auth/login)")
  if [ "$(jq -r '.password_change_required // false' <<<"$r")" = true ]; then
    new="It-$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')-9q"
    curl -fsS --max-time 15 -o /dev/null -H 'Content-Type: application/json' -H "Authorization: Bearer $(jq -r .change_token <<<"$r")" \
      -d "$(jq -cn --arg o "$(cat "$pwf")" --arg n "$new" '{old_password: $o, new_password: $n}')" "$(dr_url /auth/change-password)"
    printf '%s' "$new" >"$pwf"
    r=$(curl -sS --max-time 15 -D "$hdr" -H 'Content-Type: application/json' \
      -d "$(jq -cn --arg u "$u" --arg p "$new" '{username: $u, password: $p}')" "$(dr_url /auth/login)")
  fi
  jq -r '.token // empty' <<<"$r" >"$IT_WORK/tok-$label.access"
  tr -d '\r' <"$hdr" | sed -n 's/^[Ss]et-[Cc]ookie: custodexa_refresh=\([^;]*\).*/\1/p' | tail -n1 >"$IT_WORK/tok-$label.refresh"
  [ -s "$IT_WORK/tok-$label.access" ] || { printf 'not ok - sign-in of %s: %s\n' "$u" "$(head -c 200 <<<"$r")"; return 1; }
}

# dr_refresh <label>: the refresh endpoint with tok-<label>.refresh; on 200 the rotated refresh and
# the new access ticket replace the kept ones. Prints the status.
dr_refresh() {
  local label=$1 hdr=$IT_WORK/hdr-refresh code body
  body=$(curl -sS --max-time 15 -D "$hdr" -o - -w '\n%{http_code}' -X POST \
    -H "Cookie: custodexa_refresh=$(cat "$IT_WORK/tok-$label.refresh")" "$(dr_url /auth/refresh)") || true
  code=$(tail -n1 <<<"$body")
  if [ "$code" = 200 ]; then
    sed '$d' <<<"$body" | jq -r '.token // empty' >"$IT_WORK/tok-$label.access"
    tr -d '\r' <"$hdr" | sed -n 's/^[Ss]et-[Cc]ookie: custodexa_refresh=\([^;]*\).*/\1/p' | tail -n1 >"$IT_WORK/tok-$label.refresh"
  fi
  printf '%s' "$code"
}

dr_access() { dr_code GET /auth/me "Bearer $(cat "$IT_WORK/tok-$1.access")"; }
dr_agent() { dr_code GET /access-requests/mine "Bearer $(cat "$IT_WORK/tok-agent.token")"; }

dr_b64d() { local s=$1; s=${s//-/+}; s=${s//_//}; while [ $((${#s} % 4)) -ne 0 ]; do s+='='; done; base64 -d <<<"$s"; }
dr_b64e() { base64 -w0 | tr '+/' '-_' | tr -d '='; }
dr_claims() { dr_b64d "$(cut -d. -f2 "$IT_WORK/tok-$1.access")"; }
dr_left() { echo $(($(dr_claims "$1" | jq -r .exp) - $(date +%s))); } # seconds before it expires

# dr_craft <label> <secret>: the claims of tok-<label>.access with a fresh iat/exp, signed HS256
# with the given secret (what any holder of that secret could make; only sent, never printed).
dr_craft() {
  local h p now
  now=$(date +%s)
  h=$(cut -d. -f1 "$IT_WORK/tok-$1.access")
  p=$(dr_claims "$1" | jq -c --argjson n "$now" '.iat = $n | .exp = $n + 600 | if has("nbf") then .nbf = $n else . end' | tr -d '\n' | dr_b64e)
  printf '%s.%s.%s' "$h" "$p" "$(printf '%s.%s' "$h" "$p" | openssl dgst -sha256 -hmac "$2" -binary | dr_b64e)"
}
dr_crafted() { dr_code GET /auth/me "Bearer $(dr_craft "$1" "$2")"; }

# dr_expect <what> <wanted status> <status>
dr_expect() {
  dr_ev "ticket=\"$1\" http=$3 wanted=$2"
  it_same "$1: HTTP $2" "$2" "$3"
}

# ---- reports: the same queries before and after each step ----

dr_rows() { lv_sql "$1" | LC_ALL=C sort | dr_sha16; }
dr_count() { lv_sql "SELECT count(*) FROM $1"; }

# dr_report <R>: the same queries every time, one key=value per line, kept in $IT_WORK/<R>.txt.
dr_report() {
  local r=$1 f=$IT_WORK/$1.txt meta
  # A new administrator session for each report: the one before may have expired (15 minutes).
  LV_TOKEN=""
  {
    printf 'version=%s\n' "$(lv_st current.version)"
    printf 'health=%s\n' "$(lv_version)"
    printf 'migrations=%s %s\n' "$(dr_count schema_migrations)" \
      "$(lv_sql 'SELECT version FROM schema_migrations' | LC_ALL=C sort | dr_sha16)"
    printf 'model_migration=%s\n' "$(lv_sql "SELECT count(*) FROM schema_migrations WHERE version = '$DR_MODEL'")"
    printf 'users=%s %s\n' "$(dr_count users)" \
      "$(dr_rows "SELECT u.id||'|'||u.username||'|'||coalesce(to_jsonb(u)->>'kind','')||'|'||u.active||'|'||(u.deleted_at IS NULL)||'|'||coalesce(to_jsonb(u)->>'owner_user_id','') FROM users u")"
    printf 'user_roles=%s %s\n' "$(dr_count user_roles)" \
      "$(dr_rows "SELECT u.username||'|'||r.name||'|'||coalesce(to_jsonb(ur)->>'source','') FROM user_roles ur JOIN users u ON u.id = ur.user_id JOIN roles r ON r.id = ur.role_id")"
    printf 'user_roles.by_source=%s\n' "$(lv_sql "SELECT k||':'||count(*) FROM (SELECT coalesce(to_jsonb(ur)->>'source','-') AS k FROM user_roles ur) x GROUP BY k ORDER BY k" | paste -sd, -)"
    printf 'user_roles.scope=%s\n' "$(lv_sql "SELECT k||':'||count(*) FROM (SELECT coalesce(to_jsonb(ur)->>'scope_kind','absent') AS k FROM user_roles ur) x GROUP BY k ORDER BY k" | paste -sd, -)"
    printf 'groups=%s %s\n' "$(dr_count user_groups)" "$(dr_rows "SELECT name||'|'||(deleted_at IS NULL) FROM user_groups")"
    printf 'members=%s %s\n' "$(dr_count user_group_members)" \
      "$(dr_rows "SELECT g.name||'|'||u.username||'|'||coalesce(to_jsonb(m)->>'manual','') FROM user_group_members m JOIN user_groups g ON g.id = m.user_group_id JOIN users u ON u.id = m.user_id")"
    printf 'role_maps=%s\n' "$(dr_maps group_role_mappings)"
    printf 'group_maps=%s\n' "$(dr_maps group_user_group_mappings)"
    printf 'group_roles=%s\n' "$(if dr_has_table user_group_roles; then dr_count user_group_roles; else echo absent; fi)"
    printf 'binding_nodes=%s\n' "$(if dr_has_table role_binding_nodes; then dr_count role_binding_nodes; else echo absent; fi)"
    printf 'approver_only=%s\n' "$(lv_sql "SELECT coalesce(string_agg(r.name||'/'||ur.source, ',' ORDER BY r.name), 'none') FROM users u LEFT JOIN user_roles ur ON ur.user_id = u.id LEFT JOIN roles r ON r.id = ur.role_id WHERE u.username = 'it-approver'")"
    printf 'no_role=%s\n' "$(lv_sql "SELECT count(ur.*) FROM users u LEFT JOIN user_roles ur ON ur.user_id = u.id WHERE u.username = 'it-norole'")"
    printf 'agent_owner=%s\n' "$(lv_sql "SELECT o.username FROM users a JOIN users o ON o.id = a.owner_user_id WHERE a.username = 'it-agent'")"
    printf 'local_admins.api=%s\n' "$(lv_api GET /users/local-admin-count | jq -r .count || echo error)"
    if lv_sql "SELECT 1 FROM information_schema.columns WHERE table_name = 'roles' AND column_name = 'builtin_key'" | grep -q 1; then
      # identity.CountLocalAdmins (localAdminScope), the same conditions as SQL.
      printf 'local_admins.sql=%s\n' "$(lv_sql "SELECT count(DISTINCT u.id) FROM users u JOIN user_roles ur ON ur.user_id = u.id JOIN roles r ON r.id = ur.role_id
        WHERE r.builtin_key = 'super_admin' AND ur.scope_kind = 'global' AND ur.source IN ('manual','both') AND u.active AND u.deleted_at IS NULL
        AND NOT u.external_credential AND NOT u.is_ldap AND u.password IS NOT NULL AND trim(u.password) <> ''
        AND (u.provisioning_origin IS NULL OR u.provisioning_origin = '' OR u.provisioning_origin = 'local')")"
    else
      printf 'local_admins.sql=n/a (no builtin_key before the model migration)\n'
    fi
    if dr_has_table authz_state && lv_sql "SELECT 1 FROM information_schema.columns WHERE table_name = 'authz_state' AND column_name = 'restore_generation'" | grep -q 1; then
      printf 'authz_state=%s\n' "$(lv_sql "SELECT 'version='||version||' generation='||CASE WHEN restore_generation = '' THEN 'empty' ELSE left(encode(sha256(convert_to(restore_generation,'UTF8')),'hex'),8) END||' status='||coalesce(nullif(restore_status,''),'none')||' op='||coalesce(nullif(restore_op_id,''),'none') FROM authz_state")"
    else
      printf 'authz_state=absent\n'
    fi
    if dr_has_table permission_state_events; then
      printf 'events=%s %s\n' "$(dr_count permission_state_events)" "$(lv_sql "SELECT kind||':'||count(*) FROM permission_state_events GROUP BY kind ORDER BY kind" | paste -sd, -)"
      printf 'checkpoint_attested=%s\n' "$(lv_sql "SELECT coalesce((SELECT CASE WHEN perm_format IS NULL THEN 'no' ELSE 'yes' END FROM audit_checkpoints ORDER BY id DESC LIMIT 1), 'none')")"
    else
      printf 'events=absent\ncheckpoint_attested=absent\n'
    fi
    printf 'tokens.refresh_active=%s\n' "$(lv_sql "SELECT count(*) FROM refresh_tokens WHERE revoked_at IS NULL")"
    printf 'tokens.agent_active=%s\n' "$(lv_sql "SELECT count(*) FROM agent_tokens WHERE revoked_at IS NULL")"
    # Only a backend that has the subcommand is asked: an older binary given an unknown argument
    # would start a second server in its container.
    if [ "$(lv_version)" = "$DR_NEW" ]; then
      meta=$(docker exec custodexa-backend ./custodexa permission-meta 2>/dev/null) || meta="authz.model=error"
      printf '%s\n' "$meta" | grep -E '^authz\.(model|version|digest|refs|catalog|count\.[a-z_]+)=' | sed 's/^/perm./' || printf 'perm.authz.model=none\n'
    else
      printf 'perm.authz.model=not asked (%s)\n' "$(lv_version)"
    fi
  } >"$f"
  sed "s/^/REPORT $DR_FORM $r /" "$f"
}
dr_maps() {
  if dr_has_table "$1"; then
    printf '%s %s' "$(dr_count "$1")" "$(dr_rows "SELECT (to_jsonb(x) - 'created_at' - 'updated_at' - 'id')::text FROM $1 x")"
  else
    printf absent
  fi
}

# dr_same <what> <R a> <R b> <keys...>: the lines of these keys are the same in both reports.
dr_same() {
  local what=$1 ra=$IT_WORK/$2.txt rb=$IT_WORK/$3.txt k pat=""
  shift 3
  for k in "$@"; do pat+="${pat:+|}^${k//./\\.}="; done
  it_same "$what" "$(grep -E "$pat" "$ra")" "$(grep -E "$pat" "$rb")"
}
readonly -a DR_DATA_KEYS=(users user_roles groups members approver_only no_role agent_owner local_admins.api)

dr_get() { sed -n "s/^$2=//p" "$IT_WORK/$1.txt"; }

# ---- the backup files ----

# dr_backup_facts <label> <file>: checksum, members, snapshot.txt authz keys, the tables of the dump.
dr_backup_facts() {
  local label=$1 f=$2 x=$IT_WORK/$1.x pgc
  rm -rf "$x"
  mkdir -p "$x"
  # shellcheck disable=SC2016 # expanded by the inner shell
  it_check "$label: $f and its .sha256 match" bash -c 'cd "${1%/*}" && sha256sum -c --quiet "${1##*/}.sha256"' _ "$f"
  tar -xf "$f" -C "$x"
  # shellcheck disable=SC2016
  it_check "$label: the members match their SHA256SUMS" bash -c 'cd "$1" && sha256sum -c --quiet SHA256SUMS' _ "$x"
  dr_ev "backup=${f##*/} sha256=$(sha256sum <"$f" | cut -c1-64)"
  dr_ev "manifest $(jq -r '"trigger=" + (.trigger // "") + " product.version=" + (."product.version" // "") + " db.location=" + (."db.location" // "")' "$x/backup-manifest.json")"
  dr_ev "snapshot $(grep -E '^(authz\.|usable=|fp\.)' "$x/snapshot.txt" | paste -sd' ' -)"
  dr_ev "snapshot migrations=$(grep -c '^migration=' "$x/snapshot.txt") model=$(grep -cx "migration=$DR_MODEL" "$x/snapshot.txt")"
  if [ "$DR_FORM" = external ]; then pgc=it-pg-$DR_SERVER; else pgc=custodexa-postgres; fi
  docker exec -i "$pgc" pg_restore --list <"$x/db.dump" | sed -n 's/.* TABLE public \([a-z_]*\) .*/\1/p' | LC_ALL=C sort -u >"$x/tables"
  dr_ev "dump tables=$(grep -c . "$x/tables") model_tables=$(grep -xE 'authz_state|permission_state_events|user_group_roles|role_binding_nodes' "$x/tables" | paste -sd, -)"
}

# ---- the steps ----

dr_install() {
  local bundle
  dr_begin 1 "install $DR_OLD (published)"
  it_check "the published $DR_OLD files match their SHA256SUMS" bash -c 'cd /published && sha256sum -c --quiet SHA256SUMS'
  sed 's/^/   published: /' /published/SHA256SUMS
  bundle=$(find /published -maxdepth 1 -name "custodexa-images-$DR_OLD-*.tar")
  mkdir -p /opt
  tar -xzf "/published/custodexa-$DR_OLD.tar.gz" -C /opt
  it_same "current/VERSION of the published package" "$DR_OLD" "$(cat "$LV_ROOT/current/VERSION")"
  it_same "its MANIFEST lists no $DR_MODEL" 0 "$(jq --arg m "$DR_MODEL" '[.migrations[] | select(. == $m)] | length' "$LV_ROOT/current/MANIFEST.json")"
  dr_ev "manifest.migrations=$(jq '.migrations | length' "$LV_ROOT/current/MANIFEST.json") images=$(jq -r '.images | to_entries | map(select(.key == "backend" or .key == "frontend") | .key + "@" + .value.index_digest) | join(",")' "$LV_ROOT/current/MANIFEST.json")"
  if [ "$DR_FORM" = external ]; then
    ex_pg_start "$DR_SERVER" 17 "$DR_EXT_PORT"
    ex_db_create "$DR_SERVER"
    ex_preset "$LV_ROOT" "COMPOSE_FILE=current/compose.yml:current/compose.external-database.yml" \
      "EXTERNAL_DB_HOST=$(ex_addr)" "EXTERNAL_DB_PORT=$DR_EXT_PORT" "DB_NAME=$EX_DB" "DB_USER=$EX_USER" \
      "DB_PASSWORD=$EX_PASS" KEK_PROVIDER=env
    dr_ev "database=external PostgreSQL $(it_pg_sql "$DR_SERVER" postgres 'SHOW server_version') at $(ex_addr):$DR_EXT_PORT"
  else
    ex_preset "$LV_ROOT" KEK_PROVIDER=env
    dr_ev "database=built-in custodexa-postgres"
  fi
  dr_cx install install --images "$bundle"
  it_same "install $DR_OLD exits 0" 0 "$LV_RC"
  lv_wait_version "$DR_OLD"
  it_same "no $DR_MODEL in schema_migrations" 0 "$(lv_sql "SELECT count(*) FROM schema_migrations WHERE version = '$DR_MODEL'")"
  dr_ev "running backend image=$(docker inspect --format '{{.Image}}' custodexa-backend) frontend image=$(docker inspect --format '{{.Image}}' custodexa-frontend)"
  dr_ev "keys $(dr_keys)"
  dr_end
}

dr_user() { # <username> <roles json array> [kind/owner json]: id
  local body
  body=$(jq -cn --arg n "$1" --argjson r "$2" '{username: $n, password: "It-user-pass-0001", email: "\($n)@example.test", full_name: "Drill \($n)", roles: $r}')
  lv_api POST /users "$body" | jq -er '.data.id // .id'
}

dr_fixtures() {
  local u1 u2 ap nr ag gid aid exp x
  dr_begin 2 "fixtures, tickets and report R0 on $DR_OLD"
  u1=$(dr_user it-user1 '["user"]')
  u2=$(dr_user it-user2 '["auditor"]')
  ap=$(dr_user it-approver '["approver"]')
  nr=$(dr_user it-norole '[]')
  ag=$(lv_api POST /users "$(jq -cn --argjson o "$u1" '{kind: "agent", owner_user_id: $o, username: "it-agent", full_name: "Drill agent"}')" | jq -er '.data.id // .id')
  gid=$(lv_api POST /user-groups '{"name":"it-drill-group","description":"recovery drill"}' | jq -er '.data.id // .id')
  lv_api PUT "/user-groups/$gid/members" "$(jq -cn --argjson a "$u1" --argjson b "$u2" '{user_ids: [$a, $b]}')" >/dev/null
  aid=$(lv_api POST /assets '{"name":"it-drill-asset","protocol":"ssh","host":"192.0.2.30","port":22,"description":"recovery drill","tags":"it"}' | jq -er '.data.id // .id')
  DR_AGENT_ID=$ag
  dr_ev "fixtures user1=$u1 user2=$u2 approver=$ap norole=$nr agent=$ag group=$gid asset=$aid"
  for x in it-user1 it-user2; do printf 'It-user-pass-0001' >"$IT_WORK/pw-$x"; done
  dr_signin it-user1 u1
  dr_signin it-user2 u2
  exp=$(date -u -d '+30 days' +%FT%TZ)
  lv_api POST "/users/$ag/agent-tokens" "$(jq -cn --arg e "$exp" '{name: "it-drill", expires_at: $e}')" | jq -er .token >"$IT_WORK/tok-agent.token"
  cp "$IT_WORK/tok-u1.access" "$IT_WORK/tok-a0.access"
  dr_ev "tickets access(u1) len=$(wc -c <"$IT_WORK/tok-u1.access") refresh(u1) len=$(wc -c <"$IT_WORK/tok-u1.refresh") refresh(u2) len=$(wc -c <"$IT_WORK/tok-u2.refresh") agent len=$(wc -c <"$IT_WORK/tok-agent.token") claims=$(dr_claims a0 | jq -c 'keys')"
  dr_expect "access ticket of it-user1 on $DR_OLD" 200 "$(dr_access a0)"
  dr_expect "refresh ticket of it-user1 on $DR_OLD (rotated)" 200 "$(dr_refresh u1)"
  cp "$IT_WORK/tok-u1.refresh" "$IT_WORK/tok-u1s2.refresh"
  dr_expect "agent ticket on $DR_OLD" 200 "$(dr_agent)"
  dr_expect "an access ticket signed with JWT_SECRET (crafted from the claims) on $DR_OLD" 200 "$(dr_crafted a0 "$(lv_env_get JWT_SECRET)")"
  dr_ev "refresh(u2) kept unused for the later steps"
  # Checkpoints every 60 seconds instead of every hour: the first one after the upgrade starts the
  # chain of permission state events, which has to be running before the backup (step 8 looks
  # for the restore event on it).
  lv_api PUT /security-policies '{"policies":{"audit_checkpoint_interval_seconds":"60"}}' >/dev/null
  dr_ev "policy audit_checkpoint_interval_seconds=60 (was 3600)"
  dr_report R0
  it_same "R0: it-approver holds approver only" "approver/manual" "$(dr_get R0 approver_only)"
  it_same "R0: it-norole holds no role" 0 "$(dr_get R0 no_role)"
  it_check "R0: at least one local administrator" test "$(dr_get R0 local_admins.api)" -ge 1
  dr_end
}

dr_upgrade() {
  local x
  dr_begin 3 "upgrade $DR_OLD -> $DR_NEW"
  dr_ev "package $(cd "/it-run/pkg-$DR_NEW" && sha256sum "custodexa-$DR_NEW.tar.gz")"
  dr_ev "package manifest.migrations=$(jq '.migrations | length' "/it-run/pkg-$DR_NEW/MANIFEST.json") model=$(jq --arg m "$DR_MODEL" '[.migrations[] | select(. == $m)] | length' "/it-run/pkg-$DR_NEW/MANIFEST.json") rollback_compatible=$(jq -c '.rollback_compatible' "/it-run/pkg-$DR_NEW/MANIFEST.json") images=$(jq -r '.images | to_entries | map(select(.key == "backend" or .key == "frontend") | .key + "@" + .value.index_digest) | join(",")' "/it-run/pkg-$DR_NEW/MANIFEST.json")"
  touch "$IT_WORK/mark"
  sleep 1
  dr_cx upgrade upgrade "$(it_package_file "$DR_NEW")" --images "$(it_bundle_file "$DR_NEW")" --yes
  it_same "upgrade exits 0" 0 "$LV_RC"
  lv_wait_version "$DR_NEW"
  it_same "last_upgrade.result from to" "succeeded $DR_OLD $DR_NEW" "$(lv_st last_upgrade.result) $(lv_st last_upgrade.from) $(lv_st last_upgrade.to)"
  DR_UPGRADE_BACKUP=$LV_ROOT/$(lv_st last_upgrade.backup)
  dr_backup_facts upgrade-backup "$DR_UPGRADE_BACKUP"
  x=$IT_WORK/upgrade-backup.x
  it_same "the upgrade's backup is data of $DR_OLD" "$DR_OLD" "$(jq -r '."product.version"' "$x/backup-manifest.json")"
  it_same "its snapshot.txt says authz.model=legacy and has no other authz key" "authz.model=legacy" "$(grep '^authz\.' "$x/snapshot.txt")"
  it_same "its snapshot lists no $DR_MODEL" 0 "$(grep -cx "migration=$DR_MODEL" "$x/snapshot.txt" || true)"
  if [ "$DR_FORM" = external ]; then
    it_same "the upgrade's backup was exported from the external database" external "$(jq -r '."db.location"' "$x/backup-manifest.json")"
    dr_ev "export client $(grep -hoE 'pgclient1[678][^ ]*' "$LV_ROOT"/logs/upgrade-*.log | sort -u | paste -sd, -)"
  fi
  it_same "schema_migrations now holds $DR_MODEL" 1 "$(lv_sql "SELECT count(*) FROM schema_migrations WHERE version = '$DR_MODEL'")"
  dr_ev "running backend image=$(docker inspect --format '{{.Image}}' custodexa-backend) frontend image=$(docker inspect --format '{{.Image}}' custodexa-frontend)"
  dr_ev "keys $(dr_keys)"
  it_same "restore_generation is empty after an upgrade" "" "$(lv_sql "SELECT restore_generation FROM authz_state")"
  dr_ev "a0 seconds left=$(dr_left a0)"
  if [ "$(dr_left a0)" -gt 20 ]; then
    dr_expect "access ticket from $DR_OLD after the upgrade" 200 "$(dr_access a0)"
  fi
  dr_expect "an access ticket signed with JWT_SECRET after the upgrade (no restore generation)" 200 "$(dr_crafted a0 "$(lv_env_get JWT_SECRET)")"
  dr_expect "refresh ticket of it-user1 from $DR_OLD after the upgrade (rotated)" 200 "$(dr_refresh u1)"
  dr_expect "agent ticket from $DR_OLD after the upgrade" 200 "$(dr_agent)"
  dr_end
}

# After the upgrade: one mapping source row. The model has no API that writes a group
# binding (user_group_roles) yet, and a mapped or both role needs a sign-in through an identity
# provider, which this host has none of: the rule is written, nobody gets a role from it.
dr_mapping() {
  local r pid=""
  LV_TOKEN=""
  r=$(lv_api POST /oidc-providers '{"name":"it-drill-idp","issuer":"https://198.51.100.7/realms/it","client_id":"it-drill","client_secret":"it-drill-client-secret","scopes":"openid profile email groups","groups_claim":"groups","enabled":false,"risk_acknowledged":true}' 2>&1) || r=""
  pid=$(jq -r '.data.id // .id // empty' <<<"$r" 2>/dev/null || true)
  if [ -z "$pid" ]; then
    dr_ev "mapping source: the identity provider was not accepted here ($(head -c 160 <<<"$r" | tr '\n' ' '))"
    return 0
  fi
  r=$(lv_api POST "/identity-sources/oidc/$pid/role-mappings" '{"match_value":"it-drill-ops","role":"auditor","enabled":true,"risk_acknowledged":true}' 2>&1) || r=""
  dr_ev "mapping source: provider=$pid role-mapping=$(jq -r '.data.id // empty' <<<"$r" 2>/dev/null || true) ($(head -c 120 <<<"$r" | tr '\n' ' '))"
}

# dr_wait_chain: at most 5 minutes until the first checkpoint after the upgrade has started the
# chain of permission state events (the scheduler looks every minute, then waits its grace).
dr_wait_chain() {
  local i
  for ((i = 0; i < 100; i++)); do
    [ "$(lv_sql "SELECT count(*) FROM permission_state_events WHERE kind = 'activate'")" -ge 1 ] && return 0
    sleep 3
  done
  printf 'not ok - the permission event chain did not start within 5 minutes\n'
  return 1
}

dr_after_upgrade() {
  dr_begin 4 "report R1 after the upgrade, compared with R0"
  dr_mapping
  dr_wait_chain
  dr_ev "permission event chain active at $(dr_now): $(lv_sql "SELECT kind||' seq='||seq||' at '||created_at FROM permission_state_events ORDER BY seq" | paste -sd';' -)"
  dr_cp_export upgrade
  dr_cp_verify upgrade
  it_same "v4: the first attested checkpoint after the upgrade is the trusted origin (origin=true, event_seq=1)" "true 1" \
    "$(jq -r '[.data.items | sort_by(.seq)[] | select(.perm != null)][0] | "\(.perm.origin) \(.perm.event_seq)"' "$IT_WORK/cp-upgrade.json")"
  it_same "v4: the first activation after the upgrade opened no permission alert" 0 "$(dr_perm_alerts)"
  dr_ev "open failure events: $(dr_open_failures)"
  dr_report R1
  dr_same "R1 = R0: users, roles and sources, groups, members, approver, no-role, agent owner, local administrators" R0 R1 "${DR_DATA_KEYS[@]}"
  it_same "R1: approver only, not more" "approver/manual" "$(dr_get R1 approver_only)"
  it_same "R1: no role, not more" 0 "$(dr_get R1 no_role)"
  it_same "R1: every direct role is global" "global:$(dr_get R1 user_roles | cut -d' ' -f1)" "$(dr_get R1 user_roles.scope)"
  it_same "R1: local administrators, the API and the conditions as SQL" "$(dr_get R1 local_admins.api)" "$(dr_get R1 local_admins.sql)"
  it_same "R1: restore generation empty" "empty" "$(dr_get R1 authz_state | sed -n 's/.* generation=\([^ ]*\).*/\1/p')"
  dr_ev "migrations R0=$(dr_get R0 migrations) R1=$(dr_get R1 migrations) model_migration=$(dr_get R1 model_migration)"
  dr_end
}

dr_host_state() { (cd "$LV_ROOT" && sha256sum .env state.json && readlink current && ls -1A releases); }

# dr_rollback <step> <label>: rollback --yes is refused before anything stops (exit 3), nothing changed.
dr_rollback() {
  local ps0 st0
  ps0=$(lv_ps)
  st0=$(dr_host_state)
  dr_cx "$2" rollback --yes
  it_same "rollback exits 3" 3 "$LV_RC"
  it_same "the same containers run, none restarted" "$ps0" "$(lv_ps)"
  it_same ".env, state.json, the current link and releases/ are unchanged" "$st0" "$(dr_host_state)"
  it_same "no rollback record" "" "$(lv_st last_rollback.result)"
  # shellcheck disable=SC2016
  it_check "no preview and no confirmation were reached" bash -c '! grep -qE "\[y/N\]" <<<"$1"' _ "$LV_OUT"
  it_same "the backend still reports $DR_NEW" "$DR_NEW" "$(lv_version)"
}

dr_rollback_after_upgrade() {
  dr_begin 4b "rollback right after the upgrade (the database carries the model migration)"
  dr_rollback 4b rollback-4b
  it_check "the screen says it cannot go straight back to $DR_OLD" grep -q "Cannot go straight back to $DR_OLD" <<<"$LV_OUT"
  dr_ev "why: $(sed -n '/Why/,/To go back/p' <<<"$LV_OUT" | sed '$d' | tr '\n' ' ' | tr -s ' ')"
  # The built-in database is read by the rollback's own check; it names the migrations it found.
  if [ "$DR_FORM" = builtin ]; then
    it_check "the screen names $DR_MODEL" grep -q "$DR_MODEL" <<<"$LV_OUT"
  fi
  it_check "the screen gives the restore command of the upgrade's backup file" grep -qF "custodexa.sh restore $DR_UPGRADE_BACKUP" <<<"$LV_OUT"
  dr_end
}

dr_backup() {
  dr_begin 5 "backup on $DR_NEW"
  dr_expect "refresh ticket of it-user1 just before the backup (rotated; the new one goes into the backup)" 200 "$(dr_refresh u1)"
  cp "$IT_WORK/tok-u1.refresh" "$IT_WORK/tok-u1s5.refresh"
  dr_expect "agent ticket just before the backup" 200 "$(dr_agent)"
  dr_ev "agent tokens before the backup: $(dr_agent_marks)"
  it_same "v4: the agent token list marks nothing before the restore" "it-drill:-:active" "$(dr_agent_marks)"
  touch "$IT_WORK/mark"
  sleep 1
  dr_cx backup backup --yes
  it_same "backup exits 0" 0 "$LV_RC"
  DR_BACKUP5=$(find "$LV_ROOT/backups" -maxdepth 1 -name 'custodexa-backup-*.tar' -newer "$IT_WORK/mark" | head -n1)
  dr_backup_facts backup5 "$DR_BACKUP5"
  it_same "its snapshot has every authz key, refs=ok" "authz.model=1 authz.refs=ok" \
    "$(grep -E '^authz\.(model|refs)=' "$IT_WORK/backup5.x/snapshot.txt" | LC_ALL=C sort | paste -sd' ' -)"
  it_same "its snapshot's authz.digest is the one the backend reports now" "$(dr_get R1 perm.authz.digest)" \
    "$(sed -n 's/^authz\.digest=//p' "$IT_WORK/backup5.x/snapshot.txt")"
  it_check "the dump holds the model tables" test "$(grep -cxE 'authz_state|permission_state_events|user_group_roles|role_binding_nodes' "$IT_WORK/backup5.x/tables")" = 4
  if [ "$DR_FORM" = external ]; then
    it_same "the manifest says db.location=external" external "$(jq -r '."db.location"' "$IT_WORK/backup5.x/backup-manifest.json")"
  fi
  dr_ev "keys $(dr_keys)"
  dr_end
}

dr_restore() {
  local log
  dr_begin 6 "restore of the step 5 backup on the same host"
  dr_signin it-user1 u1pre
  dr_ev "u1pre seconds left=$(dr_left u1pre)"
  dr_expect "access ticket issued just before the restore" 200 "$(dr_access u1pre)"
  dr_expect "an access ticket signed with JWT_SECRET just before the restore" 200 "$(dr_crafted a0 "$(lv_env_get JWT_SECRET)")"
  lv_sql "SELECT restore_generation FROM authz_state" | dr_sha8 >"$IT_WORK/gen.before"
  dr_cp_export pre-restore
  dr_cp_verify pre-restore
  it_same "v4: no permission alert before the restore" 0 "$(dr_perm_alerts)"
  dr_cx restore restore "$DR_BACKUP5" --same-host --yes --confirm-data-loss
  it_same "restore exits 0" 0 "$LV_RC"
  it_same "last_restore.result" succeeded "$(lv_st last_restore.result)"
  lv_wait_version "$DR_NEW"
  log=$(lv_st last_restore.log)
  [[ $log == /* ]] || log=$LV_ROOT/$log
  { grep -nE 'CHECK|legacy|revok' "$log" || true; } | cut -c1-220 | sed "s/^/EVID $DR_FORM step=6 log: /" | awk 'NR <= 40'
  it_check "the restore log has the backend's permission restore line with a new generation" \
    grep -qE 'permission restore .*restore\.generation_fp=[0-9a-f]+ .*restore\.fresh=true' "$log"
  { grep -E '\] +[0-9]+/[0-9]+ ' <<<"$LV_OUT" || true; } | cut -c1-160 | sed "s/^/EVID $DR_FORM step=6 screen: /"
  dr_ev "keys $(dr_keys)"
  dr_end
}

dr_tickets_after_restore() {
  dr_begin 7 "old tickets and a new sign-in after the restore"
  dr_ev "u1pre seconds left=$(dr_left u1pre)"
  it_check "the access ticket issued before the restore has not expired yet" test "$(dr_left u1pre)" -gt 5
  dr_expect "access ticket issued before the restore" 401 "$(dr_access u1pre)"
  dr_expect "an access ticket signed with JWT_SECRET (the setting is unchanged; the generation is not empty)" 401 "$(dr_crafted a0 "$(lv_env_get JWT_SECRET)")"
  dr_expect "refresh ticket of it-user1 in the backup (rotated just before it)" 401 \
    "$(cp "$IT_WORK/tok-u1s5.refresh" "$IT_WORK/tok-p7.refresh" && dr_refresh p7)"
  dr_expect "refresh ticket of it-user2 from $DR_OLD (never used)" 401 \
    "$(cp "$IT_WORK/tok-u2.refresh" "$IT_WORK/tok-q7.refresh" && dr_refresh q7)"
  dr_expect "agent ticket from $DR_OLD" 401 "$(dr_agent)"
  LV_TOKEN=""
  lv_login
  it_check "administrator signs in again" test -n "$LV_TOKEN"
  dr_ev "agent tokens after the restore: $(dr_agent_marks)"
  it_same "v4: the agent token list marks the token from before the restore" "it-drill:restore_invalidated:active" "$(dr_agent_marks)"
  dr_signin it-user1 u1new
  dr_expect "new access ticket of it-user1" 200 "$(dr_access u1new)"
  dr_expect "new refresh ticket of it-user1 (rotated)" 200 "$(dr_refresh u1new)"
  it_same "the claims of a new access ticket have the same keys" "$(dr_claims a0 | jq -c 'keys')" "$(dr_claims u1new | jq -c 'keys')"
  cp "$IT_WORK/tok-u1new.access" "$IT_WORK/tok-a7.access"
  cp "$IT_WORK/tok-u1new.refresh" "$IT_WORK/tok-a7.refresh"
  dr_end
}

dr_after_restore() {
  local g1 g2
  dr_begin 8 "report R2 after the restore, compared with R1"
  ri_mark
  dr_report R2
  dr_same "R2 = R1: users, roles and sources, groups, members, approver, no-role, agent owner, local administrators" R1 R2 "${DR_DATA_KEYS[@]}"
  local -a counts=()
  mapfile -t counts < <(sed -n 's/^\(perm\.authz\.count\.[a-z_]*\)=.*/\1/p' "$IT_WORK/R1.txt")
  dr_same "R2 = R1: migrations, mapping rows, group bindings, node bindings, the backend's catalog, set counts and references" R1 R2 \
    migrations role_maps group_maps group_roles binding_nodes perm.authz.catalog perm.authz.refs "${counts[@]}"
  dr_ev "backend digest R1=$(dr_get R1 perm.authz.digest | cut -c1-16) R2=$(dr_get R2 perm.authz.digest | cut -c1-16) (it covers version, generation and operation, which the restore changes)"
  g1=$(dr_get R1 authz_state | sed -n 's/.* generation=\([^ ]*\).*/\1/p')
  g2=$(dr_get R2 authz_state | sed -n 's/.* generation=\([^ ]*\).*/\1/p')
  it_check "the restore generation is set and differs from before ($g1 -> $g2)" test "$g2" != empty -a "$g2" != "$g1"
  it_check "a restore event is on the chain" grep -qE '(^|,| )restore:[1-9]' <<<"$(dr_get R2 events)"
  it_check "version moved on ($(dr_get R1 authz_state | cut -d' ' -f1) -> $(dr_get R2 authz_state | cut -d' ' -f1))" \
    test "$(dr_get R2 authz_state | sed -n 's/^version=\([0-9]*\).*/\1/p')" -gt "$(dr_get R1 authz_state | sed -n 's/^version=\([0-9]*\).*/\1/p')"
  it_check "R2: at least one local administrator" test "$(dr_get R2 local_admins.api)" -ge 1
  dr_end
}

dr_restart() {
  dr_begin 9 "stop and start: the migrations run again on the same database"
  dr_cx stop stop --yes
  it_same "stop exits 0" 0 "$LV_RC"
  dr_cx start start
  it_same "start exits 0" 0 "$LV_RC"
  lv_wait_version "$DR_NEW"
  ri_mark
  dr_report R3
  dr_same "R3 = R2: every line of the report" R2 R3 "${DR_DATA_KEYS[@]}" migrations model_migration role_maps group_maps \
    group_roles binding_nodes authz_state events user_roles.scope user_roles.by_source local_admins.sql perm.authz.digest perm.authz.version perm.authz.refs
  dr_ev "a7 seconds left=$(dr_left a7)"
  if [ "$(dr_left a7)" -gt 5 ]; then
    dr_expect "access ticket issued after the restore, after the restart (same generation)" 200 "$(dr_access a7)"
  fi
  dr_expect "refresh ticket issued after the restore, after the restart (same generation; rotated)" 200 "$(dr_refresh a7)"
  LV_TOKEN=""
  dr_ev "agent tokens after the restart: $(dr_agent_marks)"
  it_same "v4: the agent token mark is unchanged after the restart" "it-drill:restore_invalidated:active" "$(dr_agent_marks)"
  it_same "v4: still no permission alert after the restart" 0 "$(dr_perm_alerts)"
  dr_end
}

# 8b (v4): the first checkpoint sealed after the restore carries the attestation of the restored
# state with the restore event as its head, the reconciliation says it matches and opens no alert;
# the chain is verified offline again.
dr_first_seal_after_restore() {
  local i first row restore_seq cp
  dr_begin 8b "v4: the first checkpoint sealed after the restore"
  for ((i = 0; i < 100; i++)); do
    first=$(lv_sql "SELECT coalesce(min(seq)::text, '') FROM audit_checkpoints WHERE sealed_at > (SELECT restored_at FROM authz_state)")
    [ -z "$first" ] || break
    sleep 3
  done
  it_check "a checkpoint was sealed after the restore within 5 minutes" test -n "$first"
  dr_ev "restored_at=$(lv_sql "SELECT restored_at FROM authz_state") first seal after it: seq=$first sealed_at=$(lv_sql "SELECT sealed_at FROM audit_checkpoints WHERE seq = $first")"
  restore_seq=$(lv_sql "SELECT seq FROM permission_state_events WHERE kind = 'restore' ORDER BY seq DESC LIMIT 1")
  row=$(lv_sql "SELECT agg_scheme||' format='||coalesce(perm_format::text,'null')||' reconciled='||coalesce(perm_reconciled::text,'null')||' origin='||coalesce(perm_origin::text,'null')||' event_seq='||coalesce(perm_event_seq::text,'null') FROM audit_checkpoints WHERE seq = $first")
  dr_ev "row seq=$first $row; restore event seq=$restore_seq; events $(lv_sql "SELECT kind||':'||seq FROM permission_state_events ORDER BY seq" | paste -sd, -)"
  it_same "v4: the first seal after the restore is a v4 point, attested, reconciled=true, not an origin, its event head the restore event" \
    "cp-agg-v4 reconciled=true origin=false event_seq=$restore_seq" "$(sed 's/ format=[^ ]*//' <<<"$row")"
  it_same "v4: the reconciliation opened no permission alert after the restore" 0 "$(dr_perm_alerts)"
  dr_ev "open failure events: $(dr_open_failures)"
  LV_TOKEN=""
  dr_ev "verify endpoint: $(lv_api GET /audit-checkpoints/verify | jq -c '.data // . | with_entries(select(.value | type != "array" and type != "object"))')"
  it_same "v4: the verify endpoint reports no stalled permission comparison" false \
    "$(lv_api GET /audit-checkpoints/verify | jq '(.data // .) | has("permission_state")')"
  dr_cp_export post-restore
  cp=$(jq -c --argjson s "$first" '.data.items[] | select(.seq == $s) | .perm' "$IT_WORK/cp-post-restore.json")
  dr_ev "list perm of seq=$first: $(jq -c 'del(.catalog, .snapshot_digest, .event_head)' <<<"$cp")"
  it_same "v4: the list shows that point with reconciled=true origin=false" "true false" "$(jq -r '"\(.reconciled) \(.origin)"' <<<"$cp")"
  dr_cp_verify post-restore
  it_same "v4: the restore generation is unchanged by the seal" "$(dr_get R2 authz_state)" \
    "$(lv_sql "SELECT 'version='||version||' generation='||CASE WHEN restore_generation = '' THEN 'empty' ELSE left(encode(sha256(convert_to(restore_generation,'UTF8')),'hex'),8) END||' status='||coalesce(nullif(restore_status,''),'none')||' op='||coalesce(nullif(restore_op_id,''),'none') FROM authz_state")"
  dr_end
}

dr_rollback_refused() {
  dr_begin 10 "rollback to $DR_OLD"
  dr_rollback 10 rollback
  dr_ev "screen: $(tr '\n' ' ' <<<"$LV_OUT" | tr -s ' ' | cut -c1-400)"
  dr_end
}

dr_back_to_old() {
  local old new x
  dr_begin 11 "the upgrade's backup ($DR_OLD) restored with $DR_OLD"
  old=$(lv_env_get JWT_SECRET)
  dr_cx load load "/published/$(cd /published && ls custodexa-images-"$DR_OLD"-*.tar)"
  it_same "load of the $DR_OLD bundle exits 0" 0 "$LV_RC"
  dr_cx restore-old restore "$DR_UPGRADE_BACKUP" --same-host --yes --confirm-data-loss
  it_same "restore exits 0" 0 "$LV_RC"
  it_same "last_restore.result" succeeded "$(lv_st last_restore.result)"
  lv_wait_version "$DR_OLD"
  it_same "back on $DR_OLD" "$DR_OLD releases/$DR_OLD" "$(lv_st current.version) $(readlink "$LV_ROOT/current")"
  new=$(lv_env_get JWT_SECRET)
  it_check "JWT_SECRET of .env was replaced" test -n "$new" -a "$new" != "$old"
  dr_ev "jwt_secret before=$(printf '%s' "$old" | dr_sha8) after=$(printf '%s' "$new" | dr_sha8) last_restore.legacy_return=\"$(lv_st last_restore.legacy_return)\""
  it_check "the restore record has the legacy return (secret fingerprint, revoked kinds)" \
    grep -qE '^secret=[0-9a-f]+ revoked=refresh,agent,ticket$' <<<"$(lv_st last_restore.legacy_return)"
  x=$(lv_st last_restore.log)
  [[ $x == /* ]] || x=$LV_ROOT/$x
  { grep -nE 'CHECK|legacy|revok' "$x" || true; } | cut -c1-220 | sed "s/^/EVID $DR_FORM step=11 log: /" | awk 'NR <= 40'
  it_same "the new secret is in no file of the deployment but .env, and not on the screen" "" \
    "$(grep -rlF --exclude=.env -- "$new" "$LV_ROOT" 2>/dev/null; grep -cF -- "$new" <<<"$LV_OUT" | grep -v '^0$' || true)"
  it_same "schema_migrations holds no $DR_MODEL" 0 "$(lv_sql "SELECT count(*) FROM schema_migrations WHERE version = '$DR_MODEL'")"
  dr_expect "an access ticket signed with the JWT_SECRET of before" 401 "$(dr_crafted a0 "$old")"
  dr_expect "an access ticket signed with the new JWT_SECRET (control: the claims are still good)" 200 "$(dr_crafted a0 "$new")"
  dr_expect "access ticket issued on $DR_NEW after its restore" 401 "$(dr_access a7)"
  dr_expect "refresh ticket of it-user1 that was valid when the upgrade's backup was taken" 401 "$(dr_refresh u1s2)"
  dr_expect "refresh ticket of it-user2 from $DR_OLD (never used)" 401 "$(cp "$IT_WORK/tok-u2.refresh" "$IT_WORK/tok-q11.refresh" && dr_refresh q11)"
  dr_expect "refresh ticket issued on $DR_NEW after its restore" 401 "$(dr_refresh a7)"
  dr_expect "agent ticket from $DR_OLD" 401 "$(dr_agent)"
  LV_TOKEN=""
  lv_login
  it_check "administrator signs in on $DR_OLD" test -n "$LV_TOKEN"
  dr_signin it-user1 u1old
  dr_expect "new access ticket of it-user1 on $DR_OLD" 200 "$(dr_access u1old)"
  ri_mark
  dr_report R4
  dr_same "R4 = R0: users, roles and sources, groups, members, approver, no-role, agent owner, local administrators" R0 R4 "${DR_DATA_KEYS[@]}"
  dr_same "R4 = R0: migrations, mapping rows" R0 R4 migrations model_migration role_maps group_maps
  it_same "R4: no agent ticket active" 0 "$(dr_get R4 tokens.agent_active)"
  sed -n 's/^tokens\./tokens./p' "$IT_WORK/R4.txt" | sed "s/^/EVID $DR_FORM step=11 R4 /"
  dr_ev "keys $(dr_keys)"
  dr_end
}

dr_round() {
  DR_FORM=$1
  dr_install
  dr_fixtures
  dr_upgrade
  dr_after_upgrade
  dr_rollback_after_upgrade
  dr_backup
  dr_restore
  dr_tickets_after_restore
  dr_after_restore
  dr_first_seal_after_restore
  dr_restart
  dr_rollback_refused
  dr_back_to_old
  dr_begin 12 "end of the round"
  dr_ev "state current=$(lv_st current.version) previous=$(lv_st previous.version) last_upgrade=$(lv_st last_upgrade.result) last_restore=$(lv_st last_restore.result)"
  dr_ev "worktree status before/after the builder: $(cmp -s /it-run/worktree-status.before /it-run/worktree-status.after && echo same || echo differ)"
  dr_end
}

scenario_builtin() { dr_round builtin; }
scenario_external() { dr_round external; }
