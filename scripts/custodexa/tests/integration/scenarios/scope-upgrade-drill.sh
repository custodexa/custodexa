# shellcheck shell=bash
# about: the upgrade of a deployment that already has the permission model, once with the built-in database (host builtin) and once with an external PostgreSQL 17 (host external): the published 1.18.1 installed, a node, a user holding a role over that node, a user holding a role globally and a group holding a role over a node made through its API; upgraded offline to 1.18.90 of the working tree (no migration runs and schema_migrations is the same; every assignment and its node scope is the same; the backup the upgrade took and a new one are usable with their references intact); stop and start keep everything
# hosts: builtin external
# needs: package local-versions published
# images: pg17
#
# Run with CX_IT_LOCAL_VERSIONS=1.18.90 CX_IT_PUBLISHED_VERSION=1.18.1. The reports, the HTTP and
# database helpers and the backup checks are those of permission-recovery-drill (this file loads
# it and replaces only the starting version and the steps). Output follows its conventions:
#   DRILL <form> step=<n> begin=<UTC> name=<name> / end=<UTC> result=PASS
#   EVID <form> step=<n> ...     evidence lines
#   REPORT <form> <R> <key>=<value>   the shared reports (R0 before, R1 after the upgrade, R2 after a restart)
#   SCOPE <form> <S> <key>=<value>    the reports of the assignments and their node scope (scope_before, scope_after, scope_restart)
# Nothing secret is printed.

# shellcheck source=scripts/custodexa/tests/integration/scenarios/permission-recovery-drill.sh
. "$IT_DIR/scenarios/permission-recovery-drill.sh"

readonly SC_OLD=1.18.1
SC_NODE_A="" SC_NODE_B="" SC_ROLE="" SC_GROUP="" SC_SCOPED_USER="" SC_GLOBAL_USER=""

# ---- step 1: install the published release ----

sc_install() {
  local bundle
  dr_begin 1 "install $SC_OLD (published)"
  it_check "the published $SC_OLD files match their SHA256SUMS" bash -c 'cd /published && sha256sum -c --quiet SHA256SUMS'
  sed 's/^/   published: /' /published/SHA256SUMS
  bundle=$(find /published -maxdepth 1 -name "custodexa-images-$SC_OLD-*.tar")
  mkdir -p /opt
  tar -xzf "/published/custodexa-$SC_OLD.tar.gz" -C /opt
  it_same "current/VERSION of the published package" "$SC_OLD" "$(cat "$LV_ROOT/current/VERSION")"
  it_same "its MANIFEST lists $DR_MODEL" 1 "$(jq --arg m "$DR_MODEL" '[.migrations[] | select(. == $m)] | length' "$LV_ROOT/current/MANIFEST.json")"
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
  it_same "install $SC_OLD exits 0" 0 "$LV_RC"
  lv_wait_version "$SC_OLD"
  it_same "$DR_MODEL is in schema_migrations" 1 "$(lv_sql "SELECT count(*) FROM schema_migrations WHERE version = '$DR_MODEL'")"
  dr_ev "running backend image=$(docker inspect --format '{{.Image}}' custodexa-backend) frontend image=$(docker inspect --format '{{.Image}}' custodexa-frontend)"
  dr_end
}

# ---- the assignments and their node scope, as a report ----

# sc_scope_report <S>: the assignment tables row by row, and the two role-binding reads of the API,
# kept in $IT_WORK/<S>.scope; the same queries every time.
sc_scope_report() {
  local s=$1 f=$IT_WORK/$1.scope
  LV_TOKEN=""
  {
    printf 'user_roles=%s %s\n' "$(dr_count user_roles)" \
      "$(dr_rows "SELECT ur.user_id||'|'||ur.role_id||'|'||ur.scope_kind||'|'||ur.source FROM user_roles ur")"
    printf 'user_roles.nodes=%s\n' "$(lv_sql "SELECT count(*) FROM user_roles WHERE scope_kind = 'nodes'")"
    printf 'user_group_roles=%s %s\n' "$(dr_count user_group_roles)" \
      "$(dr_rows "SELECT user_group_id||'|'||role_id||'|'||scope_kind FROM user_group_roles")"
    printf 'user_group_roles.nodes=%s\n' "$(lv_sql "SELECT count(*) FROM user_group_roles WHERE scope_kind = 'nodes'")"
    printf 'role_binding_nodes=%s %s\n' "$(dr_count role_binding_nodes)" \
      "$(dr_rows "SELECT subject_kind||'|'||subject_id||'|'||role_id||'|'||node_id FROM role_binding_nodes")"
    printf 'role_binding_nodes.by_subject=%s\n' "$(lv_sql "SELECT subject_kind||':'||count(*) FROM role_binding_nodes GROUP BY subject_kind ORDER BY subject_kind" | paste -sd, -)"
    printf 'scoped_user.rows=%s\n' "$(lv_sql "SELECT r.name||'/'||ur.scope_kind||'/'||coalesce((SELECT string_agg(rbn.node_id::text, ',' ORDER BY rbn.node_id) FROM role_binding_nodes rbn WHERE rbn.subject_kind = 'user' AND rbn.subject_id = ur.user_id AND rbn.role_id = ur.role_id), '-') FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = $SC_SCOPED_USER ORDER BY r.name" | paste -sd';' -)"
    printf 'global_user.rows=%s\n' "$(lv_sql "SELECT r.name||'/'||ur.scope_kind FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = $SC_GLOBAL_USER ORDER BY r.name" | paste -sd';' -)"
    printf 'group.rows=%s\n' "$(lv_sql "SELECT r.name||'/'||g.scope_kind||'/'||coalesce((SELECT string_agg(rbn.node_id::text, ',' ORDER BY rbn.node_id) FROM role_binding_nodes rbn WHERE rbn.subject_kind = 'user_group' AND rbn.subject_id = g.user_group_id AND rbn.role_id = g.role_id), '-') FROM user_group_roles g JOIN roles r ON r.id = g.role_id WHERE g.user_group_id = $SC_GROUP ORDER BY r.name" | paste -sd';' -)"
    printf 'api.group_role_bindings=%s\n' "$(lv_api GET "/user-groups/$SC_GROUP/role-bindings" | jq -cS '.data | sort_by(.role_id)' | dr_sha16)"
    printf 'api.user_role_bindings=%s\n' "$(lv_api GET "/users/$SC_SCOPED_USER/role-bindings" 2>/dev/null | jq -cS '.data | sort_by(.role_id)' | dr_sha16 || echo unavailable)"
    printf 'api.user_role_bindings.scoped=%s\n' "$(lv_api GET "/users/$SC_SCOPED_USER/role-bindings" 2>/dev/null | jq -cS '[.data[] | select(.node_ids != null) | {role_name, node_ids}]' || echo unavailable)"
  } >"$f"
  sed "s/^/SCOPE $DR_FORM $s /" "$f"
}

# sc_scope_same <what> <S a> <S b>: every line of the two scope reports is the same.
sc_scope_same() {
  it_same "$1" "$(cat "$IT_WORK/$2.scope")" "$(cat "$IT_WORK/$3.scope")"
}

# ---- step 2: the data, and the reports before the upgrade ----

sc_fixtures() {
  local u1 u2 ap nr x
  dr_begin 2 "fixtures through the API and the reports R0, scope_before on $SC_OLD"
  SC_NODE_A=$(lv_api POST /asset-groups '{"name":"it-scope-node-a","description":"upgrade drill"}' | jq -er '.data.id // .id')
  SC_NODE_B=$(lv_api POST /asset-groups '{"name":"it-scope-node-b","description":"upgrade drill"}' | jq -er '.data.id // .id')
  SC_ROLE=$(lv_sql "SELECT id FROM roles WHERE builtin_key = 'asset_admin' AND deleted_at IS NULL")
  it_check "the asset administrator template exists" test -n "$SC_ROLE"
  u1=$(dr_user it-user1 '["user"]')
  u2=$(dr_user it-user2 '["auditor"]')
  ap=$(dr_user it-approver '["approver"]')
  nr=$(dr_user it-norole '[]')
  SC_SCOPED_USER=$(dr_user it-scoped '[]')
  SC_GLOBAL_USER=$(dr_user it-global '[]')
  # the node scope of a direct assignment: the replace entry of the user, role name -> node IDs
  lv_api PUT "/users/$SC_SCOPED_USER/roles" "$(jq -cn --argjson a "$SC_NODE_A" '{manual_roles: ["asset_admin"], role_nodes: {asset_admin: [$a]}}')" >/dev/null
  # the same template held globally, and a second role held globally
  lv_api PUT "/users/$SC_GLOBAL_USER/roles" '{"manual_roles":["asset_admin","auditor"]}' >/dev/null
  SC_GROUP=$(lv_api POST /user-groups '{"name":"it-scope-group","description":"upgrade drill"}' | jq -er '.data.id // .id')
  lv_api PUT "/user-groups/$SC_GROUP/members" "$(jq -cn --argjson a "$u1" --argjson b "$SC_SCOPED_USER" '{user_ids: [$a, $b]}')" >/dev/null
  # a group role over a node (the key is the role ID) and a group role held globally
  x=$(lv_sql "SELECT id FROM roles WHERE name = 'auditor' AND deleted_at IS NULL")
  lv_api PUT "/user-groups/$SC_GROUP/role-bindings" "$(jq -cn --argjson r "$SC_ROLE" --argjson g "$x" --argjson b "$SC_NODE_B" '{role_ids: [$r, $g], role_nodes: {($r | tostring): [$b]}}')" >/dev/null
  dr_ev "fixtures nodes=$SC_NODE_A,$SC_NODE_B asset_admin_role=$SC_ROLE scoped_user=$SC_SCOPED_USER global_user=$SC_GLOBAL_USER group=$SC_GROUP others=$u1,$u2,$ap,$nr"
  dr_report R0
  sc_scope_report scope_before
  it_same "R0: it-approver holds approver only" "approver/manual" "$(dr_get R0 approver_only)"
  it_check "R0: at least one local administrator" test "$(dr_get R0 local_admins.api)" -ge 1
  it_check "scope_before: a direct assignment over nodes exists (user_roles.nodes >= 1)" test "$(sed -n 's/^user_roles.nodes=//p' "$IT_WORK/scope_before.scope")" -ge 1
  it_check "scope_before: a group assignment over nodes exists (user_group_roles.nodes >= 1)" test "$(sed -n 's/^user_group_roles.nodes=//p' "$IT_WORK/scope_before.scope")" -ge 1
  it_check "scope_before: node rows exist for both a user and a group (role_binding_nodes.by_subject)" \
    test "$(sed -n 's/^role_binding_nodes.by_subject=//p' "$IT_WORK/scope_before.scope")" = "user:1,user_group:1"
  it_same "scope_before: the scoped user holds asset_admin over node A" "asset_admin/nodes/$SC_NODE_A" "$(sed -n 's/^scoped_user.rows=//p' "$IT_WORK/scope_before.scope")"
  it_same "scope_before: the group holds asset_admin over node B and auditor globally" "asset_admin/nodes/$SC_NODE_B;auditor/global/-" "$(sed -n 's/^group.rows=//p' "$IT_WORK/scope_before.scope")"
  it_same "scope_before: the global user holds both roles globally" "asset_admin/global;auditor/global" "$(sed -n 's/^global_user.rows=//p' "$IT_WORK/scope_before.scope")"
  dr_end
}

# sc_log_check <what>: the current backend container's start log runs no migration.
sc_log_check() {
  local logs
  logs=$(docker logs custodexa-backend 2>&1)
  dr_ev "$1 start log: $(grep -E '所有 migrations 都已執行|成功執行 [0-9]+ 個 migration' <<<"$logs" | head -n 3 | tr '\n' '|') skipped=$(grep -c '跳過已執行的 migration' <<<"$logs" || true) ran=$(grep -c '  執行 migration:' <<<"$logs" || true)"
  it_check "$1: the start log says every migration was already executed" grep -q '所有 migrations 都已執行' <<<"$logs"
  it_same "$1: the start log shows no migration executed" 0 "$(grep -c '  執行 migration:' <<<"$logs" || true)"
  it_same "$1: the start log has no 'executed N migration(s)' line" 0 "$(grep -c '成功執行 [0-9]* 個 migration' <<<"$logs" || true)"
}

# sc_snapshot_ok <label>: the backup's snapshot.txt has its references intact and says it is usable.
sc_snapshot_ok() {
  local s=$IT_WORK/$1.x/snapshot.txt
  it_check "$1: snapshot authz.refs=ok" grep -qx 'authz.refs=ok' "$s"
  it_check "$1: snapshot usable=true" grep -qx 'usable=true' "$s"
}

# ---- step 3: the upgrade ----

sc_upgrade() {
  local x
  dr_begin 3 "upgrade $SC_OLD -> $DR_NEW"
  dr_ev "package $(cd "/it-run/pkg-$DR_NEW" && sha256sum "custodexa-$DR_NEW.tar.gz")"
  dr_ev "package manifest.migrations=$(jq '.migrations | length' "/it-run/pkg-$DR_NEW/MANIFEST.json") rollback_compatible=$(jq -c '.rollback_compatible' "/it-run/pkg-$DR_NEW/MANIFEST.json")"
  it_same "the package's MANIFEST lists the same migrations as the published $SC_OLD" \
    "$(jq -c '.migrations' "$LV_ROOT/current/MANIFEST.json")" "$(jq -c '.migrations' "/it-run/pkg-$DR_NEW/MANIFEST.json")"
  touch "$IT_WORK/mark"
  sleep 1
  dr_cx upgrade upgrade "$(it_package_file "$DR_NEW")" --images "$(it_bundle_file "$DR_NEW")" --yes
  it_same "upgrade exits 0" 0 "$LV_RC"
  lv_wait_version "$DR_NEW"
  it_same "last_upgrade.result from to" "succeeded $SC_OLD $DR_NEW" "$(lv_st last_upgrade.result) $(lv_st last_upgrade.from) $(lv_st last_upgrade.to)"
  it_same "the script reports no structure change" 0 "$(grep -cE 'structure changes? applied' <<<"$LV_OUT" || true)"
  DR_UPGRADE_BACKUP=$LV_ROOT/$(lv_st last_upgrade.backup)
  dr_backup_facts upgrade-backup "$DR_UPGRADE_BACKUP"
  x=$IT_WORK/upgrade-backup.x
  it_same "the upgrade's backup is data of $SC_OLD" "$SC_OLD" "$(jq -r '."product.version"' "$x/backup-manifest.json")"
  sc_snapshot_ok upgrade-backup
  it_same "its snapshot lists $DR_MODEL" 1 "$(grep -cx "migration=$DR_MODEL" "$x/snapshot.txt" || true)"
  if [ "$DR_FORM" = external ]; then
    it_same "the upgrade's backup was exported from the external database" external "$(jq -r '."db.location"' "$x/backup-manifest.json")"
  fi
  sc_log_check upgrade
  dr_ev "running backend image=$(docker inspect --format '{{.Image}}' custodexa-backend) frontend image=$(docker inspect --format '{{.Image}}' custodexa-frontend)"
  dr_end
}

# ---- step 4: the reports after the upgrade ----

sc_after_upgrade() {
  dr_begin 4 "reports R1, scope_after after the upgrade, compared with R0, scope_before"
  dr_report R1
  sc_scope_report scope_after
  dr_same "R1 = R0: users, roles and sources, groups, members, approver, no-role, agent owner, local administrators" R0 R1 "${DR_DATA_KEYS[@]}"
  dr_same "R1 = R0: schema_migrations (rows and their hash), model migration, mapping rows, group bindings, node bindings, scope summary" R0 R1 \
    migrations model_migration role_maps group_maps group_roles binding_nodes user_roles.scope user_roles.by_source local_admins.sql
  sc_scope_same "scope_after = scope_before: every assignment with its node scope, the node rows, and both role-binding reads of the API" scope_before scope_after
  it_same "no new schema_migrations row: the count is the same" "$(dr_get R0 migrations | cut -d' ' -f1)" "$(dr_get R1 migrations | cut -d' ' -f1)"
  it_check "scope_after: the node-scoped rows are still there (user_roles.nodes >= 1)" test "$(sed -n 's/^user_roles.nodes=//p' "$IT_WORK/scope_after.scope")" -ge 1
  it_same "R1: perm references intact" "ok" "$(dr_get R1 perm.authz.refs)"
  dr_ev "migrations R0=$(dr_get R0 migrations) R1=$(dr_get R1 migrations)"
  dr_end
}

# ---- step 5: a new backup ----

sc_backup() {
  dr_begin 5 "backup on $DR_NEW"
  touch "$IT_WORK/mark"
  sleep 1
  dr_cx backup backup --yes
  it_same "backup exits 0" 0 "$LV_RC"
  DR_BACKUP5=$(find "$LV_ROOT/backups" -maxdepth 1 -name 'custodexa-backup-*.tar' -newer "$IT_WORK/mark" | head -n1)
  dr_backup_facts backup5 "$DR_BACKUP5"
  sc_snapshot_ok backup5
  it_same "its snapshot is data of $DR_NEW" "$DR_NEW" "$(jq -r '."product.version"' "$IT_WORK/backup5.x/backup-manifest.json")"
  it_same "its snapshot's authz.digest is the one the backend reports now" "$(dr_get R1 perm.authz.digest)" \
    "$(sed -n 's/^authz\.digest=//p' "$IT_WORK/backup5.x/snapshot.txt")"
  it_check "the dump holds the node scope table" grep -qx 'role_binding_nodes' "$IT_WORK/backup5.x/tables"
  dr_end
}

# ---- step 6: stop and start ----

sc_restart() {
  dr_begin 6 "stop and start: the same database, the migrations are looked at again"
  dr_cx stop stop --yes
  it_same "stop exits 0" 0 "$LV_RC"
  dr_cx start start
  it_same "start exits 0" 0 "$LV_RC"
  lv_wait_version "$DR_NEW"
  dr_report R2
  sc_scope_report scope_restart
  dr_same "R2 = R1: users, roles and sources, groups, members, approver, no-role, agent owner, local administrators" R1 R2 "${DR_DATA_KEYS[@]}"
  dr_same "R2 = R1: schema_migrations (rows and their hash), mapping rows, group bindings, node bindings, scope summary, references" R1 R2 \
    migrations model_migration role_maps group_maps group_roles binding_nodes user_roles.scope user_roles.by_source local_admins.sql perm.authz.refs
  sc_scope_same "scope_restart = scope_after: every assignment with its node scope, the node rows, and both role-binding reads of the API" scope_after scope_restart
  it_same "R2 = R0: schema_migrations (rows and their hash)" "$(dr_get R0 migrations)" "$(dr_get R2 migrations)"
  sc_scope_same "scope_restart = scope_before: the assignments are those of before the upgrade" scope_before scope_restart
  sc_log_check restart
  dr_end
}

sc_round() {
  DR_FORM=$1
  sc_install
  sc_fixtures
  sc_upgrade
  sc_after_upgrade
  sc_backup
  sc_restart
  dr_begin 7 "end of the round"
  dr_ev "state current=$(lv_st current.version) previous=$(lv_st previous.version) last_upgrade=$(lv_st last_upgrade.result)"
  dr_ev "worktree status before/after the builder: $(cmp -s /it-run/worktree-status.before /it-run/worktree-status.after && echo same || echo differ)"
  dr_end
}

scenario_builtin() { sc_round builtin; }
scenario_external() { sc_round external; }
