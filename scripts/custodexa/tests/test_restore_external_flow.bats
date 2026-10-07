#!/usr/bin/env bats
# A restore of an external database deployment from the file to the end on this host: before the
# stop this host's own backend is only listed; once the restore stopped the services itself, the
# safety backup takes the database through the external export, the last look for connections comes
# before anything is renamed, and one transaction empties and fills the database. A connection that
# is still there after the stop holds the restore at step 2 with nothing overwritten.
load helper
load install_host
load backup_host
load upgrade_host
load restore_host
load restore_ext_flow_host
setup() {
  rs_ext_flow_host
  # This host's backend is connected until the restore stops it.
  printf '%s\n' '172.18.0.5 custodexa-backend' >"$DB/activity"
  : >"$DB/activity.after-stop"
}
digest_now() { cat "$DB/ext.digest" 2>/dev/null || echo before; }
# clients_kept: the deployment still records the three clients it has (a later backup, upgrade or
# restore finds them by these IDs).
clients_kept() {
  [ "$(jq -r '."current.tool_image_ids" // ""' "$ROOT/state.json")" = \
    "pgclient16=${BK_PGC_ID[16]} pgclient17=${BK_PGC_ID[17]} pgclient18=${BK_PGC_ID[18]}" ] ||
    { jq -r '."current.tool_image_ids" // "(none)"' "$ROOT/state.json"; return 1; }
}

@test "restore external flow: same host, the restore stops the services itself and completes" {
  rs_ext_flow_run
  [ "$status" = 0 ] && [ "$(rs_ext_flow_result)" = succeeded ] || { echo "$status $output"; return 1; }
  # Listed before the stop, not refused; after it: the safety backup's export, then the last look
  # for connections, then the one transaction.
  [ "$(grep -E '^(stop|pg_dump|psql activity|psql import)$' "$DB/events" | uniq | sed "/^psql import$/q" | paste -sd ' ')" = \
    'psql activity stop psql activity pg_dump psql activity stop psql activity psql import' ] || { grep -E "^(stop|pg_dump|psql activity|psql import)$" "$DB/events" | uniq | paste -sd " "; return 1; }
  [ "$(digest_now)" = imported ] || return 1
  [ "$(jq -r '."last_restore.safety"' "$ROOT/state.json")" = script ] || return 1
  # The safety backup's database part is the external export (the client container, not postgres).
  grep -- '--entrypoint pg_dump' "$FAKE_DOCKER_LOG" | grep -q -- "--name custodexa-backup-tool-" || { cat "$FAKE_DOCKER_LOG"; return 1; }
  ! grep -q 'exec -T postgres' "$FAKE_DOCKER_LOG" || { grep 'exec -T postgres' "$FAKE_DOCKER_LOG"; return 1; }
  [[ $output == *'Restore done'* ]] || { echo "$output"; return 1; }
  clients_kept
}

@test "restore external flow: same host, a connection left after the stop holds it at step 2 and --revert starts the services" {
  printf '%s\n' '10.0.0.45 psql' >"$DB/activity.after-stop"
  rs_ext_flow_run
  [ "$status" = 1 ] || { echo "$status $output"; return 1; }
  [[ $output == *' 2/10  Stop the services (the external database is not affected):'* ]] || { echo "$output"; return 1; }
  [[ $output == *'1 other connection'*'10.0.0.45'*'psql'* ]] || { echo "$output"; return 1; }
  [[ $output == *'The restore stopped at step 2. Nothing has been overwritten'* ]] || { echo "$output"; return 1; }
  [[ $output == *'restore --resume'*'restore --revert'* ]] || { echo "$output"; return 1; }
  # One stop screen only: the general failure screen does not follow it.
  [[ $output != *'The restore stopped at step 2;'* ]] || { echo "$output"; return 1; }
  # Nothing overwritten: no safety export, no import, the target unchanged, nothing renamed.
  ! grep -qx 'pg_dump' "$DB/events" || return 1
  ! grep -qx 'psql import' "$DB/events" || return 1
  [ "$(digest_now)" = before ] || return 1
  ! compgen -G "$ROOT/data/*.before-restore-*" >/dev/null || return 1
  [ "$(cat "$DB/ctr/backend")" = stopped ] || return 1
  run bash "$ROOT/custodexa.sh" restore --revert --yes --lang en </dev/null
  [ "$status" = 0 ] || { echo "$status $output"; return 1; }
  [ "$(cat "$DB/ctr/backend")" = running ] || { echo "$output"; return 1; }
  [ "$(digest_now)" = before ] || return 1
  [ "$(rs_ext_flow_result)" = reverted ] || { jq . "$ROOT/state.json"; return 1; }
}

@test "restore external flow: same host, after a rolled-back import --revert puts the safety backup back through the external client" {
  echo 3 >"$DB/import.rc"
  rs_ext_flow_run
  [ "$status" = 1 ] && [ "$(digest_now)" = before ] || { echo "$status $output"; return 1; }
  rm -f "$DB/import.rc"
  : >"$DB/events"
  run bash "$ROOT/custodexa.sh" restore --revert --yes --lang en </dev/null
  [ "$status" = 0 ] && [ "$(rs_ext_flow_result)" = reverted ] || { echo "$status $output"; jq . "$ROOT/state.json"; return 1; }
  # The safety backup's database went in through the external client's one transaction.
  grep -qx 'psql import' "$DB/events" || { cat "$DB/events"; return 1; }
  [ "$(cat "$DB/ctr/backend")" = running ] || return 1
  # An external deployment has no database folder here: none is listed, renamed or made.
  [[ $output != *'postgres.partial-restore'* ]] || { echo "$output"; return 1; }
  ! compgen -G "$ROOT/data/postgres.*-restore-*" >/dev/null || { ls "$ROOT/data"; return 1; }
  clients_kept
}

# A run that carries on after the database check (here: not ready in time, then --resume) reads
# the restored database again at the end; it chooses the external client itself.
@test "restore external flow: same host, carrying on after the database check finishes through the external client" {
  echo 1 >"$DB/health.rc"
  rs_ext_flow_run
  [ "$status" = 1 ] && [ "$(rs_ext_flow_result)" = in_progress ] || { echo "$status $output"; return 1; }
  [ "$(digest_now)" = imported ] || return 1
  rm -f "$DB/health.rc"
  rs_ext_flow_resume
  [ "$status" = 0 ] && [ "$(rs_ext_flow_result)" = succeeded ] || { echo "$status $output"; jq . "$ROOT/state.json"; return 1; }
  [[ $output != *'no database client for an external database chosen'* ]] || { echo "$output"; return 1; }
  [[ $output == *'Restore done'* ]] || { echo "$output"; return 1; }
  clients_kept
}

# The external database behind an external ingress too: openssl is a tool image of that form
# (backup encryption), loaded from an offline bundle on the containerd store, so this host knows
# it only by the deployment's record. Once the restore placed its files, the record still names
# openssl as well as the three clients (a later encrypted backup, upgrade or restore finds it).
ingress_too() {
  bk_state_set current.overlays "external-ingress external-database"
  bk_state_set current.image_ids "guacd=$RS_X_SVC backend=$RS_X_SVC frontend=$RS_X_SVC"
  bk_state_set current.tool_image_ids "openssl=$RS_X_OSSL $(jq -r '."current.tool_image_ids"' "$ROOT/state.json")"
  printf '%s\n' "$RS_X_OSSL" >>"$DB/images"
  rm -rf "$ROOT/tls"
  touch "$ROOT/current/compose.external-ingress.yml"
  bk_env_set COMPOSE_FILE current/compose.yml:current/compose.external-ingress.yml:current/compose.external-database.yml
}
@test "restore external flow: behind an external ingress too, the restore keeps openssl and the three clients on record" {
  # This form's host instead of the one setup laid out.
  rm -rf "$BATS_TEST_TMPDIR/source"
  RS_X_OSSL=sha256:7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e
  RS_X_BEFORE=ingress_too rs_ext_flow_host
  printf '%s\n' '172.18.0.5 custodexa-backend' >"$DB/activity"
  : >"$DB/activity.after-stop"
  # The host has openssl under the bundle's ID only, not under the release's index digest.
  grep -vxF "$BK_OPENSSL_ID" "$DB/images" >"$BATS_TEST_TMPDIR/images" || true
  cp "$BATS_TEST_TMPDIR/images" "$DB/images"
  [ "$(/usr/bin/tar -xOf "$RS_X_FILE" backup-manifest.json | jq -r '."deploy.overlays"')" = "external-ingress external-database" ] || return 1
  rs_ext_flow_run
  [ "$status" = 0 ] && [ "$(rs_ext_flow_result)" = succeeded ] || { echo "$status $output"; return 1; }
  [ "$(jq -r '."current.tool_image_ids" // ""' "$ROOT/state.json")" = \
    "openssl=$RS_X_OSSL pgclient16=${BK_PGC_ID[16]} pgclient17=${BK_PGC_ID[17]} pgclient18=${BK_PGC_ID[18]}" ] ||
    { jq -r '."current.tool_image_ids" // "(none)"' "$ROOT/state.json"; return 1; }
}
