# shellcheck shell=bash
# about: the external database form and the external database with external ingress form each go through install (older release), backup, status, upgrade to the package's release (its backup is one portable file), status and backup again; the PostgreSQL clients are recorded tool images and no database service runs
# needs: package upgrade
# images: pg17

readonly OE_PORT=15417

# oe_form <label> <COMPOSE_FILE> <overlays> <database>
oe_form() {
  local label=$1 root=/opt/custodexa from to id
  from=$(jq -r .version /it-run/pkg-from/MANIFEST.json)
  to=$(jq -r .version /it-run/pkg/MANIFEST.json)
  it_step "$label: install $from, external database PostgreSQL 17 at $(ex_addr):$OE_PORT/$4"
  ex_db_create pg17 "$4"
  EX_CF=$2 ex_install "$root" from "$OE_PORT" "DB_NAME=$4"
  it_same "install recorded as succeeded" succeeded "$(ex_st "$root" install.result)"
  it_same "the overlays" "$3" "$(ex_st "$root" current.overlays)"
  id=$(ex_st "$root" current.tool_image_ids)
  it_say "   tool images: $id"
  it_check "the PostgreSQL 16, 17 and 18 clients are recorded tool images" \
    bash -c '[[ " $1 " == *" pgclient16=sha256:"* && " $1 " == *" pgclient17=sha256:"* && " $1 " == *" pgclient18=sha256:"* ]]' _ "$id"
  it_check "no database service is recorded or runs" \
    bash -c '! grep -q " postgres=" <<<" $1" && ! docker container inspect custodexa-postgres >/dev/null 2>&1' _ "$(ex_st "$root" current.image_ids)"
  it_step "$label: backup"
  ex_backup "$root"
  it_same "the export ran with pgclient17" pgclient17 "$(ex_mf tool.dump_image)"
  it_same "state.json points at it" "backups/${EX_FILE##*/}" "$(ex_st "$root" last_backup.file)"
  it_step "$label: status"
  ex_status "$root" "$from"
  it_check "status shows the backup file" grep -qF "${EX_FILE##*/}" <<<"$EX_STATUS"
  it_step "$label: upgrade $from -> $to (offline bundle)"
  ex_upgrade "$root" offline
  it_same "the upgrade's backup is of the external database" "external pgclient17" "$(ex_mf db.location) $(ex_mf tool.dump_image)"
  it_same "the overlays are kept" "$3" "$(ex_st "$root" current.overlays)"
  it_step "$label: status, backup after the upgrade"
  ex_status "$root" "$to"
  ex_backup "$root"
  it_same "the backup says the version" "$to" "$(ex_mf product.version)"
  ex_teardown "$root"
}

scenario() {
  ex_pg_start pg17 17 "$OE_PORT"
  oe_form "external database" current/compose.yml:current/compose.external-database.yml external-database custodexa
  oe_form "external database + external ingress" \
    current/compose.yml:current/compose.external-ingress.yml:current/compose.external-database.yml \
    "external-ingress external-database" custodexa_ingress
}
