#!/usr/bin/env bats
# Threat (A): a portable backup that is not what it claims. `backup` makes one file and its checksum
# file; whoever restores it on another host has only what the file says about itself. A member
# missing or extra, a manifest that disagrees with snapshot.txt or the release manifests, a master
# key mode read differently from the backend (and its key carried out where it must not be), a
# secret copied into metadata, or a database call that bypasses the one client would each make the
# file lie to the restore. Each must show here as a failed assertion.

load helper
load install_host
load backup_host
load upgrade_host

setup() {
  backup_host ui
  backup_strict
  fake sleep ':'
  clock
  printf '%s\n' 18683107737 >"$DB/size"
}

BK_NAME=custodexa-backup-1.13.0-20260930-101502.tar

# extract_all: every member of BK_FILE into $BATS_TEST_TMPDIR/x (X).
extract_all() {
  X=$BATS_TEST_TMPDIR/x
  rm -rf "$X"
  mkdir -p "$X"
  /usr/bin/tar -xf "$BK_FILE" -C "$X"
}

# no_stop: no service was stopped and nothing was made under backups/.
no_stop() {
  if grep -q '^stop' "$DB/events"; then echo "services were stopped"; return 1; fi
  [ ! -e "$ROOT/backups" ] || { ls -lA "$ROOT/backups"; return 1; }
}

# ---------- the file ----------

@test "portable: a finished backup is one file and its .sha256, both 0600, the members exactly the fixed list" {
  backup_run en --yes
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [ "$(ls -A "$ROOT/backups")" = "$(printf '%s\n' "$BK_NAME" "$BK_NAME.sha256")" ] || { ls -lA "$ROOT/backups"; return 1; }
  BK_FILE=$ROOT/backups/$BK_NAME
  # GNU tar format (members over 8 GiB fit): the header magic of the first member.
  dd if="$BK_FILE" bs=1 skip=257 count=8 status=none | cmp - <(printf 'ustar  \0') || return 1
  [ "$(stat -c %a "$ROOT/backups")" = 700 ] || return 1
  [ "$(stat -c %a "$BK_FILE")" = 600 ] && [ "$(stat -c %a "$BK_FILE.sha256")" = 600 ] || return 1
  [ "$(cat "$BK_FILE.sha256")" = "$(cd "$ROOT/backups" && /usr/bin/sha256sum "$BK_NAME")" ] || return 1
  (cd "$ROOT/backups" && /usr/bin/sha256sum -c --quiet "$BK_NAME.sha256") || return 1
  /usr/bin/tar -tvf "$BK_FILE" >"$BATS_TEST_TMPDIR/list" || return 1
  # Plain files only, kept private in the headers too, at the top, each once, in the fixed order.
  if grep -v '^-rw------- ' "$BATS_TEST_TMPDIR/list"; then echo "not a private plain file"; return 1; fi
  diff <(awk '{print $NF}' "$BATS_TEST_TMPDIR/list") - <<'EOF' || return 1
backup-manifest.json
release-MANIFEST.json
tool-MANIFEST.json
snapshot.txt
db.dump
audit.tar.gz
env.bak
tls.tar.gz
SHA256SUMS
EOF
  extract_all
  (cd "$X" && /usr/bin/sha256sum -c --quiet SHA256SUMS) || return 1
  [ "$(wc -l <"$X/SHA256SUMS")" -eq 8 ] && ! grep -q 'SHA256SUMS$\|/' "$X/SHA256SUMS"
}

@test "portable: the exports folder is in no member, the inner archives included" {
  backup_run en --yes
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  bk_one || return 1
  extract_all
  mkdir -p "$X/inner"
  for m in audit tls; do
    /usr/bin/tar -xzf "$X/$m.tar.gz" -C "$X/inner" || return 1
  done
  [ -f "$X/inner/audit/fallback.log" ] && [ -f "$X/inner/tls/server.crt" ] || return 1
  if find "$X" | grep -q exports; then echo "exports was backed up"; return 1; fi
  if grep -rqF 'plaintext evidence' "$X"; then echo "export plaintext in the backup"; return 1; fi
}

# ---------- tls/ and the proxy template ----------

# members_of: the member names of BK_FILE, one per line, in the stored order.
members_of() { /usr/bin/tar -tf "$BK_FILE"; }

@test "portable: tls/ goes in when the deployment has it, and a deployment without one (own ingress) is backed up without it" {
  # With tls/: the archive is a member, read back, and the manifest says it is there.
  backup_run en --yes
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  bk_one || return 1
  members_of | grep -qx tls.tar.gz || { members_of; return 1; }
  [ "$(bk_mf contents.tls)" = true ] || return 1
  grep -qx 'tar -czf tls.tar.gz' "$DB/events" && grep -qx 'tar -tzf tls.tar.gz' "$DB/events" || return 1
  [[ $output == *"certificates tls/"* ]] || { echo "$output"; return 1; }
  # Without tls/ (an external ingress deployment has none): the backup finishes, no tls.tar.gz is
  # made, read back or stored, and the manifest says there was none, so a restore does not take
  # the missing archive for a loss.
  rm -rf "$ROOT/tls" "$ROOT/backups"
  : >"$DB/events"
  backup_run en --yes
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  bk_one || return 1
  diff <(members_of) - <<'EOF' || return 1
backup-manifest.json
release-MANIFEST.json
tool-MANIFEST.json
snapshot.txt
db.dump
audit.tar.gz
env.bak
SHA256SUMS
EOF
  if grep -q 'tls' "$DB/events"; then grep tls "$DB/events"; return 1; fi
  [ "$(bk_mf contents.tls)" = false ] || return 1
  [ "$(bk_mf contents.members)" = "backup-manifest.json release-MANIFEST.json tool-MANIFEST.json snapshot.txt db.dump audit.tar.gz env.bak SHA256SUMS" ] || return 1
  [ "$(bk_mf size.tls_bytes)" = 0 ] || return 1
  extract_all
  (cd "$X" && /usr/bin/sha256sum -c --quiet SHA256SUMS) || return 1
  [ "$(wc -l <"$X/SHA256SUMS")" -eq 7 ] || return 1
  bk_libs || return 1
  cx_pb_manifest_ok "$X/backup-manifest.json" || { echo "bad: $CX_PB_BAD_KEY"; return 1; }
  # The screen names no certificates it did not take.
  [[ $output != *"certificates tls/"* ]] || { echo "$output"; return 1; }
  [[ $output == *"[ OK ] 4/7  Settings and certificates"* ]] || { echo "$output"; return 1; }
  [ "$(jq -r '."last_backup.file"' "$ROOT/state.json")" = "backups/${BK_FILE##*/}" ]
}

@test "portable: TLS_NGINX_TEMPLATE not set: no template member, the manifest says none" {
  backup_run en --yes
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  bk_one || return 1
  if members_of | grep -q nginx; then members_of; return 1; fi
  [ "$(bk_mf contents.nginx_template)" = false ] && [ "$(bk_mf source.tls_nginx_template)" = "" ] || return 1
  [[ $output != *"proxy template"* ]] || { echo "$output"; return 1; }
}

@test "portable: TLS_NGINX_TEMPLATE set: the file it names goes in as it is, 0600, and the manifest keeps the path as .env has it" {
  local t f
  for t in ./custom/proxy.conf.template "$ROOT/elsewhere/my proxy.template"; do
    rm -rf "$ROOT/backups" "$ROOT/custom" "$ROOT/elsewhere"
    : >"$DB/events"
    case $t in /*) f=$t ;; *) f=$ROOT/${t#./} ;; esac
    mkdir -p "${f%/*}"
    printf 'server { listen 443 ssl; # %s\n}\n' "$t" >"$f"
    chmod 0644 "$f"
    bk_dotenv ui
    printf 'TLS_NGINX_TEMPLATE=%s\n' "$t" >>"$ROOT/.env"
    backup_run en --yes
    [ "$status" -eq 0 ] || { echo "$output"; grep -h 'FAIL\|WARN' "$ROOT"/logs/backup-*.log; return 1; }
    bk_one || return 1
    diff <(members_of | tail -n 4) - <<'EOF' || return 1
env.bak
tls.tar.gz
nginx-tls.conf.template
SHA256SUMS
EOF
    cmp <(bk_member nginx-tls.conf.template) "$f" || return 1
    /usr/bin/tar -tvf "$BK_FILE" nginx-tls.conf.template | grep -q '^-rw------- ' || return 1
    [ "$(bk_mf contents.nginx_template)" = true ] || return 1
    [ "$(bk_mf source.tls_nginx_template)" = "$t" ] || { bk_mf source.tls_nginx_template; return 1; }
    extract_all
    grep -q ' nginx-tls.conf.template$' "$X/SHA256SUMS" && (cd "$X" && /usr/bin/sha256sum -c --quiet SHA256SUMS) || return 1
    bk_libs || return 1
    cx_pb_manifest_ok "$X/backup-manifest.json" || { echo "bad: $CX_PB_BAD_KEY"; return 1; }
    [[ "$(screen_of "$output" | tr '\n' ' ' | tr -s ' ')" == *"certificates tls/, proxy template $(screen_of "$t" | tr -s ' ')"* ]] || { echo "$output"; return 1; }
  done
}

@test "portable: TLS_NGINX_TEMPLATE names a file that is missing or not a file: refused before any stop, the path named" {
  printf 'TLS_NGINX_TEMPLATE=./custom/gone.template\n' >>"$ROOT/.env"
  backup_run en --yes
  [ "$status" -eq 3 ] || { echo "$status: $output"; return 1; }
  diff <(screen_of "$output" | sed -n '/^\[FAIL\]/,$p') - <<'EOF' || return 1
[FAIL] TLS_NGINX_TEMPLATE in .env names /opt/custodexa/custom/gone.template,
       but that is not a file that can be read. The backup takes that file
       with it, so nothing is done. Nothing was stopped. Correct the path, or
       clear the line to use the shipped template, then run it again.
EOF
  no_stop || return 1
  # A folder by that name is no template either.
  mkdir -p "$ROOT/custom/gone.template"
  : >"$DB/events"
  backup_run zh-TW --yes
  [ "$status" -eq 3 ] || { echo "$status: $output"; return 1; }
  [[ $output == *".env 的 TLS_NGINX_TEMPLATE 指向 $ROOT/custom/gone.template，"* ]] || { echo "$output"; return 1; }
  no_stop
}

@test "portable: TLS_NGINX_TEMPLATE whose path the manifest cannot hold (a quote, a backslash): refused before any stop, not at the last step" {
  local t
  # The files are there and readable: only the characters of the path can refuse them.
  for t in './custom/a"b.template' './custom/a\b.template'; do
    rm -rf "$ROOT/backups" "$ROOT/custom" "$ROOT/logs"
    : >"$DB/events"
    mkdir -p "$ROOT/custom"
    printf 'server {}\n' >"$ROOT/${t#./}"
    bk_dotenv ui
    printf 'TLS_NGINX_TEMPLATE=%s\n' "$t" >>"$ROOT/.env"
    backup_run en --yes
    [ "$status" -eq 3 ] || { echo "[$t] $status: $output"; return 1; }
    diff <(screen_of "$output" | sed -n '/^\[FAIL\]/,$p') <(cat <<EOF
[FAIL] TLS_NGINX_TEMPLATE in .env is $t,
       and the path has a character the backup file cannot record (a double
       quote, a backslash, a tab, or a letter outside ASCII). The backup
       keeps that path so a restore can put the template back, so nothing
       is done. Nothing was stopped. Put the template under a path without
       such characters, or clear the line to use the shipped template, then
       run it again.
EOF
    ) || return 1
    no_stop || return 1
    grep -q 'END .*result=failed' "$ROOT"/logs/backup-*.log || { cat "$ROOT"/logs/backup-*.log; return 1; }
  done
  rm -rf "$ROOT/logs"
  : >"$DB/events"
  backup_run zh-TW --yes
  [ "$status" -eq 3 ] || { echo "$status: $output"; return 1; }
  [[ $output == *".env 的 TLS_NGINX_TEMPLATE 是 ./custom/a\\b.template，
       路徑含有備份檔記不下的字元"* ]] || { echo "$output"; return 1; }
  no_stop
}

# This case asserted a refusal while the script left an external database to the operator's own
# procedure. That rule is replaced: the database is exported by a PostgreSQL client of the release,
# through the same seven steps (test_portable_backup_external.bats holds the details).
@test "portable: an external database deployment is backed up through the seven steps (one file, db.location=external)" {
  bk_external
  backup_run en --yes
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  bk_one || return 1
  [ "$(bk_mf db.location)" = external ] && [ "$(bk_mf tool.dump_image)" = pgclient17 ] || return 1
  [ "$(grep -c '^stop' "$DB/events")" -eq 1 ] && [ "$(grep -c '^start' "$DB/events")" -eq 1 ] || { cat "$DB/events"; return 1; }
  [[ $output == *"[ OK ] 7/7  "* ]] || { echo "$output"; return 1; }
  ! grep -q 'exec -T postgres' "$FAKE_DOCKER_LOG"
}

@test "portable: a backup of the same second already there: the next second is used, the old files untouched" {
  mkdir -p "$ROOT/backups"
  printf 'an older backup\n' >"$ROOT/backups/$BK_NAME"
  printf 'its checksum\n' >"$ROOT/backups/$BK_NAME.sha256"
  cp -p "$ROOT/backups/$BK_NAME" "$BATS_TEST_TMPDIR/old"
  cp -p "$ROOT/backups/$BK_NAME.sha256" "$BATS_TEST_TMPDIR/old.sha256"
  backup_run en --yes
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [ -f "$ROOT/backups/custodexa-backup-1.13.0-20260930-101503.tar" ] || { ls -lA "$ROOT/backups"; return 1; }
  cmp "$BATS_TEST_TMPDIR/old" "$ROOT/backups/$BK_NAME" && cmp "$BATS_TEST_TMPDIR/old.sha256" "$ROOT/backups/$BK_NAME.sha256" || return 1
  # A temporary folder of that second counts too; with three seconds taken nothing is stopped.
  mkdir "$ROOT/backups/.partial-20260930-101504"
  : >"$DB/events"
  backup_run en --yes
  [ "$status" -eq 1 ] || { echo "$output"; return 1; }
  [[ $output == *"already holds a backup file or a temporary folder for"* ]] || { echo "$output"; return 1; }
  if grep -q '^stop' "$DB/events"; then echo "services were stopped"; return 1; fi
  [ -z "$(ls -A "$ROOT/backups/.partial-20260930-101504")" ]
}

# ---------- the manifest ----------

@test "portable: the manifest reads back with the plain parser and agrees with snapshot.txt and both release manifests" {
  backup_run en --yes
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  bk_one || return 1
  extract_all
  bk_libs || return 1
  local -A m=()
  local -a k=()
  cx_flat_parse "$X/backup-manifest.json" m k || { echo "line $CX_FLAT_BAD"; return 1; }
  cx_pb_manifest_check m || { echo "bad: $CX_PB_BAD_KEY"; return 1; }
  [ "${m[format]}" = 1 ] && [ "${m[kind]}" = custodexa-backup ] && [ "${m[trigger]}" = manual ] || return 1
  [[ ${m[created_at]} =~ ^20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[+-][0-9]{4}$ ]] || return 1
  [ "${m[product.version]}" = "$(jq -r '."current.version"' "$ROOT/state.json")" ] && [ "${m[product.version]}" = 1.13.0 ] || return 1
  [ "${m[product.script_version]}" = 1.13.0 ] || return 1
  # Recomputed here, independently of the script.
  [ "${m[db.migrations_count]}" = "$(grep -c '^migration=' "$X/snapshot.txt")" ] && [ "${m[db.migrations_count]}" = 2 ] || return 1
  [ "${m[db.migrations_sha256]}" = "$(sed -n 's/^migration=//p' "$X/snapshot.txt" | LC_ALL=C sort | /usr/bin/sha256sum | cut -c1-64)" ] || return 1
  [ "${m[kek.fingerprint]}" = "$(sed -n 's/^fp.kek=//p' "$X/snapshot.txt")" ] && [ "${m[kek.fingerprint]}" = 5a5a5a5a5a5a5a5a ] || return 1
  [ "${m[kek.fingerprint_status]}" = ok ] && [ "${m[snapshot.usable]}" = true ] || return 1
  [ "${m[product.manifest_sha256]}" = "$(/usr/bin/sha256sum "$X/release-MANIFEST.json" | cut -c1-64)" ] || return 1
  [ "${m[tool.manifest_sha256]}" = "$(/usr/bin/sha256sum "$X/tool-MANIFEST.json" | cut -c1-64)" ] || return 1
  cmp "$X/release-MANIFEST.json" "$ROOT/current/MANIFEST.json" && cmp "$X/tool-MANIFEST.json" "$ROOT/releases/1.13.0/MANIFEST.json" || return 1
  [ "${m[contents.members]}" = "backup-manifest.json release-MANIFEST.json tool-MANIFEST.json snapshot.txt db.dump audit.tar.gz env.bak tls.tar.gz SHA256SUMS" ] || return 1
  [ "${m[contents.recordings]}" = false ] && [ "${m[contents.state]}" = false ] || return 1
  [ "${m[encryption.enabled]}" = false ] && [ -z "${m[encryption.scheme]}" ] || return 1
  [ "${m[db.location]}" = bundled ] && [ "${m[db.server_version]}" = 16.15 ] && [ "${m[db.server_major]}" = 16 ] || return 1
  [ "${m[db.dump_tool_version]}" = 16.15 ] && [ "${m[db.name]}" = custodexa ] && [ "${m[db.user]}" = postgres ] || return 1
  [ "${m[db.encoding]}" = UTF8 ] && [ "${m[db.collate]}" = en_US.utf8 ] && [ "${m[db.ctype]}" = en_US.utf8 ] || return 1
  [ "${m[deploy.overlays]}" = "" ] && [ "${m[deploy.arch]}" = "$(uname -m)" ] && [ "${m[deploy.tls_mode]}" = selfsigned ] || return 1
  [ "${m[size.db_bytes]}" = 18683107737 ] && [ "${m[size.audit_bytes]}" = "$(/usr/bin/du -sb "$ROOT/data/audit" | cut -f1)" ] || return 1
  [ "${m[size.recordings_bytes]}" = "$(/usr/bin/du -sb "$ROOT/data/recordings" | cut -f1)" ] || return 1
  [ "${m[source.hostname]}" = ops-host.example.internal ] && [ "${m[source.root]}" = "$ROOT" ] || return 1
  [ "${m[source.data_path]}" = "$ROOT/data" ] && [ "${m[source.public_base_url]}" = https://10.0.0.12 ] || return 1
  [ "${m[source.tls_domain]}" = custodexa.example.internal ] && [ "${m[source.tls_ip_san]}" = 10.0.0.12 ]
}

@test "portable: the dump tool is the release's postgres, not the script's; the external keys are there, empty or false" {
  release_next
  run bash "$BK_SCRIPT" backup --lang en --yes </dev/null
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  bk_one || return 1
  [ "${BK_FILE##*/}" = "$BK_NAME" ] || return 1
  extract_all
  cmp "$X/tool-MANIFEST.json" "$ROOT/releases/1.13.2/MANIFEST.json" && cmp "$X/release-MANIFEST.json" "$ROOT/current/MANIFEST.json" || return 1
  [ "$(bk_mf product.version)" = 1.13.0 ] && [ "$(bk_mf product.script_version)" = 1.13.2 ] || return 1
  [ "$(bk_mf tool.dump_image)" = postgres ] && [ "$(bk_mf tool.dump_manifest)" = release ] || return 1
  [ "$(bk_mf tool.dump_image_digest)" = "$(jq -r .images.postgres.index_digest "$X/release-MANIFEST.json")" ] || return 1
  [ "$(bk_mf tool.dump_image_digest)" = "$BK_PG_DIGEST" ] || return 1
  [ "$(jq -r .images.postgres.index_digest "$X/tool-MANIFEST.json")" = "$BK_PG_DIGEST_OTHER" ] || return 1
  for k in db.external_host db.external_port db.sslmode db.tls_trust db.tls_verify db.extra_grant_roles_hex; do
    [ "$(bk_mf "$k")" = "" ] || { echo "$k: $(bk_mf "$k")"; return 1; }
  done
  [ "$(bk_mf db.tls_client_cert)" = false ] && [ "$(bk_mf contents.db_ca)" = false ] || return 1
  # The same keys as the reference manifest kept for the external-database change.
  diff <(bk_member backup-manifest.json | jq -r 'keys[]') <(jq -r 'keys[]' "$TESTS_DIR/fixtures/manifest-bundled-reference.json")
}

@test "portable: state.json and current/MANIFEST.json disagree on the version: refused before any stop, both shown" {
  sed -i 's/"version": "1.13.0"/"version": "1.13.1"/' "$ROOT/releases/1.13.0/MANIFEST.json"
  backup_run en --yes
  [ "$status" -eq 3 ] || { echo "$output"; return 1; }
  diff <(screen_of "$output" | sed -n '/^\[FAIL\]/,$p') - <<'EOF' || return 1
[FAIL] state.json says 1.13.0 is installed, but current/MANIFEST.json is
       1.13.1, so the version of this backup cannot be told. Nothing was
       stopped. Check with:
  sudo /opt/custodexa/custodexa.sh status --lang en
EOF
  no_stop
}

@test "manifest check: the plain parser leaves the state as loaded; a missing key, a bad boolean, a value off its list are refused" {
  bk_libs || return 1
  cx_state_load "$ROOT/state.json"
  local before
  before=$(declare -p CX_STATE CX_STATE_KEYS)
  local -A m=() s=()
  local -a k=() sk=()
  cx_flat_parse "$ROOT/state.json" s sk || return 1
  [ "${s[current.version]}" = 1.13.0 ] || return 1
  cx_flat_parse "$TESTS_DIR/fixtures/manifest-bundled-reference.json" m k || return 1
  [ "$(declare -p CX_STATE CX_STATE_KEYS)" = "$before" ] || { echo "CX_STATE changed"; return 1; }
  cx_pb_manifest_check m || { echo "reference refused: $CX_PB_BAD_KEY"; return 1; }
  # check_with <key> <value or -unset>: the reference with one change is refused, naming the key.
  check_with() {
    local -A c=()
    local key
    for key in "${!m[@]}"; do c[$key]=${m[$key]}; done
    if [ "$2" = -unset ]; then unset 'c[$1]'; else c[$1]=$2; fi
    if cx_pb_manifest_check c; then echo "accepted $1=$2"; return 1; fi
    [ "$CX_PB_BAD_KEY" = "$1" ] || { echo "named $CX_PB_BAD_KEY for $1"; return 1; }
  }
  check_with kek.provider -unset || return 1
  check_with source.hostname "" || return 1
  check_with snapshot.usable yes || return 1
  check_with contents.recordings TRUE || return 1
  check_with kek.provider vault || return 1
  check_with db.location elsewhere || return 1
  check_with format 2 || return 1
  check_with db.migrations_sha256 abc || return 1
  check_with db.external_host db.example.internal || return 1
  check_with contents.state true || return 1
  check_with contents.tls false || return 1
  check_with contents.nginx_template true || return 1
  check_with source.tls_nginx_template ./custom/proxy.conf.template || return 1
  # A key the reader does not know is ignored.
  m[future.key]=anything
  cx_pb_manifest_check m
}

# ---------- the master key ----------

# kek_backup <KEK_PROVIDER value or -> <ENCRYPTION_KEY value or ->: the .env with these lines (a
# kms one names its provider), then backup --yes from a clean backups/ and log folder.
kek_backup() {
  local -a lines=()
  rm -rf "$ROOT/backups" "$ROOT/logs"
  : >"$DB/events"
  [ "$1" = - ] || lines+=("KEK_PROVIDER=$1")
  [ "$2" = - ] || lines+=("ENCRYPTION_KEY=$2")
  [[ $1 != *kms* ]] || lines+=(KEK_KMS_PROVIDER=aws)
  bk_dotenv_raw "${lines[@]}"
  backup_run en --yes
}

# kek_made <provider> <declared> <material in>: the backup was made and says so.
kek_made() {
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  bk_one || return 1
  [ "$(bk_mf kek.provider)/$(bk_mf kek.provider_declared)/$(bk_mf kek.material_included)" = "$1/$2/$3" ] \
    || { echo "manifest: $(bk_mf kek.provider)/$(bk_mf kek.provider_declared)/$(bk_mf kek.material_included), want $1/$2/$3"; return 1; }
  if [ "$3" = true ]; then
    [[ $output == *"settings file .env (includes the"$'\n'"  master key)"* ]] || { echo "$output"; return 1; }
  else
    [[ $output != *"includes the"* ]] || { echo "$output"; return 1; }
  fi
}

# kek_refused <reason text>: refused before any stop, the key's value nowhere, no copy of .env.
kek_refused() {
  [ "$status" -eq 3 ] || { echo "$status: $output"; return 1; }
  [[ $output == *"$1"* ]] || { echo "$output"; return 1; }
  no_stop || return 1
  [[ $output != *"$BK_KEK"* ]] || { echo "the key on the screen"; return 1; }
  if grep -rqF -- "$BK_KEK" "$ROOT/logs"; then echo "the key in the log"; return 1; fi
}

@test "master key: the eight rows of the backend's rules, with spaces trimmed as the backend trims them" {
  kek_backup - "$BK_KEK" && kek_made env false true || return 1
  kek_backup - - && kek_refused '[FAIL] .env sets neither KEK_PROVIDER nor ENCRYPTION_KEY, so the master key' || return 1
  kek_backup env "$BK_KEK" && kek_made env true true || return 1
  kek_backup env - && kek_refused '[FAIL] KEK_PROVIDER in .env is env, but ENCRYPTION_KEY is empty.' || return 1
  kek_backup ui "$BK_KEK" && kek_refused '[FAIL] KEK_PROVIDER in .env is ui, but ENCRYPTION_KEY has a value.' || return 1
  kek_backup kms "$BK_KEK" && kek_refused 'KEK_PROVIDER in .env is kms, but ENCRYPTION_KEY has a value.' || return 1
  kek_backup hsm "$BK_KEK" && kek_refused 'KEK_PROVIDER in .env is hsm, but ENCRYPTION_KEY has a value.' || return 1
  for p in ui kms hsm; do
    kek_backup "$p" - && kek_made "$p" true false || return 1
  done
  kek_backup UI - && kek_refused 'KEK_PROVIDER in .env has a value that is not recognized' || return 1
  kek_backup vault "$BK_KEK" && kek_refused 'KEK_PROVIDER in .env has a value that is not recognized' || return 1
  # Trimmed: blanks are no provider, a quoted " ui " is ui, a key of blanks is no key.
  kek_backup '   ' "$BK_KEK" && kek_made env false true || return 1
  kek_backup '" ui "' '"   "' && kek_made ui true false
}

@test "master key: no KEK_PROVIDER and a key in .env is the env mode, not declared, carried in, said on the screen" {
  bk_dotenv implicit
  backup_run en --yes
  kek_made env false true || return 1
  [[ $output == *"  Version 1.13.0; bundled database; master key: in the settings file"* ]]
}

@test "master key: KEK_PROVIDER=ui with a key is refused before any stop; both key names, no value, no copy" {
  bk_dotenv_raw KEK_PROVIDER=ui "ENCRYPTION_KEY=$BK_KEK"
  backup_run en --yes
  kek_refused 'KEK_PROVIDER in .env is ui, but ENCRYPTION_KEY has a value' || return 1
  diff <(printf '%s\n' "$output" | sed -n '/^\[FAIL\]/,$p') - <<'EOF'
[FAIL] KEK_PROVIDER in .env is ui, but ENCRYPTION_KEY has a value. That is a
       contradictory setting the backend also refuses at its next start, and
       the backup would carry it out as a master key, so nothing is done.
       Nothing was stopped. Decide which mode you use and clear the other.
EOF
}

@test "master key: KEK_PROVIDER=env keeps .env byte for byte in env.bak, says the master key is in and names it" {
  bk_dotenv env
  backup_run en --yes
  kek_made env true true || return 1
  bk_member env.bak | cmp - "$ROOT/.env" || return 1
  [[ $output == *"  The master key is in the .env inside the backup file (fingerprint
  5a5a5a5a5a5a5a5a) and comes back with a restore."* ]] || { echo "$output"; return 1; }
  [[ $output == *"[WARN] This file is not encrypted and holds the master key and other"* ]]
}

@test "master key: the fingerprint read but another one missing keeps it as ok; the other warning only" {
  printf '1\n' >"$DB/checkpoint.rc"
  backup_run en --yes
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  bk_one || return 1
  [ "$(bk_mf kek.fingerprint)" = 5a5a5a5a5a5a5a5a ] && [ "$(bk_mf kek.fingerprint_status)" = ok ] || return 1
  [ "$(bk_mf snapshot.usable)" = false ] || return 1
  [[ $output == *"  [WARN] Not all four key fingerprints could be read (the master key's
         was), so after a restore the other keys have to be compared by"* ]] || { echo "$output"; return 1; }
  [[ $output != *"The master key fingerprint could not be read"* ]] || return 1
  # The other way round: no key ID, or more than one, and the master key warning instead.
  for case in none not-unique; do
    rm -rf "$ROOT/backups" "$DB/checkpoint.rc"
    if [ "$case" = none ]; then rm -f "$DB/kek"; else printf '%s\n' 5a5a5a5a5a5a5a5a 6b6b6b6b6b6b6b6b >"$DB/kek"; fi
    backup_run en --yes
    [ "$status" -eq 0 ] || { echo "$output"; return 1; }
    bk_one || return 1
    want=missing
    [ "$case" = none ] || want=not-unique
    [ "$(bk_mf kek.fingerprint_status)" = "$want" ] && [ "$(bk_mf kek.fingerprint)" = "" ] || return 1
    [[ $output == *"[WARN] The master key fingerprint could not be read, so a restore cannot"* ]] || return 1
    [[ $output != *"Not all four key fingerprints"* ]] || return 1
  done
}

@test "master key: no fingerprint read: the master key lines show none (no \"?\"), the warning says why (env, ui, kms)" {
  local mode
  for mode in env ui kms; do
    rm -rf "$ROOT/backups" "$ROOT/logs"
    rm -f "$DB/kek"
    bk_dotenv "$mode"
    backup_run en --yes
    [ "$status" -eq 0 ] || { echo "$output"; return 1; }
    [[ $output != *"fingerprint ?"* && $output != *"(fingerprint"* && $output != *"Key ID:"* ]] || { echo "[$mode] $output"; return 1; }
    [[ $output == *"[WARN] The master key fingerprint could not be read, so a restore cannot"* ]] || { echo "[$mode] $output"; return 1; }
    case $mode in
      env) [[ $output == *"  The master key is in the .env inside the backup file and comes back
  with a restore."* ]] ;;
      ui) [[ $output == *"  The master key is not in the backup file.
  After a restore, whoever holds the unseal material enters it on the"* ]] ;;
      kms) [[ $output == *"  The master key is held by the key custody service (aws) and is not in
  the backup file.
  After a restore, provide the custody credentials on the unseal page"* ]] ;;
    esac || { echo "[$mode] $output"; return 1; }
  done
}

@test "master key: no .env secret on the screen, in the log, state.json, the manifest or snapshot.txt (env, ui, kms)" {
  for mode in env ui kms; do
    rm -rf "$ROOT/backups" "$ROOT/logs"
    bk_dotenv "$mode"
    backup_run en --yes
    [ "$status" -eq 0 ] || { echo "$output"; return 1; }
    bk_one || return 1
    extract_all
    for v in "$BK_JWT" "$BK_KEK" "$BK_DBPW"; do
      [[ $output != *"$v"* ]] || { echo "$mode: secret on screen"; return 1; }
      if grep -rqF -- "$v" "$ROOT/logs" "$ROOT/state.json" "$X/backup-manifest.json" "$X/snapshot.txt"; then
        echo "$mode: secret written: ${v:0:4}..."
        return 1
      fi
    done
  done
}

# ---------- the database client ----------

@test "database client: every query, the dump, its listing and the tool version go through it; snapshot.txt keeps its format" {
  backup_run en --yes
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  # Each database call carries the client's mark: none came another way.
  [ -s "$DB/db-calls" ] || return 1
  if grep -v '^\(sql\|dump\|restore-list\|dump-version\) ' "$DB/db-calls"; then echo "a call outside the client"; return 1; fi
  for want in 'sql psql size' 'sql psql count.users' 'sql psql kek' 'sql psql server_version' 'sql psql encoding' \
    'dump pg_dump' 'restore-list pg_restore' 'dump-version pg_dump_version'; do
    grep -qx "$want" "$DB/db-calls" || { echo "missing: $want"; cat "$DB/db-calls"; return 1; }
  done
  # All of them an exec in the postgres service of compose.
  [ "$(grep -c 'compose .*exec -T postgres ' "$FAKE_DOCKER_LOG")" -eq "$(wc -l <"$DB/db-calls")" ] || return 1
  bk_one || return 1
  fp() { printf '%s' "$1" | /usr/bin/sha256sum | cut -c1-16; }
  diff <(bk_member snapshot.txt) - <<EOF
format=1
count.users=5
count.sessions=42
count.audit_logs=1234
migration=20260816_schema_baseline
migration=20260901_add_x
fp.jwt=$(fp "$BK_JWT")
fp.kek=5a5a5a5a5a5a5a5a
fp.export_signing=$(fp AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA)
fp.checkpoint_signing=$(fp BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB)
usable=true
unusable=
EOF
}

@test "database client: the snapshot after an upgrade goes through it too" {
  rm -rf "${BATS_TEST_TMPDIR:?}"/*
  upgraded_host ui
  clock 0 3 0 41 0 4 0 11
  : >"$DB/db-calls"
  full_run en
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  # The reads after the new version started (answered from $UP/after.*) are marked as well.
  grep -qx 'sql psql count.audit_logs after' "$DB/db-calls" || { cat "$DB/db-calls"; return 1; }
  if grep -v '^\(sql\|dump\|restore-list\|dump-version\) ' "$DB/db-calls"; then echo "a call outside the client"; return 1; fi
}

@test "database client: an external database deployment gets a clear error, never an exec in the bundled service" {
  bk_libs || return 1
  CX_OVERLAYS=external-database
  for a in "sql SELECT 1" dump restore-list dump-version; do
    # shellcheck disable=SC2086
    run cx_db $a
    [ "$status" -eq 70 ] || { echo "$a: $status"; return 1; }
    [[ $output == *"no database client for an external database"* ]] || return 1
  done
  run cx_snap_take "$BATS_TEST_TMPDIR/snap" "$BK_JWT"
  [ "$status" -ne 0 ] || return 1
  if grep -q 'postgres' "$FAKE_DOCKER_LOG"; then cat "$FAKE_DOCKER_LOG"; return 1; fi
}

# ---------- the temporary folder ----------

@test "temporary folder: 0700, every member 0600 while the services are stopped; .env as is; both manifests as they are; no exports" {
  release_next
  : >"$DB/pause.start"
  backup_bg "$BATS_TEST_TMPDIR/out"
  wait_for "$DB/paused.start" || { kill -9 "$BK_PID"; cat "$BATS_TEST_TMPDIR/out"; return 1; }
  local p=$ROOT/backups/.partial-20260930-101502 m rc=0
  if [ ! -d "$p" ]; then
    echo "no temporary folder at the pause"
    : >"$DB/go.start"
    wait "$BK_PID" || true
    return 1
  fi
  [ "$(stat -c %a "$p")" = 700 ] || rc=1
  diff <(ls -A "$p") - <<'EOF' || rc=1
audit.tar.gz
db.dump
env.bak
release-MANIFEST.json
snapshot.txt
tls.tar.gz
tool-MANIFEST.json
EOF
  for m in "$p"/*; do
    [ "$(stat -c %a "$m")" = 600 ] || { echo "${m##*/} is $(stat -c %a "$m")"; rc=1; }
  done
  cmp "$ROOT/.env" "$p/env.bak" || rc=1
  cmp "$ROOT/current/MANIFEST.json" "$p/release-MANIFEST.json" || rc=1
  cmp "$ROOT/releases/1.13.2/MANIFEST.json" "$p/tool-MANIFEST.json" || rc=1
  if /usr/bin/tar -tzf "$p/audit.tar.gz" | grep -q exports; then echo "exports in audit.tar.gz"; rc=1; fi
  : >"$DB/go.start"
  wait "$BK_PID" || { cat "$BATS_TEST_TMPDIR/out"; return 1; }
  [ "$rc" -eq 0 ]
}

# ---------- failures, restart and status ----------

@test "portable: the dump fails after the stop: no file, FAIL names the folder, the command to start the services" {
  printf '1\n' >"$DB/pg_dump.rc"
  backup_run en --yes
  [ "$status" -eq 1 ] || { echo "$output"; return 1; }
  diff <(screen_of "$output" | sed -n '/^\[FAIL\] 2\/7/,$p') - <<'EOF' || return 1
[FAIL] 2/7  Database

[FAIL] The backup did not finish and no backup file was made. What was
       taken so far is in /opt/custodexa/backups/.partial-20260930-101502/;
       it cannot be restored from and holds sensitive plaintext. Delete it
       once you know the cause.
The services may still be stopped. To start them again:
  sudo /opt/custodexa/custodexa.sh start --lang en
  Log file /opt/custodexa/logs/backup-20260930-101502.log
EOF
  if grep -q '^start' "$DB/events"; then echo "started despite the failure"; return 1; fi
  [ -d "$ROOT/backups/.partial-20260930-101502" ] && ! compgen -G "$ROOT/backups/custodexa-backup-*" >/dev/null || return 1
  [ "$(jq -r '."last_backup.result"' "$ROOT/state.json")" = failed ] && [ -z "$(bk_pointer)" ]
}

@test "restart: a kms deployment ready after the start is waiting to be unsealed, never back" {
  bk_dotenv kms
  backup_run en --yes
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [[ $output == *"[ OK ] 5/7  Start the services and wait until ready"* ]] || return 1
  [[ $output == *"  [WARN] The services are started and waiting to be unsealed: open
         https://10.0.0.12/unseal with the local administrator account,
         check the key custody details and provide the credentials."* ]] || { echo "$output"; return 1; }
  [[ $output == *"  The master key is held by the key custody service (aws) and is not in
  the backup file. Key ID:
  5a5a5a5a5a5a5a5a"* ]] || { echo "$output"; return 1; }
  [[ $output != *"The services are back"* ]]
}

@test "restart: a backend not ready in time makes step 5 a warning; the file is made; status and start are given" {
  printf '1\n' >"$DB/health.rc"
  backup_run en --yes
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  bk_one || return 1
  [[ $output == *"[WARN] 5/7  Start the services and wait until ready"* ]] || { echo "$output"; return 1; }
  [ "$(grep -c '^health$' "$DB/events")" -eq 60 ] || return 1
  diff <(screen_of "$output" | sed -n '/The backend was not ready/,/custodexa.sh start/p') - <<'EOF' || return 1
  [WARN] The backend was not ready within 180 seconds, so users may not be
         able to connect yet. The backup goes on. Check the status, and
         start again if needed:
    sudo /opt/custodexa/custodexa.sh status --lang en
    sudo /opt/custodexa/custodexa.sh start --lang en
EOF
  [[ $output != *"The services are back"* && $output != *"waiting to be unsealed"* ]]
}

# restart_case <mode>: a backup of a deployment in that master key mode; the screen in $output.
restart_case() {
  rm -rf "$ROOT/backups" "$ROOT/logs"
  : >"$DB/events"
  bk_state_fresh
  bk_dotenv "$1"
  backup_run en --yes
}

@test "restart: ready at once: env says the services are back; ui and kms are waiting to be unsealed at the unseal page" {
  restart_case env
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [[ $output == *"[ OK ] 5/7  Start the services and wait until ready"* ]] || { echo "$output"; return 1; }
  printf '%s\n' "$output" | grep -qxF '  [ OK ] The services are back.' || { echo "$output"; return 1; }
  [[ $output != *"unseal"* ]] || { echo "$output"; return 1; }
  [ "$(grep -c '^health$' "$DB/events")" -eq 1 ] || return 1
  restart_case ui
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  diff <(screen_of "$output" | sed -n '/waiting to be unsealed/,/unseal$/p') - <<'EOF' || { echo "$output"; return 1; }
  [WARN] The services are started and waiting to be unsealed: enter the
         master key at https://10.0.0.12/unseal
EOF
  [[ $output != *"The services are back"* ]] || return 1
  restart_case kms
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  diff <(screen_of "$output" | sed -n '/waiting to be unsealed/,/credentials\./p') - <<'EOF' || { echo "$output"; return 1; }
  [WARN] The services are started and waiting to be unsealed: open
         https://10.0.0.12/unseal with the local administrator account,
         check the key custody details and provide the credentials.
EOF
  [[ $output != *"The services are back"* ]] || return 1
  # zh-TW, ui: the reviewed line.
  rm -rf "$ROOT/backups" "$ROOT/logs"
  bk_state_fresh
  bk_dotenv ui
  backup_run zh-TW --yes
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  printf '%s\n' "$output" | grep -qxF '  [WARN] 服務已啟動，待解封：請到 https://10.0.0.12/unseal 輸入主金鑰。' || { echo "$output"; return 1; }
  [[ $output != *"服務已恢復"* ]]
}

@test "restart: never ready within a limit made short (CX_READY_TRIES): step 5 WARN, the file made, status and start; never back" {
  printf '1\n' >"$DB/health.rc"
  export CX_READY_TRIES=3
  for m in env ui kms; do
    restart_case "$m"
    [ "$status" -eq 0 ] || { echo "[$m] $output"; return 1; }
    bk_one || return 1
    [ "$(grep -c '^health$' "$DB/events")" -eq 3 ] || { echo "[$m] tries"; cat "$DB/events"; return 1; }
    [[ $output == *"[WARN] 5/7  Start the services and wait until ready"* ]] || { echo "[$m] $output"; return 1; }
    diff <(screen_of "$output" | sed -n '/The backend was not ready/,/custodexa.sh start/p') - <<'EOF' || { echo "[$m] $output"; return 1; }
  [WARN] The backend was not ready within 9 seconds, so users may not be
         able to connect yet. The backup goes on. Check the status, and
         start again if needed:
    sudo /opt/custodexa/custodexa.sh status --lang en
    sudo /opt/custodexa/custodexa.sh start --lang en
EOF
    [[ $output != *"The services are back"* && $output != *"waiting to be unsealed"* ]] || { echo "[$m] $output"; return 1; }
    # The steps after the start went on: the file was checked and built.
    grep -qx 'tar readback' "$DB/events" || return 1
  done
  unset CX_READY_TRIES
}

@test "status: the latest backup shows the file and its size, and says when it is encrypted" {
  backup_run en --yes
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [[ "$(bk_status)" == *"         /opt/custodexa/backups/$BK_NAME    "*" KB"* ]] || { bk_status; return 1; }
  jq '."last_backup.file" = "backups/'"$BK_NAME"'.enc" | ."last_backup.encrypted" = "true" | ."last_backup.size_bytes" = "18683107737"' \
    "$ROOT/state.json" >"$BATS_TEST_TMPDIR/s" && cp "$BATS_TEST_TMPDIR/s" "$ROOT/state.json"
  [[ "$(bk_status)" == *"         /opt/custodexa/backups/$BK_NAME.enc    17.4 GB (encrypted)"* ]] || { bk_status; return 1; }
}
