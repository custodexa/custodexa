# shellcheck shell=bash
# CX_PB_BAD_KEY is read by the callers; the CX_PB_* run values come from lib/portable.sh, which
# sources this file.
# shellcheck disable=SC2034,SC2153
# backup-manifest.json: what a portable backup holds and what it needs, for whoever restores it.
# The shape is state.json's (lib/state.sh: flat, one key per line, a restricted character set) and
# it is read with the same plain parser (cx_flat_parse), never through the state file loader. Every
# key is always written; the ones that may be empty are listed in CX_PB_NULLABLE. No .env secret is
# ever a value here.

readonly CX_PB_FORMAT=1
# The keys, in the order they are written. The reserved keys of an external database are written
# by every backup; a bundled database gives them the fixed values in CX_PB_BUNDLED.
readonly CX_PB_KEYS="format kind trigger created_at product.version product.script_version
  product.manifest_sha256 tool.manifest_sha256 tool.dump_image tool.dump_manifest
  tool.dump_image_digest db.location db.server_version db.server_major db.dump_tool_version
  db.name db.user db.encoding db.collate db.ctype db.migrations_count db.migrations_sha256
  db.external_host db.external_port db.sslmode db.tls_trust db.tls_verify db.tls_client_cert
  db.extra_grant_roles_hex deploy.overlays deploy.arch deploy.tls_mode kek.provider
  kek.provider_declared kek.kms_provider kek.material_included kek.fingerprint
  kek.fingerprint_status snapshot.usable encryption.enabled encryption.scheme contents.recordings
  contents.tls contents.nginx_template contents.state contents.db_ca contents.members
  size.db_bytes size.audit_bytes size.recordings_bytes size.tls_bytes source.hostname source.root
  source.data_path source.tls_domain source.tls_ip_san source.public_base_url
  source.tls_nginx_template"
readonly CX_PB_NULLABLE="deploy.overlays deploy.tls_mode kek.kms_provider kek.fingerprint
  encryption.scheme source.tls_domain source.tls_ip_san source.public_base_url db.external_host
  db.external_port db.sslmode db.tls_trust db.tls_verify db.extra_grant_roles_hex
  source.tls_nginx_template"
readonly CX_PB_BOOLS="kek.provider_declared kek.material_included snapshot.usable
  encryption.enabled contents.recordings contents.tls contents.nginx_template contents.state
  db.tls_client_cert contents.db_ca"
readonly CX_PB_HEX="product.manifest_sha256 tool.manifest_sha256 db.migrations_sha256"
readonly CX_PB_COUNTS="db.server_major db.migrations_count size.db_bytes size.audit_bytes
  size.recordings_bytes size.tls_bytes"
readonly CX_PB_BUNDLED="db.external_host= db.external_port= db.sslmode= db.tls_trust=
  db.tls_verify= db.tls_client_cert=false db.extra_grant_roles_hex= contents.db_ca=false
  tool.dump_manifest=release tool.dump_image=postgres"
# The reserved keys of an external database: a bundled database's file may lack them (they read as
# the fixed values above); an external database's file must have every one.
readonly CX_PB_EXT_KEYS="db.external_host db.external_port db.sslmode db.tls_trust db.tls_verify
  db.tls_client_cert db.extra_grant_roles_hex contents.db_ca"
# The trust anchor and verification pairs the client can be given (lib/dbclient.sh cx_db_tls_read).
readonly CX_PB_TLS_PAIRS="none/none system/full system/ca file/none file/ca file/full"
declare -gA CX_PB_ENUM=(
  [format]="1" [kind]="custodexa-backup" [trigger]="manual upgrade" [tool.dump_manifest]="release tool"
  [db.location]="bundled external" [deploy.arch]="x86_64 aarch64" [deploy.tls_mode]="selfsigned provided"
  [kek.provider]="env ui kms hsm" [kek.kms_provider]="aws gcp vault"
  [kek.fingerprint_status]="ok missing not-unique" [encryption.scheme]="cx-enc-1"
  [db.tls_trust]="none system file" [db.tls_verify]="none ca full")
declare -gA CX_PB_MAP=()
CX_PB_BAD_KEY=""

# cx_pb_in <word> <list>: the word is in the white-space separated list.
cx_pb_in() { [[ " $(printf '%s' "$2" | tr -s '[:space:]' ' ') " == *" $1 "* ]]; }

# cx_pb_kv <key> <value>: one value for the manifest. A value the format cannot hold, one holding
# a .env secret, or one outside the key's list of values is written empty (and noted in the log)
# when the key may be empty; otherwise the manifest cannot be written.
cx_pb_kv() {
  local k=$1 v=$2
  if ! cx_state_valid_value "$v" || cx_has_secret "$v" \
    || { [ -n "$v" ] && [ -n "${CX_PB_ENUM[$k]+x}" ] && ! cx_pb_in "$v" "${CX_PB_ENUM[$k]}"; }; then
    if ! cx_pb_in "$k" "$CX_PB_NULLABLE"; then
      cx_log FAIL "manifest: $k cannot be stored"
      return 1
    fi
    cx_log WARN "manifest: $k left empty (the value cannot be stored)"
    v=""
  fi
  CX_PB_MAP[$k]=$v
}

# cx_pb_fp_status <snapshot.txt>: CX_PB_FP (the KEK fingerprint as the snapshot has it) and
# CX_PB_FP_STATUS: ok, missing (no key ID or the query failed), not-unique.
cx_pb_fp_status() {
  local reasons
  CX_PB_FP=$(cx_snap_get "$1" fp.kek)
  reasons=" $(cx_snap_get "$1" unusable) "
  case $reasons in
    *" kek:not-unique "*) CX_PB_FP_STATUS=not-unique ;;
    *" kek:none "* | *" kek:query "*) CX_PB_FP_STATUS=missing ;;
    *) CX_PB_FP_STATUS=ok; [ -n "$CX_PB_FP" ] || CX_PB_FP_STATUS=missing ;;
  esac
}

# cx_pb_sha <file>: its SHA-256, hex.
cx_pb_sha() { local h; h=$(sha256sum -- "$1") || return 1; printf '%s' "${h%% *}"; }

# cx_pb_manifest_values <folder> <members>: CX_PB_MAP from the members in the folder and the run
# (CX_PB_FP and CX_PB_FP_STATUS come from step 2, cx_pb_fp_status).
cx_pb_manifest_values() {
  local d=$1 members=$2 rel tool host pair tls
  CX_PB_MAP=()
  # The two release manifests as stored: the data's, and the one of the script making the file.
  cx_manifest_load "$d/release-MANIFEST.json" >/dev/null || return 1
  [ "$(cx_mf version)" = "$CX_PB_VERSION" ] || { cx_log FAIL "release-MANIFEST.json is for $(cx_mf version)"; return 1; }
  cx_db_external || cx_pb_kv tool.dump_image_digest "$(cx_mf images.postgres.index_digest)" || return 1
  cx_manifest_load "$d/tool-MANIFEST.json" >/dev/null || return 1
  [ "$(cx_mf version)" = "$CX_PB_SCRIPT_VERSION" ] || { cx_log FAIL "tool-MANIFEST.json is for $(cx_mf version)"; return 1; }
  # An external database is exported by a client of this script's release (tool-MANIFEST.json).
  ! cx_db_external || cx_pb_kv tool.dump_image_digest "$(cx_mf "images.pgclient$CX_DB_EXT_MAJOR.index_digest")" || return 1
  rel=$(cx_pb_sha "$d/release-MANIFEST.json") && tool=$(cx_pb_sha "$d/tool-MANIFEST.json") || return 1
  host=$(hostname -f 2>/dev/null) || host=""
  [ -n "$host" ] || host=$(hostname 2>/dev/null) || host=""
  tls=$(cx_bk_env TLS_MODE)
  [[ " $CX_OVERLAYS " != *" external-ingress "* ]] || tls=""
  for pair in $CX_PB_BUNDLED; do cx_pb_kv "${pair%%=*}" "${pair#*=}" || return 1; done
  ! cx_db_external || cx_pb_external_values || return 1
  cx_pb_kv format "$CX_PB_FORMAT" && cx_pb_kv kind custodexa-backup && cx_pb_kv trigger "$CX_PB_TRIGGER" \
    && cx_pb_kv created_at "$CX_PB_CREATED_AT" && cx_pb_kv product.version "$CX_PB_VERSION" \
    && cx_pb_kv product.script_version "$CX_PB_SCRIPT_VERSION" && cx_pb_kv product.manifest_sha256 "$rel" \
    && cx_pb_kv tool.manifest_sha256 "$tool" \
    && cx_pb_kv db.location "$(cx_db_external && echo external || echo bundled)" \
    && cx_pb_kv db.server_version "$CX_PB_DB_VERSION" && cx_pb_kv db.server_major "$CX_PB_DB_MAJOR" \
    && cx_pb_kv db.dump_tool_version "$CX_PB_DUMP_VERSION" && cx_pb_kv db.name "$CX_BK_DBNAME" \
    && cx_pb_kv db.user "$CX_BK_DBUSER" && cx_pb_kv db.encoding "$CX_PB_DB_ENCODING" \
    && cx_pb_kv db.collate "$CX_PB_DB_COLLATE" && cx_pb_kv db.ctype "$CX_PB_DB_CTYPE" \
    && cx_pb_kv db.migrations_count "$(cx_snap_migrations "$d/snapshot.txt" | grep -c .)" \
    && cx_pb_kv db.migrations_sha256 "$(cx_snap_migrations "$d/snapshot.txt" | LC_ALL=C sort | sha256sum | cut -c1-64)" \
    && cx_pb_kv deploy.overlays "$CX_OVERLAYS" && cx_pb_kv deploy.arch "$(uname -m)" \
    && cx_pb_kv deploy.tls_mode "$tls" && cx_pb_kv kek.provider "$CX_PB_KEK" \
    && cx_pb_kv kek.provider_declared "$CX_PB_KEK_DECLARED" \
    && cx_pb_kv kek.kms_provider "$(cx_pb_trim "$(cx_bk_env KEK_KMS_PROVIDER)")" \
    && cx_pb_kv kek.material_included "$([ "$CX_PB_KEK" = env ] && echo true || echo false)" \
    && cx_pb_kv kek.fingerprint "$CX_PB_FP" && cx_pb_kv kek.fingerprint_status "$CX_PB_FP_STATUS" \
    && cx_pb_kv snapshot.usable "$(cx_snap_get "$d/snapshot.txt" usable)" \
    && cx_pb_kv encryption.enabled "$([ "$CX_PB_ENC" = 1 ] && echo true || echo false)" \
    && cx_pb_kv encryption.scheme "$([ "$CX_PB_ENC" != 1 ] || printf '%s' "$CX_PB_SCHEME")" \
    && cx_pb_kv contents.recordings "$([ "$CX_PB_WITH_REC" = 1 ] && echo true || echo false)" \
    && cx_pb_kv contents.tls "$([ "$CX_PB_TLS" = 1 ] && echo true || echo false)" \
    && cx_pb_kv contents.nginx_template "$([ -n "$CX_PB_TPL" ] && echo true || echo false)" \
    && cx_pb_kv contents.state "$([ "$CX_PB_STATE" = 1 ] && echo true || echo false)" && cx_pb_kv contents.members "$members" \
    && cx_pb_kv size.db_bytes "$CX_BK_SIZE_DB" && cx_pb_kv size.audit_bytes "$CX_BK_SIZE_AUDIT" \
    && cx_pb_kv size.recordings_bytes "$CX_BK_SIZE_REC" && cx_pb_kv size.tls_bytes "$CX_BK_SIZE_TLS" \
    && cx_pb_kv source.hostname "$host" && cx_pb_kv source.root "$CX_ROOT" \
    && cx_pb_kv source.data_path "$CX_BK_DATA" && cx_pb_kv source.tls_domain "$(cx_bk_env TLS_DOMAIN)" \
    && cx_pb_kv source.tls_ip_san "$(cx_bk_env TLS_IP_SAN)" \
    && cx_pb_kv source.public_base_url "$(cx_bk_env PUBLIC_BASE_URL)" \
    && cx_pb_kv source.tls_nginx_template "$CX_PB_TPL"
}

# cx_pb_external_values: the keys of an external database (lib/dbclient.sh, lib/dbext.sh).
cx_pb_external_values() {
  local port
  port=$(cx_bk_env EXTERNAL_DB_PORT)
  cx_pb_kv db.external_host "$(cx_bk_env EXTERNAL_DB_HOST)" && cx_pb_kv db.external_port "${port:-5432}" \
    && cx_pb_kv db.sslmode "$CX_DB_SSLMODE_RAW" && cx_pb_kv db.tls_trust "$CX_DB_TLS_TRUST" \
    && cx_pb_kv db.tls_verify "$CX_DB_TLS_VERIFY" && cx_pb_kv db.tls_client_cert "$CX_DB_CLIENT_CERT" \
    && cx_pb_kv db.extra_grant_roles_hex "$CX_DBX_ROLES" \
    && cx_pb_kv contents.db_ca "$([ "$CX_DB_TLS_TRUST" = file ] && echo true || echo false)" \
    && cx_pb_kv tool.dump_manifest tool && cx_pb_kv tool.dump_image "pgclient$CX_DB_EXT_MAJOR"
}

# cx_pb_manifest_write <file> <members>: the manifest, every key in CX_PB_KEYS order.
cx_pb_manifest_write() {
  local file=$1 k sep="" body=""
  cx_pb_manifest_values "${file%/*}" "$2" || return 1
  for k in $CX_PB_KEYS; do
    body+="$sep"$(printf '  "%s": "%s"' "$k" "${CX_PB_MAP[$k]}")
    sep=$',\n'
  done
  printf '{\n%s\n}\n' "$body" >"$file"
}

# cx_pb_manifest_check <map name>: every key present and of its kind: booleans true or false,
# listed values only, digests and counts in form, empty only where allowed; a bundled database has
# the fixed reserved values; the content flags agree with the member list. Keys not known here are
# ignored. Fails with CX_PB_BAD_KEY naming the first key that does not hold.
cx_pb_manifest_check() {
  local -n cxm_map=$1
  local k v pair members
  CX_PB_BAD_KEY=""
  for k in $CX_PB_KEYS; do
    CX_PB_BAD_KEY=$k
    # A bundled database's file without a reserved key reads it as its fixed value.
    if [ -z "${cxm_map[$k]+x}" ] && [ "${cxm_map[db.location]:-}" = bundled ] && cx_pb_in "$k" "$CX_PB_EXT_KEYS"; then
      continue
    fi
    [ -n "${cxm_map[$k]+x}" ] || return 1
    v=${cxm_map[$k]}
    if [ -z "$v" ]; then
      cx_pb_in "$k" "$CX_PB_NULLABLE" || return 1
      continue
    fi
    if cx_pb_in "$k" "$CX_PB_BOOLS"; then [[ $v == true || $v == false ]] || return 1; fi
    if [ -n "${CX_PB_ENUM[$k]+x}" ]; then cx_pb_in "$v" "${CX_PB_ENUM[$k]}" || return 1; fi
    if cx_pb_in "$k" "$CX_PB_HEX"; then [[ $v =~ ^[0-9a-f]{64}$ ]] || return 1; fi
    if cx_pb_in "$k" "$CX_PB_COUNTS"; then [[ $v =~ ^[0-9]+$ ]] || return 1; fi
    if [ "$k" = tool.dump_image_digest ]; then [[ $v =~ ^sha256:[0-9a-f]{64}$ ]] || return 1; fi
  done
  if [ "${cxm_map[db.location]}" = bundled ]; then
    for pair in $CX_PB_BUNDLED; do
      CX_PB_BAD_KEY=${pair%%=*}
      [ "${cxm_map[${pair%%=*}]-${pair#*=}}" = "${pair#*=}" ] || return 1
    done
  else
    cx_pb_external_check "$1" || return 1
  fi
  members=" ${cxm_map[contents.members]} "
  CX_PB_BAD_KEY=contents.recordings
  [ "${cxm_map[contents.recordings]}" = "$([[ $members == *" recordings.tar.gz "* ]] && echo true || echo false)" ] || return 1
  # No tls.tar.gz is not a loss when the deployment had no tls/: contents.tls says which.
  CX_PB_BAD_KEY=contents.tls
  [ "${cxm_map[contents.tls]}" = "$([[ $members == *" tls.tar.gz "* ]] && echo true || echo false)" ] || return 1
  # The proxy template .env named, and the path it was named by (where a restore puts it back).
  CX_PB_BAD_KEY=contents.nginx_template
  [ "${cxm_map[contents.nginx_template]}" = "$([[ $members == *" nginx-tls.conf.template "* ]] && echo true || echo false)" ] || return 1
  CX_PB_BAD_KEY=source.tls_nginx_template
  [ "${cxm_map[contents.nginx_template]}" = "$([ -n "${cxm_map[source.tls_nginx_template]}" ] && echo true || echo false)" ] || return 1
  CX_PB_BAD_KEY=contents.state
  [ "${cxm_map[contents.state]}" = "$([[ $members == *" state.json "* ]] && echo true || echo false)" ] || return 1
  [ "${cxm_map[contents.state]}" = "$([ "${cxm_map[trigger]}" = upgrade ] && echo true || echo false)" ] || return 1
  CX_PB_BAD_KEY=contents.db_ca
  [ "${cxm_map[contents.db_ca]-false}" = "$([[ $members == *" db-ca.pem "* ]] && echo true || echo false)" ] || return 1
  CX_PB_BAD_KEY=""
}

# cx_pb_external_check <map name>: what an external database's file must hold besides the common
# rules: the address, a trust and verification pair the client can be given, the CA member exactly
# when the trust anchor is a file, the export tool a client of the server's major from the script's
# release, and the other roles as unique hex names in byte order.
cx_pb_external_check() {
  local -n cxe_map=$1
  local roles
  CX_PB_BAD_KEY=db.external_host
  [ -n "${cxe_map[db.external_host]}" ] || return 1
  CX_PB_BAD_KEY=db.external_port
  [[ ${cxe_map[db.external_port]} =~ ^[0-9]+$ ]] || return 1
  CX_PB_BAD_KEY=db.tls_verify
  cx_pb_in "${cxe_map[db.tls_trust]}/${cxe_map[db.tls_verify]}" "$CX_PB_TLS_PAIRS" || return 1
  CX_PB_BAD_KEY=contents.db_ca
  [ "${cxe_map[contents.db_ca]}" = "$([ "${cxe_map[db.tls_trust]}" = file ] && echo true || echo false)" ] || return 1
  CX_PB_BAD_KEY=tool.dump_manifest
  [ "${cxe_map[tool.dump_manifest]}" = tool ] || return 1
  CX_PB_BAD_KEY=tool.dump_image
  [ "${cxe_map[tool.dump_image]}" = "pgclient${cxe_map[db.server_major]}" ] || return 1
  CX_PB_BAD_KEY=db.extra_grant_roles_hex
  roles=${cxe_map[db.extra_grant_roles_hex]}
  [ -z "$roles" ] || [[ $roles =~ ^([0-9a-f]{2})+( ([0-9a-f]{2})+)*$ ]] || return 1
  # shellcheck disable=SC2086 # one name per word
  [ "$(cx_dbx_hex_list $roles)" = "$roles" ] || return 1
}

# cx_pb_manifest_ok <file>: the file reads with the plain parser and passes the check.
cx_pb_manifest_ok() {
  local -A cxpb_m=()
  local -a cxpb_k=()
  if ! cx_flat_parse "$1" cxpb_m cxpb_k; then
    CX_PB_BAD_KEY="line $CX_FLAT_BAD"
    return 1
  fi
  cx_pb_manifest_check cxpb_m
}
