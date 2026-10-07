# shellcheck shell=bash
# about: backup of an external database deployment against real PostgreSQL: each TLS setting the backend accepts (verify-full and verify-ca with the system's trust, require and verify-full with a CA file, PGSSLROOTCERT=system, allow and prefer with a CA that does not match) backs up with the same check the backend makes, a wrong CA and a missing DB_SSLMODE are refused before any stop as the backend fails too; a client certificate; public of its default owner backs up, another owner's table, a tablespace, an extension and unusable TLS paths are refused before any stop; roles named with a space and in Chinese come back from the manifest as the server names them
# needs: package
# images: pg16 pg17 pg18 openssl-3.5.4

readonly XT_TLS_PORT=15417 XT_CERT_PORT=15418 XT_EDGE_PORT=15416
readonly XT_AUD_CTR=/var/log/custodexa/audit/it-tls XT_EXP_CTR=/var/lib/custodexa/exports/it-client

# xt_apply <sysca|""> KEY=VALUE...: the settings in .env, then `stop` and `start`, which recreates
# the services with them (start alone leaves running services as they are): the backend connects
# with exactly these settings (or start fails). With XT_DOWN=1 the backend is down already (stop
# would wait for its audit queue in vain): start only.
xt_apply() {
  local ca=$1
  shift
  ex_env "$XT_ROOT" "$@"
  [ "${XT_DOWN:-0}" = 1 ] || it_check "stop" ex_cx "$ca" "$XT_ROOT" stop --yes --lang en
  it_check "start with $* (the backend connects the same way)" ex_cx "$ca" "$XT_ROOT" start --lang en
  it_same "the backend runs with DB_SSLMODE / PGSSLROOTCERT of .env" \
    "$(sed -n 's/^DB_SSLMODE=//p' "$XT_ROOT/.env" | tail -n1)/$(sed -n 's/^PGSSLROOTCERT=//p' "$XT_ROOT/.env" | tail -n1)" \
    "$(docker exec custodexa-backend printenv DB_SSLMODE || true)/$(docker exec custodexa-backend printenv PGSSLROOTCERT || true)"
}

# xt_ok <what> <sysca|""> <trust> <verify> <db_ca> KEY=VALUE...: settings, start, backup; the
# manifest records the trust anchor and the check the client made; XT_MAJOR: the server's major (17).
xt_ok() {
  local what=$1 ca=$2 trust=$3 verify=$4 dbca=$5
  shift 5
  it_step "TLS: $what"
  xt_apply "$ca" "$@"
  ex_backup "$XT_ROOT" "$ca"
  it_same "db.tls_trust / db.tls_verify / contents.db_ca" "$trust $verify $dbca" \
    "$(ex_mf db.tls_trust) $(ex_mf db.tls_verify) $(ex_mf contents.db_ca)"
  it_same "db-ca.pem is a member exactly when the trust anchor is a file" "$dbca" \
    "$(tar -tf "$EX_FILE" | grep -qx db-ca.pem && echo true || echo false)"
  it_same "the export ran with the server's major (pgclient${XT_MAJOR:-17})" "pgclient${XT_MAJOR:-17}" "$(ex_mf tool.dump_image)"
  it_say "   $(grep -E '^ *Connection:' <<<"$EX_OUT" | head -n1 | sed 's/^ *//')"
}

xt_hex_names() {
  local h out=""
  for h in $1; do out+="${out:+|}$(printf '%b' "$(sed 's/../\\x&/g' <<<"$h")")"; done
  printf '%s' "$out"
}

scenario() {
  XT_ROOT=/opt/custodexa
  local aud=$XT_ROOT/data/audit/it-tls exp=$XT_ROOT/data/exports/it-client v keyline m since
  v=$(jq -r .version /it-run/pkg/MANIFEST.json)

  it_step "servers on $(ex_addr): tls17 (TLS only), cert18 (client certificate), edge16 (plain)"
  ex_pg_start tls17 17 "$XT_TLS_PORT" tls-only
  ex_pg_start cert18 18 "$XT_CERT_PORT" client-cert
  ex_pg_start edge16 16 "$XT_EDGE_PORT"
  ex_db_create tls17
  ex_db_create cert18
  it_pki_ca other
  it_pki_cert test "$EX_USER" client

  it_step "install $v: external database tls17, verify-full with a CA file under the audit folder"
  it_unpack /opt
  mkdir -p "$aud" "$exp"
  cp "$IT_PKI/test/ca.crt" "$aud/ca.crt"
  cp "$IT_PKI/other/ca.crt" "$aud/other.crt"
  install -m 600 "$IT_PKI/test/$EX_USER.crt" "$exp/$EX_USER.crt"
  install -m 600 "$IT_PKI/test/$EX_USER.key" "$exp/$EX_USER.key"
  # The backend's system trust (Go reads SSL_CERT_FILE): the test CA, as the client's sysca mount.
  ex_preset "$XT_ROOT" "COMPOSE_FILE=current/compose.yml:current/compose.external-database.yml" \
    "EXTERNAL_DB_HOST=$(ex_addr)" "EXTERNAL_DB_PORT=$XT_TLS_PORT" "DB_NAME=$EX_DB" "DB_USER=$EX_USER" \
    "DB_PASSWORD=$EX_PASS" DB_SSLMODE=verify-full "PGSSLROOTCERT=$XT_AUD_CTR/ca.crt" \
    "SSL_CERT_FILE=$XT_AUD_CTR/ca.crt" KEK_PROVIDER=env
  it_cx "$XT_ROOT" install --images "$(it_bundle_file)"
  it_same "\\dn+ public: owner pg_database_owner (as created)" "public|pg_database_owner" \
    "$(ex_db_sql tls17 "$EX_DB" '\dn+ public' | head -n1 | cut -d'|' -f1,2)"
  it_same "the product tables are DB_USER's" "$EX_USER" \
    "$(ex_db_sql tls17 "$EX_DB" "SELECT string_agg(DISTINCT tableowner, ',') FROM pg_tables WHERE schemaname = 'public'")"
  it_pg_sql tls17 postgres 'CREATE ROLE "report reader"'
  it_pg_sql tls17 postgres 'CREATE ROLE "報表"'
  ex_db_sql tls17 "$EX_DB" 'GRANT SELECT ON public.schema_migrations TO "report reader", "報表", pg_monitor'

  xt_ok "verify-full with a CA file (in the audit folder)" "" file full true
  it_check "db-ca.pem is the CA file byte for byte" cmp "$EX_X/db-ca.pem" "$aud/ca.crt"
  it_same "db.sslmode is the value of .env" verify-full "$(ex_mf db.sslmode)"
  it_same "the granted roles, decoded from the manifest, as the server names them (pg_monitor left out)" \
    "report reader|報表" "$(xt_hex_names "$(ex_mf db.extra_grant_roles_hex)")"
  it_same "the server grants both" "true true" "$(it_pg_sql tls17 "$EX_DB" \
    "SELECT has_table_privilege('report reader', 'public.schema_migrations', 'SELECT')::text || ' ' || has_table_privilege('報表', 'public.schema_migrations', 'SELECT')::text")"
  it_check "the done screen names the other roles" grep -q 'grants privileges to other roles' <<<"$(tr '\n' ' ' <<<"$EX_OUT" | tr -s ' ')"

  xt_ok "verify-full with the system's trust" "$IT_PKI/test/ca.crt" system full false -PGSSLROOTCERT DB_SSLMODE=verify-full
  xt_ok "verify-ca with the system's trust" "$IT_PKI/test/ca.crt" system ca false -PGSSLROOTCERT DB_SSLMODE=verify-ca
  xt_ok "require with a CA file" "" file ca true DB_SSLMODE=require "PGSSLROOTCERT=$XT_AUD_CTR/ca.crt"
  xt_ok "PGSSLROOTCERT=system (DB_SSLMODE=require)" "$IT_PKI/test/ca.crt" system full false \
    DB_SSLMODE=require PGSSLROOTCERT=system
  it_same "db.sslmode keeps the value of .env" require "$(ex_mf db.sslmode)"
  it_check "the preview says verify-full set by PGSSLROOTCERT=system" grep -q 'set by PGSSLROOTCERT=system' <<<"$EX_OUT"
  # The server takes TLS only, and the CA does not sign its certificate: a client that loaded the
  # CA would fail, one that fell back to plain would be refused.
  xt_ok "allow with a CA file that does not match (not checked, as the backend)" "" file none true \
    DB_SSLMODE=allow "PGSSLROOTCERT=$XT_AUD_CTR/other.crt"
  xt_ok "prefer with a CA file that does not match (not checked, as the backend)" "" file none true \
    DB_SSLMODE=prefer "PGSSLROOTCERT=$XT_AUD_CTR/other.crt"

  it_step "TLS: verify-full with the wrong CA file"
  ex_env "$XT_ROOT" DB_SSLMODE=verify-full "PGSSLROOTCERT=$XT_AUD_CTR/other.crt"
  touch "$IT_WORK/mark"
  ex_refused "refused: the server cannot be checked" 'Cannot reach the external database' "$XT_ROOT"
  it_step "TLS: DB_SSLMODE not set against a TLS-only server (effective disable)"
  ex_env "$XT_ROOT" -DB_SSLMODE -PGSSLROOTCERT
  # Only what the server logs from here on: allow above also tried a plain connection first.
  since=$(date -u +%Y-%m-%dT%H:%M:%S)
  ex_refused "refused: the server takes no plain connection" 'Cannot reach the external database' "$XT_ROOT"
  it_check "the server refused the backup's plain connection" \
    bash -c 'docker logs --since "$1" it-pg-tls17 2>&1 | grep -q "pg_hba.conf rejects connection.*no encryption"' _ "$since"
  it_check "stop" it_cx "$XT_ROOT" stop --yes --lang en
  it_expect_fail "start with the same .env: the backend cannot connect either" '.' \
    it_cx "$XT_ROOT" start --lang en
  it_check "the backend's connections were refused the same way" \
    bash -c 'docker logs --since "$1" custodexa-backend 2>&1 | grep -qiE "pg_hba.conf rejects connection.*no encryption"' _ "$since"
  XT_DOWN=1 xt_apply "" DB_SSLMODE=verify-full "PGSSLROOTCERT=$XT_AUD_CTR/ca.crt"

  it_step "support limits, refused before any service stops (server edge16)"
  for m in ts owner ext; do ex_db_create edge16 "edge_$m"; done
  docker exec -u postgres it-pg-edge16 mkdir -p /var/lib/postgresql/it-space
  it_pg_sql edge16 postgres "CREATE TABLESPACE report_space LOCATION '/var/lib/postgresql/it-space'"
  it_pg_sql edge16 postgres "GRANT CREATE ON TABLESPACE report_space TO $EX_USER"
  ex_db_sql edge16 edge_ts 'CREATE TABLE public.t (id int) TABLESPACE report_space'
  it_pg_sql edge16 postgres 'CREATE ROLE report_owner'
  ex_db_sql edge16 edge_owner 'CREATE TABLE public.t (id int)'
  it_pg_sql edge16 edge_owner 'CREATE TABLE public.report_totals (day date); ALTER TABLE public.report_totals OWNER TO report_owner'
  it_pg_sql edge16 edge_ext 'CREATE EXTENSION hstore'
  touch "$IT_WORK/mark"
  ex_env "$XT_ROOT" "EXTERNAL_DB_PORT=$XT_EDGE_PORT" -DB_SSLMODE -PGSSLROOTCERT DB_NAME=edge_ts
  ex_refused "a table in a tablespace of its own" 'Custom tablespace: report_space' "$XT_ROOT"
  ex_env "$XT_ROOT" DB_NAME=edge_owner
  ex_refused "a table of report_owner in public" "Owners other than $EX_USER: report_owner" "$XT_ROOT"
  ex_env "$XT_ROOT" DB_NAME=edge_ext
  ex_refused "an extension" 'Extension: hstore' "$XT_ROOT"
  ex_env "$XT_ROOT" "EXTERNAL_DB_PORT=$XT_TLS_PORT" "DB_NAME=$EX_DB" DB_SSLMODE=verify-full PGSSLROOTCERT=/etc/it/ca.crt
  ex_refused "a CA file outside the backend's folders" 'CA file PGSSLROOTCERT=/etc/it/ca.crt' "$XT_ROOT"
  ex_env "$XT_ROOT" "PGSSLROOTCERT=$XT_AUD_CTR/ca.crt" "PGSSLCERT=$XT_EXP_CTR/$EX_USER.crt" \
    "PGSSLKEY=/var/log/custodexa/audit/it-tls/$EX_USER.key"
  install -m 600 "$exp/$EX_USER.key" "$aud/$EX_USER.key"
  ex_refused "a client key inside the audit folder" 'private key PGSSLKEY is inside the audit folder' "$XT_ROOT"
  rm -f "$aud/$EX_USER.key"

  it_step "client certificate (server cert18 requires one; key and certificate under exports)"
  XT_MAJOR=18 xt_ok "verify-full, CA file, client certificate" "" file full true "EXTERNAL_DB_PORT=$XT_CERT_PORT" \
    "PGSSLKEY=$XT_EXP_CTR/$EX_USER.key"
  it_same "db.tls_client_cert" true "$(ex_mf db.tls_client_cert)"
  it_check "the server requires a client certificate (pg_hba.conf)" grep -q 'clientcert=verify-full' "$IT_WORK/pg/cert18/pg_hba.conf"
  keyline=$(sed -n 2p "$exp/$EX_USER.key")
  it_same "the client key is in no member (nested archives opened)" 0 "$(
    {
      tar -xOf "$EX_FILE"
      for m in $(tar -tf "$EX_FILE" | grep -E '\.tar\.gz$|\.tgz$'); do tar -xOf "$EX_FILE" "$m" | tar -xzOf - 2>/dev/null; done
    } | grep -caF "$keyline" || true
  )"
  ex_teardown "$XT_ROOT"
}
