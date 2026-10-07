# shellcheck shell=bash
# about: restore of an external database deployment, the checks before anything stops, against real PostgreSQL 15, 16, 17 and 18: a backup taken on 16 passes on 16, 17 and 18 (each asked with its own client) and is refused on 15 (no client); on 17, another connection (new host), an object of another owner, an extension, another collation, a TLS-only server whose CA the client does not trust and a client-certificate server without the key are each refused, and a summary of the target database (objects, whole-table hashes, sequences, grants) is the same after; on the backup's own host its running backend's connections are listed, not refused, and the restore goes on to the confirmation
# needs: package
# images: pg15 pg16 pg17 pg18 openssl-3.5.4

# The package's images are those of the last published release, older than the first data version a
# restore takes. The deployments here are installed from it and then labelled with that first
# version (the release folder, its VERSION and MANIFEST.json version, state.json), so the backups
# they make carry it and the restore reaches the checks of the external database. The version gate
# itself is not what this scenario proves.
readonly RX_V=1.16.0
readonly RX_P16=15436 RX_P17=15437 RX_TLS=15438 RX_CERT=15439
readonly RX_AUD_CTR=/var/log/custodexa/audit/it-tls RX_EXP_CTR=/var/lib/custodexa/exports/it-client
RX_A=/opt/a/custodexa RX_B=/opt/b/custodexa RX_B_DATA=/opt/b/data

# rx_relabel <root>: the one release of the deployment, labelled RX_V.
rx_relabel() {
  local root=$1 v
  v=$(find "$root/releases" -mindepth 1 -maxdepth 1 -type d ! -name '.*' -printf '%f\n' | head -n1)
  [ "$v" != "$RX_V" ] || return 0
  mv "$root/releases/$v" "$root/releases/$RX_V"
  printf '%s\n' "$RX_V" >"$root/releases/$RX_V/VERSION"
  jq --arg v "$RX_V" '.version = $v' "$root/releases/$RX_V/MANIFEST.json" >"$IT_WORK/mf.json"
  cat "$IT_WORK/mf.json" >"$root/releases/$RX_V/MANIFEST.json"
  ln -sfn "releases/$RX_V" "$root/current"
  [ -f "$root/state.json" ] || return 0
  jq --arg o "releases/$v" --arg n "releases/$RX_V" --arg v "$RX_V" '
    with_entries(if (.value | type) == "string" and (.value == $o or (.value | startswith($o + "/")))
      then .value = $n + .value[($o | length):] else . end)
    | if has("current.version") then ."current.version" = $v else . end
    | if has("load.version") then ."load.version" = $v else . end' \
    "$root/state.json" >"$IT_WORK/state.json"
  cat "$IT_WORK/state.json" >"$root/state.json"
}

# rx_apply <sysca|""> KEY=VALUE...: deployment A's settings, then stop and start (the backend
# connects with them, or start fails).
rx_apply() {
  local ca=$1
  shift
  ex_env "$RX_A" "$@"
  it_check "stop" ex_cx "$ca" "$RX_A" stop --yes --lang en
  it_check "start with $*" ex_cx "$ca" "$RX_A" start --lang en
}

# rx_keep <name>: the backup file ex_backup just made, with its checksum file, as $IT_WORK/f/<name>.
rx_keep() {
  mkdir -p "$IT_WORK/f/$1"
  cp -p "$EX_FILE" "$EX_FILE.sha256" "$IT_WORK/f/$1/"
  printf '%s' "$IT_WORK/f/$1/${EX_FILE##*/}"
}

readonly RX_SYS="n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname !~ '^pg_(toast|temp_)'"

# rx_digest <server>: a summary of database custodexa: its encoding and owner, the extensions, every
# object of the non-system schemas with its owner, each table's row count and the hash of all its
# rows, each sequence's value, and every grant. Measured by this scenario, not by the script.
rx_digest() {
  local s=$1 t
  {
    it_pg_sql "$s" "$EX_DB" "SELECT pg_encoding_to_char(encoding), datcollate, datctype, pg_get_userbyid(datdba) FROM pg_database WHERE datname = current_database()"
    it_pg_sql "$s" "$EX_DB" "SELECT extname, extversion FROM pg_extension ORDER BY 1"
    it_pg_sql "$s" "$EX_DB" "SELECT n.nspname, c.relname, c.relkind, pg_get_userbyid(c.relowner) FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace WHERE $RX_SYS ORDER BY 1, 2"
    it_pg_sql "$s" "$EX_DB" "SELECT n.nspname, p.proname, pg_get_function_identity_arguments(p.oid), pg_get_userbyid(p.proowner)
      FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE $RX_SYS ORDER BY 1, 2, 3"
    it_pg_sql "$s" "$EX_DB" "SELECT n.nspname, c.relname, x.grantor::regrole, x.grantee, x.privilege_type, x.is_grantable
      FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace CROSS JOIN LATERAL aclexplode(c.relacl) x
      WHERE $RX_SYS ORDER BY 1, 2, 3, 4, 5"
    it_pg_sql "$s" "$EX_DB" "SELECT n.nspname, x.grantor::regrole, x.grantee, x.privilege_type FROM pg_namespace n
      CROSS JOIN LATERAL aclexplode(n.nspacl) x WHERE $RX_SYS ORDER BY 1, 2, 3, 4"
    it_pg_sql "$s" "$EX_DB" "SELECT schemaname, sequencename, last_value FROM pg_sequences
      WHERE schemaname NOT IN ('pg_catalog', 'information_schema') ORDER BY 1, 2"
    for t in $(it_pg_sql "$s" "$EX_DB" "SELECT format('%I.%I', schemaname, tablename) FROM pg_tables
      WHERE schemaname NOT IN ('pg_catalog', 'information_schema') ORDER BY 1"); do
      it_pg_sql "$s" "$EX_DB" "SELECT '$t', count(*), md5(coalesce(string_agg(x::text, E'\n' ORDER BY x::text), '')) FROM $t x"
    done
  } | sha256sum | cut -c1-64
}

# rx_run <root> <arguments>: custodexa.sh without a terminal; RX_OUT, RX_FLAT (one line, runs of
# spaces as one), RX_RC. The failure part of the screen is shown.
rx_run() {
  RX_OUT=$(it_cx "$@" </dev/null 2>&1) && RX_RC=0 || RX_RC=$?
  RX_FLAT=$(tr '\n' ' ' <<<"$RX_OUT" | tr -s ' ')
  printf '%s\n' "$RX_OUT" | sed -n '/\[FAIL\]/,$p' | sed 's/^/   > /'
}

# rx_new <file> [options]: restore on host B, not installed: a new host.
rx_new() {
  local f=$1
  shift
  rx_run "$RX_B" restore "$f" --new-host --yes --data-path "$RX_B_DATA" --lang en "$@"
}

# rx_untouched <what> <server> <summary before> <containers before>: nothing changed.
rx_untouched() {
  it_same "$1: the target database's summary is unchanged" "$3" "$(rx_digest "$2")"
  it_same "$1: no container was started, stopped or made" "$4" "$(docker ps -a --format '{{.ID}} {{.State}}' | sort | tr '\n' ' ')"
  it_same "$1: host B is still not installed" "" "$(jq -r '."current.version" // ""' "$RX_B/state.json" 2>/dev/null || true)"
  it_same "$1: host B has no data folder" "" "$(find "$RX_B_DATA" -mindepth 1 2>/dev/null | head -n1)"
}

# rx_refused <what> <reason regex> <server> <file> [options]: refused on host B before anything
# stops, with that reason, nothing changed.
rx_refused() {
  local what=$1 pattern=$2 s=$3 f=$4 before ctr
  shift 4
  it_step "$what"
  before=$(rx_digest "$s")
  ctr=$(docker ps -a --format '{{.ID}} {{.State}}' | sort | tr '\n' ' ')
  rx_new "$f" "$@"
  it_same "$what: exit 3" 3 "$RX_RC"
  it_check "$what: refused before anything stops" grep -qF 'cannot be restored yet, because: ' <<<"$RX_FLAT"
  it_check "$what: the reason ($pattern)" grep -Eq -- "$pattern" <<<"$RX_FLAT"
  it_check "$what: nothing has been changed" grep -qF 'Nothing has been changed.' <<<"$RX_FLAT"
  rx_untouched "$what" "$s" "$before" "$ctr"
}

# rx_passes <what> <server> <file> [options]: host B's checks pass; without --yes and without a
# terminal the restore ends at its confirmation (the step that would go on to empty the database),
# nothing changed.
rx_passes() {
  local what=$1 s=$2 f=$3 before ctr
  shift 3
  it_step "$what"
  before=$(rx_digest "$s")
  ctr=$(docker ps -a --format '{{.ID}} {{.State}}' | sort | tr '\n' ' ')
  rx_run "$RX_B" restore "$f" --new-host --data-path "$RX_B_DATA" --lang en "$@"
  it_same "$what: exit 3 at the confirmation" 3 "$RX_RC"
  it_check "$what: not refused" bash -c '! grep -qF "cannot be restored yet" <<<"$1"' _ "$RX_FLAT"
  it_check "$what: past the checks and the preview, ended at the confirmation" \
    grep -qF 'Without a terminal, use --yes to confirm the restore.' <<<"$RX_FLAT"
  rx_untouched "$what" "$s" "$before" "$ctr"
}

# rx_holder <port> <application>: a connection to custodexa held open from the host's address.
rx_holder() {
  local i
  docker run -d --name it-rx-holder --network host -e PGPASSWORD="$EX_PASS" -e PGAPPNAME="$2" \
    --entrypoint psql "$(it_image pg17)" -h "$(ex_addr)" -p "$1" -U "$EX_USER" -d "$EX_DB" \
    -c 'SELECT pg_sleep(600)' >/dev/null
  for ((i = 0; i < 30; i++)); do
    [ "$(it_pg_sql rx17 postgres "SELECT count(*) FROM pg_stat_activity WHERE application_name = '$2'")" = 1 ] && return 0
    sleep 1
  done
  it_die "the held connection did not show"
}

# rx_holder_end <application>: the held connection gone, also on the server (a backend in pg_sleep
# does not notice its client went away).
rx_holder_end() {
  local i
  docker rm -f it-rx-holder >/dev/null
  it_pg_sql rx17 postgres "SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity WHERE application_name = '$1'" >/dev/null
  for ((i = 0; i < 30; i++)); do
    [ "$(it_pg_sql rx17 postgres "SELECT count(*) FROM pg_stat_activity WHERE application_name = '$1'")" = 0 ] && return 0
    sleep 1
  done
  it_die "the held connection did not end"
}

scenario() {
  local v f16 f17 ftls fcert before ctr log aud=$RX_A/data/audit/it-tls exp=$RX_A/data/exports/it-client m key
  v=$(jq -r .version /it-run/pkg/MANIFEST.json)

  it_step "servers on $(ex_addr): rx16 and rx17 (plain), tls17 (TLS only), cert17 (client certificate)"
  ex_pg_start rx16 16 "$RX_P16"
  ex_pg_start rx17 17 "$RX_P17"
  ex_pg_start tls17 17 "$RX_TLS" tls-only
  ex_pg_start cert17 17 "$RX_CERT" client-cert
  for m in rx16 rx17 tls17 cert17; do ex_db_create "$m"; done
  it_pki_cert test "$EX_USER" client

  it_step "host A: install $v on rx16 (PostgreSQL 16), labelled $RX_V, back up"
  ex_install "$RX_A" now "$RX_P16"
  rx_relabel "$RX_A"
  it_same "host A is $RX_V" "$RX_V" "$(ex_st "$RX_A" current.version)"
  ex_backup "$RX_A"
  it_same "the backup carries $RX_V and PostgreSQL 16" "$RX_V 16" "$(ex_mf product.version) $(ex_mf db.server_major)"
  f16=$(rx_keep f16)

  it_step "host A on rx17 (PostgreSQL 17), back up"
  rx_apply "" "EXTERNAL_DB_PORT=$RX_P17"
  ex_backup "$RX_A"
  it_same "PostgreSQL 17, its client" "17 pgclient17" "$(ex_mf db.server_major) $(ex_mf tool.dump_image)"
  f17=$(rx_keep f17)

  it_step "host A on tls17: verify-full with the system's trust (the test CA: the backend's SSL_CERT_FILE, the client's system CA file through the test wrapper)"
  mkdir -p "$aud" "$exp"
  cp "$IT_PKI/test/ca.crt" "$aud/ca.crt"
  install -m 600 "$IT_PKI/test/$EX_USER.crt" "$exp/$EX_USER.crt"
  install -m 600 "$IT_PKI/test/$EX_USER.key" "$exp/$EX_USER.key"
  rx_apply "$IT_PKI/test/ca.crt" "EXTERNAL_DB_PORT=$RX_TLS" DB_SSLMODE=verify-full "SSL_CERT_FILE=$RX_AUD_CTR/ca.crt"
  ex_backup "$RX_A" "$IT_PKI/test/ca.crt"
  it_same "trust system, verify full, no CA member" "system full false" "$(ex_mf db.tls_trust) $(ex_mf db.tls_verify) $(ex_mf contents.db_ca)"
  ftls=$(rx_keep ftls)

  it_step "host A on cert17: verify-full with a CA file, client certificate and key under exports"
  rx_apply "" "EXTERNAL_DB_PORT=$RX_CERT" "PGSSLROOTCERT=$RX_AUD_CTR/ca.crt" \
    "PGSSLCERT=$RX_EXP_CTR/$EX_USER.crt" "PGSSLKEY=$RX_EXP_CTR/$EX_USER.key"
  ex_backup "$RX_A"
  it_same "trust file, client certificate, CA member" "file true true" "$(ex_mf db.tls_trust) $(ex_mf db.tls_client_cert) $(ex_mf contents.db_ca)"
  fcert=$(rx_keep fcert)

  it_step "host A back on rx17 (plain), running"
  rx_apply "" "EXTERNAL_DB_PORT=$RX_P17" -DB_SSLMODE -SSL_CERT_FILE -PGSSLROOTCERT -PGSSLCERT -PGSSLKEY

  # A new host gets the release's images from the offline bundle with load, which checks them and
  # records their IDs: on the containerd image store a loaded image answers to its tag only, so the
  # restore knows the clients by those records (a tag alone is not trusted).
  it_step "host B: the same package unpacked, not installed, its offline bundle loaded, labelled $RX_V"
  it_unpack /opt/b
  it_check "host B loads the offline bundle" it_cx "$RX_B" load "$(it_bundle_file)" --lang en
  it_check "host B is still not installed" test -z "$(jq -r '."current.version" // ""' "$RX_B/state.json")"
  rx_relabel "$RX_B"
  it_same "load's record is of $RX_V" "$RX_V" "$(jq -r '."load.version" // ""' "$RX_B/state.json")"
  it_check "host B's release manifest is the one the backups recorded" cmp "$RX_B/releases/$RX_V/MANIFEST.json" "$RX_A/releases/$RX_V/MANIFEST.json"

  # The backend is paused while the summary is taken and the restore runs: its connections stay
  # open (the server still lists them), and it writes nothing meanwhile.
  docker pause custodexa-backend >/dev/null
  rx_refused "new host while the original host's backend is still connected (PostgreSQL 17)" \
    "other connections? (is|are) using custodexa \(from [0-9.]+" rx17 "$f17"
  it_check "it says to stop the original host and check for a standby" grep -qF 'Stop the services on the original host first, and make sure no standby host has taken this database over.' <<<"$RX_FLAT"

  it_step "the backup's own host, its backend connected: listed before the stop, not refused"
  before=$(rx_digest rx17)
  ctr=$(docker ps -a --format '{{.ID}} {{.State}}' | sort | tr '\n' ' ')
  # Without --yes and without a terminal it ends at the confirmation: the checks are what is proved
  # here; the restore that stops this host's services itself is restore-external-db.
  rx_run "$RX_A" restore "$f17" --same-host --confirm-data-loss --lang en
  it_same "same host: exit 3 at the confirmation" 3 "$RX_RC"
  it_check "same host: not refused" bash -c '! grep -qF "cannot be restored yet" <<<"$1"' _ "$RX_FLAT"
  it_check "same host: past the checks and the preview, ended at the confirmation" \
    grep -qF "Replacing this host's data without a version prompt requires both --yes and --confirm-data-loss." <<<"$RX_FLAT"
  log=$(find "$RX_A/logs" -name 'restore-*.log' | sort | tail -n 1)
  it_check "same host: its backend's connections were listed (${log##*/})" grep -qE 'external database other connections=[1-9]' "$log"
  it_check "same host: checked with the client of PostgreSQL 17" grep -qE 'external database checked: server=17\.[0-9]+ client=pgclient17' "$log"
  it_same "same host: the target database's summary is unchanged" "$before" "$(rx_digest rx17)"
  it_same "same host: no container was started, stopped or made" "$ctr" "$(docker ps -a --format '{{.ID}} {{.State}}' | sort | tr '\n' ' ')"
  it_same "same host: still $RX_V, no restore on record" "$RX_V " "$(ex_st "$RX_A" current.version) $(ex_st "$RX_A" last_restore.result)"
  docker unpause custodexa-backend >/dev/null
  it_check "host A stops" it_cx "$RX_A" stop --yes --lang en

  rx_holder "$RX_P17" it-holder
  rx_refused "new host, another connection held open (PostgreSQL 17)" \
    "1 other connection is using custodexa \(from $(ex_addr | sed 's/\./\\./g'), application it-holder\)" rx17 "$f17"
  rx_holder_end it-holder

  it_pg_sql rx17 postgres "CREATE ROLE analyst"
  it_pg_sql rx17 "$EX_DB" "CREATE TABLE public.report_cache (id int); ALTER TABLE public.report_cache OWNER TO analyst"
  rx_refused "new host, a table of another owner (PostgreSQL 17)" \
    "The object public\.report_cache is owned by analyst, not custodexa; the script can only empty objects that custodexa owns\." rx17 "$f17"
  it_pg_sql rx17 "$EX_DB" "DROP TABLE public.report_cache"

  it_pg_sql rx17 "$EX_DB" "CREATE EXTENSION pg_trgm"
  rx_refused "new host, an extension besides plpgsql (PostgreSQL 17)" \
    "extensions other than plpgsql \(pg_trgm [0-9.]+\)" rx17 "$f17"
  it_pg_sql rx17 "$EX_DB" "DROP EXTENSION pg_trgm"

  rx_refused "new host, a TLS-only server whose CA the client's system trust lacks (PostgreSQL 17)" \
    "Cannot reach the external database $(ex_addr | sed 's/\./\\./g'):$RX_TLS, or the login failed" tls17 "$ftls"
  log=$(find "$RX_B/logs" -name 'restore-*.log' | sort | tail -n 1)
  it_check "the client's reason is the certificate check (${log##*/})" grep -qi 'certificate verify failed' "$log"

  rx_refused "new host, a client-certificate server without the certificate and key (PostgreSQL 17)" \
    "uses a client certificate: give the certificate and its private key with --db-client-cert and --db-client-key\." cert17 "$fcert"
  key=$IT_WORK/given/$EX_USER.key
  mkdir -p "${key%/*}"
  install -m 600 "$IT_PKI/test/$EX_USER.key" "$key"
  install -m 600 "$IT_PKI/test/$EX_USER.crt" "${key%.key}.crt"
  rx_refused "new host, the certificate given without its key (PostgreSQL 17)" \
    "uses a client certificate" cert17 "$fcert" --db-client-cert "${key%.key}.crt"
  rx_passes "new host, certificate and key given: the client certificate server lets the checks in (PostgreSQL 17)" \
    cert17 "$fcert" --db-client-cert "${key%.key}.crt" --db-client-key "$key"
  it_same "the key is in no file of host B" "" "$(grep -rlF "$(sed -n 2p "$key")" "$RX_B" 2>/dev/null || true)"

  it_pg_sql rx17 postgres "DROP DATABASE $EX_DB"
  it_pg_sql rx17 postgres "CREATE DATABASE $EX_DB OWNER $EX_USER TEMPLATE template0 ENCODING 'UTF8' LC_COLLATE 'C' LC_CTYPE 'C'"
  rx_refused "new host, a database of another collation (PostgreSQL 17)" \
    "The database's encoding or collation differs from the backup's\. Create the database with the same settings: ENCODING 'UTF8' LC_COLLATE '[^']+' LC_CTYPE '[^']+'" rx17 "$f17"

  rx_passes "the PostgreSQL 16 backup on PostgreSQL 16 (rx16, holding host A's data, nobody connected)" rx16 "$f16"
  it_check "asked with the client of PostgreSQL 16" grep -qE 'external database checked: server=16\.[0-9]+ client=pgclient16' \
    "$(find "$RX_B/logs" -name 'restore-*.log' | sort | tail -n 1)"
  it_pg_stop rx16
  for m in 15 17 18; do
    ex_pg_start "rv$m" "$m" "$RX_P16"
    ex_db_create "rv$m"
    if [ "$m" = 15 ]; then
      rx_refused "the PostgreSQL 16 backup on a PostgreSQL 15 server" \
        "The server runs PostgreSQL 15\.[0-9]+, which has no client here; this release carries clients for PostgreSQL 16, 17 and 18\." "rv$m" "$f16"
    else
      rx_passes "the PostgreSQL 16 backup on a PostgreSQL $m server" "rv$m" "$f16"
      it_check "asked with the client of PostgreSQL $m" grep -qE "external database checked: server=$m\.[0-9]+ client=pgclient$m" \
        "$(find "$RX_B/logs" -name 'restore-*.log' | sort | tail -n 1)"
    fi
    it_pg_stop "rv$m"
  done

  it_same "no client container is left" "" "$(docker ps -aq --filter name=custodexa-restore-tool)"
  it_same "no pgpass file is left on either host" "" "$(find "$RX_A" "$RX_B" -name '.pgpass' 2>/dev/null | head -n1)"
  ex_teardown "$RX_A"
  rm -rf /opt/b
  for m in rx17 tls17 cert17; do it_pg_stop "$m"; done
}
