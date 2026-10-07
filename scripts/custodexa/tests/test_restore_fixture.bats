#!/usr/bin/env bats
# Threat (B): a restore test passing because its backup file was not what it claims (not made by
# the real backup, or tampered in more than the one place the test names), or because the fake
# host answered a call the restore never should make, or a failure switch did not fire. The
# fixtures must be the producer's output, each tampered file must differ in exactly its one change,
# the fake must refuse what it does not describe (99), and every switch must make its call fail.

load helper
load install_host
load backup_host
load upgrade_host
load restore_host

setup_file() { rs_ext_fixtures; }

setup() {
  RS_FIX=$BATS_FILE_TMPDIR/fixtures
  rs_host ui
  backup_strict
}

dk() { run docker "$@"; }

# mf <file> <key>: a value of the backup manifest inside a (not encrypted) file.
mf() { /usr/bin/tar -xOf "$1" backup-manifest.json | jq -r --arg k "$2" '.[$k] // "MISSING"'; }

@test "fixture: the backup files are the producer's: version, form and contents as named; each checksum file matches" {
  local n f
  for n in plain env kms enc rec notls tplabs tplrel external oldupgrade nojwt oldnofp; do
    f=$(rs_fix "$n") || return 1
    (cd "${f%/*}" && /usr/bin/sha256sum -c --quiet "${f##*/}.sha256") || { echo "$n: checksum file"; return 1; }
  done
  f=$(rs_fix enc)
  [[ $f == *.tar.enc ]] && [ "$(head -c 8 "$f")" = Salted__ ] || return 1
  local plain
  plain=$BATS_TEST_TMPDIR/enc.tar
  bk_decrypt "$f" "$RS_PASS" "$plain" || return 1
  [ "$(mf "$plain" encryption.enabled)" = true ] && [ "$(mf "$plain" product.version)" = "$RS_VERSION" ] || return 1
  f=$(rs_fix plain)
  [ "$(mf "$f" product.version)" = "$RS_VERSION" ] && [ "$(mf "$f" trigger)" = manual ] || return 1
  [ "$(mf "$f" kek.provider)" = ui ] && [ "$(mf "$f" contents.recordings)" = false ] && [ "$(mf "$f" contents.tls)" = true ] || return 1
  [ "$(mf "$f" kek.fingerprint_status)" = ok ] && [ "$(mf "$f" db.location)" = bundled ] || return 1
  [ "$(mf "$(rs_fix env)" kek.provider)" = env ] && [ "$(mf "$(rs_fix env)" kek.material_included)" = true ] || return 1
  [ "$(mf "$(rs_fix kms)" kek.provider)" = kms ] || return 1
  [ "$(mf "$(rs_fix rec)" contents.recordings)" = true ] || return 1
  f=$(rs_fix notls)
  [ "$(mf "$f" contents.tls)" = false ] && ! /usr/bin/tar -tf "$f" | grep -qx tls.tar.gz || return 1
  [[ " $(mf "$f" deploy.overlays) " == *" external-ingress "* ]] || return 1
  [[ $(mf "$(rs_fix tplabs)" source.tls_nginx_template) == /* ]] || return 1
  [ "$(mf "$(rs_fix tplrel)" source.tls_nginx_template)" = ./conf/nginx-tls.conf.template ] || return 1
  /usr/bin/tar -tf "$(rs_fix tplrel)" | grep -qx nginx-tls.conf.template || return 1
  [ "$(mf "$(rs_fix external)" db.location)" = external ] || return 1
  f=$(rs_fix oldupgrade)
  [ "$(mf "$f" trigger)" = upgrade ] && [ "$(mf "$f" product.version)" = 1.13.0 ] && [ "$(mf "$f" contents.state)" = true ] || return 1
  [ "$(mf "$(rs_fix oldnofp)" kek.fingerprint_status)" = missing ] && [ -z "$(/usr/bin/tar -xOf "$(rs_fix oldnofp)" snapshot.txt | sed -n 's/^fp.kek=//p')" ] || return 1
  [ -z "$(/usr/bin/tar -xOf "$(rs_fix nojwt)" snapshot.txt | sed -n 's/^fp.jwt=//p')" ]
}

# members_differing <a> <b>: the member names whose bytes differ (or that only one file has).
members_differing() {
  local da=$BATS_TEST_TMPDIR/a db=$BATS_TEST_TMPDIR/b m
  rm -rf "$da" "$db"
  rs_unpack "$1" "$da" && rs_unpack "$2" "$db" || return 1
  sort -u "$da/.order" "$db/.order" | while IFS= read -r m; do
    if [ -L "$da/$m" ] || [ -L "$db/$m" ] || [ -d "$da/$m" ] || [ -d "$db/$m" ]; then echo "$m"; continue; fi
    cmp -s "$da/$m" "$db/$m" || echo "$m"
  done
  cmp -s "$da/.order" "$db/.order" || echo .order
}

@test "fixture: each tampered file differs from its fixture in its one change; recomputed checksums are right" {
  local k fix f src want got sums
  local -A changed=(
    [member-hash]=db.dump [member-extra]=".order extra.txt" [member-missing]=".order audit.tar.gz"
    [member-dup]=.order [member-link]=".order link" [member-dir]=".order folder/" [member-path]=".order sub/x"
    [manifest-bad]=backup-manifest.json [release-mf]=release-MANIFEST.json [migrations]=snapshot.txt
    [kek-fp]=snapshot.txt [inner-path]=audit.tar.gz [inner-link]=audit.tar.gz
    [tls-missing]=".order backup-manifest.json tls.tar.gz" [tpl-flag]=backup-manifest.json
    [tpl-source]=backup-manifest.json [state-version]=state.json)
  for k in $(rs_tamper_kinds); do
    fix=$(printf '%s\n' "$RS_TAMPER" | awk -v k="$k" '$1 == k { print $2 }')
    src=$(rs_fix "$fix") && f=$(rs_tamper "$k") || return 1
    (cd "${f%/*}" && /usr/bin/sha256sum -c --quiet "${f##*/}.sha256" 2>/dev/null) || [ "$k" = sidecar ] \
      || { echo "$k: its checksum file does not match"; return 1; }
    case $k in
      sidecar) cmp "$src" "$f" || return 1; continue ;;
      enc-as-tar | tar-as-enc) cmp "$src" "$f" && [ "${src##*/}" != "${f##*/}" ] || return 1; continue ;;
      enc-cut) [ "$(($(stat -c %s "$src") - $(stat -c %s "$f")))" = 100 ] && cmp -n "$(stat -c %s "$f")" "$src" "$f" || return 1; continue ;;
    esac
    sums=""
    printf '%s\n' "$RS_TAMPER" | awk -v k="$k" '$1 == k' | grep -q '(sums)' && sums=SHA256SUMS
    want=$(printf '%s\n' ${changed[$k]} $sums | sort -u)
    got=$(members_differing "$src" "$f" | sort -u)
    [ "$got" = "$want" ] || { echo "$k: differs in [$got], want [$want]"; return 1; }
    if [ -n "$sums" ]; then
      (cd "$BATS_TEST_TMPDIR/b" && /usr/bin/sha256sum -c --quiet SHA256SUMS) || { echo "$k: SHA256SUMS"; return 1; }
    fi
    # The changed text member differs in one line.
    case $k in
      manifest-bad | release-mf | migrations | kek-fp | tpl-flag | tpl-source | state-version)
        got=$(diff "$BATS_TEST_TMPDIR/a/${changed[$k]}" "$BATS_TEST_TMPDIR/b/${changed[$k]}" | grep -c '^>')
        [ "$got" = 1 ] || { echo "$k: $got lines changed"; return 1; } ;;
    esac
  done
  /usr/bin/tar -tzf "$BATS_TEST_TMPDIR/b/audit.tar.gz" >/dev/null || return 1
  f=$(rs_tamper inner-path)
  /usr/bin/tar -xOf "$f" audit.tar.gz | /usr/bin/tar -tzf - | grep -qx '../escape' || return 1
  f=$(rs_tamper inner-link)
  /usr/bin/tar -xOf "$f" audit.tar.gz | /usr/bin/tar -tvzf - | grep -q '^l.*audit/shadow' || return 1
  f=$(rs_tamper member-dup)
  [ "$(/usr/bin/tar -tf "$f" | grep -cx snapshot.txt)" = 2 ]
}

@test "fixture: a query or a docker subcommand the fake does not describe exits 99" {
  dk compose -p custodexa exec -T postgres psql -AtX -c 'SELECT 1'
  [ "$status" -eq 99 ] || { echo "$status $output"; return 1; }
  for c in "network ls" "volume rm x" "compose -p custodexa exec -T postgres vacuumdb" "compose -p custodexa down" \
    "compose -p custodexa exec -T postgres pg_ctl"; do
    # shellcheck disable=SC2086
    dk $c
    [ "$status" -eq 99 ] || { echo "$c: $status"; return 1; }
  done
}

@test "fixture: pg_restore lists and prints the grants of \$DB/grants.restore; each fails with its switch" {
  printf '%s\n' reporting_ro auditor >"$DB/grants.restore"
  run bash -c 'printf dump | docker compose -p custodexa exec -T postgres pg_restore -l'
  [ "$status" -eq 0 ] && [ "$(printf '%s\n' "$output" | grep -c ' ACL ')" = 2 ] || { echo "$output"; return 1; }
  run bash -c 'printf dump | docker compose -p custodexa exec -T postgres pg_restore -L /tmp/l -f -'
  [ "$status" -eq 0 ] && [[ $output == *"TO reporting_ro;"* && $output == *"TO auditor;"* ]] || { echo "$output"; return 1; }
  rm "$DB/grants.restore"
  run bash -c 'printf dump | docker compose -p custodexa exec -T postgres pg_restore -L /tmp/l -f -'
  [ "$status" -eq 0 ] && [ -z "$output" ] || return 1
  printf '1\n' >"$DB/pg_restore.rc"
  run bash -c 'printf dump | docker compose -p custodexa exec -T postgres pg_restore -l'
  [ "$status" -eq 1 ] || return 1
  run bash -c 'printf dump | docker compose -p custodexa exec -T postgres pg_restore -L /tmp/l -f -'
  [ "$status" -eq 1 ]
}

@test "fixture: the seal status answers sealed, unsealed with an ID, unsealed without one, or cannot be read" {
  local q=(compose -p custodexa exec -T backend wget -qO- http://localhost:8080/api/v1/seal/status)
  printf 'sealed\n' >"$DB/seal"; dk "${q[@]}"
  [ "$status" -eq 0 ] && [[ $output == *'"instance_guard":{"peers":0,"state":"held"},"mode":"ui","state":"sealed"}' && $output != *kek_id* ]] || return 1
  printf 'unsealed\n' >"$DB/seal"; dk "${q[@]}"
  [ "$status" -eq 0 ] && [[ $output == *'"kek_id":"5a5a5a5a5a5a5a5a","mode":"env","state":"unsealed"}' ]] || return 1
  printf 'unsealed-noid\n' >"$DB/seal"; dk "${q[@]}"
  [ "$status" -eq 0 ] && [[ $output == *'"mode":"env","state":"unsealed"}' && $output != *kek_id* ]] || return 1
  printf 'unreadable\n' >"$DB/seal"; dk "${q[@]}"
  [ "$status" -ne 0 ] || return 1
  rm "$DB/seal"; dk "${q[@]}"
  [ "$status" -ne 0 ]
}

@test "fixture: each container's state follows stop, start, up and create; up -d postgres starts it alone and can fail" {
  st() { cat "$DB/ctr/$1"; }
  dk compose -p custodexa stop backend frontend guacd
  [ "$status" -eq 0 ] && [ "$(st backend)" = stopped ] && [ "$(st postgres)" = stopped ] || return 1
  dk compose -p custodexa up -d postgres
  [ "$status" -eq 0 ] && [ "$(st postgres)" = running ] && [ "$(st backend)" = stopped ] || return 1
  grep -qx 'up postgres' "$DB/events" || return 1
  printf 'running\n' >"$DB/ctr/postgres"; printf 'stopped\n' >"$DB/ctr/backend"
  printf '1\n' >"$DB/up.rc"
  dk compose -p custodexa up -d postgres
  [ "$status" -eq 1 ] || return 1
  rm "$DB/up.rc"
  dk compose -p custodexa start backend frontend guacd
  [ "$status" -eq 0 ] && [ "$(st backend)" = running ] || return 1
  rs_new_host
  [ -z "$(ls "$DB/ctr")" ] || return 1
  dk compose -p custodexa create
  [ "$status" -eq 0 ] && [ "$(st postgres)" = created ] && [ "$(st frontend)" = created ]
}

@test "fixture: curl downloads a release asset, answers 404 for a missing one, fails to connect when offline" {
  printf 'pkg\n' >"$DB/curl/custodexa-1.16.0.tar.gz"
  run curl -fsSL -o "$BATS_TEST_TMPDIR/p" -w '%{http_code}' https://github.com/x/releases/download/v1.16.0/custodexa-1.16.0.tar.gz
  [ "$status" -eq 0 ] && [ "$output" = 200 ] && cmp "$BATS_TEST_TMPDIR/p" "$DB/curl/custodexa-1.16.0.tar.gz" || return 1
  run curl -sSL -o "$BATS_TEST_TMPDIR/q" -w '%{http_code}' https://github.com/x/releases/download/v1.16.1/custodexa-1.16.1.tar.gz
  [ "$status" -eq 0 ] && [ "$output" = 404 ] && [ ! -e "$BATS_TEST_TMPDIR/q" ] || return 1
  printf 'custodexa-1.16.0.tar.gz\n' >"$DB/curl.404"
  run curl -fsSL -o "$BATS_TEST_TMPDIR/q" https://github.com/x/releases/download/v1.16.0/custodexa-1.16.0.tar.gz
  [ "$status" -eq 22 ] || return 1
  : >"$DB/curl.offline"
  run curl -sSL -o "$BATS_TEST_TMPDIR/q" -w '%{http_code}' https://github.com/x/custodexa-1.16.0.tar.gz
  [ "$status" -eq 7 ] && [[ $output == *000 ]]
}

@test "fixture: an injected failure fires before or after its call, once; a signal reaches the script" {
  printf '%s\n' 'before *stop* 4' 'after *start* 5' >"$DB/inject"
  dk compose -p custodexa stop backend
  [ "$status" -eq 4 ] && [ "$(cat "$DB/ctr/backend")" = running ] || return 1
  dk compose -p custodexa stop backend
  [ "$status" -eq 0 ] && [ "$(cat "$DB/ctr/backend")" = stopped ] || return 1
  dk compose -p custodexa start backend
  [ "$status" -eq 5 ] && [ "$(cat "$DB/ctr/backend")" = running ] || return 1
  printf '%s\n' 'before *custodexa-1.16.0.tar.gz* 6' >"$DB/inject"
  run curl -o "$BATS_TEST_TMPDIR/p" https://x/custodexa-1.16.0.tar.gz
  [ "$status" -eq 6 ] || return 1
  # A script named custodexa.sh gets the signal while its docker call runs.
  mkdir -p "$BATS_TEST_TMPDIR/s"
  printf '%s\n' '#!/bin/bash' 'trap "echo got-term; exit 9" TERM' 'docker compose -p custodexa stop backend' 'echo no-signal' \
    >"$BATS_TEST_TMPDIR/s/custodexa.sh"
  printf '%s\n' 'before *stop* TERM' >"$DB/inject"
  run bash "$BATS_TEST_TMPDIR/s/custodexa.sh"
  [ "$status" -eq 9 ] && [[ $output == *got-term* ]] || { echo "$status $output"; return 1; }
  grep -q 'inject before' "$DB/events"
}

@test "fixture: each docker call records the arguments and environment of the script's processes" {
  # shellcheck disable=SC2016
  printf '%s\n' '#!/bin/bash' 'export RS_MARK_ENV=env-mark-1' 'docker compose -p custodexa stop backend' \
    >"$BATS_TEST_TMPDIR/custodexa.sh"
  run bash "$BATS_TEST_TMPDIR/custodexa.sh" arg-mark-2
  [ "$status" -eq 0 ] || return 1
  grep -q 'arg-mark-2' "$DB/proc.seen" && grep -qx 'RS_MARK_ENV=env-mark-1' "$DB/proc.seen"
}

@test "fixture: the external backups are the producer's: the server's major and its client, the CA file, a client certificate without its key, the recorded roles" {
  local f n m u=$BATS_TEST_TMPDIR/u
  for n in ext16 extca extcert extgrants; do
    f=$(rs_fix "$n") || return 1
    (cd "${f%/*}" && /usr/bin/sha256sum -c --quiet "${f##*/}.sha256") || { echo "$n: checksum file"; return 1; }
    [ "$(mf "$f" db.location)" = external ] && [ "$(mf "$f" product.version)" = "$RS_VERSION" ] || { echo "$n"; return 1; }
    [[ " $(mf "$f" deploy.overlays) " == *" external-database "* ]] || return 1
  done
  f=$(rs_fix ext16)
  [ "$(mf "$f" db.server_major)" = 16 ] && [ "$(mf "$f" tool.dump_image)" = pgclient16 ] || return 1
  [ "$(mf "$f" db.tls_trust)/$(mf "$f" db.tls_verify)" = system/full ] && [ "$(mf "$f" contents.db_ca)" = false ] || return 1
  [ "$(mf "$(rs_fix external)" db.server_major)" = 17 ] || return 1
  f=$(rs_fix extca)
  [ "$(mf "$f" db.server_major)" = 17 ] && [ "$(mf "$f" tool.dump_image)" = pgclient17 ] || return 1
  [ "$(mf "$f" db.tls_trust)/$(mf "$f" db.tls_verify)" = file/full ] && [ "$(mf "$f" contents.db_ca)" = true ] || return 1
  /usr/bin/tar -xOf "$f" db-ca.pem | grep -qx 'cnMtdGVzdC1jYQ==' || return 1
  f=$(rs_fix extcert)
  [ "$(mf "$f" db.tls_client_cert)" = true ] || return 1
  rs_unpack "$f" "$u" || return 1
  ! grep -rqa 'rs-test-client-key-0005' "$u" || { echo "the client key is in a member"; return 1; }
  for m in "$u"/*.tar.gz; do
    ! /usr/bin/tar -xzOf "$m" | grep -qa 'rs-test-client-key-0005' || { echo "the client key is in $m"; return 1; }
  done
  f=$(rs_fix extgrants)
  [ "$(mf "$f" db.server_major)" = 16 ] || return 1
  [ "$(mf "$f" db.extra_grant_roles_hex)" = "$(bk_hex auditor_ro) $(bk_hex 'report reader')" ]
}

@test "fixture: the external database's client answers the restore's queries from \$DB; any other query exits 99" {
  rs_ext_host
  backup_strict
  local id=${BK_PGC_DIGEST[17]} s
  q() { run docker run --rm --pull never --network host --entrypoint psql "$id" -AtX -v ON_ERROR_STOP=1 -d "host='db.example.internal'" -c "$1"; }
  for s in 'SELECT 42' 'SELECT oid FROM pg_class' "SELECT rolname FROM pg_authid"; do
    q "$s"
    [ "$status" -eq 99 ] || { echo "$s: $status $output"; return 1; }
  done
  printf '%s\n' '10.0.0.12 custodexa-backend' '10.0.0.12 custodexa-backend' >"$DB/activity.1"
  printf '%s\n' '- psql' >"$DB/activity"
  q "SELECT coalesce(host(client_addr), '') FROM pg_stat_activity"
  [ "$status" -eq 0 ] && [ "$output" = "10.0.0.12|$(bk_hex custodexa-backend)"$'\n'"10.0.0.12|$(bk_hex custodexa-backend)" ] || { echo "$output"; return 1; }
  q "SELECT coalesce(host(client_addr), '') FROM pg_stat_activity"
  [ "$status" -eq 0 ] && [ "$output" = "|$(bk_hex psql)" ] || { echo "$output"; return 1; }
  printf '%s\n' auditor_ro postgres >"$DB/roles"
  q "SELECT x FROM pg_roles WHERE h IN ('$(bk_hex auditor_ro)', '$(bk_hex 'report reader')')"
  [ "$status" -eq 0 ] && [ "$output" = "$(bk_hex auditor_ro)" ] || { echo "$output"; return 1; }
  printf 'public|report_cache|analyst\n' >"$DB/foreign"
  q "SELECT 1 AS obj_owner"
  [ "$status" -eq 0 ] && [ "$output" = "$(bk_hex public)|$(bk_hex report_cache)|$(bk_hex analyst)" ] || return 1
  q "SELECT 1 AS obj_count"
  [ "$status" -eq 0 ] && [ -z "$output" ] || return 1
  printf 'public|214\n' >"$DB/objects"
  q "SELECT 1 AS obj_count"
  [ "$status" -eq 0 ] && [ "$output" = "$(bk_hex public)|214" ] || return 1
  grep -qx "none $id psql activity" "$DB/db-runs" || return 1
  printf '2\n' >"$DB/connect.rc"
  q "SELECT coalesce(host(client_addr), '') FROM pg_stat_activity"
  [ "$status" -eq 2 ]
}

@test "fixture: pg_restore -f writes its file into the mounted folder, and can stop after any byte with an exit code or a signal" {
  rs_ext_host
  backup_strict
  local id=${BK_PGC_DIGEST[17]} w=$BATS_TEST_TMPDIR/w act want
  mkdir -p "$w"
  pr() { run docker run --rm --pull never --network none -v "$w:/w" --entrypoint pg_restore "$id" -f /w/body.sql -L /w/list /w/db.dump; }
  pr
  [ "$status" -eq 0 ] || return 1
  grep -qx '\\restrict 0f1e2d3c4b5a' "$w/body.sql" && [ "$(tail -n 1 "$w/body.sql")" = '\unrestrict 0f1e2d3c4b5a' ] || { cat "$w/body.sql"; return 1; }
  cp "$w/body.sql" "$BATS_TEST_TMPDIR/full"
  grep -qx 'pg_restore file' "$DB/events" || return 1
  printf 'GRANT SELECT ON TABLE public.t TO x;\n' >"$DB/pg_restore.out"
  pr
  [ "$status" -eq 0 ] && cmp "$w/body.sql" "$DB/pg_restore.out" || return 1
  rm "$DB/pg_restore.out"
  for act in '40 1' '40 TERM' '120 KILL' '0 3'; do
    printf '%s\n' "$act" >"$DB/pg_restore.cut"
    rm -f "$w/body.sql"
    pr
    case ${act#* } in TERM) want=143 ;; KILL) want=137 ;; *) want=${act#* } ;; esac
    [ "$status" -eq "$want" ] && [ "$(stat -c %s "$w/body.sql")" = "${act% *}" ] || { echo "$act: $status"; return 1; }
    cmp -n "${act% *}" "$w/body.sql" "$BATS_TEST_TMPDIR/full" || return 1
  done
}
