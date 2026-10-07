# shellcheck shell=bash
# about: an encrypted backup of a built-in deployment on host a restores on host b, a new host without network that gets only the file, its .sha256, the package and the offline bundle: the rows, migrations and active master key equal a's; master key mode env holds the backup's key, mode ui waits sealed (exit 4), stays there after a wrong key is refused, and finishes once the right key is entered; b's server certificate names b and is issued by a's certificate authority; a's own proxy template, in a folder b does not have, is put at the path --nginx-template gives, .env points at it and b's proxy loads it; the recordings a's database lists are named as missing
# needs: package local-versions
# hosts: a b
# images:

readonly NH_V=1.16.90 NH_T=/transfer NH_PASS=it-new-host-passphrase-0007
# a's own proxy template is in a folder b does not have, so b names another path (--nginx-template).
readonly NH_TPL_A=/etc/custodexa/nginx-tls.conf.template NH_TPL_B=/opt/custodexa/custom/proxy.conf.template
readonly NH_TPL_MARK="the proxy template of host a"

# nh_openssl <args...>: openssl of the deployment's own image, tls/ of the deployment at /t.
nh_openssl() {
  local id
  id=$(lv_st current.image_ids | tr ' ' '\n' | sed -n 's/^openssl=//p')
  docker run --rm --network none -v "$LV_ROOT/tls:/t:ro" --entrypoint openssl "$id" "$@"
}

# nh_recordings <label> <n>: n sessions with a recording, their files in the recordings folder.
nh_recordings() {
  local i
  for ((i = 1; i <= $2; i++)); do
    install -m 640 -o 1000 -g 0 /dev/null "$LV_ROOT/data/recordings/it-$1-$i.cast"
    head -c 4096 /dev/urandom >"$LV_ROOT/data/recordings/it-$1-$i.cast"
  done
  lv_sql "INSERT INTO sessions (session_id, status, protocol, user_id, asset_id, start_time, has_recording, recording_path, created_at, updated_at)
    SELECT 'it-$1-' || g, 'closed', 'ssh', u.id, a.id, now(), true, '/var/lib/custodexa/recordings/it-$1-' || g || '.cast', now(), now()
    FROM generate_series(1, $2) g, (SELECT id FROM users WHERE username = 'it-$1') u, (SELECT id FROM assets WHERE name = 'it-$1') a" >/dev/null
  it_same "$1: the database lists $2 recordings" "$2" "$(lv_sql 'SELECT count(*) FROM sessions WHERE has_recording')"
}

# nh_take <label>: on a, the encrypted backup and what b compares with, into the transfer volume.
nh_take() {
  local label=$1 pf=$IT_WORK/pass
  (umask 077 && printf '%s\n' "$NH_PASS" >"$pf")
  ri_backup "$label" --passphrase-file "$pf"
  it_check "$label: the file is encrypted" test "${RI_FILE##*.}" = enc
  mkdir -p "$NH_T/$label"
  cp "$RI_FILE" "$RI_FILE.sha256" "$NH_T/$label/"
  # a's snapshot: the one in the file, opened with the deployment's openssl as the guide does.
  docker run --rm -i --network none -v "${RI_FILE%/*}:/b:ro" -v "$IT_WORK:/p:ro" --entrypoint openssl \
    "$(lv_st current.image_ids | tr ' ' '\n' | sed -n 's/^openssl=//p')" enc -d -aes-256-cbc -saltlen 8 -pbkdf2 -md sha256 \
    -iter 600000 -pass file:/p/pass -in "/b/${RI_FILE##*/}" >"$IT_WORK/$label.plain.tar"
  tar -xOf "$IT_WORK/$label.plain.tar" snapshot.txt >"$NH_T/$label/snapshot"
  tar -xOf "$IT_WORK/$label.plain.tar" backup-manifest.json >"$NH_T/$label/manifest"
  it_check "$label: the file's snapshot.txt is read on a" grep -q '^count\.users=' "$NH_T/$label/snapshot"
  lv_sql "SELECT DISTINCT kek_id FROM data_keys WHERE status = 'active' ORDER BY 1" >"$NH_T/$label/kek_id"
  lv_sql 'SELECT count(*) FROM sessions WHERE has_recording' >"$NH_T/$label/recordings"
  nh_openssl x509 -in /t/ca-public/custodexa-ca.crt -noout -subject >"$NH_T/$label/ca-subject"
  sha256sum <"$LV_ROOT/tls/ca-public/custodexa-ca.crt" | cut -c1-64 >"$NH_T/$label/ca-sha"
  [ ! -s "$IT_WORK/lv-admin-password" ] || cp "$IT_WORK/lv-admin-password" "$NH_T/$label/admin-password"
  it_say "   $label: $(sed -n 's/^count\.//p' "$NH_T/$label/snapshot" | paste -sd ' ' -), active key $(cat "$NH_T/$label/kek_id"), $(cat "$NH_T/$label/recordings") recordings"
}

scenario_a() {
  it_step "env: install on a, data, two recordings, encrypted backup"
  lv_install "$NH_V"
  hostname >"$NH_T/a-hostname"
  find "$LV_ROOT/tls" -type f -printf "   a tls: %P %s\n" | sort
  it_step "env: a's own proxy template, TLS_NGINX_TEMPLATE=$NH_TPL_A"
  ri_template "$NH_TPL_A" "$NH_TPL_MARK"
  ri_apply template
  it_same "a's running proxy loaded it (nginx -T)" yes "$(ri_nginx_has "$NH_TPL_MARK")"
  ri_data a-env
  nh_recordings a-env 2
  nh_take env
  ri_sha "$NH_TPL_A" >"$NH_T/env/template-sha"
  it_same "env: the backup holds the template and its path on a" "true $NH_TPL_A" \
    "$(jq -r '."contents.nginx_template" + " " + ."source.tls_nginx_template"' "$NH_T/env/manifest")"
  it_same "env: the template in the backup is a's (sha256)" "$(cat "$NH_T/env/template-sha")" \
    "$(tar -xOf "$IT_WORK/env.plain.tar" nginx-tls.conf.template | sha256sum | cut -c1-64)"
  rm -f "$IT_WORK/env.plain.tar"

  it_step "ui: a new deployment on a, the key entered in the browser, data, encrypted backup"
  ex_teardown "$LV_ROOT"
  rm -f "$IT_WORK/lv-admin-password"
  ri_ui_install "$NH_V"
  it_same "the backend waits sealed" sealed "$(ri_seal_state)"
  head -c 24 /dev/urandom | base64 | tr '+/' 'xy' >"$NH_T/ui-material"
  ri_unseal "$(cat "$NH_T/ui-material")" init
  it_same "the first unseal is accepted" 200 "$RI_HTTP"
  lv_until "the backend is unsealed" ri_is_unsealed || true
  it_same "seal/status" unsealed "$(ri_seal_state)"
  ri_data a-ui
  nh_recordings a-ui 3
  nh_take ui
  rm -f "$IT_WORK/ui.plain.tar"
}

# nh_new_host: b as a new host: no deployment, the package unpacked, the offline bundle loaded.
nh_new_host() {
  local n ref id
  ex_teardown "$LV_ROOT"
  rm -f "$IT_WORK/lv-admin-password"
  it_unpack /opt "$NH_V"
  lv_cx load load "$(it_bundle_file "$NH_V")"
  it_same "load of the offline bundle exits 0" 0 "$LV_RC"
  # What the restore has to recognise: an image a bundle loads on this store has an ID of its own.
  for n in openssl postgres; do
    ref=$(jq -r ".images.$n.ref + \":\" + .images.$n.tag" "$LV_ROOT/current/MANIFEST.json")
    id=$(docker image inspect --format '{{.Id}}' "$ref" 2>/dev/null || true)
    it_say "   $n: $ref has ID $id; index digest $(jq -r ".images.$n.index_digest" "$LV_ROOT/current/MANIFEST.json"); recorded by load: $(lv_st load.image_ids | tr ' ' '\n' | sed -n "s/^$n=//p")"
  done
}

# nh_restore <label> [expected exit] [more arguments]: restore on b as a host without network does
# it, with the command backup-and-restore.md §5 gives for a new host without a terminal.
nh_restore() {
  local label=$1 want=${2:-0} pf=$IT_WORK/pass
  shift
  [ $# -eq 0 ] || shift
  (umask 077 && printf '%s\n' "$NH_PASS" >"$pf")
  # The cutoff for the backend's own audit rows (lib/restore.sh); no database here yet, the clock is
  # the one the database containers read.
  RI_T0="$(date -u '+%Y-%m-%d %H:%M:%S.%6N')+00"
  ri_doc "$label" restore "$(find "$NH_T/$label" -name 'custodexa-backup-*.tar.enc')" --new-host --yes \
    --passphrase-file "$pf" --package "$(it_package_file "$NH_V")" --images "$(it_bundle_file "$NH_V")" "$@"
  it_same "$label: restore exits $want" "$want" "$LV_RC"
}

# nh_same_as_a <label>: rows, migrations, active key, certificate and recordings as on a.
nh_same_as_a() {
  local label=$1 host fp list san
  cp "$NH_T/$label/snapshot" "$IT_WORK/$label.snapshot"
  ri_snap_same "$label: rows, migrations and key fingerprints equal the snapshot a's backup holds" "$label"
  it_same "$label: the active master key identity equals a's" "$(cat "$NH_T/$label/kek_id")" \
    "$(lv_sql "SELECT DISTINCT kek_id FROM data_keys WHERE status = 'active' ORDER BY 1")"
  fp=$(sed -n 's/^fp\.kek=//p' "$NH_T/$label/snapshot")
  it_same "$label: the backup's master key fingerprint is the one the restore recorded" "$fp" "$(lv_st last_restore.kek_fingerprint)"
  it_same "$label: the backend reports that master key (seal/status kek_id)" "$fp" "$(ri_kek_id)"
  host=$(hostname)
  find "$LV_ROOT/tls" -type f -printf "   b tls: %P %s\n" | sort
  san=$(nh_openssl x509 -in /t/fullchain.pem -noout -ext subjectAltName)
  it_say "   $label: $(tr -s ' \n' ' ' <<<"$san")"
  it_check "$label: b's server certificate names b ($host)" grep -q "DNS:$host\(,\|$\)" <<<"$san"
  it_same "$label: it is issued by a's certificate authority" "$(sed 's/^subject/issuer/' "$NH_T/$label/ca-subject")" \
    "$(nh_openssl x509 -in /t/fullchain.pem -noout -issuer)"
  it_same "$label: the authority is a's, unchanged" "$(cat "$NH_T/$label/ca-sha")" "$(sha256sum <"$LV_ROOT/tls/ca-public/custodexa-ca.crt" | cut -c1-64)"
  it_check "$label: the certificate verifies against it" nh_openssl verify -CAfile /t/ca-public/custodexa-ca.crt /t/fullchain.pem
  list=$(find "$LV_ROOT/restore" -name missing-recordings.txt | head -n1)
  it_check "$label: the list of missing recordings is kept ($list)" test -f "$list"
  it_same "$label: it names as many recordings as a's database lists" "$(cat "$NH_T/$label/recordings")" "$(grep -c . "$list")"
  ri_running_same "$label"
}

scenario_b() {
  it_check "b has no route anywhere" bash -c '! ip route | grep -q default'
  it_check "b is another host" test "$(hostname)" != "$(cat "$NH_T/a-hostname")"

  it_step "env: restore on the new host b"
  nh_new_host
  it_check "b has no ${NH_TPL_A%/*}/, the folder of a's proxy template" test ! -e "${NH_TPL_A%/*}"
  mkdir -p "${NH_TPL_B%/*}"
  nh_restore env 0 --nginx-template "$NH_TPL_B"
  it_same "last_restore.result" succeeded "$(lv_st last_restore.result)"
  lv_wait_version "$NH_V"
  nh_same_as_a env
  it_same "env: a's proxy template is at the path given, the same file (sha256)" "$(cat "$NH_T/env/template-sha")" \
    "$(ri_sha "$NH_TPL_B")"
  it_same "env: .env points at it (TLS_NGINX_TEMPLATE)" "$NH_TPL_B" "$(lv_env_get TLS_NGINX_TEMPLATE)"
  it_same "env: b's running proxy loaded it (nginx -T)" yes "$(ri_nginx_has "$NH_TPL_MARK")"

  it_step "ui: restore on the new host b, the backend waits sealed"
  nh_new_host
  cp "$NH_T/ui/admin-password" "$IT_WORK/lv-admin-password"
  nh_restore ui 4
  it_same "last_restore.result, phase" "in_progress awaiting_unseal" "$(lv_st last_restore.result) $(lv_st last_restore.phase)"
  it_same "seal/status" sealed "$(ri_seal_state)"
  ri_unseal "wrong-material-$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  it_check "a wrong key is refused by the backend (HTTP $RI_HTTP)" test "$RI_HTTP" -ge 400
  it_same "seal/status after the wrong key" sealed "$(ri_seal_state)"
  ri_doc resume-sealed restore --resume
  it_same "restore --resume while sealed exits 4" 4 "$LV_RC"
  it_check "the screen says it is still sealed" grep -q 'The system is still sealed, so the restore cannot finish yet' <<<"$LV_OUT"
  it_same "last_restore.result, phase are unchanged" "in_progress awaiting_unseal" "$(lv_st last_restore.result) $(lv_st last_restore.phase)"
  ri_unseal_after_backoff "$(cat "$NH_T/ui-material")"
  it_same "the right key is accepted" 200 "$RI_HTTP"
  lv_until "the backend is unsealed" ri_is_unsealed || true
  ri_doc resume restore --resume
  it_same "restore --resume exits 0" 0 "$LV_RC"
  it_same "last_restore.result" succeeded "$(lv_st last_restore.result)"
  nh_same_as_a ui
}
