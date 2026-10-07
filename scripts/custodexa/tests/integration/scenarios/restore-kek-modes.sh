# shellcheck shell=bash
# about: master key modes held outside the deployment, against the real backend: kms with a Vault (dev mode, image pinned by digest, TLS listener signed by a test CA): a restore waits for unseal (exit 4), and with the key service reachable and the same key it finishes with the runtime key ID equal to the backup's; with the key service unreachable, and with the same key name holding other material, the unseal fails, `restore --resume` stays waiting (exit 4) and `upgrade` is refused; ui: the wrong material does not let the restore finish
# needs: package local-versions
# images: vault openssl-3.5.4

readonly KM_V=1.16.90 KM_NEXT=1.16.91
readonly KM_VAULT=it-vault KM_ROOT_TOKEN=it-dev-root-token KM_KEY=custodexa-kek KM_ROLE=custodexa
readonly KM_ADDR=https://vault:8201
readonly KM_CA_CTR=/var/log/custodexa/audit/it-vault-ca.crt
KM_ROLE_ID="" KM_HTTP="" KM_BODY="" KM_NET=""

# ---- the key service ----

km_vx() { docker exec -i -e VAULT_ADDR=http://127.0.0.1:8200 -e "VAULT_TOKEN=$KM_ROOT_TOKEN" "$KM_VAULT" vault "$@"; }

# km_vault_start: a new dev-mode Vault (its storage is memory only, so a new one holds no key),
# listening with TLS on 8201 for the backend, plain HTTP on 8200 inside its container for setup.
km_vault_start() {
  local i
  mkdir -p "$IT_WORK/vault"
  cp "$IT_PKI/vault/vault.crt" "$IT_PKI/vault/vault.key" "$IT_WORK/vault/"
  chmod 644 "$IT_WORK/vault/vault.key" # read by the vault user of the image; a test key
  cat >"$IT_WORK/vault/tls.hcl" <<'EOF'
listener "tcp" {
  address       = "0.0.0.0:8201"
  tls_cert_file = "/it/vault.crt"
  tls_key_file  = "/it/vault.key"
}
disable_mlock = true
EOF
  docker rm -f "$KM_VAULT" >/dev/null 2>&1 || true
  docker run -d --name "$KM_VAULT" -v "$IT_WORK/vault:/it:ro" --entrypoint vault "$(it_image vault)" \
    server -dev "-dev-root-token-id=$KM_ROOT_TOKEN" -dev-listen-address=127.0.0.1:8200 -config=/it/tls.hcl >/dev/null
  for ((i = 0; i < 60; i++)); do
    km_vx status >/dev/null 2>&1 && return 0
    sleep 1
  done
  docker logs "$KM_VAULT" 2>&1 | tail -n 20
  it_die "Vault did not come up"
}

# km_vault_setup: the transit key, a policy for it alone and an AppRole (with KM_ROLE_ID when set,
# so a new Vault can carry the role ID the deployment's topology names).
km_vault_setup() {
  km_vx secrets enable transit >/dev/null
  km_vx write -f "transit/keys/$KM_KEY" type=aes256-gcm96 derived=true exportable=false allow_plaintext_backup=false >/dev/null
  km_vx auth enable approle >/dev/null
  km_vx policy write custodexa-transit - >/dev/null <<EOF
path "transit/keys/$KM_KEY" { capabilities = ["read"] }
path "transit/encrypt/$KM_KEY" { capabilities = ["update"] }
path "transit/decrypt/$KM_KEY" { capabilities = ["update"] }
path "transit/rewrap/$KM_KEY" { capabilities = ["update"] }
path "auth/token/renew-self" { capabilities = ["update"] }
EOF
  km_vx write "auth/approle/role/$KM_ROLE" bind_secret_id=true token_policies=custodexa-transit \
    token_no_default_policy=true token_ttl=10m token_max_ttl=60m >/dev/null
  if [ -n "$KM_ROLE_ID" ]; then
    km_vx write "auth/approle/role/$KM_ROLE/role-id" "role_id=$KM_ROLE_ID" >/dev/null
  else
    KM_ROLE_ID=$(km_vx read -field=role_id "auth/approle/role/$KM_ROLE/role-id")
  fi
  it_same "Vault holds the transit key $KM_KEY (derived)" true "$(km_vx read -format=json "transit/keys/$KM_KEY" | jq -r .data.derived)"
}

km_secret() { km_vx write -f -field=secret_id "auth/approle/role/$KM_ROLE/secret-id"; }

# km_vault_attach: the Vault on the deployment's network as "vault".
km_vault_attach() {
  KM_NET=$(docker inspect --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' custodexa-backend | awk '{print $1}')
  docker network disconnect "$KM_NET" "$KM_VAULT" >/dev/null 2>&1 || true
  docker network connect --alias vault "$KM_NET" "$KM_VAULT"
}

# ---- the seal endpoints, as the unseal page uses them ----

km_admin_pw() { lv_env_get ADMIN_INITIAL_PASSWORD; }

# km_post <path> <json> [grant]: KM_HTTP (status), KM_BODY (response).
km_post() {
  local ip
  local -a auth=()
  ip=$(lv_backend_ip)
  [ -z "${3:-}" ] || auth=(-H "Authorization: SealGrant $3")
  KM_BODY=$(curl -sS --max-time 30 -o - -w '\n%{http_code}' -H 'Content-Type: application/json' \
    ${auth[@]+"${auth[@]}"} -d "$2" "http://$ip:8080/api/v1$1") || true
  KM_HTTP=${KM_BODY##*$'\n'}
  KM_BODY=${KM_BODY%$'\n'*}
}

km_status() { curl -fsS --max-time 10 "http://$(lv_backend_ip):8080/api/v1/seal/status"; }
km_state() { km_status | jq -r '.state // empty' 2>/dev/null || true; }
km_kek_id() { km_status | jq -r '.kek_id // empty' 2>/dev/null || true; }

# km_unseal <label> <json without the grant>: authorize as the administrator, then unseal.
# KM_DIGEST is the topology digest the authorization returned (kms).
km_unseal() {
  local label=$1 body=$2 grant i
  lv_until "$label: the backend answers the seal status" km_status
  # A refused attempt makes the backend wait before it takes the next one from the same source
  # (HTTP 429); as an operator would, try again after a pause.
  for ((i = 0; i < 12; i++)); do
    km_post /seal/authorize "$(jq -cn --arg p "$(km_admin_pw)" '{username: "admin", password: $p}')"
    it_same "$label: seal/authorize HTTP" 200 "$KM_HTTP"
    grant=$(jq -r '.grant' <<<"$KM_BODY")
    KM_DIGEST=$(jq -r '.topology_digest // empty' <<<"$KM_BODY")
    km_post /seal/unseal "$(jq -c --arg d "$KM_DIGEST" 'if has("topology_digest") then .topology_digest = $d else . end' <<<"$body")" "$grant"
    it_say "   $label: seal/unseal HTTP $KM_HTTP $(jq -c '{code: (.code // .error // null)}' <<<"$KM_BODY" 2>/dev/null)"
    [ "$KM_HTTP" = 429 ] || return 0
    sleep 5
  done
}

km_is_unsealed() { [ "$(km_state)" = unsealed ]; }

# ---- the restore ----

km_manifest() { tar -xOf "$1" backup-manifest.json | jq -r --arg k "$2" '.[$k]'; }

# km_wait <label> <backup>: restore of that backup on this host stops waiting for unseal.
km_wait() {
  lv_cx "$1" restore "$2" --same-host --yes --confirm-data-loss
  it_same "$1: restore exits 4 (waiting for unseal)" 4 "$LV_RC"
  it_check "$1: the screen says it waits for unseal" grep -qF 'waiting for' <<<"$LV_OUT"
  it_same "$1: last_restore.phase" awaiting_unseal "$(lv_st last_restore.phase)"
  it_same "$1: the backend is sealed" sealed "$(km_state)"
}

# km_not_done <label>: --resume stays waiting (exit 4, still sealed), and upgrade is refused.
km_not_done() {
  local label=$1 ps0
  lv_cx "$label-resume" restore --resume
  it_same "$label: restore --resume exits 4" 4 "$LV_RC"
  it_check "$label: the screen says it is still sealed" grep -qF 'The system is still sealed, so the restore cannot finish yet.' <<<"$LV_OUT"
  it_same "$label: last_restore.phase, result" "awaiting_unseal in_progress" "$(lv_st last_restore.phase) $(lv_st last_restore.result)"
  it_same "$label: no runtime key ID recorded" "" "$(lv_st last_restore.kek_evidence)"
  ps0=$(lv_ps)
  lv_cx "$label-upgrade" upgrade "$(it_package_file "$KM_NEXT")" --images "$(it_bundle_file "$KM_NEXT")" --yes
  it_check "$label: upgrade is refused (exit $LV_RC)" test "$LV_RC" -ne 0
  it_check "$label: the screen names the unfinished restore" grep -qi 'restore' <<<"$LV_OUT"
  it_same "$label: still $KM_V, the same containers" "$KM_V releases/$KM_V" "$(lv_st current.version) $(readlink "$LV_ROOT/current")"
  it_same "$label: the containers are unchanged" "$ps0" "$(lv_ps)"
}

# km_done <label> <backup>: --resume finishes; the ID read after unseal is the backup's.
km_done() {
  local label=$1 want
  want=$(km_manifest "$2" kek.fingerprint)
  lv_cx "$label-resume" restore --resume
  it_same "$label: restore --resume exits 0" 0 "$LV_RC"
  it_check "$label: the screen says the runtime ID $want matches" grep -qF "the ID read after unseal, $want, matches" <<<"$(tr '\n' ' ' <<<"$LV_OUT" | tr -s ' ')"
  it_same "$label: last_restore.result, phase, kek_evidence" "succeeded done runtime-id" \
    "$(lv_st last_restore.result) $(lv_st last_restore.phase) $(lv_st last_restore.kek_evidence)"
  it_same "$label: /seal/status kek_id equals the backup's kek.fingerprint" "$want" "$(km_kek_id)"
}

km_backup() {
  lv_cx backup backup --yes
  it_same "backup exits 0" 0 "$LV_RC"
  KM_FILE=$LV_ROOT/$(lv_st last_backup.file)
  it_check "the backup file exists" test -f "$KM_FILE"
}

scenario() {
  local id want
  it_step "a test CA and a certificate for vault; a dev-mode Vault with a TLS listener"
  it_pki_cert vault vault server DNS:vault
  km_vault_start
  km_vault_setup

  it_step "kms (Vault): install $KM_V, initialize through the unseal endpoint"
  it_unpack /opt "$KM_V"
  mkdir -p "$LV_ROOT/data/audit"
  cp "$IT_PKI/vault/ca.crt" "$LV_ROOT/data/audit/it-vault-ca.crt"
  # The backend's system trust (Go reads SSL_CERT_FILE): the test CA under the audit folder.
  ex_preset "$LV_ROOT" KEK_PROVIDER=kms KEK_KMS_PROVIDER=vault "SSL_CERT_FILE=$KM_CA_CTR"
  lv_cx install install --images "$(it_bundle_file "$KM_V")"
  it_same "install exits 0" 0 "$LV_RC"
  km_vault_attach
  km_unseal init "$(jq -cn --arg p "$(km_admin_pw)" --arg a "$KM_ADDR" --arg k "$KM_KEY" --arg r "$KM_ROLE_ID" \
    --arg s "$(km_secret)" '{username: "admin", password: $p, address: $a, transit_key_name: $k, role_id: $r, vault_secret_id: $s}')"
  it_same "init: unseal HTTP" 200 "$KM_HTTP"
  lv_until "init: unsealed" km_is_unsealed
  id=$(km_kek_id)
  it_check "init: the runtime key ID is the Vault reference ($id)" grep -qE '^vault:[A-Za-z0-9_-]+:transit:custodexa-kek$' <<<"$id"
  lv_wait_version "$KM_V"
  km_backup
  it_same "the backup: kek.provider, kek.fingerprint" "kms $id" "$(km_manifest "$KM_FILE" kek.provider) $(km_manifest "$KM_FILE" kek.fingerprint)"

  it_step "kms, round 1: the key service reachable, the same key"
  km_wait success "$KM_FILE"
  km_unseal success '{"vault_secret_id": "'"$(km_secret)"'", "topology_digest": ""}'
  it_same "success: unseal HTTP" 200 "$KM_HTTP"
  lv_until "success: unsealed" km_is_unsealed
  km_done success "$KM_FILE"

  it_step "kms, round 2: the key service unreachable"
  km_wait unreachable "$KM_FILE"
  docker network disconnect "$KM_NET" "$KM_VAULT"
  km_unseal unreachable '{"vault_secret_id": "'"$(km_secret)"'", "topology_digest": ""}'
  # The backend answers 502 only for failures it can tell apart as unreachable; any other failure of
  # the key service is answered as invalid material (400). Either way the unseal is refused.
  it_check "unreachable: unseal is refused (HTTP $KM_HTTP)" test "$KM_HTTP" -ge 400
  it_same "unreachable: the backend stays sealed" sealed "$(km_state)"
  km_not_done unreachable
  it_step "kms, round 2: the key service back, the same restore finishes"
  docker network connect --alias vault "$KM_NET" "$KM_VAULT"
  km_unseal unreachable-back '{"vault_secret_id": "'"$(km_secret)"'", "topology_digest": ""}'
  it_same "unreachable-back: unseal HTTP" 200 "$KM_HTTP"
  lv_until "unreachable-back: unsealed" km_is_unsealed
  km_done unreachable-back "$KM_FILE"

  it_step "kms, round 3: the same key name in a new Vault, other key material"
  km_wait mismatch "$KM_FILE"
  km_vault_start
  km_vault_setup
  km_vault_attach
  km_unseal mismatch '{"vault_secret_id": "'"$(km_secret)"'", "topology_digest": ""}'
  it_check "mismatch: unseal is refused (HTTP $KM_HTTP)" test "$KM_HTTP" -ge 400
  it_same "mismatch: the backend stays sealed" sealed "$(km_state)"
  km_not_done mismatch
  docker rm -f "$KM_VAULT" >/dev/null

  it_step "ui: install $KM_V, initialize with material only the operator holds"
  ex_teardown "$LV_ROOT"
  it_unpack /opt "$KM_V"
  ex_preset "$LV_ROOT" KEK_PROVIDER=ui
  lv_cx install install --images "$(it_bundle_file "$KM_V")"
  it_same "install exits 0" 0 "$LV_RC"
  local kek wrong
  kek=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
  wrong=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
  km_unseal ui-init "$(jq -cn --arg p "$(km_admin_pw)" --arg k "$kek" \
    '{kek: $k, kek_confirm: $k, confirm_saved: true, username: "admin", password: $p}')"
  it_same "ui-init: unseal HTTP" 200 "$KM_HTTP"
  lv_until "ui-init: unsealed" km_is_unsealed
  want=$(km_kek_id)
  lv_wait_version "$KM_V"
  km_backup
  it_same "the backup: kek.provider, kek.fingerprint" "ui $want" "$(km_manifest "$KM_FILE" kek.provider) $(km_manifest "$KM_FILE" kek.fingerprint)"
  km_wait ui "$KM_FILE"
  km_unseal ui-wrong "$(jq -cn --arg k "$wrong" '{kek: $k}')"
  it_check "ui-wrong: unseal with the wrong material is refused (HTTP $KM_HTTP)" test "$KM_HTTP" -ge 400
  it_same "ui-wrong: the backend stays sealed" sealed "$(km_state)"
  km_not_done ui-wrong
  it_step "ui: the right material finishes the same restore"
  km_unseal ui-right "$(jq -cn --arg k "$kek" '{kek: $k}')"
  it_same "ui-right: unseal HTTP" 200 "$KM_HTTP"
  lv_until "ui-right: unsealed" km_is_unsealed
  km_done ui-right "$KM_FILE"
}
