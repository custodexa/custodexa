# shellcheck shell=bash
# about: the restore procedure of the operations guide (docs/ops/backup-and-restore.md, sections 5.2 and 5, and the passphrase checks of 3.8), taken from the guide at run time and run as written on real backup files: an unencrypted one in place, an encrypted one on a fresh install; the database comes back equal to snapshot.txt and the service starts with the restored master key
# needs: package
# images:

readonly DC_DOC=/src/docs/ops/backup-and-restore.md
readonly DC_PASS='it-test-only passphrase 0008'

# dc_block <first heading> <next heading> <n>: the n-th (from 1) bash code block between two
# headings of the guide, as written.
dc_block() {
  awk -v a="$1" -v b="$2" -v n="$3" '
    index($0, a) == 1 { on = 1; next }
    on && index($0, b) == 1 { exit }
    on && /^```bash$/ { k++; if (k == n) { inb = 1; next } }
    inb && /^```$/ { exit }
    inb { print }
  ' "$DC_DOC"
}

# dc_guide <encrypted: 0|1>: the blocks of one restore as the guide has them: 5.2 (the first block,
# the C block for that kind of file, the last block), then section 5.
dc_guide() {
  dc_block '### 5.2' '## 6.' 1
  dc_block '### 5.2' '## 6.' $((2 + $1))
  dc_block '### 5.2' '## 6.' 4
  dc_block '## 5. Restore procedure' '### 5.1' 1
}

# dc_script <file> <stamp> <encrypted: 0|1> <hook>: the commands an operator types for one restore,
# in one shell. Changed from the guide, and only these:
#   "sudo -s" is left out (this runs as root already); FILE= and STAMP= get the actual values (the
#   guide says to fill them in); section 5 step 0's two assignments are skipped (the guide says
#   to); and before section 5 step 6 the hook takes the snapshot of the loaded database. Step 1
#   sets the old database aside with the guide's own commands.
dc_script() {
  local file=$1 stamp=$2 enc=$3 hook=$4
  # shellcheck disable=SC2016 # the added lines are written for the operator's shell
  dc_guide "$enc" | sed -e '/^sudo -s$/d' -e "s|^FILE=[^ ]*|FILE=$file|" -e "s|^STAMP=YYYYMMDD-HHMMSS|STAMP=$stamp|" \
    -e '/^STAMP=YYYYMMDD-HHMM$/d' -e '/^BACKUP_DIR=\.$/d' \
    -e "/^# 6\. Start the remaining services/i\\
# [not in the guide] the snapshot of the loaded database, before the other services start\\
bash $hook"
}

# dc_hook <label>: a script, run from the deployment folder, that takes the script's snapshot of the
# database the restore loaded, into $IT_WORK/<label>-restored.txt.
dc_hook() {
  local f=$IT_WORK/$1-hook.sh
  {
    printf '. /src/scripts/custodexa/tests/integration/lib/snap.sh\n'
    # shellcheck disable=SC2016 # expanded by the hook
    printf 'v() { sed -n "s/^[[:space:]]*$1=//p" .env | tail -n 1; }\n'
    # shellcheck disable=SC2016
    printf 'it_snap_take %q "$(v JWT_SECRET)" docker exec -i custodexa-postgres psql -U "$(v DB_USER)" -d "$(v DB_NAME)" -AtX -v ON_ERROR_STOP=1 -c\n' \
      "$IT_WORK/$1-restored.txt"
  } >"$f"
  printf '%s' "$f"
}

# dc_restore <label> <file, absolute> <stamp> <encrypted: 0|1>: the guide's procedure (the database
# compared with snapshot.txt before step 6), then the checks of section 6 that need no browser.
dc_restore() {
  local label=$1 file=$2 stamp=$3 enc=$4 root=/opt/custodexa bdir out rc in=/dev/null
  dc_script "$file" "$stamp" "$enc" "$(dc_hook "$label")" >"$IT_WORK/$label.sh"
  it_say "   the commands ($IT_WORK/$label.sh), as changed from the guide:"
  diff <(dc_guide "$enc") "$IT_WORK/$label.sh" | sed 's/^/     | /' || true
  if [ "$enc" = 1 ]; then
    printf '%s\n' "$DC_PASS" >"$IT_WORK/$label.stdin"
    in=$IT_WORK/$label.stdin
  fi
  (cd "$root" && bash "$IT_WORK/$label.sh" <"$in") >"$IT_WORK/$label.out" 2>&1 && rc=0 || rc=$?
  it_say "   their output (exit $rc, of the last command):"
  sed 's/^/     > /' "$IT_WORK/$label.out"
  bdir=$root/backups/restore-$stamp
  it_check "$label: 5.2 ends with '5.2: ready'" grep -qx '5.2: ready' "$IT_WORK/$label.out"
  it_check "$label: step D reported every member OK" \
    bash -c '[ "$(grep -c ": OK$" "$1")" -ge 9 ] && ! grep -q "FAILED" "$1"' _ "$IT_WORK/$label.out"
  it_check "$label: step E printed the version and the master key mode" \
    bash -c 'grep -q "\"product.version\"" "$1" && grep -q "\"kek.provider\": \"env\"" "$1"' _ "$IT_WORK/$label.out"
  it_check "$label: no command printed an error" \
    bash -c '! grep -Eiq "error|no such|not found|cannot|denied|failed|refused" "$1"' _ "$IT_WORK/$label.out"
  it_check "$label: step 1 set the database it found aside, and postgres started from an empty folder" \
    test -d "$root/data/postgres.before-restore-$stamp"
  it_same "$label: step 4 put the proxy template back where .env names it, as it was" \
    "$(sha256sum <"$IT_WORK/proxy.conf.template")" "$(sha256sum <"$root/custom/proxy.conf.template")"

  it_step "$label: the database loaded at section 5 step 5, against snapshot.txt"
  it_snap_same "$label: row counts, schema_migrations and the four fingerprints equal snapshot.txt" \
    "$bdir/snapshot.txt" "$IT_WORK/$label-restored.txt"
  it_same "$label: fp.kek equals the manifest's kek.fingerprint" \
    "$(jq -r '."kek.fingerprint"' "$bdir/backup-manifest.json")" "$(sed -n 's/^fp\.kek=//p' "$IT_WORK/$label-restored.txt")"
  it_same "$label: the restored .env is the backed-up one" \
    "$(sha256sum <"$bdir/custodexa-env-$stamp.bak")" "$(sha256sum <"$root/.env")"

  it_step "$label: section 6 items 1 to 4"
  dc_ready "$root"
  out=$(cd "$root" && set -a && . ./current/images.env && set +a && docker compose ps --format '{{.Service}} {{.State}} {{.Health}}')
  printf '%s\n' "$out" | sed 's/^/     1| /'
  it_check "$label: item 1, every service runs and postgres is healthy" \
    bash -c '! grep -v " running" <<<"$1" | grep -q . && grep -q "^postgres running healthy" <<<"$1"' _ "$out"
  out=$(cd "$root" && docker exec custodexa-backend wget -qO- http://localhost:8080/health 2>&1) || true
  it_say "     2| $out"
  it_check "$label: item 2, the backend health check answers" grep -q . <<<"$out"
  out=$(docker logs custodexa-backend 2>&1 | tail -50)
  it_check "$label: item 3, no refusal to start or master key mismatch in the backend log" \
    bash -c '! grep -Eiq "fatal|panic|mismatch|refus" <<<"$1"' _ "$out"
  out=$(curl -skI https://localhost/ 2>&1 | sed -n 1p) || true
  it_say "     4| curl -skI https://localhost/ : $out"
  it_check "$label: item 4, the frontend answers 200 through the built-in proxy" grep -q '^HTTP/[0-9.]* 200' <<<"$out"
  out=$(curl -sI http://localhost/ 2>&1 | sed -n 1p) || true
  it_say "     4| curl -I http://localhost/ : $out"
  it_check "$label: item 4, plain http answers 301 towards HTTPS, as the guide says" grep -q '^HTTP/[0-9.]* 301' <<<"$out"
  out=$(it_cx "$root" status --lang en) && rc=0 || rc=$?
  it_check "$label: the script's status after the restore reports no failure (exit $rc)" \
    test "$(grep -c '\[FAIL\]' <<<"$out")" = 0
  rm -rf "${bdir:?}"
}

# dc_ready <root>: the backend answers its health check (at most 3 minutes).
dc_ready() {
  local i
  for ((i = 0; i < 90; i++)); do
    docker exec custodexa-backend wget -qO- http://localhost:8080/health >/dev/null 2>&1 && return 0
    sleep 2
  done
}

# dc_check_38 <file, relative to the deployment folder>: "Checking a file and its passphrase" of
# 3.8: its first block, then each of its three commands, in one shell, as written.
dc_check_38() {
  local file=$1 root=/opt/custodexa n b out rc
  for n in 3 4 5; do
    {
      dc_block '#### Encrypting the backup file with a passphrase' '#### The backup an upgrade takes' 2 |
        sed "s|^FILE=[^ ]*|FILE=$file|"
      dc_block '#### Encrypting the backup file with a passphrase' '#### The backup an upgrade takes' "$n"
      printf 'echo "exit codes: ${PIPESTATUS[*]}"\n'
      printf 'unset CX_PASS\n'
    } >"$IT_WORK/check-$n.sh"
    b=$(dc_block '#### Encrypting the backup file with a passphrase' '#### The backup an upgrade takes' "$n" | sed -n 1p)
    out=$(cd "$root" && printf '%s\n' "$DC_PASS" | bash "$IT_WORK/check-$n.sh" 2>&1) && rc=0 || rc=$?
    it_say "   3.8 command $((n - 2)) of 3: ${b:0:100}..."
    printf '%s\n' "$out" | sed 's/^/     > /'
    it_check "3.8 command $((n - 2)): every stage exits 0 and tar lists the ten members" \
      test "$(grep -c '^exit codes: 0 0 0$' <<<"$out")" = 1 -a "$(grep -cE ' (backup-manifest\.json|release-MANIFEST\.json|tool-MANIFEST\.json|snapshot\.txt|db\.dump|audit\.tar\.gz|env\.bak|tls\.tar\.gz|nginx-tls\.conf\.template|SHA256SUMS)$' <<<"$out")" = 10
  done
}

dc_stamp() { sed -E 's/^custodexa-backup-[0-9.]+-([0-9]{8}-[0-9]{6})\.tar(\.enc)?$/\1/' <<<"$1"; }

scenario() {
  local root=/opt/custodexa plain enc ids
  it_step "built-in form, master key mode env: install --images $(it_bundle_file)"
  it_unpack /opt
  it_env_preset "$root" KEK_PROVIDER=env
  it_cx "$root" install --images "$(it_bundle_file)" >/dev/null
  install -m 600 -o root /dev/null "$IT_WORK/cx-pass"
  printf '%s\n' "$DC_PASS" >"$IT_WORK/cx-pass"
  it_step "the deployment's own proxy template (TLS_NGINX_TEMPLATE), a copy of the shipped one"
  mkdir -p "$root/custom"
  { cat "$root/current/reverse-proxy/nginx-tls.conf.template"; printf '# the deployment'"'"'s own copy\n'; } \
    >"$root/custom/proxy.conf.template"
  cp "$root/custom/proxy.conf.template" "$IT_WORK/proxy.conf.template"
  printf 'TLS_NGINX_TEMPLATE=./custom/proxy.conf.template\n' >>"$root/.env"

  it_step "two backups: unencrypted, and encrypted with a passphrase file"
  it_cx "$root" backup --lang en --yes >/dev/null
  it_cx "$root" backup --lang en --yes --passphrase-file "$IT_WORK/cx-pass" >/dev/null
  plain=$(cd "$root/backups" && find . -maxdepth 1 -name 'custodexa-backup-*.tar' -printf '%f')
  enc=$(cd "$root/backups" && find . -maxdepth 1 -name 'custodexa-backup-*.tar.enc' -printf '%f')
  it_say "   $plain, $enc"
  mkdir -p "$IT_WORK/keep"
  cp -p "$root/backups/$enc" "$root/backups/$enc.sha256" "$IT_WORK/keep/"

  it_step "3.8: the commands that check an encrypted file and its passphrase"
  dc_check_38 "backups/$enc"

  it_same "the backup holds the proxy template and the path .env gave" "true ./custom/proxy.conf.template" \
    "$(tar -xOf "$root/backups/$plain" backup-manifest.json | jq -r '."contents.nginx_template" + " " + ."source.tls_nginx_template"')"

  it_step "in place: the unencrypted file, restored on the host that made it (the proxy template deleted first)"
  rm -rf "$root/custom"
  dc_restore in-place "$root/backups/$plain" "$(dc_stamp "$plain")" 0

  it_step "another host: remove everything, install the same version afresh, restore the encrypted file kept outside the deployment folder"
  ids=$(docker ps -aq)
  # shellcheck disable=SC2086 # one ID per word
  [ -z "$ids" ] || docker rm -fv $ids >/dev/null
  docker network prune -f >/dev/null
  docker volume prune -af >/dev/null
  rm -rf "${root:?}"
  it_unpack /opt
  it_cx "$root" install --images "$(it_bundle_file)" >/dev/null
  it_same "the fresh install has its own master key mode (ui)" ui "$(sed -n 's/^KEK_PROVIDER=//p' "$root/.env" | tail -n1)"
  dc_restore new-host "$IT_WORK/keep/$enc" "$(dc_stamp "$enc")" 1
}
