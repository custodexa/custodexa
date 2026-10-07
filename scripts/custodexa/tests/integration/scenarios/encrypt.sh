# shellcheck shell=bash
# about: a real encrypted backup (backup --yes --passphrase-file) opens with openssl 3.5.4, 3.5.7 and 1.1.1 by the restore commands, to the same tar; a wrong passphrase does not; the passphrase is in no process's arguments or environment, nor in any file of the deployment; OpenSSL 1.1.1 to 3.5 each open it with the command the guide picks by whether `enc -help` lists -saltlen, and the first line that lists it is measured
# needs: package
# images: openssl-3.5.4 openssl-3.5.7 openssl-1.1.1 openssl-3.0 openssl-3.1 openssl-3.2 openssl-3.3

readonly ENC_PASS='it-test-only passphrase 0005'
readonly ENC_WRONG='it-test-only passphrase 0006'

# enc_watch <stop file> <out folder>: until the stop file exists, look at every process's arguments
# and environment for the passphrase (hits), and note each pass that found an openssl encryption
# running (seen). Read with builtins only: a helper process would carry the passphrase itself.
enc_watch() {
  local stop=$1 out=$2 p c e
  local -a a=()
  : >"$out/hits"
  : >"$out/seen"
  while [ ! -e "$stop" ]; do
    for p in /proc/[0-9]*; do
      mapfile -d '' -t a 2>/dev/null <"$p/cmdline" || continue
      c="${a[*]}"
      [[ $c != *'enc -e -aes-256-cbc'* ]] || echo "${p#/proc/} $c" >>"$out/seen"
      [[ $c != *"$ENC_PASS"* ]] || echo "cmdline ${p#/proc/}" >>"$out/hits"
      mapfile -d '' -t a 2>/dev/null <"$p/environ" || continue
      e="${a[*]}"
      [[ $e != *"$ENC_PASS"* ]] || echo "environ ${p#/proc/}" >>"$out/hits"
    done
  done
}

# enc_open <version> <passphrase> <file in /work> <out file>: the restore's command for that build.
enc_open() {
  local v=$1 salt=(-saltlen 8)
  [ "$v" != 1.1.1 ] || salt=()
  printf '%s\n' "$2" | it_openssl "$v" enc -d -aes-256-cbc "${salt[@]}" -pbkdf2 -md sha256 -iter 600000 \
    -pass stdin -in "$3" >"$4"
}

scenario() {
  local root=/opt/custodexa w=$IT_WORK/watch f name v want got sum vec_pass vec_sum
  it_step "built-in form: install --images $(it_bundle_file)"
  it_unpack /opt
  it_cx "$root" install --images "$(it_bundle_file)"

  it_step "backup --yes --passphrase-file, the processes watched while it runs"
  install -m 600 -o root /dev/null "$IT_WORK/cx-pass"
  printf '%s\n' "$ENC_PASS" >"$IT_WORK/cx-pass"
  mkdir -p "$w"
  enc_watch "$w/stop" "$w" &
  local watcher=$!
  it_cx "$root" backup --lang en --yes --passphrase-file "$IT_WORK/cx-pass"
  : >"$w/stop"
  wait "$watcher"
  it_check "the encryption ran while watched" test -s "$w/seen"
  it_same "no process held the passphrase in its arguments or environment" "" "$(cat "$w/hits")"
  # The files the deployment writes (releases/ holds the package's source, this scenario included).
  it_check "no log, state, backup or setting file holds the passphrase" \
    bash -c '! grep -rlF -- "$1" "${@:2}"' _ "$ENC_PASS" "$root/logs" "$root/state.json" "$root/backups" "$root/.env" "$root/data"
  it_check "no tool container is left" bash -c '[ -z "$(docker ps -aq --filter name=custodexa-backup-tool-)" ]'

  f=$(find "$root/backups" -maxdepth 1 -name 'custodexa-backup-*.tar.enc')
  name=${f##*/}
  it_check "one encrypted backup file, 0600" test "$(stat -c %a "$f")" = 600
  it_check "its checksum file matches" bash -c 'cd "$1" && sha256sum -c --quiet "$2.sha256"' _ "$root/backups" "$name"
  it_same "it starts with Salted__" Salted__ "$(head -c 8 "$f")"
  it_same "8-byte salt: whole blocks after the 16-byte header" 0 "$(($(stat -c %s "$f") % 16))"

  it_step "the file opened by each openssl build with the restore's command"
  mkdir -p "$IT_WORK/work"
  cp "$f" "$IT_WORK/work/b.tar.enc"
  want=""
  for v in $IT_OPENSSL_VERSIONS; do
    it_check "openssl $v opens it" enc_open "$v" "$ENC_PASS" b.tar.enc "$IT_WORK/plain-$v.tar"
    got=$(sha256sum <"$IT_WORK/plain-$v.tar" | cut -d' ' -f1)
    [ -n "$want" ] || want=$got
    it_same "openssl $v gives the same tar" "$want" "$got"
  done
  it_say "   plaintext tar sha256: $want"
  mkdir -p "$IT_WORK/x"
  tar -xf "$IT_WORK/plain-3.5.4.tar" -C "$IT_WORK/x"
  it_same "the members" "backup-manifest.json release-MANIFEST.json tool-MANIFEST.json snapshot.txt db.dump audit.tar.gz env.bak tls.tar.gz SHA256SUMS" \
    "$(tar -tf "$IT_WORK/plain-3.5.4.tar" | tr '\n' ' ' | sed 's/ $//')"
  it_check "the members match SHA256SUMS" bash -c 'cd "$1" && sha256sum -c --quiet SHA256SUMS' _ "$IT_WORK/x"
  it_same "the manifest says encrypted, cx-enc-1" "true cx-enc-1" \
    "$(jq -r '."encryption.enabled" + " " + ."encryption.scheme"' "$IT_WORK/x/backup-manifest.json")"
  it_check "the manifest does not hold the passphrase" bash -c '! grep -qF -- "$1" "$2"' _ "$ENC_PASS" "$IT_WORK/x/backup-manifest.json"
  it_expect_fail "openssl 1.1.1 has no -saltlen (hence the command without it)" 'saltlen|nknown option|ecognized' \
    it_openssl 1.1.1 enc -d -aes-256-cbc -saltlen 8 -pbkdf2 -md sha256 -iter 600000 -pass pass:x -in b.tar.enc

  it_step "a wrong passphrase opens it with no build"
  for v in $IT_OPENSSL_VERSIONS; do
    sum=$(enc_open "$v" "$ENC_WRONG" b.tar.enc /dev/stdout 2>/dev/null | sha256sum | cut -d' ' -f1) || true
    it_check "openssl $v does not give the tar with a wrong passphrase" test "$sum" != "$want"
    it_expect_fail "openssl $v fails with a wrong passphrase" 'bad decrypt|error' \
      enc_open "$v" "$ENC_WRONG" b.tar.enc /dev/null
  done

  it_step "-saltlen by OpenSSL line: each build opens the file with the guide's command for what its enc -help lists"
  local table="" help ver has
  local -a salt
  for v in 1.1.1 3.0 3.1 3.2 3.3 3.5.4 3.5.7; do
    ver=$(it_openssl "$v" version | awk '{print $2}')
    help=$(it_openssl "$v" enc -help 2>&1 || true)
    if grep -q -- '-saltlen' <<<"$help"; then has=yes salt=(-saltlen 8); else has=no salt=(); fi
    sum=$(printf '%s\n' "$ENC_PASS" | it_openssl "$v" enc -d -aes-256-cbc "${salt[@]}" -pbkdf2 -md sha256 -iter 600000 \
      -pass stdin -in b.tar.enc | sha256sum | cut -d' ' -f1)
    it_same "OpenSSL $ver (enc -help lists -saltlen: $has) gives the same tar with the guide's command for that" "$want" "$sum"
    table="$table ${ver%%[a-z]*}:$has"
  done
  it_say "   -saltlen listed by:$table"
  it_same "the first line that lists -saltlen is 3.2 (1.1.1, 3.0, 3.1: no; 3.2, 3.3, 3.5: yes)" \
    "no no no yes yes yes yes" "$(tr ' ' '\n' <<<"$table" | sed -n 's/.*://p' | tr '\n' ' ' | sed 's/ $//')"

  it_step "the known answer vector of the scheme, by each build"
  cp /src/scripts/custodexa/tests/fixtures/cx-enc-1-vector.tar.enc "$IT_WORK/work/vector.tar.enc"
  vec_pass=$(sed -n 's/^passphrase=//p' /src/scripts/custodexa/tests/fixtures/cx-enc-1-vector.txt)
  vec_sum=$(sed -n 's/^plaintext_sha256=//p' /src/scripts/custodexa/tests/fixtures/cx-enc-1-vector.txt)
  for v in $IT_OPENSSL_VERSIONS; do
    enc_open "$v" "$vec_pass" vector.tar.enc "$IT_WORK/vector-$v.tar"
    it_same "openssl $v gives the recorded plaintext" "$vec_sum" "$(sha256sum <"$IT_WORK/vector-$v.tar" | cut -d' ' -f1)"
  done
}
