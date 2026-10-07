# shellcheck shell=bash
# about: openssl 3.5.4, 3.5.7 and 1.1.1 run, and each decrypts a file the pinned 3.5.4 encrypted
# images: openssl-3.5.4 openssl-3.5.7 openssl-1.1.1

readonly SMOKE_PASS=it-test-only-passphrase
readonly SMOKE_ITER=1000

scenario() {
  local v out want
  for v in $IT_OPENSSL_VERSIONS; do
    out=$(it_openssl "$v" version)
    it_say "   $v: $out"
    it_check "openssl $v reports version $v" grep -q "^OpenSSL $v" <<<"$out"
  done

  it_step "a file encrypted by 3.5.4 (password on stdin, PBKDF2), decrypted by each version"
  head -c 1048576 /dev/urandom >"$IT_WORK/work/plain.bin"
  want=$(sha256sum <"$IT_WORK/work/plain.bin" | cut -d' ' -f1)
  printf '%s\n' "$SMOKE_PASS" | it_openssl 3.5.4 enc -e -aes-256-cbc -salt -pbkdf2 -md sha256 \
    -iter "$SMOKE_ITER" -pass stdin -in plain.bin -out plain.enc
  it_same "the ciphertext starts with Salted__" Salted__ "$(head -c 8 "$IT_WORK/work/plain.enc")"
  for v in $IT_OPENSSL_VERSIONS; do
    out=$(printf '%s\n' "$SMOKE_PASS" | it_openssl "$v" enc -d -aes-256-cbc -pbkdf2 -md sha256 \
      -iter "$SMOKE_ITER" -pass stdin -in plain.enc | sha256sum | cut -d' ' -f1)
    it_same "openssl $v decrypts it to the same bytes" "$want" "$out"
  done
}
