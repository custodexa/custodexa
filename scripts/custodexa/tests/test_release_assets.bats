#!/usr/bin/env bats
# Threat (B): the release asset check passing a set that is not one consistent release. The release
# job runs this check on its own draft before anyone may publish, and deployers run the same code;
# a check that says yes to a mismatched set lets a broken or swapped file out under a valid signature.
# Each case below changes one thing, signs again where a real attacker or a broken job could, and
# expects a failure that names what is wrong.

load helper

IDENTITY="https://github.com/custodexa/custodexa/.github/workflows/release-images.yml@refs/tags/v1.13.0"

setup() {
  . "$SRC/lib/verify.sh"
  export PATH="$TESTS_DIR/fakes:$PATH"
  R=$BATS_TEST_TMPDIR/release
  mkdir -p "$R" "$BATS_TEST_TMPDIR/pkg/custodexa/releases/1.13.0"
  printf '{\n  "format": 1,\n  "version": "1.13.0",\n  "images": {\n    "backend": {"index_digest": "sha256:%064d"},\n    "frontend": {"index_digest": "sha256:%064d"}\n  }\n}\n' 1 2 >"$R/MANIFEST.json"
  cp "$R/MANIFEST.json" "$BATS_TEST_TMPDIR/pkg/custodexa/releases/1.13.0/MANIFEST.json"
  tar -C "$BATS_TEST_TMPDIR/pkg" -czf "$R/custodexa-1.13.0.tar.gz" custodexa
  printf 'amd64 images\n' >"$R/custodexa-images-1.13.0-amd64.tar"
  printf 'arm64 images\n' >"$R/custodexa-images-1.13.0-arm64.tar"
  printf '{"version": "1.13.0", "images": {"backend": {"digest": "sha256:%064d"}, "frontend": {"digest": "sha256:%064d"}}}\n' 1 2 \
    >"$BATS_TEST_TMPDIR/image-digests.json"
  sums
  sign "$IDENTITY"
}

sums() { (cd "$R" && sha256sum custodexa-1.13.0.tar.gz custodexa-images-1.13.0-amd64.tar custodexa-images-1.13.0-arm64.tar MANIFEST.json >SHA256SUMS); }
sign() { printf 'identity %s\nsha256 %s\n' "$1" "$(sha256sum "$R/SHA256SUMS" | cut -d' ' -f1)" >"$R/SHA256SUMS.sigstore.json"; }

# check_fails <what the message must name>
check_fails() {
  run cx_verify_release_assets "$R" "$IDENTITY" "$BATS_TEST_TMPDIR/image-digests.json"
  [ "$status" -ne 0 ] || { echo "accepted a bad set"; echo "$output"; return 1; }
  [[ $output == *"$1"* ]] || { echo "failure does not name '$1':"; echo "$output"; return 1; }
}

@test "a consistent, signed set passes" {
  run cx_verify_release_assets "$R" "$IDENTITY" "$BATS_TEST_TMPDIR/image-digests.json"
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [[ $output == *"release 1.13.0"* ]]
}

@test "the standalone MANIFEST differs from the packaged one by one byte, signed again: fails" {
  sed -i 's/"format": 1/"format": 2/' "$R/MANIFEST.json"
  sums
  sign "$IDENTITY"
  check_fails "MANIFEST.json differs"
}

@test "SHA256SUMS lists a file that is not there, signed again: fails and names it" {
  printf '%064d  custodexa-images-1.13.0-s390x.tar\n' 7 >>"$R/SHA256SUMS"
  sign "$IDENTITY"
  check_fails "custodexa-images-1.13.0-s390x.tar"
}

@test "SHA256SUMS leaves a file out, signed again: fails and names it" {
  sed -i '/arm64/d' "$R/SHA256SUMS"
  sign "$IDENTITY"
  check_fails "does not list custodexa-images-1.13.0-arm64.tar"
}

@test "a signature by another workflow identity: fails" {
  sign "https://github.com/someone-else/fork/.github/workflows/release-images.yml@refs/tags/v1.13.0"
  check_fails "signature does not verify"
}

@test "a file changed after signing: fails and names it" {
  printf 'swapped\n' >"$R/custodexa-images-1.13.0-amd64.tar"
  check_fails "custodexa-images-1.13.0-amd64.tar: FAILED"
}

@test "SHA256SUMS changed after signing: the signature no longer verifies" {
  printf 'swapped\n' >"$R/custodexa-images-1.13.0-amd64.tar"
  sums
  check_fails "signature does not verify"
}

@test "an extra file next to the set, even listed and signed: fails" {
  printf 'x\n' >"$R/notes.txt"
  (cd "$R" && sha256sum notes.txt >>SHA256SUMS)
  sign "$IDENTITY"
  check_fails "notes.txt"
}

@test "a MANIFEST whose image digest is not the published one, packaged consistently: fails" {
  sed -i 's/"sha256:0*1"/"sha256:'"$(printf '%064d' 9)"'"/' "$R/MANIFEST.json"
  cp "$R/MANIFEST.json" "$BATS_TEST_TMPDIR/pkg/custodexa/releases/1.13.0/MANIFEST.json"
  tar -C "$BATS_TEST_TMPDIR/pkg" -czf "$R/custodexa-1.13.0.tar.gz" custodexa
  sums
  sign "$IDENTITY"
  check_fails "backend digest is not the published one"
}
