#!/usr/bin/env bats
# Threat (A): an image taken from the wrong place or labelled with the wrong source; a local build
# passed off under the published name; a tag trusted for its name; an offline bundle trusted for
# what its index says rather than what its bytes are; a container running something other than
# what was checked. A simulated daemon (tests/fakes/daemon-sim) gives image IDs the way the classic
# and the containerd image store do.

load helper
load release_fixture

ROOT=/opt/custodexa

setup() {
  rm -rf "$ROOT" /home/ops
  mkdir -p /home/ops/downloads
  make_root "$ROOT"
  use_fake_docker
  cp "$TESTS_DIR/fakes/daemon-sim" "$FAKE_DOCKER_REPLAY/hook"
  export SIM=$FAKE_DOCKER_REPLAY/sim
  mkdir -p "$SIM"
  FAKES=$BATS_TEST_TMPDIR/host
  mkdir -p "$FAKES"
  printf '#!/bin/bash\nif [ "$1" = -m ]; then echo x86_64; else exec /bin/uname "$@"; fi\n' >"$FAKES/uname"
  chmod +x "$FAKES/uname"
  export PATH="$FAKES:$PATH"
  unset LC_ALL LC_MESSAGES LANG NO_COLOR CUSTODEXA_HOME
  fixture_release
  cp "$SRC/../../packaging/compose.yml" "$ROOT/current/compose.yml"
}
manifest() { release_manifest; }

env_line() { grep "^CUSTODEXA_IMAGE_$1=" "$ROOT/current/images.env" | cut -d= -f2-; }
id_line() { grep "^$1=" "$ROOT/current/image-ids.env" | cut -d= -f2-; }

# Step 3 as install prints it, the closing line taking the duration it is given.
step3() { # <lang> [overlays]
  run env CX_LANG_FLAG="$1" OV="${2:-}" bash -c '
    . "$1/lib/common.sh"; cx_load_libs "$1"; CX_ROOT=/opt/custodexa
    cx_manifest_load "$CX_ROOT/current/MANIFEST.json" || exit 1
    cx_state_load "$CX_ROOT/state.json"
    cx_step_line RUN 3/7 "$(cx_msg step_images)"
    cx_images_resolve "$OV"; rc=$?
    cx_images_write_env "$CX_ROOT/current/images.env"
    cx_images_write_ids "$CX_ROOT/current/image-ids.env"
    [ $rc -eq 0 ] || exit 1
    cx_step_line OK 3/7 "$(cx_msg step_images_done "${#CX_IMG_NAMES[@]}" "$(cx_msg ver_all)")" "$(cx_duration 72)"' _ "$SRC"
}

@test "the reviewed screen, word for word: host, bundle, GHCR timing out, Docker Hub, upstream" {
  store classic
  down ghcr.io
  have "${REF[frontend]}@${IDX[frontend]}" "${CFG[frontend]}"
  for n in postgres openssl nginx; do have "${REF[$n]}@${IDX[$n]}" "${CFG[$n]}"; done
  cd /home/ops/downloads
  for l in zh-TW en; do
    rm -f "$SIM/images.bak"
    cp "$SIM/images" "$SIM/images.bak"
    step3 "$l"
    [ "$status" -eq 0 ] || { echo "$output"; return 1; }
    diff <(printf '%s\n' "$output") "$TESTS_DIR/snapshots/s03.$l.txt" || { echo "[$l] differs from the reviewed screen"; return 1; }
    mv "$SIM/images.bak" "$SIM/images"
  done
  # GHCR timed out once; it is not tried again for the other images in the same run.
  [ "$(grep -c 'pull.*ghcr.io' "$FAKE_DOCKER_LOG")" -eq 2 ] # once per language run
  [ "$(env_line BACKEND)" = "docker.io/custodexa/backend@${IDX[backend]}" ]
  [ "$(env_line FRONTEND)" = "${REF[frontend]}@${IDX[frontend]}" ]
}

@test "registry pulls on both stores: the reference and the ID each store gives are recorded" {
  for s in classic containerd; do
    : >"$SIM/images"
    store "$s"
    step3 en
    [ "$status" -eq 0 ] || { echo "$output"; return 1; }
    for n in $NAMES; do
      [ "$(env_line "${n^^}")" = "${REF[$n]}@${IDX[$n]}" ] || { echo "[$s] $n: $(env_line "${n^^}")"; return 1; }
      if [ "$s" = classic ]; then want=${CFG[$n]}; else want=${IDX[$n]}; fi
      [ "$(id_line "$n")" = "$want" ] || { echo "[$s] $n id $(id_line "$n") != $want"; return 1; }
    done
  done
}

@test "offline bundle on both stores: checked before loading, then the IDs after loading agree" {
  down ghcr.io
  down docker.io
  for s in classic containerd; do
    : >"$SIM/images"
    store "$s"
    make_bundle "$ROOT/custodexa-images-1.13.0-amd64.tar" "$s"
    step3 en
    [ "$status" -eq 0 ] || { echo "[$s] $output"; return 1; }
    [[ $output == *"[ OK ] Offline bundle $ROOT/custodexa-images-1.13.0-amd64.tar"* ]] || { echo "$output"; return 1; }
    for n in $NAMES; do
      [ "$(env_line "${n^^}")" = "${REF[$n]}:${TAG[$n]}" ] || { echo "[$s] $n: $(env_line "${n^^}")"; return 1; }
      if [ "$s" = classic ]; then
        want=${CFG[$n]}
      else
        want=sha256:$(tar -xOf "$ROOT/custodexa-images-1.13.0-amd64.tar" index.json |
          jq -r --arg r "${REF[$n]}:${TAG[$n]}" '.manifests[] | select(.annotations["io.containerd.image.name"] == $r) | .digest' | cut -d: -f2)
      fi
      [ "$(id_line "$n")" = "$want" ] || { echo "[$s] $n id $(id_line "$n") != $want"; return 1; }
    done
  done
  # Without SHA256SUMS next to it the bundle is not used at all.
  : >"$SIM/images"
  rm "$ROOT/SHA256SUMS"
  : >"$FAKE_DOCKER_LOG"
  step3 en
  [ "$status" -eq 1 ] && [[ $output == *"no SHA256SUMS in $ROOT"* ]] || { echo "$output"; return 1; }
  ! grep -q $'\tload' "$FAKE_DOCKER_LOG" || return 1
}

@test "damaged offline bundle fails without falling back to a registry" {
  store classic
  make_bundle "$ROOT/custodexa-images-1.13.0-amd64.tar" classic
  printf 'damaged' >>"$ROOT/custodexa-images-1.13.0-amd64.tar"
  step3 en
  [ "$status" -eq 1 ] || { echo "$output"; return 1; }
  [[ $output == *"[FAIL] Offline bundle"* && $output == *"download it again"* ]] || { echo "$output"; return 1; }
  ! grep -q $'\tpull ' "$FAKE_DOCKER_LOG" || return 1
}

@test "loaded bundle image ID mismatch fails without trying a registry" {
  store classic
  make_bundle "$ROOT/custodexa-images-1.13.0-amd64.tar" classic
  touch "$SIM/load-swap"
  step3 en
  [ "$status" -eq 1 ] || { echo "$output"; return 1; }
  [[ $output == *"[FAIL] Offline bundle"* && $output == *"download it again"* ]] || { echo "$output"; return 1; }
  ! grep -q $'\tpull ' "$FAKE_DOCKER_LOG" || return 1
}

@test "downloaded image content digest mismatch stops before trying a mirror" {
  store classic
  awk -v ref="${REF[backend]}@${IDX[backend]}" \
    '$1 == ref { $2 = "sha256:0bad000000000000000000000000000000000000000000000000000000000000" } { print }' \
    "$SIM/registry" >"$SIM/registry.new"
  mv "$SIM/registry.new" "$SIM/registry"
  step3 en
  [ "$status" -eq 1 ] || { echo "$output"; return 1; }
  [[ $output == *"[FAIL] GHCR"* && $output == *"content digest differs"* ]] || { echo "$output"; return 1; }
  ! grep -q $'\tpull .*docker.io/custodexa/backend' "$FAKE_DOCKER_LOG" || return 1
  ! grep -q $'\tpull .*frontend' "$FAKE_DOCKER_LOG" || return 1
}

@test "a bundle whose manifest was swapped, index.json unchanged, is refused before loading" {
  down ghcr.io
  down docker.io
  store containerd
  local tar=$ROOT/custodexa-images-1.13.0-amd64.tar d m other
  make_bundle "$tar" containerd
  # Replace backend's manifest with another one (same config, another layer) under the old name.
  d=$BATS_TEST_TMPDIR/bundle-containerd
  m=$(jq -r --arg r "${REF[backend]}:1.13.0" '.manifests[] | select(.annotations["io.containerd.image.name"] == $r) | .digest' "$d/index.json")
  other=$(jq --arg l "sha256:$(printf 'x' | sha256sum | cut -d' ' -f1)" '.layers[0].digest = $l' "$d/blobs/sha256/${m#sha256:}")
  printf '%s' "$other" >"$d/blobs/sha256/${m#sha256:}"
  (cd "$d" && tar -cf "$tar" index.json manifest.json oci-layout blobs)
  (cd "$ROOT" && sha256sum custodexa-images-1.13.0-amd64.tar >SHA256SUMS)
  step3 en
  [ "$status" -eq 1 ]
  [[ $output == *"the manifest of ghcr.io/custodexa/backend:1.13.0 does not match its digest"* ]] || { echo "$output"; return 1; }
  ! grep -q $'\tload' "$FAKE_DOCKER_LOG" || return 1
  # A bundle naming another config than the release manifest is refused the same way.
  make_bundle "$tar" classic
  store classic
  CFG[backend]=sha256:$(printf 'other config' | sha256sum | cut -d' ' -f1)
  manifest >"$ROOT/current/MANIFEST.json"
  step3 en
  [ "$status" -eq 1 ] && [[ $output == *"config digest of ghcr.io/custodexa/backend:1.13.0 does not match"* ]] || { echo "$output"; return 1; }
  ! grep -q $'\tload' "$FAKE_DOCKER_LOG" || return 1
}

@test "a tag on this host with other content is not taken for the release" {
  store classic
  down ghcr.io
  down docker.io
  have "${REF[backend]}:1.13.0" sha256:0bad000000000000000000000000000000000000000000000000000000000000
  touch "$SIM/build-fails"
  step3 en
  [ "$status" -eq 1 ]
  [[ $output == *"[WARN] This host: ghcr.io/custodexa/backend:1.13.0 has a different content digest; not used"* ]] || { echo "$output"; return 1; }
  [ -z "$(env_line BACKEND)" ]
  # The same tag with the release's content is taken (it came from an earlier load).
  : >"$SIM/images"
  rm "$SIM/build-fails"
  have "${REF[backend]}:1.13.0" "${CFG[backend]}"
  for n in frontend postgres guacd openssl nginx; do have "${REF[$n]}@${IDX[$n]}" "${CFG[$n]}"; done
  step3 en
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [ "$(env_line BACKEND)" = "${REF[backend]}:1.13.0" ]
}

@test "build from source: only under custodexa-local/, only when the source matches" {
  store classic
  down ghcr.io
  down docker.io
  for n in postgres guacd openssl nginx; do have "${REF[$n]}@${IDX[$n]}" "${CFG[$n]}"; done
  step3 en
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [ "$(env_line BACKEND)" = custodexa-local/backend:1.13.0 ] && [ "$(env_line FRONTEND)" = custodexa-local/frontend:1.13.0 ] || return 1
  ! grep -E '^CUSTODEXA_IMAGE_(BACKEND|FRONTEND)=.*(ghcr\.io|docker\.io)' "$ROOT/current/images.env" || return 1
  [[ $output == *"Building from source needs access to Go modules"* ]]
  grep -q $'\tcompose -p custodexa --project-directory /opt/custodexa -f /opt/custodexa/current/compose.yml build backend' "$FAKE_DOCKER_LOG"
  # A source tree that is not the released one is not built.
  echo tampered >>"$ROOT/current/source/backend/main.go"
  : >"$FAKE_DOCKER_LOG"
  : >"$SIM/images"
  step3 en
  [ "$status" -eq 1 ] && [[ $output == *"source checksum does not match the release"* && $output == *"download them again"* ]] || { echo "$output"; return 1; }
  ! grep -q 'build' "$FAKE_DOCKER_LOG" || return 1
}

@test "after start: a container running another image than the recorded one fails" {
  store containerd
  run bash -c '
    . "$1/lib/common.sh"; CX_LANG_FLAG=en cx_load_libs "$1"; CX_ROOT=/opt/custodexa
    cx_manifest_load "$CX_ROOT/current/MANIFEST.json" >/dev/null
    cx_images_resolve "" >/dev/null || exit 9
    for n in "${CX_IMG_NAMES[@]}"; do echo "$(cx_img_container "$n") ${CX_IMG_ID[$n]}"; done >"$SIM/containers"
    cx_images_verify_running || exit 8
    sed -i "s/^custodexa-backend .*/custodexa-backend sha256:0bad/" "$SIM/containers"
    cx_images_verify_running' _ "$SRC"
  [ "$status" -eq 1 ] || { echo "$output"; return 1; }
  [[ $output == *"[FAIL] custodexa-backend runs image sha256:0bad, not the one just obtained"* ]] || { echo "$output"; return 1; }
}

# ---- who published the images (checksums always; signature and provenance when possible) ----
# tools <cosign|gh|none...>: which of cosign and gh this host has.
tools() {
  local bin=$BATS_TEST_TMPDIR/bin t
  rm -rf "$bin"
  mkdir -p "$bin"
  ln -s "$TESTS_DIR/fakes/docker" "$bin/docker"
  for t in "$@"; do [ "$t" = none ] || ln -s "$TESTS_DIR/fakes/$t" "$bin/$t"; done
  export PATH="$FAKES:$bin:${ORIG_PATH:=${PATH//$TESTS_DIR\/fakes:/}}"
}
trim() { awk 'NF { p = NR } { l[NR] = $0 } END { for (i = 1; i <= p; i++) print l[i] }'; }
trust() { # <lang> [--yes]
  run env CX_LANG_FLAG="$1" CX_YES="$([ "${2:-}" = --yes ] && echo 1 || echo 0)" bash -c '
    . "$1/lib/common.sh"; cx_load_libs "$1"; CX_ROOT=/opt/custodexa
    cx_manifest_load "$CX_ROOT/current/MANIFEST.json" >/dev/null
    cx_log_open install
    cx_images_resolve "" >/dev/null || exit 9
    cx_trust_check
    printf "%s\n%s\n" "$(cx_trust_state)" "$(cx_trust_summary)" >"$2"
    cx_trust_screen </dev/null || exit 3' _ "$SRC" "$BATS_TEST_TMPDIR/trust.out"
}

@test "no cosign warns without a confirmation and records unverified trust" {
  store classic
  tools none
  trust en
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [[ $output == *"[WARN] Publisher signature"* && $output != *"[SKIP] Publisher signature"* ]] || { echo "$output"; return 1; }
  [ "$(sed -n 1p "$BATS_TEST_TMPDIR/trust.out")" = "checksum=ok signature=skip-no-cosign provenance=skip-no-gh" ]
}

@test "wrong image signer warns and records mismatch without stopping" {
  store classic
  tools cosign gh
  export FAKE_COSIGN_SIGNER=https://github.com/someone/fork/.github/workflows/release-images.yml@refs/tags/v1.13.0
  trust en
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [[ $output == *"[WARN] Publisher signature"* && $output == *"signature mismatch, publisher unverified"* ]] || { echo "$output"; return 1; }
  [ "$(sed -n 1p "$BATS_TEST_TMPDIR/trust.out")" = "checksum=ok signature=mismatch provenance=ok" ]
}

@test "publisher not verified: WARN screen with full digests and no confirmation" {
  store classic
  tools none
  for l in zh-TW en; do
    trust "$l" --yes
    [ "$status" -eq 0 ] || { echo "$output"; return 1; }
    diff <(printf '%s\n' "$output" | sed '1{/^$/d}' | trim) <(trim <"$TESTS_DIR/snapshots/s04.$l.txt") ||
      { echo "[$l] differs from the reviewed screen"; return 1; }
  done
  [ "$(sed -n 1p "$BATS_TEST_TMPDIR/trust.out")" = "checksum=ok signature=skip-no-cosign provenance=skip-no-gh" ]
  [ "$(sed -n 2p "$BATS_TEST_TMPDIR/trust.out")" = "content digests checked;" ]
  grep -q ' VERIFY checksum OK | image_sig WARN reason=no-cosign | provenance WARN reason=no-gh$' "$ROOT"/logs/install-*.log
  trust en
  [ "$status" -eq 0 ] && [[ $output == *"[WARN] Publisher signature"* ]] || { echo "$output"; return 1; }
}

@test "publisher checks that run: verified skips the screen, unavailable or mismatched warns" {
  store containerd
  tools cosign gh
  export FAKE_COSIGN_SIGNER="https://github.com/custodexa/custodexa/.github/workflows/release-images.yml@refs/tags/v1.13.0"
  trust en
  [ "$status" -eq 0 ] && [ -z "$output" ] || { echo "$output"; return 1; }
  [ "$(sed -n 1p "$BATS_TEST_TMPDIR/trust.out")" = "checksum=ok signature=ok provenance=ok" ]
  # Signing service unreachable: said as such, and only the layer that did not run gets commands.
  FAKE_COSIGN_VERIFY=offline trust en --yes
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [[ $output == *"[WARN] Publisher signature   offline, the signing service is unreachable"* ]] || { echo "$output"; return 1; }
  [[ $output == *"[ OK ] Build provenance      verified"* && $output == *"cosign verify ghcr.io/custodexa/frontend@"* ]] || { echo "$output"; return 1; }
  [[ $output != *"gh attestation verify"* ]] || { echo "$output"; return 1; }
  FAKE_GH=login trust en --yes
  [[ $output == *"[WARN] Build provenance      gh is not signed in (gh auth login)"* ]] || { echo "$output"; return 1; }
  # Unavailable checks warn without requiring a terminal.
  FAKE_COSIGN_VERIFY=offline trust en
  [ "$status" -eq 0 ] && [[ $output == *"[WARN] Files were checked for damage"* ]] || { echo "$output"; return 1; }
  FAKE_GH=login trust en
  [ "$status" -eq 0 ] && [[ $output == *"[WARN] Files were checked for damage"* ]] || { echo "$output"; return 1; }
  # A signature by anyone else, or provenance that does not verify, remains unverified.
  FAKE_COSIGN_SIGNER=https://github.com/someone/fork/.github/workflows/release-images.yml@refs/tags/v1.13.0 trust en --yes
  [ "$status" -eq 0 ] && [[ $output == *"[WARN] Publisher signature   signature mismatch, publisher unverified"* ]] || { echo "$output"; return 1; }
  FAKE_GH=bad trust en --yes
  [ "$status" -eq 0 ] && [[ $output == *"[WARN] Build provenance      build provenance mismatch, publisher unverified"* ]] || { echo "$output"; return 1; }
  # Images built here have nothing to verify; the screen says why.
  down ghcr.io
  down docker.io
  : >"$SIM/images"
  for n in postgres guacd openssl nginx; do have "${REF[$n]}@${IDX[$n]}" "${IDX[$n]}"; done
  trust en --yes
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [[ $output == *"[WARN] Publisher signature   images built from source carry no publisher signature"* ]] || { echo "$output"; return 1; }
}

@test "the manifest as build-package writes it (notes keyed by language tag) is read" {
  release_manifest | jq '. + {min_source_version: "1.12.4", notes: {"zh-TW": ["first"], en: [], ja: []}}' \
    >"$ROOT/current/MANIFEST.json"
  run bash -c '. "$1/lib/common.sh"; cx_load_libs "$1"
    cx_manifest_load "$2" || exit 1
    printf "%s|%s|%s\n" "$(cx_mf notes.zh-TW.0)" "$(cx_mf version)" "$(cx_mf min_source_version)"' _ "$SRC" "$ROOT/current/MANIFEST.json"
  [ "$status" -eq 0 ] && [ "$output" = "first|1.13.0|1.12.4" ] || { echo "$output"; return 1; }
}
