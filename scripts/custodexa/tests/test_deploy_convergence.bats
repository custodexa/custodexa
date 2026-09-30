#!/usr/bin/env bats

load helper
load release_fixture

ROOT=/opt/custodexa

setup() {
  rm -rf "$ROOT"
  make_root "$ROOT"
  use_fake_docker
  cp "$TESTS_DIR/fakes/daemon-sim" "$FAKE_DOCKER_REPLAY/hook"
  export SIM=$FAKE_DOCKER_REPLAY/sim
  mkdir -p "$SIM"
  local fakes=$BATS_TEST_TMPDIR/host
  mkdir -p "$fakes"
  printf '#!/bin/bash\nif [ "$1" = -m ]; then echo x86_64; else exec /bin/uname "$@"; fi\n' >"$fakes/uname"
  chmod +x "$fakes/uname"
  export PATH="$fakes:$PATH"
  fixture_release
  cp "$SRC/../../packaging/compose.yml" "$ROOT/current/compose.yml"
  unset CUSTODEXA_HOME
}

@test "images-from rejects missing, unknown, read-only and conflicting values before state changes" {
  local expected
  for args in 'install --images-from' 'install --images-from nowhere' 'status --images-from source' 'upgrade --images-from source' 'install --images-from source --images /tmp/bundle.tar'; do
    read -r -a words <<<"$args"
    run "$ROOT/custodexa.sh" "${words[@]}" --lang en
    [ "$status" -eq 2 ] || { echo "$args: $status $output"; return 1; }
    case $args in
      'install --images-from') expected='needs a value' ;;
      'install --images-from nowhere') expected='Unknown image source' ;;
      'install --images-from source --images /tmp/bundle.tar') expected='cannot be combined' ;;
      *) expected='only for install or upgrade with a target' ;;
    esac
    [[ $output == *"$expected"* ]] || { echo "$args: $output"; return 1; }
  done
  run "$ROOT/custodexa.sh" install --help --lang en
  [[ $output == *'--images-from <mode>'* ]] || return 1
  [ ! -e "$ROOT/.custodexa.lock" ]
}

@test "source mode builds own images directly and keeps upstream resolution" {
  run env CX_IMAGES_FROM=source bash -c '
    . "$1/lib/common.sh"; CX_LANG_FLAG=en; cx_load_libs "$1"; CX_ROOT=/opt/custodexa
    cx_manifest_load "$CX_ROOT/current/MANIFEST.json" || exit 1
    cx_images_resolve ""' _ "$SRC"
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [[ $output == *"Built from source"* ]] || { echo "$output"; return 1; }
  ! grep -q $'\tpull .*custodexa/backend' "$FAKE_DOCKER_LOG"
  ! grep -q $'\tpull .*custodexa/frontend' "$FAKE_DOCKER_LOG"
  grep -q $'\tcompose .* build backend' "$FAKE_DOCKER_LOG"
  grep -q $'\tcompose .* build frontend' "$FAKE_DOCKER_LOG"
}

@test "source checksum mismatch stops before build or upstream pull" {
  printf 'tampered\n' >>"$ROOT/current/source/backend/main.go"
  run env CX_IMAGES_FROM=source bash -c '
    . "$1/lib/common.sh"; CX_LANG_FLAG=en; cx_load_libs "$1"; CX_ROOT=/opt/custodexa
    cx_manifest_load "$CX_ROOT/current/MANIFEST.json" || exit 1
    cx_images_resolve ""' _ "$SRC"
  [ "$status" -eq 1 ] || { echo "$output"; return 1; }
  [[ $output == *"[FAIL]"* && $output == *"download them again"* ]] || { echo "$output"; return 1; }
  ! grep -Eq $'\t(build|pull) ' "$FAKE_DOCKER_LOG"
}

@test "source mode accepts checked upstream images already on this host" {
  store classic
  for n in postgres guacd openssl nginx; do
    have "${REF[$n]}@${IDX[$n]}" "${CFG[$n]}"
  done
  run env CX_IMAGES_FROM=source bash -c '
    . "$1/lib/common.sh"; CX_LANG_FLAG=en; cx_load_libs "$1"; CX_ROOT=/opt/custodexa
    cx_manifest_load "$CX_ROOT/current/MANIFEST.json" || exit 1
    cx_images_resolve ""' _ "$SRC"
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [[ $output == *"This host: present, content digest matches"* ]] || return 1
  ! grep -q $'\tpull ' "$FAKE_DOCKER_LOG"
}

@test "upgrade source mode checks and builds the target release source" {
  local target=$ROOT/releases/1.13.2 wrapper=$BATS_TEST_TMPDIR/context-bin
  mkdir -p "$target"
  cp -R "$ROOT/current/." "$target/"
  printf 'target release\n' >"$target/source/backend/main.go"
  jq --arg s "$(cx_tree_sha256 "$target/source")" \
    '.version = "1.13.2" | .source.sha256 = $s' "$target/MANIFEST.json" >"$target/MANIFEST.new"
  mv "$target/MANIFEST.new" "$target/MANIFEST.json"
  mkdir -p "$wrapper"
  printf '#!/bin/bash\nif [ "$1" = compose ] && [[ " $* " == *" build "* ]]; then printf "%%s\\n" "$CUSTODEXA_BUILD_SOURCE" >>"$BUILD_CONTEXT_LOG"; fi\nexec %q "$@"\n' \
    "$TESTS_DIR/fakes/docker" >"$wrapper/docker"
  chmod +x "$wrapper/docker"
  run env PATH="$wrapper:$PATH" BUILD_CONTEXT_LOG="$BATS_TEST_TMPDIR/build-contexts" CX_IMAGES_FROM=source CX_TARGET="$target" bash -c '
    . "$1/lib/common.sh"; CX_LANG_FLAG=en; cx_load_libs "$1"; CX_ROOT=/opt/custodexa; CX_DIR=$CX_TARGET
    cx_manifest_load "$CX_DIR/MANIFEST.json" || exit 1
    cx_images_resolve ""' _ "$SRC"
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  grep -q -- "-f $target/compose.yml build backend" "$FAKE_DOCKER_LOG"
  grep -q -- "-f $target/compose.yml build frontend" "$FAKE_DOCKER_LOG"
  grep -q '^CUSTODEXA_IMAGE_BACKEND=custodexa-local/backend:1.13.2$' "$target/images.env"
  [ "$(wc -l <"$BATS_TEST_TMPDIR/build-contexts")" -eq 2 ]
  ! grep -vxF "$target/source" "$BATS_TEST_TMPDIR/build-contexts"
}

@test "upgrade image resolution leaves every current release file unchanged before confirmation" {
  local target=$ROOT/releases/1.13.2
  mkdir -p "$target"
  cp -R "$ROOT/current/." "$target/"
  jq '.version = "1.13.2"' "$target/MANIFEST.json" >"$target/MANIFEST.new"
  mv "$target/MANIFEST.new" "$target/MANIFEST.json"
  printf 'CUSTODEXA_IMAGE_BACKEND=ghcr.io/custodexa/backend:1.13.0\n' >"$ROOT/current/images.env"
  (cd "$ROOT/current" && find . -type f -print0 | sort -z | xargs -0 sha256sum) >"$BATS_TEST_TMPDIR/current-before"
  run env CX_IMAGES_FROM=source CX_TARGET="$target" bash -c '
    . "$1/lib/common.sh"; CX_LANG_FLAG=en; cx_load_libs "$1"; CX_ROOT=/opt/custodexa; CX_DIR=$CX_TARGET
    cx_manifest_load "$CX_DIR/MANIFEST.json" || exit 1
    cx_images_resolve ""' _ "$SRC"
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  (cd "$ROOT/current" && find . -type f -print0 | sort -z | xargs -0 sha256sum) >"$BATS_TEST_TMPDIR/current-after"
  diff "$BATS_TEST_TMPDIR/current-before" "$BATS_TEST_TMPDIR/current-after"
}

@test "image heading and failed GHCR result precede a slow Docker Hub fallback" {
  local slow=$BATS_TEST_TMPDIR/slow out=$BATS_TEST_TMPDIR/fallback-progress pid
  mkdir -p "$slow"
  down ghcr.io
  printf '#!/bin/bash\nif [ "$1" = pull ] && [[ " $* " == *" docker.io/custodexa/backend@"* ]]; then /bin/sleep 2; fi\nexec %q "$@"\n' \
    "$TESTS_DIR/fakes/docker" >"$slow/docker"
  chmod +x "$slow/docker"
  env PATH="$slow:$PATH" bash -c '
    . "$1/lib/common.sh"; CX_LANG_FLAG=en; cx_load_libs "$1"; CX_ROOT=/opt/custodexa
    cx_manifest_load "$CX_ROOT/current/MANIFEST.json" || exit 1
    cx_images_resolve ""' _ "$SRC" >"$out" 2>&1 &
  pid=$!
  for _ in {1..50}; do
    grep -q 'Obtaining backend from Docker Hub' "$out" 2>/dev/null && break
    /bin/sleep 0.1
  done
  grep -q '^       backend 1.13.0$' "$out" || { cat "$out"; wait "$pid"; return 1; }
  grep -q 'GHCR ghcr.io/custodexa/backend: connection timed out' "$out" || { cat "$out"; wait "$pid"; return 1; }
  grep -q 'Obtaining backend from Docker Hub' "$out" || { cat "$out"; wait "$pid"; return 1; }
  wait "$pid" || { cat "$out"; return 1; }
}

@test "registry progress is visible before a slow pull returns" {
  local slow=$BATS_TEST_TMPDIR/slow out=$BATS_TEST_TMPDIR/progress pid
  mkdir -p "$slow"
  printf '#!/bin/bash\nif [ "$1" = pull ]; then /bin/sleep 2; fi\nexec %q "$@"\n' \
    "$TESTS_DIR/fakes/docker" >"$slow/docker"
  chmod +x "$slow/docker"
  env PATH="$slow:$PATH" bash -c '
    . "$1/lib/common.sh"; CX_LANG_FLAG=en; cx_load_libs "$1"; CX_ROOT=/opt/custodexa
    cx_manifest_load "$CX_ROOT/current/MANIFEST.json" || exit 1
    CX_IMG_ARCH=amd64
    cx_img_try_registry backend ghcr.io/custodexa/backend' _ "$SRC" >"$out" 2>&1 &
  pid=$!
  /bin/sleep 0.2
  grep -q 'Obtaining backend from GHCR' "$out" || { cat "$out"; wait "$pid"; return 1; }
  wait "$pid" || { cat "$out"; return 1; }
}

@test "build progress is visible before a slow Docker build returns" {
  local slow=$BATS_TEST_TMPDIR/slow out=$BATS_TEST_TMPDIR/build-progress pid
  mkdir -p "$slow"
  printf '#!/bin/bash\nif [ "$1" = compose ] && [[ " $* " == *" build backend "* ]]; then /bin/sleep 2; fi\nexec %q "$@"\n' \
    "$TESTS_DIR/fakes/docker" >"$slow/docker"
  chmod +x "$slow/docker"
  env PATH="$slow:$PATH" CX_IMAGES_FROM=source bash -c '
    . "$1/lib/common.sh"; CX_LANG_FLAG=en; cx_load_libs "$1"; CX_ROOT=/opt/custodexa
    cx_manifest_load "$CX_ROOT/current/MANIFEST.json" || exit 1
    cx_images_resolve ""' _ "$SRC" >"$out" 2>&1 &
  pid=$!
  /bin/sleep 0.2
  grep -q 'Building backend from source' "$out" || { cat "$out"; wait "$pid"; return 1; }
  wait "$pid" || { cat "$out"; return 1; }
}

@test "offline load progress is visible before a slow Docker load returns" {
  local slow=$BATS_TEST_TMPDIR/slow out=$BATS_TEST_TMPDIR/load-progress pid
  mkdir -p "$slow"
  store classic
  make_bundle "$ROOT/custodexa-images-1.13.0-amd64.tar" classic
  printf '#!/bin/bash\nif [ "$1" = load ]; then /bin/sleep 2; fi\nexec %q "$@"\n' \
    "$TESTS_DIR/fakes/docker" >"$slow/docker"
  chmod +x "$slow/docker"
  env PATH="$slow:$PATH" bash -c '
    . "$1/lib/common.sh"; CX_LANG_FLAG=en; cx_load_libs "$1"; CX_ROOT=/opt/custodexa
    cx_manifest_load "$CX_ROOT/current/MANIFEST.json" || exit 1
    cx_images_resolve ""' _ "$SRC" >"$out" 2>&1 &
  pid=$!
  for _ in {1..15}; do
    grep -q 'Loading offline bundle' "$out" && break
    /bin/sleep 0.1
  done
  grep -q 'Loading offline bundle' "$out" || { cat "$out"; wait "$pid"; return 1; }
  wait "$pid" || { cat "$out"; return 1; }
}

@test "old git clone root is refused with no writes or service calls" {
  local old=$BATS_TEST_TMPDIR/old
  mkdir -p "$old/.git" "$old/data"
  printf '1.12.4\n' >"$old/VERSION"
  : >"$old/docker-compose.yml"
  printf 'recording\n' >"$old/data/recording.txt"
  cp "$ROOT/custodexa.sh" "$old/custodexa.sh"
  cp -R "$ROOT/current/lib" "$ROOT/current/lang" "$old/"
  (cd "$old" && find . -printf '%y %m %p\n' | sort && find . -type f -print0 | sort -z | xargs -0 -r sha256sum) >"$BATS_TEST_TMPDIR/before"
  for cmd in install status upgrade backup load; do
    run env CUSTODEXA_HOME="$old" "$ROOT/custodexa.sh" "$cmd" --lang en
    [ "$status" -eq 3 ] || { echo "$cmd: $status $output"; return 1; }
    [[ $output == *"older git clone deployment"* ]] || { echo "$output"; return 1; }
  done
  for lang in zh-TW ja; do
    run env CUSTODEXA_HOME="$old" "$ROOT/custodexa.sh" status --lang "$lang"
    [ "$status" -eq 3 ] && [[ $output == '[FAIL]'* ]] || { echo "$output"; return 1; }
    if [ "$lang" = zh-TW ]; then
      [[ $output == *'手動遷移說明'* ]] || return 1
    else
      [[ $output == *'手動移行'* ]] || return 1
    fi
  done
  run script -qec "bash $old/custodexa.sh --lang en" /dev/null <<<0
  [ "$status" -eq 3 ] && [[ $output == *"older git clone deployment"* ]] || { echo "$output"; return 1; }
  (cd "$old" && find . -printf '%y %m %p\n' | sort && find . -type f -print0 | sort -z | xargs -0 -r sha256sum) >"$BATS_TEST_TMPDIR/after"
  diff "$BATS_TEST_TMPDIR/before" "$BATS_TEST_TMPDIR/after"
  [ ! -e "$old/.custodexa.lock" ]
  [ ! -e "$old/state.json" ]
  [ ! -s "$FAKE_DOCKER_LOG" ]
}

@test "direct entry under old git clone refuses every command and menu before writing" {
  local old=$BATS_TEST_TMPDIR/direct-old entry
  entry=$old/scripts/custodexa/custodexa.sh
  mkdir -p "$old/.git" "$old/data" "$old/scripts/custodexa"
  printf '1.12.4\n' >"$old/VERSION"
  : >"$old/docker-compose.yml"
  printf 'recording\n' >"$old/data/recording.txt"
  cp "$SRC/custodexa.sh" "$entry"
  cp -R "$SRC/lib" "$SRC/lang" "$old/scripts/custodexa/"
  (cd "$old" && find . -printf '%y %m %p\n' | sort && find . -type f -print0 | sort -z | xargs -0 -r sha256sum) >"$BATS_TEST_TMPDIR/direct-before"
  for cmd in install status upgrade backup load; do
    run "$entry" "$cmd" --lang en --no-color
    [ "$status" -eq 3 ] || { echo "$cmd: $status $output"; return 1; }
    [[ $output == *"older git clone deployment"* ]] || { echo "$cmd: $output"; return 1; }
  done
  run script -qec "bash $entry --lang en --no-color" /dev/null <<<0
  [ "$status" -eq 3 ] && [[ $output == *"older git clone deployment"* ]] || { echo "menu: $status $output"; return 1; }
  (cd "$old" && find . -printf '%y %m %p\n' | sort && find . -type f -print0 | sort -z | xargs -0 -r sha256sum) >"$BATS_TEST_TMPDIR/direct-after"
  diff "$BATS_TEST_TMPDIR/direct-before" "$BATS_TEST_TMPDIR/direct-after"
  [ ! -e "$old/.custodexa.lock" ]
  [ ! -e "$old/state.json" ]
  [ ! -s "$FAKE_DOCKER_LOG" ]
}

@test "historical conversion fields do not block a current package deployment" {
  cat >"$ROOT/state.json" <<'STATE'
{
  "format": "2",
  "current.kind": "package",
  "current.version": "1.13.0",
  "conversion.from": "1.12.4"
}
STATE
  run "$ROOT/custodexa.sh" status --lang en
  [ "$status" -eq 0 ] || [ "$status" -eq 4 ] || { echo "$output"; return 1; }
  [[ $output != *"older git clone deployment"* ]] || return 1
  run "$ROOT/custodexa.sh" upgrade 1.13.0 --lang en
  [ "$status" -eq 3 ] || { echo "$output"; return 1; }
  [[ $output != *"older git clone deployment"* ]] || return 1
}
