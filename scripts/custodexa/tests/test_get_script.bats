#!/usr/bin/env bats
# The download guide must leave a verified package in place before handing execution to it.
load helper

GET=/src/scripts/get-custodexa.sh

setup() {
  export CX_GET_RELEASE_BASE=https://fixture.example/releases
  export GET_HANDOFF_LOG=$BATS_TEST_TMPDIR/handoff.log
  export FAKE_RELEASE_DIR=$BATS_TEST_TMPDIR/release
  mkdir -p "$FAKE_RELEASE_DIR/latest/download" "$FAKE_RELEASE_DIR/download/v1.14.0" \
    "$BATS_TEST_TMPDIR/pkg/custodexa" "$BATS_TEST_TMPDIR/bin"
  printf '{"version":"1.14.0"}\n' >"$FAKE_RELEASE_DIR/latest/download/MANIFEST.json"
  cat >"$BATS_TEST_TMPDIR/pkg/custodexa/custodexa.sh" <<'CHILD'
#!/usr/bin/env bash
for arg in "$@"; do printf 'arg=<%s>\n' "$arg" >>"$GET_HANDOFF_LOG"; done
if [ -t 0 ]; then echo 'stdin=tty' >>"$GET_HANDOFF_LOG"; else echo 'stdin=not-tty' >>"$GET_HANDOFF_LOG"; fi
echo child-ok
CHILD
  chmod +x "$BATS_TEST_TMPDIR/pkg/custodexa/custodexa.sh"
  tar -C "$BATS_TEST_TMPDIR/pkg" -czf "$FAKE_RELEASE_DIR/download/v1.14.0/custodexa-1.14.0.tar.gz" custodexa
  (cd "$FAKE_RELEASE_DIR/download/v1.14.0" && sha256sum custodexa-1.14.0.tar.gz >SHA256SUMS)
  cat >"$BATS_TEST_TMPDIR/bin/curl" <<'FAKE'
#!/usr/bin/env bash
out='' url=''
while [ "$#" -gt 0 ]; do
  case $1 in -o) out=$2; shift 2 ;; http*) url=$1; shift ;; *) shift ;; esac
done
src="$FAKE_RELEASE_DIR/${url#"$CX_GET_RELEASE_BASE"/}"
[ -f "$src" ] || { echo "curl: (22) HTTP 404 for $url" >&2; exit 22; }
cp "$src" "$out"
FAKE
  chmod +x "$BATS_TEST_TMPDIR/bin/curl"
  export PATH="$BATS_TEST_TMPDIR/bin:$PATH"
  DEST=$BATS_TEST_TMPDIR/opt/custodexa
}

@test "latest release is resolved and a verified package is handed to the installed script" {
  run bash "$GET" --dir "$DEST" status
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [ -f "$DEST/custodexa.sh" ]
  [[ $output == *'[ .. ]'* && $output == *'child-ok'* ]]
  grep -Fxq 'arg=<status>' "$GET_HANDOFF_LOG"
}

@test "explicit semver is accepted and other child arguments keep their order" {
  run bash "$GET" --version 1.14.0 --dir "$DEST" --lang en install --yes
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [ "$(sed -n '1,3p' "$GET_HANDOFF_LOG")" = $'arg=<--lang>\narg=<en>\narg=<install>' ]
  grep -Fxq 'arg=<--yes>' "$GET_HANDOFF_LOG"
  run bash "$GET" --version 1.14 --dir "$BATS_TEST_TMPDIR/bad" install
  [ "$status" -ne 0 ] && [[ $output == *'X.Y.Z'* ]]
}

@test "checksum mismatch stops before unpacking and asks for a fresh download" {
  printf 'tampered\n' >"$FAKE_RELEASE_DIR/download/v1.14.0/custodexa-1.14.0.tar.gz"
  run bash "$GET" --version 1.14.0 --dir "$DEST" install --yes
  [ "$status" -ne 0 ] && [[ $output == *'checksum'* && $output == *'download again'* ]] || { echo "$output"; return 1; }
  [ ! -e "$DEST" ] && [ ! -e "$GET_HANDOFF_LOG" ]
}

@test "existing deployment is not overwritten and receives the original arguments" {
  mkdir -p "$DEST"
  cp "$BATS_TEST_TMPDIR/pkg/custodexa/custodexa.sh" "$DEST/custodexa.sh"
  printf 'keep\n' >"$DEST/sentinel"
  run bash "$GET" --version 1.14.0 --dir "$DEST" upgrade 1.14.1 --yes
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [ "$(cat "$DEST/sentinel")" = keep ]
  [ "$(sed -n '1,3p' "$GET_HANDOFF_LOG")" = $'arg=<upgrade>\narg=<1.14.1>\narg=<--yes>' ]
}

@test "an unrecognized occupied directory is refused without writes" {
  mkdir -p "$DEST"
  printf 'keep\n' >"$DEST/sentinel"
  run bash "$GET" --dir "$DEST" install
  [ "$status" -ne 0 ] && [[ $output == *'already exists'* ]] || { echo "$output"; return 1; }
  [ "$(cat "$DEST/sentinel")" = keep ]
}

@test "a pipe with a controlling terminal gives the child /dev/tty" {
  run script -q -c "cat '$GET' | bash -s -- --version 1.14.0 --dir '$DEST' install" /dev/null
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  grep -Fxq 'stdin=tty' "$GET_HANDOFF_LOG" || { cat "$GET_HANDOFF_LOG"; return 1; }
}

@test "no terminal and no child command refuses promptly instead of waiting for the script pipe" {
  run timeout 5 bash "$GET" --version 1.14.0 --dir "$DEST"
  [ "$status" -ne 0 ] && [ "$status" -ne 124 ] || { echo "$output"; return 1; }
  [[ $output == *'install --yes'* ]] || { echo "$output"; return 1; }
  [ ! -e "$DEST" ]
}

@test "a missing latest release or package gives an actionable network error" {
  rm "$FAKE_RELEASE_DIR/latest/download/MANIFEST.json"
  run bash "$GET" --dir "$DEST" install --yes
  [ "$status" -ne 0 ] && [[ $output == *'release'* && $output == *'download'* ]] || { echo "$output"; return 1; }
  [ ! -e "$DEST" ]
  rm "$FAKE_RELEASE_DIR/download/v1.14.0/custodexa-1.14.0.tar.gz"
  run bash "$GET" --version 1.14.0 --dir "$DEST" install --yes
  [ "$status" -ne 0 ] && [[ $output == *'custodexa-1.14.0.tar.gz'* ]] || { echo "$output"; return 1; }
  [ ! -e "$DEST" ]
}

@test "release workflow lists the fixed-name guide in checksums and verifies its downloaded bytes" {
  workflow=$(</src/.github/workflows/release-images.yml)
  [[ $workflow == *'cp scripts/get-custodexa.sh "$dist/get-custodexa.sh"'* ]] || return 1
  [[ $workflow == *'MANIFEST.json get-custodexa.sh > SHA256SUMS'* ]] || return 1
  [[ $workflow == *'sha256sum --check --strict --quiet SHA256SUMS'* ]] || return 1
}

@test "handoff refuses group or world writable parent, deployment, and script" {
  mkdir -p "$DEST"
  cp "$BATS_TEST_TMPDIR/pkg/custodexa/custodexa.sh" "$DEST/custodexa.sh"
  for unsafe in "$(dirname "$DEST")" "$DEST" "$DEST/custodexa.sh"; do
    for bit in g+w o+w; do
      chmod "$bit" "$unsafe"
      run bash "$GET" --dir "$DEST" status
      [ "$status" -ne 0 ] && [[ $output == *'owner and permissions'* ]] || { echo "$output"; return 1; }
      [ ! -e "$GET_HANDOFF_LOG" ]
      chmod "${bit%+w}-w" "$unsafe"
    done
  done
}

@test "handoff refuses another owner and symlinked deployment path or script" {
  mkdir -p "$DEST"
  cp "$BATS_TEST_TMPDIR/pkg/custodexa/custodexa.sh" "$DEST/custodexa.sh"
  chown 65534 "$DEST/custodexa.sh"
  run bash "$GET" --dir "$DEST" status
  [ "$status" -ne 0 ] && [[ $output == *'owner and permissions'* ]] || { echo "$output"; return 1; }
  [ ! -e "$GET_HANDOFF_LOG" ]
  chown 0 "$DEST/custodexa.sh"
  mv "$DEST/custodexa.sh" "$BATS_TEST_TMPDIR/outside.sh"
  ln -s "$BATS_TEST_TMPDIR/outside.sh" "$DEST/custodexa.sh"
  run bash "$GET" --dir "$DEST" status
  [ "$status" -ne 0 ] && [[ $output == *'owner and permissions'* ]] || { echo "$output"; return 1; }
  [ ! -e "$GET_HANDOFF_LOG" ]
  mv "$DEST" "$BATS_TEST_TMPDIR/real-deployment"
  ln -s "$BATS_TEST_TMPDIR/real-deployment" "$DEST"
  run bash "$GET" --dir "$DEST" status
  [ "$status" -ne 0 ] && [[ $output == *'owner and permissions'* ]] || { echo "$output"; return 1; }
  [ ! -e "$GET_HANDOFF_LOG" ]
}

@test "handoff refuses a symlinked parent directory" {
  mkdir -p "$DEST"
  cp "$BATS_TEST_TMPDIR/pkg/custodexa/custodexa.sh" "$DEST/custodexa.sh"
  ln -s "$(dirname "$DEST")" "$BATS_TEST_TMPDIR/link-parent"
  run bash "$GET" --dir "$BATS_TEST_TMPDIR/link-parent/custodexa" status
  [ "$status" -ne 0 ] && [[ $output == *'owner and permissions'* ]] || { echo "$output"; return 1; }
  [ ! -e "$GET_HANDOFF_LOG" ]
}

@test "archive with an external custodexa.sh symlink is rejected before publication" {
  outside=$BATS_TEST_TMPDIR/outside.sh
  cp "$BATS_TEST_TMPDIR/pkg/custodexa/custodexa.sh" "$outside"
  rm "$BATS_TEST_TMPDIR/pkg/custodexa/custodexa.sh"
  ln -s "$outside" "$BATS_TEST_TMPDIR/pkg/custodexa/custodexa.sh"
  tar -C "$BATS_TEST_TMPDIR/pkg" -czf "$FAKE_RELEASE_DIR/download/v1.14.0/custodexa-1.14.0.tar.gz" custodexa
  (cd "$FAKE_RELEASE_DIR/download/v1.14.0" && sha256sum custodexa-1.14.0.tar.gz >SHA256SUMS)
  run bash "$GET" --version 1.14.0 --dir "$DEST" install --yes
  [ "$status" -ne 0 ] && [[ $output == *'archive'* ]] || { echo "$output"; return 1; }
  [ ! -e "$DEST" ] && [ ! -e "$GET_HANDOFF_LOG" ]
}

@test "archive refuses an unrelated external link member before extraction" {
  ln -s "$BATS_TEST_TMPDIR" "$BATS_TEST_TMPDIR/pkg/custodexa/escape"
  tar -C "$BATS_TEST_TMPDIR/pkg" -czf "$FAKE_RELEASE_DIR/download/v1.14.0/custodexa-1.14.0.tar.gz" custodexa
  (cd "$FAKE_RELEASE_DIR/download/v1.14.0" && sha256sum custodexa-1.14.0.tar.gz >SHA256SUMS)
  run bash "$GET" --version 1.14.0 --dir "$DEST" install --yes
  [ "$status" -ne 0 ] && [[ $output == *'archive'* ]] || { echo "$output"; return 1; }
  [ ! -e "$DEST" ] && [ ! -e "$GET_HANDOFF_LOG" ]
}

@test "fresh install refuses a writable target parent before extraction" {
  mkdir -p "$(dirname "$DEST")"
  chmod o+w "$(dirname "$DEST")"
  run bash "$GET" --version 1.14.0 --dir "$DEST" install --yes
  [ "$status" -ne 0 ] && [[ $output == *'owner and permissions'* ]] || { echo "$output"; return 1; }
  [ ! -e "$DEST" ] && [ ! -e "$GET_HANDOFF_LOG" ]
}

@test "the release package's fixed internal links resolve to a regular script inside the deployment" {
  mkdir -p "$BATS_TEST_TMPDIR/pkg/custodexa/releases/1.14.0"
  mv "$BATS_TEST_TMPDIR/pkg/custodexa/custodexa.sh" \
    "$BATS_TEST_TMPDIR/pkg/custodexa/releases/1.14.0/custodexa.sh"
  ln -s releases/1.14.0 "$BATS_TEST_TMPDIR/pkg/custodexa/current"
  ln -s current/custodexa.sh "$BATS_TEST_TMPDIR/pkg/custodexa/custodexa.sh"
  tar -C "$BATS_TEST_TMPDIR/pkg" -czf "$FAKE_RELEASE_DIR/download/v1.14.0/custodexa-1.14.0.tar.gz" custodexa
  (cd "$FAKE_RELEASE_DIR/download/v1.14.0" && sha256sum custodexa-1.14.0.tar.gz >SHA256SUMS)
  run bash "$GET" --version 1.14.0 --dir "$DEST" status
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  grep -Fxq 'arg=<status>' "$GET_HANDOFF_LOG"
  run bash "$GET" --dir "$DEST" status
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
}

@test "archive extraction stages privately beside the target and cleans up on failure" {
  mkdir -p "$(dirname "$DEST")"
  export TAR_STAGE_LOG=$BATS_TEST_TMPDIR/tar-stage.log
  cat >"$BATS_TEST_TMPDIR/bin/tar" <<'FAKE'
#!/usr/bin/env bash
args=("$@")
if [ "$1" = -xzf ]; then
  for ((i=0; i<${#args[@]}; i++)); do
    if [ "${args[$i]}" = -C ]; then
      stage=${args[$((i + 1))]}
      printf '%s %s\n' "$stage" "$(stat -c %a "$stage")" >"$TAR_STAGE_LOG"
    fi
  done
fi
exec /usr/bin/tar "${args[@]}"
FAKE
  chmod +x "$BATS_TEST_TMPDIR/bin/tar"
  run bash "$GET" --version 1.14.0 --dir "$DEST" install --yes
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  read -r stage mode <"$TAR_STAGE_LOG"
  [ "$(dirname "$stage")" = "$(dirname "$DEST")" ] && [ "$mode" = 700 ] || {
    echo "expected private staging beside target; got $stage mode $mode"
    return 1
  }
  [ ! -e "$stage" ] && [ -f "$DEST/custodexa.sh" ]

  failed_dest=$BATS_TEST_TMPDIR/failed/custodexa
  mkdir -p "$(dirname "$failed_dest")"
  rm "$BATS_TEST_TMPDIR/pkg/custodexa/custodexa.sh"
  tar -C "$BATS_TEST_TMPDIR/pkg" -czf "$FAKE_RELEASE_DIR/download/v1.14.0/custodexa-1.14.0.tar.gz" custodexa
  (cd "$FAKE_RELEASE_DIR/download/v1.14.0" && sha256sum custodexa-1.14.0.tar.gz >SHA256SUMS)
  run bash "$GET" --version 1.14.0 --dir "$failed_dest" install --yes
  [ "$status" -ne 0 ] && [ ! -e "$failed_dest" ]
  [ -z "$(find "$(dirname "$failed_dest")" -mindepth 1 -maxdepth 1 -print -quit)" ]
}

@test "three-language product guides explain trusted source override and pipeline failure status" {
  for doc in /src/docs/QUICKSTART.md /src/docs/zh-TW/QUICKSTART.md /src/docs/ja/QUICKSTART.md \
    /src/README.md /src/docs/zh-TW/README.md /src/docs/ja/README.md; do
    grep -Fq 'CX_GET_RELEASE_BASE' "$doc" || { echo "missing trust boundary: $doc"; return 1; }
    grep -Fq 'set -o pipefail' "$doc" || { echo "missing pipeline status guidance: $doc"; return 1; }
  done
}
