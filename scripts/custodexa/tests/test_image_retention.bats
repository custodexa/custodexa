#!/usr/bin/env bats
# Threat (A): an image removed that a rollback, a pending load or a container still needs, an
# upstream image removed, or a removal that fails taking the upgrade with it; and (B) old images
# left behind until the disk is full. The simulated daemon (tests/fakes/daemon-sim) keeps the images
# and their references, and removes them the way both image stores do.

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
  unset LC_ALL LC_MESSAGES LANG NO_COLOR CUSTODEXA_HOME
  fixture_release
  : >"$SIM/images"
  : >"$SIM/containers"
  STATE=""
}

docker_says() { printf '%s\n' "$2" >"$FAKE_DOCKER_REPLAY/$1.out"; }
fake() { printf '#!/bin/bash\n%s\n' "$2" >"$FAKES/$1"; chmod +x "$FAKES/$1"; }

# sid <label>: a made-up image ID.
sid() { printf 'sha256:%s' "$(printf '%s' "$1" | sha256sum | cut -c1-64)"; }
# state <key> <value>: a state.json entry for the run.
state() { STATE+="$1=$2"$'\n'; }
gone() { ! grep -q " $1\$" "$SIM/images"; }
here() { grep -q " $1\$" "$SIM/images"; }
rmi_calls() { grep -c $'^ARGS\trmi ' "$FAKE_DOCKER_LOG" || true; }

# prune [lang]: cx_ir_prune with the release manifest of fixture_release and the state given, then
# the closing lines and an end marker. Under the shell options of custodexa.sh, and called the way
# the upgrade calls it (not inside a condition, where errexit would be off): a command that fails
# inside ends the shell here as it would end the upgrade there.
prune() {
  run env CX_LANG_FLAG="${1:-en}" STATE="$STATE" CX_KEEP_IMAGES="${KEEP:-0}" bash -c '
    set -euo pipefail
    . "$1/lib/common.sh"; cx_load_libs "$1"; . "$1/lib/image_retention.sh"
    CX_ROOT=/opt/custodexa CX_LOG_FILE=$BATS_TEST_TMPDIR/upgrade.log CX_IMG_ARCH=amd64
    cx_manifest_load "$CX_ROOT/current/MANIFEST.json" || exit 1
    cx_state_reset
    while IFS= read -r kv; do [ -z "$kv" ] || cx_state_set "${kv%%=*}" "${kv#*=}"; done <<<"$STATE"
    cx_ir_prune
    printf "removed=%s failed=%s\n" "$CX_IR_REMOVED" "${#CX_IR_FAILED[@]}"
    cx_ir_print
    echo "end of closing screen"' _ "$SRC"
}

# three_versions <store>: A (two upgrades ago), B (previous) and C (current) of backend and
# frontend pulled by digest, the upstream images of the release, state recording B and C.
three_versions() {
  local v n
  store "$1"
  for v in a b c; do
    for n in backend frontend; do have "${REF[$n]}@$(sid "idx-$v-$n")" "$(sid "id-$v-$n")"; done
  done
  for n in postgres guacd openssl nginx; do
    if [ "$1" = containerd ]; then have "${REF[$n]}@${IDX[$n]}" "${IDX[$n]}"; else have "${REF[$n]}@${IDX[$n]}" "${CFG[$n]}"; fi
  done
  state current.image_ids "backend=$(sid id-c-backend) frontend=$(sid id-c-frontend)"
  state previous.image_ids "backend=$(sid id-b-backend) frontend=$(sid id-b-frontend)"
}

@test "two upgrades in a row: only the version before the previous one goes, on both stores" {
  for s in classic containerd; do
    : >"$SIM/images"
    : >"$FAKE_DOCKER_LOG"
    STATE=""
    three_versions "$s"
    prune
    [ "$status" -eq 0 ] || { echo "[$s] $output"; return 1; }
    [[ $output == *"removed=2 failed=0"* ]] || { echo "[$s] $output"; return 1; }
    gone "$(sid id-a-backend)" || return 1; gone "$(sid id-a-frontend)" || return 1
    for v in b c; do here "$(sid "id-$v-backend")" || return 1; here "$(sid "id-$v-frontend")" || return 1; done
    [ "$(grep -c . "$SIM/images")" -eq 8 ] # B, C and the four upstream images
    grep -q $'^ARGS\trmi ghcr.io/custodexa/backend@' "$FAKE_DOCKER_LOG"
    [ "$(rmi_calls)" -eq 2 ]
  done
}

@test "upstream images never reach rmi, not even an older one no state names" {
  three_versions classic
  have docker.io/library/postgres:15.8 "$(sid old-postgres)"
  have docker.io/guacamole/guacd:1.5.5 "$(sid old-guacd)"
  prune
  [ "$status" -eq 0 ]
  here "$(sid old-postgres)" || return 1; here "$(sid old-guacd)" || return 1
  ! grep -E $'^ARGS\trmi .*(postgres|guacd|openssl|nginx)' "$FAKE_DOCKER_LOG" || return 1
}

@test "an image load recorded for the next version stays" {
  three_versions classic
  have ghcr.io/custodexa/backend:1.17.9 "$(sid id-load-backend)"
  have ghcr.io/custodexa/frontend:1.17.9 "$(sid id-load-frontend)"
  state load.version 1.17.9
  state load.image_ids "backend=$(sid id-load-backend) frontend=$(sid id-load-frontend)"
  prune
  [ "$status" -eq 0 ]
  here "$(sid id-load-backend)" || return 1; here "$(sid id-load-frontend)" || return 1
  [[ $output == *"removed=2 failed=0"* ]]
}

@test "both sides of the last rollback stay (rollback --revert needs them)" {
  three_versions classic
  have ghcr.io/custodexa/backend:1.12.0 "$(sid id-rb-from)"
  have ghcr.io/custodexa/frontend:1.12.0 "$(sid id-rb-to-tool)"
  state last_rollback.from.image_ids "backend=$(sid id-rb-from)"
  state last_rollback.to.tool_image_ids "openssl=$(sid id-rb-to-tool)"
  prune
  [ "$status" -eq 0 ]
  here "$(sid id-rb-from)" || return 1; here "$(sid id-rb-to-tool)" || return 1
  gone "$(sid id-a-backend)"
}

@test "an image a container uses stays, a stopped container included" {
  three_versions classic
  printf '%s %s\n' old-backend-stopped "$(sid id-a-backend)" >>"$SIM/containers"
  prune
  [ "$status" -eq 0 ]
  here "$(sid id-a-backend)"
  gone "$(sid id-a-frontend)"
  ! grep -q $'^ARGS\trmi .*idx-a-backend' "$FAKE_DOCKER_LOG" || return 1
  [[ $output == *"removed=1 failed=0"* ]]
}

@test "containerd: images loaded from a bundle are told apart by the recorded ID alone" {
  store containerd
  # Loaded bundles: tags only, IDs that no digest of any manifest names.
  for v in 1.16.0 1.17.0 1.17.5; do
    for n in backend frontend; do have "${REF[$n]}:$v" "$(sid "loaded-$v-$n")"; done
  done
  state current.image_ids "backend=$(sid loaded-1.17.5-backend) frontend=$(sid loaded-1.17.5-frontend)"
  state previous.image_ids "backend=$(sid loaded-1.17.0-backend) frontend=$(sid loaded-1.17.0-frontend)"
  prune
  [ "$status" -eq 0 ]
  gone "$(sid loaded-1.16.0-backend)" || return 1; gone "$(sid loaded-1.16.0-frontend)" || return 1
  here "$(sid loaded-1.17.0-backend)" || return 1; here "$(sid loaded-1.17.5-frontend)" || return 1
  grep -q $'^ARGS\trmi ghcr.io/custodexa/backend:1.16.0' "$FAKE_DOCKER_LOG"
}

@test "a removal that fails is reported with the command and the others still go" {
  three_versions classic
  have docker.io/custodexa/backend:latest "$(sid legacy-backend)"
  printf '%s\n' "ghcr.io/custodexa/backend@$(sid idx-a-backend)" >"$SIM/rmi-fail"
  prune
  [ "$status" -eq 0 ]
  here "$(sid id-a-backend)"
  gone "$(sid id-a-frontend)" || return 1; gone "$(sid legacy-backend)" || return 1
  [[ $output == *"removed=2 failed=1"* ]]
  [[ $output == *"[WARN] 1 old image reference(s) could not be removed"* ]]
  [[ $output == *"    sudo docker rmi ghcr.io/custodexa/backend@$(sid idx-a-backend)"* ]]
  grep -q 'device or resource busy' "$BATS_TEST_TMPDIR/upgrade.log"
}

@test "an image the operator tagged in another repository keeps that tag and the image" {
  three_versions classic
  have docker.io/mine/backend:keep "$(sid id-a-backend)"
  prune
  [ "$status" -eq 0 ]
  here "$(sid id-a-backend)"
  grep -q "^docker.io/mine/backend:keep $(sid id-a-backend)\$" "$SIM/images"
  ! grep -q "^ghcr.io/custodexa/backend@$(sid idx-a-backend) " "$SIM/images" || return 1
  ! grep -q $'^ARGS\trmi .*mine/backend' "$FAKE_DOCKER_LOG" || return 1
  [[ $output == *"removed=1 failed=0"* ]]
}

@test "the earlier deployments' custodexa/* tags, the mirror and local builds are cleared too" {
  three_versions classic
  have docker.io/custodexa/backend:latest "$(sid legacy-backend)"
  have docker.io/custodexa/frontend:latest "$(sid legacy-frontend)"
  have docker.io/custodexa/backend@"$(sid idx-mirror)" "$(sid mirror-backend)"
  have docker.io/custodexa-local/frontend:1.15.0 "$(sid local-frontend)"
  have docker.io/library/busybox:latest "$(sid unrelated)"
  prune
  [ "$status" -eq 0 ]
  for x in legacy-backend legacy-frontend mirror-backend local-frontend; do gone "$(sid "$x")" || { echo "$x left"; return 1; }; done
  here "$(sid unrelated)"
  [[ $output == *"removed=6 failed=0"* ]]
  grep -q $'^ARGS\trmi custodexa/backend:latest' "$FAKE_DOCKER_LOG"
}

@test "--keep-images: nothing is listed or removed, and the screen says so in each language" {
  three_versions classic
  KEEP=1 prune en
  [ "$status" -eq 0 ]
  [ "$(rmi_calls)" -eq 0 ]
  ! grep -q $'^ARGS\timage ls' "$FAKE_DOCKER_LOG" || return 1
  [[ $output == *"[SKIP] Old images not removed (--keep-images)."* ]]
  KEEP=1 prune zh-TW
  [[ $output == *"[SKIP] 依 --keep-images，未清除舊版映像。"* ]]
  KEEP=1 prune ja
  [[ $output == *"[SKIP] --keep-images の指定により"* ]]
}

@test "nothing to remove: no line on screen and no question to the containers" {
  store classic
  have "${REF[backend]}@$(sid idx-c-backend)" "$(sid id-c-backend)"
  state current.image_ids "backend=$(sid id-c-backend)"
  prune
  [ "$status" -eq 0 ]
  [ "$output" = $'removed=0 failed=0\nend of closing screen' ]
  ! grep -q $'^ARGS\tps ' "$FAKE_DOCKER_LOG" || return 1
}

@test "the space freed is the difference of the free space before and after, shown in each language" {
  three_versions classic
  docker_says info_--format_{{.DockerRootDir}} /var/lib/docker
  FAKES=$BATS_TEST_TMPDIR/host
  mkdir -p "$FAKES"
  # df: 10 GiB free before the removals, 10 GiB + 540 MiB after.
  fake df 'n=$(cat '"$BATS_TEST_TMPDIR"'/df.n 2>/dev/null || echo 0); echo $((n + 1)) >'"$BATS_TEST_TMPDIR"'/df.n
k=10485760; [ "$n" -ge 1 ] && k=$((k + 552960))
printf "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/sda1 20000000 1 %s 50%% /\n" "$k"'
  export PATH="$FAKES:$PATH"
  prune en
  [ "$status" -eq 0 ]
  [[ $output == *"[ OK ] Removed 2 old backend and frontend image(s), 540 MB freed."* ]] || { echo "$output"; return 1; }
  rm -f "$BATS_TEST_TMPDIR/df.n"
  : >"$SIM/images"; STATE=""; three_versions classic
  prune zh-TW
  [[ $output == *"[ OK ] 已清除 2 個舊版 backend、frontend 映像，釋出 540 MB。"* ]] || { echo "$output"; return 1; }
}

@test "a container gone between the listing and its inspection is skipped; the upgrade still ends well" {
  three_versions classic
  printf '%s %s\n' old-backend-stopped "$(sid id-a-backend)" >>"$SIM/containers"
  # Listed last: the image IDs of the containers come back with a failed inspection at the end.
  echo gone-with-rm >"$SIM/containers-gone"
  prune
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  here "$(sid id-a-backend)" || return 1
  gone "$(sid id-a-frontend)" || return 1
  [[ $output == *"removed=1 failed=0"* ]] || { echo "$output"; return 1; }
  [[ $output == *"[ OK ] Removed 1 old backend and frontend image(s)."* ]] || { echo "$output"; return 1; }
  grep -q "container gone-with-rm skipped" "$BATS_TEST_TMPDIR/upgrade.log" || return 1
  [[ $output == *"end of closing screen"* ]]
}

@test "free space that cannot be read: the images still go and only their number is shown" {
  three_versions classic
  docker_says info_--format_{{.DockerRootDir}} /var/lib/docker
  FAKES=$BATS_TEST_TMPDIR/host
  mkdir -p "$FAKES"
  fake df 'echo "df: /var/lib/docker: Permission denied" >&2; exit 1'
  export PATH="$FAKES:$PATH"
  prune en
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  gone "$(sid id-a-backend)" || return 1; gone "$(sid id-a-frontend)" || return 1
  [[ $output == *"removed=2 failed=0"* ]] || { echo "$output"; return 1; }
  [[ $output == *"[ OK ] Removed 2 old backend and frontend image(s)."* ]] || { echo "$output"; return 1; }
  [[ $output != *"freed"* ]] || { echo "$output"; return 1; }
  grep -q 'freed=unknown' "$BATS_TEST_TMPDIR/upgrade.log"
  [[ $output == *"end of closing screen"* ]]
}
