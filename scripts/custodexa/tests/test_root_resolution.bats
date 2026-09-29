#!/usr/bin/env bats
# Threat (A): acting on the wrong directory. The deployment root decides where .env, state.json,
# data/ and the compose project live; a wrong answer writes into the wrong place.

load helper

setup() {
  T=$BATS_TEST_TMPDIR
  ROOT=$T/opt/custodexa
  make_root "$ROOT"
  load_lib
  unset CUSTODEXA_HOME
}

@test "root link custodexa.sh -> current/custodexa.sh resolves to the root" {
  run cx_resolve_root "$ROOT/custodexa.sh"
  [ "$status" -eq 0 ]
  [ "$output" = "$ROOT" ]
}

@test "three levels of symlinks resolve to the real root" {
  mkdir -p "$T/a" "$T/b" "$T/usr/local/bin"
  ln -s "$ROOT/custodexa.sh" "$T/a/cx1"
  ln -s "$T/a/cx1" "$T/b/cx2"
  ln -s "$T/b/cx2" "$T/usr/local/bin/custodexa.sh"
  run cx_resolve_root "$T/usr/local/bin/custodexa.sh"
  [ "$status" -eq 0 ]
  [ "$output" = "$ROOT" ]
}

@test "running releases/<ver>/custodexa.sh directly (handoff target) resolves to the root" {
  make_root_release() { mkdir -p "$ROOT/releases/1.14.0"; cp -R "$SRC/custodexa.sh" "$SRC/lib" "$SRC/lang" "$ROOT/releases/1.14.0/"; }
  make_root_release
  run cx_resolve_root "$ROOT/releases/1.14.0/custodexa.sh"
  [ "$status" -eq 0 ]
  [ "$output" = "$ROOT" ]
}

@test "a root holding state.json but no releases/ still resolves (converted layout)" {
  mkdir -p "$T/srv/cx"
  cp -R "$SRC/custodexa.sh" "$SRC/lib" "$SRC/lang" "$T/srv/cx/"
  printf '{\n  "format": "2"\n}\n' >"$T/srv/cx/state.json"
  run cx_resolve_root "$T/srv/cx/custodexa.sh"
  [ "$status" -eq 0 ]
  [ "$output" = "$T/srv/cx" ]
}

@test "CUSTODEXA_HOME overrides the script location" {
  OTHER=$T/data/custodexa
  make_root "$OTHER"
  CUSTODEXA_HOME=$OTHER run cx_resolve_root "$ROOT/custodexa.sh"
  [ "$status" -eq 0 ]
  [ "$output" = "$OTHER" ]
}

@test "CUSTODEXA_HOME pointing at a folder that is not a deployment is refused" {
  mkdir -p "$T/empty"
  CUSTODEXA_HOME=$T/empty run cx_resolve_root "$ROOT/custodexa.sh"
  [ "$status" -ne 0 ]
  [[ "$output" == *"$T/empty"* ]]
}

@test "a script outside any deployment is refused instead of guessing a parent" {
  mkdir -p "$T/loose/x"
  cp -R "$SRC/custodexa.sh" "$SRC/lib" "$SRC/lang" "$T/loose/x/"
  run cx_resolve_root "$T/loose/x/custodexa.sh"
  [ "$status" -ne 0 ]
}

@test "root path check accepts the allowed characters" {
  run cx_check_root_path /opt/custodexa-1.13_0/x.y
  [ "$status" -eq 0 ]
}

@test "root path with a space is rejected" {
  run cx_check_root_path "/opt/my custodexa"
  [ "$status" -ne 0 ]
}

@test "root path with quotes, backslash, dollar or non-ASCII is rejected" {
  for p in "/opt/it's" '/opt/a"b' '/opt/a\b' '/opt/$HOME' '/opt/部署' '/opt/a
b' 'relative/path'; do
    run cx_check_root_path "$p"
    [ "$status" -ne 0 ] || { echo "accepted: $p"; return 1; }
  done
}

@test "whole script: a root under a path with a space stops before writing anything" {
  SP="$T/with space/custodexa"
  make_root "$SP"
  use_fake_docker
  before=$(cd "$SP" && find . | sort)
  run "$SP/custodexa.sh" install --lang en
  [ "$status" -eq 1 ]
  [[ "$output" == *"[FAIL]"* ]]
  [[ "$output" == *"with space"* ]]
  after=$(cd "$SP" && find . | sort)
  [ "$before" = "$after" ]
  [ ! -s "$FAKE_DOCKER_LOG" ]
}

@test "non-Linux host is refused and pointed at quickstart.sh" {
  mkdir -p "$T/fakeuname"
  printf '#!/bin/sh\necho Darwin\n' >"$T/fakeuname/uname"; chmod +x "$T/fakeuname/uname"
  PATH="$T/fakeuname:$PATH" run "$ROOT/custodexa.sh" status --lang en
  [ "$status" -eq 1 ]
  [[ "$output" == *"Linux"* ]]
  [[ "$output" == *"quickstart.sh"* ]]
}
