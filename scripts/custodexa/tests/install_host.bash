# A Linux host for the tests that run install and load: what the host tools answer (architecture,
# addresses, free space, port listeners, clock) and, for a whole run, a simulated Docker daemon with
# the release's images in its registries (tests/fakes/stack-sim over tests/fakes/daemon-sim).
# Needs helper.bash and release_fixture.bash loaded, and ROOT set.

docker_says() { printf '%s\n' "$2" >"$FAKE_DOCKER_REPLAY/$1.out"; }
docker_rc() { printf '%s\n' "$2" >"$FAKE_DOCKER_REPLAY/$1.rc"; }
fake() { printf '#!/bin/bash\n%s\n' "$2" >"$FAKES/$1"; chmod +x "$FAKES/$1"; }
host_arch() { fake uname 'if [ "$1" = -m ]; then echo '"$1"'; else exec /bin/uname "$@"; fi'; }
host_ip() { fake ip 'echo "1.1.1.1 via 10.0.0.1 dev eth0 src '"$1"' uid 0"'; }
host_free() { # <mount> <free KiB>: df answers for a path with the longest mount above it
  touch "$FAKES/df.table"
  { grep -v "^$1 " "$FAKES/df.table" || true; printf '%s %s\n' "$1" "$2"; } >"$FAKES/df.new"
  mv "$FAKES/df.new" "$FAKES/df.table"
  fake df 'd=${@: -1}; best=""; kb=""
while read -r m k; do
  if [ "$m" = / ] || [ "$d" = "$m" ] || [[ $d == "$m"/* ]]; then [ ${#m} -le ${#best} ] || { best=$m; kb=$k; }; fi
done <'"$FAKES/df.table"'
echo "Filesystem 1024-blocks Used Available Capacity Mounted on"; echo "/dev/x 999999999 1 $kb 1% $best"'
}
port_holder() { # <port> <ss users field>: ss reports a listener on that port
  printf 'LISTEN 0 511 0.0.0.0:%s 0.0.0.0:* %s\n' "$1" "$2" >"$FAKES/ss.$1"
  fake ss 'for f in '"$FAKES"'/ss.*; do [ -e "$f" ] || continue; case "$*" in *":${f##*.}") cat "$f" ;; esac; done'
}
# clock <seconds...>: each `date +%s` moves the clock on by the next number (0 once they run out);
# the log file name gets a fixed time. Durations on the screen are then the ones given here.
clock() {
  printf '1000000000\n' >"$FAKES/clock"
  printf '%s\n' "$@" >"$FAKES/clock.steps"
  fake date 'case "$*" in
  +%s) s=$(head -n1 '"$FAKES"'/clock.steps); sed -i 1d '"$FAKES"'/clock.steps
       n=$(( $(cat '"$FAKES"'/clock) + ${s:-0} )); echo $n >'"$FAKES"'/clock; echo $n ;;
  +%Y%m%d-%H%M%S) echo 20260930-101502 ;;
  *) exec /usr/bin/date "$@" ;;
esac'
}

# host_base: the host checks all pass (Docker 27.3.1, Compose v2.29.7, x86_64, room on disk).
host_base() {
  FAKES=$BATS_TEST_TMPDIR/host
  mkdir -p "$FAKES" /var/lib/docker /srv/docker
  export PATH="$FAKES:$PATH"
  unset LC_ALL LC_MESSAGES LANG NO_COLOR CUSTODEXA_HOME
  docker_says 'info_--format_{{.ServerVersion}}-{{.DockerRootDir}}' '27.3.1 /var/lib/docker'
  docker_says compose_version_--short '2.29.7'
  host_arch x86_64
  host_ip 10.0.0.12
  fake hostname 'echo ops-host.example.internal'
  fake sleep ':'
  host_free /var/lib/docker 222298112 # 212 GB in KiB
  host_free / 104857600
}

# host_full: host_base plus the release unpacked at $ROOT, its images in the registries, and the
# simulated daemon answering for images and the deployment's containers.
host_full() {
  host_base
  cp "${CX_TEST_REPO:-/src}/.env.example" "$ROOT/current/.env.example"
  export SIM=$FAKE_DOCKER_REPLAY/sim
  mkdir -p "$SIM"
  ln -sf "$TESTS_DIR/fakes/stack-sim" "$FAKE_DOCKER_REPLAY/hook"
  fixture_release
  cp "$SRC/../../packaging/compose.yml" "$ROOT/current/compose.yml"
}

# install_run <lang> [options...]: the real script, as an operator runs it, without a terminal.
install_run() {
  local l=$1
  shift
  run bash "$ROOT/custodexa.sh" install --lang "$l" "$@" </dev/null
}

# no_publisher_tools: this host has neither cosign nor gh (tests/fakes holds fakes of both).
no_publisher_tools() {
  local bin=$BATS_TEST_TMPDIR/bin
  mkdir -p "$bin"
  ln -sf "$TESTS_DIR/fakes/docker" "$bin/docker"
  export PATH="$FAKES:$bin:${PATH//$TESTS_DIR\/fakes:/}"
}

# fresh_host: forget an earlier install on this host (settings, state, logs, running services), keep
# the images; the next install starts from an unpacked package again.
fresh_host() {
  rm -rf "$ROOT/.env" "$ROOT/state.json" "$ROOT/state.json.prev" "$ROOT/logs" "$ROOT/data" \
    "$ROOT/.custodexa.lock" "$ROOT/current/images.env" "$ROOT/current/image-ids.env"
  : >"$SIM/containers"
  : >"$SIM/published"
  rm -f "$SIM/workdir"
}
