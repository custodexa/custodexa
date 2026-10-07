# shellcheck shell=bash
# Shared by the builder and the scenarios, on the integration host. Paths on that host:
#   /src          the working tree, read-only
#   /it           scratch space of this host, gone with it
#   /it-run       this run: the package (pkg/), the builder's notes; read-only for scenarios
#   /cache/images image tars, read-only for scenarios
#   /bundle       the offline bundle with its SHA256SUMS (scenarios that need the package)
#   /transfer     the one volume the hosts of a two-host scenario share (read-write)

readonly IT_WORK=/it

it_say() { printf '%s\n' "$*"; }
it_step() { printf -- '-- %s\n' "$*"; }
it_die() {
  printf 'integration: %s\n' "$*" >&2
  exit 1
}

# it_check <what> <command...>: "ok - <what>", or "not ok - <what>" with the end of the command's
# output and a non-zero return (which ends the scenario).
it_check() {
  local what=$1 out rc
  shift
  out=$("$@" 2>&1) && rc=0 || rc=$?
  if [ "$rc" -ne 0 ]; then
    printf 'not ok - %s (exit %s)\n' "$what" "$rc"
    printf '%s\n' "$out" | tail -n 30 | sed 's/^/   | /'
    return 1
  fi
  printf 'ok - %s\n' "$what"
}

# it_expect_fail <what> <pattern> <command...>: the command must fail and print the pattern (an
# extended regular expression), so a refusal is told apart from a broken setup.
it_expect_fail() {
  local what=$1 pattern=$2 out rc
  shift 2
  out=$("$@" 2>&1) && rc=0 || rc=$?
  if [ "$rc" -eq 0 ] || ! grep -Eq -- "$pattern" <<<"$out"; then
    printf 'not ok - %s (exit %s, wanted a failure matching: %s)\n' "$what" "$rc" "$pattern"
    printf '%s\n' "$out" | tail -n 30 | sed 's/^/   | /'
    return 1
  fi
  printf 'ok - %s\n' "$what"
}

# it_same <what> <expected> <actual>
it_same() {
  if [ "$2" != "$3" ]; then
    printf 'not ok - %s\n   | expected: %s\n   | actual:   %s\n' "$1" "$2" "$3"
    return 1
  fi
  printf 'ok - %s\n' "$1"
}

# IT_IMAGE[key]: the reference of each image loaded for this scenario (keys of images.txt).
declare -gA IT_IMAGE=()

# it_load_images "<key>=<tar> ...": docker load each tar from the cache.
it_load_images() {
  local pair key tar out
  for pair in $1; do
    key=${pair%%=*} tar=${pair#*=}
    out=$(docker load -i "/cache/images/$tar") || it_die "cannot load $tar"
    IT_IMAGE[$key]=$(sed -n 's/^Loaded image: //p' <<<"$out" | head -n1)
    [ -n "${IT_IMAGE[$key]}" ] || it_die "$tar loaded no tagged image"
  done
}

it_image() {
  [ -n "${IT_IMAGE[$1]:-}" ] || it_die "image $1 is not loaded: add it to the scenario's '# images:' line"
  printf '%s' "${IT_IMAGE[$1]}"
}

# it_run_scenario <name>: the scenario file defines scenario(); errexit ends it at the first
# failing command, and the EXIT trap prints the FAIL line. On a host of a two-host scenario
# (IT_HOST set by run.sh) it runs scenario_<IT_HOST>() instead, and only the last host
# (IT_HOST_LAST=1) prints the PASS line.
it_run_scenario() {
  local name=$1 file=$IT_DIR/scenarios/$1.sh fn=scenario where=""
  [ -f "$file" ] || it_die "no scenario $name"
  if [ -n "${IT_HOST:-}" ]; then
    fn=scenario_$IT_HOST
    where="host $IT_HOST, "
  fi
  mkdir -p "$IT_WORK"
  it_load_images "${IT_IMAGES:-}"
  # shellcheck source=scripts/custodexa/tests/integration/lib/deploy.sh
  . "$IT_DIR/lib/deploy.sh"
  # shellcheck source=scripts/custodexa/tests/integration/lib/openssl.sh
  . "$IT_DIR/lib/openssl.sh"
  # shellcheck source=scripts/custodexa/tests/integration/lib/pg.sh
  . "$IT_DIR/lib/pg.sh"
  # shellcheck source=scripts/custodexa/tests/integration/lib/snap.sh
  . "$IT_DIR/lib/snap.sh"
  # shellcheck source=scripts/custodexa/tests/integration/lib/extdb.sh
  . "$IT_DIR/lib/extdb.sh"
  # shellcheck source=scripts/custodexa/tests/integration/lib/versions.sh
  . "$IT_DIR/lib/versions.sh"
  # shellcheck source=scripts/custodexa/tests/integration/lib/restore.sh
  . "$IT_DIR/lib/restore.sh"
  # shellcheck source=scripts/custodexa/tests/integration/lib/extrestore.sh
  . "$IT_DIR/lib/extrestore.sh"
  # shellcheck disable=SC1090
  . "$file"
  declare -F "$fn" >/dev/null || it_die "scenario $name defines no $fn()"
  IT_SCENARIO=$name
  IT_WHERE=$where
  trap 'rc=$?; [ "$rc" -eq 0 ] || printf "FAIL %s (%sexit %s)\n" "$IT_SCENARIO" "$IT_WHERE" "$rc"' EXIT
  it_say "engine: $(docker version --format '{{.Server.Version}}'), image store: $(it_store)"
  "$fn"
  if [ -n "${IT_HOST:-}" ] && [ "${IT_HOST_LAST:-0}" != 1 ]; then
    printf 'ok - host %s done\n' "$IT_HOST"
    return 0
  fi
  printf 'PASS %s\n' "$name"
}

it_store() {
  if docker info --format '{{json .DriverStatus}}' | grep -q io.containerd.snapshotter; then
    printf containerd
  else
    printf classic
  fi
}
