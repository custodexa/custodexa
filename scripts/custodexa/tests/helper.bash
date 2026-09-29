# Shared helpers for the custodexa.sh bats suite.
# SRC is the script tree under test (scripts/custodexa in the repo, or a mutated copy).
SRC=${CX_TEST_SRC:-/src/scripts/custodexa}
TESTS_DIR=$SRC/tests

# make_root <dir> [version]: lay out a package deployment the way the tarball unpacks it:
#   <dir>/custodexa.sh -> current/custodexa.sh, current -> releases/<ver>, releases/<ver>/<script tree>
make_root() {
  local root=$1 ver=${2:-1.13.0}
  mkdir -p "$root/releases/$ver"
  cp -R "$SRC/custodexa.sh" "$SRC/lib" "$SRC/lang" "$root/releases/$ver/"
  ln -s "releases/$ver" "$root/current"
  ln -s current/custodexa.sh "$root/custodexa.sh"
}

# use_fake_docker: put tests/fakes on PATH; every docker call is appended to $FAKE_DOCKER_LOG.
use_fake_docker() {
  export FAKE_DOCKER_LOG=$BATS_TEST_TMPDIR/docker-calls.txt
  export FAKE_DOCKER_REPLAY=${FAKE_DOCKER_REPLAY:-$BATS_TEST_TMPDIR/replay}
  mkdir -p "$FAKE_DOCKER_REPLAY"
  : >"$FAKE_DOCKER_LOG"
  export PATH="$TESTS_DIR/fakes:$PATH"
}

# load_lib: source the script libraries into the test shell (no subcommand is run).
load_lib() {
  # shellcheck disable=SC1091
  . "$SRC/lib/common.sh"
  cx_load_libs "$SRC"
}
