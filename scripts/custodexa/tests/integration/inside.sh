#!/usr/bin/env bash
# Runs on an integration host (inside its dind container); run.sh calls it with docker exec.
#   inside.sh build              builder host: the install package, the offline bundle, image tars
#   inside.sh scenario <name>    load the scenario's images, run it, print PASS <name> or FAIL <name>
set -euo pipefail
IT_DIR=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=scripts/custodexa/tests/integration/lib/common.sh
. "$IT_DIR/lib/common.sh"

case ${1:-} in
  build)
    # shellcheck source=scripts/custodexa/tests/integration/lib/build.sh
    . "$IT_DIR/lib/build.sh"
    it_build
    ;;
  scenario)
    [ -n "${2:-}" ] || it_die "usage: inside.sh scenario <name>"
    it_run_scenario "$2"
    ;;
  *) it_die "usage: inside.sh build | scenario <name>" ;;
esac
