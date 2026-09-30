#!/usr/bin/env bash
# Run the custodexa.sh test suite (bats) and shellcheck inside the pinned runner image.
#   bash scripts/custodexa/tests/run.sh            # all tests + shellcheck
#   bash scripts/custodexa/tests/run.sh <file.bats> # one file
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
img=custodexa-script-test:1
docker build -q -t "$img" "$here" >/dev/null
targets=("$@")
[ ${#targets[@]} -gt 0 ] || targets=(scripts/custodexa/tests/)
# CX_MUTANT=<dir>: run the suite against a mutated copy of scripts/custodexa (mutation checks).
extra=()
[ -n "${CX_MUTANT:-}" ] && extra=(-v "$CX_MUTANT:/src/scripts/custodexa:ro")
# CX_MUTANT_PACKAGING=<dir>: the same for a mutated copy of packaging/ (the compose files).
[ -n "${CX_MUTANT_PACKAGING:-}" ] && extra+=(-v "$CX_MUTANT_PACKAGING:/src/packaging:ro")
docker run --rm -v "$repo:/src:ro" ${extra[@]+"${extra[@]}"} "$img" bash -c '
  set -u
  echo "== versions: $(bats --version); shellcheck $(shellcheck --version | sed -n "s/^version: //p"); $(jq --version)"
  bats --print-output-on-failure "$@"; b=$?
  echo "== shellcheck -S style"
  shellcheck -S style -x -P scripts/custodexa scripts/get-custodexa.sh scripts/custodexa/custodexa.sh scripts/custodexa/lib/*.sh scripts/custodexa/lang/*.sh; s=$?
  [ $s -eq 0 ] && echo "shellcheck: no findings"
  echo "== bats exit=$b shellcheck exit=$s"
  [ $b -eq 0 ] && [ $s -eq 0 ]
' _ "${targets[@]}"
