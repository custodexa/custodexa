#!/usr/bin/env bash
# Run the custodexa.sh test suite (bats) and shellcheck inside the pinned runner image.
#   bash scripts/custodexa/tests/run.sh            # all tests + shellcheck
#   bash scripts/custodexa/tests/run.sh <file.bats> # one file
#   CX_JOBS=1 bash scripts/custodexa/tests/run.sh   # one container, files one after another
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
img=custodexa-script-test:1
docker build -q -t "$img" "$here" >/dev/null
# Several files run at once, each container taking the next file from a shared queue. The tests
# use fixed host paths (/opt/custodexa, /home/ops), so two files never share one container.
# Capped at 3 containers by default so the suite leaves the rest of the machine free.
jobs=${CX_JOBS:-3}
case $jobs in ''|*[!0-9]*|0) echo "CX_JOBS must be a positive number" >&2; exit 2 ;; esac
# CX_MUTANT=<dir>: run the suite against a mutated copy of scripts/custodexa (mutation checks).
extra=()
[ -n "${CX_MUTANT:-}" ] && extra=(-v "$CX_MUTANT:/src/scripts/custodexa:ro")
# CX_MUTANT_PACKAGING=<dir>: the same for a mutated copy of packaging/ (the compose files).
[ -n "${CX_MUTANT_PACKAGING:-}" ] && extra+=(-v "$CX_MUTANT_PACKAGING:/src/packaging:ro")

# Split the arguments: --timing is the one bats option the queue passes on; any other option,
# or a single file, runs everything in one container as given.
opts=() files=() single=0
for a in "$@"; do
  case $a in
    --timing) opts+=("$a") ;;
    -*) single=1 ;;
    *.bats) files+=("$a") ;;
    *) for f in $(cd "$repo" && ls -S "${a%/}"/*.bats); do files+=("$f"); done ;;
  esac
done
paths=${#files[@]}
[ "$paths" -gt 0 ] || for f in $(cd "$repo" && ls -S scripts/custodexa/tests/*.bats); do files+=("$f"); done
[ "$jobs" -gt 1 ] && [ ${#files[@]} -gt 1 ] || single=1

# Both snippets run inside the container, so they stay unexpanded here.
# shellcheck disable=SC2016
shellcheck_step='
  echo "== shellcheck -S style"
  shellcheck -S style -x -P scripts/custodexa scripts/get-custodexa.sh scripts/custodexa/custodexa.sh scripts/custodexa/lib/*.sh scripts/custodexa/lang/*.sh; s=$?
  [ $s -eq 0 ] && echo "shellcheck: no findings"'
# shellcheck disable=SC2016
versions='echo "== versions: $(bats --version); shellcheck $(shellcheck --version | sed -n "s/^version: //p"); $(jq --version)"'

if [ $single = 1 ]; then
  [ "$paths" -gt 0 ] || set -- "$@" scripts/custodexa/tests/
  docker run --rm -v "$repo:/src:ro" ${extra[@]+"${extra[@]}"} "$img" bash -c "
    set -u
    $versions
    bats --print-output-on-failure \"\$@\"; b=\$?
    $shellcheck_step
    echo \"== bats exit=\$b shellcheck exit=\$s\"
    [ \$b -eq 0 ] && [ \$s -eq 0 ]
  " _ "$@"
  exit
fi

q=$(mktemp -d "${TMPDIR:-/tmp}/cx-bats.XXXXXX")
trap 'rm -rf "$q"' EXIT
# The largest files first, so a long one does not start last.
pids=()
for _ in $(seq "$jobs"); do
  docker run --rm -v "$repo:/src:ro" -v "$q:/q" ${extra[@]+"${extra[@]}"} -e CX_BATS_OPTS="${opts[*]:-}" "$img" bash -c '
    set -u
    for f in "$@"; do
      n=$(printf %s "$f" | tr / _)
      mkdir "/q/$n.claim" 2>/dev/null || continue
      # shellcheck disable=SC2086
      bats --print-output-on-failure $CX_BATS_OPTS "$f" >"/q/$n.out" 2>&1
      echo $? >"/q/$n.rc"
    done
  ' _ "${files[@]}" &
  pids+=($!)
done
for p in "${pids[@]}"; do wait "$p" || true; done

docker run --rm "$img" bash -c "$versions"
b=0
for f in $(printf '%s\n' "${files[@]}" | sort); do
  n=$(printf %s "$f" | tr / _)
  echo "== $f"
  cat "$q/$n.out" 2>/dev/null || echo "no output: the file did not run"
  [ "$(cat "$q/$n.rc" 2>/dev/null)" = 0 ] || { b=1; echo "== $f failed"; }
done
docker run --rm -v "$repo:/src:ro" ${extra[@]+"${extra[@]}"} "$img" bash -c "
  set -u
  $shellcheck_step
  echo \"== bats exit=$b shellcheck exit=\$s\"
  [ $b -eq 0 ] && [ \$s -eq 0 ]
"
