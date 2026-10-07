# shellcheck shell=bash
# A package deployment on the integration host, made the way an operator makes one: check the
# package against SHA256SUMS, unpack it, run custodexa.sh as root without a terminal.
#   it_unpack <parent> [from|from2]     /it-run/pkg (with "from": /it-run/pkg-from, the older release
#                                       of a scenario that needs upgrade; "from2": /it-run/pkg-from2,
#                                       the one before it, needs upgrade twice) checked and unpacked
#                                       to <parent>/custodexa
#   it_env_preset <root> KEY=VALUE...   .env from the release template plus these values, before
#                                       install (install keeps values already set); for overlays
#   it_cx <root> <arguments>            <root>/custodexa.sh <arguments>
#   it_bundle_file [from|from2]         the offline bundle (/bundle, /bundle-from or /bundle-from2)
#   it_package_file [from]              the package itself (for upgrade <package>)

it_unpack() {
  local parent=$1 dir=/it-run/pkg${2:+-$2} pkg
  (cd "$dir" && sha256sum -c --quiet SHA256SUMS) || it_die "the package does not match its SHA256SUMS"
  pkg=$(find "$dir" -maxdepth 1 -name 'custodexa-*.tar.gz' | head -n1)
  [ -n "$pkg" ] || it_die "no package in /it-run/pkg (the scenario needs '# needs: package')"
  mkdir -p "$parent"
  tar -xzf "$pkg" -C "$parent"
}

it_env_preset() {
  local root=$1 kv
  shift
  [ -f "$root/.env" ] || install -m 600 "$root/current/.env.example" "$root/.env"
  for kv in "$@"; do printf '%s\n' "$kv" >>"$root/.env"; done
}

it_cx() {
  local root=$1
  shift
  "$root/custodexa.sh" "$@"
}

it_bundle_file() {
  local f dir=/bundle${1:+-$1}
  f=$(find "$dir" -maxdepth 1 -name 'custodexa-images-*.tar' | head -n1)
  [ -n "$f" ] || it_die "no offline bundle in $dir"
  printf '%s' "$f"
}

it_package_file() {
  local f dir=/it-run/pkg${1:+-$1}
  f=$(find "$dir" -maxdepth 1 -name 'custodexa-*.tar.gz' | head -n1)
  [ -n "$f" ] || it_die "no package in $dir"
  printf '%s' "$f"
}
