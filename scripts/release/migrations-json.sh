#!/usr/bin/env bash
# Read migration versions from the ordered Go slice without building a package.

migrations_json() { # <source tree>
  local go=$1/backend/internal/database
  local ids id base
  base=$(sed -n 's/^const BaselineVersion = "\([^"]*\)"$/\1/p' "$go"/*.go)
  ids=$(awk '
    /^var migrations = \[\]Migration\{$/ { slice = 1; found = 1; next }
    slice && /^}$/ {
      if (entry) { print "unfinished migration entry" > "/dev/stderr"; exit 1 }
      ended = 1; exit
    }
    slice {
      line = $0
      sub(/\/\/.*/, "", line)
      if (!entry && line !~ /^[[:space:]]*($|\{)/) {
        print "unrecognized migration entry: " line > "/dev/stderr"; exit 1
      }
      if (line ~ /^[[:space:]]*\{/) {
        if (entry) { print "nested migration entry" > "/dev/stderr"; exit 1 }
        entry = 1
        version = ""
        count = 0
      }
      if (entry && line ~ /Version[[:space:]]*:/) {
        value = line
        sub(/^.*Version[[:space:]]*:[[:space:]]*/, "", value)
        sub(/[,}].*$/, "", value)
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
        version = value
        count++
      }
      if (entry && line ~ /}[[:space:]]*,[[:space:]]*$/) {
        if (count != 1 || version == "") {
          print "migration entry has no single Version" > "/dev/stderr"; exit 1
        }
        print version
        entry = 0
      }
    }
    END { if (!found || !ended) { print "migrations slice not found or unfinished" > "/dev/stderr"; exit 1 } }
  ' "$go/migrations.go") || die "cannot read migrations from $go/migrations.go"
  [ -n "$ids" ] || die "no migrations found in $go/migrations.go"
  # Resolve every id before handing the list to jq: a die inside a pipeline only ends that
  # pipeline's subshell, and jq would still print a shortened list without pipefail.
  local resolved=""
  while IFS= read -r id; do
    case $id in
      BaselineVersion) [ -n "$base" ] || die "BaselineVersion not found"; resolved+="$base"$'\n' ;;
      \"*\") id=${id#\"}; [[ $id == *\" ]] || die "invalid migration version: $id"; resolved+="${id%\"}"$'\n' ;;
      *) die "migration version is neither a literal nor BaselineVersion: $id" ;;
    esac
  done <<<"$ids"
  printf '%s' "$resolved" | jq -R . | jq -s .
}
