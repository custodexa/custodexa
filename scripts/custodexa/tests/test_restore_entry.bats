#!/usr/bin/env bats
# Threat (B): a restore started the wrong way round. Which kind of restore runs follows from this
# host alone (installed: its data is replaced; not installed: a new host); without a terminal the
# kind must be named and agree with the host, or the run ends as a usage error before anything is
# read or stopped. The restore's own options must not slip into another command, where they would
# be ignored silently.

load helper
load install_host
load backup_host
load upgrade_host
load restore_host
load restore_engine_host

setup() {
  if [[ $BATS_TEST_DESCRIPTION == *'same-host bundled database env backup'* ]]; then rs_engine_host; return; fi
  backup_host ui
  backup_strict
}

# restore_run <options...>: the real script, English, without a terminal.
restore_run() { run bash "$ROOT/custodexa.sh" restore --lang en "$@" </dev/null; }

# not_installed: the deployment folder of a new host (no current.version).
not_installed() { printf '{\n  "format": "2"\n}\n' >"$ROOT/state.json"; }

# untouched: nothing was stopped or asked of docker, state.json is as it was.
untouched() {
  if grep -q . "$DB/events"; then echo "events:"; cat "$DB/events"; return 1; fi
  if grep -q . "$FAKE_DOCKER_LOG"; then echo "docker:"; cat "$FAKE_DOCKER_LOG"; return 1; fi
  cmp "$ROOT/state.json" "$BATS_TEST_TMPDIR/state.before"
}

before() { cp "$ROOT/state.json" "$BATS_TEST_TMPDIR/state.before"; }

@test "restore entry: without a terminal and without --same-host or --new-host: exit 2, the flag this host needs named" {
  before
  restore_run /srv/transfer/custodexa-backup-1.16.0-20261005-101502.tar --yes
  [ "$status" -eq 2 ] && [[ $output == *"This host"*"is installed"*"add --same-host"* ]] || { echo "$status $output"; return 1; }
  untouched || return 1
  not_installed
  before
  restore_run /srv/transfer/custodexa-backup-1.16.0-20261005-101502.tar --yes
  [ "$status" -eq 2 ] && [[ $output == *"not installed yet: add --new-host"* ]] || { echo "$status $output"; return 1; }
  untouched
}

@test "restore entry: the flag disagrees with this host: exit 2, nothing stopped (both ways), both flags at once refused" {
  not_installed
  before
  restore_run /srv/x.tar --same-host --yes
  [ "$status" -eq 2 ] && [[ $output == *"not installed yet"*"use --new-host instead of --same-host"* ]] || { echo "$status $output"; return 1; }
  untouched || return 1
  bk_state_fresh
  before
  restore_run /srv/x.tar --new-host --yes
  [ "$status" -eq 2 ] && [[ $output == *"already installed"*"use"*"--same-host instead of --new-host"* ]] || { echo "$status $output"; return 1; }
  untouched || return 1
  restore_run /srv/x.tar --new-host --same-host
  [ "$status" -eq 2 ] && [[ $output == *"cannot be given together"* ]] || { echo "$status $output"; return 1; }
  untouched
}

@test "restore entry: the kind that agrees with this host gets past the entry (installed: --same-host; new: --new-host)" {
  before
  restore_run /srv/x.tar --same-host --yes
  [ "$status" -ne 2 ] || { echo "$output"; return 1; }
  not_installed
  restore_run /srv/x.tar --new-host --yes
  [ "$status" -ne 2 ] || { echo "$output"; return 1; }
}

@test "restore entry: no file, two files, or an action with a file or with options it does not take: usage errors" {
  before
  restore_run --same-host
  [ "$status" -eq 2 ] && [[ $output == *"Name the backup file"* ]] || { echo "$status $output"; return 1; }
  restore_run a.tar b.tar --same-host
  [ "$status" -eq 2 ] && [[ $output == *'Unexpected argument "b.tar"'* ]] || { echo "$status $output"; return 1; }
  restore_run a.tar --resume
  [ "$status" -eq 2 ] && [[ $output == *'Unexpected argument "a.tar"'* ]] || { echo "$status $output"; return 1; }
  restore_run --resume --revert
  [ "$status" -eq 2 ] && [[ $output == *"--revert cannot be used with --resume"* ]] || { echo "$status $output"; return 1; }
  restore_run --revert --passphrase-file /root/cx-pass
  [ "$status" -eq 2 ] && [[ $output == *"--passphrase-file cannot be used with --revert"* ]] || { echo "$status $output"; return 1; }
  restore_run --abandon --same-host
  [ "$status" -eq 2 ] && [[ $output == *"--same-host cannot be used with --abandon"* ]] || { echo "$status $output"; return 1; }
  restore_run --resume --no-checksum-file
  [ "$status" -eq 2 ] && [[ $output == *"--no-checksum-file cannot be used with --resume"* ]] || { echo "$status $output"; return 1; }
  restore_run --revert --backup-ref snap-1
  [ "$status" -eq 2 ] && [[ $output == *"--backup-ref cannot be used with --revert"* ]] || { echo "$status $output"; return 1; }
  untouched
}

@test "restore entry: another command given an option of restore alone ends as a usage error, the option named" {
  before
  local c o
  for c in install upgrade status start stop backup load; do
    for o in --same-host --new-host --confirm-data-loss --no-checksum-file --abandon \
      "--package /tmp/p.tar.gz" "--data-path /srv/data" "--tls-domain a.example" "--tls-ip-san 10.0.0.31" \
      "--public-base-url https://10.0.0.31" "--nginx-template /etc/t"; do
      # shellcheck disable=SC2086 # an option and its value
      run bash "$ROOT/custodexa.sh" "$c" --lang en $o </dev/null
      [ "$status" -eq 2 ] && [[ $output == *"Option ${o%% *} is only for restore"* ]] || { echo "$c $o: $status $output"; return 1; }
    done
    # --resume and --revert are shared with rollback
    for o in --resume --revert; do
      run bash "$ROOT/custodexa.sh" "$c" --lang en $o </dev/null
      [ "$status" -eq 2 ] && [[ $output == *"--resume and --revert are only for rollback and restore"* ]] || { echo "$c $o: $status $output"; return 1; }
    done
  done
  untouched
}

@test "restore entry: restore --help shows the restore lines and its own options, and how to make a passphrase file" {
  run bash "$ROOT/custodexa.sh" restore --help --lang en
  [ "$status" -eq 0 ] || return 1
  [[ $output == *"restore <backup file>   Restore from a portable backup file."* ]] || return 1
  [[ $output == *"restore --abandon       Give up on an unfinished restore"* ]] || return 1
  [[ $output == *"Options for restore"*"--nginx-template <path>"* ]] || return 1
  [[ $output == *"To create a passphrase file"* ]] || return 1
  # The external database's options: its client certificate, and skipping grants to missing roles.
  [[ $output == *"--db-client-cert, --db-client-key"* && $output == *"--accept-grant-loss          External database lacks roles"* ]] || return 1
  [[ $output != *"install                First install"* ]]
}

@test "restore entry: same-host bundled database env backup runs from the file argument to completion" {
  rs_engine_run
  [ "$status" = 0 ] && [ "$(rs_engine_result)" = succeeded ] || { echo "$output"; return 1; }
  [ "$(jq -r '."last_restore.phase"' "$ROOT/state.json")" = done ] || return 1
  [[ $output == *'Restore done; the service is back (1.16.0)'* ]]
}
