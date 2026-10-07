#!/usr/bin/env bats
load helper
load install_host
load backup_host
load upgrade_host
load restore_host
load restore_import_host
load restore_files_host
setup() { rs_files_host; }
@test "restore files: a same-host backup without recordings leaves their file list sizes and timestamps unchanged" {
  find "$ROOT/data/recordings" -printf '%p %s %T@\n' | sort >"$BATS_TEST_TMPDIR/before"
  rs_files_run
  [ "$status" = 0 ] || { echo "$output"; return 1; }
  find "$ROOT/data/recordings" -printf '%p %s %T@\n' | sort >"$BATS_TEST_TMPDIR/after"
  cmp "$BATS_TEST_TMPDIR/before" "$BATS_TEST_TMPDIR/after"
}
@test "restore files: included recordings never replace an existing file of the same name" {
  export RS_FILES_REC=true
  printf 'different existing recording\n' >"$ROOT/data/recordings/session.cast"
  cp "$ROOT/data/recordings/session.cast" "$BATS_TEST_TMPDIR/kept"
  rs_files_run
  [ "$status" = 0 ] || { echo "$output"; return 1; }
  cmp "$ROOT/data/recordings/session.cast" "$BATS_TEST_TMPDIR/kept"
}
@test "restore files: changed self-signed address retains the leaf before reissue" {
  export RS_FILES_REISSUE=1
  rs_files_run
  [ "$status" = 0 ] || { echo "$output"; return 1; }
  cmp "$ROOT/tls/leaf.before-restore-import-test/fullchain.pem" "$RS_I_STAGE/payload/tls/fullchain.pem"
  cmp "$ROOT/tls/leaf.before-restore-import-test/privkey.pem" "$RS_I_STAGE/payload/tls/privkey.pem"
}
@test "restore files: absent certificate contents leave an existing tls tree alone and never create a missing one" {
  export RS_FILES_TLS=false
  cp -a "$ROOT/tls" "$BATS_TEST_TMPDIR/tls-before"
  rs_files_run
  [ "$status" = 0 ] || { echo "$output"; return 1; }
  diff -r "$ROOT/tls" "$BATS_TEST_TMPDIR/tls-before" || return 1
  rs_files_host
  rm -rf "$ROOT/tls"
  rs_files_run
  [ "$status" = 0 ] || { echo "$output"; return 1; }
  [ ! -e "$ROOT/tls" ]
}
@test "restore files: a custom template is placed at the chosen path and current points to the data release" {
  export RS_FILES_TEMPLATE=$ROOT/conf/chosen.template
  rs_files_run
  [ "$status" = 0 ] || { echo "$output"; return 1; }
  cmp "$RS_FILES_TEMPLATE" "$RS_I_STAGE/pass2/nginx-tls.conf.template" || return 1
  [ "$(readlink "$ROOT/current")" = releases/1.16.1 ]
}
@test "restore files: different template content is retained on both host flows" {
  local flow
  for flow in same new; do
    rs_files_host
    export RS_FILES_FLOW=$flow RS_FILES_TEMPLATE=$ROOT/conf/existing.template
    printf 'original template\n' >"$RS_FILES_TEMPLATE"
    cp "$RS_FILES_TEMPLATE" "$BATS_TEST_TMPDIR/original"
    rs_files_run
    [ "$status" = 0 ] || { echo "$output"; return 1; }
    cmp "$RS_FILES_TEMPLATE.before-restore-import-test" "$BATS_TEST_TMPDIR/original" || return 1
    cmp "$RS_FILES_TEMPLATE" "$RS_I_STAGE/pass2/nginx-tls.conf.template" || return 1
  done
}
@test "restore files: identical template content is not renamed on either host flow" {
  local flow
  for flow in same new; do
    rs_files_host
    export RS_FILES_FLOW=$flow RS_FILES_TEMPLATE=$ROOT/conf/existing.template
    cp "$RS_I_STAGE/pass2/nginx-tls.conf.template" "$RS_FILES_TEMPLATE"
    rs_files_run
    [ "$status" = 0 ] || { echo "$output"; return 1; }
    [ ! -e "$RS_FILES_TEMPLATE.before-restore-import-test" ] || return 1
  done
}
