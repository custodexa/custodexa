#!/usr/bin/env bats
# Roles the backup grants rights to and the external database server lacks, before anything stops:
# without a terminal the restore refuses unless --accept-grant-loss; at a terminal the user creates
# them first (the default, nothing changed) or skips their grants. Skipping reads the dump's grant
# statements strictly, one per line, and leaves out only those naming a missing role; a statement
# it cannot tell apart for certain means the roles must be created first.
load helper
load install_host
load backup_host
load upgrade_host
load restore_host

setup_file() { rs_ext_fixtures; }
setup() {
  RS_FIX=$BATS_FILE_TMPDIR/fixtures
  rs_ext_host 16.4
  # The checks end at the boundary before the durable record; what the transaction does with the
  # skipped grants is test_restore_external_import.bats.
  rs_preflight_only
  backup_strict
  # The dump grants to three roles; the server has only auditor_ro (and DB_USER).
  printf '%s\n' '"report reader"' auditor_ro custodexa_app >"$DB/grants.restore"
  printf '%s\n' auditor_ro >"$DB/roles"
}
same() { run bash "$ROOT/custodexa.sh" restore "$(rs_fix extgrants)" --same-host --yes --confirm-data-loss --lang "${LANG_RUN:-en}" "$@" </dev/null; }
# same_tty <input> <language>: the restore at a terminal, the input typed.
same_tty() {
  run bash -c 'printf "%b" "$2" | script -qec "$1" /dev/null' _ \
    "bash '$ROOT/custodexa.sh' restore '$(rs_fix extgrants)' --same-host --no-color --lang $2" "$1"
  output=${output//$'\r'/}
}
no_stop() { ! grep -Eq '^(stop|start|up|create|curl)( |$)' "$DB/events"; }
# The part of the screen from the question on, the paths as on a production host.
from_question() { sed -n '/^\[ ?? \] /,$p' <<<"$output" | sed '/^Restore preview\|^還原預覽\|^復元のプレビュー/,$d'; }

@test "restore external grants: the filter leaves out only the statements naming a missing role, wrapping kept" {
  local d=$BATS_TEST_TMPDIR/g
  mkdir -p "$d"
  cat >"$d/in.sql" <<'SQL'
--
-- PostgreSQL database dump
--

\restrict 0f1e2d3c4b5a

SET statement_timeout = 0;
SELECT pg_catalog.set_config('search_path', '', false);

--
-- Name: TABLE users; Type: ACL; Schema: public; Owner: custodexa_app
--

GRANT SELECT ON TABLE public.users TO "report reader";
GRANT SELECT ON TABLE public."a TO b" TO auditor_ro;
REVOKE ALL ON TABLE public.t FROM PUBLIC;
GRANT ALL ON SCHEMA public TO "report reader" WITH GRANT OPTION;
ALTER DEFAULT PRIVILEGES FOR ROLE custodexa_app IN SCHEMA public GRANT SELECT ON TABLES TO "report reader";
ALTER DEFAULT PRIVILEGES FOR ROLE custodexa_app IN SCHEMA public GRANT SELECT ON TABLES TO auditor_ro;

--
-- PostgreSQL database dump complete
--

\unrestrict 0f1e2d3c4b5a
SQL
  printf '%s\n' 'report reader' >"$d/missing"
  filter() { run bash -c '. "$1/lib/common.sh"; cx_load_libs "$1"; . "$1/lib/cmd_restore.sh"; cx_rs_ext_grants_filter "$2/in.sql" "$2/missing" "$2/kept.sql" "$2/skipped.txt"' _ "$SRC" "$d"; }
  filter
  [ "$status" -eq 0 ] && [ "$output" = 3 ] || { echo "$status $output"; return 1; }
  [ "$(cat "$d/skipped.txt")" = 'GRANT SELECT ON TABLE public.users TO "report reader";
GRANT ALL ON SCHEMA public TO "report reader" WITH GRANT OPTION;
ALTER DEFAULT PRIVILEGES FOR ROLE custodexa_app IN SCHEMA public GRANT SELECT ON TABLES TO "report reader";' ] || { cat "$d/skipped.txt"; return 1; }
  # Everything else, in order, byte for byte.
  diff <(grep -vF '"report reader"' "$d/in.sql") "$d/kept.sql" || return 1
  # Each of these cannot be told apart for certain.
  local bad
  for bad in 'GRANT SELECT ON TABLE public.v TO "report reader", auditor_ro;' \
    'GRANT SELECT ON TABLE public.v TO "report reader" GRANTED BY postgres;' \
    'GRANT SELECT ON TABLE public.v TO "report reader"' \
    'GRANT SELECT ON TABLE public.v TO "report reader,auditor_ro;' \
    'ALTER DEFAULT PRIVILEGES FOR ROLE "report reader" GRANT SELECT ON TABLES TO auditor_ro;' \
    'SET SESSION AUTHORIZATION postgres;' \
    'CREATE TABLE public.x (id int);'; do
    printf '%s\n' "$bad" >"$d/in.sql"
    filter
    [ "$status" -eq 3 ] || { echo "$bad: $status $output"; return 1; }
  done
}

@test "restore external grants: without a terminal --accept-grant-loss skips just their grants, lists them and says so in the preview" {
  same
  [ "$status" -eq 3 ] && no_stop || { echo "$output"; return 1; }
  [[ $output == *'lacks 1 role the backup grants rights'$'\n''       to: "report reader".'$'\n''       Create it first, or add --accept-grant-loss to skip its grants.'$'\n''Nothing has been changed.'* ]] || { echo "$output"; return 1; }
  same --accept-grant-loss
  [ "$status" -eq 3 ] && [[ $output == *'restore-preflight-accepted'* ]] && no_stop || { echo "$output"; return 1; }
  [[ $output == *$'\n''  Skipped grants the grants to this role are not restored'$'\n'* ]] || { echo "$output"; return 1; }
  grep -q 'external database grants to missing roles skipped=1' "$ROOT"/logs/restore-*.log
}

@test "restore external grants: two missing roles are counted in the plural on every screen that counts them" {
  printf '%s\n' '"report reader"' '"audit export"' auditor_ro >"$DB/grants.restore"
  same
  [ "$status" -eq 3 ] && no_stop || { echo "$output"; return 1; }
  [[ $output == *'lacks 2 roles the backup grants rights'$'\n''       to: "audit export", "report reader".'$'\n''       Create them first, or add --accept-grant-loss to skip their grants.'$'\n'* ]] || { echo "$output"; return 1; }
  same --accept-grant-loss
  [ "$status" -eq 3 ] || { echo "$output"; return 1; }
  [[ $output == *$'\n''  Skipped grants the grants to these 2 roles are not restored'$'\n'* ]] || { echo "$output"; return 1; }
  same_tty '\n' en
  [ "$status" -eq 3 ] || { echo "$output"; return 1; }
  [[ $output == *'[ ?? ] The backup grants rights to the 2 roles below, and the target'$'\n''       database server does not have them:'* ]] || { echo "$output"; return 1; }
  [[ $output == *'  [1] Create these roles first'*'  [2] Skip the grants to these roles and go on'* ]] || { echo "$output"; return 1; }
}

@test "restore external grants: a grant statement that cannot be told apart refuses even with --accept-grant-loss; nothing changed" {
  printf '%s\n' '"report reader", auditor_ro' >"$DB/grants.restore"
  same --accept-grant-loss
  [ "$status" -eq 3 ] && no_stop || { echo "$output"; return 1; }
  [ "$output" != "${output%%'[FAIL] Some grant statements cannot be told apart from the ones for the'$'\n''       missing roles, so the script cannot skip just those.'$'\n''       Create the roles on the server first, then restore.'$'\n''Nothing has been changed.'*}" ] || { echo "$output"; return 1; }
  grep -q 'grant statement 1 cannot be read for certain' "$ROOT"/logs/restore-*.log || return 1
  ! grep -q 'skipped=' "$ROOT"/logs/restore-*.log
}

@test "restore external grants: --accept-grant-loss belongs to a restore from a file" {
  run bash "$ROOT/custodexa.sh" restore --resume --accept-grant-loss --lang en </dev/null
  [ "$status" -eq 2 ] && [[ $output == *"--accept-grant-loss cannot be used with --resume"* ]] || { echo "$status $output"; return 1; }
  run bash "$ROOT/custodexa.sh" backup --accept-grant-loss --lang en </dev/null
  [ "$status" -eq 2 ] && [[ $output == *"Option --accept-grant-loss is only for restore"* ]] || { echo "$status $output"; return 1; }
}

@test "restore external grants: at a terminal the question reads as drawn in all three languages; Enter ends with nothing changed" {
  local l expected errs=0
  for l in en zh-TW ja; do
    same_tty '\n' "$l"
    [ "$status" -eq 3 ] && no_stop || { echo "$l: $status $output"; return 1; }
    expected=$TESTS_DIR/snapshots/restore-ext-roles-ask.$l.txt
    if [ ! -f "$expected" ]; then
      printf '# SNAPSHOT %s %s\n' "${expected##*/}" "$(from_question | base64 -w0)" >&3
      errs=1
    else diff <(from_question) "$expected" || errs=1; fi
  done
  [ "$errs" = 0 ] || return 1
  # The snapshots end with "nothing has been changed" in each language; the log says why.
  grep -q 'external database missing roles: create them first' "$ROOT"/logs/restore-*.log || return 1
  ! grep -q 'skipped=' "$ROOT"/logs/restore-*.log
}

@test "restore external grants: at a terminal choosing 2 skips their grants and goes on to the preview" {
  # 2 at the roles' question, Enter at the safety backup's (its default), then no confirmation.
  same_tty '2\n\n' en
  [[ $output == *'Choose [1-2], or press Enter for the default: '* ]] || { echo "$output"; return 1; }
  [[ $output == *$'\n''  Skipped grants the grants to this role are not restored'$'\n'* ]] || { echo "$output"; return 1; }
  [ "$status" -eq 3 ] && [[ $output != *'restore-preflight-accepted'* ]] || { echo "$output"; return 1; }
  no_stop || return 1
  grep -q 'external database grants to missing roles skipped=1' "$ROOT"/logs/restore-*.log
}

@test "restore external grants: the refusals read the same in zh-TW and ja" {
  local l expected errs=0 kind
  for kind in refused unsure; do
    [ "$kind" = refused ] || printf '%s\n' '"report reader", auditor_ro' >"$DB/grants.restore"
    for l in en zh-TW ja; do
      if [ "$kind" = refused ]; then LANG_RUN=$l same; else LANG_RUN=$l same --accept-grant-loss; fi
      [ "$status" -eq 3 ] || { echo "$output"; return 1; }
      output=$(sed -n '/^\[FAIL\]/,$p' <<<"$output")
      expected=$TESTS_DIR/snapshots/restore-ext-roles-$kind.$l.txt
      if [ ! -f "$expected" ]; then
        printf '# SNAPSHOT %s %s\n' "${expected##*/}" "$(printf '%s\n' "$output" | base64 -w0)" >&3
        errs=1
      else diff <(printf '%s\n' "$output") "$expected" || errs=1; fi
    done
  done
  [ "$errs" = 0 ]
}
