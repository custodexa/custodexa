#!/usr/bin/env bats
# Threat (A): secret collection from .env reading a value the file no longer holds. Compose takes
# the last line of a key that appears twice; a collector that also keeps the replaced line treats an
# ordinary string (an image name, a database name) as a secret, so log lines are garbled and a
# backup manifest value is refused as "holding a secret".

load helper

setup() {
  E=$BATS_TEST_TMPDIR/.env
  load_lib
  # shellcheck disable=SC1091
  . "$SRC/lib/backup_manifest.sh"
  CX_SECRETS=()
  CX_PB_MAP=()
  CX_LOG_FILE=$BATS_TEST_TMPDIR/run.log
  : >"$CX_LOG_FILE"
}

@test "a key on two lines masks the last value and not the replaced one" {
  printf 'DB_PASSWORD=postgres\nDB_PASSWORD=S3cret-value-xyz\n' >"$E"
  cx_secrets_from_env "$E"
  run cx_has_secret 'docker.io/library/postgres:17-alpine'; [ "$status" -ne 0 ]
  cx_has_secret 'S3cret-value-xyz'
  [ "$(cx_mask 'pw S3cret-value-xyz end')" = 'pw <DB_PASSWORD> end' ]
  [ "$(cx_mask 'image postgres')" = 'image postgres' ]
}

@test "single lines, export prefix, quotes and CRLF are still collected; shown keys never" {
  printf 'PLAIN_KEY=plain-secret-1\nexport EXP_KEY=export-secret-2\nDQ_KEY="double-secret-3"\n' >"$E"
  printf "SQ_KEY='single-secret-4'\nCRLF_KEY=crlf-secret-5\r\n" >>"$E"
  printf 'DB_USER=shown-user-aa\nDB_USER=shown-user-bb\n' >>"$E"
  cx_secrets_from_env "$E"
  local v
  for v in plain-secret-1 export-secret-2 double-secret-3 single-secret-4 crlf-secret-5; do
    cx_has_secret "x $v x" || { echo "not collected: $v"; return 1; }
  done
  run cx_has_secret shown-user-aa; [ "$status" -ne 0 ]
  run cx_has_secret shown-user-bb; [ "$status" -ne 0 ]
  [ "$(cx_mask crlf-secret-5)" = '<CRLF_KEY>' ]
}

@test "the manifest keeps a database image name when only the replaced line held it" {
  printf 'DB_PASSWORD=postgres\nDB_PASSWORD=S3cret-value-xyz\n' >"$E"
  cx_secrets_from_env "$E"
  cx_pb_kv tool.dump_image postgres
  [ "${CX_PB_MAP[tool.dump_image]}" = postgres ]
  # Control: with only the one line the value is a secret and the key may not be empty, which
  # proves the refusal branch is reached and the passing case above is not vacuous.
  CX_SECRETS=() CX_PB_MAP=()
  printf 'DB_PASSWORD=postgres\n' >"$E"
  cx_secrets_from_env "$E"
  run cx_pb_kv tool.dump_image postgres
  [ "$status" -ne 0 ]
  grep -q 'manifest: tool.dump_image cannot be stored' "$CX_LOG_FILE"
}
