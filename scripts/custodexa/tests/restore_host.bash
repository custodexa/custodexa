# Hosts and backup files for the restore tests. Needs helper.bash, install_host.bash,
# backup_host.bash and upgrade_host.bash loaded.
#
# The backup files are made by the real backup command (lib/portable.sh) on a deployment of
# RS_VERSION, once per test file (rs_fixtures in setup_file), each in its own folder under $RS_FIX
# with its checksum file beside it (rs_fix <name> names the file):
#   plain        ui, not encrypted, no recordings, tls/ present
#   env | kms    the master key mode of the .env (env carries ENCRYPTION_KEY in env.bak)
#   enc          ui, encrypted with RS_PASS (cx-enc-1)
#   rec          ui, with the recordings
#   notls        external ingress form: no tls/, so no tls.tar.gz and contents.tls=false
#   tplabs       TLS_NGINX_TEMPLATE an absolute path    tplrel   the same, relative to the root
#   external     a deployment on an external database (refused before any stop)
#   oldupgrade   trigger=upgrade by the upgrade command of 1.13.0: product.version 1.13.0
# Two more are derived, not made by the producer (each changes one fact and recomputes the
# checksums that follow from it, as a producer of that kind would have written them):
#   nojwt        plain with fp.jwt empty in snapshot.txt
#   oldnofp      oldupgrade without the master key fingerprint (snapshot fp.kek empty,
#                kek.fingerprint empty, kek.fingerprint_status=missing)
# The tampered files (rs_tamper) change one thing of a fixture; rs_tamper_kinds lists them.
#
# What the restore's own calls get from the fake host (rs_host), besides backup_host's:
#   $DB/grants.restore   role names a bundled dump grants to (pg_restore -l lists an ACL entry per
#                        role, pg_restore -L <list> -f - prints its GRANT)
#   $DB/seal             what /api/v1/seal/status answers: sealed, unsealed (with kek_id),
#                        unsealed-noid (no kek_id: the backend is wrong), unreadable (fails)
#   $DB/curl/<name>      a release asset curl downloads (200); $DB/curl.404 lists names that answer
#                        404; $DB/curl.offline makes every download fail to connect (exit 7)
#   $DB/recordings       the recording_path of each session with a recording (one per line), as
#                        the restored database answers; $DB/recordings.rc makes that query fail
#   $DB/offsite          how many current offsite storage generations there are (0 when absent)
#   $DB/ctr/<service>    created, running or stopped: what each container is doing now
#   $DB/inject           lines "<before|after> <glob over the docker or curl arguments, without
#                        spaces> <exit code or SIGNAL>": that call fails, or the script gets the signal, before or
#                        after it runs (each line fires once)
#   $DB/proc.seen        the arguments and the environment of every process of the script at each
#                        docker and curl call (cmdline and environ of the callers up to the script)
# An external database (rs_ext_host; the PostgreSQL client containers of backup_host's bk_external),
# for the restore's own queries; any other query still exits 99:
#   $DB/activity         the other connections to the database, lines "<address or -> <application>";
#                        $DB/activity.<n> answers the n-th such query instead (a list that changes
#                        between the checks before and after the stop)
#   $DB/roles            role names the server has (the query asks for some by their hex name and
#                        gets back those it has)
#   $DB/foreign          objects owned by another role, lines "<schema>|<name>|<owner>"
#   $DB/objects          objects per non-system schema, lines "<schema>|<count>" (none: empty)
#   $DB/pg_restore.out   what pg_restore -f <file> writes (else a short dump with its \restrict
#                        wrapping); $DB/pg_restore.cut "<bytes> <exit code|signal>" makes it stop
#                        after that many bytes with that code, or be killed by that signal

RS_VERSION=1.16.0
# Test value only; it stands for a passphrase so the tests can look for it.
RS_PASS=restore-test-passphrase-0004

# rs_at_version <version>: backup_host's deployment as an installed <version>: the release folder,
# its VERSION and MANIFEST.json (the one of 1.13.0 with the version changed), current, state.json
# and the version /health reports.
rs_at_version() {
  local v=$1 d=$ROOT/releases/$1 cf=current/compose.yml ov
  mkdir -p "$d"
  cp -R "$SRC/custodexa.sh" "$SRC/lib" "$SRC/lang" "$d/"
  printf '%s\n' "$v" >"$d/VERSION"
  jq --arg v "$v" --argjson mig "$(jq -R . <"$DB/migrations" | jq -s .)" \
    '.version = $v | .migrations = $mig | .runtime_markers = []' \
    "$ROOT/releases/1.13.0/MANIFEST.json" >"$d/MANIFEST.json"
  /usr/bin/ln -sfn "releases/$v" "$ROOT/current"
  rm -rf "$ROOT/releases/1.13.0"
  bk_state_set current.version "$v"
  for ov in $(jq -r '."current.overlays" // ""' "$ROOT/state.json"); do cf+=:current/compose.$ov.yml; done
  bk_env_set COMPOSE_FILE "$cf"
  bk_env_set COMPOSE_PROJECT_NAME custodexa
  printf '{"status":"ok","version":"%s"}\n' "$v" >"$DB/health"
}

# rs_make <dir> <mode> <setup> [backup options...]: one backup file of RS_VERSION made by the real
# script in a host of its own (<setup> is run there first), copied with its checksum file to <dir>.
rs_make() {
  local out=$1 mode=$2 setup=$3
  shift 3
  (
    BATS_TEST_TMPDIR=$out.host
    mkdir -p "$BATS_TEST_TMPDIR" "$out"
    backup_host "$mode"
    eval "$setup"
    rs_at_version "$RS_VERSION"
    bash "$ROOT/custodexa.sh" backup --lang en --yes "$@" </dev/null >"$out.log" 2>&1 \
      || { cat "$out.log"; exit 1; }
    cp -p "$ROOT"/backups/custodexa-backup-* "$out/"
  ) || return 1
  rm -rf "$out.host"
}

# rs_make_upgrade <dir>: the portable file the upgrade of 1.13.0 to 1.13.2 makes at its step 7
# (trigger=upgrade, product.version 1.13.0, state.json inside).
rs_make_upgrade() {
  local out=$1
  (
    BATS_TEST_TMPDIR=$out.host
    mkdir -p "$BATS_TEST_TMPDIR" "$out"
    upgraded_host ui || exit 1
    clock 0 3 0 41 0 4 0 11
    bash "$ROOT/releases/1.13.2/custodexa.sh" upgrade --lang en --yes </dev/null >"$out.log" 2>&1 \
      || { cat "$out.log"; exit 1; }
    cp -p "$ROOT"/backups/custodexa-backup-1.13.0-* "$out/"
  ) || return 1
  rm -rf "$out.host"
}

# rs_fixtures: every fixture under RS_FIX ($BATS_FILE_TMPDIR/fixtures), made once per test file.
rs_fixtures() {
  export RS_FIX=$BATS_FILE_TMPDIR/fixtures
  [ ! -e "$RS_FIX/.done" ] || return 0
  mkdir -p "$RS_FIX"
  local pf=$BATS_FILE_TMPDIR/passphrase
  bk_passfile "$pf" "$RS_PASS"
  rs_make "$RS_FIX/plain" ui : || return 1
  rs_make "$RS_FIX/env" env : || return 1
  rs_make "$RS_FIX/kms" kms : || return 1
  rs_make "$RS_FIX/enc" ui bk_openssl --passphrase-file "$pf" || return 1
  rs_make "$RS_FIX/rec" ui : --with-recordings || return 1
  rs_make "$RS_FIX/notls" ui 'rm -rf "$ROOT/tls"; bk_state_set current.overlays external-ingress' || return 1
  rs_make "$RS_FIX/tplabs" ui 'mkdir -p "$BATS_TEST_TMPDIR/etc"; printf "server {}\n" >"$BATS_TEST_TMPDIR/etc/nginx-tls.conf.template"
    bk_env_set TLS_NGINX_TEMPLATE "$BATS_TEST_TMPDIR/etc/nginx-tls.conf.template"' || return 1
  rs_make "$RS_FIX/tplrel" ui 'mkdir -p "$ROOT/conf"; printf "server {}\n" >"$ROOT/conf/nginx-tls.conf.template"
    bk_env_set TLS_NGINX_TEMPLATE ./conf/nginx-tls.conf.template' || return 1
  rs_make "$RS_FIX/external" ui 'fake sleep :; host_arch x86_64; clock; bk_external' || return 1
  rs_make_upgrade "$RS_FIX/oldupgrade" || return 1
  rs_derive plain nojwt 'sed -i "s/^fp.jwt=.*/fp.jwt=/" snapshot.txt' || return 1
  rs_derive oldupgrade oldnofp 'sed -i "s/^fp.kek=.*/fp.kek=/" snapshot.txt
    rs_mf_set kek.fingerprint ""; rs_mf_set kek.fingerprint_status missing' || return 1
  : >"$RS_FIX/.done"
}

# rs_fix <name>: the backup file of that fixture (or tampered file).
rs_fix() {
  local -a f=()
  mapfile -t f < <(compgen -G "$RS_FIX/$1/custodexa-backup-*" | grep -v '\.sha256$' || true)
  [ "${#f[@]}" -eq 1 ] || { echo "rs_fix $1: ${#f[@]} files" >&2; return 1; }
  printf '%s' "${f[0]}"
}

# rs_unpack <file> <dir>: the members of a (not encrypted) backup file, and their order in
# <dir>/.order.
rs_unpack() {
  mkdir -p "$2"
  /usr/bin/tar -tf "$1" >"$2/.order" && /usr/bin/tar -xf "$1" -C "$2"
}

# rs_pack <dir> <file> [sums]: the members back into a file in their order (gnu format, as the
# producer writes it); with "sums" SHA256SUMS is recomputed first. The checksum file beside it is
# written anew.
rs_pack() {
  local d=$1 f=$2 m
  local -a list=()
  mapfile -t list <"$d/.order"
  if [ "${3:-}" = sums ]; then
    (cd "$d" && for m in "${list[@]}"; do
      [ "$m" = SHA256SUMS ] || [ ! -f "$m" ] || [ -L "$m" ] || /usr/bin/sha256sum -- "$m"
    done >SHA256SUMS) || return 1
  fi
  rm -f "$f"
  /usr/bin/tar --format=gnu -cf "$f" -C "$d" --no-recursion -- "${list[@]}" || return 1
  (cd "${f%/*}" && /usr/bin/sha256sum -- "${f##*/}" >"${f##*/}.sha256")
}

# rs_mf_set <key> <value>: one value of backup-manifest.json in the current folder (its layout kept).
rs_mf_set() {
  local k=${1//./\\.}
  sed -i "s/^  \"$k\": \"[^\"]*\"/  \"$1\": \"$2\"/" backup-manifest.json
}

# rs_derive <fixture> <name> <change>: a fixture with <change> run in its unpacked folder, the
# checksums that follow recomputed (SHA256SUMS, and the checksum file).
rs_derive() {
  local src w=$BATS_FILE_TMPDIR/derive-$2
  src=$(rs_fix "$1") || return 1
  rs_unpack "$src" "$w" || return 1
  (cd "$w" && eval "$3") || return 1
  mkdir -p "$RS_FIX/$2"
  rs_pack "$w" "$RS_FIX/$2/${src##*/}" sums || return 1
  rm -rf "$w"
}

# The tampered files: each changes one thing of a fixture. Those marked "sums" have SHA256SUMS
# recomputed after the change, so the change is found by the rule it breaks and not by the
# checksum; the others leave SHA256SUMS as the producer wrote it.
#   kind          fixture  the change                                         reason the reader gives
RS_TAMPER="sidecar     plain   the checksum file names another hash              sidecar
member-hash   plain   db.dump changed, SHA256SUMS as made                    hash
member-extra  plain   one member more (extra.txt)                            members
member-missing plain  audit.tar.gz gone                                      members
member-dup    plain   snapshot.txt stored twice                              members
member-link   plain   a symbolic link member                                 type
member-dir    plain   a directory member                                     type
member-path   plain   a member under a folder (sub/x)                        type
manifest-bad  plain   format=2 in backup-manifest.json (sums)                manifest
release-mf    plain   release-MANIFEST.json changed (sums)                   cross
migrations    plain   a migration line of snapshot.txt changed (sums)        cross
kek-fp        plain   fp.kek of snapshot.txt changed (sums)                  cross
inner-path    plain   audit.tar.gz holds ../escape (sums)                    inner
inner-link    plain   audit.tar.gz holds a symbolic link (sums)              inner
tls-missing   plain   tls.tar.gz gone, from SHA256SUMS and contents.members too (sums)  manifest
tpl-flag      tplabs  contents.nginx_template=false, the member kept (sums)  manifest
tpl-source    tplabs  source.tls_nginx_template emptied (sums)               manifest
state-version oldupgrade  state.json current.version changed (sums)          cross
enc-as-tar    enc     the encrypted file named .tar                          name
tar-as-enc    plain   the plain file named .tar.enc                          name
enc-cut       enc     the encrypted file loses its last 100 bytes            decrypt"

# rs_tamper_kinds: the kinds, one per line.
rs_tamper_kinds() { printf '%s\n' "$RS_TAMPER" | awk '{ print $1 }'; }

# rs_tamper <kind>: RS_FIX/t-<kind>/ holds the tampered file and a checksum file that matches it
# (except kind sidecar). Prints the file.
rs_tamper() {
  local kind=$1 fix src w out name
  fix=$(printf '%s\n' "$RS_TAMPER" | awk -v k="$kind" '$1 == k { print $2 }')
  [ -n "$fix" ] || { echo "rs_tamper: unknown kind $kind" >&2; return 1; }
  src=$(rs_fix "$fix") || return 1
  out=$RS_FIX/t-$kind
  w=$BATS_FILE_TMPDIR/tamper-$kind
  rm -rf "$out" "$w"
  mkdir -p "$out"
  name=${src##*/}
  case $kind in
    sidecar)
      cp "$src" "$out/$name"
      printf '%064d  %s\n' 0 "$name" >"$out/$name.sha256" ;;
    enc-as-tar | tar-as-enc | enc-cut)
      case $kind in
        enc-as-tar) name=${name%.enc} ;;
        tar-as-enc) name=$name.enc ;;
      esac
      cp "$src" "$out/$name"
      [ "$kind" != enc-cut ] || truncate -s -100 "$out/$name"
      (cd "$out" && /usr/bin/sha256sum -- "$name" >"$name.sha256") ;;
    *)
      rs_unpack "$src" "$w" || return 1
      rs_tamper_change "$kind" "$w" || return 1
      if printf '%s\n' "$RS_TAMPER" | awk -v k="$kind" '$1 == k' | grep -q '(sums)'; then
        rs_pack "$w" "$out/$name" sums || return 1
      else
        rs_pack "$w" "$out/$name" || return 1
      fi ;;
  esac
  rm -rf "$w"
  printf '%s' "$out/$name"
}

# rs_tamper_change <kind> <dir>: the one change in the unpacked folder.
rs_tamper_change() {
  local d=$2
  case $1 in
    member-hash) printf 'X' >>"$d/db.dump" ;;
    member-extra) printf 'extra\n' >"$d/extra.txt"; sed -i '/^SHA256SUMS$/i extra.txt' "$d/.order" ;;
    member-missing) rm "$d/audit.tar.gz"; sed -i '/^audit.tar.gz$/d' "$d/.order" ;;
    member-dup) sed -i '/^snapshot.txt$/a snapshot.txt' "$d/.order" ;;
    member-link) /usr/bin/ln -s /etc/hostname "$d/link"; sed -i '/^SHA256SUMS$/i link' "$d/.order" ;;
    member-dir) mkdir "$d/folder"; sed -i '/^SHA256SUMS$/i folder' "$d/.order" ;;
    member-path) mkdir "$d/sub"; printf 'x\n' >"$d/sub/x"; sed -i '/^SHA256SUMS$/i sub/x' "$d/.order" ;;
    manifest-bad) (cd "$d" && rs_mf_set format 2) ;;
    release-mf) jq '.version = "1.16.9"' "$d/release-MANIFEST.json" >"$d/x" && /usr/bin/mv "$d/x" "$d/release-MANIFEST.json" ;;
    migrations) sed -i '0,/^migration=/s/^migration=.*/migration=20990101_other/' "$d/snapshot.txt" ;;
    kek-fp) sed -i 's/^fp.kek=.*/fp.kek=0000000000000000/' "$d/snapshot.txt" ;;
    inner-path | inner-link)
      mkdir -p "$d/inner/audit"
      printf 'audit\n' >"$d/inner/audit/fallback.log"
      if [ "$1" = inner-path ]; then
        printf 'x\n' >"$d/inner/escape"
        /usr/bin/tar -czPf "$d/audit.tar.gz" -C "$d/inner" audit/fallback.log --transform 's,^escape$,../escape,' escape
      else
        /usr/bin/ln -s /etc/shadow "$d/inner/audit/shadow"
        /usr/bin/tar -czf "$d/audit.tar.gz" -C "$d/inner" audit/fallback.log audit/shadow
      fi
      rm -rf "$d/inner" ;;
    tls-missing)
      rm "$d/tls.tar.gz"; sed -i '/^tls.tar.gz$/d' "$d/.order"
      (cd "$d" && rs_mf_set contents.members "$(grep -v '^SHA256SUMS$' .order | tr '\n' ' ' | sed 's/ $//') SHA256SUMS") ;;
    tpl-flag) (cd "$d" && rs_mf_set contents.nginx_template false) ;;
    tpl-source) (cd "$d" && rs_mf_set source.tls_nginx_template "") ;;
    state-version) jq '."current.version" = "1.12.9"' "$d/state.json" >"$d/x" && /usr/bin/mv "$d/x" "$d/state.json" ;;
    *) echo "rs_tamper_change: $1" >&2; return 1 ;;
  esac
}

# ---------- the host a restore runs on ----------

# rs_host [mode] [setup]: backup_host's deployment as an installed RS_VERSION, with the restore's
# fakes; <setup> is run on the deployment before it becomes RS_VERSION (as rs_make runs its own).
rs_host() {
  backup_host "${1:-ui}"
  eval "${2:-:}"
  rs_at_version "$RS_VERSION"
  bk_openssl
  printf '%s\n' "$BK_PG_DIGEST" >>"$DB/images"
  mkdir -p "$DB/ctr" "$DB/curl"
  local s
  for s in postgres guacd backend frontend; do printf 'running\n' >"$DB/ctr/$s"; done
  : >"$DB/proc.seen"
  rs_fakes
}

# rs_new_host: rs_host's deployment folder as a host not installed yet (no current.version,
# nothing running).
rs_new_host() {
  # What load recorded stays: a new host loads the offline bundle before it restores.
  jq '{format: "2"} + with_entries(select(.key | startswith("load.")))' "$ROOT/state.json" >"$ROOT/state.json.new"
  /usr/bin/mv "$ROOT/state.json.new" "$ROOT/state.json"
  rm -f "$DB/ctr/"*
}

# rs_fakes: the restore's calls on top of backup_host's hook (kept as db-hook), and curl.
rs_fakes() {
  /usr/bin/mv "$FAKE_DOCKER_REPLAY/hook" "$FAKE_DOCKER_REPLAY/db-hook"
  rs_inject_tool
  cat >"$FAKE_DOCKER_REPLAY/hook" <<'HOOK'
#!/bin/bash
all=" $* "
ev() { printf '%s\n' "$1" >>"$DB/events"; }
hex() { printf '%s' "$1" | od -An -tx1 -v | tr -d ' \n'; }
# seen <what>: a query of the external database answered here, in the events and in db-runs with
# the client image it ran in (the argument before psql's own options).
seen() {
  local a img="" prev=""
  for a in "${ARGS[@]}"; do [ "$a" != -AtX ] || img=$prev; prev=$a; done
  ev "psql $1"
  printf '%s %s psql %s\n' "${CX_DB_ACTION:-none}" "$img" "$1" >>"$DB/db-runs"
}
ARGS=("$@")
"$DB/../rs-inject" before "$*" || exit $?
set_all() { local f; for f in "$DB"/ctr/*; do [ -e "$f" ] && printf '%s\n' "$1" >"$f"; done; }
rc=99
case $all in
  *" exec -T postgres "*" -U  -d "* | *" exec -T postgres "*" -d  -"*)
    # The database client without the account or the database, as PostgreSQL answers it.
    echo 'psql: error: connection to server on socket "/var/run/postgresql/.s.PGSQL.5432" failed: FATAL:  role "root" does not exist' >&2
    rc=2 ;;
  " info --format "*DriverStatus*" ")
    # $DB/store: the image store the daemon reports (classic unless it says containerd).
    if [ "$(cat "$DB/store" 2>/dev/null)" = containerd ]; then
      printf '%s\n' '[["driver-type","io.containerd.snapshotter.v1"]]'
      rc=0
    fi ;;
  " image inspect "*)
    # $DB/images.ref: lines "<reference> <image ID>", an image this host knows by that reference
    # (a tag, or a repository@digest); another reference of a repository listed there is not on
    # this host. A bare ID, and the other repositories, are still db-hook's.
    if [ -e "$DB/images.ref" ]; then
      ref=${*: -1}
      id=$(awk -v r="$ref" '$1 == r { print $2; exit }' "$DB/images.ref")
      if [ -n "$id" ]; then
        printf '%s\n' "$id"
        rc=0
      elif [[ $ref == *[:@]* && $ref != sha256:* ]] &&
        awk -v p="${ref%%[:@]*}" 'index($1, p ":") == 1 || index($1, p "@") == 1 { f = 1 } END { exit !f }' "$DB/images.ref"; then
        echo "Error response from daemon: No such image: ${*: -1}" >&2
        rc=1
      fi
    fi ;;
  *" exec -T backend wget "*seal/status*)
    ev seal-status
    case $(cat "$DB/seal" 2>/dev/null) in
      # As the backend answers: keys sorted, the instance guard's own state nested before the
      # top-level one, kek_id only when unsealed.
      sealed) printf '{"authorization_required":true,"generation":0,"instance_guard":{"peers":0,"state":"held"},"mode":"ui","state":"sealed"}\n'; rc=0 ;;
      unsealed) printf '{"authorization_required":true,"generation":1,"instance_guard":{"peers":0,"state":"held"},"kek_id":"%s","mode":"env","state":"unsealed"}\n' "$(cat "$DB/kek")"; rc=0 ;;
      unsealed-noid) printf '{"authorization_required":true,"generation":1,"instance_guard":{"peers":0,"state":"held"},"mode":"env","state":"unsealed"}\n'; rc=0 ;;
      *) echo 'wget: server returned error: HTTP/1.1 503' >&2; rc=1 ;;
    esac ;;
  *" --entrypoint psql "*" --single-transaction "*)
    # The external import: the files of the mounted /w in one transaction, kept in $DB/sent.
    # $DB/import.rc ends psql with that code (3: an error, rolled back; others: killed or the
    # connection lost, the server committed when $DB/import.commit holds 1); otherwise committed.
    # Committed, the target's digest is that of the backup's content ($DB/ext.digest = imported).
    ev "psql import"
    printf '%s psql import\n' "${CX_DB_ACTION:-none}" >>"$DB/db-runs"
    prev=""
    for a in "$@"; do
      if [ "$prev" = -v ] && [[ $a == *:/w:ro ]]; then rm -rf "$DB/sent"; cp -r "${a%%:*}" "$DB/sent"; fi
      prev=$a
    done
    # $DB/import.digest: the content a commit leaves instead (a put-back of an export).
    content=imported
    [ ! -e "$DB/import.digest" ] || content=$(cat "$DB/import.digest")
    if [ -e "$DB/import.rc" ]; then
      [ "$(cat "$DB/import.commit" 2>/dev/null)" != 1 ] || echo "$content" >"$DB/ext.digest"
      exit "$(cat "$DB/import.rc")"
    fi
    echo "$content" >"$DB/ext.digest"
    rc=0 ;;
  *" --entrypoint psql "*)
    # The external database's answers to the restore's own queries (the others: db-hook).
    sql=${*: -1}
    if [ ! -e "$DB/connect.rc" ]; then
      case $sql in
        *target_digest*)
          # $DB/ext.digest names the target's content (before when absent); its hash answers.
          seen digest
          if [ -e "$DB/digest.rc" ]; then rc=$(cat "$DB/digest.rc"); else
            printf '%s' "$(cat "$DB/ext.digest" 2>/dev/null || echo before)" | sha256sum | cut -d' ' -f1
            rc=0
          fi ;;
        *ext_schemas*)
          seen schemas
          if [ -e "$DB/objects" ]; then
            while IFS='|' read -r s c; do printf '%s\n' "$(hex "$s")"; done <"$DB/objects"
          fi
          rc=0 ;;
        *aclexplode*) ;;
        *client_addr*)
          seen activity
          n=$(($(cat "$DB/activity.calls" 2>/dev/null || echo 0) + 1))
          echo "$n" >"$DB/activity.calls"
          f=$DB/activity.$n
          [ -e "$f" ] || f=$DB/activity
          if [ -e "$f" ]; then
            while read -r a app; do
              [ -n "$a$app" ] || continue
              [ "$a" != - ] || a=""
              printf '%s|%s\n' "$a" "$(hex "$app")"
            done <"$f"
          fi
          rc=0 ;;
        *"FROM pg_roles"*" IN ("*)
          seen roles
          if [ -e "$DB/roles" ]; then
            while IFS= read -r r; do
              h=$(hex "$r")
              [[ $sql != *"'$h'"* ]] || printf '%s\n' "$h"
            done <"$DB/roles"
          fi
          rc=0 ;;
        *obj_owner*)
          seen owners
          if [ -e "$DB/foreign" ]; then
            while IFS='|' read -r s o w; do printf '%s|%s|%s\n' "$(hex "$s")" "$(hex "$o")" "$(hex "$w")"; done <"$DB/foreign"
          fi
          rc=0 ;;
        *obj_total*)
          # The number of objects: the sum of $DB/objects (none when absent).
          seen total
          awk -F'|' '{n += $2} END {print n + 0}' "$DB/objects" 2>/dev/null || echo 0
          rc=0 ;;
        *obj_count*)
          seen objects
          if [ -e "$DB/objects" ]; then
            while IFS='|' read -r s c; do printf '%s|%s\n' "$(hex "$s")" "$c"; done <"$DB/objects"
          fi
          rc=0 ;;
      esac
    fi ;;
  *" --entrypoint pg_restore "*" -f /"*)
    # pg_restore -f <file>: the SQL of $DB/pg_restore.out (else a short dump with its restrict
    # wrapping) into the mounted file; $DB/pg_restore.cut "<bytes> <exit code|signal>" stops it
    # after that many bytes, with that code or killed by that signal.
    ev "pg_restore file"
    out="" prev=""
    for a in "$@"; do [ "$prev" != -f ] || out=$a; prev=$a; done
    target=$out prev=""
    for a in "$@"; do
      if [ "$prev" = -v ]; then
        h=${a%%:*} c=${a#*:}
        c=${c%%:*}
        case $out in "$c"/*) target=$h${out#"$c"} ;; esac
      fi
      prev=$a
    done
    [[ $all != *" -i "* ]] || cat >/dev/null
    # -L <list of grant entries only>: the grants ($DB/pg_restore.grants, else GRANTs to the roles
    # of $DB/grants.restore, wrapped); $DB/pg_restore.cut.grants stops it as .cut does the rest.
    list="" prev=""
    for a in "$@"; do [ "$prev" != -L ] || list=$a; prev=$a; done
    prev=""
    for a in "$@"; do
      if [ "$prev" = -v ] && [ -n "$list" ]; then
        h=${a%%:*} c=${a#*:}; c=${c%%:*}
        case $list in "$c"/*) list=$h${list#"$c"} ;; esac
      fi
      prev=$a
    done
    cut=$DB/pg_restore.cut
    if [ -n "$list" ] && grep -q ' ACL ' "$list" && ! grep -v '^;' "$list" | grep -v ' ACL ' | grep -q .; then
      cut=$DB/pg_restore.cut.grants
      src=$DB/pg_restore.grants
      if [ ! -e "$src" ]; then
        src=$DB/pg_restore.grants.default
        {
          printf '%s\n' '--' '-- PostgreSQL database dump' '--' '' '\restrict 9a8b7c6d5e4f' ''
          n=4000
          while IFS= read -r r; do [ -n "$r" ] && printf 'GRANT SELECT ON TABLE public.t%s TO %s;\n' "$n" "$r"; n=$((n + 1)); done \
            < <(cat "$DB/grants.restore" 2>/dev/null)
          printf '%s\n' '' '--' '-- PostgreSQL database dump complete' '--' '' '\unrestrict 9a8b7c6d5e4f'
        } >"$src"
      fi
    else
      src=$DB/pg_restore.out
    fi
    if [ ! -e "$src" ]; then
      src=$DB/pg_restore.default
      printf '%s\n' '--' '-- PostgreSQL database dump' '--' '' '\restrict 0f1e2d3c4b5a' '' \
        'SET statement_timeout = 0;' 'CREATE TABLE public.users (id bigint);' '' '--' \
        '-- PostgreSQL database dump complete' '--' '' '\unrestrict 0f1e2d3c4b5a' >"$src"
    fi
    if [ -e "$cut" ]; then
      read -r off act <"$cut"
      head -c "$off" "$src" >"$target"
      case $act in
        [0-9]*) exit "$act" ;;
        *) kill -s "$act" $$; /usr/bin/sleep 5; exit 1 ;;
      esac
    fi
    cp "$src" "$target"
    rc=0 ;;
  *" compose "*" create "*)
    ev create
    for c in postgres guacd backend frontend; do printf 'created\n' >"$DB/ctr/$c"; done
    rc=0 ;;
  *" exec -T postgres psql "*recording_path*)
    ev "psql recordings"
    if [ -e "$DB/recordings.rc" ]; then rc=$(cat "$DB/recordings.rc"); else cat "$DB/recordings" 2>/dev/null; rc=0; fi ;;
  *" exec -T postgres psql "*offsite_profiles*)
    ev "psql offsite"
    if [ -e "$DB/offsite" ]; then cat "$DB/offsite"; else echo 0; fi
    rc=0 ;;
  *" up -d postgres "*)
    ev "up postgres"
    if [ -e "$DB/up.rc" ]; then rc=$(cat "$DB/up.rc"); else printf 'running\n' >"$DB/ctr/postgres"; rc=0; fi ;;
  *" pg_restore"*" -l "*)
    ev "pg_restore list"
    cat >/dev/null
    if [ -e "$DB/pg_restore.rc" ]; then rc=$(cat "$DB/pg_restore.rc"); else
      printf ';\n; Archive created at 2026-10-05\n'
      n=4000
      while IFS= read -r r; do [ -n "$r" ] && printf '%s; 0 0 ACL public TABLE t%s postgres\n' "$n" "$n"; n=$((n + 1)); done \
        < <(cat "$DB/grants.restore" 2>/dev/null)
      rc=0
    fi ;;
  *" pg_restore"*" -L "*)
    ev "pg_restore acl"
    cat >/dev/null
    if [ -e "$DB/pg_restore.rc" ]; then rc=$(cat "$DB/pg_restore.rc"); else
      n=4000
      while IFS= read -r r; do [ -n "$r" ] && printf 'GRANT SELECT ON TABLE public.t%s TO %s;\n' "$n" "$r"; n=$((n + 1)); done \
        < <(cat "$DB/grants.restore" 2>/dev/null)
      rc=0
    fi ;;
  # After -L: the grants read before anything stops is "-L <list> -f -" too.
  *" --entrypoint pg_restore "*" -f - "*)
    # The full read of an export: $DB/pg_restore_full.rc ends it with that code.
    ev "pg_restore full"
    cat >/dev/null
    if [ -e "$DB/pg_restore_full.rc" ]; then rc=$(cat "$DB/pg_restore_full.rc"); else printf -- '-- PostgreSQL database dump complete\n'; rc=0; fi ;;
esac
if [ "$rc" = 99 ]; then
  "$FAKE_DOCKER_REPLAY/db-hook" "$@"
  rc=$?
  if [ "$rc" = 0 ]; then
    case $all in
      *" compose "*" stop "*) set_all stopped ;;
      *" compose "*" start "* | *" compose "*" up -d "*) set_all running ;;
    esac
  fi
fi
[ "$rc" = 99 ] || "$DB/../rs-inject" after "$*" || exit $?
exit "$rc"
HOOK
  chmod +x "$FAKE_DOCKER_REPLAY/hook"
  # shellcheck disable=SC2016
  fake curl 'DB='"$DB"'
"$DB/../rs-inject" before "$*" || exit $?
# -w (the HTTP code wanted on stdout): a 404 still exits 0, as curl without -f does.
out="" code=0 url=""
while [ $# -gt 0 ]; do
  case $1 in
    -o) out=$2; shift 2 ;;
    -w) code=1; shift 2 ;;
    -*) shift ;;
    *) url=$1; shift ;;
  esac
done
n=${url##*/}
printf "curl %s\n" "$n" >>"$DB/events"
[ ! -e "$DB/curl.offline" ] || { echo "curl: (7) Failed to connect" >&2; [ "$code" = 0 ] || printf 000; exit 7; }
if grep -qxF -- "$n" "$DB/curl.404" 2>/dev/null || [ ! -e "$DB/curl/$n" ]; then
  [ "$code" = 0 ] || printf 404
  [ "$code" = 1 ] || { echo "curl: (22) The requested URL returned error: 404" >&2; exit 22; }
  exit 0
fi
if [ -n "$out" ]; then cp "$DB/curl/$n" "$out"; else cat "$DB/curl/$n"; fi
[ "$code" = 0 ] || printf 200
"$DB/../rs-inject" after "$n" || exit $?
exit 0'
}

# rs_inject_tool: $DB/../rs-inject <before|after> <arguments>: the line of $DB/inject for this call
# (each fires once): an exit code makes the call fail with it; a signal name goes to the script
# (the nearest caller running custodexa.sh). It also records the callers' arguments and environment
# in $DB/proc.seen.
rs_inject_tool() {
  cat >"$DB/../rs-inject" <<'TOOL'
#!/bin/bash
when=$1 args=$2 p=$PPID target=""
if [ "$when" = before ]; then
  while [ -n "$p" ] && [ "$p" -gt 1 ]; do
    { tr '\0' ' ' </proc/$p/cmdline; echo; tr '\0' '\n' </proc/$p/environ; } >>"$DB/proc.seen" 2>/dev/null
    if [ -z "$target" ] && tr '\0' ' ' </proc/$p/cmdline 2>/dev/null | grep -q 'custodexa\.sh'; then target=$p; fi
    p=$(awk '{ print $4 }' /proc/$p/stat 2>/dev/null)
  done
else
  while [ -n "$p" ] && [ "$p" -gt 1 ]; do
    if tr '\0' ' ' </proc/$p/cmdline 2>/dev/null | grep -q 'custodexa\.sh'; then target=$p; break; fi
    p=$(awk '{ print $4 }' /proc/$p/stat 2>/dev/null)
  done
fi
[ -e "$DB/inject" ] || exit 0
n=0
while read -r w pat act; do
  n=$((n + 1))
  [ "$w" = "$when" ] || continue
  # shellcheck disable=SC2053 # the pattern is a glob
  [[ " $args " == $pat ]] || continue
  sed -i "${n}s/^/#/" "$DB/inject"
  printf 'inject %s %s %s\n' "$when" "$pat" "$act" >>"$DB/events"
  case $act in
    [0-9]*) exit "$act" ;;
    *) [ -n "$target" ] && kill -s "$act" "$target"; exit 0 ;;
  esac
done <"$DB/inject"
exit 0
TOOL
  chmod +x "$DB/../rs-inject"
}

# ---------- an external database ----------

# rs_ext_fixtures: rs_fixtures and the backups of external database deployments, each made by the
# real backup against backup_host's external database (bk_external):
#   ext16        PostgreSQL 16 (the 16 client), verify-full against the system's authorities
#   external     PostgreSQL 17 (rs_fixtures)
#   extca        PostgreSQL 17, verify-full with a CA file of its own: db-ca.pem in the backup
#   extcert      PostgreSQL 17 with a client certificate and key (the key in no member)
#   extgrants    PostgreSQL 16 with grants to two more roles, "report reader" and auditor_ro
rs_ext_fixtures() {
  rs_fixtures || return 1
  [ ! -e "$RS_FIX/.ext-done" ] || return 0
  local base='fake sleep :; host_arch x86_64; clock'
  rs_make "$RS_FIX/ext16" ui "$base; bk_external 16.4"'
    printf "pg_dump (PostgreSQL) 16.15\n" >"$DB/pg_dump_version"' || return 1
  rs_make "$RS_FIX/extca" ui "$base; bk_external 17.6"'
    printf "pg_dump (PostgreSQL) 17.11\n" >"$DB/pg_dump_version"
    mkdir -p "$ROOT/data/exports/db"
    printf "%s\n" "-----BEGIN CERTIFICATE-----" "cnMtdGVzdC1jYQ==" "-----END CERTIFICATE-----" >"$ROOT/data/exports/db/ca.pem"
    bk_env_set PGSSLROOTCERT /var/lib/custodexa/exports/db/ca.pem' || return 1
  rs_make "$RS_FIX/extcert" ui "$base; bk_external 17.6"'
    printf "pg_dump (PostgreSQL) 17.11\n" >"$DB/pg_dump_version"
    mkdir -p "$ROOT/data/exports/db"
    printf "client certificate\n" >"$ROOT/data/exports/db/client.crt"
    printf "rs-test-client-key-0005\n" >"$ROOT/data/exports/db/client.key"
    chmod 600 "$ROOT/data/exports/db/client.key"
    bk_env_set PGSSLCERT /var/lib/custodexa/exports/db/client.crt
    bk_env_set PGSSLKEY /var/lib/custodexa/exports/db/client.key' || return 1
  rs_make "$RS_FIX/extgrants" ui "$base; bk_external 16.4"'
    printf "pg_dump (PostgreSQL) 16.15\n" >"$DB/pg_dump_version"
    printf "%s\n" "$(bk_hex "report reader")" "$(bk_hex auditor_ro)" >"$DB/grants"' || return 1
  : >"$RS_FIX/.ext-done"
}

# rs_ext_host [server version]: rs_host as a deployment on an external database (PostgreSQL 17.6
# unless given), the way bk_external lays it out. The three clients of the release are on this host
# as an offline bundle leaves them on the containerd image store: known by their tags only, under
# IDs of their own (BK_PGC_ID; neither the release's index nor its config digest finds them), with
# those IDs recorded by install (current.tool_image_ids) and by load (load.*, which rs_new_host
# keeps). A new host is rs_new_host after it. rs_ext_pulled lays them out as pulled instead.
rs_ext_host() {
  local m ids=""
  # Laid out anew when a test's setup made another host first.
  rm -rf "$BATS_TEST_TMPDIR/opt" "$BATS_TEST_TMPDIR/db"
  rs_host ui "bk_external ${1:-17.6}"
  printf 'containerd\n' >"$DB/store"
  for m in 16 17 18; do
    printf 'docker.io/library/postgres:%s %s\n' "${BK_PGC_TAG[$m]}" "${BK_PGC_ID[$m]}"
    ids+="${ids:+ }pgclient$m=${BK_PGC_ID[$m]}"
  done >"$DB/images.ref"
  printf '%s\n' "${BK_PGC_ID[16]}" "${BK_PGC_ID[17]}" "${BK_PGC_ID[18]}" >>"$DB/images"
  bk_state_set load.version "$RS_VERSION"
  bk_state_set load.image_ids "$ids"
}

# rs_ext_pulled: the clients as a pull by the release's index digest leaves them on the containerd
# image store (the ID is that digest), with nothing recorded by load or install.
rs_ext_pulled() {
  local m
  for m in 16 17 18; do
    printf 'docker.io/library/postgres@%s %s\n' "${BK_PGC_DIGEST[$m]}" "${BK_PGC_DIGEST[$m]}"
    printf '%s\n' "${BK_PGC_DIGEST[$m]}" >>"$DB/images"
  done >"$DB/images.ref"
  jq 'with_entries(select(.key | startswith("load.") | not)) | del(."current.tool_image_ids")' \
    "$ROOT/state.json" >"$ROOT/state.json.new"
  /usr/bin/mv "$ROOT/state.json.new" "$ROOT/state.json"
}

# Tests of the read/prepare/preview stages stop at the boundary before the durable record.
# Their unchanged-tree and no-stop assertions remain in force after execution is enabled.
rs_preflight_only() {
  cat >>"$ROOT/current/lib/cmd_restore.sh" <<'SH'
cx_rs_begin_execution() { printf 'restore-preflight-accepted\n'; return 3; }
SH
}
