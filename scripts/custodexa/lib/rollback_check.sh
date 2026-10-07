# shellcheck shell=bash
# CX_RB_* are read by the rollback command and the upgrade screens that offer it.
# shellcheck disable=SC2034
# Whether `rollback` may go back to the version before the last upgrade, decided before anything
# stops. Everything here only reads: state.json (already loaded, under the deployment lock), the
# current link, the release folders, the local images and, for the database, the one query the
# upgrade snapshot uses, made only while the database is already running.
#
#   cx_rb_premise    the deployment is where an upgrade by this script left it, after the switch,
#                    not gone back yet, and the version before is 1.16.0 or later (no database read)
#   cx_rb_hint_ok    the same, for the upgrade screens that print the rollback command
#   cx_rb_judge      the new version has not changed the database: it never started; or the
#                    migrations now are the ones recorded before the upgrade; or the release lists
#                    the version before as one it can go straight back to. Unknown means changed.
#   cx_rb_images     every image of the version before is on this host with the ID recorded then
#   cx_rb_start      starts the services, after recording that the new version may run
# The database client may already be loaded (lib/backup.sh brings it); its constants are readonly.
# shellcheck source=lib/dbclient.sh
declare -F cx_db >/dev/null || . "${BASH_SOURCE[0]%/*}/dbclient.sh"
# shellcheck source=lib/version_rules.sh
declare -F cx_vr_cmp >/dev/null || . "${BASH_SOURCE[0]%/*}/version_rules.sh"

readonly CX_RB_MIN=1.16.0
CX_RB_WHY=""       # a premise that does not hold: none, changed, link, before_switch, already, too_old
CX_RB_TARGET=""    # the version to go back to (the version the last upgrade started from)
CX_RB_PRESWITCH=0  # 1: the upgrade recorded step 9 but never saved the switch; nothing to swap
CX_RB_BASIS=""     # why going back is safe: not_started, same_migrations, compatible
CX_RB_READ=0       # both migration sets could be read
CX_RB_REASON=""    # why it is not: changed (CX_RB_ADDED lists what), unreadable
CX_RB_ADDED=()     # migrations the database has now and did not have before the upgrade
CX_RB_IMG_BAD=()   # "<name> missing" or "<name> differs <recorded ID> <ID now>"

# cx_rb_older <a> <b>: version a is older than b.
cx_rb_older() { [ "$(cx_vr_cmp "$1" "$2" 2>/dev/null)" = -1 ]; }

# cx_rb_premise: rows 2 to 5 of the premises, in this order: gone back already, or settled by a
# restore that finished; stopped before the switch; the version record and the current link as the
# upgrade left them; the version before not older than 1.16.0. Sets CX_RB_WHY (empty when every
# one holds), CX_RB_TARGET, CX_RB_PRESWITCH.
cx_rb_premise() {
  local res step from to cur prev link
  res=$(cx_state_get last_upgrade.result) step=$(cx_state_get last_upgrade.step)
  from=$(cx_state_get last_upgrade.from) to=$(cx_state_get last_upgrade.to)
  cur=$(cx_state_get current.version) prev=$(cx_state_get previous.version)
  link=$(readlink -- "$CX_ROOT/current" 2>/dev/null) || link=""
  CX_RB_WHY="" CX_RB_TARGET=$from CX_RB_PRESWITCH=0
  if [ -z "$from" ] || [ -z "$to" ] || [ -z "$res" ]; then
    CX_RB_WHY=none
    return 1
  fi
  if [ "$res" = rolled_back ]; then
    CX_RB_WHY=already
    return 1
  fi
  # A restore finished after the upgrade: the deployment is what the backup holds, not the upgrade.
  if [ "$(cx_state_get last_upgrade.settled_by)" = restore ]; then
    CX_RB_WHY=changed
    return 1
  fi
  case $res in
    succeeded) ;;
    failed | in_progress)
      if ! [[ $step =~ ^[0-9]+$ ]] || [ "$step" -lt 9 ]; then
        CX_RB_WHY=before_switch
        return 1
      fi
      ;;
    *)
      CX_RB_WHY=changed
      return 1
      ;;
  esac
  if [ "$step" = 9 ] && [ "$res" != succeeded ] && [ "$cur" = "$from" ]; then
    # Step 9 is on record but the switch was not saved: still the version before, in every place.
    if [ "$link" != "releases/$from" ]; then
      CX_RB_WHY='link'
      return 1
    fi
    CX_RB_PRESWITCH=1
  else
    if [ "$prev" != "$from" ] || [ "$cur" != "$to" ] || ! cx_rb_older "$prev" "$cur"; then
      CX_RB_WHY=changed
      return 1
    fi
    if [ "$link" != "releases/$cur" ] && { [ "$step" != 9 ] || [ "$link" != "releases/$prev" ]; }; then
      CX_RB_WHY='link'
      return 1
    fi
  fi
  if cx_rb_older "$from" "$CX_RB_MIN"; then
    CX_RB_WHY=too_old
    return 1
  fi
}

# cx_rb_hint_ok: the upgrade screens offer `rollback` (it still decides for itself).
cx_rb_hint_ok() { cx_rb_premise; }

# cx_rb_db_running: the bundled database container runs, or the external database has its client.
cx_rb_db_running() {
  if cx_db_external; then
    cx_db_ready
    return
  fi
  cx_compose ps --status running --services 2>/dev/null | grep -qx postgres
}

# cx_rb_migrations_now: the migrations the database holds now, one per line, sorted.
cx_rb_migrations_now() {
  local out
  # The query of the upgrade snapshot (lib/snapshot.sh), so the two lists compare.
  out=$(cx_db sql "SELECT version FROM schema_migrations ORDER BY version") || return 1
  [ -n "$out" ] || return 1
  printf '%s\n' "$out" | LC_ALL=C sort -u
}

# cx_rb_judge: whether the new version has not changed the database (state.json loaded again by the
# caller when this is the second check). Sets CX_RB_BASIS and returns 0, or sets CX_RB_REASON and
# CX_RB_ADDED and returns 1. Starts nothing.
cx_rb_judge() {
  local step res snap now before compat to
  CX_RB_BASIS="" CX_RB_REASON="" CX_RB_ADDED=() CX_RB_READ=0
  step=$(cx_state_get last_upgrade.step) res=$(cx_state_get last_upgrade.result)
  if [ "$step" = 9 ] && [[ $res == failed || $res == in_progress ]] \
    && [ -z "$(cx_state_get last_upgrade.new_started_at)" ]; then
    CX_RB_BASIS=not_started
    cx_log CHECK "rollback basis=not_started"
    return 0
  fi
  CX_RB_REASON=unreadable
  snap=$(cx_state_get last_upgrade.snapshot)
  if [ -n "$snap" ] && [ -s "$CX_ROOT/$snap" ] && cx_rb_db_running && now=$(cx_rb_migrations_now); then
    before=$(sed -n 's/^migration=//p' "$CX_ROOT/$snap" | LC_ALL=C sort -u)
    if [ -n "$before" ]; then
      CX_RB_READ=1
      if [ "$now" = "$before" ]; then
        CX_RB_BASIS=same_migrations CX_RB_REASON=""
        cx_log CHECK "rollback basis=same_migrations"
        return 0
      fi
      CX_RB_REASON=changed
      mapfile -t CX_RB_ADDED < <(LC_ALL=C comm -23 <(printf '%s\n' "$now") <(printf '%s\n' "$before"))
    fi
  fi
  to=$(cx_state_get last_upgrade.to)
  compat=$(jq -r --arg v "$CX_RB_TARGET" '(.rollback_compatible // []) | index($v) // empty' \
    "$CX_ROOT/releases/$to/MANIFEST.json" 2>/dev/null) || compat=""
  if [ -n "$compat" ]; then
    CX_RB_BASIS=compatible CX_RB_REASON=""
    cx_log CHECK "rollback basis=compatible"
    return 0
  fi
  cx_log CHECK "rollback refused reason=$CX_RB_REASON added=${CX_RB_ADDED[*]+"${CX_RB_ADDED[*]}"}"
  return 1
}

# cx_rb_target_ids: the image IDs recorded for the version to go back to.
cx_rb_target_ids() {
  if [ "$CX_RB_PRESWITCH" = 1 ]; then
    cx_state_get current.image_ids
  else
    cx_state_get previous.image_ids
  fi
}

# cx_rb_images: row 8. The release of the version to go back to has images.env and MANIFEST.json,
# and each image it names is on this host with the ID recorded before the upgrade. Only this host
# is asked; nothing is pulled. Sets CX_RB_IMG_BAD.
cx_rb_images() {
  local rel=$CX_ROOT/releases/$CX_RB_TARGET line name ref want got count=0
  local -A ids=()
  CX_RB_IMG_BAD=()
  for line in $(cx_rb_target_ids); do ids[${line%%=*}]=${line#*=}; done
  if [ ! -f "$rel/images.env" ] || [ ! -f "$rel/MANIFEST.json" ] || [ ${#ids[@]} -eq 0 ]; then
    CX_RB_IMG_BAD=("release missing")
    return 1
  fi
  while IFS= read -r line || [ -n "$line" ]; do
    [[ $line =~ ^CUSTODEXA_IMAGE_([A-Z0-9_]+)=(.+)$ ]] || continue
    name=${BASH_REMATCH[1],,} ref=${BASH_REMATCH[2]}
    want=${ids[$name]:-}
    count=$((count + 1))
    if [ -z "$want" ]; then CX_RB_IMG_BAD+=("$name unrecorded"); continue; fi
    got=$(cx_img_id "$ref") || got=""
    if [ -z "$got" ]; then
      CX_RB_IMG_BAD+=("$name missing")
    elif [ "$got" != "$want" ]; then
      CX_RB_IMG_BAD+=("$name differs $want $got")
    fi
  done <"$rel/images.env"
  [ "$count" -gt 0 ] || CX_RB_IMG_BAD+=("release missing")
  [ ${#CX_RB_IMG_BAD[@]} -eq 0 ]
}

# cx_rb_start: step 3. The record that the new version may run comes first (it is written only when
# current points at the version the upgrade went to, that is when going back to it); when it cannot
# be written nothing starts.
cx_rb_start() {
  cx_new_started_mark || return 1
  cx_log_run cx_compose up -d --remove-orphans >/dev/null 2>&1
}
