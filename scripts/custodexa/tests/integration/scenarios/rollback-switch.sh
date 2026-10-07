# shellcheck shell=bash
# about: a built-in deployment goes back from 1.16.91 to 1.16.90 (the same migrations) with rollback: the old images run again, the data written on 1.16.91 is read through 1.16.90, the settings file, certificates and a recording are unchanged; a second rollback is refused; a run interrupted while it starts the services, and a run whose old version does not become ready, finish with --resume and --revert as the screens say, also when the revert is interrupted or cannot confirm the drain; a missing old image is refused until the old offline bundle is loaded
# needs: package local-versions
# images:

readonly SW_OLD=1.16.90 SW_NEW=1.16.91

# sw_data <label>: a user and an asset made through the API of the version running now; their JSON
# and that of every audit event about them are kept in $IT_WORK/data-<label>.json.
sw_data() {
  local label=$1 uid aid r
  r=$(lv_api POST /users "$(jq -cn --arg n "it-$label" \
    '{username: $n, password: "It-user-pass-0001", email: "\($n)@example.test", full_name: "Rollback test \($n)"}')")
  uid=$(jq -er '.data.id // .id' <<<"$r")
  r=$(lv_api POST /assets "$(jq -cn --arg n "it-$label" \
    '{name: $n, protocol: "ssh", host: "192.0.2.10", port: 22, description: "rollback test \($n)", tags: "it,rollback"}')")
  aid=$(jq -er '.data.id // .id' <<<"$r")
  printf '%s %s\n' "$uid" "$aid" >"$IT_WORK/data-$label.ids"
  # A create carries no resource ID in its path, so its event is not filed under the new user or
  # asset; one read of each is. Events are written in the background: wait until both are there.
  lv_api GET "/users/$uid" >/dev/null
  lv_api GET "/assets/$aid" >/dev/null
  lv_until "$label: audit events filed under user $uid and asset $aid" sw_has_events "$uid" "$aid" || true
  # Not straight into data-<label>.json: sw_read takes the event list from that file once it exists.
  sw_read "$label" >"$IT_WORK/data-$label.json.tmp"
  mv -f "$IT_WORK/data-$label.json.tmp" "$IT_WORK/data-$label.json"
  it_say "   on $(lv_version): user $uid, asset $aid and $(jq '.audit | length' "$IT_WORK/data-$label.json") audit events about them"
  it_check "$label: there are audit events about the user and the asset" \
    test "$(jq '[.audit[] | .resource] | unique | sort | join(" ")' "$IT_WORK/data-$label.json")" = '"asset user"'
}

sw_has_events() {
  [ "$(lv_api GET "/audit-logs/resource/user/$1" | jq '.logs | length')" -gt 0 ] &&
    [ "$(lv_api GET "/audit-logs/resource/asset/$2" | jq '.logs | length')" -gt 0 ]
}

# sw_read <label>: the user, the asset and the audit events recorded when sw_data ran, read now.
sw_read() {
  local uid aid id ids
  read -r uid aid <"$IT_WORK/data-$1.ids"
  if [ -f "$IT_WORK/data-$1.json" ]; then
    ids=$(jq -r '.audit[].id' "$IT_WORK/data-$1.json")
  else
    ids=$({ lv_api GET "/audit-logs/resource/user/$uid" | jq -r '.logs[].id'
      lv_api GET "/audit-logs/resource/asset/$aid" | jq -r '.logs[].id'; } | sort -n)
  fi
  {
    lv_api GET "/users/$uid" | jq -c '{user: (.data // .)}'
    lv_api GET "/assets/$aid" | jq -c '{asset: (.data // .)}'
    for id in $ids; do lv_api GET "/audit-logs/$id" | jq -c '.data // .'; done | jq -sc '{audit: .}'
  } | jq -sS 'add'
}

# sw_same_data <label>: what sw_data recorded reads the same now.
sw_same_data() {
  it_same "the data written as '$1' reads the same through $(lv_version) (user, asset, $(jq '.audit | length' "$IT_WORK/data-$1.json") audit events)" \
    "$(jq -cS . "$IT_WORK/data-$1.json")" "$(sw_read "$1" | jq -cS .)"
}

# sw_back <label>: the deployment runs the old version as the record before the upgrade says.
sw_back() {
  lv_wait_version "$SW_OLD"
  it_same "$1: current.version, the current link" "$SW_OLD releases/$SW_OLD" \
    "$(lv_st current.version) $(readlink "$LV_ROOT/current")"
  it_same "$1: the running images are those recorded before the upgrade (previous.image_ids then)" \
    "$SW_PREV_IDS" "$(lv_ids_running)"
  it_same "$1: last_rollback.result, last_upgrade.result" "succeeded rolled_back" \
    "$(lv_st last_rollback.result) $(lv_st last_upgrade.result)"
}

# sw_on_new <label>: the deployment runs the new version again.
sw_on_new() {
  lv_wait_version "$SW_NEW"
  it_same "$1: current.version, the current link" "$SW_NEW releases/$SW_NEW" \
    "$(lv_st current.version) $(readlink "$LV_ROOT/current")"
  it_same "$1: the running images are those of $SW_NEW" "$SW_NEW_IDS" "$(lv_ids_running)"
}

# sw_screen_cmd <pattern>: the last command on the screen (LV_OUT) that runs custodexa.sh and
# matches the pattern, without sudo and without --lang (lv_cx adds it).
sw_screen_cmd() {
  grep -E "custodexa\.sh .*$1" <<<"$LV_OUT" | tail -n 1 | sed -E 's/^ *(sudo +)?//; s/ --lang [a-zA-Z-]+//; s#^[^ ]*/custodexa\.sh +##'
}

# sw_timeout <label>: a fresh rollback whose old backend is paused after its start (step 3), so the
# step 4 readiness check runs out (CX_READY_TRIES shortens the wait); the record stays unfinished.
sw_timeout() {
  local label=$1
  it_step "$label: rollback; the old backend is paused after the start, so it never becomes ready"
  LV_INJECT=pause-after-up LV_READY_TRIES=2 lv_cx "$label" rollback --yes
  it_same "$label: exit 1" 1 "$LV_RC"
  it_same "$label: last_rollback.result, step, direction" "in_progress 4 rollback" \
    "$(lv_st last_rollback.result) $(lv_st last_rollback.step) $(lv_st last_rollback.direction)"
  it_check "$label: the screen gives rollback --resume and rollback --revert" \
    bash -c 'grep -q "custodexa.sh rollback --resume" <<<"$1" && grep -q "custodexa.sh rollback --revert" <<<"$1"' _ "$LV_OUT"
  it_same "$label: the backend is paused" true "$(docker inspect --format '{{.State.Paused}}' custodexa-backend)"
}

scenario() {
  local ps0 im0 from to cmd
  lv_install "$SW_OLD"
  install -m 640 /dev/null "$LV_ROOT/$LV_RECORDING"
  head -c 262144 /dev/urandom >"$LV_ROOT/$LV_RECORDING"
  chown 1000:0 "$LV_ROOT/$LV_RECORDING"
  sw_data on-old
  lv_upgrade "$SW_NEW"
  lv_wait_version "$SW_NEW"
  SW_NEW_IDS=$(lv_ids_running)
  sw_data on-new
  SW_PREV_IDS=$(lv_st previous.image_ids)
  lv_files_sha >"$IT_WORK/files.before"
  it_say "   files kept: $(wc -l <"$IT_WORK/files.before") (.env, tls/, the recording)"

  it_step "rollback --yes: back to $SW_OLD"
  lv_cx rollback rollback --yes
  it_same "rollback exits 0" 0 "$LV_RC"
  it_same "the basis is: no migration since the upgrade" same_migrations "$(lv_st last_rollback.basis)"
  sw_back "rollback"
  it_same ".env, the files under tls/ and the recording are unchanged" "$(cat "$IT_WORK/files.before")" "$(lv_files_sha)"
  # shellcheck disable=SC2034 # read by lv_api: sign in again on the version now running
  LV_TOKEN=""
  sw_same_data on-old
  sw_same_data on-new

  it_step "a second rollback is refused: only one step back"
  ps0=$(lv_ps) im0=$(lv_images)
  lv_cx again rollback --yes
  it_same "exit 3" 3 "$LV_RC"
  it_check "the screen says the last change was already a rollback" grep -q 'already a rollback' <<<"$LV_OUT"
  it_same "the same containers run" "$ps0" "$(lv_ps)"
  it_same "the same images are here" "$im0" "$(lv_images)"

  it_step "upgrade again; rollback interrupted (SIGTERM) while it starts the services, then --resume"
  lv_upgrade "$SW_NEW"
  SW_PREV_IDS=$(lv_st previous.image_ids)
  touch "$IT_WORK/lv-hold"
  LV_INJECT=hold-up lv_bg sigterm rollback --yes
  lv_signal_at_up sigterm
  it_check "the rollback ended with an error" test "$LV_RC" -ne 0
  it_check "the screen names step 3 and gives rollback --resume" \
    bash -c 'grep -q "Interrupted at step 3" <<<"$1" && grep -q "custodexa.sh rollback --resume" <<<"$1"' _ "$LV_OUT"
  it_same "last_rollback.result, step" "in_progress 3" "$(lv_st last_rollback.result) $(lv_st last_rollback.step)"
  it_same "no tool container is left" "" "$(lv_tools_left)"
  cmd=$(sw_screen_cmd 'rollback --resume')
  # shellcheck disable=SC2086 # the command as the screen gives it
  lv_cx resume $cmd
  it_same "rollback --resume exits 0" 0 "$LV_RC"
  sw_back "resume"
  sw_same_data on-new

  it_step "upgrade again; the old version does not become ready, then --revert"
  lv_upgrade "$SW_NEW"
  SW_PREV_IDS=$(lv_st previous.image_ids) SW_NEW_IDS=$(lv_ids_running)
  sw_timeout timeout
  docker unpause custodexa-backend >/dev/null
  lv_cx revert rollback --revert --yes
  it_same "rollback --revert exits 0" 0 "$LV_RC"
  sw_on_new "revert"
  it_same "last_rollback.result" reverted "$(lv_st last_rollback.result)"

  it_step "the old version does not become ready, and --revert cannot confirm the drain either (backend paused)"
  sw_timeout timeout-2
  from=$(lv_st last_rollback.from) to=$(lv_st last_rollback.to)
  ps0=$(lv_ps)
  lv_cx revert-paused rollback --revert --yes
  it_same "rollback --revert exits 1" 1 "$LV_RC"
  it_same "the record is still unfinished: last_rollback.result" in_progress "$(lv_st last_rollback.result)"
  it_same "last_rollback.from, to" "$from $to" "$(lv_st last_rollback.from) $(lv_st last_rollback.to)"
  it_same "no service was stopped or started" "$ps0" "$(lv_ps)"
  cmd=$(sw_screen_cmd 'rollback --(resume|revert)')
  it_check "the screen gives the command to finish ($cmd)" test -n "$cmd"
  docker unpause custodexa-backend >/dev/null
  # shellcheck disable=SC2086
  lv_cx finish $cmd --yes
  it_same "the command on the screen exits 0" 0 "$LV_RC"
  sw_on_new "finished as the screen says"
  it_same "last_rollback.result" reverted "$(lv_st last_rollback.result)"

  it_step "the revert is interrupted (SIGTERM) while it starts the services, then --resume as the screen says"
  sw_timeout timeout-3
  from=$(lv_st last_rollback.from) to=$(lv_st last_rollback.to)
  docker unpause custodexa-backend >/dev/null
  touch "$IT_WORK/lv-hold"
  LV_INJECT=hold-up lv_bg revert-sigterm rollback --revert --yes
  lv_signal_at_up revert-sigterm
  it_check "the revert ended with an error" test "$LV_RC" -ne 0
  it_same "last_rollback.result, step, direction" "in_progress 3 revert" \
    "$(lv_st last_rollback.result) $(lv_st last_rollback.step) $(lv_st last_rollback.direction)"
  it_same "no tool container is left" "" "$(lv_tools_left)"
  it_check "the screen gives rollback --resume" grep -q "custodexa.sh rollback --resume" <<<"$LV_OUT"
  it_check "and not rollback --revert" bash -c '! grep -q "custodexa.sh rollback --revert" <<<"$1"' _ "$LV_OUT"
  cmd=$(sw_screen_cmd 'rollback --resume')
  # shellcheck disable=SC2086
  lv_cx resume-revert $cmd
  it_same "rollback --resume exits 0" 0 "$LV_RC"
  sw_on_new "the revert resumed"
  it_same "last_rollback.result" reverted "$(lv_st last_rollback.result)"
  it_same "last_rollback.from, to are unchanged" "$from $to" "$(lv_st last_rollback.from) $(lv_st last_rollback.to)"

  it_step "the old backend image is removed: rollback is refused until the old offline bundle is loaded"
  SW_PREV_IDS=$(lv_st previous.image_ids)
  docker rmi "ghcr.io/custodexa-it/backend:$SW_OLD" >/dev/null
  ps0=$(lv_ps)
  lv_cx images rollback --yes
  it_same "exit 3" 3 "$LV_RC"
  it_check "the screen says backend is not on this host" grep -qE 'backend +not on this host' <<<"$LV_OUT"
  it_same "the same containers run" "$ps0" "$(lv_ps)"
  cmd=$(sw_screen_cmd 'load ')
  it_check "the screen gives the load command ($cmd)" grep -q "^load " <<<"$cmd"
  # shellcheck disable=SC2086
  lv_cx load load "$(it_bundle_file "$SW_OLD")"
  it_same "load of the $SW_OLD bundle exits 0" 0 "$LV_RC"
  lv_cx rollback-loaded rollback --yes
  it_same "rollback exits 0" 0 "$LV_RC"
  sw_back "after load"
  sw_same_data on-new
}
