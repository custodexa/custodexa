#!/usr/bin/env bats
# Threat (B): the state file reader passing a damaged file. Upgrade and rollback decide what to
# stop, move and restore from state.json; a reader that guesses on a broken file acts on wrong data.

load helper
load release_fixture
load install_host

setup() {
  D=$BATS_TEST_TMPDIR
  F=$D/state.json
  load_lib
}

good() {
  printf '{\n  "format": "2",\n  "compose_project": "custodexa",\n  "current.version": "1.13.0"\n}\n' >"$F"
}

@test "a well-formed file loads and values are readable" {
  good
  cx_state_load "$F"
  [ "$(cx_state_get current.version)" = "1.13.0" ]
  [ "$(cx_state_get compose_project)" = "custodexa" ]
}

bad_case() { # <description> <content>
  printf '%s' "$2" >"$F"
  run cx_state_load "$F"
  [ "$status" -eq 5 ] || { echo "case '$1' gave status $status"; echo "$output"; return 1; }
  [[ "$output" == *"$F"* ]] || { echo "case '$1' does not name the file"; return 1; }
  [[ "$output" == *"$F.prev"* ]] || { echo "case '$1' does not name .prev"; return 1; }
}

@test "damaged files stop with exit code 5 and name the line" {
  bad_case quote   $'{\n  "format": "2",\n  "a": "x"y"\n}\n'
  bad_case backslash $'{\n  "format": "2",\n  "a": "x\\\\y"\n}\n'
  bad_case newline $'{\n  "format": "2",\n  "a": "x\ny"\n}\n'
  bad_case duplicate $'{\n  "format": "2",\n  "a": "1",\n  "a": "2"\n}\n'
  bad_case truncated $'{\n  "format": "2",\n  "a": "1",\n  "b": "'
  bad_case no-close $'{\n  "format": "2",\n  "a": "1"\n'
  bad_case unknown-format $'{\n  "format": "1",\n  "a": "1"\n}\n'
  bad_case no-format $'{\n  "a": "1"\n}\n'
  bad_case trailing-comma $'{\n  "format": "2",\n  "a": "1",\n}\n'
  bad_case missing-comma $'{\n  "format": "2"\n  "a": "1"\n}\n'
  bad_case nested $'{\n  "format": "2",\n  "a": {"b": "1"}\n}\n'
  bad_case number $'{\n  "format": "2",\n  "a": 1\n}\n'
  bad_case uppercase-key $'{\n  "format": "2",\n  "A": "1"\n}\n'
  bad_case control-char $'{\n  "format": "2",\n  "a": "x\ty"\n}\n'
  bad_case empty ''
}

@test "the reported line number points at the bad line" {
  printf '{\n  "format": "2",\n  "a": "1",\n  "b": "x"y",\n  "c": "3"\n}\n' >"$F"
  run cx_state_load "$F"
  [ "$status" -eq 5 ]
  [[ "$output" == *":4"* ]] || [[ "$output" == *" 4"* ]]
}

@test "write produces valid JSON with string values only, and keeps the previous file as .prev" {
  good
  cx_state_load "$F"
  cx_state_set current.version 1.13.2
  cx_state_set install.result succeeded
  cx_state_set current.image_ids "backend=sha256:aa frontend=sha256:bb"
  cx_state_save "$F"
  jq -e 'type == "object" and ([.[] | type] | all(. == "string"))' "$F"
  [ "$(jq -r '."current.version"' "$F")" = "1.13.2" ]
  [ "$(jq -r '."current.version"' "$F.prev")" = "1.13.0" ]
  cx_state_load "$F"
  [ "$(cx_state_get install.result)" = "succeeded" ]
}

@test "setting a value with a forbidden character is a program error, the file is untouched" {
  good
  cp "$F" "$D/orig"
  cx_state_load "$F"
  for v in 'a"b' 'a\b' $'a\nb' $'a\tb' 'é'; do
    run cx_state_set some.key "$v"
    [ "$status" -ne 0 ] || { echo "accepted: $v"; return 1; }
  done
  run cx_state_set Bad-Key x
  [ "$status" -ne 0 ]
  cmp "$F" "$D/orig"
}

@test "killing the writer at random moments leaves either the whole old or the whole new file" {
  good
  big=$(head -c 3000 /dev/zero | tr '\0' 'x')
  cat >"$D/writer.sh" <<W
. "$SRC/lib/common.sh"; cx_load_libs "$SRC"
cx_state_load "$F"
i=0
while :; do i=\$((i+1)); for k in \$(seq 1 40); do cx_state_set "k\$k.v" "\$i-$big"; done; cx_state_save "$F"; done
W
  for n in $(seq 1 15); do
    bash "$D/writer.sh" & pid=$!
    sleep "0.0$((RANDOM % 9 + 1))"
    kill -9 "$pid"; wait "$pid" 2>/dev/null || true
    run cx_state_load "$F"
    [ "$status" -eq 0 ] || { echo "round $n: $output"; return 1; }
    jq -e . "$F" >/dev/null
  done
}

# ---- run control: lock, confirmation without a terminal, interruption ----

run_script() { # <file> <body>: a small program using the libraries on a deployment root
  cat >"$1" <<W
set -euo pipefail
. "$SRC/lib/common.sh"; cx_load_libs "$SRC"
CX_ROOT=$ROOT
$2
W
}

@test "two state-changing runs at once: the second is refused with exit code 3" {
  ROOT=$D/root; make_root "$ROOT"
  run_script "$D/a.sh" 'cx_begin load; sleep 4; cx_finish succeeded'
  run_script "$D/b.sh" 'cx_begin load; cx_finish succeeded'
  bash "$D/a.sh" & pa=$!
  for _ in $(seq 1 50); do [ -s "$ROOT/.custodexa.lock" ] && break; sleep 0.1; done
  run bash "$D/b.sh"
  wait "$pa"
  [ "$status" -eq 3 ]
  [[ "$output" == *"$pa"* ]]
}

@test "a confirmation without a terminal and without --yes stops at once with exit code 3" {
  ROOT=$D/root; make_root "$ROOT"
  run_script "$D/c.sh" 'cx_confirm run_install_rerun; echo confirmed'
  run timeout 5 bash "$D/c.sh" </dev/null
  [ "$status" -eq 3 ]
  [[ "$output" != *confirmed* ]]
  run_script "$D/c2.sh" 'CX_YES=1; cx_confirm run_install_rerun; echo confirmed'
  run timeout 5 bash "$D/c2.sh" </dev/null
  [ "$status" -eq 0 ]
  [[ "$output" == *confirmed* ]]
}

@test "SIGINT leaves in_progress with the step, and the next run prints the recovery command" {
  ROOT=$D/root; make_root "$ROOT"
  run_script "$D/i.sh" 'cx_begin backup; cx_step 2; sleep 30; cx_finish succeeded'
  # Ctrl-C reaches the whole foreground process group. Job control (set -m) gives the run its
  # own group; without it bash starts background jobs with SIGINT ignored.
  set -m
  bash "$D/i.sh" >"$D/i.out" 2>&1 & pi=$!
  set +m
  for _ in $(seq 1 50); do grep -q '"last_backup.step": "2"' "$ROOT/state.json" 2>/dev/null && break; sleep 0.1; done
  kill -INT -- "-$pi"; rc=0; wait "$pi" || rc=$?
  cat "$D/i.out"
  [ "$rc" -eq 1 ]
  grep -q '"last_backup.result": "in_progress"' "$ROOT/state.json"
  grep -q '"last_backup.step": "2"' "$ROOT/state.json"
  run_script "$D/j.sh" 'cx_begin backup; echo started'
  run bash "$D/j.sh"
  [ "$status" -eq 3 ]
  [[ "$output" == *"custodexa.sh status"* ]]
  [[ "$output" != *started* ]]
}

@test "an interrupted install does not block install: it starts over" {
  ROOT=$D/root; make_root "$ROOT"
  printf '{\n  "format": "2",\n  "install.result": "in_progress",\n  "install.step": "3"\n}\n' >"$ROOT/state.json"
  run_script "$D/k.sh" 'cx_begin install; echo started; cx_finish succeeded'
  run bash "$D/k.sh"
  [ "$status" -eq 0 ]
  [[ "$output" == *started* ]]
  grep -q '"install.result": "succeeded"' "$ROOT/state.json"
}

@test "an interrupted load blocks nothing: Ctrl-C names the load to repeat, load and install go on" {
  ROOT=$D/root; make_root "$ROOT"
  run_script "$D/l.sh" 'cx_begin load; cx_state_set load.bundle /media/usb/b.tar; cx_step 4; sleep 30; cx_finish succeeded'
  set -m
  bash "$D/l.sh" >"$D/l.out" 2>&1 & pl=$!
  set +m
  for _ in $(seq 1 50); do grep -q '"load.step": "4"' "$ROOT/state.json" 2>/dev/null && break; sleep 0.1; done
  kill -INT -- "-$pl"; rc=0; wait "$pl" || rc=$?
  [ "$rc" -eq 1 ] && grep -q "custodexa.sh load /media/usb/b.tar" "$D/l.out" || { cat "$D/l.out"; return 1; }
  grep -q '"load.result": "in_progress"' "$ROOT/state.json" || return 1
  cp "$ROOT/state.json" "$D/interrupted.json"
  for c in load install; do
    cp "$D/interrupted.json" "$ROOT/state.json"
    run_script "$D/m.sh" "cx_begin $c; echo started; cx_finish succeeded"
    run bash "$D/m.sh"
    [ "$status" -eq 0 ] && [[ $output == *started* ]] || { echo "[$c] $output"; return 1; }
  done
  # Another command's interrupted run still comes first, and the command shown is the one that
  # finishes that run, not the one just refused.
  printf '{\n  "format": "2",\n  "install.result": "in_progress",\n  "install.step": "5"\n}\n' >"$ROOT/state.json"
  run_script "$D/n.sh" 'cx_begin load; echo started'
  run bash "$D/n.sh"
  [ "$status" -eq 3 ] && [[ $output == *"custodexa.sh install"* && $output != *started* ]] || { echo "$output"; return 1; }
}

# ---- run log and secrets: .env values never reach logs/ or state.json ----

secret_env() { # <file>: an .env holding known secrets in the shapes people write them
  cat >"$1" <<'ENV'
JWT_SECRET=jwt-7Qe2VbN9xLr4TzP1sW8k
DB_PASSWORD="db-Hn3Kq8Zr2Lw5Xc9V"
ADMIN_INITIAL_PASSWORD='adm-Xk82mQ0pLr7sWv3n'
export ENCRYPTION_KEY=kek-Zm9vYmFyYmF6cXV4MTIzNDU2
OFFSITE_S3_SECRET_ACCESS_KEY=s3-Ab12Cd34Ef56Gh78
LDAP_BIND_PASSWORD=ldap-Pw4Uu7Ii0Oo3
KEK_PROVIDER=ui
DATA_PATH=/opt/custodexa/data
ENV
}
SECRETS="jwt-7Qe2VbN9xLr4TzP1sW8k db-Hn3Kq8Zr2Lw5Xc9V adm-Xk82mQ0pLr7sWv3n kek-Zm9vYmFyYmF6cXV4MTIzNDU2 s3-Ab12Cd34Ef56Gh78 ldap-Pw4Uu7Ii0Oo3"

@test "secrets from .env appear in neither logs/ nor state.json, even when a command prints them" {
  ROOT=$D/root; make_root "$ROOT"
  secret_env "$ROOT/.env"
  # A docker that prints the settings back, the way `compose config` shows resolved values.
  mkdir -p "$D/bin"
  printf '#!/bin/sh\necho "  JWT_SECRET: jwt-7Qe2VbN9xLr4TzP1sW8k"\necho "  POSTGRES_PASSWORD: db-Hn3Kq8Zr2Lw5Xc9V" >&2\necho "  KEY: kek-Zm9vYmFyYmF6cXV4MTIzNDU2 s3-Ab12Cd34Ef56Gh78 ldap-Pw4Uu7Ii0Oo3 adm-Xk82mQ0pLr7sWv3n"\n' >"$D/bin/docker"
  chmod +x "$D/bin/docker"
  run_script "$D/s.sh" '
PATH='"$D/bin"':$PATH
CX_FLAGS_TEXT=" --yes --lang zh-TW"
cx_begin install
cx_step 1 7 preflight
cx_log_run cx_compose config >/dev/null
cx_log WARN "a careless message with adm-Xk82mQ0pLr7sWv3n in it"
if cx_state_set current.note "x-adm-Xk82mQ0pLr7sWv3n"; then echo "STORED A SECRET"; fi
cx_state_set current.version 1.13.0
cx_finish succeeded'
  run bash "$D/s.sh"
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [[ $output != *"STORED A SECRET"* ]]
  log=$(ls "$ROOT"/logs/install-*.log)
  cat "$log"
  for s in $SECRETS; do
    ! grep -rF -- "$s" "$ROOT/logs" "$ROOT/state.json" "$ROOT/state.json.prev" || { echo "leaked: $s"; return 1; }
  done
  # The output did reach the log, masked by key name (a missing OUT line would also pass the check above).
  grep -q 'OUT   .*JWT_SECRET: <JWT_SECRET>' "$log"
  grep -q 'OUT   .*POSTGRES_PASSWORD: <DB_PASSWORD>' "$log"
  grep -q 'a careless message with <ADMIN_INITIAL_PASSWORD> in it' "$log"
  # Paths and modes stay readable: only secret-named keys are masked.
  if grep -q '<DATA_PATH>\|<KEK_PROVIDER>' "$log"; then echo "a readable key was masked"; return 1; fi
}

@test "a whole install with secrets in .env: none of them in logs/ or state.json, even printed back" {
  ROOT=/opt/custodexa
  rm -rf "$ROOT"
  make_root "$ROOT"
  use_fake_docker
  host_full
  secret_env "$ROOT/.env"
  touch "$SIM/echo-env" # compose up prints every setting it read, on stdout and stderr
  run bash "$ROOT/custodexa.sh" install --lang zh-TW --yes </dev/null
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [ "$(jq -r '."install.result"' "$ROOT/state.json")" = succeeded ] || return 1
  log=$(ls "$ROOT"/logs/install-*.log)
  for s in $SECRETS; do
    ! grep -rF -- "$s" "$ROOT/logs" "$ROOT/state.json" "$ROOT/state.json.prev" || { echo "leaked: $s"; return 1; }
  done
  # The printed settings did reach the log, masked by key name.
  grep -q 'OUT   JWT_SECRET=<JWT_SECRET>$' "$log" || { cat "$log"; return 1; }
  grep -q 'OUT   warn DB_PASSWORD="<DB_PASSWORD>"$' "$log" || { cat "$log"; return 1; }
  grep -q "OUT   ADMIN_INITIAL_PASSWORD='<ADMIN_INITIAL_PASSWORD>'\$" "$log" || return 1
  # The values set before install are kept, not replaced by generated ones.
  [ "$(sed -n 's/^JWT_SECRET=//p' "$ROOT/.env")" = jwt-7Qe2VbN9xLr4TzP1sW8k ] || return 1
}

@test "secrets the install generates are masked in the log from the moment they exist" {
  ROOT=/opt/custodexa
  rm -rf "$ROOT"
  make_root "$ROOT"
  use_fake_docker
  host_full
  touch "$SIM/echo-env"
  run bash "$ROOT/custodexa.sh" install --lang en --yes </dev/null
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  local k v n=0
  for k in JWT_SECRET DB_PASSWORD ADMIN_INITIAL_PASSWORD; do
    v=$(sed -n "s/^$k=//p" "$ROOT/.env")
    [ "${#v}" -ge 16 ] || { echo "$k not generated"; return 1; }
    ! grep -rF -- "$v" "$ROOT/logs" "$ROOT/state.json" "$ROOT/state.json.prev" || { echo "leaked: $k"; return 1; }
    grep -q "OUT   $k=<$k>\$" "$ROOT"/logs/install-*.log || { echo "$k never reached the log"; return 1; }
    n=$((n + 1))
  done
  [ "$n" -eq 3 ]
}

# Every key of the shipped settings template, commented ones included, with a distinct value each.
# Masking is the default: whatever is not on the reviewed list must stay out of logs/ and state.json.
REPO=${CX_TEST_REPO:-/src}
template_keys() { grep -oE '^(# ?)?[A-Z][A-Z0-9_]*=' "$REPO/.env.example" | sed -E 's/^# ?//; s/=$//' | sort -u; }

# Keys of the template whose values are secrets. They must never be on the list of shown keys.
KNOWN_SECRETS="ADMIN_INITIAL_PASSWORD DB_PASSWORD ENCRYPTION_KEY JWT_SECRET KEK_HSM_PIN LDAP_BIND_PASSWORD
  METRICS_TOKEN OFFSITE_S3_ACCESS_KEY_ID OFFSITE_S3_SECRET_ACCESS_KEY VAULT_DEV_ROOT_TOKEN_ID"

@test "the list of readable .env keys holds no secret: no known secret, no secret-looking name" {
  for k in $KNOWN_SECRETS; do
    template_keys | grep -qx "$k" || { echo "$k is no longer in .env.example; update this test"; return 1; }
    ! cx_env_value_shown "$k" || { echo "secret key shown in logs: $k"; return 1; }
  done
  for k in $CX_ENV_SHOWN; do
    [[ ! $k =~ PASSWORD|SECRET|TOKEN|CREDENTIAL|PIN|_KEY$|_KEY_ID$|ENCRYPTION|_DN$ ]] || { echo "secret-looking key shown: $k"; return 1; }
  done
}

@test "every .env.example value outside the readable list stays out of logs/ and state.json" {
  ROOT=$D/root; make_root "$ROOT"
  n=0
  : >"$ROOT/.env"
  # Plus a key the template does not have yet, named like an ordinary setting: a key someone adds
  # later must be masked without anyone remembering to list it.
  for k in $(template_keys) COMPOSE_PROJECT_NAME SETTING_ADDED_LATER; do
    n=$((n + 1))
    printf '%s=fx%03d-%s-v\n' "$k" "$n" "$(printf '%s' "$k" | cksum | cut -c1-6)" >>"$ROOT/.env"
  done
  [ "$n" -gt 60 ] || { echo "only $n keys read from .env.example"; return 1; }
  # A docker that prints every setting back on stdout and stderr, as `compose config` would.
  mkdir -p "$D/bin"
  printf '#!/bin/sh\nsed "s/=/: /" "%s"\nsed "s/^/err /" "%s" >&2\n' "$ROOT/.env" "$ROOT/.env" >"$D/bin/docker"
  chmod +x "$D/bin/docker"
  run_script "$D/t.sh" '
PATH='"$D/bin"':$PATH
cx_begin install
cx_log_run cx_compose config >/dev/null
while IFS== read -r k v; do
  cx_log WARN "value of $k is $v"
  cx_state_set "probe.${k,,}" "$v" 2>/dev/null || true
done <'"$ROOT/.env"'
cx_state_save "$CX_ROOT/state.json"
cx_finish succeeded'
  run bash "$D/t.sh"
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  masked=0 shown=0
  while IFS== read -r k v; do
    if [ "$k" != SETTING_ADDED_LATER ] && cx_env_value_shown "$k"; then
      shown=$((shown + 1))
      grep -qF -- "$v" "$ROOT"/logs/install-*.log || { echo "readable key $k did not reach the log"; return 1; }
    else
      masked=$((masked + 1))
      ! grep -rF -- "$v" "$ROOT/logs" "$ROOT/state.json" "$ROOT/state.json.prev" || { echo "leaked: $k"; return 1; }
      grep -qF -- "<$k>" "$ROOT"/logs/install-*.log || { echo "masked key $k never reached the log"; return 1; }
    fi
  done <"$ROOT/.env"
  if cx_env_value_shown SETTING_ADDED_LATER; then echo "a key nobody listed is shown"; return 1; fi
  echo "masked $masked, shown $shown"
  [ "$masked" -gt 0 ] && [ "$shown" -gt 0 ] || return 1
}

@test "the log has one event per line: ISO time, BEGIN with flags, STEP, CMD, END; private modes" {
  ROOT=$D/root; make_root "$ROOT"
  use_fake_docker
  run_script "$D/l.sh" '
CX_FLAGS_TEXT=" --yes"
cx_begin install
cx_step 3 7 images
cx_compose up -d
cx_finish failed'
  run bash "$D/l.sh"
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  log=$(ls "$ROOT"/logs/install-*.log)
  [[ ${log##*/} =~ ^install-[0-9]{8}-[0-9]{6}\.log$ ]]
  ts='^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[+-][0-9]{2}:[0-9]{2} '
  grep -Eq "${ts}BEGIN install lang=[a-zA-Z-]+ script=[^ ]* flags=\"--yes\"$" "$log"
  grep -Eq "${ts}STEP  3/7 images$" "$log"
  grep -Eq "${ts}CMD   docker compose -p custodexa --project-directory $ROOT -f $ROOT/current/compose.yml up -d$" "$log"
  grep -Eq "${ts}END   result=failed step=3$" "$log"
  [ "$(wc -l <"$log")" -eq 4 ]
  grep -q "\"install.log\": \"logs/${log##*/}\"" "$ROOT/state.json"
  [ "$(stat -c %a "$ROOT/logs")" = 700 ]
  [ "$(stat -c %a "$log")" = 600 ]
}

@test "tracing stays off: no set -x in the code, and bash -x does not trace past the first lines" {
  run grep -nE 'set -[a-wyz]*x|set -o xtrace|BASH_XTRACEFD' "$SRC/custodexa.sh" "$SRC"/lib/*.sh
  [ "$status" -eq 1 ] || { echo "$output"; return 1; }
  ROOT=$D/root; make_root "$ROOT"
  run bash -x "$ROOT/custodexa.sh" --version
  [ "$status" -eq 0 ]
  [[ $output != *"cx_parse_args"* ]] || { echo "$output"; return 1; }
}

@test "SIGINT while a step's command runs with its output redirected: the recovery message still reaches the terminal" {
  ROOT=$D/root; make_root "$ROOT"
  # install step 5 runs `cx_log_run cx_compose up ... >/dev/null 2>&1`; the trap runs inside that redirection.
  run_script "$D/r.sh" 'cx_begin load; cx_step 2; { sleep 30; } >/dev/null 2>&1; cx_finish succeeded'
  set -m
  bash "$D/r.sh" >"$D/r.out" 2>&1 & pi=$!
  set +m
  for _ in $(seq 1 50); do grep -q '"load.step": "2"' "$ROOT/state.json" 2>/dev/null && break; sleep 0.1; done
  kill -INT -- "-$pi"; rc=0; wait "$pi" || rc=$?
  cat "$D/r.out"
  [ "$rc" -eq 1 ]
  grep -q 'Interrupted at step 2' "$D/r.out"
  grep -q 'custodexa.sh' "$D/r.out"
}
