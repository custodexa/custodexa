#!/usr/bin/env bats
load helper

setup() {
  ROOT=$BATS_TEST_TMPDIR/opt/custodexa
  make_root "$ROOT"
  printf '{\n  "format": "2",\n  "current.version": "1.13.0",\n  "current.kind": "package",\n  "current.overlays": "external-ingress"\n}\n' >"$ROOT/state.json"
  use_fake_docker
  export SVC_SIM=$BATS_TEST_TMPDIR/service
  mkdir -p "$SVC_SIM"
  printf 'running\n' >"$SVC_SIM/state"
  printf '0\n' >"$SVC_SIM/queue"
  cat >"$FAKE_DOCKER_REPLAY/hook" <<'HOOK'
#!/bin/bash
args=" $* "
case $args in
  *' ps --all --services '*) printf 'postgres\nguacd\nbackend\nfrontend\ntls-proxy\n'; exit 0 ;;
  *' ps --status running --services '*)
    [ "$(cat "$SVC_SIM/state")" != running ] || printf 'postgres\nguacd\nbackend\nfrontend\ntls-proxy\n'
    exit 0 ;;
  *' stop '*) printf 'stopped\n' >"$SVC_SIM/state"; exit 0 ;;
  *' up -d --remove-orphans '*) printf 'running\n' >"$SVC_SIM/state"; exit 0 ;;
  *' exec -T backend wget -qO- http://localhost:8080/health '*)
    [ ! -e "$SVC_SIM/unhealthy" ] || exit 1
    printf '{"version":"1.13.0"}\n'; exit 0 ;;
  *' container inspect --format {{.State.Running}} {{.State.FinishedAt}} custodexa-backend '*)
    [ "$(cat "$SVC_SIM/state")" != running ] || { printf 'true 0001-01-01T00:00:00Z\n'; exit 0; }
    printf 'false 2026-10-01T00:00:00Z\n'; exit 0 ;;
  *' exec custodexa-backend /bin/busybox sh -c '*'/metrics '* )
    [ ! -e "$SVC_SIM/unknown" ] || exit 1
    printf 'HTTP/1.1 200 OK\n' >&2
    printf 'custodexa_audit_queue_depth %s\n' "$(cat "$SVC_SIM/queue")"; exit 0 ;;
  *' exec custodexa-backend /bin/busybox sh -c '*'/api/v1/seal/status '* ) exit 1 ;;
esac
exit 99
HOOK
  chmod +x "$FAKE_DOCKER_REPLAY/hook"
}

svc_run() { run bash "$ROOT/custodexa.sh" "$@" --lang zh-TW </dev/null; }

@test "stop_warns_and_drains_before_compose_stop" {
  svc_run stop
  [ "$status" -eq 3 ] && [[ $output == *'現有使用者連線會中斷'* ]] || { echo "$output"; return 1; }
  ! grep -q $'\tcompose .* stop\tIMG_BACKEND=' "$FAKE_DOCKER_LOG"
  touch "$SVC_SIM/unknown"
  svc_run stop --yes
  [ "$status" -eq 1 ] && [[ $output == *'無法確認稽核佇列已排空；服務未停止。'* ]] || { echo "$output"; return 1; }
  ! grep -q $'\tcompose .* stop\tIMG_BACKEND=' "$FAKE_DOCKER_LOG"
  rm "$SVC_SIM/unknown"
  svc_run stop --yes
  [ "$status" -eq 0 ] && [[ $output == *'[ OK ] 稽核佇列已排空'* && $output == *'[ OK ] 服務已停止'* ]] || { echo "$output"; return 1; }
  grep -q $'\tcompose .* stop\tIMG_BACKEND=' "$FAKE_DOCKER_LOG"
}

@test "start_waits_for_backend_health" {
  printf 'stopped\n' >"$SVC_SIM/state"
  svc_run start
  [ "$status" -eq 0 ] && [[ $output == *'[ OK ] 後端已就緒'* ]] || { echo "$output"; return 1; }
  local up_line health_line
  up_line=$(grep -n $'\tcompose .* up -d --remove-orphans\tIMG_BACKEND=' "$FAKE_DOCKER_LOG" | head -1 | cut -d: -f1)
  health_line=$(grep -n 'exec -T backend wget -qO- http://localhost:8080/health' "$FAKE_DOCKER_LOG" | head -1 | cut -d: -f1)
  [ "$up_line" -lt "$health_line" ]
  touch "$SVC_SIM/unhealthy"
  printf 'stopped\n' >"$SVC_SIM/state"
  # Shorten only the test poll by replacing sleep and the shared limit in the copied release.
  sed -i 's/CX_UP_READY_TRIES=60 CX_UP_READY_WAIT=3/CX_UP_READY_TRIES=2 CX_UP_READY_WAIT=0/' "$ROOT/current/lib/health.sh"
  svc_run start
  [ "$status" -eq 1 ] && [[ $output == *'後端未在 180 秒內就緒'* ]] || { echo "$output"; return 1; }
  [ "$(cat "$SVC_SIM/state")" = running ]
  ! grep -q $'\tcompose .* stop\tIMG_BACKEND=' "$FAKE_DOCKER_LOG"
}

@test "start_stop_are_idempotent_and_use_current_overlays" {
  local before
  before=$(cat "$ROOT/state.json")
  svc_run start --yes
  [ "$status" -eq 2 ] || { echo "$output"; return 1; }
  svc_run start
  [ "$status" -eq 0 ] && [[ $output == *'服務已在執行，後端已就緒。'* ]] || { echo "$output"; return 1; }
  ! grep -q $'\tcompose .* up -d ' "$FAKE_DOCKER_LOG"
  ! grep -q $'\tcompose .* stop\tIMG_BACKEND=' "$FAKE_DOCKER_LOG"
  svc_run stop --yes
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  : >"$FAKE_DOCKER_LOG"
  svc_run stop --yes
  [ "$status" -eq 0 ] && [[ $output == *'服務已停止，無需重複停止。'* ]] || { echo "$output"; return 1; }
  ! grep -q $'\tcompose .* stop\tIMG_BACKEND=' "$FAKE_DOCKER_LOG"
  svc_run start
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  grep -qF -- "-p custodexa --project-directory $ROOT -f $ROOT/current/compose.yml -f $ROOT/current/compose.external-ingress.yml up -d --remove-orphans" "$FAKE_DOCKER_LOG"
  ! grep -q ' stop backend\| start backend' "$FAKE_DOCKER_LOG"
  [ "$(cat "$ROOT/state.json")" = "$before" ]
  sed -i 's/external-ingress/unknown-overlay/' "$ROOT/state.json"
  : >"$FAKE_DOCKER_LOG"
  svc_run stop --yes
  [ "$status" -eq 3 ] || { echo "$output"; return 1; }
  [ ! -s "$FAKE_DOCKER_LOG" ]
}
