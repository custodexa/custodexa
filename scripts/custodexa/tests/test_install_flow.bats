#!/usr/bin/env bats
# Threat (A): install acting on a host it should not touch, or telling people the wrong next step.
# The host checks run before anything is written; a failure must name the cause with the numbers
# behind it, leave the host as it was, and never install over an existing deployment.

load helper
load release_fixture
load install_host

ROOT=/opt/custodexa

setup() {
  rm -rf "$ROOT"
  make_root "$ROOT"
  use_fake_docker
  host_base
  manifest >"$ROOT/current/MANIFEST.json"
  docker_rc container_inspect 1
}

# A release manifest whose amd64 images add up to 1.2 GiB compressed: 3.6 GiB unpacked + 2 GiB = 6 GB.
manifest() {
  cat <<'M'
{
  "format": 1,
  "version": "1.13.0",
  "images": {
    "backend": {
      "ref": "ghcr.io/custodexa/backend",
      "platforms": {
        "amd64": {
          "config_digest": "sha256:aa",
          "size": 644245094
        }
      }
    },
    "frontend": {
      "ref": "ghcr.io/custodexa/frontend",
      "platforms": {
        "amd64": {
          "config_digest": "sha256:bb",
          "size": 644245094
        }
      }
    }
  },
  "rollback_compatible": []
}
M
}

# The host checks as `custodexa.sh install` runs them; they fail before step 2 in these tests.
step1() { install_run "${1:-zh-TW}"; }

files_untouched() {
  [ ! -e "$ROOT/.env" ] && [ ! -e "$ROOT/state.json" ] && [ ! -e "$ROOT/logs" ] && [ ! -e "$ROOT/.custodexa.lock" ]
}

@test "a port in use: the screen names who holds it and what to do, word for word, nothing written" {
  port_holder 443 'users:(("nginx",pid=1203,fd=6))'
  for l in zh-TW en; do
    step1 "$l"
    [ "$status" -eq 1 ] || { echo "$output"; return 1; }
    diff <(printf '%s\n' "$output") "$TESTS_DIR/snapshots/s02.$l.txt" || { echo "[$l] differs from the reviewed screen"; return 1; }
  done
  files_untouched
}

@test "all checks passing: step 1 is one line, no check listed under it" {
  step1 en
  [ "${lines[0]}" = "Custodexa 1.13.0 install    Deployment directory $ROOT" ] || { echo "$output"; return 1; }
  [[ ${lines[1]} == "[ OK ] 1/7  Check this host "*s ]] || { echo "$output"; return 1; }
  [[ ${lines[2]} == "[FAIL] 2/7  "* ]] || { echo "$output"; return 1; } # this host has no .env template
}

@test "too little disk space prints both numbers; one file system for Docker and the folder needs the sum" {
  host_free /var/lib/docker 3145728 # 3 GiB
  step1 en
  [ "$status" -eq 1 ]
  [[ $output == *"[FAIL] 3 GB free (6 GB needed)"* ]] || { echo "$output"; return 1; }
  # Docker's data folder on the root file system: 2 + 3.6 + 5 GiB.
  docker_says 'info_--format_{{.ServerVersion}}-{{.DockerRootDir}}' '27.3.1 /srv/docker'
  host_free / 3145728
  step1 en
  [[ $output == *"[FAIL] 3 GB free (11 GB needed)"* ]] || { echo "$output"; return 1; }
  files_untouched
}

@test "an existing deployment is refused with exit code 3 and pointed to status and upgrade" {
  printf '{\n  "format": "2",\n  "current.version": "1.13.0"\n}\n' >"$ROOT/state.json"
  step1 en
  [ "$status" -eq 3 ] || { echo "$output"; return 1; }
  [[ $output == *"Custodexa 1.13.0 is already installed"* ]]
  [[ $output == *"    sudo $ROOT/custodexa.sh status"* && $output == *"    sudo $ROOT/custodexa.sh upgrade"* ]]
  rm "$ROOT/state.json"
  mkdir "$ROOT/.git"
  step1 en
  [ "$status" -eq 3 ] && [[ $output == *"git clone deployment"* ]] || return 1
  rmdir "$ROOT/.git"
  # A custodexa-backend container of another folder.
  rm "$FAKE_DOCKER_REPLAY/container_inspect.rc"
  docker_says container_inspect '{"com.docker.compose.project":"custodexa","com.docker.compose.project.working_dir":"/srv/other"}'
  step1 en
  [ "$status" -eq 3 ] && [[ $output == *"custodexa-backend container exists"* ]] || return 1
}

@test "the container of this folder's own unfinished install is not an existing deployment" {
  printf '{\n  "format": "2",\n  "install.result": "failed",\n  "install.step": "6"\n}\n' >"$ROOT/state.json"
  rm "$FAKE_DOCKER_REPLAY/container_inspect.rc"
  docker_says container_inspect '{"com.docker.compose.project":"custodexa","com.docker.compose.project.working_dir":"/opt/custodexa"}'
  step1 en
  [[ $output == *"[ OK ] 1/7  Check this host"* ]] || { echo "$output"; return 1; }
  # The same container without any install record in this folder is somebody else's deployment.
  rm "$ROOT/state.json"
  step1 en
  [ "$status" -eq 3 ] || { echo "$output"; return 1; }
}

@test "no permission on the Docker socket: say so and suggest sudo or the docker group" {
  docker_rc info 1
  docker_says info 'permission denied while trying to connect to the Docker daemon socket'
  fake docker 'echo "permission denied while trying to connect to the Docker daemon socket" >&2; exit 1'
  step1 en
  [ "$status" -eq 1 ]
  [[ $output == *"[FAIL] No permission to use Docker"* && $output == *"add this account to the docker group"* ]] || { echo "$output"; return 1; }
}

@test "old Compose, unsupported architecture, busy http port, unknown listener tools" {
  docker_says compose_version_--short '1.29.2'
  host_arch s390x
  port_holder 80 'users:(("docker-proxy",pid=77,fd=4))'
  docker_says ps_--filter_publish=80 'web-1'
  step1 en
  [ "$status" -eq 1 ]
  [[ $output == *"[FAIL] Docker 27.3.1, Compose v1.29.2 is too old"* ]] || { echo "$output"; return 1; }
  [[ $output == *"[FAIL] Architecture s390x is not supported"* ]]
  [[ $output == *"Port 80 is already in use by docker-proxy (pid 77), publishing it for container web-1"* ]]
  rm "$FAKES/ss"
  step1 en
  [[ $output == *"[WARN] Neither ss nor lsof is installed; ports 443, 80 not checked"* ]] || { echo "$output"; return 1; }
}

# ---- the whole install on a simulated daemon ----

# The screen as reviewed: step 3 shows only its closing line (its body is the image screen, checked
# on its own), and the generated password is a placeholder.
s01_view() {
  awk '/^\[ \.\. \] 3\/7/ { skip = 1; next } skip && /^\[/ { skip = 0 } !skip' |
    sed -E 's/^(   (密碼|Password) +)[A-Za-z0-9]{20}$/\1<password>/'
}
state() { jq -r --arg k "$1" '.[$k] // ""' "$ROOT/state.json"; }

@test "a whole install: the reviewed screen word for word, and the deployment recorded" {
  host_full
  for l in zh-TW en; do
    fresh_host
    : >"$SIM/images"
    clock 0 2 0 48 0 9 0 21
    install_run "$l"
    [ "$status" -eq 0 ] || { echo "$output"; return 1; }
    diff <(printf '%s\n' "$output" | s01_view) <(s01_view <"$TESTS_DIR/snapshots/s01.$l.txt") ||
      { echo "[$l] differs from the reviewed screen"; return 1; }
  done
  # The password on the screen is the one in .env; it is shown there and nowhere else.
  pw=$(sed -n 's/^   Password  //p' <<<"$output")
  [ "${#pw}" -eq 20 ] && [ "$pw" = "$(sed -n 's/^ADMIN_INITIAL_PASSWORD=//p' "$ROOT/.env")" ] || { echo "password [$pw]"; return 1; }
  ! grep -rqF -- "$pw" "$ROOT/logs" "$ROOT/state.json" || { echo "password leaked"; return 1; }
  grep -q ' ENV   ADMIN_INITIAL_PASSWORD generated (value not recorded)$' "$ROOT"/logs/install-*.log || return 1
  # What status, upgrade and rollback read later.
  [ "$(state install.result)" = succeeded ] && [ "$(state current.version)" = 1.13.0 ] || return 1
  [ "$(state current.kind)" = package ] && [ "$(state current.release_dir)" = releases/1.13.0 ] || return 1
  [ "$(state current.images_env)" = releases/1.13.0/images.env ] && [ "$(state home)" = "$ROOT" ] || return 1
  [ "$(state current.verification)" = "checksum=ok signature=ok provenance=ok" ] || return 1
  for n in $NAMES; do
    [[ " $(state current.image_ids) " == *" $n=${CFG[$n]} "* ]] || { echo "$n: $(state current.image_ids)"; return 1; }
  done
  [[ " $(state current.image_source) " == *" backend=ghcr.io "* && " $(state current.image_source) " == *" postgres=docker.io "* ]] || return 1
  # Started once, by the script, with the checked references and the fixed project.
  grep -q $'\tcompose -p custodexa --project-directory /opt/custodexa -f /opt/custodexa/current/compose.yml up -d --remove-orphans\tIMG_BACKEND=ghcr.io/custodexa/backend@'"${IDX[backend]}" "$FAKE_DOCKER_LOG" || return 1
  grep -q $'\trun --rm --pull never --network none --user 0:0 -v /opt/custodexa/data/recordings:/r ' "$FAKE_DOCKER_LOG" || return 1
  [ "$(stat -c %a "$ROOT/.env")" = 600 ]
}

@test "a container running another image stops the install at step 5; running install again finishes it" {
  host_full
  touch "$SIM/up-swap"
  install_run en
  [ "$status" -eq 1 ] || { echo "$output"; return 1; }
  [[ $output == *"[FAIL] 5/7  Start the services (running the images just"* ]] || { echo "$output"; return 1; }
  [[ $output == *"[FAIL] custodexa-backend runs image sha256:0bad"* ]] || { echo "$output"; return 1; }
  [[ $output == *"Install stopped at step 5"* && $output == *"    sudo $ROOT/custodexa.sh install"* ]] || { echo "$output"; return 1; }
  [ "$(state install.result)" = failed ] && [ "$(state install.step)" = 5 ] && [ -z "$(state current.version)" ] || return 1
  # Again, with the services of the first run still up and publishing 443 and 80: the ports are
  # this deployment's own, .env stays as it is, and the images already here are not fetched again.
  rm "$SIM/up-swap"
  cp "$ROOT/.env" "$BATS_TEST_TMPDIR/env.first"
  port_holder 443 'users:(("docker-proxy",pid=301,fd=4))'
  port_holder 80 'users:(("docker-proxy",pid=302,fd=4))'
  : >"$FAKE_DOCKER_LOG"
  install_run en
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  cmp "$ROOT/.env" "$BATS_TEST_TMPDIR/env.first" || return 1
  ! grep -q $'\tpull ' "$FAKE_DOCKER_LOG" || return 1
  [[ $output == *"Nothing generated; the values already in .env are kept"* ]] || { echo "$output"; return 1; }
  [[ $output == *"Password  the ADMIN_INITIAL_PASSWORD value in $ROOT/.env"* ]] || { echo "$output"; return 1; }
  [ "$(state install.result)" = succeeded ] && [ "$(state current.version)" = 1.13.0 ] || return 1
  # With this folder's install unfinished, the same ports held by another folder's services are
  # still a conflict.
  fresh_host
  printf '{\n  "format": "2",\n  "install.result": "failed",\n  "install.step": "5"\n}\n' >"$ROOT/state.json"
  printf '443 web-1\n' >"$SIM/published"
  printf '/srv/other' >"$SIM/workdir"
  install_run en
  [ "$status" -eq 1 ] && [[ $output == *"[FAIL] Port 443 is already in use by docker-proxy (pid 301)"* ]] || { echo "$output"; return 1; }
}

@test "recordings folder not as required, not ready in time, another version answering: each stops" {
  host_full
  echo "0:0 755" >"$SIM/run-mode"
  install_run en
  [ "$status" -eq 1 ] || { echo "$output"; return 1; }
  [[ $output == *"[FAIL] 4/7  Prepare the recordings folder"* && $output == *"[FAIL] $ROOT/data/recordings is 0:0 755, not 1000:0 2770"* ]] || { echo "$output"; return 1; }
  ! grep -q $'\tcompose .* up ' "$FAKE_DOCKER_LOG" || return 1
  rm "$SIM/run-mode"
  touch "$SIM/health-fails"
  install_run en
  [ "$status" -eq 1 ] || { echo "$output"; return 1; }
  [[ $output == *"[FAIL] 6/7  Wait until ready"* && $output == *"[FAIL] The backend did not report ready within 180 seconds"* ]] || { echo "$output"; return 1; }
  [[ $output == *"    cd $ROOT && sudo docker compose logs backend"* ]] || { echo "$output"; return 1; }
  [ "$(grep -c $'\tcompose .* exec -T backend wget' "$FAKE_DOCKER_LOG")" -eq 60 ] || return 1
  rm "$SIM/health-fails"
  echo 1.12.4 >"$SIM/health-version"
  install_run en
  [ "$status" -eq 1 ] && [[ $output == *"[FAIL] The backend reports version 1.12.4, not 1.13.0"* ]] || { echo "$output"; return 1; }
  [ -z "$(state current.version)" ] || return 1
}

@test "the closing block follows the master key mode and the certificate setting" {
  host_full
  sed -i 's/^KEK_PROVIDER=ui$/KEK_PROVIDER=env/' "$ROOT/current/.env.example"
  install_run en
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [[ $output == *" Installed. Sign in with your browser."* && $output == *"master key, database password"* ]] || { echo "$output"; return 1; }
  [[ $output == *" 1. Sign in with the account above."* && $output == *" 2. This site uses a certificate"* ]] || { echo "$output"; return 1; }
  [[ $output != *"master key setup page"* && $output != *" 3. "* ]] || { echo "$output"; return 1; }
  fresh_host
  sed -i 's/^KEK_PROVIDER=env$/KEK_PROVIDER=kms/; s/^TLS_MODE=selfsigned$/TLS_MODE=provided/' "$ROOT/current/.env.example"
  install_run zh-TW
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [[ $output == *"主金鑰模式：外部金鑰保管服務（KMS）"* && $output == *" 1. 第一次開網址會進入解封頁。"* ]] || { echo "$output"; return 1; }
  [[ $output == *" 2. 用上面的帳號密碼登入。"* && $output != *"custodexa-ca.crt"* && $output != *" 3. "* ]] || { echo "$output"; return 1; }
}

@test "publisher not verified: no answer, no install; with --yes it goes on and says what was checked" {
  host_full
  no_publisher_tools
  install_run en
  [ "$status" -eq 3 ] || { echo "$output"; return 1; }
  [[ $output == *"[ ?? ] Files were checked for damage"* && $output == *"[FAIL] This step needs a confirmation"* ]] || { echo "$output"; return 1; }
  ! grep -q $'\tcompose .* up ' "$FAKE_DOCKER_LOG" || return 1
  [ "$(state install.result)" = cancelled ] || return 1
  # Asked on a terminal and answered N: stopped the same way.
  run script -qec "bash $ROOT/custodexa.sh install --lang en" /dev/null <<<"n"
  [ "$status" -eq 3 ] && [[ $output == *"Stopped as you chose; no service was started"* ]] || { echo "$output"; return 1; }
  ! grep -q $'\tcompose .* up ' "$FAKE_DOCKER_LOG" || return 1
  install_run en --yes
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [[ $output == *"[ OK ] 3/7  Get the program images (6; content digests checked;"* ]] || { echo "$output"; return 1; }
  [ "$(state current.verification)" = "checksum=ok signature=skip-no-cosign provenance=skip-no-gh" ] || return 1
}

# ---- load ----
load_run() { # <lang> <bundle>
  run bash "$ROOT/custodexa.sh" load "$2" --lang "$1" </dev/null
}
s18_view() { sed -E 's/（[0-9.]+ GB）$/（<size>）/; s/ \([0-9.]+ GB\)$/ (<size>)/'; }

@test "load: the reviewed screen word for word; checked, loaded, nothing started, IDs recorded" {
  host_full
  mkdir -p /media/usb
  local tar=/media/usb/custodexa-images-1.13.0-amd64.tar
  export FAKE_COSIGN_VERIFY=offline
  for s in classic containerd; do
    store "$s"
    make_bundle "$tar" "$s"
    for l in zh-TW en; do
      : >"$SIM/images"
      : >"$FAKE_DOCKER_LOG"
      clock 0 65
      load_run "$l" "$tar"
      [ "$status" -eq 0 ] || { echo "$output"; return 1; }
      diff <(printf '%s\n' "$output" | s18_view) <(s18_view <"$TESTS_DIR/snapshots/s18.$l.txt") ||
        { echo "[$s $l] differs from the reviewed screen"; return 1; }
    done
    grep -q $'\tload -q -i '"$tar" "$FAKE_DOCKER_LOG" || return 1
    ! grep -Eq $'\t(compose|start|run|pull) ' "$FAKE_DOCKER_LOG" || { cat "$FAKE_DOCKER_LOG"; return 1; }
    [ "$(state load.version)" = 1.13.0 ] && [ "$(state load.result)" = succeeded ] || return 1
    for n in $NAMES; do
      if [ "$s" = classic ]; then want=${CFG[$n]}; else
        want=sha256:$(tar -xOf "$tar" index.json | jq -r --arg r "${REF[$n]}:${TAG[$n]}" \
          '.manifests[] | select(.annotations["io.containerd.image.name"] == $r) | .digest' | cut -d: -f2)
      fi
      [[ " $(state load.image_ids) " == *" $n=$want "* ]] || { echo "[$s] $n: $(state load.image_ids)"; return 1; }
    done
  done
  [ -z "$(state current.version)" ] && [ "$(readlink "$ROOT/current")" = releases/1.13.0 ] || return 1
}

@test "load refuses another architecture, a damaged file and a bundle unlike the release; nothing loaded" {
  host_full
  mkdir -p /media/usb
  make_bundle /media/usb/custodexa-images-1.13.0-arm64.tar classic
  load_run en /media/usb/custodexa-images-1.13.0-arm64.tar
  [ "$status" -eq 1 ] && [[ $output == *"[FAIL] The bundle is for arm64, this host is amd64; use custodexa-images-1.13.0-amd64.tar."* ]] || { echo "$output"; return 1; }
  local tar=/media/usb/custodexa-images-1.13.0-amd64.tar
  make_bundle "$tar" classic
  printf 'x' >>"$tar"
  load_run en "$tar"
  [ "$status" -eq 1 ] && [[ $output == *"[FAIL] Checksum does not match SHA256SUMS"* ]] || { echo "$output"; return 1; }
  make_bundle "$tar" classic
  CFG[backend]=sha256:$(printf 'other config' | sha256sum | cut -d' ' -f1)
  release_manifest >"$ROOT/current/MANIFEST.json"
  load_run en "$tar"
  [ "$status" -eq 1 ] || { echo "$output"; return 1; }
  [[ $output == *"[FAIL] The bundle does not match the release manifest; nothing was loaded:"* ]] || { echo "$output"; return 1; }
  ! grep -q $'\tload ' "$FAKE_DOCKER_LOG" || return 1
  [ "$(state load.result)" = failed ] && [ -z "$(state load.image_ids)" ] || return 1
  # Loaded, but the daemon then holds other content under the tag: refused, no IDs recorded.
  fixture_release
  make_bundle "$tar" classic
  touch "$SIM/load-swap"
  load_run en "$tar"
  [ "$status" -eq 1 ] || { echo "$output"; return 1; }
  [[ $output == *"[FAIL] After loading, ghcr.io/custodexa/backend:1.13.0 does not have the image ID checked"* ]] || { echo "$output"; return 1; }
  [ "$(state load.result)" = failed ] && [ -z "$(state load.image_ids)" ] || return 1
}

@test "load with the release manifest next to the bundle: publisher shown verified only when SHA256SUMS is signed" {
  host_full
  mkdir -p /media/usb
  local tar=/media/usb/custodexa-images-1.13.0-amd64.tar flat sums
  local id=https://github.com/custodexa/custodexa/.github/workflows/release-images.yml@refs/tags/v1.13.0
  # This version's package is not unpacked here (loading ahead of an upgrade), so load takes the
  # manifest published next to the bundle. cosign and gh reach the registry and pass for the index
  # digests that manifest names; that says nothing about the loaded content unless the manifest
  # itself is the publisher's.
  rm "$ROOT/current/MANIFEST.json"
  make_bundle "$tar" classic
  release_manifest >/media/usb/MANIFEST.json
  (cd /media/usb && sha256sum MANIFEST.json >>SHA256SUMS)
  sums=$(sha256sum /media/usb/SHA256SUMS | cut -d' ' -f1)
  # Signed, but the signature does not verify for the release workflow of this version: a check
  # that ran and failed stops, as in install and upgrade; nothing loaded, no IDs recorded.
  printf 'identity %s\nsha256 %s\n' "${id/v1.13.0/v1.12.4}" "$sums" >/media/usb/SHA256SUMS.sigstore.json
  load_run en "$tar"
  flat=$(printf '%s' "$output" | tr '\n' ' ' | tr -s ' ')
  [ "$status" -eq 1 ] && [[ $flat == *"[FAIL] The signature over SHA256SUMS in /media/usb does not verify"* ]] || { echo "$output"; return 1; }
  [[ $output != *"verified"* ]] || { echo "$output"; return 1; }
  ! grep -q $'\tload ' "$FAKE_DOCKER_LOG" || return 1
  [ "$(state load.result)" = failed ] && [ -z "$(state load.image_ids)" ] || return 1
  rm /media/usb/SHA256SUMS.sigstore.json
  # SHA256SUMS without a signature: loaded as before, the publisher shown as not verified.
  load_run en "$tar"
  flat=$(printf '%s' "$output" | tr '\n' ' ' | tr -s ' ')
  [ "$status" -eq 0 ] && [ "$(state load.result)" = succeeded ] || { echo "$output"; return 1; }
  [[ $output != *"Publisher signature and build provenance verified"* ]] || { echo "$output"; return 1; }
  [[ $flat == *"[SKIP] Publisher signature: the release manifest next to the bundle is not verified (no SHA256SUMS.sigstore.json next to it)"* ]] || { echo "$output"; return 1; }
  [[ $flat == *"the publisher is not verified"* ]] || { echo "$output"; return 1; }
  load_run zh-TW "$tar"
  [ "$status" -eq 0 ] && [[ $output != *"都已驗證"* && $output == *"[SKIP] 發行者簽章：離線包旁的發行清單未經驗證"* ]] || { echo "$output"; return 1; }
  # Signed by the release workflow of this version: the manifest is the publisher's, and so is
  # the content that matches it.
  printf 'identity %s\nsha256 %s\n' "$id" "$sums" >/media/usb/SHA256SUMS.sigstore.json
  load_run en "$tar"
  [ "$status" -eq 0 ] && [[ $output == *"[ OK ] Publisher signature and build provenance verified"* ]] || { echo "$output"; return 1; }
  grep -q 'VERIFY manifest /media/usb/MANIFEST.json signed' "$ROOT"/logs/load-*.log || return 1
  # The manifest of the unpacked package: verified before unpacking, as the install relies on too.
  rm /media/usb/SHA256SUMS.sigstore.json
  release_manifest >"$ROOT/current/MANIFEST.json"
  load_run en "$tar"
  [ "$status" -eq 0 ] && [[ $output == *"[ OK ] Publisher signature and build provenance verified"* ]] || { echo "$output"; return 1; }
}

@test "an interrupted load holds nothing up: status says so, load runs again, install goes on" {
  host_full
  export FAKE_COSIGN_VERIFY=offline
  mkdir -p /media/usb
  local tar=/media/usb/custodexa-images-1.13.0-amd64.tar flat
  make_bundle "$tar" classic
  # docker load cut off by Ctrl-C or a dropped SSH session: the run stays recorded at step 4.
  printf '{\n  "format": "2",\n  "load.log": "logs/load-20260930-101502.log",\n  "load.result": "in_progress",\n  "load.step": "4",\n  "load.bundle": "%s"\n}\n' "$tar" >"$ROOT/state.json"
  status_run en
  flat=$(printf '%s' "$output" | tr '\n' ' ' | tr -s ' ')
  [ "$status" -eq 4 ] && [[ $flat == *"[WARN] The last load was interrupted at step 4."* ]] || { echo "$output"; return 1; }
  [[ $output == *"    sudo $ROOT/custodexa.sh load $tar"* ]] || { echo "$output"; return 1; }
  status_run zh-TW
  [[ $output == *"[WARN] 上次的 load 在第 4 步中斷"* ]] || { echo "$output"; return 1; }
  load_run en "$tar"
  [ "$status" -eq 0 ] && [ "$(state load.result)" = succeeded ] || { echo "$output"; return 1; }
  [[ $output == *"The last load run was interrupted at step 4."* ]] || { echo "$output"; return 1; }
  status_run en
  [[ $output != *"interrupted"* ]] || { echo "$output"; return 1; }
  # install after an interrupted load goes on as well.
  state_put load.result in_progress
  install_run en --yes
  [ "$status" -eq 0 ] && [ "$(state install.result)" = succeeded ] || { echo "$output"; return 1; }
}

@test "offline: after load on the containerd store, install takes the loaded images by their recorded IDs" {
  host_full
  store containerd
  down ghcr.io
  down docker.io
  export FAKE_COSIGN_VERIFY=offline
  mkdir -p /media/usb
  make_bundle /media/usb/custodexa-images-1.13.0-amd64.tar containerd
  load_run en /media/usb/custodexa-images-1.13.0-amd64.tar
  [ "$status" -eq 0 ] && [[ $output == *"[SKIP] Publisher signature: offline"* ]] || { echo "$output"; return 1; }
  cd /tmp
  # load let the unverified publisher pass without a question; install still asks, whatever load recorded.
  install_run en
  [ "$status" -eq 3 ] || { echo "$output"; return 1; }
  [[ $output == *"[ ?? ] "* && $output == *"[FAIL] This step needs a confirmation"* ]] || { echo "$output"; return 1; }
  ! grep -q $'\tcompose .* up ' "$FAKE_DOCKER_LOG" || return 1
  [ "$(state install.result)" = cancelled ] && [ -z "$(state current.version)" ] || return 1
  install_run en --yes
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [ "$(grep -c 'This host: present, content digest matches' <<<"$output")" -eq 3 ] || { echo "$output"; return 1; }
  ! grep -q $'\tpull ' "$FAKE_DOCKER_LOG" || return 1
  [ "$(state current.image_ids)" = "$(state load.image_ids)" ] || { echo "$(state current.image_ids) / $(state load.image_ids)"; return 1; }
  [ "$(state current.verification)" = "checksum=ok signature=skip-offline provenance=ok" ] || { echo "$(state current.verification)"; return 1; }
}

# ---- status ----
status_run() { # <lang> [options...]
  local l=$1
  shift
  run bash "$ROOT/custodexa.sh" status --lang "$l" "$@" </dev/null
}
# status_at <YYYY-mm-dd HH:MM>: the time status reads as now.
status_at() {
  clock 0
  /usr/bin/date -d "$1" +%s >"$FAKES/clock"
}
# Every Docker call status made only reads: daemon info, container state, and /health and the seal
# status from inside the backend container.
status_calls_read_only() {
  local bad
  bad=$(grep -v -E $'^ARGS\t(info|container inspect --format \\{\\{\\.State\\.Status\\}\\} \\{\\{\\.State\\.ExitCode\\}\\} custodexa-[a-z-]+|exec custodexa-backend wget -qO- http://localhost:8080/(health|api/v1/seal/status))\t' "$FAKE_DOCKER_LOG") || true
  [ -z "$bad" ] || { echo "not a read-only call: $bad"; return 1; }
}
# tree_print <dir>: every path, mode, owner and file content under dir.
tree_print() { find "$1" -printf '%p %m %u:%g %s\n' | sort; find "$1" -type f -exec sha256sum {} + | sort; }
# status_locked <lang>: status while another custodexa.sh holds the deployment lock.
status_locked() {
  exec 8>>"$ROOT/.custodexa.lock"
  flock -n 8
  status_run "$@"
  exec 8>&-
}
state_put() { # <key> <value>...: set keys in state.json the way the script writes it
  local tmp=$ROOT/state.json.test
  local -a args=()
  while [ $# -gt 1 ]; do args+=(--arg "$1" "$2"); shift 2; done
  jq '. + $ARGS.named' "${args[@]}" "$ROOT/state.json" >"$tmp" && mv "$tmp" "$ROOT/state.json"
}
recordings_ready() { chown 1000:0 "$1" && chmod 2770 "$1"; }

@test "status: the reviewed screen word for word; nothing written, no lock taken, Docker only asked" {
  host_full
  mkdir -p "$ROOT/releases/1.13.2" "$ROOT/backups/20260930-021504" "$ROOT/data/recordings"
  recordings_ready "$ROOT/data/recordings"
  printf 'DATA_PATH=%s/data\nPUBLIC_BASE_URL=https://10.0.0.12\nADMIN_INITIAL_PASSWORD=example-initial-pass\n' "$ROOT" >"$ROOT/.env"
  chmod 600 "$ROOT/.env"
  printf '{\n  "format": "2"\n}\n' >"$ROOT/state.json"
  state_put home "$ROOT" compose_project custodexa install.result succeeded \
    current.version 1.13.2 current.kind package current.since 2026-09-30T02:31:12+0800 \
    current.release_dir releases/1.13.2 current.overlays "" \
    current.image_ids "postgres=sha256:01 guacd=sha256:02 backend=sha256:03 frontend=sha256:04 openssl=sha256:05 nginx=sha256:06" \
    current.image_source "postgres=docker.io guacd=docker.io backend=ghcr.io frontend=ghcr.io openssl=docker.io nginx=docker.io" \
    current.verification "checksum=ok signature=ok provenance=ok" previous.version 1.13.0 \
    last_backup.id 20260930-021504 last_backup.kind script last_backup.taken_at 2026-09-30T02:17:55+0800 \
    last_backup.dir backups/20260930-021504 last_backup.size_bytes 19434727014 \
    last_upgrade.from 1.13.0 last_upgrade.to 1.13.2 last_upgrade.result succeeded last_upgrade.step 13 \
    last_upgrade.finished_at 2026-09-30T02:31:12+0800 last_upgrade.backup_id 20260930-021504
  for c in postgres guacd backend frontend tls-init tls-proxy; do echo "custodexa-$c sha256:0$c"; done >"$SIM/containers"
  echo sealed >"$SIM/seal-state"
  echo 1.13.2 >"$SIM/health-version"
  # 16.9 GB in data/, 36.4 GB in backups/, 175 GB free.
  fake du 'case "${@: -1}" in '"$ROOT"'/data) printf "18146236826\t%s\n" "${@: -1}" ;; '"$ROOT"'/backups) printf "39084202394\t%s\n" "${@: -1}" ;; *) exec /usr/bin/du "$@" ;; esac'
  host_free / 183500800
  local before
  : >"$ROOT/.custodexa.lock"
  before=$(tree_print "$ROOT")
  for l in zh-TW en; do
    status_at '2026-10-02 09:30'
    status_locked "$l"
    [ "$status" -eq 4 ] || { echo "[$l] exit $status"; echo "$output"; return 1; }
    diff <(printf '%s\n' "$output") "$TESTS_DIR/snapshots/s16.$l.txt" || { echo "[$l] differs from the reviewed screen"; return 1; }
  done
  [ "$(tree_print "$ROOT")" = "$before" ] || { diff <(printf '%s\n' "$before") <(tree_print "$ROOT"); return 1; }
  status_calls_read_only
}

@test "status after a real install: each reminder and fault is a warning (exit 4); none left, exit 0" {
  host_full
  install_run en
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  : >"$FAKE_DOCKER_LOG"
  local before rec=$ROOT/data/recordings
  before=$(tree_print "$ROOT")
  status_locked en
  [ "$status" -eq 4 ] || { echo "exit $status"; echo "$output"; return 1; }
  [[ $output == *"  Installed  1.13.0    package deployment, installed $(/usr/bin/date +%Y-%m-%d)"* ]] || { echo "$output"; return 1; }
  [[ $output == *"  [ OK ] 6 service processes started (tls-init runs once and has"* ]] || { echo "$output"; return 1; }
  [[ $output == *"  [ OK ] Backend healthy, version 1.13.0"* && $output == *"  [ OK ] Unsealed and serving users"* ]] || { echo "$output"; return 1; }
  [[ $output == *"  [ OK ] From GHCR; checksums, signatures and build provenance verified"* ]] || { echo "$output"; return 1; }
  [[ $output == *"  [WARN] No backup on record"* && $output == *"  [WARN] .env still holds the initial admin password"* ]] || { echo "$output"; return 1; }
  [[ $output == *"  [WARN] The recordings folder $rec"* && $output == *"1000:0 2770"* ]] || { echo "$output"; return 1; }
  [[ $output != *"Previous"* && $output != *"Last upgrade"* ]] || { echo "$output"; return 1; }
  [ "$(tree_print "$ROOT")" = "$before" ] || { diff <(printf '%s\n' "$before") <(tree_print "$ROOT"); return 1; }
  status_calls_read_only
  # Nothing left to say: exit 0.
  sed -i '/^ADMIN_INITIAL_PASSWORD=/d' "$ROOT/.env"
  recordings_ready "$rec"
  state_put last_backup.id 20260101-000000 last_backup.kind external last_backup.external_ref snap-0412 \
    last_backup.taken_at "$(/usr/bin/date -d '-1 day' '+%Y-%m-%dT%H:%M:%S%z')"
  status_run en
  [ "$status" -eq 0 ] || { echo "exit $status"; echo "$output"; return 1; }
  [[ $output == *"(your own backup; 1 day ago)"* && $output == *"         snap-0412"* && $output != *"Reminders"* ]] || { echo "$output"; return 1; }
  # A reminder alone is enough for exit code 4.
  echo 'ADMIN_INITIAL_PASSWORD=still-here-123' >>"$ROOT/.env"
  status_run en
  [ "$status" -eq 4 ] && [[ $output == *$'\nReminders\n  [WARN] .env still holds'* ]] || { echo "exit $status"; echo "$output"; return 1; }
  sed -i '/^ADMIN_INITIAL_PASSWORD=/d' "$ROOT/.env"
  # A backup older than 30 days, a stopped service, a sealed system still to be set up: each warns.
  state_put last_backup.taken_at "$(/usr/bin/date -d '-31 day' '+%Y-%m-%dT%H:%M:%S%z')"
  status_run en
  [ "$status" -eq 4 ] && [[ $output == *"  [WARN] Latest "*"(your own backup; 31 days ago)"* ]] || { echo "$output"; return 1; }
  state_put last_backup.taken_at "$(/usr/bin/date '+%Y-%m-%dT%H:%M:%S%z')"
  echo custodexa-guacd >"$SIM/stopped"
  status_run en
  [ "$status" -eq 4 ] && [[ $output == *"  [FAIL] 1 of 6 services are not running: custodexa-guacd"* ]] || { echo "$output"; return 1; }
  : >"$SIM/stopped"
  echo sealed >"$SIM/seal-state"
  touch "$SIM/seal-init"
  status_run zh-TW
  [ "$status" -eq 4 ] && [[ $output == *"  [WARN] 主金鑰尚未初始化"* ]] || { echo "$output"; return 1; }
  rm -f "$SIM/seal-init" "$SIM/seal-state"
  echo 1.13.1 >"$SIM/health-version"
  status_run en
  [ "$status" -eq 4 ] && [[ $output == *"  [WARN] The backend reports version 1.13.1"* ]] || { echo "$output"; return 1; }
  status_calls_read_only
}

@test "status on a git clone deployment: not converted yet, word for word; other commands still refuse that folder" {
  host_full
  local old=/data/custodexa
  rm -rf "$old"
  mkdir -p "$old/.git" "$old/data/recordings"
  recordings_ready "$old/data/recordings"
  echo 1.12.4 >"$old/VERSION"
  : >"$old/docker-compose.yml"
  printf 'DATA_PATH=./data\nPUBLIC_BASE_URL=https://10.0.0.12\n' >"$old/.env"
  for c in postgres guacd backend frontend tls-init tls-proxy; do echo "custodexa-$c sha256:0$c"; done >"$SIM/containers"
  echo 1.12.4 >"$SIM/health-version"
  local before
  before=$(tree_print "$old")
  export CUSTODEXA_HOME=$old
  status_run zh-TW
  [ "$status" -eq 4 ] || { echo "exit $status"; echo "$output"; return 1; }
  [[ $output == *$'\n  目前       1.12.4    git clone 部署，尚未轉換\n             下次用 custodexa.sh upgrade 升級時，會先把目錄整理成新結構\n'* ]] || { echo "$output"; return 1; }
  [[ $output == *"  [ OK ] 後端回報正常，版本 1.12.4"* && $output != *"映像"* ]] || { echo "$output"; return 1; }
  status_run en
  [[ $output == *$'\n  Installed  1.12.4    git clone deployment, not converted yet\n             The next custodexa.sh upgrade reorganizes the folder first\n'* ]] || { echo "$output"; return 1; }
  [ "$(tree_print "$old")" = "$before" ] || return 1
  status_calls_read_only
  # Only status reads a git clone deployment; commands that write stop before touching it.
  run bash "$ROOT/custodexa.sh" load /media/none.tar --lang en </dev/null
  [ "$status" -eq 1 ] && [[ $output == *"CUSTODEXA_HOME=$old"* ]] || { echo "$output"; return 1; }
  [ "$(tree_print "$old")" = "$before" ]
}

@test "status with a damaged state.json stops with exit code 5 and points at the previous copy" {
  host_full
  printf '{\n  "format": "2",\n  "current.version": "1.1' >"$ROOT/state.json"
  status_run en
  [ "$status" -eq 5 ] || { echo "exit $status"; echo "$output"; return 1; }
  [[ $output == *"$ROOT/state.json.prev"* ]] || { echo "$output"; return 1; }
  [ ! -s "$FAKE_DOCKER_LOG" ] || { cat "$FAKE_DOCKER_LOG"; return 1; }
}

@test "a form chosen before install by copying .env.example: its placeholder values do not stop step 7" {
  # The template's DB_PASSWORD placeholder is "postgres", which is also an image name in the state.
  host_full
  fresh_host
  : >"$SIM/images"
  cp "$ROOT/current/.env.example" "$ROOT/.env"
  printf 'COMPOSE_FILE=current/compose.yml:current/compose.external-ingress.yml\n' >>"$ROOT/.env"
  clock 0 2 0 48 0 9 0 21
  install_run en --yes
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [ "$(state install.result)" = succeeded ] || return 1
  [[ " $(state current.image_ids) " == *" postgres=${CFG[postgres]} "* ]] || { echo "$(state current.image_ids)"; return 1; }
  ! grep -q '^DB_PASSWORD=postgres$' "$ROOT/.env"
}
