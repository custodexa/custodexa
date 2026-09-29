#!/usr/bin/env bash
# test_release_workflow.sh - static checks on the image release workflow.
#
# Guards against: an action referenced by a movable tag (whoever moves the tag could then sign
# images under this project's identity); permissions wider than each job needs; the workflow
# running on anything but a version tag (for example pull_request_target, which gives
# untrusted code a token) or on a tag outside the version pattern; floating runner labels;
# registry credentials reachable outside the mirror job; a repository other than the release
# repository publishing into the release namespace; a tag-only toolchain image behind the
# image contract checks; a repository other than the release repository signing or attesting,
# which would put its name into the public Sigstore transparency log.
#
# Usage: bash .github/scripts/test_release_workflow.sh [workflow-file]
#   Default file: .github/workflows/release-images.yml. Needs yq (mikefarah, v4) and actionlint.
set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
wf="${1:-$here/../workflows/release-images.yml}"
[ -f "$wf" ] || { echo "FAIL: workflow not found: $wf" >&2; exit 1; }
for tool in yq actionlint; do
  command -v "$tool" >/dev/null 2>&1 || { echo "FAIL: $tool not found" >&2; exit 1; }
done

# Text is fed to grep -q through here-strings, never a pipe: with pipefail, grep -q exiting on the
# first match can kill the writer with SIGPIPE and turn a match into a failure (or a pass).
failures=0
fail() {
  echo "FAIL: $*"
  failures=$((failures + 1))
}
ok() {
  echo "  ok: $*"
}

yq -e '.' "$wf" >/dev/null 2>&1 || { echo "FAIL: $wf is not valid YAML"; exit 1; }

# 1. Every action is pinned to a full commit SHA with a version comment.
uses_lines="$(grep -nE '^[[:space:]]*(-[[:space:]]+)?uses:' "$wf")"
if [ -z "$uses_lines" ]; then
  fail "no uses: lines found"
fi
while IFS= read -r line; do
  [ -n "$line" ] || continue
  if ! grep -qE 'uses:[[:space:]]+[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}[[:space:]]+#[[:space:]]*v[0-9]' <<<"$line"; then
    fail "action not pinned to a 40-character commit SHA with a version comment: ${line}"
  fi
done <<<"$uses_lines"
[ "$failures" -eq 0 ] && ok "$(printf '%s\n' "$uses_lines" | grep -c .) uses: lines pinned to commit SHAs"

# 2. Top-level permissions are empty.
if [ "$(yq '(.permissions | tag) == "!!map" and (.permissions | length) == 0' "$wf")" = "true" ]; then
  ok "top-level permissions: {}"
else
  fail "top-level permissions must be {} (found: $(yq -o=json -I=0 '.permissions' "$wf"))"
fi

# 3. Job permissions stay within the table in the design.
allowed_for() {
  case "$1" in
    build) echo "contents=read packages=write" ;;
    verify) echo "contents=read packages=read" ;;
    publish) echo "contents=read packages=write id-token=write attestations=write" ;;
    mirror) echo "contents=read packages=read id-token=write" ;;
    # Attaches the install package to a draft release; the only job allowed contents: write.
    package) echo "contents=write id-token=write packages=read" ;;
    *) echo "" ;;
  esac
}
rank() {
  case "$1" in none) echo 0 ;; read) echo 1 ;; write) echo 2 ;; *) echo 9 ;; esac
}
jobs="$(yq '.jobs | keys | .[]' "$wf")"
for job in $jobs; do
  allowed="$(allowed_for "$job")"
  if [ -z "$allowed" ]; then
    fail "job '${job}' is not in the permission table"
    continue
  fi
  if [ "$(yq ".jobs.\"${job}\".permissions | tag" "$wf")" != "!!map" ]; then
    fail "job '${job}' must declare its permissions as a map"
    continue
  fi
  job_ok=1
  while IFS='=' read -r perm level; do
    [ -n "$perm" ] || continue
    max="none"
    for entry in $allowed; do
      [ "${entry%%=*}" = "$perm" ] && max="${entry#*=}"
    done
    if [ "$(rank "$level")" -gt "$(rank "$max")" ]; then
      fail "job '${job}' asks for ${perm}: ${level} (allowed: ${max})"
      job_ok=0
    fi
  done < <(yq ".jobs.\"${job}\".permissions | to_entries | .[] | .key + \"=\" + .value" "$wf")
  [ "$job_ok" -eq 1 ] && ok "job '${job}' permissions within {${allowed}}"
done

# 3b. contents: write only where a release is written.
for job in $jobs; do
  [ "$job" = package ] && continue
  if [ "$(yq ".jobs.\"${job}\".permissions.contents // \"\"" "$wf")" = "write" ]; then
    fail "job '${job}' asks for contents: write (only the package job may write repository contents)"
  fi
done

# 4. Triggered only by pushing version tags.
if [ "$(yq -o=json -I=0 '.on | keys' "$wf")" = '["push"]' ] \
  && [ "$(yq -o=json -I=0 '.on.push | keys' "$wf")" = '["tags"]' ]; then
  ok "on: push tags only ($(yq -o=json -I=0 '.on.push.tags' "$wf"))"
else
  fail "on: must be push with tags only (found: $(yq -o=json -I=0 '.on' "$wf"))"
fi
# 4b. The tag filter is exactly the version pattern; image-tags.sh rejects malformed tags later,
# but a wider filter would start the workflow (and its token) for any tag.
tags_filter="$(yq -o=json -I=0 '.on.push.tags' "$wf")"
if [ "$tags_filter" = '["v*.*.*"]' ]; then
  ok "tag filter is exactly [\"v*.*.*\"]"
else
  fail "tag filter must be exactly [\"v*.*.*\"] (found: ${tags_filter})"
fi
for trigger in pull_request_target pull_request workflow_dispatch workflow_run schedule repository_dispatch; do
  if grep -qE "^[[:space:]]*${trigger}:" "$wf"; then
    fail "trigger '${trigger}' present"
  fi
done

# 5. Runner labels are specific versions.
for job in $jobs; do
  runner="$(yq -o=json -I=0 ".jobs.\"${job}\".\"runs-on\"" "$wf")"
  case "$runner" in
    *latest*|null|*"\${{"*) fail "job '${job}' runs-on ${runner} (a pinned runner version is required)" ;;
    *) ok "job '${job}' runs-on ${runner}" ;;
  esac
done

# 6. Only the mirror job uses the release environment, and only it touches Docker Hub secrets.
env_jobs="$(yq '.jobs | to_entries | map(select(.value.environment != null)) | .[].key' "$wf" | paste -sd' ' -)"
env_name="$(yq '.jobs.mirror.environment | select(tag == "!!map") |= .name' "$wf")"
if [ "$env_jobs" = "mirror" ] && [ "$env_name" = "release" ]; then
  ok "only job 'mirror' uses environment 'release'"
else
  fail "environment use must be exactly mirror -> release (jobs: '${env_jobs}', mirror environment: '${env_name}')"
fi
for job in $jobs; do
  [ "$job" = mirror ] && continue
  if grep -q 'DOCKERHUB_TOKEN\|DOCKERHUB_USERNAME' <<<"$(yq ".jobs.\"${job}\"" "$wf")"; then
    fail "job '${job}' references Docker Hub credentials"
  fi
done

# 7. Only the release repository may use the release namespace. Organization variables reach
# every repository in the organization, so another repository (a rehearsal copy, a fork) could
# otherwise create the release packages and link them to itself. The guard is a build step that
# runs before anything is built or pushed, build is the job every other job needs, and its
# script is executed here in both directions.
guard_name="Release namespace only from the release repository"
guard_idx="$(yq ".jobs.build.steps | to_entries | map(select(.value.name == \"${guard_name}\")) | .[0].key // \"\"" "$wf")"
if [ -z "$guard_idx" ]; then
  fail "build job has no step named '${guard_name}'"
else
  guard=".jobs.build.steps[${guard_idx}]"
  first_effect="$(yq '.jobs.build.steps | to_entries
    | map(select((.value.uses // "" | test("docker/(setup-qemu|setup-buildx|login)-action"))
                 or (.value.run // "" | test("docker |crane |cosign "))))
    | .[0].key // ""' "$wf")"
  if [ -n "$first_effect" ] && [ "$guard_idx" -lt "$first_effect" ]; then
    ok "namespace guard (step ${guard_idx}) runs before the first registry or build step (${first_effect})"
  else
    fail "namespace guard (step ${guard_idx}) must run before the first registry or build step (${first_effect:-none})"
  fi
  if [ "$(yq "${guard} | (has(\"if\") or has(\"continue-on-error\"))" "$wf")" = "true" ]; then
    fail "namespace guard must not carry if: or continue-on-error:"
  fi
  expect_env() {
    local got
    got="$(yq "${guard}.env.$1 // \"\"" "$wf")"
    [ "$got" = "$2" ] || fail "namespace guard env $1 is '${got}' (expected '$2')"
  }
  # shellcheck disable=SC2016 # the expressions are GitHub's, compared literally
  expect_env REPOSITORY '${{ github.repository }}'
  # shellcheck disable=SC2016
  expect_env NAMESPACE '${{ steps.tags.outputs.namespace }}'
  expect_env RELEASE_REPOSITORY 'custodexa/custodexa'
  expect_env RELEASE_NAMESPACE 'custodexa'
  guard_run="$(yq "${guard}.run // \"\"" "$wf")"
  release_repo="$(yq "${guard}.env.RELEASE_REPOSITORY // \"\"" "$wf")"
  release_ns="$(yq "${guard}.env.RELEASE_NAMESPACE // \"\"" "$wf")"
  run_guard() {
    env -i PATH="$PATH" REPOSITORY="$1" NAMESPACE="$2" \
      RELEASE_REPOSITORY="$release_repo" RELEASE_NAMESPACE="$release_ns" \
      bash -c "$guard_run" >/dev/null 2>&1
  }
  # repository | resolved namespace | expected result
  while IFS='|' read -r repo ns want; do
    [ -n "$repo" ] || continue
    if run_guard "$repo" "$ns"; then got=pass; else got=stop; fi
    if [ "$got" = "$want" ]; then
      ok "namespace guard: ${repo} -> ${ns}: ${got}"
    else
      fail "namespace guard: ${repo} -> ${ns}: ${got} (expected ${want})"
    fi
  done <<'CASES'
custodexa/custodexa|custodexa|pass
Custodexa/Custodexa|custodexa|pass
custodexa/rehearsal|custodexa|stop
someone/custodexa|custodexa|stop
private-owner/private-repo|custodexa|stop
custodexa/rehearsal|custodexa/rehearsal|pass
private-owner/private-repo|private-owner|pass
someone/custodexa|someone|pass
CASES
fi
for job in $jobs; do
  [ "$job" = build ] && continue
  if ! grep -qx build <<<"$(yq "[.jobs.\"${job}\".needs] | flatten | .[]" "$wf")"; then
    fail "job '${job}' does not need build, so the namespace guard does not gate it"
  fi
done

# 8. The Go toolchain image behind the GOARCH and version checks is pinned by digest, and the
# workflow does not replace it with a tag-only reference.
verify_script="${VERIFY_IMAGE_SCRIPT:-$here/verify-image.sh}"
if grep -qE '^GO_IMAGE="\$\{GO_IMAGE:-golang:[0-9.]+-alpine@sha256:[0-9a-f]{64}\}"' "$verify_script"; then
  ok "verify-image.sh pins its Go toolchain image by digest"
else
  fail "verify-image.sh must default GO_IMAGE to golang:<version>-alpine@sha256:<digest>"
fi
while IFS= read -r line; do
  [ -n "$line" ] || continue
  grep -qE '@sha256:[0-9a-f]{64}' <<<"$line" \
    || fail "workflow sets GO_IMAGE without a digest: ${line}"
done < <(grep -nE '^[[:space:]]*GO_IMAGE:' "$wf")

# 9. Only the release repository signs. Keyless signatures and attestations write the workflow
# identity (repository, workflow path, tag) into the public Sigstore transparency log for good, so a
# rehearsal copy or a fork builds and publishes unsigned. The build step that decides is executed
# here in both directions; every step that signs, attests or verifies a signature must be gated on
# its output, and each gate is evaluated for the release repository and for any other repository.
official_name="Sign only in the release repository"
official_idx="$(yq ".jobs.build.steps | to_entries | map(select(.value.name == \"${official_name}\")) | .[0].key // \"\"" "$wf")"
# shellcheck disable=SC2016 # the expressions are GitHub's, compared literally
official_wire='${{ needs.build.outputs.official }}'
if [ -z "$official_idx" ]; then
  fail "build job has no step named '${official_name}'"
else
  ostep=".jobs.build.steps[${official_idx}]"
  [ "$(yq "${ostep}.id // \"\"" "$wf")" = official ] || fail "step '${official_name}' must have id: official"
  if [ "$(yq "${ostep} | (has(\"if\") or has(\"continue-on-error\"))" "$wf")" = "true" ]; then
    fail "step '${official_name}' must not carry if: or continue-on-error:"
  fi
  # shellcheck disable=SC2016
  [ "$(yq '.jobs.build.outputs.official // ""' "$wf")" = '${{ steps.official.outputs.official }}' ] \
    || fail "build output 'official' must be \${{ steps.official.outputs.official }}"
  # shellcheck disable=SC2016
  [ "$(yq "${ostep}.env.REPOSITORY // \"\"" "$wf")" = '${{ github.repository }}' ] \
    || fail "step '${official_name}' env REPOSITORY must be \${{ github.repository }}"
  [ "$(yq "${ostep}.env.RELEASE_REPOSITORY // \"\"" "$wf")" = 'custodexa/custodexa' ] \
    || fail "step '${official_name}' env RELEASE_REPOSITORY must be custodexa/custodexa"
  official_run="$(yq "${ostep}.run // \"\"" "$wf")"
  official_release_repo="$(yq "${ostep}.env.RELEASE_REPOSITORY // \"\"" "$wf")"
  official_out="$(mktemp)"
  run_official() {
    : >"$official_out"
    env -i PATH="$PATH" REPOSITORY="$1" RELEASE_REPOSITORY="$official_release_repo" \
      GITHUB_OUTPUT="$official_out" bash -c "$official_run" >/dev/null 2>&1 || { echo error; return; }
    local lines
    lines="$(grep -c . "$official_out")"
    [ "$lines" = 1 ] || { echo "lines=${lines}"; return; }
    sed -n 's/^official=//p' "$official_out"
  }
  # repository | expected output
  while IFS='|' read -r repo want; do
    [ -n "$repo" ] || continue
    got="$(run_official "$repo")"
    if [ "$got" = "$want" ]; then
      ok "signing decision: ${repo}: official=${got}"
    else
      fail "signing decision: ${repo}: official=${got:-<empty>} (expected ${want})"
    fi
  done <<'CASES'
custodexa/custodexa|true
Custodexa/Custodexa|true
CUSTODEXA/custodexa|true
custodexa/rehearsal|false
custodexa/custodexa-drill|false
someone/custodexa|false
private-owner/private-repo|false
CASES
  rm -f "$official_out"
fi

# Evaluates a step-level if: of the form "env.A == 'x' && env.B != 'y'" (terms joined by &&
# only; GitHub compares strings without regard to case) with env.OFFICIAL and env.ATTEST set to
# the given values and every other env value empty. Prints true or false, or "unsupported" for
# any other form. A step with no if: always runs.
lower() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }
eval_if() {
  local cond=$1 official=$2 attest=$3
  [ -n "$cond" ] || { echo true; return; }
  cond="${cond#\$\{\{}"
  cond="${cond%\}\}}"
  case "$cond" in *'||'* | *'!'[!=]* | *'('* | *')'*) echo unsupported; return ;; esac
  local result=true term re="^[[:space:]]*env\.([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*(==|!=)[[:space:]]*'([^']*)'[[:space:]]*$"
  local rest=$cond
  while :; do
    term=${rest%%&&*}
    [[ $term =~ $re ]] || { echo unsupported; return; }
    local var=${BASH_REMATCH[1]} op=${BASH_REMATCH[2]} want have=""
    want="$(lower "${BASH_REMATCH[3]}")"
    case "$var" in OFFICIAL) have=$official ;; ATTEST) have=$attest ;; esac
    have="$(lower "$have")"
    if { [ "$op" = "==" ] && [ "$have" != "$want" ]; } || { [ "$op" = "!=" ] && [ "$have" = "$want" ]; }; then
      result=false
    fi
    [ "$term" = "$rest" ] && break
    rest=${rest#*&&}
  done
  echo "$result"
}

signing_re='cosign[[:space:]]+(sign|sign-blob|attest|attest-blob|verify|verify-blob|verify-attestation)([[:space:]]|$)|gh[[:space:]]+attestation|cx_verify_release_assets'
attest_uses_re='^actions/attest(@|-build-provenance@|-sbom@)|^sigstore/.*attest'
signing_kinds=""
signing_steps=0
for job in $jobs; do
  nsteps="$(yq ".jobs.\"${job}\".steps | length" "$wf")"
  job_official="$(yq ".jobs.\"${job}\".env.OFFICIAL // \"\"" "$wf")"
  for ((i = 0; i < nsteps; i++)); do
    step=".jobs.\"${job}\".steps[${i}]"
    run="$(yq "${step}.run // \"\"" "$wf")"
    uses="$(yq "${step}.uses // \"\"" "$wf")"
    name="$(yq "${step}.name // \"\"" "$wf")"
    [ -n "$name" ] || name="${uses:-step ${i}}"
    cond="$(yq "${step}.if // \"\"" "$wf")"
    kind=""
    if grep -qE "$attest_uses_re" <<<"$uses"; then
      kind=attest
    elif grep -qE "$signing_re" <<<"$run"; then
      kind="$(printf '%s\n' "$run" | grep -oE "$signing_re" | head -n1 | tr -s '[:space:]' ' ' | sed 's/ $//')"
    fi
    if [ -n "$kind" ]; then
      signing_steps=$((signing_steps + 1))
      signing_kinds="${signing_kinds}${job}:${kind}"$'\n'
      # Record every operation of the step, not only the first.
      while IFS='|' read -r label pattern; do
        grep -qE "$pattern" <<<"$run" && signing_kinds="${signing_kinds}${job}:${label}"$'\n'
      done <<'KINDS'
cosign sign|cosign[[:space:]]+sign[[:space:]]
cosign sign-blob|cosign[[:space:]]+sign-blob([[:space:]]|$)
cosign verify|cosign[[:space:]]+verify([[:space:]]|$)
gh attestation|gh[[:space:]]+attestation[[:space:]]+verify
cx_verify_release_assets|cx_verify_release_assets
KINDS
      if [ "$job_official" != "$official_wire" ]; then
        fail "job '${job}' signs or verifies signatures ('${name}') but its env OFFICIAL is '${job_official}' (expected ${official_wire})"
        continue
      fi
      in_release="$(eval_if "$cond" true true)"
      in_other="$(eval_if "$cond" false true)"
      in_other_private="$(eval_if "$cond" false false)"
      if [ "$in_release" = true ] && [ "$in_other" = false ] && [ "$in_other_private" = false ]; then
        ok "${job} / ${name}: release repository runs it, any other repository skips it"
      else
        fail "${job} / ${name} (${kind}) must run only in the release repository: if '${cond:-<none>}' gives release=${in_release}, other=${in_other}, other private=${in_other_private}"
      fi
    fi
    # A step that says in the job summary that this run is unsigned.
    if grep -q 'GITHUB_STEP_SUMMARY' <<<"$run" && grep -q 'Not signed' <<<"$run"; then
      in_release="$(eval_if "$cond" true true)"
      in_other="$(eval_if "$cond" false true)"
      if [ "$job_official" = "$official_wire" ] && [ "$in_release" = false ] && [ "$in_other" = true ]; then
        signing_kinds="${signing_kinds}${job}:note"$'\n'
        ok "${job} / ${name}: unsigned note only outside the release repository"
      else
        fail "${job} / ${name}: the unsigned note must run only outside the release repository (if '${cond:-<none>}', env OFFICIAL '${job_official}')"
      fi
    fi
  done
done
# The release repository still signs, attests and verifies everything it did before, and every
# job that would have signed notes in its summary when it does not.
for want in "publish:cosign sign" publish:attest "publish:cosign verify" "publish:gh attestation" publish:note \
  "mirror:cosign sign" "mirror:cosign verify" mirror:note \
  "package:cosign sign-blob" package:cx_verify_release_assets package:note; do
  grep -qxF "$want" <<<"$signing_kinds" || fail "no gated step for '${want#*:}' in job '${want%%:*}'"
done
attest_steps="$(yq '[.jobs.publish.steps[] | select(.uses // "" | test("^actions/attest@"))] | length' "$wf")"
[ "$attest_steps" = 4 ] || fail "publish must attest provenance and SBOM for both images (4 actions/attest steps, found ${attest_steps})"
ok "${signing_steps} signing, attesting or signature-verifying steps checked"

# 10. actionlint.
if lint="$(actionlint "$wf" 2>&1)"; then
  ok "actionlint clean"
else
  fail "actionlint reported problems:"
  printf '%s\n' "$lint" | sed 's/^/    /'
fi

if [ "$failures" -gt 0 ]; then
  echo "test_release_workflow: ${failures} check(s) failed for ${wf}"
  exit 1
fi
echo "test_release_workflow: all checks passed for ${wf}"
