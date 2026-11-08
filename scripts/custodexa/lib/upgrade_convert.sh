# shellcheck shell=bash
# The conversion of .env that an upgrade to a release with the profiles layout makes:
# the COMPOSE_FILE / COMPOSE_PROFILES lines of the old notation leave, the managed block of
# lib/form.sh takes their place, and an external ingress written as a COMPOSE_FILE overlay becomes
# TLS_MODE=external. The form itself (CX_OVERLAYS, from state.json) never changes here.
#
# Step 9 writes it in three parts, in this order, so that an interruption at any point leaves a
# .env that the script now running can use:
#   a  state.json: current.* <- the target and last_upgrade.env_rewrite=pending with the sha256 of
#      .env as it is now and the keys to change (cx_up_conv_record, saved with the switch)
#   b  the links current and custodexa.sh
#   c  .env, rewritten whole through a temporary file and one rename (cx_up_env_rewrite), then the
#      record becomes done (cx_up_env_done)
# A pending record whose sha256 still matches .env is the evidence that .env is the one from before
# the upgrade (lib/form_guard.sh).
# The target release is releases/$CX_UP_TARGET; CX_OVERLAYS is the form recorded before the switch.

# cx_up_conv_layout: the compose layout of the release being upgraded to.
cx_up_conv_layout() { cx_form_layout "$CX_ROOT/releases/$CX_UP_TARGET"; }

# cx_up_conv_active: only a release with the profiles layout converts .env. An older release reads the
# COMPOSE_FILE the deployment already has, so going to one changes nothing.
cx_up_conv_active() { [ "$(cx_up_conv_layout)" = profiles ]; }

# cx_up_conv_tls_change: succeed when TLS_MODE must become external (an external ingress that the
# old notation wrote in COMPOSE_FILE, going to a release whose form comes from the two keys).
cx_up_conv_tls_change() {
  [ "$1" = profiles ] || return 1
  [[ " $CX_OVERLAYS " == *" external-ingress "* ]] || return 1
  [ "$(cx_form_tls_mode "$CX_ROOT/.env")" != external ]
}

# cx_up_conv_build <layout> <out file>: .env as it will be after the conversion, written to the file.
cx_up_conv_build() {
  local layout=$1 out=$2
  cx_form_managed_rewrite "$CX_ROOT/.env" "$layout" "$CX_OVERLAYS" >"$out" || return 1
  if cx_up_conv_tls_change "$layout"; then
    cx_env_set "$out" TLS_MODE external || return 1
  fi
}

# cx_up_conv_keys: the keys the conversion changes, for the record.
cx_up_conv_keys() {
  local keys="" line
  while IFS= read -r line; do
    line=${line#"${line%%[![:space:]]*}"}
    case $line in
      COMPOSE_FILE=*) [[ " $keys " == *" COMPOSE_FILE "* ]] || keys+=${keys:+ }COMPOSE_FILE ;;
      COMPOSE_PROFILES=*) [[ " $keys " == *" COMPOSE_PROFILES "* ]] || keys+=${keys:+ }COMPOSE_PROFILES ;;
    esac
  done <<<"$(cx_form_managed_moved "$CX_ROOT/.env")"
  ! cx_up_conv_tls_change "$(cx_up_conv_layout)" || keys+=${keys:+ }TLS_MODE
  printf '%s' "$keys"
}

# cx_up_conv_record: a, in the state kept in memory (saved together with the switch).
cx_up_conv_record() {
  cx_up_conv_active || return 0
  cx_state_set last_upgrade.env_rewrite pending
  cx_state_set last_upgrade.env_rewrite_from "$(sha256sum "$CX_ROOT/.env" | cut -d' ' -f1)"
  cx_state_set last_upgrade.env_rewrite_keys "$(cx_up_conv_keys)"
}

# cx_up_env_rewrite: c, the file. Nothing is left behind when it fails; .env stays as it was.
cx_up_env_rewrite() {
  local tmp layout
  cx_up_conv_active || return 0
  layout=$(cx_up_conv_layout)
  tmp=$(umask 077 && mktemp "$CX_ROOT/.env.tmp-XXXXXX") || return 1
  if ! cx_up_conv_build "$layout" "$tmp" || ! chmod 600 "$tmp"; then
    rm -f "$tmp"
    return 1
  fi
  if cmp -s "$tmp" "$CX_ROOT/.env"; then
    rm -f "$tmp"
    return 0
  fi
  mv -f "$tmp" "$CX_ROOT/.env" || { rm -f "$tmp"; return 1; }
}

# cx_up_env_done: c, the record: the conversion is finished.
cx_up_env_done() {
  cx_up_conv_active || return 0
  cx_state_set last_upgrade.env_rewrite "done"
  cx_state_save "$CX_ROOT/state.json"
}

# cx_up_conv_preview: the preview section "what will change in .env"; nothing when .env
# stays as it is. Writes nothing in the deployment folder.
cx_up_conv_preview() {
  local layout tmp line old
  cx_up_conv_active || return 0
  layout=$(cx_up_conv_layout)
  tmp=$(mktemp) || return 0
  if ! cx_up_conv_build "$layout" "$tmp" 2>/dev/null; then
    rm -f "$tmp"
    return 0
  fi
  if cmp -s "$tmp" "$CX_ROOT/.env"; then
    rm -f "$tmp"
    return 0
  fi
  rm -f "$tmp"
  printf '\n%s\n' "$(cx_msg uc_head)"
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    line=${line#"${line%%[![:space:]]*}"}
    printf '%s\n' "$(cx_msg uc_remove "$line")"
  done <<<"$(cx_form_managed_moved "$CX_ROOT/.env")"
  if cx_up_conv_tls_change "$layout"; then
    old=$(cx_form_tls_mode "$CX_ROOT/.env")
    printf '%s\n' "$(cx_msg uc_tls "${old:-selfsigned}")"
  fi
  printf '%s\n' "$(cx_msg uc_add)"
  cx_form_managed_text "$layout" "$CX_OVERLAYS" | sed '1d;$d; s/^/             /'
  printf '%s\n' "$(cx_msg uc_foot "$CX_UP_TARGET")"
}
