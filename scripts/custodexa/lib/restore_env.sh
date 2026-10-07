# shellcheck shell=bash
# The reader supplies CX_RS_* metadata. Only the merged file in the private work folder is
# written here; no keys are generated and no destination template is placed before confirmation.
# shellcheck disable=SC2034,SC2153
CX_RS_ENV="" CX_RS_VALUE="" CX_RS_TEMPLATE="" CX_RS_TEMPLATE_CHANGED=0 CX_RS_TEMPLATE_KEEP=""
CX_RS_REISSUE=0 CX_RS_DATA=""
declare -gA CX_RS_HOST_VALUES=() CX_RS_HOST_SOURCE=()

cx_rs_data_valid() {
  local path=$1 part
  [[ $path == /* ]] || { cx_line FAIL "$(cx_msg rs_data_absolute)"; return 1; }
  for part in postgres audit; do
    if { [ -e "$path/$part" ] && [ ! -d "$path/$part" ]; } ||
      [ -n "$(find "$path/$part" -mindepth 1 -print -quit 2>/dev/null)" ]; then
      cx_line FAIL "$(cx_msg rs_data_nonempty "$path/$part")"
      return 1
    fi
  done
}
cx_rs_host_question() {
  local key=$1 suggestion=$2 source=$3 answer prompt=rs_host_ask
  [ "$key" != DATA_PATH ] || prompt=rs_host_ask_path
  while :; do
    printf '\n'
    cx_line ASK "$(cx_msg "rs_host_${key,,}")"
    printf '%s\n' "$(cx_msg rs_host_values "$source" "$suggestion")"
    printf '%s' "$(cx_msg "$prompt")"
    IFS= read -r answer || return 1
    case $answer in '') answer=$suggestion ;; -) answer=$source ;; esac
    [ "$key" != DATA_PATH ] || cx_rs_data_valid "$answer" || continue
    CX_RS_VALUE=$answer
    return 0
  done
}

# Canonicalize relative paths against the deployment root, not the caller's working directory.
cx_rs_template_path() {
  local path=$1
  [[ $path == /* ]] || path=$CX_ROOT/${path#./}
  readlink -m -- "$path"
}
cx_rs_template_usable() {
  local path=$1 canonical
  [ -d "${path%/*}" ] && [ ! -L "$path" ] || return 1
  [ ! -e "$path" ] || [ -f "$path" ] || return 1
  canonical=$(cx_rs_template_path "$path") || return 1
  case $canonical in "$CX_ROOT/releases"|"$CX_ROOT/releases/"*|"$CX_ROOT/current"|"$CX_ROOT/current/"*) return 1 ;; esac
}
cx_rs_template() {
  local original path input
  CX_RS_TEMPLATE="" CX_RS_TEMPLATE_CHANGED=0 CX_RS_TEMPLATE_KEEP=""
  [ "$(cx_rs_get contents.nginx_template)" = true ] || return 0
  original=$(cx_rs_get source.tls_nginx_template)
  path=$original
  [[ $path == /* ]] || path=$CX_ROOT/${path#./}
  if [ "$CX_RS_FLOW" = new ] && ! cx_rs_template_usable "$path"; then
    input=${CX_RS_NGINX_TEMPLATE:-}
    while :; do
      if [ -z "$input" ]; then
        if [ ! -t 0 ] || [ "${CX_YES:-0}" = 1 ]; then
          cx_rs_refuse rs_template_needed "$original"; return 1
        fi
        printf '\n'
        cx_line ASK "$(cx_msg rs_host_tls_nginx_template)"
        printf '%s\n' "$(cx_msg rs_template_source "$original" "${path%/*}/")"
        printf '%s ' "$(cx_msg rs_template_ask)"
        IFS= read -r input || { cx_rs_unchanged; return 1; }
      fi
      if [[ $input == /* ]] && cx_rs_template_usable "$input"; then break; fi
      cx_line FAIL "$(cx_msg rs_template_invalid "$input")"
      if [ ! -t 0 ] || [ "${CX_YES:-0}" = 1 ]; then cx_rs_unchanged; return 1; fi
      input=""
    done
    path=$input
    cx_env_set "$CX_RS_ENV" TLS_NGINX_TEMPLATE "$path" || return 1
    CX_RS_TEMPLATE_CHANGED=1
  fi
  CX_RS_TEMPLATE=$(cx_rs_template_path "$path") || return 1
  if [ -f "$CX_RS_TEMPLATE" ] && ! cmp -s "$CX_RS_TEMPLATE" "$CX_RS_DIR/pass2/nginx-tls.conf.template"; then
    CX_RS_TEMPLATE_KEEP=$CX_RS_TEMPLATE.before-restore-$CX_RS_TS
  fi
}

cx_rs_env_merge() {
  local source=$CX_RS_DIR/pass2/env.bak key suggestion flag old value host ips port suffix="" cf ov="" expected
  CX_RS_ENV=$CX_RS_DIR/env.merged
  cp "$source" "$CX_RS_ENV" && chmod 600 "$CX_RS_ENV" || return 1
  cf=$(cx_env_get "$source" COMPOSE_FILE)
  for key in $CX_OVERLAY_NAMES; do
    [[ ":$cf:" != *":current/compose.$key.yml:"* ]] || ov="${ov:+$ov }$key"
  done
  expected=current/compose.yml
  for key in $ov; do expected+=:current/compose.$key.yml; done
  if [ "$cf" != "$expected" ] || [ "$ov" != "$(cx_rs_get deploy.overlays)" ]; then
    cx_rs_refuse env_compose_file_bad "$cf"; return 1
  fi
  value=$(cx_env_get "$source" COMPOSE_PROJECT_NAME)
  [ "$value" = "$CX_PROJECT" ] || { cx_rs_refuse env_project_bad "$value" "$CX_PROJECT"; return 1; }
  host=$(cx_env_host_fqdn) ips=$(cx_env_host_ipv4s)
  port=$(cx_env_get "$source" TLS_HTTPS_PORT)
  [ "${port:-443}" = 443 ] || suffix=":$port"
  if [ "$CX_RS_FLOW" = new ] && [ -t 0 ] && [ "${CX_YES:-0}" != 1 ]; then
    if [ -n "$(cx_rs_get deploy.tls_mode)" ]; then printf '%s\n' "$(cx_msg rs_host_intro)"
    else printf '%s\n' "$(cx_msg rs_host_intro_external)"; fi
  fi
  for key in DATA_PATH TLS_DOMAIN TLS_IP_SAN PUBLIC_BASE_URL; do
    old=$(cx_env_get "$source" "$key")
    CX_RS_HOST_SOURCE[$key]=$old
    if [ "$CX_RS_FLOW" = same ]; then
      value=$(cx_env_get "$CX_ROOT/.env" "$key")
    else
      case $key in
        DATA_PATH) suggestion=$CX_ROOT/data; flag=data-path; value=${CX_RS_DATA_PATH:-} ;;
        TLS_DOMAIN) suggestion=$host; flag=tls-domain; value=${CX_RS_TLS_DOMAIN:-} ;;
        TLS_IP_SAN) suggestion=$ips; flag=tls-ip-san; value=${CX_RS_TLS_IP_SAN:-} ;;
        PUBLIC_BASE_URL)
          suggestion=https://${ips%%,*}$suffix
          [ -n "$ips" ] || suggestion=https://$host$suffix
          flag=public-base-url; value=${CX_RS_PUBLIC_URL:-} ;;
      esac
      case $key in TLS_DOMAIN|TLS_IP_SAN)
        if [ -z "$(cx_rs_get deploy.tls_mode)" ]; then CX_RS_HOST_VALUES[$key]=$old; continue; fi ;;
      esac
      if [[ " ${CX_RS_GIVEN:-} " == *" --$flag "* ]]; then
        [ "$value" != - ] || value=$old
      elif [ -t 0 ] && [ "${CX_YES:-0}" != 1 ]; then
        cx_rs_host_question "$key" "$suggestion" "$old" || { cx_rs_unchanged; return 1; }
        value=$CX_RS_VALUE
      else
        value=$suggestion
      fi
      [ "$key" != DATA_PATH ] || cx_rs_data_valid "$value" || { cx_rs_unchanged; return 1; }
    fi
    CX_RS_HOST_VALUES[$key]=$value
    [ "$value" = "$old" ] || cx_env_set "$CX_RS_ENV" "$key" "$value" || return 1
  done
  CX_RS_DATA=${CX_RS_HOST_VALUES[DATA_PATH]}
  [[ $CX_RS_DATA == /* ]] || CX_RS_DATA=$CX_ROOT/${CX_RS_DATA#./}
  CX_RS_REISSUE=0
  if [ "$(cx_rs_get deploy.tls_mode)" = selfsigned ] &&
    { [ "${CX_RS_HOST_VALUES[TLS_DOMAIN]}" != "${CX_RS_HOST_SOURCE[TLS_DOMAIN]}" ] ||
      [ "${CX_RS_HOST_VALUES[TLS_IP_SAN]}" != "${CX_RS_HOST_SOURCE[TLS_IP_SAN]}" ]; }; then
    CX_RS_REISSUE=1
  fi
  cx_rs_template
}
