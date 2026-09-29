# shellcheck shell=bash
# Language selection and message lookup.
# Messages live in lang/<lang>.sh as MSG_<id>='printf format'. English is loaded first, so a key
# missing from another language falls back to English; the test suite keeps the key sets equal.

# cx_detect_lang: --lang > LC_ALL > LC_MESSAGES > LANG; zh_TW*/zh_Hant* -> zh-TW, ja* -> ja,
# anything else (zh_CN, zh_HK, C, POSIX, unset) -> en.
cx_detect_lang() {
  local v
  if [ -n "${CX_LANG_FLAG:-}" ]; then
    v=$CX_LANG_FLAG
  else
    v=${LC_ALL:-${LC_MESSAGES:-${LANG:-}}}
  fi
  case $v in
    zh-TW | zh_TW* | zh_Hant* | zh-Hant*) printf 'zh-TW' ;;
    ja | ja_* | ja-* | ja.*) printf 'ja' ;;
    *) printf 'en' ;;
  esac
}

cx_i18n_init() {
  local dir=$1
  CX_LANG=$(cx_detect_lang)
  # shellcheck source=/dev/null
  . "$dir/lang/en.sh"
  if [ "$CX_LANG" != en ]; then
    # shellcheck source=/dev/null
    . "$dir/lang/$CX_LANG.sh"
  fi
}

# cx_msg <id> [args...]: print the message without a trailing newline.
cx_msg() {
  local id=$1 var
  shift
  var="MSG_$id"
  if [ -z "${!var+x}" ]; then
    printf '%s' "$id"
    return 0
  fi
  # shellcheck disable=SC2059
  printf "${!var}" "$@"
}
