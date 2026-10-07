# shellcheck shell=bash
# CX_PB_PASS_* and CX_PB_PF_* are read by lib/cmd_backup.sh and lib/backup_ask.sh.
# shellcheck disable=SC2034
# Passphrase encryption of the portable backup (scheme cx-enc-1). The whole file is encrypted with
# the openssl of the image the release pins, never a tool of the host, with fixed parameters:
#   AES-256-CBC (PKCS#7 padding), key and IV by PBKDF2-HMAC-SHA256 600,000 rounds, an 8-byte salt,
#   openssl's salted format (ASCII "Salted__", the salt, the ciphertext).
# The passphrase is 12 to 256 printable ASCII characters (0x20-0x7E), taken as typed. It lives in
# CX_PB_PASS of this shell only: it reaches the tool container on its standard input through the
# shell's own printf, never as an argument or an environment variable of any process, and no file
# is written with it. The plaintext tar goes to the container through a named pipe (0600) in the
# temporary folder, so the whole plaintext file never lands on disk.

readonly CX_PB_SCHEME=cx-enc-1
readonly CX_PB_ITER=600000
readonly CX_PB_PASS_MIN=12
readonly CX_PB_PASS_MAX=256

CX_PB_ENC=0 CX_PB_PASS="" CX_PB_PASS_WHY="" CX_PB_OPENSSL_ID=""
CX_PB_PF_WHY="" CX_PB_PF_PATH="" CX_PB_PF_MODE="" CX_PB_PF_ACL=0

# cx_pb_pass_check <passphrase>: CX_PB_PASS_WHY is "" when it fits the rules, else chars (a
# character outside printable ASCII), short or long. Counted in bytes: only ASCII passes anyway.
cx_pb_pass_check() {
  local LC_ALL=C
  CX_PB_PASS_WHY=""
  if [[ $1 == *[![:print:]]* ]]; then
    CX_PB_PASS_WHY=chars
  elif [ "${#1}" -lt "$CX_PB_PASS_MIN" ]; then
    CX_PB_PASS_WHY=short
  elif [ "${#1}" -gt "$CX_PB_PASS_MAX" ]; then
    CX_PB_PASS_WHY=long
  fi
}

# cx_pb_pass_set <passphrase>: the passphrase for this run; masked in the log from now on.
cx_pb_pass_set() {
  CX_PB_PASS=$1
  cx_secret_add PASSPHRASE "$1"
}

# cx_pb_pass_file <path>: the passphrase from the first line of the file (its line end, \n or
# \r\n, left out). The file must be a regular file and no symbolic link, readable, owned by the
# user running the script or by root, with no read or write bit for group or others and no
# extended ACL. Sets CX_PB_PF_PATH (absolute, for the screen), and on failure CX_PB_PF_WHY: read,
# perm (CX_PB_PF_MODE, CX_PB_PF_ACL say why) or line.
cx_pb_pass_file() {
  local f=$1 mode owner line=""
  CX_PB_PF_WHY="" CX_PB_PF_MODE="" CX_PB_PF_ACL=0
  CX_PB_PF_PATH=$f
  [[ $f == /* ]] || CX_PB_PF_PATH=$PWD/$f
  if [ -L "$f" ] || [ ! -f "$f" ] || [ ! -r "$f" ]; then
    CX_PB_PF_WHY='read'
    return 1
  fi
  if ! mode=$(stat -c %a -- "$f" 2>/dev/null) || ! owner=$(stat -c %u -- "$f" 2>/dev/null); then
    CX_PB_PF_WHY='read'
    return 1
  fi
  CX_PB_PF_MODE=$(printf '%04o' "$((8#$mode))")
  # ls marks a file with an extended ACL with "+" after the mode.
  [[ $(ls -ld -- "$f" 2>/dev/null) != ??????????+* ]] || CX_PB_PF_ACL=1
  if [ $((8#$mode & 8#066)) -ne 0 ] || [ "$CX_PB_PF_ACL" = 1 ] ||
    { [ "$owner" != "$(id -u)" ] && [ "$owner" != 0 ]; }; then
    CX_PB_PF_WHY=perm
    return 1
  fi
  { IFS= read -r line || [ -n "$line" ]; } <"$f" 2>/dev/null || true
  line=${line%$'\r'}
  cx_pb_pass_check "$line"
  if [ -n "$CX_PB_PASS_WHY" ]; then
    CX_PB_PF_WHY=line
    return 1
  fi
  cx_pb_pass_set "$line"
}

# cx_pb_openssl_id: CX_PB_OPENSSL_ID, the openssl image recorded at install or upgrade (a tool
# image, or the certificate initializer's service image), and true when this host holds exactly it.
cx_pb_openssl_id() {
  local kv
  CX_PB_OPENSSL_ID=""
  for kv in $(cx_state_get current.tool_image_ids) $(cx_state_get current.image_ids); do
    if [ "${kv%%=*}" = openssl ]; then
      CX_PB_OPENSSL_ID=${kv#*=}
      break
    fi
  done
  [[ $CX_PB_OPENSSL_ID =~ ^sha256:[0-9a-f]{64}$ ]] || return 1
  [ "$(docker image inspect --format '{{.Id}}' "$CX_PB_OPENSSL_ID" 2>/dev/null)" = "$CX_PB_OPENSSL_ID" ]
}

# cx_pb_openssl <role> <openssl enc arguments...>: openssl enc in a tool container of the recorded
# image, named custodexa-backup-tool-<ts>-<role> (so an interruption can remove it), with no
# network, no log of its output, and the temporary folder at /w. The passphrase is its stdin.
cx_pb_openssl() {
  local role=$1
  local -a ps=()
  shift
  printf '%s\n' "$CX_PB_PASS" | docker run --rm -i --pull never --network none --log-driver none \
    --name "custodexa-backup-tool-$CX_BK_TS-$role" -v "$CX_BK_DIR:/w" --entrypoint openssl \
    "$CX_PB_OPENSSL_ID" enc "$@"
  ps=("${PIPESTATUS[@]}")
  return "${ps[1]}"
}

# cx_pb_pipe_release <named pipe>: let a process waiting to open the pipe go on (it then meets
# the end of the data, or a broken pipe), when the other side never opened it.
cx_pb_pipe_release() {
  local w
  { exec {w}<>"$1" && exec {w}>&-; } 2>/dev/null || true
}

# cx_pb_encrypt <members...>: the backup file, encrypted: tar writes the members (removing each
# once stored) into a named pipe that the tool container reads, and the container writes the file,
# created 0600 here first. Fails when tar or the container fails.
cx_pb_encrypt() {
  local d=$CX_BK_DIR pipe=$CX_BK_DIR/.pack-plain rc=0 tp
  (umask 077 && : >"$d/$CX_PB_NAME" && mkfifo -m 0600 -- "$pipe") || return 1
  cx_bk_quiet /dev/null tar --format=gnu -cf "$pipe" --remove-files -C "$d" -- "$@" &
  tp=$!
  cx_bk_quiet /dev/null cx_pb_openssl enc -e -aes-256-cbc -salt -saltlen 8 -pbkdf2 -md sha256 \
    -iter "$CX_PB_ITER" -pass stdin -in "/w/${pipe##*/}" -out "/w/$CX_PB_NAME" || rc=1
  cx_pb_pipe_release "$pipe"
  wait "$tp" || rc=1
  rm -f -- "$pipe"
  [ "$rc" = 0 ] || cx_log FAIL "encrypting the backup file"
  return "$rc"
}

# cx_pb_readback_enc <file> <tar --to-command> <error file>: the read-back of an encrypted file,
# into the files cx_pb_readback reads: the ciphertext goes once through tee, which hashes the whole
# file and feeds the tool container through a named pipe; the container decrypts with the same
# command a restore uses and hands the tar back through another named pipe to tar, which hashes
# each member. Fails when any of them fails.
cx_pb_readback_enc() {
  local f=$1 cmd=$2 err=$3 d=$CX_BK_DIR rc=0 sub tp p
  local cp=$CX_BK_DIR/.readback-cipher pp=$CX_BK_DIR/.readback-plain
  (umask 077 && mkfifo -m 0600 -- "$cp" "$pp") || return 1
  (tee -- "$cp" <"$f" | sha256sum >"$d/.readback-whole") 2>>"$err" &
  sub=$!
  # Read from stdin, whole records at a time: a pipe hands over the decrypted tar in pieces of any size.
  tar -x -v -B --index-file="$d/.readback-list" --to-command="$cmd" -f - <"$pp" >"$d/.readback-sums" 2>>"$err" &
  tp=$!
  cx_pb_openssl dec -d -aes-256-cbc -saltlen 8 -pbkdf2 -md sha256 -iter "$CX_PB_ITER" -pass stdin \
    -in "/w/${cp##*/}" -out "/w/${pp##*/}" 2>>"$err" || rc=1
  for p in "$cp" "$pp"; do cx_pb_pipe_release "$p"; done
  wait "$tp" || rc=1
  wait "$sub" || rc=1
  rm -f -- "$cp" "$pp"
  return "$rc"
}
