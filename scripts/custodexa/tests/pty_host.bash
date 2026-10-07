# A terminal for the tests that answer the script's questions: the command runs under script(1)
# and each answer is typed only once the screen ends with its prompt, the way a person types. A
# secret answer waits until the terminal stops echoing, so a passphrase typed too early cannot show
# on the screen by accident of timing. Needs helper.bash loaded.

# pty_tty <script pid>: the terminal (pts/N) of the command script runs.
pty_tty() {
  local c t
  for c in $(pgrep -P "$1" 2>/dev/null); do
    t=$(ps -o tty= -p "$c" 2>/dev/null | tr -d ' ')
    case $t in pts/*) printf '%s' "$t"; return 0 ;; esac
  done
  return 1
}

# pty_wait_prompt <out file> <size before> <prompt> <pid>: until the output grew past the size and
# its last line ends with the prompt (20 seconds at most). Fails when the command ended first.
pty_wait_prompt() {
  local out=$1 size=$2 prompt=$3 pid=$4 i last
  for i in $(seq 1 400); do
    if [ "$(stat -c %s "$out")" -gt "$size" ]; then
      # The x keeps a line break at the end, which $(...) would drop.
      last=$(tail -c 2000 "$out" | tr -d '\r'; printf x)
      last=${last%x}
      last=${last##*$'\n'}
      [[ $last != *"$prompt" ]] || return 0
    fi
    kill -0 "$pid" 2>/dev/null || return 1
    /usr/bin/sleep 0.05
  done
  echo "pty: no prompt \"$prompt\" within 20 seconds" >&2
  return 1
}

# pty_wait_noecho <script pid>: until the command's terminal no longer echoes (10 seconds at most).
pty_wait_noecho() {
  local i t
  for i in $(seq 1 200); do
    t=$(pty_tty "$1") && stty -F "/dev/$t" -a 2>/dev/null | grep -qw -- '-echo' && return 0
    /usr/bin/sleep 0.05
  done
  echo "pty: the terminal still echoes" >&2
  return 1
}

# pty_talk <out file> <command> [<prompt> <answer>]...: run the command on a terminal (output and
# the echo of what is typed into the file), type each answer after its prompt, then end the input.
# A prompt written as "secret:<prompt>" waits for the echo to be off before its answer is typed;
# "secret:" alone waits for that only.
# Returns the command's exit code; PTY_FED is the number of answers typed.
pty_talk() {
  local out=$1 cmd=$2 fifo fd pid rc=0 size=0 prompt
  shift 2
  fifo=$BATS_TEST_TMPDIR/pty-in.$$.$RANDOM
  mkfifo "$fifo"
  : >"$out"
  script -qec "$cmd" /dev/null <"$fifo" >"$out" 2>&1 &
  pid=$!
  exec {fd}>"$fifo"
  PTY_FED=0
  while [ $# -ge 2 ]; do
    prompt=${1#secret:}
    # An empty prompt: a read that prints none; only the echo going off tells it is waiting.
    if [ -n "$prompt" ]; then pty_wait_prompt "$out" "$size" "$prompt" "$pid" || break; fi
    if [ "$prompt" != "$1" ]; then pty_wait_noecho "$pid" || break; fi
    size=$(stat -c %s "$out")
    printf '%s\n' "$2" >&"$fd"
    PTY_FED=$((PTY_FED + 1))
    shift 2
  done
  exec {fd}>&-
  wait "$pid" || rc=$?
  rm -f "$fifo"
  return "$rc"
}

# pty_screen <out file>: what the screen showed, without carriage returns, the deployment folder
# shown as /opt/custodexa.
pty_screen() { tr -d '\r' <"$1" | sed "s#$ROOT#/opt/custodexa#g"; }
