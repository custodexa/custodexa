# shellcheck shell=bash
# about: two hosts without a network between them share only /transfer: b reads what a wrote
# hosts: a b

readonly TH_PORT=18080

# th_offline: no default route (IPv4 or IPv6), and an address off this host is unreachable.
th_offline() {
  it_same "$(hostname) has no IPv4 default route" "" "$(ip -4 route show default)"
  it_same "$(hostname) has no IPv6 default route" "" "$(ip -6 route show default 2>/dev/null)"
  it_expect_fail "nc on $(hostname) cannot reach an address off the host (192.0.2.1:80)" \
    'Network unreachable' nc -v -w 3 192.0.2.1 80 </dev/null
  it_expect_fail "wget on $(hostname) cannot reach it either" 'Network unreachable' \
    wget -q -T 3 -O - http://192.0.2.1/
}

scenario_a() {
  local sum i
  it_step "host a writes a file into the shared folder"
  head -c 4194304 /dev/urandom >/transfer/payload.bin
  sum=$(sha256sum </transfer/payload.bin | cut -d' ' -f1)
  printf '%s\n' "$sum" >/transfer/payload.sha256
  hostname >/transfer/a.hostname
  it_say "   sha256 $sum, hostname $(hostname)"
  it_check "the shared folder holds the file" test -s /transfer/payload.bin

  it_step "host a has no network"
  th_offline

  it_step "host a answers on port $TH_PORT (so the probes from b have something to find)"
  cat >"$IT_WORK/reply.sh" <<'EOF'
#!/bin/bash
while IFS= read -r line; do line=${line%$'\r'}; [ -n "$line" ] || break; done
printf 'HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\n%s\n' "$(hostname)"
EOF
  chmod 755 "$IT_WORK/reply.sh"
  setsid nohup nc -lk -p "$TH_PORT" -e "$IT_WORK/reply.sh" </dev/null >/dev/null 2>&1 &
  for ((i = 0; i < 20; i++)); do
    nc -z -w 1 127.0.0.1 "$TH_PORT" && break
    sleep 0.5
  done
  it_check "nc on host a reaches 127.0.0.1:$TH_PORT" nc -z -w 3 127.0.0.1 "$TH_PORT"
  it_same "wget on host a gets the reply from 127.0.0.1:$TH_PORT" "$(hostname)" \
    "$(wget -q -T 3 -O - "http://127.0.0.1:$TH_PORT/")"
}

scenario_b() {
  local a
  it_step "host b reads the file host a wrote"
  it_check "the shared folder holds the file" test -s /transfer/payload.bin
  it_same "host b reads the same bytes (sha256)" "$(cat /transfer/payload.sha256)" \
    "$(sha256sum </transfer/payload.bin | cut -d' ' -f1)"
  a=$(cat /transfer/a.hostname)
  it_check "host b is another machine ($(hostname), not $a)" test "$(hostname)" != "$a"

  it_step "host b has no network and cannot reach host a"
  th_offline
  # No network, so no name service either: b has no address for a at all.
  it_expect_fail "nc from b to $a:$TH_PORT fails" "bad address '$a'" \
    nc -v -w 3 "$a" "$TH_PORT" </dev/null
  it_expect_fail "wget from b to http://$a:$TH_PORT/ fails" "bad address '$a" \
    wget -q -T 3 -O - "http://$a:$TH_PORT/"
  # The same probes that reached a's listener on a: on b nothing answers, the two hosts are
  # separate network namespaces. (BusyBox nc says nothing when a loopback connection is refused,
  # so its pattern is the empty output; wget names the refusal.)
  it_expect_fail "nc from b to 127.0.0.1:$TH_PORT fails" '^$' \
    nc -z -w 3 127.0.0.1 "$TH_PORT" </dev/null
  it_expect_fail "wget from b to http://127.0.0.1:$TH_PORT/ fails" "Connection refused" \
    wget -q -T 3 -O - "http://127.0.0.1:$TH_PORT/"
}
