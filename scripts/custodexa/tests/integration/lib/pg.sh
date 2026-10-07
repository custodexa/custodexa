# shellcheck shell=bash
# PostgreSQL servers on the integration host, for scenarios that need a real server (an external
# database, a restore target). Server <name> is the container it-pg-<name> on the network it-pg,
# reachable there as <name>:5432 and on this host as 127.0.0.1:$(it_pg_port <name>).
#
#   it_pg_start <name> <16|17|18> [--tls | --tls-only | --client-cert]
#       --tls          also serve TLS, with a certificate for <name> signed by the test CA
#       --tls-only     --tls, and refuse every connection that is not TLS
#       --client-cert  --tls-only, and require a client certificate signed by the test CA whose CN
#                      is the user name
#   it_pg_sql <name> <database> <sql>   SQL as the superuser over the server's local socket
#   it_pg_client <16|17|18> [docker run options] -- <command...>
#       a throw-away client container of that major on it-pg, /it/pki at /pki, /it/work at /work
#   it_pg_port <name>   it_pg_stop <name>
#   it_pki_ca <ca>                     a self-signed test CA: /it/pki/<ca>/ca.crt
#   it_pki_cert <ca> <cn> server|client [subjectAltName]
#                                      /it/pki/<ca>/<cn>.crt and .key, signed by <ca>
# The superuser is postgres, password IT_PG_PASSWORD (a test value). The scenario's images line
# needs pg<major> for each server and openssl-3.5.4 for the certificates.

readonly IT_PG_NET=it-pg
readonly IT_PG_PASSWORD=it-test-only-superuser
readonly IT_PG_UID=70 # postgres in the Alpine images
readonly IT_PG_READY_TRIES=60
readonly IT_PKI=$IT_WORK/pki

it_pki_openssl() {
  local img out
  img=$(it_image openssl-3.5.4)
  out=$(docker run --rm --pull never --network none -v "$IT_PKI:/pki" -w /pki --entrypoint openssl "$img" "$@" 2>&1) || {
    printf 'openssl %s failed:\n%s\n' "$1" "$out" >&2
    return 1
  }
}

it_pki_ca() {
  local ca=$1
  [ -f "$IT_PKI/$ca/ca.crt" ] && return 0
  mkdir -p "$IT_PKI/$ca"
  it_pki_openssl req -x509 -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 30 \
    -subj "/CN=$ca test CA" -keyout "$ca/ca.key" -out "$ca/ca.crt" \
    -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign
}

it_pki_cert() {
  local ca=$1 cn=$2 use=$3 san=${4:-}
  it_pki_ca "$ca"
  {
    printf 'basicConstraints=CA:FALSE\n'
    case $use in
      server) printf 'extendedKeyUsage=serverAuth\nsubjectAltName=%s\n' "${san:-DNS:$cn}" ;;
      client) printf 'extendedKeyUsage=clientAuth\n' ;;
      *) it_die "it_pki_cert: use must be server or client" ;;
    esac
  } >"$IT_PKI/$ca/$cn.ext"
  it_pki_openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj "/CN=$cn" \
    -keyout "$ca/$cn.key" -out "$ca/$cn.csr"
  it_pki_openssl x509 -req -in "$ca/$cn.csr" -CA "$ca/ca.crt" -CAkey "$ca/ca.key" -CAcreateserial \
    -days 30 -extfile "$ca/$cn.ext" -out "$ca/$cn.crt"
  chmod 600 "$IT_PKI/$ca/$cn.key"
}

# it_pg_tls_files <name> <dir> <tls-only: 0|1> <client cert: 0|1>: certificate, key, CA and an
# hba file for the server, owned by its postgres user (the server refuses a key others can read).
it_pg_tls_files() {
  local name=$1 dir=$2 only=$3 ccert=$4 opt=""
  it_pki_cert test "$name" server "DNS:$name,DNS:localhost,IP:127.0.0.1"
  cp "$IT_PKI/test/ca.crt" "$dir/ca.crt"
  cp "$IT_PKI/test/$name.crt" "$dir/server.crt"
  cp "$IT_PKI/test/$name.key" "$dir/server.key"
  [ "$ccert" = 1 ] && opt=" clientcert=verify-full"
  {
    printf 'local all all trust\n'
    [ "$only" = 1 ] && printf 'hostnossl all all all reject\n'
    printf 'hostssl all all all scram-sha-256%s\n' "$opt"
    [ "$only" = 1 ] || printf 'host all all all scram-sha-256\n'
  } >"$dir/pg_hba.conf"
  chown -R "$IT_PG_UID:$IT_PG_UID" "$dir"
  chmod 600 "$dir/server.key"
}

it_pg_start() {
  local name=$1 major=$2 tls=0 only=0 ccert=0 img dir=$IT_WORK/pg/$1 i
  local -a cmd=() mounts=()
  shift 2
  for i in "$@"; do
    case $i in
      --tls) tls=1 ;;
      --tls-only) tls=1 only=1 ;;
      --client-cert) tls=1 only=1 ccert=1 ;;
      *) it_die "it_pg_start: unknown option $i" ;;
    esac
  done
  img=$(it_image "pg$major")
  docker network inspect "$IT_PG_NET" >/dev/null 2>&1 || docker network create "$IT_PG_NET" >/dev/null
  rm -rf "$dir"
  mkdir -p "$dir"
  if [ "$tls" = 1 ]; then
    it_pg_tls_files "$name" "$dir" "$only" "$ccert"
    mounts=(-v "$dir:/etc/it-pg:ro")
    cmd=(-c ssl=on -c ssl_cert_file=/etc/it-pg/server.crt -c ssl_key_file=/etc/it-pg/server.key
      -c ssl_ca_file=/etc/it-pg/ca.crt -c hba_file=/etc/it-pg/pg_hba.conf)
  fi
  docker run -d --name "it-pg-$name" --network "$IT_PG_NET" --network-alias "$name" -p 127.0.0.1::5432 \
    -e POSTGRES_PASSWORD="$IT_PG_PASSWORD" ${mounts[@]+"${mounts[@]}"} "$img" postgres ${cmd[@]+"${cmd[@]}"} >/dev/null
  for ((i = 0; i < IT_PG_READY_TRIES; i++)); do
    # Over TCP: the entrypoint's first, socket-only server does not count as ready.
    docker exec "it-pg-$name" pg_isready -q -h 127.0.0.1 -U postgres && return 0
    sleep 1
  done
  docker logs "it-pg-$name" 2>&1 | tail -n 20 >&2
  it_die "server $name (PostgreSQL $major) did not become ready"
}

it_pg_sql() {
  docker exec -i "it-pg-$1" psql -X -q -At -v ON_ERROR_STOP=1 -U postgres -d "$2" -c "$3"
}

it_pg_client() {
  local img
  img=$(it_image "pg$1")
  shift
  local -a opts=()
  while [ $# -gt 0 ] && [ "$1" != -- ]; do
    opts+=("$1")
    shift
  done
  [ "${1:-}" = -- ] || it_die "it_pg_client: missing -- before the command"
  shift
  mkdir -p "$IT_WORK/work" "$IT_PKI"
  docker run --rm -i --pull never --network "$IT_PG_NET" -v "$IT_PKI:/pki:ro" -v "$IT_WORK/work:/work" -w /work \
    ${opts[@]+"${opts[@]}"} "$img" "$@"
}

it_pg_port() {
  docker port "it-pg-$1" 5432/tcp | sed -n 's/^127\.0\.0\.1://p' | head -n1
}

it_pg_stop() {
  docker rm -fv "it-pg-$1" >/dev/null
}
