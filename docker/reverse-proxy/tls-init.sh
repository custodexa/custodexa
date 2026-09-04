#!/bin/sh
# Custodexa 對外 TLS 的憑證前置步驟（docker-compose.yml 的 tls-init 服務）。
#
# 兩件事，做完就結束，反向代理才會啟動：
#   TLS_MODE=selfsigned（預設）沒有憑證時產生一組本地 CA 與伺服器憑證；已經有了就原封不動
#                             （換憑證＝刪掉 tls/ 內的檔案再啟動）。
#   TLS_MODE=provided          檢查 tls/fullchain.pem 與 tls/privkey.pem 在不在，缺檔就以明確
#                             訊息退出非零，代理不會帶著半套設定起來。
#
# 檔案配置（掛載點 /tls 對應專案下的 ./tls）：
#   fullchain.pem              伺服器憑證鏈（葉憑證＋CA 憑證），代理唯讀掛載
#   privkey.pem                伺服器私鑰，代理唯讀掛載
#   ca-public/custodexa-ca.crt CA 憑證，代理唯讀掛載並以 /custodexa-ca.crt 提供下載
#   ca-private/custodexa-ca.key CA 私鑰，權限 600，**不掛進代理容器**
set -eu

TLS_DIR=/tls
MODE="${TLS_MODE:-selfsigned}"
DOMAIN="${TLS_DOMAIN:-}"
IP_SAN="${TLS_IP_SAN:-}"

CERT="${TLS_DIR}/fullchain.pem"
KEY="${TLS_DIR}/privkey.pem"
CA_PUBLIC_DIR="${TLS_DIR}/ca-public"
CA_PRIVATE_DIR="${TLS_DIR}/ca-private"
CA_CERT="${CA_PUBLIC_DIR}/custodexa-ca.crt"
CA_KEY="${CA_PRIVATE_DIR}/custodexa-ca.key"

# CA 憑證目錄一律存在：代理以唯讀方式掛它，provided 模式下它是空的，
# 於是 /custodexa-ca.crt 回 404 而不是一個空檔案。
mkdir -p "$CA_PUBLIC_DIR"

case "$MODE" in
  provided)
    missing=""
    [ -f "$CERT" ] || missing="${missing} tls/fullchain.pem"
    [ -f "$KEY" ] || missing="${missing} tls/privkey.pem"
    if [ -n "$missing" ]; then
      echo "TLS_MODE=provided：缺少憑證檔 ->${missing}" >&2
      echo "把憑證鏈與私鑰放進專案下的 tls/ 再啟動，或改用 TLS_MODE=selfsigned 由本產品產生一組自簽憑證。" >&2
      exit 1
    fi
    echo "TLS_MODE=provided：憑證與私鑰就位，交給反向代理。"
    exit 0
    ;;
  selfsigned) ;;
  *)
    echo "TLS_MODE 的值為 '${MODE}'，可用值是 provided 或 selfsigned。" >&2
    exit 1
    ;;
esac

if [ -f "$CERT" ] && [ -f "$KEY" ]; then
  echo "TLS_MODE=selfsigned：tls/ 內已有憑證，沿用不重新產生。"
  exit 0
fi

if [ -z "$DOMAIN" ]; then
  echo "TLS_MODE=selfsigned：TLS_DOMAIN 是空的，憑證沒有主機名可簽。" >&2
  exit 1
fi

SAN="DNS:${DOMAIN}"
if [ -n "$IP_SAN" ]; then
  # 逗號分隔的 IP 清單，逐個加成 IP: 項
  OLD_IFS="$IFS"
  IFS=','
  for ip in $IP_SAN; do
    ip="$(printf '%s' "$ip" | tr -d ' ')"
    [ -n "$ip" ] || continue
    SAN="${SAN},IP:${ip}"
  done
  IFS="$OLD_IFS"
fi

echo "TLS_MODE=selfsigned：產生本地 CA 與伺服器憑證（SAN=${SAN}）。"

mkdir -p "$CA_PRIVATE_DIR"
chmod 700 "$CA_PRIVATE_DIR"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# CA：10 年，只用來簽這台機器的伺服器憑證
if [ ! -f "$CA_CERT" ] || [ ! -f "$CA_KEY" ]; then
  openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
    -keyout "${WORK}/ca.key" -out "${WORK}/ca.crt" \
    -subj "/CN=Custodexa Internal CA/O=Custodexa" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1
  install -m 600 "${WORK}/ca.key" "$CA_KEY"
  install -m 644 "${WORK}/ca.crt" "$CA_CERT"
  echo "  本地 CA 已產生：ca-public/custodexa-ca.crt（派發給使用者端）、ca-private/custodexa-ca.key（留在主機上）"
else
  echo "  沿用既有的本地 CA。"
fi

# 伺服器憑證：825 天（公開瀏覽器對憑證效期的上限，自簽也照這個數字走）
cat > "${WORK}/server.ext" <<EOF
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=${SAN}
EOF

openssl req -newkey rsa:2048 -sha256 -nodes \
  -keyout "${WORK}/server.key" -out "${WORK}/server.csr" \
  -subj "/CN=${DOMAIN}" >/dev/null 2>&1

openssl x509 -req -in "${WORK}/server.csr" -sha256 -days 825 \
  -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial -CAserial "${WORK}/ca.srl" \
  -extfile "${WORK}/server.ext" -out "${WORK}/server.crt" >/dev/null 2>&1

cat "${WORK}/server.crt" "$CA_CERT" > "${WORK}/fullchain.pem"
install -m 600 "${WORK}/server.key" "$KEY"
install -m 644 "${WORK}/fullchain.pem" "$CERT"

echo "  伺服器憑證已產生：tls/fullchain.pem、tls/privkey.pem（825 天）"
PORT_SUFFIX=""
[ "${TLS_HTTPS_PORT:-8443}" = "443" ] || PORT_SUFFIX=":${TLS_HTTPS_PORT:-8443}"
echo "  使用者端信任這把 CA 之後瀏覽器就不再警告；CA 可從 https://${DOMAIN}${PORT_SUFFIX}/custodexa-ca.crt 下載。"
