# 開發環境 Dockerfile
#
# build context 為專案根（見 openspec/specs/container-build）：所有 COPY 來源
# 以專案根為基準，故 backend 原始碼需帶 backend/ 前綴。
#
# 基底版本釘選規則（2026-08-17 查證，全檔各 FROM 適用）：
# 一律釘到具體版本，不用 latest／浮動 major tag。理由有三，皆非潔癖：
# (1) AGPL 的「對應源碼」義務要指名交付二進位對應的是哪一版元件；
# (2) 離線安裝包要能指名包內是哪一版；
# (3) 漏洞公告要能說「升到 X 版」——浮動 tag 使 X 連自己都不知道。
#
# **Go 1.26 而非 1.25**（2026-08-17 決定）：Go 1.24 已於 2026-02-10 隨 1.26 發布而 EOL
# （go.dev/doc/devel/release 的「每個 major 版本支援至其後第二個 major 發布」）。同一條
# 政策也決定了 1.25 的死期——**`go1.27rc3` 已釋出，1.27 正式發布之日即 1.25 EOL 之日**，
# 停在 1.25 等於 1.0 發佈後數週內就要再升一次，且屆時是在有外部使用者的情況下升。
# 故直接上 1.26（該分支要到 1.28 發布才 EOL）。**釘 1.26.6** 是 2026-08-17 查
# `go.dev/dl/?mode=json&include=all` 得到的 1.26 分支最高 patch；它同時涵蓋前一輪
# 促成升版的那批 stdlib 修復（其最高需求為 go1.25.13，1.26 全系列皆高於此）。
# 註：查證當日 golang:1.26.6-alpine ＝ 1.26-alpine ＝ 1.26.6-alpine3.24
# （digest 皆 sha256:3889b425…），即目前 `-alpine` 就是 Alpine 3.24。
# 續期提醒：1.27 正式發布時 1.26 尚有一個 major 的壽命，但 1.28 發布日即 1.26 EOL 日。
FROM golang:1.26.6-alpine AS development

# 安裝必要的工具
RUN apk add --no-cache git

# 設定工作目錄
WORKDIR /app

# 複製 go mod 文件
COPY backend/go.mod backend/go.sum ./

# 下載依賴
RUN go mod download

# 複製所有原始碼（trailing slash：複製目錄內容而非目錄本身，故 /app 下直接是 go.mod 等）
COPY backend/ ./

# 暴露端口
EXPOSE 8080

# 使用 go run 進行開發（支援熱重載需要額外工具）
CMD ["go", "run", "cmd/server/main.go"]

# 生產環境構建階段
#
# **正式版二進位由本階段建出，故 stdlib 漏洞的實際修復點就在這一行**（版本選擇理由見檔首）。
FROM golang:1.26.6-alpine AS builder

WORKDIR /app

# 安裝 build 工具
RUN apk add --no-cache git ca-certificates

# 複製依賴文件
COPY backend/go.mod backend/go.sum ./
RUN go mod download

# 複製原始碼
COPY backend/ ./

# 編譯二進位文件
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags '-w -s' -o /bin/custodexa ./cmd/server

# MSSQL CLI（sqlcmd）建置階段（database-protocol「mssql 協議 CLI」）
#
# 來源 https://github.com/microsoft/go-sqlcmd（授權 MIT，非 EULA）。刻意**自建**而非
# 下載官方 release tarball：自建與既有 go mod download 走同一信任面（module proxy ＋
# checksum DB 的 go.sum 驗證），不需另引入「下載 GitHub release 資產並比對 sha256」
# 這條路徑與其憑證維護。純 Go（TDS driver 為 microsoft/go-mssqldb），CGO_ENABLED=0
# 建出的靜態二進位可直接落進 alpine 執行階段，不需 ODBC／unixODBC。
#
# **基底須不低於 go-sqlcmd v1.10.0 的 go.mod 宣告（go 1.25.7）**；本專案明文拒絕以
# GOTOOLCHAIN=auto 掩蓋版本落差（container-build「建置基底映像語言版本不低於模組宣告」）。
# 自 2026-08-17 主 builder 升至 1.26.6 後，本階段與主 builder 同版——歷史上本階段
# 曾刻意高於主 builder（1.25 vs 1.24），該落差已消失，但仍保留獨立階段：兩者的版本
# 需求來源不同（此處是 go-sqlcmd 的宣告，主 builder 是本專案 go.mod 與 stdlib 修復版），
# 合併會讓日後任一方升版時失去可追溯的理由。
# **main 套件是 cmd/modern，不是 cmd/sqlcmd**（後者為旗標定義的函式庫套件，
# go install 會回 "not a main package"）。此為上游官方建置腳本的同一目標：
# build/build.cmd:45 `go build -o ..\sqlcmd.exe -ldflags="-X main.version=..." ..\cmd\modern`。
# go install 產出的檔名取自套件目錄故為 `modern`，於 COPY 時更名為 sqlcmd。
FROM golang:1.26.6-alpine AS sqlcmd-builder
ARG SQLCMD_VERSION=v1.10.0
RUN apk add --no-cache git \
    && CGO_ENABLED=0 go install -trimpath \
       -ldflags "-w -s -X main.version=${SQLCMD_VERSION}" \
       github.com/microsoft/go-sqlcmd/cmd/modern@${SQLCMD_VERSION}

# 生產環境運行階段
#
# **釘 3.24.1（2026-08-17 查證：當日 alpine:latest／3.24／3.24.1 三個 tag 的 manifest
# digest 完全相同 sha256:28bd5fe8…，故本次釘版不改變任何交付內容，只是把「當時拉到什麼」
# 變成「指名拉什麼」）**。3.24 為當時 Alpine 最新穩定分支；不選 3.23.x 是因為既有
# dev 映像（Alpine 3.23.3）的 trivy 掃描帶 musl CVE-2026-40200 與 zlib CVE-2026-22184
# 兩項 HIGH。釘版理由（AGPL 對應源碼／離線包／漏洞公告需可指名版本）見檔首。
# 續期提醒：Alpine 每個分支約兩年 EOL；升版時須確認 apk 仍提供下方的 postgresql16-client
# 等 CLI（Alpine 換 major 時資料庫 client 的版本後綴會變）。
FROM alpine:3.24.1 AS production

# 資料庫 CLI 供 dbproxy（database-protocol）、kubectl 供 k8sproxy（k8s-exec）
# mariadb-connector-c 提供 client auth plugin（caching_sha2_password.so）：
# mysql-client（MariaDB client）預設不含，連 MySQL 8（caching_sha2_password）會 ERROR 1045
RUN apk --no-cache add ca-certificates postgresql16-client mysql-client mariadb-connector-c redis kubectl

WORKDIR /root/

# 從 builder 複製二進位文件
COPY --from=builder /bin/custodexa .

# MSSQL CLI：Alpine 無現成套件（微軟的 ODBC 版 mssql-tools18 受 EULA 約束），
# 故由上方 sqlcmd-builder 階段自建後複製。0755 非 setuid、非全域可寫，
# prod_build_check.sh 的兩項掃描自動涵蓋。
COPY --from=sqlcmd-builder /go/bin/modern /usr/local/bin/sqlcmd

# 創建必要的目錄（0700：只有後端本體 root 可進，資料庫 CLI 身分連目錄都列不出）
RUN mkdir -p /var/log/custodexa /var/lib/custodexa/recordings \
    && chmod 0700 /var/log/custodexa /var/lib/custodexa /var/lib/custodexa/recordings

# 資料庫 CLI 子程序的專用非 root 身分（database-protocol「CLI 子程序執行環境降權」）。
#
# 保證從「看得懂使用者打什麼」搬到「子程序即使收到任意輸入也讀不到有價值的東西」：
# 該身分不是 root，讀不到後端程序的 /proc/<pid>/environ（KEK/JWT secret）、讀不到
# 0600/0700 的資料與日誌，也沒有任何 capability（非 root exec 且 image 內無 setuid 檔）。
#
# uid/gid 固定 65123（基底未使用的號段）。HOME 為 root 所有、對該身分唯讀的空目錄——
# 子程序不需要任何可寫路徑（三個 client 的歷史檔皆導向 /dev/null），給了就是
# 跨會話交換檔案的面。/tmp 與 /var/tmp 由 1777 收成 0755：後端本體以 root 寫入
# 不受影響（verify-ca 的 CA 暫存檔另行 chown 給該身分讀），該身分則無可寫路徑。
RUN addgroup -g 65123 -S dbcli \
    && adduser -u 65123 -G dbcli -S -D -H -h /var/empty/dbcli -s /sbin/nologin dbcli \
    && mkdir -p /var/empty/dbcli \
    && chmod 0555 /var/empty/dbcli \
    && chmod 0755 /tmp /var/tmp

# 移除 shell 解譯器（deployment-hardening：正式版執行環境不得含 shell）。
#
# 資料庫 CLI 的逃逸路徑（psql `\!`、`\copy ... TO PROGRAM`、`\e`，mariadb
# `system`、`pager <程式>`）與其他經 libc system()/popen() 的間接執行，一律以
# 硬編碼的 /bin/sh 為入口；移除該入口使整類逃逸失效，且不隨 client 版本漂移。
#
# **必須是本 stage 的最後一個 RUN**：其後任何 RUN 都會因無 shell 可用而失敗。
# 本 image 不需要 shell——CMD 為 exec 形式、compose 的 backend 服務無
# healthcheck、後端全庫僅兩處 exec.Command（資料庫 CLI 與 kubectl）皆非 shell。
# /bin/busybox 本身保留（ls/cat 等維運工具仍可經 `docker exec ... /bin/busybox ls`
# 使用）：逃逸依賴的是 system()/popen() 硬編碼的 /bin/sh 路徑，沒有其他 exec
# 原語可用來喚起 busybox 的 sh applet。
# 開發版（Dockerfile.dev）刻意保留 shell：Air 熱重載以 sh -c 執行 build。
RUN rm -f /bin/sh /bin/ash /bin/bash /usr/bin/sh /usr/bin/ash /usr/bin/bash

EXPOSE 8080

CMD ["./custodexa"]
