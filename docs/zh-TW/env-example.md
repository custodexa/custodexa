# Custodexa 環境變數範本（參考譯本）

<p align="center"><a href="../../.env.example">English</a> | <b>繁體中文</b> | <a href="../ja-JP/env-example.md">日本語</a></p>

> **本檔是參考譯本，不是可以拿來用的範本——請不要複製本檔。**
>
> 唯一實際被使用的範本是專案根目錄的 `.env.example`（英文）：`cp .env.example .env` 複製的是它，
> `scripts/quickstart.sh` 也只認它。實際設定請編輯由 `.env.example` 複製出來的 `.env`。
>
> 本檔逐節、逐鍵對照英文主檔，只為了讓看不懂英文的部署者讀懂每個變數的意思。
> 變數名、範本值與指令一律保留原文，方便左右對照。**若譯本與英文主檔有出入，以英文主檔為準。**

---

## 檔頭：範本總覽

這份英文檔案是唯一實際被使用的範本：`cp .env.example .env` 複製的就是它。
譯本的存在只是讓你能用另一種語言讀說明，而你複製與編輯的檔案永遠是英文主檔，絕不是譯本：

- 繁體中文：`docs/zh-TW/env-example.md`
- 日本語：`docs/ja-JP/env-example.md`

### 安裝步驟（維運者與開發者相同）

1. `cp .env.example .env`
2. 編輯：更換掉每一個密鑰，然後依需要設定 `DB_SSLMODE` / `LDAP` / `DATA_PATH`
3. `docker compose up -d`

或者用一行指令完成：`bash scripts/quickstart.sh --up` 會建立 `.env`、為仍停留在範本值的那些密鑰生成新值，
並啟動整套服務；你已經自己填好的值不會被動到。

### 正式版堆疊與開發版堆疊

預設的 `docker-compose.yml` 就是正式版堆疊：nginx 供應編譯好的前端、後端是精簡二進位、沒有測試靶機。
只是要把 Custodexa 部署起來自己用？看到這裡就夠了。

開發者：把下面的 `COMPOSE_FILE` 取消註解，之後每一條 `docker compose` 指令
（包含 `exec ... go test`）不必加 `-f` 就會指向開發版堆疊——前後端熱重載、完整的 Go 工具鏈、
六個測試靶機（ssh、rdp、vnc、ldap、mysql、k3s）。顯式寫出的 `-f docker-compose.yml` 仍然會覆蓋它，
所以在開發機上依然驗證得了正式版。
同時也要設 `KEK_PROVIDER=env` 並給一把 `ENCRYPTION_KEY`：熱重載每次重建都會重啟行程，
用 `ui` 的話你每存一次檔就得解封一次。

```env
# COMPOSE_FILE=docker-compose.dev.yml
```

上面那一行必須保持註解狀態。部署者之所以拿到正式版堆疊，靠的就是複製這份範本；
這裡若留下一個有效值，等於默默把開發版堆疊（Vite 開發伺服器、不一樣的對外埠）交到他手上。
`COMPOSE_FILE` 是由 docker compose CLI 消費而不是後端，所以它不在 env 漂移守衛的鍵集合裡。

### 讀取方式與寫法上的注意事項

兩份 compose 檔都經由 `env_file` 讀取本範本，而 compose 用 `${DATA_PATH}` 決定持久化資料的落點。
要小心：`env_file` **不會**把行內註解從一個**空值**上剝除
（`SOME_KEY=  # note` 這一行得到的字面值是 `"# note"`），而這裡多數旋鈕的預設值都是空的
——所以每一段說明都獨立成行，沒有任何一行值後面帶著行內註解。

### 不歸這裡管的常數

拓撲與模式常數（`DB_HOST=postgres`、`GUACD_HOST=guacd`、`DB_DRIVER`、`GIN_MODE`、容器內路徑）
來自 compose 的 `environment:` 區塊，該區塊的優先序高於 `env_file`；在這裡設定它們不會有任何作用。

`DB_DRIVER` 沒有出廠預設值，後端缺了它就拒絕啟動：兩份 compose 檔都會提供它，
但裸二進位或自建的部署形態（k8s manifest、systemd unit）必須自行在那邊提供。
PostgreSQL 是唯一支援的目標——sqlite 分支是給單元測試用的，而版本化的 migration 是 PostgreSQL SQL。

這是唯一的一份環境變數範本，而且 `backend/config/env_drift_test.go` 會在
「後端會消費的某個變數既沒有記載於此、也不是由 compose 提供」時讓建置失敗。

### 標記

- `[secret]`：上正式環境前必須更換。
- `[PCI x.y]`：這把鍵背後的 PCI DSS 條號。
  標記寫成「建議 N」時，N 是那條要求指名的值，而出貨預設值是另一個數字，你可以自行調高或調低；
  其餘的 `[PCI]` 鍵則是系統自行強制的要求，該鍵的說明會寫出要求未被滿足時系統拒絕做什麼。
- `[seed]`：首次啟動時寫入一次，之後改由政策頁管理。

---

## 資料落點（Data location）

### `DATA_PATH`

應用程式資料（審計日誌、錄影、資料庫）的根目錄，會以 bind mount 掛進容器。
預設是專案內的 `./data`，開發時方便檢視；
正式環境請指向專屬的資料夾或磁碟，例如 `/opt/custodexa/data`。

```env
DATA_PATH=./data
```

---

## 資料庫

本節是 compose 的 postgres 服務的名稱與憑證，開發版與正式版皆同。

### `DB_NAME`

```env
DB_NAME=custodexa
```

### `DB_USER`

```env
DB_USER=postgres
```

### `DB_PASSWORD`

`[secret]` 這是開發用預設值；正式環境請務必換成強密碼。

```env
DB_PASSWORD=postgres
```

### `DB_SSLMODE`

內建的 postgres 是透過同主機的隔離 bridge 網路連上的、不走 TLS，因此設為 `disable`。
若資料庫在外部、需要跨網路連線，則必須用 `require` 或 `verify-full`（PCI Req 4）。

```env
DB_SSLMODE=disable
```

---

## 密鑰（Secrets）

### `JWT_SECRET`

`[secret][PCI 2.2.2]` `JWT_SECRET` 是 HS256 認證的信任根，長度必須至少 32 bytes
（更短則拒絕啟動）。下面的值是出貨預設值：release（正式）建置在它未被更換前**拒絕啟動**
（fail-close，PCI 2.2.2），debug 建置則會接受它。
正式環境的值請用 CSPRNG 生成，例如 `openssl rand -base64 32`。

```env
JWT_SECRET=change-me-in-production-dev-secret
```

### KEK：信封加密的金鑰加密金鑰

KEK 保護資料庫裡每一個加密欄位：資產憑證、SFTP 密碼、TOTP 種子、通知密鑰。
出貨預設值是 `ui`。**在任何模式下，金鑰材料都沒有出廠預設值**，
所以每一套部署都需要一個明確的動作——跑 quickstart 腳本，或者自己生成並宣告材料。
選之前先了解每種模式在維運上的代價：

- **`ui`（出貨預設值）**：材料**只**存在於記憶體中——由瀏覽器在首次啟動的初始化頁面本地生成，
  之後每次都由管理員在解封頁面重新輸入，**永不寫入磁碟**。
  代價是：**每一次**行程重啟（當機、主機重開、容器重建）回來時都是封印狀態，
  在有人重新把金鑰打進去以前一直處於停止服務的狀態。
  無人值守的部署應該改用 `env` 或 `kms`。

- **`env`**：設 `KEK_PROVIDER=env`，然後把下面的 `ENCRYPTION_KEY` 取消註解並填入生成好的值
  （只要宣告了 `env`，`bash scripts/quickstart.sh` 就會為你生成一次）。
  重啟不需要人介入，這也是熱重載開發之所以還能忍受的原因。
  代價是：材料以明文躺在伺服器磁碟上，所以任何能讀到這個檔案的人
  ——透過備份、快照、或一個設錯的權限位元——就握有你的根金鑰。

- **`kms`**：委託給雲端金鑰服務；見下方的設定項。

- **`hsm`**：硬體模組介面未實作，請勿選用這個值。

#### `KEK_PROVIDER`

`KEK_PROVIDER` **區分大小寫**，任何白名單以外的值（包含 `ENV`）都會拒絕啟動：不猜測、不回落。
把它**留空**代表「未設定」，而**不是** `ui`——空值在 `ENCRYPTION_KEY` 存在時會退回 `env` 模式，
在 `ENCRYPTION_KEY` 不存在時則拒絕啟動。
`ui` 是這份範本明確寫上的出貨值，並不是執行期的預設值。

```env
KEK_PROVIDER=ui
```

#### `ENCRYPTION_KEY`

`[secret][PCI 2.2.2]` KEK 材料：一把 **32 位元組（32-BYTE）**的金鑰。
「32 bytes」講的是金鑰長度，不是你打進去的字串長度，所以下面三種寫法都會被接受：

1. 恰好 32 個字元（`A-Z a-z 0-9`）
2. 64 個十六進位字元
3. 解碼後恰好是 32 位元組的 base64（標準或 URL-safe，有無 padding 皆可）

任何解不出 32 位元組的東西都會被拒絕；過短的材料**不會**被補齊。

下面這把金鑰是**刻意保持註解狀態**的。只有 `KEK_PROVIDER=env` 需要它——
在 `ui`（預設）與 `kms` 之下它**必須**維持註解狀態，
在那些模式下給它一個值屬於自相矛盾的組態，會拒絕啟動。
請用 CSPRNG 生成材料，不要自己發明一個字串：低熵的值一樣能通過長度檢查卻依然脆弱，
而從公開文件複製來的值會讓每一套部署共用同一把 KEK。下列任一皆可：

```sh
openssl rand -hex 32
openssl rand -base64 32
LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 32
```

（每種可接受的形態各給一條指令；有一個守衛測試會實際跑過每一條，
檢查它的輸出永遠通得過驗證。）
KEK 材料鍵**只有一把**——沒有別名、沒有備援鍵——而且空字串並不會「停用」它：
空代表沒有材料，此時 `env` 模式就會拒絕啟動。
在 `ui` 之下，讓下面這個佔位鍵保持註解才是正確狀態。

要使用 `env` 模式，就把下一行取消註解，貼上你生成的值：

```env
# ENCRYPTION_KEY=
```

#### 委託模式的設定項（`KEK_PROVIDER=kms`）

啟動時會檢查三把 `KEK_KMS_*` 鍵是否齊備，缺少的會**逐項列出**；
而且每一把本地 KEK 材料鍵都必須維持未設定狀態，否則就是自相矛盾的組態，拒絕啟動。

`KEK_KMS_PROVIDER` 目前只支援 `aws`。
`KEK_KMS_KEY_ID` 接受別名、裸的 key id 或完整 ARN；
啟動時會透過 `DescribeKey` 把它正規化成 key ARN 之後才存起來，所以三種寫法是等價的。
憑證來自 AWS SDK 的預設鏈（IRSA、instance profile、`AWS_*` 變數、SSO）；
Custodexa 既不持有雲端憑證，也不提供 endpoint 覆寫。

Endpoint 覆寫在正式路徑上一律直接拒絕：`AWS_ENDPOINT_URL_KMS` 與 `AWS_ENDPOINT_URL`
是由 SDK 自己解析的，會把 `kms:Encrypt` 請求——那裡面帶著明文 DEK——送到該位址，
而且可能是走明文 HTTP。這兩個只要有一個被設了就 fail-close，
`~/.aws/config` 裡的 `endpoint_url` 也一樣。

`KEK_KMS_KEY_ID` 同時也宣告了這套部署信任哪一個 KMS 帳號：
交給換鑰精靈的重包目標（請求 body 裡的 `key_ref`）必須與這把金鑰位於**同一個 partition
與同一個 AWS 帳號**，否則會被拒絕。光是 region 相符並不夠。

需要的 IAM 動作：`kms:DescribeKey`、`kms:Encrypt`、`kms:Decrypt`；
若要從一把 KMS 金鑰換到另一把，還需要 `kms:ReEncryptFrom` 與 `kms:ReEncryptTo`
（是**兩個**動作，不是單一個 `kms:ReEncrypt`）。
除了 `DescribeKey` 之外，啟動時還會跑一次用完即丟的 Encrypt/Decrypt 往返，
所以權限不足或外部金鑰儲存（XKS）連不上，會在開機時就浮現，而不是等到第一次使用才爆。

多區域金鑰（MRK）可以當 KEK 使用，但這個版本把 primary 與 replica 視為**兩把不同的金鑰**
（存下來的 `kek_id` 含 region），所以切換到 replica 屬於換鑰，必須先經由精靈做一次重包。

從本地模式（`env` 或 `ui`）遷移到 `kms` 的順序：
在仍以本地模式運行時把下面三把鍵填好 → 在換鑰精靈中重包到目標 `key_ref`
→ 然後移除本地 KEK 材料鍵、設 `KEK_PROVIDER=kms` 並重啟。

```env
# KEK_KMS_PROVIDER=
# KEK_KMS_KEY_ID=
# KEK_KMS_REGION=
```

#### `KEK_HSM_*`

未使用，為完整性列出（`hsm` 模式）：

```env
# KEK_HSM_MODULE=
# KEK_HSM_TOKEN_LABEL=
# KEK_HSM_KEY_LABEL=
# KEK_HSM_PIN=
# KEK_HSM_PIN_FILE=
```

### `ADMIN_INITIAL_PASSWORD`

`[secret][PCI 8.3.6/2.2.2]` `ADMIN_INITIAL_PASSWORD` 是全新部署（空資料庫）時所建立的初始管理員帳號的密碼。
**已經不再有公開的預設值**，所以每一套會種入初始資料的部署——包含一個全新的開發資料庫——
都必須自己設定一個值。下面這個佔位值在拒絕清單（denylist）上：
只要值仍是該佔位值、短於 12 個字元、或含有空白字元或換行，
空資料庫的啟動在**任何模式**下都會被拒絕。

請使用高熵值（`openssl rand -base64 24`，並去掉結尾換行）。
它會在首次登入的強制改密時退場，所以進去之後就把這裡的值移除或輪替掉；
若對著一個非空的資料庫啟動而這個值仍然可用，系統會發出警告。
非空的既有資料庫則根本不需要這個值。

```env
ADMIN_INITIAL_PASSWORD=change-me-admin-initial-password-in-env
```

---

## 伺服器（Server）

註：`GIN_MODE` 由 compose 依環境固定（dev=debug、prod=release）。
它不是部署層的旋鈕，所以不列在這裡。

### `CORS_ALLOWED_ORIGINS`

`[PCI 7.3]` 以逗號分隔的允許清單；在 release 下留空 = 僅限同源（same origin）。

```env
CORS_ALLOWED_ORIGINS=
```

### `METRICS_TOKEN`

維運指標端點 `/metrics` 的 Bearer token。
留空 = 不做認證，而留空是安全的預設值：`/metrics` 不在 `/api` 之下，
且正式環境的邊緣只代理 `/api` 與 `/ws`，所以外部無從觸及它。
但如果你為了從另一台主機抓取指標而在反向代理上開了一條通往 `/metrics` 的路由，
你就**必須**設定這個值——否則你等於公開了端點清單、各功能的使用量與錯誤率。

```env
METRICS_TOKEN=
```

---

## 瀏覽器會話（Browser sessions）

### `AUTH_REFRESH_COOKIE_SECURE`

`[seed]` 交給瀏覽器的會話刷新 cookie 是否帶上 `Secure` 屬性。
帶上之後，瀏覽器只會在 HTTPS 連線下保存與送出它。可接受的值是 `true` 與 `false`。
這裡填的值會在**首次啟動**時種進同名的安全政策；此後開關就在
系統設定 → 安全政策 →「連線與帳號」的**「登入狀態僅在 https 連線保存」**，
在那裡儲存後，下一次發放的 cookie 就採用新值，不需重啟。
政策一旦有值，再改本檔不會有任何效果。

留空 = 依 `PUBLIC_BASE_URL` 的協定決定種入的初值：https 位址種入開啟，
http 位址種入關閉，兩者都沒有則政策維持出廠預設的開啟。
TLS 若是在本系統前面一層終結，而 `PUBLIC_BASE_URL` 沒有寫上對外的 https 位址，
請把這個值設成 `true`；本系統以明文 http 對外時，請在首次啟動前設成 `false`。

政策開著而站台走明文 http，系統仍然可用，代價是瀏覽器會丟掉這個 cookie，
每個人隔約 15 分鐘（存取權杖的壽命）就要重新登入一次。這件事使用者看得到：
登入頁會說明現況，安全政策頁也會給管理員同一則提示，在那裡把政策關掉即刻解除。

本機開發用 `http://localhost` 會不會受影響，看瀏覽器：Chromium 與 Firefox 接受來自這個位址的
Secure cookie；Safari 一系的 WebKit 會丟棄，拿 Safari 開發時把該政策關掉即可。

生效的值與它的來源，都會寫在啟動日誌裡。

```env
AUTH_REFRESH_COOKIE_SECURE=
```

---

## 功能旗標（Feature flags）

註：權限檢查**完全沒有旗標**，它在每一種模式下都無條件生效。

`FEATURE_AUDIT_LOG_ENABLED` 是這裡唯一的 release 安全底線：在 `GIN_MODE=release` 之下
把它設成 `false` 會被忽略，審計被強制開回來，而被強制的鍵名會列在啟動日誌中
（全操作審計是一條紅線，部署層不能把它關掉）。
下面另外四把旗標是一般開關——你設什麼就是什麼，在 release 模式下也一樣。

```env
FEATURE_AUDIT_LOG_ENABLED=true
FEATURE_ASYNC_AUDIT_ENABLED=true
FEATURE_AUDIT_FALLBACK_TO_FILE=true
FEATURE_ANOMALY_DETECTION_ENABLED=false
FEATURE_ALERTING_ENABLED=false
```

---

## OIDC 身分提供者整合

提供者本身（issuer、client id、secret、准入規則）是在管理介面中設定、儲存於資料庫；
這裡只有那三項必須由部署層決定的設定。

啟用 SSO 之前有兩個維運上的前提條件（全文見 `docs/QUICKSTART.md`）：

1. **至少保留一個本地管理員帳號。**
   解封（`KEK_PROVIDER=ui`）與初始管理員授權**只接受本地憑證**：
   它們發生在系統尚未完全啟動之前，所以沒有任何外部 IdP 能完成它們。
   如果所有管理員都外部化了，一套被封印的系統就再也沒有人能解封它。
   請給那個帳號一個強密碼並啟用 MFA。（已有一條不變式擋住「移除最後一個本地管理員」。）

2. **在 IdP 端停用一個使用者，並不會切斷正在進行中的協議會話。**
   這個版本沒有 back-channel logout，而一條已經建立的 SSH/RDP/VNC 會話不再碰觸憑證，
   所以它會一直存活到閒置逾時或最長會話時間為止；已簽發的 access token 則在到期前
   （15 分鐘）持續有效。IdP 端的停權只會擋下**下一次**登入。
   要立即切斷存取，請在本系統的管理介面中停用該帳號或整個提供者：
   兩者都會撤銷憑證、終止會話並中斷監看串流。

### `PUBLIC_BASE_URL`

對外的基底 URL，用來組出交給 IdP 的 `redirect_uri` 以及 callback 的返回位址。
它**不是**從請求的 `Host` 推導出來的：在多層反向代理後面，推導注定會出錯，
而錯誤的值會進到 `redirect_uri` 裡、把使用者送到錯誤的主機。
在它未設定期間，已啟用的提供者會被標記為不完整並從登入頁面隱藏（fail-close）。
正式環境必須是 https，例如 `https://bastion.example.com`。

```env
PUBLIC_BASE_URL=
```

### `OIDC_DEDICATED_ISSUERS`

專屬 issuer 宣告（逗號分隔）。
未知的 issuer 會被 fail-close 當成**共享**身分網域，這會強制它的准入規則必須帶有組織條件
（tenant id 或 hosted domain）；而 Okta、自架 IdP 之類並不會簽發這樣的 claim，
所以少了這項宣告，它們的自動佈建就無法設定。
在這裡宣告一個 issuer 意思是「這個 issuer 只服務我們這個組織」
——這是只有部署者才做得了的判斷，所以它不在管理介面中對管理員開放。
內建的共享清單（Google、Microsoft 多租戶端點等等）優先，且無法從這裡覆寫。
改動必須等到每一個副本都滾動重啟之後才生效。

範例：`OIDC_DEDICATED_ISSUERS=https://acme.okta.com,https://idp.internal.example`

```env
OIDC_DEDICATED_ISSUERS=
```

### `OIDC_ALLOWED_INTERNAL_HOSTS`

允許作為對外連線目的地的內部主機名稱（逗號分隔）。
連向 IdP 的對外請求預設拒絕解析到 loopback、link-local（含雲端 metadata 位址）或私有網段，
所以內部 IdP 必須明確列在這裡；**不存在**任何可以把位址檢查整個關掉的布林開關。
在 release 模式之外，列在這裡的主機名稱也可以走 http 連線，開發用的 IdP 靶機需要的正是這一點。

```env
OIDC_ALLOWED_INTERNAL_HOSTS=
```

---

## LDAP 認證（只是種子值，不是執行期設定）

下面從 `LDAP_ENABLED` 到 `LDAP_SKIP_TLS_VERIFY` 這幾把鍵只會寫入資料庫**一次**，
而且只在「首次啟動時發現資料表是空的、且 `LDAP_ENABLED=true`」的情況下才寫入。
在那之後，管理介面的「身分管理 -> LDAP 目錄」頁面是唯一的事實來源，
編輯這個檔案不會有任何作用（系統會記下一個評估標記，所以把那些資料列刪掉也不會讓它重新種入）。
本節最後一把鍵 `LDAP_ALLOWED_LOOPBACK_ENDPOINTS` 不屬於這一組：
它是執行期的對外連線政策，會持續從這個檔案讀取。

在降版到舊版本之前，請把目前管理介面上的設定抄回這個檔案，**含 bind 密碼**；見 `docs/QUICKSTART.md`。

預設為停用。要在開發環境測試 LDAP，把 `LDAP_ENABLED=true`——
下面的值對應的正是內建的 `ldap-test` 服務。
正式環境請把 `LDAP_URL` 指向真正的目錄伺服器，並填入相對應的 DN 與密碼。

### `LDAP_ENABLED`

```env
LDAP_ENABLED=false
```

### `LDAP_URL`

內建的開發測試服務；正式環境請用真正的伺服器（`ldap://` 或 `ldaps://`）。

```env
LDAP_URL=ldap://ldap-test:1389
```

### `LDAP_BIND_DN`

```env
LDAP_BIND_DN=cn=admin,dc=example,dc=org
```

### `LDAP_BIND_PASSWORD`

`[secret]` 開發測試用的值；正式環境請更換。

```env
LDAP_BIND_PASSWORD=adminpass
```

### `LDAP_BASE_DN`

```env
LDAP_BASE_DN=ou=users,dc=example,dc=org
```

### `LDAP_USER_FILTER`

```env
LDAP_USER_FILTER=(uid=%s)
```

### `LDAP_ATTR_EMAIL`

```env
LDAP_ATTR_EMAIL=mail
```

### `LDAP_ATTR_FULLNAME`

```env
LDAP_ATTR_FULLNAME=cn
```

### `LDAP_SKIP_TLS_VERIFY`

僅供自簽測試憑證使用；正式環境永遠是 `false`。

```env
LDAP_SKIP_TLS_VERIFY=false
```

### `LDAP_ALLOWED_LOOPBACK_ENDPOINTS`

允許作為對外連線目的地的 loopback 端點（逗號分隔，`host:port` 精確比對，不支援萬用字元）。
LDAP 撥號預設拒絕 loopback、link-local（含雲端 metadata 位址）、unspecified 與 multicast 位址，
但**私有網段是允許的**，因為目錄伺服器通常就位於內部網路；
**不存在**任何可以把位址檢查整個關掉的布林開關。
當目錄伺服器跑在同一台主機上時，把端點列在這裡，例如 `127.0.0.1:1389`。

```env
LDAP_ALLOWED_LOOPBACK_ENDPOINTS=
```

---

## 會話逾時（單位：分鐘）

`[seed]` 首次啟動時種入；之後改由安全政策頁面管理。

### `SSH_IDLE_TIMEOUT_MINUTES`

`[PCI 8.2.8 建議 15]`；`0` = 停用。

```env
SSH_IDLE_TIMEOUT_MINUTES=30
```

### `SSH_MAX_SESSION_MINUTES`

`0` = 無上限。

```env
SSH_MAX_SESSION_MINUTES=0
```

---

## 審計、錄影與維運上限

### `RECORDING_RETENTION_DAYS`

`[PCI 10.5.1 建議 365][seed]` 留空 = 政策預設值 90。

```env
RECORDING_RETENTION_DAYS=
```

### `AUDIT_CHECKPOINT_INTERVAL_SECONDS`

`[seed]` 檢查點封章間隔，單位為秒；留空 = 3600，最大 86400（24 小時）。
零、無效值、或超出範圍的值都會**退回預設值**。
首次啟動之後，「系統設定 -> 安全政策」才是權威來源，這裡只是初始值
（政策頁面一旦被使用過，env 就不再參與）。

```env
AUDIT_CHECKPOINT_INTERVAL_SECONDS=
```

### `AUDIT_CHECKPOINT_ROW_THRESHOLD`

`[seed]` 檢查點封章的資料列門檻；留空、無效或超出範圍 = 10000，最大 1000000。
門檻與間隔**哪一個先到就觸發檢查點**。

```env
AUDIT_CHECKPOINT_ROW_THRESHOLD=
```

### `KEY_ROTATION_MAX_PER_RUN`

`[seed]` 每一次換鑰執行的最大重新加密筆數；留空或無效 = 100000。

```env
KEY_ROTATION_MAX_PER_RUN=
```

### `RETENTION_MAX_PER_RUN`

`[seed]` 每一次保留期清理執行的最大刪除筆數；留空或無效 = 100000。

```env
RETENTION_MAX_PER_RUN=
```

### `K8S_LIST_TIMEOUT_SECONDS`

`[seed]` Kubernetes list 的逾時秒數；留空或無效 = 10。

```env
K8S_LIST_TIMEOUT_SECONDS=
```

---

## 封印狀態機與解封端點（在 `KEK_PROVIDER=ui` 時生效）

這裡每一把鍵都可以留空，留空即套用內建的安全預設值。
KEK 材料只會經由解封 API 進入記憶體，所以整個這一節都是速率、來源與監聽面的旋鈕，
**不承載任何金鑰材料**。

封印期日誌寫在審計日誌目錄底下：兩份 compose 檔都在容器內設
`AUDIT_LOG_PATH=/var/log/custodexa/audit`，並把它從主機上的 `${DATA_PATH}/audit` bind mount 進去，
所以要找日誌就去主機的那個資料夾。它的落點沒有獨立的鍵。

### 四個 `*_SECONDS` 旋鈕共用的解析規則

下面四個 `*_SECONDS` 旋鈕共用同一條解析規則：
**留空或非數字文字**會退回該鍵上所標示的預設值，
但一個落在 1..86400 之外的**數字**——零、負值或過大的值——
會**拒絕啟動**而不是被夾取（clamp），
因為一個默默忽略掉你設定值的速率限制，比完全沒有速率限制更糟。
同樣地，當封頂低於其基準時也會拒絕啟動。

> 注意：緊接在這四個之後的 `SEAL_UNSEAL_COOLDOWN_THRESHOLD` **不適用**上面這條規則，
> 它有自己的一條，寫在該鍵的說明裡。

### `SEAL_UNSEAL_BACKOFF_BASE_SECONDS`

per-source（依來源）退避基準，單位為秒；留空或非數字 = 2。

```env
SEAL_UNSEAL_BACKOFF_BASE_SECONDS=
```

### `SEAL_UNSEAL_BACKOFF_MAX_SECONDS`

per-source 退避封頂，單位為秒；留空或非數字 = 300。
退避的成長需要一個封頂，好讓「等一下就能再試一次」這件事在任何攻擊強度下都成立。

```env
SEAL_UNSEAL_BACKOFF_MAX_SECONDS=
```

### `SEAL_UNSEAL_COOLDOWN_THRESHOLD`

帶著錯誤金鑰的解封嘗試連續累積到這個次數，就會啟動全域冷卻。
這個計數跨所有來源一起累加，而第一次成功解封就會把它歸零。

它算的是**次數**而不是時間長度，跟上面那些 `*_SECONDS` 旋鈕沒有可比性。
取值請設得明顯高於一個管理員可能連續打錯的次數：
這樣打錯金鑰只會讓那個人自己等一段 per-source 退避，
而不是把端點推進冷卻、連帶把其他所有人一起卡住。

留空 = 20。**與上面那四個 `*_SECONDS` 旋鈕不同**：任何其他不是 1..1048576 範圍內整數的值
——**包含非數字文字**——都會**拒絕啟動**，而不是退回預設值。
（也就是說，這把鍵只有「留空」才會退回預設值。）

```env
SEAL_UNSEAL_COOLDOWN_THRESHOLD=
```

### `SEAL_UNSEAL_COOLDOWN_SECONDS`

全域冷卻基準，單位為秒；留空或非數字 = 60。
冷卻一定會自己到期；要從冷卻中恢復，**永遠不需要**重啟行程。

```env
SEAL_UNSEAL_COOLDOWN_SECONDS=
```

### `SEAL_UNSEAL_COOLDOWN_MAX_SECONDS`

全域冷卻封頂，單位為秒；留空或非數字 = 900。

```env
SEAL_UNSEAL_COOLDOWN_MAX_SECONDS=
```

### `TRUSTED_PROXIES`

可信代理清單（IP 或 CIDR，逗號分隔）。
在它未設定期間，per-IP 退避會降級為全域退避：
沒有一個約定好的代理鏈，限速鍵就可能被轉送標頭污染，
而一道可被繞過的防線比一道笨拙的防線更糟。

```env
TRUSTED_PROXIES=
```

### `SEAL_UNSEAL_BIND_ADDR`

解封端點的獨立監聽位址，例如 `127.0.0.1:8081`；留空 = 與主服務共用監聽。

```env
SEAL_UNSEAL_BIND_ADDR=
```

### `SEAL_UNSEAL_ALLOWED_CIDRS`

允許連到解封端點的來源網段（CIDR 或裸 IP，逗號分隔）；留空 = 不限制。
請把它與你的管理網路搭配使用：在一個不做認證的端點上，
沒有任何速率限制手段能保證管理員自己進得來。

```env
SEAL_UNSEAL_ALLOWED_CIDRS=
```
