# 部署與升級 SOP

> 適用版本：Custodexa 1.0。
>
> 本文涵蓋兩件事：**新裝交付的必做檢核**，與**既有部署的版本升級程序**。
>
> 相關文件：[備份與還原](./backup-and-restore.md)、[部署形態限制](./deployment-topology-limits.md)、
> [平台自身特權憑證輪替](./privileged-credential-rotation.md)。

---

## 1. 新裝交付檢核清單（交付必做項）

以下每一項都是**交付人員必須執行的步驟**，不是「建議考慮」。
未執行的後果寫在各項的「不做的話」欄；請在交付驗收時逐項簽核。

### 1.1 套用合規基準值

**出廠預設採易用取向，未套用合規基準即代表新裝系統處於不合規狀態。**

安全政策的出廠值是為了讓系統裝完就能動，不是為了合規。例如：

| 政策 | 出廠值 | PCI 建議值 |
|---|---|---|
| 傳輸強制等級（RDP／VNC／資料庫／LDAP／syslog／通知，共六鍵） | `off`（不強制） | `warn` |
| 全域預設存取政策段位 | `open` | `approval` |

**做法**：以 admin 身分逐一開啟各政策頁（安全政策、傳輸安全、存取管控、金鑰管理），
按該頁的套用鈕填入基準值，**再按儲存**。系統提供兩組基準，各自獨立：

- **套用 PCI 建議值**：填入該頁政策鍵的 PCI DSS 建議值。
- **套用電支基準**：填入的是後端算好的**兩基準取嚴值**，不是電支基準的原值。
  兩基準在部分項目上方向相反（例如密碼最小長度 PCI 要求 12 位、電支只要求 6 位），
  無條件填入電支值會把已設 12 的系統改成 6；那不是「套用合規基準」，是降低安全性。

套用鈕只填入表單值，**按下「儲存」才生效**，儲存前隨時可還原。
套用範圍是「當前頁的政策鍵」，故必須逐頁執行，一次不會蓋到全部。

> **不做的話**：新裝系統的傳輸強制與存取管控全部處於最寬鬆狀態，且沒有任何警示。
> 系統不會替你判斷該不該收緊。

### 1.2 設定離機日誌收集器（syslog 轉發）——必要配套，非選配

**位置**：系統設定 → 安全政策 → 日誌轉發設定。

審計完整性機制（檢查點鏈）在**未設定離機收集器時只覆蓋本地完整性**。
它可以證明「資料庫裡的紀錄沒有被改過」，但無法對抗「把本地資料連同檢查點整套換掉」
（包含以一份舊備份整庫回滾）。要讓這種攻擊被發現，必須有一份系統本身控制不到的副本。

未設定時，產品內的驗證頁最上方會標示為降級狀態並指引至該設定；
**但那是產品在事後提醒，不是部署前的檢核。本清單就是那個檢核。**

> **不做的話**：完整性機制的對外主張範圍必須相應縮小。**不得**在未設定收集器的部署上
> 宣稱系統可對抗「掌握資料庫的內部人抽換紀錄」：那條防線的承擔者是收集端的留存，
> 收集端不存在，防線就不存在。

轉發本身的傳輸加密另受 `transport_syslog_level` 政策鍵管制（見 1.1）。

### 1.3 檢查 `DATA_PATH` 的檔案權限

bind mount 情境下映像內的權限設定不生效，主機端目錄權限由部署方負責。
錄影檔含使用者在目標主機上鍵入的完整內容。詳見
[備份與還原 §3.6](./backup-and-restore.md#36-data_path-的檔案權限部署方責任)。

> **不做的話**：主機上任何本地帳號都能讀取全部會話錄影。

### 1.4 更換出廠機密值，並移除初始密碼

- `JWT_SECRET`：出廠值即為佔位字串；release 模式偵測到未更改會拒絕啟動（fail-close）。
- `ENCRYPTION_KEY`（僅 KEK 模式 A 需要）：出貨預設是 `KEK_PROVIDER=ui`（金鑰不落地），
  該模式下本鍵必須維持無值——有值即為組態矛盾，系統拒絕啟動。
  **若採模式 A**，須以 CSPRNG 生成 32 字元材料，並**顯式宣告 `KEK_PROVIDER=env`**：
  顯式宣告時材料格式不合格會拒絕啟動；未宣告而僅設 `ENCRYPTION_KEY` 走的是既有部署的
  向後相容路徑，**刻意不套格式驗證**，新裝依賴該路徑等於放棄這道把關。
- `ADMIN_INITIAL_PASSWORD`：資料庫初始化完成後，**自 `.env` 移除**。
  仍留有效格式值時系統會在啟動日誌告警提醒（此項不 fail-close，只告警），
  但留著就是一組長期有效的靜態憑證。

### 1.5 確認部署形態

本版**為單實例部署**。交付前確認架構規劃中沒有多實例、負載平衡後端多副本、
或滾動更新的假設。詳見[部署形態限制](./deployment-topology-limits.md)。

本版對同一資料庫啟動的第二個應用實例會**攔下並要求確認**（訊息判讀與救援見 §2.6b）。
攔下的保證範圍有兩條邊界，交付時一併告知客戶：

- 只在守衛版之間成立。不含守衛的舊版本不持鎖，混版並存不會被攔。
- 攔的是「不知情的並存」，不是並存本身。操作者以確認碼啟動後，兩個實例會同時執行；
  資料後果由確認者承擔，守衛保證的是這件事被記錄（`audit_logs` 事件、指標、管理介面橫幅）。

### 1.6 建立備份程序與首次演練

交付不是把系統裝起來就結束。請同時完成：

- 依[備份與還原](./backup-and-restore.md)建立定期備份，並確認 KEK 材料的離機保管已就位。
- **記錄金鑰清冊的四個指紋**（`ENCRYPTION_KEY (KEK)`、`JWT_SECRET`、`匯出簽章鑰 (Ed25519)`、
  `檢查點簽章鑰 (Ed25519)`），隨備份保存。
- KEK 若採介面填鑰模式，向客戶完成**部署前揭露**：材料遺失即資料永久不可解，
  產品不提供任何救回途徑。

### 1.7 執行部署驗證

跑 `docs/QUICKSTART.md`「部署驗證」段的五步（服務起、後端健康檢查、前端可達、
登入鏈路、啟動日誌無 fatal）。

---

## 2. 版本升級程序

### 2.0 先確定回退方案，確認前提成立，並做升級前預檢

**升級失敗時的回退路徑只有一條：還原備份**（程序見第 4 節）。代價是遺失最近一次備份
之後產生的全部資料，請據此決定備份時點與停機視窗，不要升級到一半才發現沒有退路。

**回退要兩樣東西，缺一樣都退不回去：升級前的備份，以及舊版的映像。**
備份見 §2.1；映像這一格特別容易漏——三顆映像的參照都是 `custodexa/*:latest`，
新版一建置或一拉取就把同名 tag 覆蓋掉，舊版映像沒有另一個名字就找不回來了。
自行建置者見 §2.2 的另存 tag，以交付映像部署者請先確認舊版映像檔仍在手上
（或該版本在貴方的 registry 上仍取得到）。

> **本節的適用範圍**：`Custodexa 1.0` 的資料庫 schema 以單一 baseline
> （`20260816_schema_baseline`）為起點，其後以**增量 migration** 演進（本版含
> `20260824_audit_export_jobs` 與 `20260826_source_ip_forensics`，見下 §2.5）；
> 因此本節適用於同屬 1.0 baseline 世代的版本更替，
> 也就是資料庫已套用過該 baseline 的部署。
>
> 若資料庫的 `schema_migrations` 表內含有本版程式碼不認識的版本值、而 baseline 尚未套用，
> 後端會拒絕啟動（見 §2.6）。這類跨越 baseline 世代的升級請視為「新裝＋資料移轉專案」，
> 移轉的範圍與工具須與交付方另行議定，不在本 SOP 之內。
>
> 請在規劃升級前確認貴方的來源版本。

> **單實例守衛的保證範圍**：本版起，第二個應用實例對同一資料庫啟動會被攔下並要求確認（§2.6b）。
> 這道互斥**只在守衛版之間成立**：不含守衛的舊版本不持鎖，首次自無守衛版升級到本版時，
> 新版能取得鎖**不代表**舊版已停。§2.3 步驟 5 的首次升級檢核就是為此而設，不可略過。

#### 升級前預檢：對外以 http 提供服務的部署

Web 會話刷新 cookie 要不要只在 https 連線保存，由安全政策
**「登入狀態僅在 https 連線保存」**決定（系統設定 → 安全政策 →「連線與帳號」），
出廠值為開啟。這個政策不是本版新增的，**v1.0.4 的部署就有**；下表講的是它**還沒有值**時
第一次啟動的播種規則：

| 升級後首次啟動時的 `.env` | 政策初值 |
|---|---|
| 有 `AUTH_REFRESH_COOKIE_SECURE=true` 或 `false` | 直接採用 |
| 未設，`PUBLIC_BASE_URL` 為 `https://…` | 開啟 |
| 未設，`PUBLIC_BASE_URL` 為 `http://…` | 關閉 |
| 兩者都沒有 | 開啟（出廠值） |

**貴方若以 http 對外提供服務，升級前請在 `.env` 設 `AUTH_REFRESH_COOKIE_SECURE=false`。**
這樣升級後的登入行為與升級前一致。

**但貴方的部署很可能已經有值了**（既有部署只要曾以 `AUTH_REFRESH_COOKIE_SECURE` 或
`PUBLIC_BASE_URL` 啟動過，播種在那時就發生了），這種情況下改 `.env` 不會有任何效果
——見本節末的提醒。**要確認現況，看的是安全政策頁上那個開關的實際值，不是 `.env`。**

沒設不會讓系統無法使用：服務照常啟動、連線照常建立。代價是瀏覽器不保存刷新 cookie，
使用者的登入狀態最多維持 15 分鐘（存取權杖的壽命），時間一到，下一次操作就會被帶回
登入頁，手上正在看的畫面跟著中斷。登入頁會向使用者說明現況並請他找管理員；管理員以
同一個 http 位址登入後，安全政策頁上方也會出現對應提示。
**系統不會自行改動這個政策。**

**升級後才發現的話，不必再動部署檔**：以 admin 登入，在系統設定 → 安全政策把
「登入狀態僅在 https 連線保存」關掉並儲存，下一次發放的 cookie 即採用新值，不需重啟。

以 https 對外的部署不必做這一項，政策維持開啟就是正確設定。

> 這個政策只在沒有值的時候接受 `.env` 播種。播種過、或有人在安全政策頁存過之後，
> 再改 `.env` 不會有任何效果，調整一律回到安全政策頁。

> **已經確認政策是關閉的，登入頁卻還是說「系統設定卻是只在 https 連線保存登入狀態」**：
> 那則提示由前端依三個**本機**條件顯示——頁面以 http 開啟、這個分頁不曾成功續期過、
> 刷新終告失敗——**它不查政策的實際值**。因此一個全新的瀏覽器（或無痕視窗）第一次開登入頁，
> 即使政策已經關閉也會看到它。**判斷政策現況一律以安全政策頁的開關為準**；
> 成功登入之後不再出現，就是這個情形，不必去追一個不存在的設定問題。

### 2.1 升級前備份（必要，不可略過）

依[備份與還原 §3.2](./backup-and-restore.md#32-建議程序服務停機一致性最佳)執行**停機備份**。

升級前的備份必須是停機備份，不接受不停機備份：升級失敗時要還原的是一個一致的時點，
而不是一個「資料庫與錄影差幾分鐘」的時點。

同時確認：

- 備份檔可讀——即[備份與還原 §3.2](./backup-and-restore.md#32-建議程序服務停機一致性最佳) 的步驟 6
  （走容器內的 `pg_restore --list` 與 `tar -tzf`，不要求操作機安裝 PostgreSQL 用戶端）。
- KEK 材料在手（模式 A 的 `.env`、模式 B 的解封材料、模式 C 的 KMS 存取）。
- 已記錄金鑰清冊的四個指紋（`ENCRYPTION_KEY (KEK)`、`JWT_SECRET`、
  `匯出簽章鑰 (Ed25519)`、`檢查點簽章鑰 (Ed25519)`）。
- **已記下幾張業務表的列數**，供 §2.5 升級後核對「接到的是同一份資料」：

  ```bash
  docker compose -f docker-compose.yml exec -T postgres \
    psql -U "${DB_USER:?}" -d "${DB_NAME:?}" -tAc \
    "SELECT 'users', count(*) FROM users
     UNION ALL SELECT 'sessions', count(*) FROM sessions
     UNION ALL SELECT 'audit_logs', count(*) FROM audit_logs"
  ```

### 2.2 建置驗證（部署新映像前）

**適用對象是自行建置映像者**：此步驟需要完整的原始碼樹（`docker-compose.yml` 與各 Dockerfile
都在建置範圍內）。以交付的映像部署、手上沒有原始碼樹者，此步驟不適用，跳到 §2.3。

> **新版原始碼樹放在另一個目錄時，先處理 `.env` 裡的相對路徑。**
> 正式版 compose 的三個資料落點（`postgres`／`recordings`／`audit`）全是
> `${DATA_PATH:-./data}` 的 **bind mount，沒有任何 named volume**；而 `docker compose`
> 解析相對路徑的基準是**該 compose 檔所在的目錄**。
> 因此把既有部署的 `.env` 原封複製到另一個目錄下的新原始碼樹之後，`DATA_PATH=./data`
> （範本出廠值）指的是**新目錄底下那個還不存在的空 data**，不是原本那份資料。
> 服務會照常起來、當作新裝把 baseline 從頭跑一次，而且**不會有任何錯誤訊息**——
> 系統無從分辨「這是新裝」與「你接錯了目錄」。
>
> **做法**：升級前把 `.env` 的 `DATA_PATH` 改成**絕對路徑**（例如 `DATA_PATH=/opt/custodexa/data`），
> 或確認它在新目錄下仍指得回原本的資料目錄。`.env` 內其他以 `./`、`../` 開頭的路徑設定
> 同樣要逐一檢查。在原目錄就地更新原始碼與映像者不受影響。
>
> `COMPOSE_PROJECT_NAME` 不提供保護：它隔離的是容器與網路的命名，不是 bind mount 的落點。
> 萬一還是接錯了，怎麼在還沒造成損失前發現，見 §2.5 的「升級後第一件事」。

> **建置會覆蓋同名 tag：先把現行映像另存一份，否則沒有東西可回退。**
> 三顆映像的參照都是 `:latest`（`custodexa/backend:latest`、`custodexa/frontend:latest`、
> `custodexa/guacd:latest`），新版建置一跑，現行運作中的那三顆就不再有名字可指。
> 回退程序（§4.2 步驟 2）要的正是它們。**在下面的 `build` 之前**先執行：
>
> ```bash
> for img in backend frontend guacd; do
>   docker tag "custodexa/${img}:latest" "custodexa/${img}:pre-upgrade"
> done
> docker images | grep pre-upgrade    # 三行都在，才往下建置
> ```
>
> 以交付映像部署者同理：**保留舊版映像檔或確認 registry 上該版本仍取得到**，
> 不要只靠 `:latest`。

於專案根對正式版 compose 的全部 build 目標執行一次真實建置，任一目標失敗即不得部署：

```bash
docker compose -f docker-compose.yml build
```

**一律顯式帶 `-f docker-compose.yml`**：本機 `.env` 若設有 `COMPOSE_FILE`，不帶旗標時
建到的可能不是正式版目標。正式版與開發版的映像名已分離（`custodexa/*:latest` 與
`custodexa/*:dev`），故建置正式版不會覆蓋開發版映像。

建置成功後，另核對一項正式版才有的性質：**backend 映像內不存在可執行的 shell 解譯器**
（資料庫 CLI 的逃逸面因此在結構上關閉）：

```bash
for sh_path in /bin/sh /bin/ash /bin/bash /usr/bin/sh; do
  docker run --rm --entrypoint "$sh_path" custodexa/backend:latest -c true 2>/dev/null \
    && echo "FAIL: ${sh_path} 仍可執行"
done
```

**沒有任何 `FAIL` 輸出**才算通過；印出 FAIL 代表該建置的映像不符本版的執行環境前提。

**改動了 Dockerfile、`.dockerignore` 或 compose 的 build 區塊後，此步驟為必跑。**

#### 換基底映像版本時，授權文件要跟著改

全部出貨基底皆已釘到具體版本（`alpine:3.24.1`、`nginx:1.31.3-alpine3.24`、
`guacamole/guacd:1.6.0`、`postgres:16.15-alpine3.24`）。
`THIRD-PARTY-LICENSES.md` 第 3 節對外承諾「提供這些映像內 GPL／LGPL 元件的對應源碼」，
而「對應」的前提是版本可指名。基底一浮動，承諾就無法履行。

因此**動了任何 `FROM` 行的版本，同一個 commit 內必須連帶更新**：

1. `THIRD-PARTY-LICENSES.md` §3.1 的版本表——三欄都要重讀，不可只改一欄：
   Dockerfile 內的釘定值、映像內 `/etc/alpine-release` 實測值、GPL／LGPL 套件數。
   實測指令（三個映像各跑一次，`<img>` 換成 `custodexa/backend:latest` 等）：

   ```bash
   cid=$(docker create <img>)
   docker cp "$cid":/etc/alpine-release - | tar -xO
   docker cp "$cid":/lib/apk/db/installed - | tar -xO \
     | awk '/^P:/{p=substr($0,3)} /^L:/{if (substr($0,3) ~ /GPL/) print p}' | wc -l
   docker rm "$cid"
   ```

2. `THIRD-PARTY-LICENSES.md` §3.2 的 aports 分支名——Alpine major 版跳號時
   `3.24-stable` 會變成別的分支，指向舊分支的源碼連結即失效。
3. §2.8 的發佈存檔（新版本＝新的一份清單，舊版本的三年期不因升級而終止）。

> **換基底後須重新做一次授權盤點。** 請以貴方既有的 SBOM／授權掃描工具
> （如 `syft`＋`grype`、`trivy`）對三顆正式版映像各執行一次，
> 判準是「每個套件至少有一個 OSI 認可的授權選項」，確認新基底沒有引入
> 不符該判準的套件。
>
> **無論用哪個工具，它都不會檢查上述文件是否同步；那是人工項。**

### 2.3 停機

**選擇低流量時段。** 理由見第 3 節：優雅關閉有兩個殘留缺口，流量越低，受影響的
審計列越少。

停機前的順序：

1. **停止新連線進入**（於前端反向代理層擋掉，或公告維護視窗）。
2. **等待進行中的會話結束**，或依營運判斷主動終止。
3. **確認審計佇列已排空**（見 §2.4）。
4. 送出停止指令：`docker compose stop`（會送 SIGTERM，走優雅關閉路徑）。
5. **首次升級到守衛版的檢核**（來源版本不含單實例守衛時必做；之後每次升級照做也無害）。
   守衛在這個窗口**不提供保護**：舊版不持鎖，新版起來一定取得到鎖。兩項都要成立才能進 §2.5：
   - `docker compose ps` 沒有 backend 在跑。曾在其他主機、或以另一個 compose project
     （例如開發版與正式版並存）指向同一資料庫起過實例的，每一處都要看。
   - 應用帳號在資料庫上的連線數為 0（`DB_USER`／`DB_NAME` 自 `.env` 取得，取法見
     [備份與還原 §2.3](./backup-and-restore.md#23-本文-shell-指令如何取得部署變數動手前先讀)）：

     ```bash
     docker compose -f docker-compose.yml exec -T postgres \
       psql -U "${DB_USER:?}" -d "${DB_NAME:?}" -tAc \
       "SELECT count(*) FROM pg_stat_activity
        WHERE datname = current_database() AND usename = current_user
          AND pid <> pg_backend_pid()"
     ```

     `pid <> pg_backend_pid()` 排除的是這條 psql 自己的連線。**非 0 ＝舊實例還在，
     或它的工作階段尚未被回收，不得部署**：回頭找出它並停掉，再查一次直到為 0。
   - 判讀：**新版起來後取得鎖，不能當作舊版已停的證據。** 這一步的證據只有上面兩項。

### 2.4 停機前確認審計佇列已排空

指標 `custodexa_audit_queue_depth` 曝露審計非同步寫入佇列的目前深度。

**此端點自外部打不到**（見下方第一點），所以取用方式是自 backend 容器內打：

```bash
# METRICS_TOKEN 為空（預設）時
docker compose exec -T backend \
  wget -qO- http://localhost:8080/metrics | grep custodexa_audit_queue_depth

# METRICS_TOKEN 有設值時（token 未帶或不符一律回 401 且回應體不含任何指標）
docker compose exec -T backend \
  wget -qO- --header="Authorization: Bearer <token>" http://localhost:8080/metrics \
  | grep custodexa_audit_queue_depth
```

- **端點**：`/metrics`，掛在 backend 自己的 HTTP 服務（容器內 8080）上。
  **刻意不在 `/api` 之下**：正式版的 edge 只代理 `location /api` 與 `/ws`。
  加上正式版 compose 只對外發佈 nginx 的 80 埠、backend 的 8080 不發佈，
  此端點在預設部署下只在 compose 網路內可達，自外部打不到。
  若貴方另行把 backend 接進可直達的內部網路（供 Prometheus 採集），
  自該處以 `curl -s http://<backend>:8080/metrics` 取用亦可。
- **認證**：`METRICS_TOKEN` 環境變數非空時，須帶 `Authorization: Bearer <token>`；
  為空時免認證曝光（安全性由「edge 不代理」承擔）。
- **判準**：值為 `0` 再停機。
- **這個指標只在系統已解封時存在**。封印狀態下 `/metrics` 回得出來，但裡面只有封印狀態
  與單實例守衛那兩組，`grep` 不到 `custodexa_audit_queue_depth`——**那不是指標壞了，
  是非同步審計還沒起來**（它與其餘業務元件同屬解封後才裝配的段 2）。
  採 `KEK_PROVIDER=ui`（模式 B）者尤其會遇到：backend 每次重啟都回到封印，
  包含[備份與還原 §3.2](./backup-and-restore.md#32-建議程序服務停機一致性最佳)的例行備份之後。
  **封印狀態下沒有審計佇列可排空**，先解封再做這項確認。

> **這個指標的邊界**：它讀的是佇列本身的長度，代表「還有多少列尚未被 worker 取走」。
> **值為 0 不等於「全部審計列都已經寫進資料庫」**：worker 手上可能還握著一批尚未
> flush 的列。它能排除的是「佇列裡積著一堆還沒人碰過的列」這種明確會掉資料的情況，
> 這正是低流量時段停機要確認的事。
>
> 另：佇列只在非同步審計啟用時存在。同步模式下寫入直接阻塞完成，此指標恆為 0。

### 2.5 部署新版本

```bash
docker compose -f docker-compose.yml pull    # 或依交付方式載入新映像
docker compose -f docker-compose.yml up -d
```

資料庫 migration 於後端啟動時自動執行。**啟動日誌是判斷 migration 是否成功的唯一依據**，
不要在沒看日誌的情況下宣告升級完成。

升級到**未引入任何新 migration** 的版本時（資料庫已套用過 baseline 與全部既有增量），日誌會出現：

```
開始執行 database migrations...
  跳過已執行的 migration: 20260816_schema_baseline (schema_baseline)
所有 migrations 都已執行，無需更新
```

**升級到引入新增量 migration 的版本時**，每套用一條就多出一行 `執行 migration: <版本> (<名稱>)`，
該增量在同一交易內套用；未見對應行即代表該增量**未跑**（多半是來源版本已含它），非異常。
本版的兩條增量對應的日誌行逐字為：

```
  執行 migration: 20260824_audit_export_jobs (audit_export_jobs)
  執行 migration: 20260826_source_ip_forensics (source_ip_forensics)
```

`20260826_source_ip_forensics` 除了建表與加欄之外還做一次**冷啟動回填**（自既有會話全史與
登入成功紀錄整理出每個帳號已見過的來源位址），使升級當下已經看得到的位址不會觸發
新來源位址告警。回填的耗時隨 `sessions` 與 `audit_logs` 的存量成長，請把它算進停機視窗；
正式升級前建議先在資料量相當的複本環境試跑一次，量出實際耗時再敲定停機視窗。

**本版另有一次性的剪貼簿內容加密轉換**（`content` → `content_enc`）：它需要 codec，
故不在上述段 1 migration 內，而在 **KEK 解封後（段 2）** 執行，完成時日誌印出
`[ClipboardMigration] 剪貼簿內容加密轉換完成：<N> 筆既有列已回填，明文欄已移除`。
此轉換以「`content` 欄是否存在」判冪等（升級後重啟不會重跑），回填失敗即整段 rollback、
保留明文欄（fail-close）。**KEK 未解封前不會執行**——採介面填鑰（模式 B）者，
須完成解封才會走到這一步。

全新的空資料庫則會看到 baseline 實際執行並印出建立的 DDL 條數與內建告警規則條數。
**若看到的是拒絕啟動訊息，停下來讀 §2.6。**
**若看到的是 `CRITICAL：單實例鎖由另一個資料庫工作階段持有`，停下來讀 §2.6b**——
migration 那幾行不會出現，因為守衛的判定在 migration 之前。

#### 升級後第一件事：確認接到的是原本那份資料

**既有部署的升級，日誌裡不該出現 baseline 實際執行**。看到下面這兩行，就是後端接到了
一個**空的資料目錄**、正把它當新裝建庫：

```
  執行 migration: 20260816_schema_baseline (schema_baseline)
  baseline schema 已建立：<N> 條 DDL、<M> 條內建告警規則
```

**立刻停手**：`docker compose -f docker-compose.yml stop`，不要登入、不要讓使用者進來、
不要做任何寫入。成因幾乎都是 §2.2 講的那一格——`.env` 的 `DATA_PATH` 是相對路徑，
而新版原始碼樹在另一個目錄。原本那份資料還在原目錄、一個位元都沒被動到；
把 `DATA_PATH` 指回去（或改成絕對路徑）再重來即可，錯的目錄下那份剛被建出來的空資料直接刪掉。
繼續操作才會開始在錯的目錄上累積新資料。

**這個失敗沒有錯誤訊號**：後端會正常啟動、`/health` 會回 ok、前端也起得來，
只是資料庫裡什麼都沒有。§2.7 的前五項全部會過。
（採介面填鑰（模式 B）者另有一個間接訊號：空庫沒有既有的 KEK，畫面會要求**初始化** KEK
而不是解封。看到這個就不要初始化，先回頭查 `DATA_PATH`。模式 A 與模式 C 連這個訊號都沒有。）

不翻日誌的等價檢查，兩條各做一次：

```bash
# 1. 升級前既有的那些列還在嗎
docker compose -f docker-compose.yml exec -T postgres \
  psql -U "${DB_USER:?}" -d "${DB_NAME:?}" -tAc \
  "SELECT version FROM schema_migrations ORDER BY version"

# 2. 業務列數與 §2.1 備份前記下的數字對得上嗎
docker compose -f docker-compose.yml exec -T postgres \
  psql -U "${DB_USER:?}" -d "${DB_NAME:?}" -tAc \
  "SELECT 'users', count(*) FROM users
   UNION ALL SELECT 'sessions', count(*) FROM sessions
   UNION ALL SELECT 'audit_logs', count(*) FROM audit_logs"
```

判讀：**第 2 條是決定性的**——回「1 個使用者、0 場會話、寥寥數列審計」就是空庫。
第 1 條輔助：解封過至少一次的部署，`schema_migrations` 內除了 migration 版本之外
還會有**執行期標記列**（本版為 `20260804_ldap_env_seeded`，LDAP env→DB seed 的冪等標記，
不是 migration），全新庫在第一次解封前沒有它。

> 這個順序不能顛倒：**先確認資料接對了，再做 §2.7 的其餘驗證**。
> §2.7 驗的是「新版跑得對不對」，它不會告訴你「跑的是不是你那份資料」。

### 2.6 若後端拒絕啟動並指出 `schema_migrations` 有不認識的版本

這是 1.0 刻意的 fail-close，資料庫本身沒有損毀。

**訊息形態**（節錄）：

```
拒絕啟動：資料庫的 schema_migrations 內有 N 筆本版程式碼不認得的 migration 版本：…
  本版本以單一 schema baseline（20260816_schema_baseline）作為 schema 的唯一事實源，
  壓縮前的逐條 migration 已不存在，因此不提供既有資料庫的就地升級路徑。
```

**它的意思**：這個資料庫是 baseline 世代**之前**建立的。本版程式碼看不懂它的 schema 形狀。

**判定發生在任何寫入之前**：走到這一步時資料庫一個位元都沒動。這是刻意的設計：
若讓 baseline 對既有庫跑下去，最好的結果是建表衝突而中止，最壞的結果是種子資料重複寫入
而使告警靜默翻倍。

**處置**：

1. **開發環境**：重建一個空的資料庫即可。
2. **正式環境**：可行的路徑是以新的空資料庫做新裝，既有資料的移轉屬專案性工作。
   請在此停下並與交付方確認，不要自行嘗試繞過。
3. **絕對不要手動刪除 `schema_migrations` 的列來繞過本檢查。**
   baseline 的建表語句是無條件的（無 `IF NOT EXISTS`），第一句 `CREATE TABLE` 就會撞上
   既有表而中止，留下的是一個**既非舊版也非新版**的資料庫，而你已經破壞了唯一能判斷
   它是哪一版的那張表。

> **一個容易誤判的正常情形**：`schema_migrations` 內除了 baseline 之外，還會有模組寫入的
> **執行期冪等標記**（現況唯一一個是 LDAP 的 env→DB seed 標記）。這些**不是** migration，
> fail-close 的判定已把它們扣除，故它們的存在不會觸發拒絕啟動。

### 2.6b 若後端被攔下並指出單實例鎖由另一個資料庫工作階段持有

這是本版的單實例守衛，資料庫本身沒有損毀。守衛的保證是「第二個實例不會在你不知情下運作」，
不是「不會有第二個實例」；本段結尾的「確認的意思」會再說一次。

**訊息形態**（節錄自 2026-08-25 的實走；`pid`、時間與 `code` 隨每次衝突不同）：

```
[InstanceGuard] 等待既有實例釋放單實例鎖（第 1/5 次，2s 後重試）
…
[InstanceGuard] 等待既有實例釋放單實例鎖（第 4/5 次，2s 後重試）
CRITICAL：單實例鎖由另一個資料庫工作階段持有。本版不支援多實例部署，本實例未啟動服務。
  持鎖者：application_name=custodexa-instance-guard pid=8510 backend_start=2026-08-25T10:04:22.2442Z code=55bd875b8d97
  風險：兩個實例同時執行會造成金鑰快取、匯出工作、錄影落地與封印期留痕的資料問題（見 docs/ops/deployment-topology-limits.md）。
  處置 (a)：若確認另一實例仍在執行：先停止它，再重啟本實例（無需任何設定）。
  處置 (b)：若確認無其他實例在執行（例如持鎖者是主機當機後殘留的工作階段）：設定環境變數 INSTANCE_GUARD_ACK=55bd875b8d97 後重啟。本次啟動會寫入審計事件並在管理介面顯示橫幅，直到鎖由本實例取得。
  澄清：這不是資料庫損毀；本次啟動未由本實例執行 migration 或任何資料寫入；INSTANCE_GUARD_ACK 綁定上列指紋，持鎖者變更後失效；確認後兩實例並存造成的資料問題由確認者承擔，守衛只保證此事被記錄。
```

**它的意思**：資料庫裡有另一條工作階段持有本系統的單實例鎖。守衛分不出那是活著的實例
還是殘留的工作階段，所以把判斷交給你。前面的等待行是刻意的：前一個行程剛退出時，資料庫要幾毫秒
才回收它的工作階段，守衛等 5 次、每次 2 秒（約 10 秒），等完仍被持有才印這一段。

**判定發生在任何寫入之前**：本實例未執行 migration、未寫入任何資料、未開放監聽。行程以離開碼 1 結束，
與其他啟動期 fatal 相同；守衛沒有專屬離開碼。

**持鎖者那一行怎麼讀**：

| 欄位 | 意思 |
|---|---|
| `application_name=custodexa-instance-guard` | 持鎖者是守衛版實例的守衛連線。空值或別的名字＝持鎖者不是本系統的守衛連線，不在本段範圍，交資料庫管理者 |
| `pid` | 持鎖工作階段在 postgres 內的行程 id，**不是**容器內的應用行程 id |
| `backend_start` | 該工作階段建立的時間。比現在早很多、又找不到活著的實例，是殘留工作階段的典型樣子 |
| `code` | 確認碼：上面三欄的雜湊前 12 碼。換了持鎖者就換碼 |

若這一行寫的是「無法取得持鎖者細節（pg_stat_activity 查詢失敗或無權限），降級確認碼為 code=…」：
守衛查不到持鎖者。降級碼不綁定特定工作階段，只綁「查不到」這件事；以它啟動後，審計事件的
`holder.fingerprint_source` 會是 `unavailable`。同時去查應用帳號對 `pg_stat_activity` 的讀取權限是否被動過。

**處置（兩條擇一；全程不需要對資料庫做任何操作）**：

1. **另一個實例還在跑**：停掉它，再重啟本實例。不需要設任何東西——前一個實例一停，鎖就釋放。
   每一台可能起過本系統的主機、每一個指向同一資料庫的 compose project 都要看
   （開發版與正式版 compose 各自是一個 project，同時起就是兩個實例）。
2. **確認沒有其他實例在跑**（上述各處都看過，持鎖者是殘留的工作階段）：把訊息裡的碼設進 `.env` 後重啟。

   ```bash
   # .env 加一行；值取自訊息的 code=，只對這一次衝突有效
   INSTANCE_GUARD_ACK=55bd875b8d97
   ```

   ```bash
   docker compose -f docker-compose.yml up -d backend
   ```

   啟動日誌應出現
   `CRITICAL：以 INSTANCE_GUARD_ACK 啟動：單實例鎖仍由 … 持有；本實例將照常執行 migration 與服務；此確認已記錄（actor=operator via env）`，
   接著是正常的 migration 與監聽日誌。**啟動成功後即可把該行自 `.env` 移除**，不需要再重啟：
   它只對這一次衝突有效，留著也是惰性的（下次無衝突啟動只會印一行
   「INSTANCE_GUARD_ACK 已設定但本次未偵測到衝突，未使用；建議自環境移除」）。

**確認的意思（設 `INSTANCE_GUARD_ACK` 之前先讀完）**：

- 它綁定訊息裡那一組持鎖者指紋。持鎖者一變（另一個實例起來了、或殘留被回收後又有新的持鎖者），
  這個碼就失效，守衛會再攔一次並印新碼。錯的碼視同沒設：訊息多一行
  `提供的 INSTANCE_GUARD_ACK 與當前持鎖者指紋不符（持鎖者已變更），請以上列 code 重新確認`，且不寫審計事件。
  所以它不能常設來關掉守衛。
- 每一次以它啟動都寫一筆 `audit_logs`：`resource=instance_guard`、`status=failure`、details 含 `event=overridden`、`ack`、
  持鎖者指紋（`holder.*`）、本實例 `instance.hostname`／`pid`／`started_at`、`actor="operator via env"`。
  採介面填鑰（模式 B）者，這一筆在解封後才落庫，時間戳仍是啟動當下。
- `actor="operator via env"` 的意思是**系統不知道是誰設的**。環境變數識別不了自然人；
  誰在何時設了它，由貴方的變更管理承擔，請把這次確認記進變更單。
- 確認後守衛**不再做任何攔阻**：migration 照跑、服務照開、背景工作照跑。若你的判斷錯了、另一個實例其實還活著，
  兩個實例會同時寫同一個資料庫，訊息「風險」行列的資料問題**會發生，守衛不防止**，由確認者承擔。
- 以確認碼啟動的實例每個週期（15 秒）重試取鎖。取得前，管理介面對所有登入者顯示常駐橫幅
  「本實例以確認碼啟動，單實例鎖仍由另一個資料庫工作階段持有」（管理者另看得到指紋與確認碼），
  指標 `custodexa_instance_guard_overridden` 為 1。殘留的工作階段由 postgres 依作業系統的 TCP keepalive 回收
  （postgres 容器未另行設定，走 Linux 預設約 2 小時）；回收後守衛自動取得鎖、橫幅消失、
  `audit_logs` 多一筆 `event=regained`（`reason=ack_startup`）。**不需要重啟。**
- 若另一個實例其實在跑而你選了處置 2，那個實例的橫幅會出現「偵測到 1 個其他實例連線到同一資料庫」。
  這是它知情的方式，不是錯誤。

**選配的診斷：持鎖者是活的實例還是殘留？**（不是救援必經；上面兩條處置不需要它）

以鎖鍵連接 `pg_locks` 與 `pg_stat_activity` 是權威查法，`application_name` 只是輔助。以應用帳號執行
（`DB_USER`／`DB_NAME` 自 `.env` 取得，取法見
[備份與還原 §2.3](./backup-and-restore.md#23-本文-shell-指令如何取得部署變數動手前先讀)）：

```bash
docker compose -f docker-compose.yml exec -T postgres \
  psql -U "${DB_USER:?}" -d "${DB_NAME:?}" -c "
SELECT a.pid, a.usename, a.application_name, a.backend_start, a.state, a.state_change
FROM pg_locks l
JOIN pg_stat_activity a ON a.pid = l.pid
WHERE l.locktype = 'advisory'
  AND l.classid = 1869900645 AND l.objid = 1795162116 AND l.objsubid = 1
  AND l.granted
  AND l.database = (SELECT oid FROM pg_database WHERE datname = current_database());"
```

- `classid`／`objid` 是守衛鎖鍵 `0x6F746B656B000004` 拆成的兩個 32 位元整數；`objsubid = 1` 是 64 位元 advisory lock 的固定值。
- **`l.database = …` 這一行不可省略。** `pg_locks` 是整個叢集的視圖，advisory lock 卻是每個資料庫各自一套；
  不過濾會把別的資料庫裡持同一鍵的工作階段當成持鎖者（2026-08-25 於 compose 內實測：在維護庫查到的是
  `custodexa` 庫的持鎖者）。
- 判讀：`backend_start` 早於你所知最後一次正常停機、且各主機都找不到活著的實例＝殘留，走處置 2；
  找得到活著的實例＝走處置 1。
- 欄位可見性（**postgres 16.15 實測，不是文件保證**：官方文件只說其他角色的工作階段「許多欄位為 NULL」，未逐欄列出）：
  持鎖者與查詢者是同一個應用帳號時，全欄可見；持鎖者屬別的角色時，`application_name` 可見、
  `backend_start` 為 NULL——這時守衛的指紋以 `-` 代入該欄，確認碼仍由 `pid` 與 `application_name` 綁定。
  `state`／`state_change` 對別的角色的工作階段本文未實測，可能為 NULL。貴方的 postgres 版本若不同，以實際輸出為準。
- 權限：`pg_locks` 所有角色可讀；`pg_stat_activity` 對自己角色的工作階段全欄可讀，對其他角色只看得到存在與一般屬性。
  查詢被拒（`permission denied`）或欄位全空時，改以維運帳號執行或交資料庫管理者，**不要為此擴權**：
  **不得把 `pg_signal_backend`、`pg_read_all_stats` 或超級使用者授予應用帳號**。
- 這段是診斷，不是處置。查完仍回到上面兩條；**不要終止資料庫的工作階段**——守衛的救援路徑不需要，
  而你終止到的可能是另一台主機上活著的實例。

> **一個容易誤判的正常情形**：正式版 compose 的 backend 設 `restart: always`。被攔下的容器每次退出後
> 會被重新拉起、再等約 10 秒、再被攔下，日誌裡同一段訊息反覆出現。這不是故障，是它在排隊：
> 前一個實例一停、或你設了確認碼，下一輪它就進門。看到反覆的訊息，讀最新一次的 `code=` 即可
> （持鎖者沒變，碼就不變）。

### 2.7 升級後驗證

跑 `docs/QUICKSTART.md`「部署驗證」段的五步：

1. `docker compose ps` — 全部服務起來且 postgres healthy。
2. `docker compose exec backend wget -qO- http://localhost:8080/health` — 後端健康檢查
   （backend 不對外開埠，且 `/health` 不在 nginx 代理路徑內，故走容器內）。
3. `curl -I http://localhost/` — 前端可達。
4. 登入鏈路通。
5. `docker compose logs backend | tail -30` — 啟動日誌無 fatal；release 的 fail-close
   都會出現在這裡。單實例守衛也在這裡：正常升級應看到一行
   `[InstanceGuard] 單實例鎖狀態=held hostname=… pid=… started_at=… db_session_pid=…`，
   看到 `CRITICAL：單實例鎖由另一個資料庫工作階段持有` 讀 §2.6b。

再補三項升級特有的檢查：

6. **金鑰清冊四個指紋與升級前相同**（升級不應改動任何金鑰；指紋變了代表出了別的事）。
   清冊的 env 側共四項：`ENCRYPTION_KEY (KEK)`、`JWT_SECRET`、`匯出簽章鑰 (Ed25519)`、
   `檢查點簽章鑰 (Ed25519)`。**四項都要比**——只比前三項的話，檢查點簽章鑰換掉了不會被發現。
7. **審計鏈驗證**通過，且序列未出現非預期斷點。
8. 抽驗一筆升級前的既有會話錄影可播放。
9. **實跑一次端到端稽核驗證**：建立一條測試連線（SSH 或資料庫皆可）、執行數條可辨識的
   指令，再到稽核介面確認**該會話的指令確實出現**。

> **第 9 項不可省略。** 後端啟動成功**不蘊含**稽核仍在運作，兩者是不同的機制：啟動只
> 驗證程式跑得起來與 migration 已套用，而稽核寫入失敗時的既有設計是**不中斷連線**
> （避免審計故障變成使用者被踢線）。因此若連線正常、操作正常，但稽核紀錄為空，
> 那是稽核寫入層的問題，**不會有任何錯誤訊息告訴你**；實跑是唯一能發現它的方式。

> 開發機驗證正式版時，上列指令一律加顯式 `-f docker-compose.yml`（覆蓋 `.env` 的 `COMPOSE_FILE`）。

### 2.8 發佈時的 GPL 對應源碼記錄（散布映像者適用）

**適用對象：把自建映像交給第三方的人**（本專案的發佈者，以及任何自行建置後再散布的人）。
只在自己機房內部署、不對外交付映像者，本節不適用。

映像內含來自基底映像（Alpine）的 GPL／LGPL 二進位。`THIRD-PARTY-LICENSES.md` §3.2
以**指向上游來源**的方式履行對應源碼義務（GPLv3 §6(d)／GPLv2 §3 末段），
而該方式成立的前提是：**能指出「這一版映像裡的二進位，對應的是哪一份源碼」**。

因此發佈每個版本時記錄以下兩樣即可（各數 KB、耗時數秒）：

```bash
VERSION=<本次發佈的 tag>
mkdir -p "release-archive/$VERSION"

# 1. 三個映像的完整套件清單（含版本）——「對應源碼」對應的是哪些套件，由這份清單定義
for img in custodexa/backend custodexa/frontend custodexa/guacd; do
  cid=$(docker create "$img:$VERSION")
  docker cp "$cid":/lib/apk/db/installed - | tar -xO > "release-archive/$VERSION/${img##*/}-apk-installed.txt"
  docker rm "$cid"
done

# 2. 對應的 aports commit（版本鎖定的錨；分支會前進，commit 不會）
#    兩條分支都要記：3.24-stable 對應 backend／frontend 映像的 Alpine 基底，
#    3.18-stable 對應 guacd 的上游基底（見「部署形態限制」）。漏記一條，
#    該顆映像就沒有可指名的對應源碼。
for br in 3.24-stable 3.18-stable; do
  git ls-remote https://gitlab.alpinelinux.org/alpine/aports.git "refs/heads/$br" \
    >> "release-archive/$VERSION/aports-refs.txt"
done
```

**為什麼記這兩樣就夠**：

Alpine 的上游源碼可得性相當穩固：aports 保有 2014 年至今的全部 `*-stable` 分支
（命名多年未變），EOL 分支的套件索引仍可存取，distfiles 只累積不修剪
（已 EOL 約五年的分支抽樣實測，套件源碼仍全數可下載）。
因此指出「哪一版對應哪份源碼」即可，不需要自行囤積源碼。

已知的可用性風險（非合規缺口）：Alpine 未就保存期作書面承諾，
且 `distfiles.alpinelinux.org` 目前為單一主機、官方鏡像站不含 distfiles 路徑。
若貴方的風險偏好要求證據自足，見下方說明。

**若貴方的風險偏好要求自持一份**（例如受監理產業要求證據自足），建議的範圍是
**只鏡像 GPL／LGPL 套件的 distfiles tarball ＋ 該版 APKBUILD 快照**，
並將保存期綁在「該映像 tag 仍可下載」而非固定年限。
**但對外不得將其表述為「承諾三年內應要求提供」**；那會把一個較輕的義務
（可隨下架終止）自願升級為較重的義務（自最後散布起三年、且不隨下架終止）。

## 3. 停機對進行中非同步寫入的影響

**送出 SIGTERM 會走優雅關閉路徑，審計 worker 會 flush 自己手上的批次。**
這一點成立，不是空話。

但有**兩個殘留缺口**，操作者必須知道：

### 3.1 worker 不排空佇列即返回

worker 收到關閉信號時，flush 的是**自己手上已累積的批次**，然後直接返回。
**它不會把佇列中尚未取走的列讀完再走。** 停機當下仍留在佇列裡的審計列會遺失。

這正是 §2.4 要求「停機前確認 `custodexa_audit_queue_depth` 為 0」的原因。

### 3.2 全部收束步驟共用單一 5 秒逾時

關閉時的各個步驟（解封端點獨立監聽、主監聽、段 2 資源含審計服務）**共用同一個 5 秒
context**。若前面的步驟耗掉了大部分時間，留給審計 flush 的時間就所剩無幾。

逾時的行為是**記錄訊息並以非零離開碼結束**（不會跳過後續資源收束，非零碼留到最末端才生效）。
非零離開碼是 supervisor 與 CI 需要知道的事實，**也是操作者需要看的事實**：

```bash
docker compose logs backend | tail -20   # 找「關閉過程有未完成項目」
```

看到這行，就代表這次停機有審計列沒能寫完。

### 3.3 操作建議

- 低流量時段停機。
- 停機前先擋新連線、再等佇列歸零。
- 停機後檢查離開碼與日誌，確認沒有逾時訊息。
- 上述都做了仍可能有極少量遺失，這是本版停機路徑的已知邊界。

### 3.4 執行期失去單實例鎖：日誌、橫幅與稽核事件的判讀

這一段與停機無關，放在這裡是因為它和 §3.2 一樣關乎離開碼：**守衛沒有專屬離開碼，執行期失去鎖不會讓行程退出。**
失鎖的三個訊號是日誌、管理介面橫幅與 `audit_logs`；`/health` 不變、任何請求都不會因此被拒。

守衛每 15 秒在自己的釘選連線上查一次 `pg_locks`，確認鎖仍由本工作階段持有（查詢逾時 5 秒），
故**偵測延遲上界約 20 秒**。查到「未持有」或查詢出錯，守衛進入 `lost`：丟棄舊連線、重釘一條、
`custodexa_instance_guard_held` 轉 0、`custodexa_instance_guard_lost_total` 加 1、寫一筆 `audit_logs`
（`event=lost`、`reason=…`），然後**繼續服務**，每 15 秒重試取鎖，沒有上限。重取成功即回到 `held`：
`held` 轉 1、寫一筆 `event=regained`（含 `unheld_for_ms`），橫幅在介面下一次輪詢（60 秒內）消失。

**日誌行**（`grep '\[InstanceGuard\]'` 即可撈出；`reason=` 有四種）：

```
[InstanceGuard] CRITICAL：單實例鎖已失守（reason=<reason> lost_total=<n>）；本實例繼續服務、每週期重取，不阻擋任何操作
[InstanceGuard] CRITICAL：重取單實例鎖失敗（reason=contention）：鎖由另一個工作階段持有 [<持鎖者指紋>]；本實例繼續服務、下一週期再試
[InstanceGuard] 重取單實例鎖失敗（reason=db_unreachable，可重試；本行每分鐘至多一次）: <錯誤>
[InstanceGuard] CRITICAL：守衛無法驗證或重取單實例鎖（reason=<permanent|unknown>）；本實例繼續服務、下一週期再試: <錯誤>
[InstanceGuard] 已重新取得單實例鎖（自 <前一狀態：lost 或 overridden> 起未持鎖 <n> ms，reason=<失守前的 reason>）；告知解除
```

| `reason` | 意思 | 橫幅文字 | 下一步 |
|---|---|---|---|
| `contention` | 鎖被另一條工作階段拿走了；日誌與事件含它的指紋（`holder.*`）。最常見的來源：另一個實例在本實例失鎖的空檔起來了 | 本實例已失去單實例鎖：鎖由另一個工作階段持有 | 到各主機找出那個實例。它不該存在就停掉它，本實例下一週期取回鎖；它才是該留的，就停掉本實例。兩邊都在寫資料庫的這段期間，資料後果同 §2.6b「確認的意思」 |
| `db_unreachable` | 到資料庫的連線斷了（postgres 重啟、網路事件、查詢逾時）。此時所有需要資料庫的請求本來就會失敗，這一行只是守衛也看到了。重取失敗的日誌每分鐘至多一行；事件寫不進資料庫時落 JSONL 備援檔 | 本實例已失去單實例鎖：資料庫連線中斷 | 處理資料庫連線本身。連線恢復後守衛自動重取，不需要重啟 |
| `permanent` | 資料庫回了權限或物件類錯誤（例如應用帳號對 `pg_locks`／`pg_stat_activity` 的權限被收，SQLSTATE `42501`）。每週期一行 CRITICAL，不節流 | 本實例已失去單實例鎖：守衛無法驗證鎖狀態（權限或物件錯誤） | 查應用帳號在資料庫上的權限是否被動過，看日誌行尾的 SQLSTATE。修好後守衛自動重取 |
| `unknown` | 無法歸類的錯誤，處理方式同 `permanent` | 本實例已失去單實例鎖：原因不明 | 看日誌行尾的錯誤本文，交資料庫管理者或回報。守衛持續重取 |

`reason=ack_startup` 不是失鎖，是 §2.6b 處置 2 的狀態：以確認碼啟動、尚未取得鎖。它的 `regained` 事件也帶這個 reason。

**`audit_logs` 怎麼查**：稽核頁的資源篩選選「單實例守衛」，或直接查 `resource = 'instance_guard'`。三種事件：

| `details.event` | `status` | 何時 | 專屬欄位 |
|---|---|---|---|
| `overridden` | `failure` | 以確認碼啟動的當下 | `ack`、`actor="operator via env"`、`holder.*` |
| `lost` | `failure` | 執行期進入 `lost` | `reason`；`contention` 時另有 `holder.*` |
| `regained` | `success` | 自 `lost` 或 `overridden` 回到 `held` | `unheld_for_ms`、`reason`（失守前的原因） |

每筆都有 `instance.hostname`／`pid`／`started_at`、`db_session_pid`、`lost_total`；不含連線字串、密碼、主機位址、`client_addr`。
`overridden` 與 `lost` 記 `failure` 的意思是「互斥不成立」，不是「行程壞了」：篩 `failure` 就能撈到全部失守時刻。
事件走非同步稽核（at-most-once），資料庫寫不進時落 JSONL 備援檔，不宣稱必達。啟動段 2 稽核服務接上之前發生的事件先暫存在行程內緩衝，**上限 16 筆**，超過時丟最舊——只影響啟動最初幾秒，正常情況不會觸及。

**橫幅**：狀態非 `held`、或持鎖實例偵測到其他守衛版實例連線（`custodexa_instance_guard_peers` 大於 0，
日誌另有一行 `偵測到 <n> 個其他守衛版實例連線至同一資料庫`，每 10 分鐘至多一次）時，
管理介面對所有登入者顯示常駐橫幅，沒有關閉鈕；介面每 60 秒輪詢 `GET /api/v1/seal/status` 更新。
管理者在橫幅內看得到持鎖者指紋、確認碼、本實例主機名／行程 id 與處置說明
（來自 `GET /api/v1/instance-guard`，每次查看留一筆讀取審計）。狀態回到 `held` 且無對等連線，橫幅自動消失。

**守衛不會做的事**（判讀時別等它做）：不拒絕請求、不暫停背景工作、不退出行程、不終止別的資料庫工作階段。
失鎖到你介入之間的寫入沒有被擋，這是本版刻意的取捨：誤判時自動阻擋會讓你無法救援。

---

## 4. 回退路徑

### 4.1 回退的唯一手段是還原備份

升級後若要退回舊版本，走的是「部署回舊版映像，再還原升級前的備份」，程序見 §4.2。

本版的資料庫有**三條** migration：schema baseline（`20260816_schema_baseline`）
與其後的兩條增量（`20260824_audit_export_jobs`、`20260826_source_ip_forensics`）。
**三條都不提供把資料退回升級前狀態的手段。**

baseline 的 `Down` 一律回拒絕錯誤。它建的是**整個資料庫 schema**，執行它的 `Down` 等於
刪掉全部資料表，使用者、資產、授權與審計證據一併消失，而不是還原到某個較舊的 schema 形狀，
故該路徑一律回錯，把退路指回還原備份。

**`20260824_audit_export_jobs` 的 `Down` 存在且會刪掉該表**（表內只有匯出工作的狀態，
產物與審計證據都不在其中，故 `DB_SCHEMA.md` 稱它「可棄可逆」——那是說**刪表不會失去證據**，
不是說它能當回退手段）。它同樣**沒有生產入口**：`RollbackMigration` 全樹只有測試呼叫它，
而且刪表不會把任何資料還原成升級前的樣子。

**`20260826_source_ip_forensics` 的 `Down` 只還原結構、不還原資料，僅供開發資料庫使用。**
它會刪掉整份帳號來源位址基準（`user_source_ips`）、刪掉每位使用者的允許來源網段
（`users.allowed_cidrs`），並刪除既有的 `new_source_ip` 告警列（不刪就加不回舊的 CHECK 約束）。
再次升級之後，那些清單是空的、基準是空的——**來源限制會靜默消失，全部位址重新被判為新**。
**`20260826_source_ip_forensics` 的生產回退手段是部署回舊版映像並還原升級前的備份**（§4.2），
不是執行這個 `Down`。

程式碼中另有一個內部的 `RollbackMigration` 函式。本版沒有給它任何生產可用的入口，
產品程式碼中也沒有呼叫者（唯一的呼叫者是測試）。規劃回退方案時，可以列入選項的只有還原備份。

跨越 baseline 世代的資料庫連新版都啟動不了（§2.0、§2.6），該情境在動到資料之前就被擋住，
不會走到回退這一步。

### 4.2 實際的回退程序

1. 停止全部服務。**回退前先確認守衛版已停**：`docker compose ps` 沒有 backend 在跑，
   且 §2.3 步驟 5 的連線數查詢為 0。回退目標若是無守衛版，舊版不持鎖，新舊並存不會被攔下；
   這一步的證據只有這兩項。
2. **部署回舊版本的映像／二進位**（先做這一步；還原的資料庫結構要配上對應的程式碼）。

   **自行建置者：把舊版映像掛回 `:latest`。** compose 參照的是 `custodexa/*:latest`，
   而 §2.2 的新版建置已經把這三個 tag 覆蓋成新版產物——不做這一步，`up -d` 起來的
   會是**新版程式碼配舊版資料庫**，也就是 §2.6 fail-close 要擋的那種組合。
   用 §2.2 事先另存的 tag：

   ```bash
   for img in backend frontend guacd; do
     docker tag "custodexa/${img}:pre-upgrade" "custodexa/${img}:latest"
   done
   docker image inspect custodexa/backend:latest --format '{{.Id}}'   # 與舊版映像 ID 相同才往下做
   ```

   §2.2 沒先存 tag、舊版映像也已經被覆蓋掉的話，回退前得先把舊版重建或重新取得
   （自 registry 拉該版本、或以舊版原始碼樹重跑一次建置）；**沒有舊版映像就沒有回退**。
   以交付映像部署者：改為重新載入舊版映像檔並確認 compose 參照到它。
3. 依[備份與還原 §5](./backup-and-restore.md#5-還原程序)還原升級前的備份。
4. 執行[還原後的驗證清單](./backup-and-restore.md#6-還原後的驗證清單)全部九項。

### 4.3 回退的代價

**還原備份會遺失備份時點之後產生的全部資料**，包含該期間的會話紀錄、錄影與審計紀錄。
若升級後系統已經對外服務了一段時間才決定回退，這段時間的稽核軌跡不會回來。

因此：

- 升級前備份的時點要**盡可能貼近停機時點**（§2.1 要求停機備份，正是為此）。
- 升級後的驗證（§2.7）要在恢復對外服務**之前**做完。發現問題的時間越早，回退代價越小。

