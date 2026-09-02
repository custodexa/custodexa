# database-protocol

## Purpose

資料庫資產（MySQL／PostgreSQL／Redis／MSSQL）的 CLI 代理連線、憑證收口與全審計：後端以本地 CLI 子程序（psql／mariadb／redis-cli／sqlcmd）掛 PTY 代理連線，真憑證不進子程序，會話文字流沿用 sshproxy bridge 的指令審計、asciicast 錄製、即時監看與指令阻斷。

## 對標基準（非規範性）

> 資料庫存取控管的兩種模式辨析（DAM vs PAM）與由此得出的差距裁決。DAM 側實態取自
> 2026-07-16 對商用 DAM 產品官方產品頁的實查；該類產品為閉源，以官方公開資料為準，
> 「原生體驗」等業務措辭以架構實態解讀。

**DAM 模式的典型實態**：於 DB 協議層以 gateway 代理全部進出 DB 流量；使用者端雙模式——
自機裝輔助元件後沿用原生工具經閘道連線，另備 Web 入口；DB 主機側另掛 agent 攔截繞過
閘道的直連。能力面涵蓋 SQL 即時稽核、數十種報表範本、管理員操作獨立稽核、查詢核准
（帳號/IP × 表格條件）、結果集遮罩、表/欄粒度阻斷，並宣稱支援數十種 DBMS。

**定位辨析**：DAM 模式下使用者自持 DB 帳密、以自機工具直連、閘道旁路稽核，因此需要
主機側 agent 補繞道缺口。本系統走 PAM 收口模式——憑證零出端（使用者拿不到 DB 帳密），
web 為唯一入口，繞道面不存在（前提：DB 網路層僅對本系統開放）。兩者的「原生」語義
不同：本系統 CLI 內即真原生工具（psql/mariadb/redis-cli，非模擬器）；DAM 模式的原生
指使用者自機 GUI/CLI 工具沿用。

**差距處置**：
- 自機原生工具經本系統代理（DB wire-protocol proxy）＋結果集遮罩（兩者技術前提相同，
  併同項）：暫不實作，待使用場景實證再啟動；屆時實查同類產品再設計。收口紅線可
  保持——使用者以短效 token 連本系統閘道，真 DB 憑證仍零出端。
- 查詢核准 workflow（高危 SQL 先核准再執行）：暫不實作，屬指令阻斷能力的後續演進（阻斷→核准
  為同一攔截點的階梯升級）。
- DBMS 廣度：需求驅動逐個加（CLI 模態新增一 DBMS≈新增一 client），不設固定目標數。
- 報表範本廣度：接受為定位差異結案（審計頁＋證據匯出＋API 已覆蓋稽核核心，
  不追範本數量堆疊）。
## Requirements
### Requirement: 資料庫 CLI 代理連線
系統 SHALL 以本地 CLI 子程序（psql/mariadb/redis-cli/sqlcmd）代理資料庫資產連線；憑證 SHALL 由後端記憶體組裝，SHALL NOT 出現於 argv、子程序環境或前端（詳見「明文憑證於 CLI 子程序內不得可讀」），SHALL 於 client 索取時經 PTY 注入：mariadb SHALL 以不帶值的 `-p` 觸發提示（帶值即落 argv），redis-cli SHALL 以 `--askpass` 觸發，psql 不設 `PGPASSWORD` 時即自行提示，**sqlcmd 在給定 `-U` 而不給 `-P` 且未設 `SQLCMDPASSWORD` 時即自行提示**。子程序環境 SHALL 最小化，SHALL NOT 繼承後端程序的機密環境變數。MySQL 連線 SHALL 使用 `mariadb`（非 deprecated 別名 `mysql`）並具備 caching_sha2_password client plugin，以連線 MySQL 8 預設認證。

CLI 啟動參數 SHALL 關閉可被間接利用的本機面：psql SHALL 帶 `-X`（不讀 `~/.psqlrc`，使會話行為與共享 HOME 解耦）與 `-P pager=off`（pager 經 `popen` 進 shell）；mariadb SHALL 帶 `--sandbox`（client 原生的檔案存取拒絕）與 `--local-infile=0`（`LOAD DATA LOCAL INFILE` 是等價於 psql `\lo_import` 的本機讀檔原語，且 SHALL NOT 假設 `--sandbox` 會擋它）；**sqlcmd SHALL 帶 `-X 0`**（關閉 `:!!` 與 `:ED` 兩個本機執行原語）。`-X` 為整數旗標且上游未設 `NoOptDefVal`，故 SHALL 以 `-X` 與 `0` 兩個獨立 argv 元素傳入，SHALL NOT 寫成裸 `-X`；值 SHALL 為 `0`（警告）而非 `1`（遇到即結束程序）——誤觸一個被封鎖的命令 SHALL NOT 使整條會話連同未存的查詢一起消失。三個互動歷史檔（psql／mariadb／redis-cli）SHALL 導向 `/dev/null`——CLI 的執行身分為全體資料庫會話共用，落檔的歷史會使 SQL 文字跨會話、跨使用者殘留（會話**內**的上下鍵歷史由 readline 的記憶體緩衝提供，不受影響）。client 原生限制 SHALL 視為加值層，SHALL NOT 作為唯一控制（實測 mariadb `--sandbox` 仍放行 `pager <程式>` 與 `edit`；sqlcmd 的 `-X` 關不掉 `:R`／`:OUT`）。

**mariadb 的 TLS 檔位 SHALL 明示，不得依賴 client 啟發式**：MariaDB client 11.4 起會依「是否提供密碼」自動切換 `--ssl-verify-server-cert`（無密碼時關閉並印警告、有密碼時開啟）。憑證改走 `-p` 提示注入後該啟發式會被觸發，故 `db_tls_mode` 為空或 `require` 時系統 SHALL 明示 `--ssl-verify-server-cert=0`，維持既有語義（空＝不主動要求 TLS、`require`＝加密但不核對憑證）；`verify-ca`／`verify-full` 不受影響。此為**維持現狀**而非放寬：不明示會使所有未設 TLS 檔位的既有資產在升級當下要求可信憑證鏈而連不上。要提高保證 SHALL 明示改 per-asset 的 TLS 檔位。

**sqlcmd 的終端前提 SHALL 被滿足，SHALL NOT 假設與其他三個 client 相同**：sqlcmd 以 `peterh/liner` 讀密碼，該函式庫在 `TERM` 為空／`dumb`／`cons25`、或終端寬度為 0 時**直接回錯誤且不印提示**。系統 SHALL 確保 mssql 會話的 PTY 具備有效 `TERM` 與**非零**的列寬與行高——前端傳入的尺寸為 0 或負值時 SHALL 夾到預設值（80×24），SHALL NOT 原樣傳遞。不滿足此前提的後果是「client 不印提示、注入永不觸發、會話無聲失敗」，使用者看不到任何原因。

**sqlcmd 的提示字串 SHALL 保持在地化中性**：其提示由 `SQLCMD_LANG` 決定語言（未設或不在支援清單即英文）。系統交給子程序的環境 SHALL NOT 含 `SQLCMD_LANG`，且此性質 SHALL 有守衛測試——該變數一旦進入環境，提示字串改變、注入器比對失效、會話停在使用者答不出來的提示上。

系統 SHALL NOT 過濾、改寫或丟棄使用者鍵入的位元組：方向鍵、Home/End、Tab 補全、Ctrl-A/E/R/W/K/U 等行編輯按鍵 SHALL 原樣送達 client。堡壘機的可用性本身是安全性質——會話退化到無歷史、無補全會促使使用者繞過堡壘機直連目標資料庫。

#### Scenario: 開籤即連
- **WHEN** 使用者在工作區點擊資料庫資產
- **THEN** 頁籤內直接呈現該資料庫 CLI 的互動終端（與 SSH 同體驗）

#### Scenario: 憑證零出端
- **WHEN** 任何資料庫連線建立
- **THEN** 前端與 URL 全程無明文憑證；目標機 ps 不可見密碼；CLI 子程序的環境與 argv 亦不含密碼

#### Scenario: 啟動參數關閉等價讀檔原語
- **WHEN** 檢視 mariadb 會話的實際啟動參數
- **THEN** 含 `--local-infile=0`，且 `db_tls_mode` 未設定或為 `require` 時含 `--ssl-verify-server-cert=0`

#### Scenario: 連線 MySQL 8
- **WHEN** 連線使用 caching_sha2_password 的 MySQL 8 資產
- **THEN** client plugin 齊備，認證成功不報 ERROR 1045

#### Scenario: 啟動參數關閉間接本機面
- **WHEN** 檢視四種協議的實際 CLI 啟動參數與環境
- **THEN** psql 含 `-X` 與 `-P pager=off`、mariadb 含 `--sandbox`、sqlcmd 含 `-X 0`，psql／mariadb／redis-cli 的歷史檔環境變數皆指向 `/dev/null`

#### Scenario: sqlcmd 的本機執行原語被關閉
- **WHEN** 使用者在 mssql 會話輸入 `:!! id` 或 `:ED`
- **THEN** client 回報該命令已被停用，SHALL NOT 執行任何本機程式，且會話 SHALL 維持存活

#### Scenario: 終端尺寸為零時仍能建立 mssql 會話
- **WHEN** 前端以 `cols=0`／`rows=0` 發起 mssql 連線
- **THEN** 系統夾到預設尺寸後啟動 client，密碼提示正常出現且注入成功

#### Scenario: 子程序環境不含 SQLCMD_LANG
- **WHEN** 檢視 mssql 會話 CLI 子程序的環境變數
- **THEN** 不含 `SQLCMD_LANG`（提示字串因此穩定為英文 `Password:`）

#### Scenario: 行編輯與歷史完整可用
- **WHEN** 使用者在資料庫會話按 ↑／↓／←／→、Home、Tab、Ctrl-A／E／R／W／K／U
- **THEN** client 正常反應（歷史重放、游標移動、補全、反向搜尋皆可用）

### Requirement: 資料庫 CLI 子程序的執行環境降權

資料庫會話的 CLI 子程序 SHALL 以**專用的非 root 系統身分**執行，SHALL NOT 以後端程序本身的身分（root）執行。該身分 SHALL：

- uid/gid 的 real／effective／saved／fs 四者皆為該身分（只換 effective 會留下可原路升回的 saved uid）；
- 不帶任何附屬群組（後端程序的群組若被繼承，group 權限位元即成為讀取面）；
- 不具任何 capability（非 root 執行，且映像內 SHALL NOT 含 setuid／setgid 檔）；
- HOME 與 TMPDIR 指向一個**該身分不可寫的空目錄**，SHALL NOT 沿用後端程序的家目錄；
- 在容器內 SHALL NOT 有任何可寫路徑（容器執行期由 docker 掛載、映像內無法變更的 tmpfs 除外，該例外 SHALL 明載）。

查不到該身分時系統 SHALL 拒絕建立會話（fail-close）；SHALL NOT 退回以後端身分啟動 CLI——那會靜默地失去本要求的全部保證。

子程序需要讀取的暫存檔（如 verify-ca 模式的 CA 憑證）SHALL 以移交所有權（chown）方式提供，SHALL NOT 以放寬 mode 的方式提供。

本要求取代「以輸入層白名單限制 client 本機能力面」的做法：client 的讀檔類 meta-command（`\copy … FROM`、`\i` 等）**維持可用**，安全保證改由「該身分讀得到的東西沒有價值、且寫不了任何地方」承擔。理由如下——輸入層過濾在原理上不可靠（歷史重放使系統看不到實際執行的內容），且其 UX 代價會把使用者推去繞過堡壘機。

#### Scenario: CLI 不以後端身分執行
- **WHEN** 建立任一資料庫會話並檢視其 CLI 子程序
- **THEN** 該程序的 uid/gid 為專用降權身分而非 root，附屬群組為空，capability 全為 0

#### Scenario: 降權身分無可寫路徑
- **WHEN** 列舉該身分在容器內可寫的所有路徑
- **THEN** 結果為空（明載的執行期 tmpfs 例外除外）

#### Scenario: 降權身分不存在時不建立會話
- **WHEN** 執行環境缺少該專用身分（例如映像未重建）
- **THEN** 會話建立失敗並回明確錯誤，SHALL NOT 以後端身分啟動 CLI

#### Scenario: 讀檔類命令維持可用
- **WHEN** 使用者在 psql 會話輸入 `\copy leak FROM '/etc/passwd'`
- **THEN** 命令正常執行（此為刻意允許），且該身分讀得到的內容不含任何憑證

### Requirement: CLI 執行環境的可驗證不變式

執行環境的降權保證 SHALL 以**機械斷言**維持，SHALL NOT 僅以文件或人工複查維持。版控內 SHALL 具備下列測試，且 SHALL 在每次改動連線鏈或容器映像時執行：

1. **無可讀憑證**：以權限位元推算該身分在容器內可達且可讀的全部檔案，逐檔比對執行期的活憑證（加密金鑰、JWT secret 等），命中即失敗。掃描 SHALL NOT 設檔案大小上限（設上限即留下「把憑證放進大檔案」的缺口）；探針數量為零時 SHALL 直接失敗（無探針的通過是假綠）。**探針 SHALL NOT 以長度門檻剔除短憑證**——長度只可決定比對方式（長值原樣子字串比對；短值要求「機密欄位名 ＋ 賦值符號 ＋ 完整 token 邊界」以避開低熵預設值的假警報），不得決定「掃或不掃」。任何比對範圍的排除 SHALL 在測試輸出中量化印出，SHALL NOT 靜默。**排除的判準 SHALL 為「該樹的內容是否經由我方寫入路徑產生」**——內容由第三方決定且不存在我方寫入路徑者（套件管理器的依賴快取、語言 toolchain）得排除；**我方原始碼樹、執行期掛載點與可寫面 SHALL NOT 排除**。本斷言是**探索式**偵測而非核對式檢查：它要找的是未被預期的可讀憑證面，故射程 SHALL 涵蓋「憑證可能非預期出現」的全部位置。實證：一次真實事故中，含活憑證的 `.env` 經掛載進入我方原始碼樹而對該身分可讀，該路徑不在任何既有清單上（當日才產生），核對式檢查無從發現。
2. **可寫面為空**：該身分可寫的路徑集合 SHALL 與明載的 allowlist 完全相符。allowlist SHALL 為**子樹**語義——名單內的執行期 tmpfs 中出現檔案是預期行為，SHALL NOT 使測試轉紅（假紅會訓練人忽略這組唯一的守門測試）。allowlist 的每一項 SHALL 被斷言為真正的執行期掛載點且帶 `nosuid,nodev,noexec`，使「加一行就讓任意目錄消音」不可行。
3. **執行身分**：資料庫會話實際啟動的 CLI 子程序 SHALL 被斷言為降權身分——localpty 具備降權能力但 `dbproxy.Start` 未使用，等同沒有。
4. **後端機密不可讀**：後端程序的環境區塊 SHALL NOT 對該身分可讀。
5. **無 setuid／setgid 檔**：映像內 SHALL 以機械斷言核對不存在 setuid／setgid 一般檔（該掃描 SHALL 涵蓋全映像，SHALL NOT 因「該身分進不去」而剪除子樹——上層權限一旦放寬即成升權面）。**本項只讀取檔案 metadata，SHALL NOT 因效能考量而縮減其涵蓋面**——它與第 1 項的內容讀取是不同成本量級，兩者的射程 SHALL 各自依其目的決定。
6. **會話 PTY 不對該身分開放**：`/dev/pts/<N>` 的 owner SHALL 為 root、且該降權身分對其無任何 rwx 位元——這是跨會話 `fd/` 讀寫實際被擋下的地方。

這組測試 SHALL 在「有人把含活憑證的檔案掛進容器」「有人放寬資料／日誌目錄權限」「有人放寬會話 PTY 或引入 setuid 檔」時轉紅——那是撤除輸入層過濾後唯一的失效條件。正式版映像的同一組性質 SHALL 由正式版建置驗證流程對已建置 image 實跑核對（見 `deployment-hardening`）。

#### Scenario: 掛進含憑證的檔案即轉紅
- **WHEN** 在容器內放入一個該身分可讀、內容含活憑證的檔案
- **THEN** 環境不變式測試失敗並指出該檔案路徑與命中的憑證變數名（SHALL NOT 印出憑證值）

#### Scenario: 放寬資料目錄權限即轉紅
- **WHEN** 有人把錄影／日誌目錄改為該身分可寫或可讀
- **THEN** 對應的不變式測試失敗

#### Scenario: 降權未接上實際連線路徑即轉紅
- **WHEN** 資料庫會話改以後端身分啟動 CLI
- **THEN** 執行身分斷言失敗

#### Scenario: allowlist 內的 tmpfs 殘留檔不轉紅
- **WHEN** 前一個會話在 `/dev/shm` 留下該降權身分擁有的檔案或子目錄
- **THEN** 可寫面測試維持通過；但在 allowlist 之外新增任何該身分可寫的檔案或目錄時，測試失敗並列出該路徑

#### Scenario: 映像出現 setuid 檔即轉紅
- **WHEN** 映像內被放入一個 setuid 或 setgid 的一般檔
- **THEN** 不變式測試失敗並列出該檔路徑與 mode

#### Scenario: 會話 PTY 被放寬即轉紅
- **WHEN** 會話的 `/dev/pts/<N>` 被 chown 給該降權身分、或 other 位元被放寬
- **THEN** PTY 權限斷言失敗（跨會話將可讀他人擊鍵並注入其終端）

#### Scenario: 排除第三方依賴樹不影響掛載面的偵測
- **WHEN** 憑證掃描排除了套件管理器的依賴快取，而含活憑證的檔案被掛載至我方原始碼樹
- **THEN** 該檔案仍被偵測並使測試失敗；測試輸出同時量化印出因排除而未讀取內容的檔案數

### Requirement: 明文憑證於 CLI 子程序內不得可讀

資料庫資產帳號的明文密碼 SHALL NOT 能被會話使用者從 CLI 的任何讀取面取得——包含**自己這條會話的**子程序，不只是別人的。

**CLI 子程序 SHALL NOT 以任何形式持有真憑證**：SHALL NOT 進入子程序環境（`PGPASSWORD`／`MYSQL_PWD`／`REDISCLI_AUTH`／`SQLCMDPASSWORD` 等）、SHALL NOT 進入 argv（含 sqlcmd 的 `-P`）、SHALL NOT 落成憑證檔（`.pgpass`、`--defaults-file` 等）。密碼 SHALL 只在 client 於終端索取的那一刻由 PTY 層注入。

**環境變數傳遞已被證實不安全，SHALL NOT 復用（含「為了省事暫時改回」）**：舊版曾以「程序環境區塊以 NUL 分隔，文字讀取只取得到第一段」為由刻意選用環境變數。該論證只涵蓋文字讀取路徑，**不成立於二進位讀取原語**：實測 psql `\lo_import '/proc/self/environ'` ＋ `SELECT position('PGPASSWORD=' in encode(lo_get(:LASTOID),'escape'))` 可取出明文密碼（offset 187），且因各會話共用同一降權身分，**跨會話亦成立**——只被授權某一資產的使用者可讀出另一資產的密碼。此為連線收口紅線（前端零接觸明文憑證）的實質破口。

PTY 提示注入 SHALL 滿足下列條件，全部成立才寫出密碼：

1. 提示字串**完整命中**且落在輸出區塊**尾端**（真提示之後 client 必然停下等輸入；中段命中 SHALL NOT 注入，否則使用者可用查詢結果誘出密碼）；
2. 對具備判準的 client（psql／mariadb），PTY 行紀律 SHALL 處於 `ICANON && !ECHO`（該 client 讀密碼的狀態，與 readline 互動態互斥）；判準不可用的 client SHALL 於 spec 註明——**redis-cli（`--askpass` 走遮罩式 raw 讀取）與 sqlcmd（`peterh/liner` 自行下 raw mode，ICANON 與 ECHO 皆關，與其互動態同型）皆無此判準可用**；
3. **整條會話至多注入一次**。psql 只在 user／host／port 三者不變時重用已快取的密碼（實測 `\c <同一 db>` 不再提示、`\c db <其他 user>` 才提示），故第一次之後的同名提示在構造上必然代表 client 正連往**別的 host／port**——SHALL NOT 對其注入；
4. psql 的提示 SHALL 以**本會話帳號名稱**完整比對（`\c db otheruser` 索取的是別人的密碼）。

**各 client 的提示登記** SHALL 逐字精確，SHALL NOT 相互套用：

| 協議 | client | 提示字串 | 尾隨空白 | 行紀律判準 |
|---|---|---|---|---|
| postgres | psql | `Password for user <本會話帳號>: ` | 有 | `ICANON && !ECHO` 可用 |
| mysql | mariadb | `Enter password: ` | 有 | `ICANON && !ECHO` 可用 |
| redis | redis-cli | `Please input password: ` | 有 | 不可用（raw 遮罩讀取） |
| mssql | sqlcmd | `Password:` | **無** | 不可用（liner raw mode） |

**mssql 的第 4 條件不成立，SHALL 明載其後果**：sqlcmd 的提示不含使用者名稱，無從做帳號比對。因此當使用者以 `:CONNECT <其他伺服器> -U <使用者>` 連往別的目標而觸發第二次 `Password:` 時，**唯一的守衛是第 3 條件（一次性注入）**。此為 mssql 相對其他三協議較弱之處，SHALL NOT 被描述為等同保證。

**注入的密碼與密碼提示 SHALL NOT 進入審計鏈**：提示字串 SHALL 於輸出流被濾除（錄影、即時監看、審計虛擬螢幕皆在其下游）；注入的位元組 SHALL NOT 經指令審計路徑（SHALL NOT 出現於 `session_commands`）；注入後至第一個換行為止的輸出 SHALL 丟棄，以覆蓋「client 尚未關閉回顯」的競態。sqlcmd 於 raw 模式下不回顯密碼，該丟棄機制 SHALL 仍然保留——它同時吞掉 liner 於讀取結束後補印的換行，且是對「上游改為回顯遮罩字元」的前置防護。

**記憶體殘留是偶然，SHALL NOT 被當成防線**：密碼在注入後仍存在於 client 的程序記憶體。實測 `\lo_import '/proc/self/mem'` 回 `could not read from file: I/O error`，成因是該原語自 offset 0 順序讀而低位址不可讀，**不是** client 或核心提供的保護。本要求可驗證的保證範圍到「憑證不在環境、不在 argv、不在任何可讀的一般檔」為止；要消除記憶體殘留需憑證代理（後端代持連線），屬未來範圍。

本要求另 SHALL 以「該降權身分讀得到的一般檔裡沒有憑證」為前提——`\lo_import` 對一般檔可完整讀出（實測 `/etc/os-release` 188 bytes），sqlcmd 的 `:R` 為同等原語，該前提由「CLI 執行環境的可驗證不變式」的憑證掃描承擔。

CLI 子程序 SHALL NOT 繼承後端程序的機密環境變數（加密金鑰、JWT secret），且 SHALL NOT 能讀取後端程序的 `/proc/<pid>/environ`。

**已知殘留（SHALL 明載）**：各資料庫會話共用同一降權身分，故彼此之間存在下列跨會話面。要完全消除需 per-session 身分，屬未來範圍。

1. **`/proc` 面**：彼此讀得到 `/proc/<pid>/environ` 與 `/proc/<pid>/cmdline`，且以二進位讀取原語（`\lo_import`）可取得**完整內容**——SHALL NOT 再以「NUL 截斷只洩漏第一段」描述（該說法只對文字讀取成立，且曾據以做出錯誤的憑證設計）。實際洩漏面為：對方會話的程式名、連線參數（主機／埠／使用者名）與最小化後的環境變數名；憑證已不在其中（見本要求主文）。`/proc/<pid>/fd/` 亦**可列出且 `readlink` 成功**——同 uid 的 ptrace 檢查是通過的，此處 SHALL NOT 宣稱其依賴 `CAP_SYS_PTRACE` 的缺席。實際擋下 fd 讀寫的是 PTY 從屬端的 DAC：`/dev/pts/N` 為 `root:tty`、`crw--w----`，降權身分對它無任何權限。該權限 SHALL 有守衛測試（chown 給該身分或放寬 other 位元即轉紅），否則跨會話面會從「讀到 `PATH`」升級為「讀他人擊鍵與注入他人終端」。
2. **`/dev/shm` 檔案交換面**：`/dev/shm` 為 docker 執行期掛載的 tmpfs（`nosuid,nodev,noexec`，預設 64 MiB），映像內無法變更，是該身分僅有的可寫面。實測會話 X 可 `\copy (SELECT …) TO '/dev/shm/f.csv'` 落檔（`COPY 3`），會話 Y 可 `\copy … FROM '/dev/shm/f.csv'` 原樣取回；sqlcmd 的 `:OUT`／`:R` 為同等原語。**能傳什麼**：任一會話的使用者權限內查得到的任意資料，上限為 tmpfs 容量。**稽核看得到什麼**：兩側的命令文字皆進 `session_commands`（誰在何時對哪個檔案做了讀寫）。**看不到什麼**：檔案內容不經終端，故不入錄影與虛擬螢幕；容器重啟即消失，事後無從取證。此為刻意接受的殘留（封閉它需 per-session tmpfs 或檔案層攔截），SHALL NOT 被描述為「已封閉」。

#### Scenario: 無法經二進位讀取原語讀出自己的憑證
- **WHEN** 使用者在 psql 會話執行 `\lo_import '/proc/self/environ'` 並以 `lo_get` 取出完整內容
- **THEN** `PGPASSWORD`／`MYSQL_PWD`／`REDISCLI_AUTH`／`SQLCMDPASSWORD` 命中皆為 0，環境中只有 `PATH`／`TERM`／`LANG`／`TMPDIR`／`HOME`／歷史檔變數

#### Scenario: mssql 會話的 argv 與環境不含密碼
- **WHEN** 檢視 mssql 會話 CLI 子程序的 `/proc/<pid>/cmdline` 與 `environ`
- **THEN** 不含 `-P`、不含密碼值、不含 `SQLCMDPASSWORD`

#### Scenario: 跨會話亦讀不到憑證
- **WHEN** 使用者從自己被授權的會話讀取另一條資料庫會話的 `/proc/<pid>/environ` 與 `cmdline`
- **THEN** 兩者皆不含任何憑證（argv 亦然），未授權資產的密碼不可得

#### Scenario: 密碼提示與注入的密碼不進審計鏈
- **WHEN** 會話建立後檢視該會話的 asciicast 錄影檔與 `session_commands`
- **THEN** 兩者皆不含密碼值，也不含 client 的密碼提示字串

#### Scenario: 第二次密碼提示不注入
- **WHEN** 使用者以 `\c <db> <同一使用者> <其他主機>`（psql）或 `:CONNECT <其他伺服器> -U <使用者>`（sqlcmd）觸發第二次同名密碼提示
- **THEN** 系統 SHALL NOT 注入密碼；提示原樣呈現給使用者，由其自行處置

#### Scenario: 查詢結果誘出提示不注入
- **WHEN** mssql 會話已輸出過一段非提示內容之後，再出現以 `Password:` 結尾的輸出
- **THEN** 注入器已解除武裝，SHALL NOT 注入密碼

#### Scenario: 密碼錯誤時顯性失敗
- **WHEN** 資產憑證與目標資料庫不符
- **THEN** client 於數秒內回傳認證失敗訊息並結束會話，SHALL NOT 無限等待，訊息中 SHALL NOT 含密碼值

#### Scenario: 後端程序的機密不可達
- **WHEN** 使用者嘗試讀取後端程序的 `/proc/<pid>/environ`、審計日誌或錄影檔
- **THEN** 一律 Permission denied

#### Scenario: 後端機密不入子程序環境
- **WHEN** 在資料庫會話內列舉子程序自身的環境變數
- **THEN** 環境中不含加密金鑰與 JWT secret

### Requirement: 新增協議 CLI 的准入準則

新增任何以本地 CLI 子程序代理的協議時，SHALL 假設該 client 具備**任意本地讀取能力**（檔案與程序記憶體），SHALL NOT 以「本 client 沒有讀檔命令」或「原生 sandbox 會擋」作為憑證面的論證。理由是機械性的：這類能力散落在 client 的各種功能中（psql 的 `\lo_import`／`\copy`、mariadb 的 `LOAD DATA LOCAL INFILE`／`source`、sqlcmd 的 `:R`／`:OUT`），逐一枚舉並追上上游版本演進在原理上做不到，且本專案曾兩度因這類論證而判斷錯誤（一次高估輸入層過濾，一次高估 NUL 截斷）。

因此准入評估 SHALL 只問一個問題：**真憑證是否離開後端程序、進入 CLI 子程序**（環境、argv、檔案、或子程序可長期持有的任何形式）。答案為是即 SHALL NOT 准入，除非改以不交付真憑證的方式（PTY 提示注入、一次性 token、後端代持連線）。

新協議 SHALL 同時登記：該 client 索取密碼的提示字串、其索取當下的 PTY 行紀律狀態（是否可作為結構性判準）、以及等價於任意讀檔的原語清單與對應的關閉旗標。

**mssql（sqlcmd）的登記**：

- 提示字串 `Password:`（無尾隨空白），觸發條件為給 `-U` 而不給 `-P` 且不設 `SQLCMDPASSWORD`。
- 索取當下 PTY 為 raw（ICANON 與 ECHO 皆關），與互動態同型，**無結構性判準可用**。
- 本機原語清單：

| 原語 | 性質 | 關閉方式 |
|---|---|---|
| `:!!` | 執行本機程式 | `-X 0` 關閉 |
| `:ED` | 開 `$EDITOR` 並建暫存檔 | `-X 0` 關閉 |
| `:R` | 讀任意本機檔 | **無旗標可關**，刻意允許（等價於 psql `\copy … FROM`） |
| `:OUT` | 寫任意本機檔 | **無旗標可關**，刻意允許（降權身分無可寫路徑，操作會顯性失敗） |
| `-i/--input-file` | 讀本機檔 | 系統不傳該旗標；使用者無法於會話中追加 argv |
| `BULK INSERT`／`OPENROWSET` | **伺服端**能力 | 不屬 CLI 本機面，由目標資料庫的權限模型管 |

- 授權：`microsoft/go-sqlcmd` 為 MIT（`LICENSE`），非 EULA。映像內的二進位 SHALL 為自建（見 `deployment-hardening`），SHALL NOT 使用受 EULA 約束的 `mssql-tools18`／`msodbcsql18`。

#### Scenario: 新協議以環境變數帶憑證即不予准入
- **WHEN** 評估一個新的資料庫 CLI 協議，其連線方式為以環境變數或設定檔提供密碼
- **THEN** 該方案不予採用，須改為不讓子程序持有真憑證的形式

#### Scenario: 以「client 無讀檔命令」作為安全論證即不予採信
- **WHEN** 提案主張某 client 因不具備讀檔 meta-command 而可安全持有憑證
- **THEN** 該論證不成立；憑證面的判斷 SHALL 只依「真憑證是否進入子程序」

#### Scenario: 新協議的登記缺項即不予准入
- **WHEN** 新增協議的提案未登記提示字串、行紀律判準與本機原語清單
- **THEN** 該提案不完整，SHALL NOT 進入實作

### Requirement: 審計鏈沿用
資料庫**命令列**會話 SHALL 走 sshproxy bridge 的 TerminalConn 介面，指令審計、asciicast 錄製、即時監看、指令阻斷 SHALL 對資料庫會話自動生效，無需另行配置。

資料庫**查詢主控台**會話不經 bridge：其語句紀錄為結構化執行來源、錄影為伺服端轉錄、監看與阻斷沿同一落地面，規範見 `db-query-console`；本要求的射程 SHALL 限於命令列會話，SHALL NOT 被讀成主控台會話亦經 TerminalConn。

#### Scenario: SQL 指令入審計
- **WHEN** 使用者在 psql 會話執行 SQL
- **THEN** 該指令出現於 session_commands 並可於指令審計頁查得

#### Scenario: 會話錄製與回放
- **WHEN** 資料庫會話結束
- **THEN** asciicast 錄製落盤且會話詳情頁可回放

#### Scenario: 主控台會話不經 bridge 仍全審計
- **WHEN** 使用者以查詢主控台對同一資產執行 SQL
- **THEN** 該語句出現於 session_commands（帶結果事實欄）、轉錄錄影落盤可回放、會話可被監看，且無 CLI 子程序被啟動

### Requirement: 協議感知的能力門檻
SSH 專屬能力（SFTP 檔案管理、/proc 系統指標）SHALL 對資料庫會話隱藏；文字終端共通能力（片段、分享、監看）SHALL 對資料庫**命令列**會話開放；Redis 資產 SHALL 免使用者名稱（僅密碼認證）；**MSSQL 資產 SHALL 要求使用者名稱**（SQL 認證的 login 名稱，沒有它 sqlcmd 不會索取密碼、注入無從觸發）。

本要求的「資料庫會話」指命令列分頁；查詢主控台分頁的工具列門檻另見 `session-workspace` 的「資料庫查詢主控台分頁」（不提供分享與片段，監看由既有入口承擔）。

#### Scenario: 工具列門檻
- **WHEN** 當前啟用頁籤為資料庫會話
- **THEN** 工具列僅顯示分享與片段，不顯示檔案管理與系統監控

#### Scenario: mssql 資產缺使用者名稱即拒絕建立
- **WHEN** 建立 mssql 資產或其帳號而未填使用者名稱
- **THEN** 系統拒絕並回機器碼，SHALL NOT 建立一個必然連不上的資產

#### Scenario: 主控台分頁不顯示終端工具列
- **WHEN** 當前啟用頁籤為資料庫查詢主控台分頁
- **THEN** 工具列不顯示分享、片段、檔案管理與系統監控

### Requirement: DB 目標資料庫
資料庫資產 SHALL 可選地指定連線目標資料庫（`db_name`）；指定時 dbproxy SHALL 將其帶入 client 連線（postgres positional dbname、mysql positional database、redis `-n`、**mssql `-d`**）；未指定 SHALL 連 client 預設庫。

#### Scenario: 指定資料庫連線
- **WHEN** mysql 資產設定 db_name=testdb 並連線
- **THEN** 終端 prompt 為 `MySQL [testdb]>`，`SELECT DATABASE()` 回 testdb

#### Scenario: 未指定連預設
- **WHEN** 資產未設 db_name 並連線
- **THEN** 連線成功並落在 client 預設庫，既有行為不變

#### Scenario: mssql 指定資料庫
- **WHEN** mssql 資產設定 db_name=testdb 並連線
- **THEN** `SELECT DB_NAME()` 回 testdb

### Requirement: DB 連線 TLS 模式（per-asset）
資料庫資產 SHALL 提供 per-asset TLS 模式 `db_tls_mode`：空（沿用 client 預設）/ `disable`（停用，供不支援 TLS 的 DB）/ `require`（加密不驗憑證）/ `verify-ca`（加密並驗證伺服器憑證）/ `verify-full`（加密、驗證憑證並核對主機名——Postgres 對應 PGSSLMODE=verify-full；MySQL 對應 --ssl-verify-server-cert；Redis 無獨立檔位，等同 verify-ca；**MSSQL 無獨立檔位，等同 verify-ca**）。`verify-ca`／`verify-full` SHALL 可附自訂 CA（`db_ca_cert`，PEM）；系統 SHALL 把 CA 寫暫存檔供 client 驗證，並於連線結束清除。預設（空）SHALL NOT 改變既有資產連線行為。

**MSSQL 的檔位映射 SHALL 為**：空＝不加旗標；`disable`＝`-N false`；`require`＝`-N true -C`；`verify-ca`／`verify-full`＝`-N true`，有自訂憑證時加 `-J <檔案>`。

**MSSQL 的 `db_ca_cert` 語義差異 SHALL 明載，SHALL NOT 以「與其他協議相同」帶過**：sqlcmd 的 `-J/--server-certificate` 是對伺服器 TLS 憑證做**比對／釘選**，而非「以此為信任錨驗證憑證鏈」——與 `PGSSLROOTCERT`／`--ssl-ca`／`--cacert` 的 CA bundle 語義不同。未提供 `db_ca_cert` 時 `verify-ca`／`verify-full` 以系統根憑證驗證，語義與其他協議一致；提供時為釘選語義。UI 與 API 說明文字 SHALL 對 mssql 標示此差異。**此表述為保守釘選，尚未經決定性實測**：先前實作期的實驗未能完成——決定性實驗需要「CA 簽發的葉憑證」（自簽憑證同時是自己的根，釘選與信任錨兩種語義都會成功而無從分辨），而靶機 azure-sql-edge 於 arm64 上一設定 `network.tlscert` 即在啟動階段 fatal（證據見對應的實作與測試）。本段 SHALL 維持保守表述，SHALL NOT 被改寫為已確定；待以 amd64 的 `mssql/server` 靶機實測後複核，若實測顯示 `-J` 亦接受簽發 CA 而完成鏈驗證，本段 SHALL 據實改寫。

#### Scenario: require 加密生效
- **WHEN** 資產設 db_tls_mode=require 連 mysql
- **THEN** 連線加密（`Ssl_version` 顯示 TLSv1.x）

#### Scenario: verify-ca 拒絕不受信憑證
- **WHEN** 資產設 db_tls_mode=verify-ca 連自簽憑證的 DB
- **THEN** client 因憑證不受信而拒絕連線並斷線

#### Scenario: verify-full 核對主機名
- **WHEN** 資產設 db_tls_mode=verify-full 連 Postgres，憑證受信但 CN/SAN 與連線主機不符
- **THEN** client 因主機名不符而拒絕連線

#### Scenario: 停用供不支援 TLS 的 DB
- **WHEN** 資產設 db_tls_mode=disable
- **THEN** 連線不協商 TLS，明文連線成功

#### Scenario: mssql 的 TLS 檔位映射
- **WHEN** mssql 資產設 db_tls_mode=require 並連線
- **THEN** 啟動參數含 `-N true` 與 `-C`，連線加密且不驗憑證

### Requirement: MSSQL 協議的 web CLI 支援

系統 SHALL 支援協議值 `mssql` 的資產，其連線 SHALL 以本地 `sqlcmd` 子程序掛 PTY 的方式提供，SHALL 與既有三個資料庫協議走同一條連線鏈（`dbproxy` → `localpty` → sshproxy bridge），使指令審計、asciicast 錄製、即時監看、指令阻斷**自動沿用**、無需另行配置。

協議值 SHALL 為 `mssql`（非 `sqlserver`）。預設埠 SHALL 為 1433。

連線目標 SHALL 以 `-S <host>,<port>` 形式傳入。**host 欄位 SHALL 拒絕含逗號**——`-S` 以逗號分隔主機與埠，含逗號的 host 會被 client 解讀為指向別的埠。此檢查 SHALL 為 mssql 專屬，SHALL NOT 放進通用的 argv 驗證（其他協議的逗號無此語義）。

`mssql` 協議 SHALL 納入既有的協議分類判定（`IsDatabase`／`IsTextTerminal`）、資產協議白名單、撥測對照表、告警規則的協議值域、以及傳輸政策的資料庫協議盤點——任一處遺漏都會使該協議在對應功能面**靜默失效**。

映像內缺少 `sqlcmd` 執行檔時，系統 SHALL 拒絕建立 mssql 會話並回明確錯誤（fail-close），SHALL NOT 退化為其他行為。

#### Scenario: 建立並連線 mssql 資產
- **WHEN** 管理者建立 protocol=mssql 的資產並在工作區點擊
- **THEN** 頁籤內呈現 sqlcmd 互動終端，`SELECT @@VERSION` 可執行並回傳結果

#### Scenario: mssql 會話的審計鏈自動生效
- **WHEN** 使用者在 mssql 會話執行一個 T-SQL 批次並結束會話
- **THEN** 該批次出現於 `session_commands`，asciicast 錄影落盤且可回放，會話期間可被即時監看

#### Scenario: host 含逗號即拒絕
- **WHEN** 建立 mssql 資產且 host 為 `db.example.com,1434`
- **THEN** 系統拒絕並回機器碼

#### Scenario: 缺 client 時 fail-close
- **WHEN** 映像未含 `sqlcmd` 而使用者發起 mssql 連線
- **THEN** 會話建立失敗並回明確錯誤

### Requirement: MSSQL 批次終止符與指令審計切分

MSSQL 會話的指令審計 SHALL 以 T-SQL 的**批次**為單位切分。系統 SHALL 將獨立一行的 `GO`（不分大小寫，可帶重複次數參數如 `GO 5`，前後允許空白）辨識為語句終止符；`;` SHALL 同時保留為終止符，兩者取聯集。

理由 SHALL 明載：sqlcmd 的執行單位是批次而非語句，`;` 不觸發執行。若沿用只認 `;`／`\g`／`\G` 的判斷，審計看到的切分將與實際執行的批次永久錯位——使用者打 `SELECT 1;` 時審計就結算（但 client 尚未執行），打 `GO` 時審計不結算（`GO` 被併進下一條），且指令阻斷與 SQL 危險規則的比對對象因此是錯的。保留 `;` 是為了不削弱「關鍵字拆行送出以規避 SQL 危險規則」的既有防線。

終止符判斷 SHALL 為協議感知：mssql 以外協議的切分行為 SHALL 位元組級不變。

系統 SHALL NOT 傳入 sqlcmd 的自訂批次終止符旗標（`-c`）——傳了會使本要求的假設失效。

**誠實邊界 SHALL 明載——`:` 命令不自成一筆審計記錄**：sqlcmd 的 `:` 命令（`:connect`、`:out`、`:r`、`:list`、`:ed` 等）**不以 `;` 或 `GO` 結尾**，而切分點只有這兩者，故一連串 `:` 命令會累進於打字緩衝，直到下一個 `GO`／達 `typingBufMax`／會話結束才沖出（實測六行併成一筆 `session_commands`）。**遺失的是切分而非內容**：查核 `:connect`／`:out` 這類安全相關動作 SHALL 以**內容子字串搜尋**進行，SHALL NOT 只看筆數或每筆首行——稽核者若以為每個 `:connect` 都是獨立一筆，會在數不到筆數時錯誤推論「沒有人重連過」。psql 的 `\` 元命令（`\c`、`\copy`、`\!`）同型，屬既有行為；要修需在 parser 補「協議專屬的元命令即終止符」規則，影響面跨既有三協議的切分基準，屬另一個 change 的射程。

#### Scenario: GO 結算一個批次
- **WHEN** 使用者在 mssql 會話依序輸入 `SELECT 1`、`SELECT 2`、`GO`
- **THEN** `session_commands` 中出現一筆包含兩行 SELECT 的完整批次

#### Scenario: 分號亦結算
- **WHEN** 使用者輸入 `SELECT 1;`
- **THEN** 該語句結算為一筆指令

#### Scenario: 既有協議切分不受影響
- **WHEN** 在 mysql／postgres 會話執行多行 SQL
- **THEN** 切分行為與新增 mssql 支援前完全相同

### Requirement: MSSQL 提示符不得污染指令審計文字

mssql 會話落入 `session_commands` 的指令文字 SHALL NOT 含 sqlcmd 的提示符（`1>`／`2>`／…／`55>` 等逐行遞增形態）。系統 SHALL 在 mssql 專屬路徑上，於指令結算時剝除指令行開頭殘留的提示符前綴。

理由 SHALL 明載：sqlcmd 的提示符**逐行遞增**，且提示符與 Enter 回顯的換行**不保證落在同一次寫出**。指令重組只在輸入起始時快照**單一**提示符文字並剝除**一次**，故當使用者的按鍵（典型為上鍵召回歷史，其重繪會重印提示符）落在換行與提示符兩次寫出之間時，快照取到的是空字串或半截提示符，重繪帶進的提示符即留在審計文字裡。已於產品資料庫實查命中此污染。

**此競態 SHALL NOT 被視為已由指令原點修正消除**：原點種入解決的是「螢幕缺少 prompt 導致欄位算術錯位」，而本要求解決的是「快照取不到提示符、重繪把遞增後的提示符帶進打字緩衝」。競態發生時快照本來就是空字串或半截，種入無從補上正確的提示符，螢幕上仍會是 `<數字>> <語句>`。故本剝除 SHALL 保留。

**剝除順序 SHALL 明載**：mssql 專屬剝除 SHALL 在原點切除**之前**進行。理由是機械性的——快照為半截提示符（如 `55`）時，先做原點切除會切掉那半截而在行首留下孤立的 `>`，製造出新的污染形態；先做提示符剝除則直接得到乾淨語句。誤剝閘門（快照本身即為提示符形態時不啟動）SHALL 在此順序下維持原語義。

**危害 SHALL 明載**：指令審計的稽核用法是**內容子字串比對**（查有沒有人下過某個危險語句）。提示符污染使同一條語句每次的文字都不同，比對、去重與 `command-alerts` 的 SQL 危險規則命中皆因此失準。

**射程限制 SHALL 明載**：本剝除 SHALL 僅對 mssql 生效。ssh／mysql／postgres／redis／k8s 的指令切分 SHALL 維持不變，其結算文字 SHALL NOT 因本剝除而改變。**此處 SHALL NOT 再宣稱「位元組級不變」**——虛擬螢幕自身的缺陷修正（絕對定位的欄位原點等）本就會改變覆寫結果，該變動屬螢幕還原的射程、不屬本剝除；把兩者混為一談會使守衛測試的期望值失去可解釋性。

**誤剝防線 SHALL 明載**：當提示符正常抵達（快照到的提示符**本身即為 sqlcmd 提示符形態**）時，本剝除 SHALL NOT 啟動——此時既有的單次剝除已足夠，使用者自行輸入、以 `<數字>> ` 起頭的內容因而 SHALL NOT 被誤剝。剝除 SHALL 只進行一次，SHALL NOT 迴圈剝除。行首以外位置出現的 `<數字>>`（如 `SELECT '55> x'`）SHALL NOT 被剝除。

**孤立殘骸形態 SHALL 隨其根因一併消失**：行首出現「孤立 `>` ＋ 完整提示符」（如 `>55> SELECT name`）是絕對定位差一欄的產物——重繪自第 2 欄起覆寫，使重繪前已寫出的第一個位元組存活。該缺陷修正後此形態在原理上不再產生，故其專屬剝除分支 SHALL 被移除，SHALL NOT 以「多一道防線無害」為由留存不可達的程式碼。其「行首孤立 `>` 不得被誤剝」的斷言 SHALL 遷移至端到端測試保留，SHALL NOT 隨函式一併刪除。

**殘留風險 SHALL 誠實登記**：唯有「快照競態發生」與「使用者該行恰以 `<數字>> ` 起頭」同時成立時，該前綴會被移除；此時行內其餘文字 SHALL 完整保留，故子字串稽核與危險規則比對不受影響。

#### Scenario: 上鍵重繪不把提示符寫進審計

- **WHEN** 使用者在 mssql 會話按上鍵召回歷史指令，且提示符與換行分屬兩次寫出（sqlcmd 實測行為）
- **THEN** `session_commands` 記下的該行文字為使用者的指令原文，不含任何 `<數字>>` 提示符前綴

#### Scenario: 快照為半截提示符時仍得到乾淨語句

- **WHEN** 分塊邊界切在提示符中間（快照為 `55`），其後重繪重印完整提示符與語句
- **THEN** 入庫文字為語句原文，行首既無 `<數字>>` 亦無孤立的 `>`

#### Scenario: 使用者自行輸入的提示符樣式文字不被剝除

- **WHEN** 提示符正常抵達，使用者輸入以 `55> ` 起頭的一行內容
- **THEN** 該行文字原樣入庫，`55> ` 不被移除

#### Scenario: 行首孤立大於號不被剝除

- **WHEN** 剝除閘門開啟（快照非提示符形態）而使用者輸入以 `> ` 或 `>>` 起頭的內容
- **THEN** 該行文字原樣入庫

#### Scenario: 其他協議不受本剝除影響

- **WHEN** 對 ssh／mysql／postgres 會話餵入同型的「提示符落入打字緩衝」位元組序列
- **THEN** mssql 專屬的剝除不啟動，結算文字仍留有 mssql 剝除本會拿掉的提示符殘餘；
  拿掉協議閘門即會使該斷言轉紅
- **AND** 該殘餘的形態**因本次的原點修正而改變**（種入的原點被切除，只餘重繪帶來的部分），
  故本 scenario 取代原規格「結算文字與本要求實作前完全相同」的說法——
  該說法在原點種入後不再成立，保留它會使規格描述一個系統不再具備的行為

### Requirement: MSSQL 批次終止符的使用者提示

mssql 會話的 web CLI SHALL 在連線成功後呈現一則協議專屬提示，說明 T-SQL 以**獨立一行的 `GO`** 送出批次、僅輸入分號不會執行。提示 SHALL 為可關閉，關閉後於該次會話內 SHALL NOT 再出現。

理由 SHALL 明載：同一個 web CLI 介面上 mysql／postgres 以 `;` 執行而 mssql 需要 `GO`，此差異在介面上無任何說明時，首次使用者會把「打了分號沒有反應」誤判為連線失敗（已由真實使用者踩中）。

**落點限制 SHALL 明載**：提示 SHALL 由前端呈現，SHALL NOT 由後端寫入終端輸出流——寫入輸出流會混進 asciicast 錄影與會話輸出基準，使回放與審計含有非目標主機產生的位元組。提示 SHALL NOT 藉由變更 sqlcmd 啟動參數達成（`-c` 自訂批次終止符旗標仍為 SHALL NOT 傳入）。

**協議判定 SHALL** 取自資產的協議欄位，SHALL NOT 由終端輸出內容推測。

系統 SHALL NOT 代使用者自動補上 `GO`，亦 SHALL NOT 提供代為改寫送出內容的捷徑——改寫會使審計文字與使用者實際送出的內容脫鉤。

#### Scenario: mssql 連線成功後看得到批次終止符說明

- **WHEN** 使用者以 mssql 協議連上 web CLI 且連線狀態為已連線
- **THEN** 終端上方出現一則說明 `GO` 為批次送出方式的提示，且該提示可被關閉

#### Scenario: 非 mssql 協議不出現此提示

- **WHEN** 使用者連上 ssh／mysql／postgres／redis／k8s 會話
- **THEN** 不出現批次終止符提示

#### Scenario: 提示不進錄影與審計

- **WHEN** 提示呈現於畫面
- **THEN** 該會話的 asciicast 錄影與 `session_commands` 皆不含此提示文字

### Requirement: 資料庫帳號的認證類型

資產帳號 SHALL 具備認證類型欄位 `auth_method`，值域 `sql`（資料庫本身的帳密認證）與 `domain`（作業系統／目錄服務整合認證）。既有列與未指定時 SHALL 為 `sql`。

該欄位 SHALL 位於**帳號**而非資產：憑證屬帳號，連線層取用的 username 與密碼皆來自帳號；同一台資料庫可同時掛一個資料庫本身的 login 與一個域帳號，欄位放在資產上會使兩者無法並存。

本階段 SHALL NOT 實作域認證。API 收到 `domain` 時 SHALL 明確拒絕並回機器碼，SHALL NOT 靜默降級為 `sql`——靜默接受一個做不到的設定會使管理員誤以為域認證已生效。UI SHALL 呈現該選項但標示為尚未支援，使預留可見。

#### Scenario: 既有帳號預設為 sql
- **WHEN** 升級後檢視既有資產帳號
- **THEN** `auth_method` 為 `sql`，連線行為不變

#### Scenario: 域認證被明確拒絕
- **WHEN** 以 API 建立或更新帳號並指定 `auth_method=domain`
- **THEN** 系統回 400 與機器碼，帳號未被建立或更新

#### Scenario: 值域外的值被拒絕
- **WHEN** 指定 `auth_method` 為值域外的字串
- **THEN** 系統回 400 與機器碼

