# portable-backup Specification

## Purpose
規範管理腳本產出的單一可攜備份檔：檔案組成、命名與權限、自我描述清單的欄位與版本語義、完整性驗證與提交點、主金鑰模式的判定與材料處理、可選的通行密語加密、工具映像的取得與核對、錄影的選擇，以及備份過程的問答、進度、完成、失敗與中斷輸出。還原行為不在本能力範圍。

## Requirements

### Requirement: 備份清單記載版本與部署型態

備份檔 SHALL 含 `backup-manifest.json`，其行格式與狀態檔相同：單層扁平 JSON、一行一鍵、鍵只含 `[a-z0-9_.]`、值為不含引號、反斜線與控制字元的 ASCII 字串；所有鍵必寫，布林只接受 `true`／`false`。清單 SHALL 至少記載：備份格式版本 `format`（本版為 `1`）、產生方式（手動或升級前）、停止服務的時間、是否加密與加密方案代號、產品版本、產生此檔的腳本版本、兩份發行清單成員的 SHA-256、匯出工具映像的鍵名、其所屬發行清單（內建資料庫為資料版本的發行清單，外接資料庫為產生者腳本的發行清單）與在該清單中的 digest、資料庫的 migration 筆數與排序後清單的 SHA-256、資料庫位置與伺服器版本、編碼與定序、匯出工具版本、部署 overlays、主機架構、TLS 模式、後端實際採用的主金鑰模式與是否顯式宣告、主金鑰材料是否在檔內、主金鑰指紋與其取得狀態、快照是否整體可用、各選擇性成員（錄影、TLS 憑證、自訂代理範本、狀態檔、資料庫 CA）是否收錄、各部分的原始大小，以及來源主機名稱、部署根、`DATA_PATH`、`TLS_DOMAIN`、`TLS_IP_SAN`、`PUBLIC_BASE_URL`、`TLS_NGINX_TEMPLATE`。`release-MANIFEST.json` SHALL 與備份當時 `current/MANIFEST.json` 逐位元組相同；`tool-MANIFEST.json` SHALL 與執行中腳本所屬發行版的 MANIFEST 逐位元組相同。選擇性成員的收錄旗標 SHALL 與實際成員雙向一致；TLS 憑證未收錄 SHALL 只表示部署當時沒有 `tls/`。自訂代理範本的原路徑 SHALL 在且只在收錄範本時非空。`TLS_NGINX_TEMPLATE` 的值是路徑而非機密，SHALL 照原值記入清單與紀錄檔。外接資料庫用的保留鍵（連線設定、TLS 信任來源與驗證程度、用戶端憑證旗標、授權角色清單、CA 收錄旗標）SHALL 在每一份檔案寫入；內建部署的值固定為空或 `false`；外接部署 SHALL 寫入實際值：原連線設定、信任錨來源、依後端連線程式庫規則推得的實際驗證程度、是否使用用戶端憑證，以及以每個角色名 UTF-8 位元組的 hex 表示、去重並依位元組序排列、以空白分隔的授權角色清單。讀取時，內建部署的檔案缺少這些保留鍵 SHALL 視同空或 `false`；外接部署的檔案缺任一保留鍵 SHALL 判為無效。

清單的產品版本 SHALL 等於狀態檔記載的已安裝版本，且等於 `current/MANIFEST.json` 的版本；兩者不一致時備份 SHALL 在停機前拒絕並指出兩個值。清單 SHALL NOT 含 `.env` 中任何機密值，也 SHALL NOT 含通行密語或其衍生值。

#### Scenario: 清單可由獨立解析讀回且交叉一致
- **WHEN** 以與狀態檔相同的行規則、但不經狀態檔載入流程，讀取剛產出備份檔內的 `backup-manifest.json`
- **THEN** 每行皆合格，產品版本等於部署狀態，migration 摘要與筆數等於由 `snapshot.txt` 重算的值，主金鑰指紋等於 `snapshot.txt` 的 KEK 指紋，兩份發行清單的雜湊與成員相符

#### Scenario: 內建部署的匯出工具指向資料版本的發行清單
- **WHEN** 內建資料庫部署完成手動備份
- **THEN** 清單記匯出工具為 `postgres`、所屬清單為資料版本的發行清單，其 digest 等於 `release-MANIFEST.json` 中 `postgres` 的 digest；外接用的保留鍵全部存在且為空或 `false`

#### Scenario: 收錄旗標與成員不一致即無效
- **WHEN** 清單檢查讀到憑證收錄旗標與成員清單是否含 `tls.tar.gz` 不一致，或範本收錄旗標與成員、原路徑是否為空三者不一致
- **THEN** 清單判為無效並指出該鍵，這樣的清單不會被寫進備份檔

#### Scenario: 已安裝版本與發行清單不一致
- **WHEN** 狀態檔記載 1.16.0 而 `current/MANIFEST.json` 記載 1.16.1
- **THEN** 備份在停止任何服務前以拒絕結束，畫面列出兩個版本，沒有產生備份檔

#### Scenario: 外接資料庫的清單欄位
- **WHEN** 外接資料庫部署完成備份
- **THEN** 清單記資料庫位置為外接、原連線位址與 `sslmode`、信任錨來源與實際驗證程度、是否使用用戶端憑證、授權角色清單，匯出工具指向產生者腳本的發行清單中的 `pgclientNN`（NN 為伺服器主版本）

#### Scenario: 角色名可逆編碼
- **WHEN** 外接資料庫有物件授權給 `report reader`（含空白）與 `報表`，另一個資料庫授權給 `report` 與 `reader` 兩個角色
- **THEN** 兩份清單的角色欄位不同，各自解碼後得到原本的角色名集合

#### Scenario: 外接支援加入前的內建檔在擴充後仍可讀
- **WHEN** 以擴充後的讀取規則讀一份外接支援加入前產出的內建部署清單
- **THEN** 清單判為有效；把外接部署清單刪掉任一保留鍵則判為無效

### Requirement: 備份檔完整性驗證後才提交

備份 SHALL 在封存內附 `SHA256SUMS`，每個成員恰一列、只用成員名，涵蓋除自身以外的全部成員。提交前 SHALL 確認：資料庫匯出檔可被還原工具列出內容、每個內層封存可被列出、組成後的備份檔可被完整讀回（加密時以固定解密參數與同一密語解密後讀回）、成員各出現一次且每個成員的雜湊等於 `SHA256SUMS`。組裝與驗證 SHALL 在暫存目錄內完成；校驗檔 SHALL 先於備份檔放到 `backups/`，備份檔以不覆寫的方式放到完成名稱即為提交點。提交點之前任何失敗 SHALL 不產生完成名稱的備份檔；提交點之後若狀態紀錄或暫存清理失敗，畫面 SHALL 說明備份檔有效，並列出未完成的項目與手動處置，結束碼為失敗。提交點之前的失敗與新紀錄寫入本身的失敗 SHALL NOT 改動上一次成功備份的狀態紀錄；新紀錄寫入成功之後才發生的清理失敗 SHALL 保留新紀錄。收到中斷訊號時，輸出 SHALL 依提交狀態決定：提交前說明沒有產生備份檔；已提交時說明備份檔有效，並列出狀態紀錄或清理中未完成的項目。

#### Scenario: 組成後讀回失敗
- **WHEN** 組成後的備份檔在讀回時有成員雜湊與 `SHA256SUMS` 不符
- **THEN** 不產生完成名稱的備份檔，畫面以 FAIL 指出暫存目錄位置、不能還原且含機敏明文，狀態檔的最近備份不變

#### Scenario: 提交後收到中斷訊號
- **WHEN** 備份檔已放到完成名稱、狀態檔尚未寫入時收到 SIGTERM
- **THEN** 畫面說明備份檔有效並列出路徑與校驗檔，再說明狀態檔未更新與暫存目錄未刪，不出現「沒有產生備份檔」

#### Scenario: 新紀錄寫入後清理失敗
- **WHEN** 狀態檔已指向新備份檔後，刪除暫存目錄失敗
- **THEN** 狀態檔仍指向新備份檔，畫面說明備份檔有效、暫存目錄須手動刪除，結束碼為失敗

#### Scenario: 提交後狀態檔寫入失敗
- **WHEN** 備份檔已放到完成名稱後，寫入狀態檔失敗
- **THEN** 畫面先說明備份檔有效並列出其路徑與校驗檔，再以 FAIL 說明狀態檔未更新，結束碼為失敗

### Requirement: 主金鑰模式依後端規則判定並處理材料

腳本 SHALL 以與後端相同的規則判定主金鑰模式：`KEK_PROVIDER` 與 `ENCRYPTION_KEY` 皆去除頭尾空白後判斷；未宣告或空值且有本地材料視為 `env`；`ui`、`kms`、`hsm` 帶本地材料、未宣告且無材料、`env` 無材料、或值不在白名單時，SHALL 在停止任何服務前拒絕，訊息只點名鍵名、不印值，且 SHALL NOT 刪改 `.env` 副本。

`env` 模式的 `.env` 副本 SHALL 原樣保留 `ENCRYPTION_KEY`，清單 SHALL 記載主金鑰材料在檔內，完成畫面的內容行 SHALL 標示設定檔「含主金鑰」，未加密時機敏警告 SHALL 點名主金鑰。`ui`、`kms`、`hsm` 模式下 `.env` 的 `ENCRYPTION_KEY` 必為空，腳本 SHALL NOT 另外蒐集任何主金鑰材料，清單 SHALL 記載材料不在檔內。清單 SHALL 保留快照中主金鑰指紋的實際值與其取得狀態；完成畫面 SHALL 依模式說明還原時主金鑰從何處取得並顯示指紋或金鑰識別。只有主金鑰指紋本身取不到時，畫面 SHALL 以 WARN 說明還原時無法自動核對主金鑰並照常產出；其他指紋取不到時 SHALL 另以不同的 WARN 說明。畫面、紀錄檔、狀態檔、清單與 `snapshot.txt` SHALL NOT 含 `.env` 的任何機密值。

#### Scenario: 未宣告模式的相容部署
- **WHEN** `.env` 沒有 `KEK_PROVIDER`、`ENCRYPTION_KEY` 有值
- **THEN** 清單記主金鑰模式為 `env`、未顯式宣告、材料在檔內，完成畫面標示「含主金鑰」

#### Scenario: 網頁輸入模式卻留有材料
- **WHEN** `.env` 的 `KEK_PROVIDER` 為 `ui` 且 `ENCRYPTION_KEY` 有值
- **THEN** 備份在停止任何服務前拒絕，畫面點名 `KEK_PROVIDER` 與 `ENCRYPTION_KEY` 兩個鍵名而不印值，沒有產生備份檔

#### Scenario: 本機環境變數模式的主金鑰入檔並標示
- **WHEN** `KEK_PROVIDER=env` 的部署完成未加密的備份
- **THEN** 備份檔內 `env.bak` 與部署的 `.env` 逐位元組相同，清單記材料在檔內，完成畫面的內容行標示「含主金鑰」，機敏警告點名主金鑰

#### Scenario: 主金鑰指紋有值而其他指紋取不到
- **WHEN** 快照的 KEK 指紋有唯一值，但 checkpoint 指紋取不到而整體標為不可用
- **THEN** 清單保留 KEK 指紋並記其狀態為可用，完成畫面不說主金鑰指紋取不到，另以 WARN 說明其餘指紋須人工比對

#### Scenario: 機密值不外洩
- **WHEN** 任一主金鑰模式完成備份
- **THEN** `.env` 中 `ENCRYPTION_KEY`、`JWT_SECRET`、`DB_PASSWORD` 的值不出現在畫面、紀錄檔、狀態檔、`backup-manifest.json` 與 `snapshot.txt`

### Requirement: 可選擇以通行密語加密備份檔

手動備份 SHALL 可選擇以通行密語加密整份備份檔；預設不加密。只有 stdin 是終端機且未帶 `--yes` 時才詢問；選擇加密時 SHALL 不回顯地輸入兩次密語並比對，原樣保留前後空白；兩次不同、長度不在 12 到 256 個字元、或含可列印 ASCII 以外的字元時 SHALL 重問，三輪都未成功或輸入中斷時 SHALL 取消且不停止任何服務。`--passphrase-file <檔案>` SHALL 以檔案第一行為密語並加密且不再詢問；檔案不存在、不是一般檔、是符號連結、讀不到、第一行不合規則、群組或其他人有讀寫權限、擁有者不是執行者也不是 root、或設有擴充存取控制清單時，SHALL 在停止任何服務前拒絕並給出可複製的修正指令。帶 `--yes` 而未給 `--passphrase-file` 時 SHALL 不加密且不詢問，預覽 SHALL 說明如何加密。

加密 SHALL 以發行清單釘選並核對過的映像內的 openssl 執行，使用固定方案：AES-256-CBC 與 PKCS#7 填補、PBKDF2-HMAC-SHA256 600,000 次、8 bytes 隨機鹽、openssl 加鹽檔頭格式；支援指定鹽長的工具版本 SHALL 顯式指定 8 bytes；SHALL NOT 依賴主機上的加密工具。缺少該映像時 SHALL 在停止任何服務前拒絕。密語 SHALL NOT 出現在任何程序的命令列參數或環境變數、紀錄檔、狀態檔，腳本 SHALL NOT 建立含密語的檔案。明文的整份 tar SHALL NOT 落地。完成畫面 SHALL 標示已加密與加密方案，並以 WARN 說明還原需要同一密語且密語遺失即無法還原。

#### Scenario: 互動選擇加密
- **WHEN** 維運在終端機執行 `backup`，選擇加密並兩次輸入相同且合規的密語
- **THEN** 產出 `.tar.enc` 與其 `.sha256`，前 8 bytes 為 `Salted__`、鹽長 8 bytes，以同一密語與固定參數解密後得到成員齊全且雜湊相符的 tar，完成畫面標示已加密

#### Scenario: 兩次密語不同
- **WHEN** 維運兩次輸入的密語不同
- **THEN** 畫面以 WARN 要求重輸並顯示剩餘次數；三輪都不同時備份取消，沒有停止任何服務，結束碼 3

#### Scenario: 終端機上帶 --yes
- **WHEN** 維運在終端機執行 `backup --yes` 而未給 `--passphrase-file`
- **THEN** 不出現任何問題，備份不加密，預覽說明以 `--passphrase-file` 加密的方法

#### Scenario: 密語檔權限過寬
- **WHEN** 排程以 `backup --yes --passphrase-file <模式 0644 的檔>` 執行
- **THEN** 備份在停止任何服務前以 FAIL 結束並印出 `chmod 600` 的修正指令，沒有產生備份檔

#### Scenario: 密語不外洩
- **WHEN** 以任一方式提供密語完成加密備份
- **THEN** 密語不出現在紀錄檔、狀態檔、清單、任何程序的命令列參數或環境變數，腳本沒有建立含密語的檔案

#### Scenario: 固定方案可解開已知答案向量
- **WHEN** 以固定測試密語與規定的解密參數解開倉庫內的加密測試向量
- **THEN** 解出的明文 SHA-256 等於獨立記錄的已知值；錯密語、改變迭代次數、改變雜湊演算法或截斷一個區塊時，皆得不到該明文

### Requirement: 工具映像與部署容器分開核對

加密使用的 openssl 映像在服務映像組不含它的部署形態（外部入口形態），以及外接資料庫部署的 PostgreSQL 16、17、18 客戶端映像，SHALL 作為工具映像取得，並以發行清單的 digest 核對內容、記錄本機 image ID；工具映像 SHALL NOT 被當成須常駐執行的部署容器核對，也 SHALL NOT 列在 `status` 的容器清單中。執行工具時 SHALL 以記錄的 image ID 啟動，且 SHALL NOT 拉取未釘選的映像。

#### Scenario: 外部入口形態的工具映像
- **WHEN** 使用外部入口 overlay 的部署完成安裝或升級
- **THEN** openssl 映像已取得並核對內容，啟動後的容器核對不要求有執行中的 tls-init 容器且結果為通過，`status` 的容器清單不含它

#### Scenario: 外接資料庫與外部入口同時使用
- **WHEN** 外部入口與外接資料庫兩種 overlay 同時使用的部署完成安裝或升級
- **THEN** openssl 與三顆 PostgreSQL 客戶端映像已取得並核對內容，啟動後的容器核對不要求它們有執行中的容器且結果為通過

### Requirement: 錄影預設不放入備份檔

錄影 SHALL 預設不放入備份檔；稽核檔、資料庫與設定 SHALL 一律放入，憑證在部署有 `tls/` 時 SHALL 一律放入。只有 stdin 是終端機且未帶 `--yes` 時，預覽 SHALL 列出錄影大小並詢問是否放入，Enter 為不放入，並分別顯示兩種選擇的預估大小與暫停時間，某選項所需空間超過可用量時 SHALL 標出。`--with-recordings` SHALL 放入錄影且不再詢問；帶 `--yes` 而未帶 `--with-recordings` 時 SHALL 不放入且不詢問。未放入錄影時完成畫面 SHALL 以 WARN 指出錄影目錄位置與另行保存的必要。

#### Scenario: 互動直接按 Enter
- **WHEN** 維運在終端機執行 `backup`，於錄影問題直接按 Enter 並確認開始
- **THEN** 備份檔不含 `recordings.tar.gz`，清單記錄影未收錄，完成畫面以 WARN 列出錄影目錄

#### Scenario: 自動化指定放入錄影
- **WHEN** 排程以 `backup --yes --with-recordings` 執行
- **THEN** 不出現任何問題，備份檔含 `recordings.tar.gz`

### Requirement: 停機一致性、重啟結果與失敗語義

備份 SHALL 先停止後端、連線服務與網頁再擷取資料（內建資料庫保持運作），擷取完資料庫、檔案、設定與憑證後即重新啟動服務並以既有健康檢查等待後端就緒，等待 SHALL 有上限；驗證與組裝在重新啟動之後進行。重新啟動的結果 SHALL 分三種呈現：本機環境變數模式就緒為「服務已恢復」；網頁輸入與委託模式就緒為「已啟動、待解封」並給出解封指引；逾時為「未就緒」並給出查看狀態與再次啟動的指令，備份繼續完成。畫面 SHALL NOT 在未確認就緒或仍待解封時宣稱服務已恢復。

空間檢查 SHALL 在停止任何服務前完成，需求量 SHALL 計入組裝期間的暫存量與餘裕；不足即拒絕並說明可採取的動作。任一步失敗 SHALL 停下、保留暫存內容並指出其位置與機敏性；本次尚未確認服務已重新啟動時 SHALL 印出可複製的啟動指令。收到中斷訊號時 SHALL 停止並等待本次啟動的工具程序與容器、刪除管道與連線密碼檔，保留其餘暫存內容並印出啟動與重新備份的指令。stdin 不是終端機且未帶 `--yes` 時 SHALL 以拒絕結束而不等待。

#### Scenario: 空間不足
- **WHEN** 備份位置的可用空間小於含組裝暫存與餘裕的預估需求
- **THEN** 腳本在停止任何服務前以 FAIL 結束並列出需要量、可用量與可採取的動作

#### Scenario: 擷取資料庫時失敗
- **WHEN** 服務已停止後資料庫匯出失敗
- **THEN** 沒有完成名稱的備份檔，畫面以 FAIL 指出暫存位置，並印出啟動服務的指令

#### Scenario: 重新啟動後待解封
- **WHEN** 委託模式的部署完成備份，後端在等待上限內就緒
- **THEN** 完成畫面說明服務已啟動、待解封並給出解封頁位址，不出現「服務已恢復」

#### Scenario: 重新啟動逾時
- **WHEN** 後端在等待上限內沒有就緒
- **THEN** 第 5 步標為 WARN，備份繼續完成，完成畫面說明未就緒並印出查看狀態與啟動指令

#### Scenario: 備份中斷
- **WHEN** 備份在第 3 步收到中斷訊號
- **THEN** 本次啟動的工具程序與容器已結束、連線密碼檔與管道已刪除，沒有完成名稱的備份檔，畫面印出啟動服務與重新備份的指令

### Requirement: 備份問答與輸出三語一致

`backup` 的預覽、問答、進度、完成、失敗與中斷畫面 SHALL 以 zh-TW、en、ja 三語提供，三語訊息鍵集與參數數量 SHALL 相同；狀態標記沿用 ASCII 字樣。主選單已安裝狀態的備份項目 SHALL 維持原編號並以新標籤表示產出可攜備份檔。`--help` SHALL 列出 `--with-recordings` 與 `--passphrase-file`，且只有 `backup` 接受這兩個旗標，其他子命令收到時 SHALL 以用法錯誤結束。`status` 的最近備份 SHALL 顯示備份檔路徑與大小，加密的備份註明已加密，舊格式紀錄照常顯示資料夾。可攜檔、資料夾與自備備份三種紀錄指標 SHALL 互斥：寫入其中一種時清掉另兩種留下的指標，`status` SHALL NOT 把一次備份的時間與另一次備份的路徑配在一起。

#### Scenario: 三語畫面逐字比對
- **WHEN** 以三種語言各執行一次成功的互動備份
- **THEN** 每種語言的畫面與審定的文字稿逐字相同

#### Scenario: 最近備份顯示檔案
- **WHEN** 加密備份成功後執行 `status`
- **THEN** 最近備份一段列出備份檔的絕對路徑與大小並註明已加密

#### Scenario: 手動可攜檔之後做了一次資料夾形式的升級前備份
- **WHEN** 先完成一次加密的手動備份，再執行一次產生資料夾備份的升級
- **THEN** `status` 的最近備份顯示升級的資料夾路徑與該次的時間，不顯示先前的 `.tar.enc` 路徑或「已加密」

#### Scenario: 其他子命令不接受備份旗標
- **WHEN** 維運執行 `load <離線包> --with-recordings`
- **THEN** 腳本以用法錯誤結束，不載入任何映像

### Requirement: 備份產物為單一可攜檔且適用外接資料庫

`custodexa.sh backup` SHALL 在部署根的 `backups/` 下產出單一檔案 `custodexa-backup-<產品版本>-<YYYYMMDD-HHMMSS>.tar`，以及同目錄、同名加 `.sha256` 的校驗檔，其內容可直接以 `sha256sum -c` 核對該備份檔。選擇加密時，備份檔名改以 `.tar.enc` 結尾、內容為整個 tar 的密文，校驗檔為同名加 `.sha256` 並核對密文。`backups/` 與暫存目錄權限 SHALL 為 0700，暫存成員、備份檔與校驗檔在建立時即 SHALL 為 0600。腳本 SHALL NOT 覆寫任何既有備份檔或校驗檔。備份檔 SHALL 為未壓縮的 tar，成員 SHALL 只有固定名稱的一般檔案，各至多出現一次，位於封存根層、不含目錄、連結或含 `/` 與 `..` 的名稱。成員固定為：`backup-manifest.json`、`release-MANIFEST.json`、`tool-MANIFEST.json`、`snapshot.txt`、`db.dump`、`audit.tar.gz`、`env.bak`、`SHA256SUMS`；選擇放入錄影時另含 `recordings.tar.gz`；部署根有 `tls/` 時另含 `tls.tar.gz`，沒有 `tls/`（例如外部入口形態）時 SHALL 照常完成且不含該成員；`.env` 設了 `TLS_NGINX_TEMPLATE` 時另含 `nginx-tls.conf.template`，內容與該設定所指的檔案（相對路徑以部署根為準）逐位元組相同；升級前備份另含 `state.json`；外接資料庫設了可換算的 CA 檔時另含 `db-ca.pem`。`TLS_NGINX_TEMPLATE` 有值而所指不是可讀的一般檔案，或其值含清單無法記載的字元時，備份 SHALL 在停止任何服務前拒絕並指出該路徑。匯出產物目錄 SHALL NOT 放入備份檔。

#### Scenario: 完成的備份只有一個檔與其校驗檔
- **WHEN** 維運在內建資料庫的安裝包部署執行 `backup --yes` 且成功
- **THEN** `backups/` 下新增一個 `custodexa-backup-1.16.0-<時間>.tar` 與其 `.sha256`，兩者權限 0600，`sha256sum -c` 通過，封存內成員名稱恰為固定清單、各出現一次且皆為一般檔案

#### Scenario: 匯出產物不入檔
- **WHEN** 資料目錄下的匯出產物目錄有檔案時執行備份
- **THEN** 備份檔任何成員（含內層封存）都不含匯出產物目錄的內容

#### Scenario: 外部入口形態沒有 tls/
- **WHEN** 部署根沒有 `tls/` 的外部入口形態部署執行 `backup --yes`
- **THEN** 備份照常完成，備份檔不含 `tls.tar.gz`，清單記憑證未收錄且成員清單不含它，`SHA256SUMS` 通過，完成畫面的內容行不列憑證

#### Scenario: 帶入自訂代理範本
- **WHEN** `.env` 的 `TLS_NGINX_TEMPLATE` 指向一個可讀的範本檔（相對或絕對路徑）並執行 `backup --yes`
- **THEN** 備份檔含 `nginx-tls.conf.template`，內容與該檔逐位元組相同、權限 0600，清單記範本已收錄且原路徑照 `.env` 的寫法記載，完成畫面的內容行列出代理範本與該路徑

#### Scenario: 自訂代理範本讀不到
- **WHEN** `.env` 的 `TLS_NGINX_TEMPLATE` 指向不存在的檔案或一個目錄
- **THEN** 備份在停止任何服務前以結束碼 3 拒絕，畫面列出解析後的路徑，沒有產生備份檔

#### Scenario: 自訂代理範本路徑含清單無法記載的字元
- **WHEN** `.env` 的 `TLS_NGINX_TEMPLATE` 指向可讀的檔案，但路徑含雙引號或反斜線
- **THEN** 備份在停止任何服務前以結束碼 3 拒絕並列出 `.env` 的原值，不會到組裝備份檔時才失敗

#### Scenario: 外接資料庫的自訂 CA 入檔
- **WHEN** 外接資料庫部署的 `.env` 以 `PGSSLROOTCERT` 指定可換算的 CA 檔並完成備份
- **THEN** 備份檔含 `db-ca.pem`，內容與該 CA 檔相同，清單的 CA 收錄旗標為 `true`

#### Scenario: 外接資料庫部署產出同一格式的備份檔
- **WHEN** 使用外接資料庫 overlay、伺服器主版本有對應客戶端且沒有不支援依賴的部署執行 `backup --yes`
- **THEN** 腳本不以外接資料庫為由拒絕，產出同一命名與權限的備份檔與其 `.sha256`，封存成員為固定清單，清單記載資料庫位置為外接

#### Scenario: 同一秒已有備份
- **WHEN** `backups/` 下已有與本次時間戳同名的備份檔或暫存目錄
- **THEN** 腳本在停止服務前改用下一秒的時間戳，既有檔案不被改動

### Requirement: 外接資料庫部署由腳本一併備份

使用外接資料庫 overlay 的部署，`backup` SHALL 連到 `.env` 指定的外接資料庫匯出資料庫，SHALL NOT 以外接資料庫為由拒絕。匯出 SHALL 使用發行清單釘選、已核對的 PostgreSQL 16、17、18 客戶端映像，這些映像 SHALL 作為工具映像取得與核對，SHALL NOT 被當成須常駐執行的部署容器核對。停機前 SHALL 依序：確認客戶端映像在本機、以客戶端探測伺服器版本、選用與伺服器主版本相同的客戶端、檢查支援邊界、估算空間；任一步不成立 SHALL 在停止任何服務前拒絕，並分別說明是工具不在本機、連不上或認證失敗、沒有同主版本工具，或有不支援的依賴。

支援邊界：資料庫有自訂表空間、物件擁有者不只 `DB_USER`、有 `plpgsql` 以外的擴充套件時 SHALL 拒絕並列出命中項目；`public` schema 本身由內建角色 `pg_database_owner` 擁有時 SHALL NOT 視為其他擁有者，但其中的物件仍須由 `DB_USER` 擁有。物件權限授予 `DB_USER`、`PUBLIC` 與 `pg_` 開頭內建角色以外的角色時 SHALL NOT 拒絕，SHALL 把角色名以可逆編碼記入清單並在完成畫面以 WARN 說明新伺服器上須先建立這些角色，否則還原後權限會不同。客戶端驗證伺服器憑證的程度 SHALL 與後端連線程式庫在同一設定下的實際行為相同，SHALL NOT 降低或提高 `sslmode`（`PGSSLROOTCERT=system` 時後端本身即改用 `verify-full`，客戶端相同）；`DB_SSLMODE` 未設或為空時 SHALL 依後端設定層的規則視為 `disable`；後端不驗證伺服器憑證的模式下，客戶端 SHALL NOT 載入任何根憑證（不帶 `sslrootcert`、不繼承 `PGSSLROOTCERT` 或家目錄的根憑證檔）；`verify-ca` 而未指定 CA 檔時 SHALL 以匯出工具映像的系統 CA 檔驗證，該檔不存在即在停機前拒絕；`.env` 指定自訂 CA 檔時，該檔 SHALL 放入備份檔，指定的路徑無法換算為腳本可讀的位置時 SHALL 拒絕。用戶端憑證的私鑰 SHALL NOT 放入備份檔，清單 SHALL 記載有使用用戶端憑證；私鑰位於會被打包的目錄下時 SHALL 拒絕。資料庫密碼 SHALL NOT 出現在任何程序的命令列參數或環境變數，也 SHALL NOT 出現在紀錄檔。快照（筆數、migration、指紋）SHALL 以同一客戶端取得。預覽 SHALL 提醒備份期間不得讓備援主機接手該資料庫。

#### Scenario: 外接資料庫版本可支援
- **WHEN** 外接資料庫伺服器主版本為 17，維運執行 `backup --yes`
- **THEN** 服務停止後以 17 的已釘選客戶端匯出，清單記載資料庫位置為外接、伺服器版本、匯出工具版本與該客戶端映像的 digest

#### Scenario: 外接資料庫沒有同主版本工具
- **WHEN** 外接資料庫伺服器主版本為 15 或 19
- **THEN** 備份在停止任何服務前以 FAIL 結束，畫面列出伺服器版本與可用客戶端主版本，沒有產生備份檔

#### Scenario: 外接資料庫有自訂表空間
- **WHEN** 外接資料庫有物件放在自訂表空間
- **THEN** 備份在停止任何服務前以 FAIL 結束，畫面列出該表空間名稱與物件數

#### Scenario: 授權給其他角色
- **WHEN** 外接資料庫中有物件授權給角色 `report_reader`
- **THEN** 備份照常完成，清單記載 `report_reader`，完成畫面以 WARN 說明須先建立該角色

#### Scenario: 預設 public schema 的專用庫
- **WHEN** 外接資料庫以預設方式建立（`public` 由 `pg_database_owner` 擁有），產品的表全由 `DB_USER` 擁有
- **THEN** 依賴檢查通過，備份照常完成，授權角色清單不含 `pg_database_owner`

#### Scenario: verify-ca 且未指定 CA 檔
- **WHEN** `DB_SSLMODE=verify-ca` 且 `.env` 沒有 `PGSSLROOTCERT`
- **THEN** 客戶端以 `verify-ca` 加匯出工具映像的系統 CA 檔連線，清單記信任錨來源為系統、驗證程度為 `ca`；該映像沒有系統 CA 檔時在停止任何服務前拒絕

#### Scenario: require 搭配自訂 CA
- **WHEN** `DB_SSLMODE=require` 且 `PGSSLROOTCERT` 指向可換算的 CA 檔
- **THEN** 客戶端以 `require` 加該 CA 檔連線，清單記驗證程度為 `ca`，預覽的連線行說明以 CA 檔驗證、不核對主機名稱

#### Scenario: prefer 搭配不匹配的 CA 檔
- **WHEN** `DB_SSLMODE=prefer` 且 `PGSSLROOTCERT` 指向一個與伺服器憑證不匹配的 CA 檔
- **THEN** 備份與後端一樣不驗證伺服器憑證而照常完成，CA 檔仍放進備份檔，清單記信任錨來源為 `file`、驗證程度為 `none`

#### Scenario: 未設 DB_SSLMODE
- **WHEN** `.env` 沒有 `DB_SSLMODE`（或為空字串）且沒有 `PGSSLROOTCERT`
- **THEN** 客戶端以 `disable` 連線，清單的 `sslmode` 欄為空、驗證程度為 `none`，預覽的連線行顯示 `disable`
