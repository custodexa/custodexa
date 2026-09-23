# 稽核檢查點鏈：離線驗章規格與外部驗證指南

> 對象：稽核單位、QSA、客戶方安全團隊——**不需要信任本系統、也不需要取得產品原始碼**的第三方。
> 版本：canonical 編碼 v1、v2 與 v3（見下方「載荷版本」；新封檢查點為 `cp-agg-v3`，各版本的位元組一經釘定不再變更）。
> 本文件所載的每一條規格都經實測，證據見文末「規格的實測驗證」。
>
> 若您是稽核方或客戶安全團隊，需要控制項對照表或其他評鑑材料，
> 請依 `SECURITY.md` 的聯絡管道索取——本檔可獨立使用，
> 驗章所需的全部規格與工具（`tools/checkpoint-verify/`）皆已一併提供。

## 0. 這份文件證明什麼、不證明什麼

檢查點鏈的對外承諾是：**你可以拿公鑰，在我們的系統之外，自行判定某個檢查點是否被動過**。
系統內建的驗證端點（`GET /api/v1/audit-checkpoints/verify`）與封章程式共用同一份程式碼，
它證明不了規格本身可被外部重建——所以才有本文件與獨立工具。

離線驗章**能**判定的：

- 檢查點的被簽欄位（區間、列數、聚合雜湊、鏈接雜湊、封章時間、鑰版本）自封章後未被修改。
- 檢查點之間的鏈接未被切斷或重排（`prev_checkpoint_hash` 可逐點重算）。
- 區間是否連續（`id_from` 是否等於前一點的 `id_to + 1`），即鏈上有無「被拿掉一段」的缺口。

離線驗章**不能**判定的（誠實邊界，勿在對外簡報中越線宣稱）：

- **不能**判定稽核日誌「內容」正確：簽章覆蓋的是檢查點欄位，不是 `audit_logs` 的列內容。
  要驗內容需另行執行內容層驗證（需資料庫存取，見第 6 節聚合編碼）。
- **不能**判定鏈頭之前是否曾有資料：鏈頭（最小 `seq`）的 `prev_checkpoint_hash` 錨定
  `integrity_baselines`，該錨定值需要基準記錄才能重算，**不在僅憑 API 的可驗範圍內**。
- **不能**證明公鑰屬於誰：公鑰的真實性須以帶外方式建立（指紋當面核對、憑證、
  交付文件簽收）。本系統只保證**私鑰無任何匯出、下載或刪除路徑**。
- `anchor_status` 為本地參考資訊，**不在簽章涵蓋範圍**，不得作為外部錨定證據。

## 1. 取得驗證所需資料

| 用途 | 端點 | 角色 |
|---|---|---|
| 公鑰 | `GET /api/v1/audit-checkpoints/public-key` | admin 或 auditor |
| 檢查點列表 | `GET /api/v1/audit-checkpoints?page=N&page_size=200` | admin 或 auditor |

公鑰回應：

```json
{"data":{"algorithm":"Ed25519","fingerprint":"8f28c059ed36ad69",
         "public_key":"2i0fl9yPbPABeYN1gxlPCmldrxcq5jrD5lMqXuzyYUE=","version":1}}
```

- `public_key`＝**原始 32 bytes Ed25519 公鑰的 base64（標準字母表、含 padding）**，非 PEM、非 DER。
- `fingerprint`＝該 32 bytes 的 SHA-256 前 8 bytes 之 hex（用於帶外核對）。
- `version` 對應檢查點的 `signing_key_version`；驗證時**必須**以相同版本的公鑰驗，
  版本不符即應判為驗證失敗，不得改用其他版本重試。

檢查點列表回應（`data.items` 為陣列、`seq` 倒序，`data.total` 為總數）。單頁上限 200 筆，
鏈長可達萬級，**必須逐頁取完**——只取首頁會讓其餘檢查點在報表上安靜消失。單筆形如：

```json
{"id":21,"seq":21,"id_from":22221,"id_to":22226,"row_count":6,
 "agg_hash":"15a0671d…","agg_scheme":"cp-agg-v1","prev_checkpoint_hash":"49836f01…",
 "min_created_at":"2026-08-12T19:09:00.080086Z","max_created_at":"2026-08-12T19:22:17.090016Z",
 "sealed_at":"2026-08-12T20:10:30.062453Z","signing_key_version":1,
 "signature":"lFAS2vwNg4xfy2Tnu4iZWuSB6x5wplrjcgq4dJM0rQhq27/pAd208S4JncgsWGw7xpMD+La9Ebnu5SeE57QmBQ==",
 "anchor_status":"disabled","created_at":"2026-08-12T20:10:30.070697Z"}
```

**易踩的坑（必讀）**：空區間的檢查點（`row_count = 0`）其 `min_created_at`／`max_created_at`
在 JSON 回應中**整個鍵被省略**，但 canonical payload 中這兩個欄位**必須以 `null` 明確寫出**。
把「省略」照抄成「省略」會使該類檢查點永遠驗不過。

## 2. 簽章 payload 的 canonical 編碼（外部驗章者需要的就是這一份）

被簽的位元組＝**UTF-8 編碼的緊湊 JSON 物件**，規則如下，缺一不可：

1. **無任何空白**：鍵與值之間、逗號之後皆無空格；無換行、**無結尾換行字元**。
2. **鍵順序固定**（非字典序，而是下表由上而下的宣告序），且**所有鍵一律出現**，
   包含值為 `null` 的欄位——沒有 omitempty、沒有條件性省略。
3. 整數以十進位輸出，無正號、無前導零、無小數點、無指數表示。
4. 字串以雙引號包覆。本 payload 的字串欄位值域限於 hex 與受控枚舉，
   理論上不含需跳脫字元；若實作遇到需跳脫的字元，應**報錯而非自行猜測跳脫規則**
   （產品端以 Go `encoding/json` 產生，其預設會將 `<`、`>`、`&` 分別輸出為
   `\u003c`、`\u003e`、`\u0026` 這類六字元跳脫序列；其餘控制字元依 JSON 規範跳脫）。
5. 時間欄一律轉為 **Unix 微秒整數**（見第 3 節），欄名帶 `_us` 後綴。

### 載荷版本

被簽欄位的組成**隨載荷版本而異**，版本值即檢查點自身的 `agg_scheme` 欄。
驗章者一律**先讀該欄再決定重建哪一組鍵**，不可假設全鏈同版本——升級後的鏈
必然是混版本的（舊點以其原版本重建，新點以新版本重建）。

| 版本值 | 被簽的鍵 | 出現時機 |
|---|---|---|
| `cp-agg-v1` | 下表第 1–8、11–13 鍵（無 `state`、無 `role_state_reconciled`） | 角色指派納入鏈之前封的檢查點 |
| `cp-agg-v2` | 下表全部 13 鍵 | 角色指派納入鏈之後、帳本入鏈之前的檢查點 |
| `cp-agg-v3` | v2 全部鍵＋帳本四欄（見文末第三版） | 帳本入鏈之後的新封章 |

三版本的操作日誌 `agg_hash` 計算方式**完全相同**（第 6 節未變）；v2 的差別只在載荷多兩個鍵。
遇到不認識的版本值時應**停止並回報**，不可猜一組鍵去驗——猜錯的結果會是
「簽章驗不過」，把版本不相容偽裝成竄改。

| # | 鍵 | 型別 | 來源欄位 | 說明 |
|---|---|---|---|---|
| 1 | `seq` | 非負整數 | `seq` | 檢查點序號，自 1 起連續 |
| 2 | `id_from` | 非負整數 | `id_from` | 區間起始 `audit_logs.id`（含） |
| 3 | `id_to` | 非負整數 | `id_to` | 區間結束 `audit_logs.id`（含）；空區間時 `id_to = id_from - 1` |
| 4 | `row_count` | 整數 | `row_count` | 區間內列數 |
| 5 | `agg_hash` | 字串 | `agg_hash` | 聚合雜湊，64 字元小寫 hex（空區間為空輸入的 SHA-256：`e3b0c442…b855`） |
| 6 | `agg_scheme` | 字串 | `agg_scheme` | 聚合／載荷版本標識，值域 `cp-agg-v1`／`cp-agg-v2`／`cp-agg-v3`；先讀本欄再決定重建哪一組欄位（見載荷版本表） |
| 7 | `prev_checkpoint_hash` | 字串 | `prev_checkpoint_hash` | 前一檢查點的鏈接雜湊，64 字元小寫 hex |
| 8 | `min_created_at_us` | 整數或 `null` | `min_created_at` | 區間內最早 `created_at`；空區間為 `null` |
| 9 | `state` | 陣列（**僅 v2**） | `role_state_snapshot` | 隨檢查點簽入的權限狀態摘要，見下節 |
| 10 | `role_state_reconciled` | 布林或 `null`（**僅 v2**） | `role_state_reconciled` | 封章當下的權限狀態核對結果；`null`＝該次封章未做核對 |
| 11 | `max_created_at_us` | 整數或 `null` | `max_created_at` | 區間內最晚 `created_at`；空區間為 `null` |
| 12 | `sealed_at_us` | 整數 | `sealed_at` | 封章時間，**不可為 null** |
| 13 | `signing_key_version` | 整數 | `signing_key_version` | 簽章鑰版本 |

> `state` 與 `role_state_reconciled` 兩鍵夾在 `min_created_at_us` 與
> `max_created_at_us` 之間，**不在結尾**。鍵順序是規格的一部分，請照本表由上而下輸出。

### `state`：權限狀態摘要（v2 起）

每個檢查點另簽入封章當下的權限狀態指紋，使「直接改資料庫把某個帳號變成管理者」
無法在不被察覺的情況下發生。被簽的是摘要，不是狀態本身：

```
"state":[{"table":"user_roles","hash":"<64 字元小寫 hex>","count":<非負整數>}]
```

- 陣列元素依 `table` 升冪排序；每個物件的鍵順序固定為 `table`、`hash`、`count`。
- 新封章含三個元素，依序為 `agent_tokens`、`user_principals`、`user_roles`；舊點只含當時已登記的項，驗證時依該點實際鍵集合重建。
- **`hash` 由快照本體現算，不可直接取 `role_state_hash` 欄**：產品端簽的就是現算值。
  取欄位會使「本體被改、摘要欄未改」的檢查點在您的實作驗過、在系統內驗不過。

快照本體來自檢查點的 `role_state_snapshot` 欄，形狀為以表名為鍵的緊湊 JSON 物件：

```
{"user_roles":[[1,1],[2,2],[10,2]]}
```

其中每個元素是 `[帳號識別碼, 角色識別碼]`，依帳號識別碼、角色識別碼升冪排序。
**角色指派本體只有整數**；三項均不含帳號名、電子郵件或任何個人資料。

新增投影的離線重建步驟：

1. `user_principals` 取未軟刪帳號的 `[id,kind,owner_user_id]`，依 id 數值升冪。`kind` 為 `human`／`agent`，human 的 owner 明寫 `null`。
2. `agent_tokens` 取全部憑證的 `[id,user_id,revoked,suspended,credential_fingerprint,expires_at]`，依 id 數值升冪；旗標是 JSON boolean，指紋是對資料庫儲存的 token_hash 字串 UTF-8 位元組再取 SHA-256 的小寫 hex，並非 token_hash 原值。到期值使用 UTC RFC3339Nano（尾端小數零省略，整秒無小數，`Z` 結尾）。名稱、原因、註記與最後使用時刻均不入快照。
3. 每項編碼為無空白 JSON 陣列；空項為 `[]`。外層鍵依字典序：`{"agent_tokens":<陣列>,"user_principals":<陣列>,"user_roles":<陣列>}`。
4. 對每個陣列原始位元組獨立套下式，再按相同鍵序組出 `state`。`TestCheckpointOfflineRebuildThreeKeys` 以手寫陣列及長度前綴重建，比對產品快照與摘要。

新增鍵不改載荷版本或聚合算法：封章使用 `model.LatestCheckpointScheme`（目前 `cp-agg-v3`）；後續版本升級時沿用當時最新值。`role_state_reconciled` 為全部項的合取；有不符記 false，全數已涵蓋且相符才記 true，其餘未知／未涵蓋記 null。

`hash` 的計算＝對該表的本體位元組（如上例的 `[[1,1],[2,2],[10,2]]`，不含表名與外層大括號）：

```
hash = SHA-256( 本體長度的 8 位元組大端無號整數 ‖ 本體位元組 )
```

長度前綴不可省：少了它，不同的本體切法可以湊出相同的雜湊輸入。
`count` ＝本體陣列的元素個數（同樣由本體現算，不取 `role_state_count` 欄）。

若您取得的資料不含 `role_state_snapshot`（部署可能不將其對外投影），
只有單項 `user_roles` 的舊點可改以 `role_state_hash` 與 `role_state_count` 兩欄組出 `state` 完成驗章；三項新點須取得全部三項摘要，不能以角色摘要代替，
但此時驗到的是「摘要未被改」而非「快照本體未被改」，報表上應明確標示。

**不納入簽章的欄位**（列出以杜絕誤解）：`id`、`created_at`、`anchor_status`、
`purged_at`、`purge_signature` 及其鑰版本欄。前二者是資料庫列的自身屬性，
後數者是封章**之後**才可能發生的狀態——蓋進簽章就永遠簽不出來。
purge 的真實性由獨立的 purge 簽章承擔。

### 完整範例（取自實測，可逐位元組比對）

有列的檢查點（`seq = 21`）：

```
{"seq":21,"id_from":22221,"id_to":22226,"row_count":6,"agg_hash":"15a0671df69d7f43e1c2d8ccbb77e5f4994dbe8f1b66b7b28543d722519bfdec","agg_scheme":"cp-agg-v1","prev_checkpoint_hash":"49836f01630eae691d33487c14305b2e567a8e250d12341bcc5dae52ac5ad224","min_created_at_us":1786561740080086,"max_created_at_us":1786562537090016,"sealed_at_us":1786565430062453,"signing_key_version":1}
```

其 `sha256(payload) = 9ed45e49e59f8c07b57d18e7811a5003a406a7cd1afac68380da98523d9d9145`。

空區間的檢查點（`seq = 26`，注意兩個 `null`）：

```
{"seq":26,"id_from":22227,"id_to":22226,"row_count":0,"agg_hash":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","agg_scheme":"cp-agg-v1","prev_checkpoint_hash":"37bcada97b8841f34268fef8f4cc15dc47de5bcb08c4d9d1fbf0ca5d3c683684","min_created_at_us":null,"max_created_at_us":null,"sealed_at_us":1786585166358566,"signing_key_version":1}
```

其 `sha256(payload) = 681ff4046cf8fab50096982a5a7da62a1a73aca587cc164d701e9b9c279cfe1a`。

（以上兩串雜湊供實作者自檢：若你的重建結果雜湊相同，編碼就對了。）

## 3. 時間欄的換算規則

- API 以 RFC 3339 字串回傳，時區為 UTC（`Z` 結尾），精度至微秒。
- canonical 值＝**Unix epoch 起算的微秒整數**，即
  `unix_seconds * 1_000_000 + microseconds`，向下取整（floor）至微秒。
- 為何是微秒而非奈秒：PostgreSQL `timestamptz` 只保存微秒精度，
  取奈秒會在 round-trip 後產生不一致，使驗章隨機失敗。
- 實作提醒：不要用浮點數做這個換算（`float64` 無法精確表示 1.7e15 級的微秒值）。
  以整數運算或十進位字串處理。
- **小數位數不固定，必須右補零至 6 位**：API 的時間字串由 Go 的 RFC3339Nano 產生，
  它會**裁掉小數尾端的零**，故實際小數位數是 1–6 位而非固定 6 位。
  例：`…30.09768Z` 的微秒數是 **96780** 而非 9768——先把小數部分右補零補滿 6 位再取整數。
  照字面把小數當作固定 6 位（或直接取到的位數當微秒）會使約一成的檢查點驗章失敗。
  本節上方兩串自檢範例的小數皆恰為 6 位，抓不到這個案例，勿以其通過即認定實作正確。

## 4. 簽章演算法

- **Ed25519（RFC 8032 純 EdDSA）**，直接對第 2 節的 payload 位元組簽名——
  **不預先雜湊**（非 Ed25519ph）、無任何前綴或 context 字串。
- `signature` 欄＝64 bytes 簽章的 base64（標準字母表、含 padding）。
- 驗證即 `Ed25519.Verify(public_key, payload_bytes, signature)`。

## 5. 鏈接雜湊（`prev_checkpoint_hash` 的重算）

第 N+1 個檢查點的 `prev_checkpoint_hash` ＝ 對第 N 個檢查點計算：

```
sha256( '{"signed":' || <第 N 點的 payload 位元組，原樣內嵌> || ',"signature":"' || <第 N 點的 signature base64> || '"}' )
```

輸出為小寫 hex。要點：

- `signed` 的值是**原樣內嵌的 JSON 物件**，不是被字串化後的 JSON 字串——
  巢狀字串化會引入跳脫規則，外部驗證者難以逐位元組重建，故刻意避開。
- 鏈接輸入包含 signature：換簽章會改變鏈接雜湊，但**只鏈欄位不鏈簽章**的做法
  會讓重簽不斷鏈，故此處刻意納入。
- 鏈頭之外的每一點都應通過此重算；不符即為 `chain_broken`。

genesis（鏈頭）的 `prev_checkpoint_hash` 另有其編碼：
`sha256('{"kind":"integrity_baseline","max_log_id":<N>,"baseline_at_us":<M>}')`。
外部驗證者若未取得 `integrity_baselines` 記錄則無法重算——這是誠實邊界，
本文件不宣稱它是純 API 可驗的。

## 6. 聚合雜湊 `agg_hash` 的編碼（**外部驗章不需要**，需資料庫存取時才用）

**兩種 canonical 形態刻意不同形**：簽章 payload 是上述 JSON；聚合雜湊則是
**定長二進位、HMAC 帶長度前綴**。若你只是要驗檢查點沒被動過，本節可略過；
本節是給有資料庫唯讀權限、要重算「區間內容是否與封章時一致」的驗證者。

輸入為 `audit_logs` 中 `id >= id_from AND id <= id_to` 的所有列，**依 `id` 升冪**，
每列取三欄寫入一個 SHA-256 串流：

| 位移 | 長度 | 內容 |
|---|---|---|
| 0 | 8 bytes | `id`，big-endian uint64 |
| 8 | 4 bytes | `key_version`，big-endian int32（負值以二補數表示） |
| 12 | 2 bytes | `len(integrity_hmac)`，big-endian uint16 |
| 14 | 該長度 | `integrity_hmac` 的**原始位元組**（欄位是文字，**不做 hex 解碼**；可能為空字串，此時長度為 0） |

`agg_hash` ＝該串流 SHA-256 的小寫 hex；空區間即空輸入的 SHA-256
（`e3b0c442…b855`），與「有列但雜湊碰巧相同」不會混淆，因為 `row_count` 另存於簽章內。

**為何是長度前綴而非分隔符**：本機制的威脅模型明載對手可直寫資料庫。
分隔符編碼下，攻擊者只要把分隔位元組寫進 `integrity_hmac` 欄，就能讓「一列」與
「兩列」產生相同串流，使抽列不被偵測；長度前綴使編碼對任意欄位內容皆為單射。

## 7. 獨立驗證工具

程式碼：`tools/checkpoint-verify/`（Go，**僅用標準庫，不 import 任何產品程式碼、
不依賴任何第三方套件**）。稽核方複製該目錄即可建置，無需取得產品原始碼其餘部分。

```bash
# 線上：直接向 API 取公鑰與整條鏈（自動分頁）
# -url 填您的部署位址；正式部署經前端反向代理對外，而非後端的 8080 埠
go run . -url https://<您的部署位址> -token "$TOKEN"

# 離線：手上只有匯出的 JSON 與帶外取得的公鑰
go run . -input checkpoints.json -pubkey 2i0fl9yPbPABeYN1gxlPCmldrxcq5jrD5lMqXuzyYUE=

# 印出重建的 payload 位元組（供他語言實作逐位元組比對）
go run . -input checkpoints.json -pubkey <KEY> -only-seq 21 -show-payload

# 反向對照：證明驗證器真的會拒絕（三種竄改，皆應 FAIL）
go run . -input checkpoints.json -pubkey <KEY> -tamper payload-bit
go run . -input checkpoints.json -pubkey <KEY> -tamper row-count
go run . -input checkpoints.json -pubkey <KEY> -tamper signature-bit
```

離開碼：`0`＝全數通過、`1`＝有檢查點未通過、`2`＝輸入或環境錯誤。
工具逐點輸出簽章、鏈接雜湊與區間鄰接三項結果，並在結尾重述誠實邊界。

**不要只看工具的結論**：工具本身也只是一份實作。真正的獨立驗證是你依第 2–5 節
自行實作一次，並與第 2 節的兩串 `sha256(payload)` 比對——比對相同即代表你的實作與
產品端對齊，此後你的實作就是你自己的判準。

## 8. 不用 Go 也能驗：任何語言 ＋ OpenSSL

payload 依第 2 節組出後，可用 OpenSSL 驗 Ed25519 簽章（OpenSSL 3.x）。
先把 base64 公鑰包成 PEM（SubjectPublicKeyInfo ＝固定 DER 前綴 `302a300506032b6570032100` ＋ 32 bytes 公鑰）：

```python
import base64
pub = base64.b64decode("2i0fl9yPbPABeYN1gxlPCmldrxcq5jrD5lMqXuzyYUE=")
der = bytes.fromhex("302a300506032b6570032100") + pub
open("pub.pem", "w").write("-----BEGIN PUBLIC KEY-----\n"
    + base64.encodebytes(der).decode().strip() + "\n-----END PUBLIC KEY-----\n")
```

把 payload 位元組寫入 `payload.bin`、`base64 -d` 後的簽章寫入 `sig.bin`，然後：

```bash
openssl pkeyutl -verify -pubin -inkey pub.pem -rawin -in payload.bin -sigfile sig.bin
# Signature Verified Successfully   → 離開碼 0
```

`-rawin` 是必要的：它表示對輸入原始位元組做純 EdDSA，而非先雜湊。

## 9. 規格的實測驗證

本文件的每一條規格都經實測，非紙上規格：

- 以 `tools/checkpoint-verify`（不 import 產品程式碼、自行依本文件重建位元組）
  對一組 27 個真實檢查點驗證：**簽章 PASS=27 FAIL=0；鏈接 PASS=26 FAIL=0**
  （鏈頭無前點故 26）。區間鄰接全數 PASS。
- 反向對照三種竄改（payload 翻一位元、`row_count` +1、簽章翻一位元），
  皆使該點簽章 FAIL、且其後一點鏈接 FAIL（竄改沿鏈傳播），工具離開碼 1。
- **跨語言／跨工具鏈交叉驗證**：另以純 Python（僅標準庫）依本文件第 2–3 節重建
  `seq = 21` 與 `seq = 26` 的位元組，雜湊與第 2 節所載相同；簽章驗證改用
  `openssl pkeyutl -verify -rawin` 完成，回報 `Signature Verified Successfully`；
  將 `row_count` 改為 7 後 OpenSSL 回報 `Signature Verification Failure`。
  此路徑全程不涉及 Go 與產品程式碼，故「外部可獨立重建位元組」不是宣稱而是已實現。

## 10. 相容性紀律

canonical 編碼**一經釘定不再變更**。任何編碼演進一律以新的 `agg_scheme` 值表示，
舊檢查點續以其原 scheme 重算驗證（`cp-agg-v1` 的位元組與本文件初版完全相同，
角色指派納入鏈並未改動任何既有檢查點）。產品端有 golden 測試逐位元組釘住兩種編碼，
本文件與該測試同源；若兩者出現分歧，以本文件所載的實測位元組為準並視為缺陷回報。


### 主體與憑證投影的營運語義

三個快照鍵各自選取基準並重播事件。既有 `role_state` 回應維持原形；新增
`principal_state`、`agent_token_state` 回應及驗證頁兩列，各自顯示涵蓋、差集識別值與事件連結。
升級後首個包含新鍵的封章之前，新兩列為「尚未涵蓋」，不代表相符；來源或推演錯誤為未知。
對帳發生在驗證、封章、核發憑證前，因此偵測非即時。發證前對帳不符仍可發證，
讀取失敗留日誌，不更改業務資料，也不把未知視為相符。兩項不符各自建立
`principal_state_integrity`／`principal_state_mismatch` 事件與通知，差集只含識別值。
服務層投影狀態列 actor 記 `system`，操作者由既有 HTTP 稽核列承擔。
主體與憑證投影當時沿用 v2，未升版；工具呼叫帳本加入後新封章升至 v3。回退為單向相容：新版可驗舊章，
舊版無法解讀新增快照鍵，不可視為完整驗證；不得刪鍵重簽或還原單機制唯一索引
來配合舊版，回退須取升級前的一致備份並按備份／還原程序操作。


## 第三版載荷與工具呼叫帳本

`cp-agg-v3` 使用 v2 的固定 JSON 欄序，最後追加四個帳本欄位，順序固定為：

```text
tool_call_id_from, tool_call_id_to, tool_call_row_count, tool_call_agg_hash
```

完整鍵序為 `seq, id_from, id_to, row_count, agg_hash, agg_scheme, prev_checkpoint_hash,
min_created_at_us, state, role_state_reconciled, max_created_at_us, sealed_at_us,
signing_key_version, tool_call_id_from, tool_call_id_to, tool_call_row_count, tool_call_agg_hash`。
前段編碼、state 重建、微秒時戳與 JSON null 規則與 v2 相同；不加空白、不換行。
四個新增欄位在 v3 必須全部存在，前三個為整數，hash 為小寫 hex 字串；不得以 null
替代。v1／v2 不帶這四個欄位，仍按原位元組驗章；舊版本值帶帳本欄位視為載荷降版異常。

帳本的閉區間獨立於 audit_logs。按 id 升冪，只取第一階段送出時固定欄位。
每列先生成下列固定鍵序的 UTF-8 JSON（不加空白或換行）：

```text
id, seq, user_id, agent_token_id, access_request_id, session_id, on_behalf_of_user_id, owner_user_id, tool, args_sha256, created_at_us, key_version
```

識別值與 seq 為十進位整數；三個可空識別值以 JSON null 表示，不能省略；
`created_at_us` 是 UTC Unix 微秒整數；`key_version` 是 pending 入庫時鑰版本，結果完成也不得改。
`args_sha256` 為遮罩參數 canonical JSON 的 SHA-256 小寫 hex：物件鍵遞迴排序、
無空白、JSON number 不轉 float64：去除正負零及無效前後零，將十進位小數與指數統一為
`[-]有效整數e指數`（整數尾零移入指數，指數 0 則省略 e0）；例如 1.00→1、1000→1e3、
0.001200→12e-4。如此 PostgreSQL JSONB 展開指數後仍得相同雜湊。字串按 Go encoding/json
規則跳脫（含 `<`、`>`、`&`、U+2028、U+2029）。`tool` 亦按同一 JSON 字串規則。
每列 JSON 前置 **8-byte big-endian uint64 的 UTF-8 位元組長度**，再接 JSON 原始位元組。
對全部列的這些長度前綴與位元組串流做 SHA-256 小寫 hex，另記實際列數。
HMAC 與第二階段結果欄均不放進此聚合。

空區間為 id_from=id_to+1、列數 0，hash 為
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`。
以下單列 JSON（args 為 `{}`）連同其 8-byte 長度前綴的聚合為
`29848bb05fef66c3c7d4a03c1c1131db14e5c2b9c4f17a0f00045d0ae49035f8`：

```json
{"id":1,"seq":1,"user_id":1,"agent_token_id":2,"access_request_id":null,"session_id":null,"on_behalf_of_user_id":null,"owner_user_id":3,"tool":"list_assets","args_sha256":"44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a","created_at_us":0,"key_version":1}
```

第二列僅將 id、seq 改為 9，tool 改為 `check_request`；兩列串接聚合為
`acab7e6635e971ba8887b60caf22c944e025499e43b18b8f4641deb41914446c`。

鏈接雜湊仍為 `{"signed":<該版本載荷物件>,"signature":<簽章字串>}` 的 SHA-256。
新封章一律 v3，第一個 v3 帳本區間從 1 起，之後從前章的 tool_call_id_to+1 起。
全新 genesis 的帳本為 [1,0] 空區間，下一章納入全部既有帳本列。
封章不排除 pending，亦不等待呼叫結果；PostgreSQL 封章讀取上界前等待在途 INSERT 交易，
避免已取號未提交的列落於已封區間之後。任何帳本讀取錯誤均不產生新章。

驗證器分三步：(1) 簽章、帳本 id 區間鄰接及區間內列數；(2) 第一階段聚合與簽章內 hash 比對；
(3) 區間內逐列 HMAC。操作日誌與帳本分別回報，日誌通過不能代替帳本通過。
第一階段（包含主體／token／任務／會話／代表人／負責人快照）由 ORM 守衛拒絕更新。
已封 pending 列結果完成合法，不重簽既有章；以原鑰版本重算涵蓋 id、兩階段全部欄位的列級 HMAC。
入庫前先算 HMAC，取得自增 id 後在同一交易內完成含 id 的 HMAC，外部不會讀到中間態。
列級 HMAC 的 JSON 域為 `agent_tool_call_v1`，參數採同樣 canonical 規則；驗證需要該版本對稱鑰，
僅有 Ed25519 公鑰者只能驗檢查點簽章與第一階段聚合，不能宣稱結果 HMAC 已通過。

**誠實邊界：檢查點鏈證明帳本列的存在與送出內容；結果欄由列級 HMAC 證明，不進鏈的聚合。**
結果欄遭 DB 直改或 HMAC 被改報 `row_hmac_mismatch`；送出內容被改報 `hash_mismatch`；
刪列報 `count_mismatch`。持有 HMAC 鑰者能偽造或重播另一份有效結果而不破壞鏈，
鏈不證明結果的不可回退性或最終性。未封尾段不受鏈保護。摘要與節錄取自遮罩後回傳，
不代表主機輸出全文或主機實際效果。

`TestCheckpointOfflineRebuildV3` 依上列 literal JSON、長度前綴、完整載荷鍵序與 state 規則，
獨立重建聚合與載荷位元組，不使用生產 payload struct 或 stateHash，逐位元組比對。
現有 `tools/checkpoint-verify` CLI 僅接受 v1／v2；v3 依本節重建後使用 Ed25519 公鑰驗章，
不得將舊 CLI 的未知版本拒驗解讀為竄改，也不得去除帳本欄後驗證。
