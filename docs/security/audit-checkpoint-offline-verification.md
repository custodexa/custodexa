# 審計檢查點鏈：離線驗章規格與外部驗證指南

> 對象：稽核單位、QSA、客戶方安全團隊——**不需要信任本系統、也不需要取得產品原始碼**的第三方。
> 版本：canonical 編碼 v1（`agg_scheme = cp-agg-v1`，簽章 payload 形態一經釘定不再變更）。
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

- **不能**判定審計日誌「內容」正確：簽章覆蓋的是檢查點欄位，不是 `audit_logs` 的列內容。
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

| # | 鍵 | 型別 | 來源欄位 | 說明 |
|---|---|---|---|---|
| 1 | `seq` | 非負整數 | `seq` | 檢查點序號，自 1 起連續 |
| 2 | `id_from` | 非負整數 | `id_from` | 區間起始 `audit_logs.id`（含） |
| 3 | `id_to` | 非負整數 | `id_to` | 區間結束 `audit_logs.id`（含）；空區間時 `id_to = id_from - 1` |
| 4 | `row_count` | 整數 | `row_count` | 區間內列數 |
| 5 | `agg_hash` | 字串 | `agg_hash` | 聚合雜湊，64 字元小寫 hex（空區間為空輸入的 SHA-256：`e3b0c442…b855`） |
| 6 | `agg_scheme` | 字串 | `agg_scheme` | 聚合編碼版本標識，現值 `cp-agg-v1` |
| 7 | `prev_checkpoint_hash` | 字串 | `prev_checkpoint_hash` | 前一檢查點的鏈接雜湊，64 字元小寫 hex |
| 8 | `min_created_at_us` | 整數或 `null` | `min_created_at` | 區間內最早 `created_at`；空區間為 `null` |
| 9 | `max_created_at_us` | 整數或 `null` | `max_created_at` | 區間內最晚 `created_at`；空區間為 `null` |
| 10 | `sealed_at_us` | 整數 | `sealed_at` | 封章時間，**不可為 null** |
| 11 | `signing_key_version` | 整數 | `signing_key_version` | 簽章鑰版本 |

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
舊檢查點續以其原 scheme 重算驗證。產品端有 golden 測試逐位元組釘住兩種編碼，
本文件與該測試同源；若兩者出現分歧，以本文件所載的實測位元組為準並視為缺陷回報。
