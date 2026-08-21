# asset-connection-test Specification

## Purpose
資產撥測（test-connection）的分派、驗證深度、時限與失敗分類語義。與 asset-management 的分工：本 capability 界定「撥測本身怎麼做、成功代表什麼」，asset-management 界定「結果如何持久化與呈現」。

## Requirements
### Requirement: 撥測分派以顯式對照表決定，未登記協議一律拒絕

資產撥測 SHALL 依「協議 → 撥測方式」的顯式對照表分派，SHALL NOT 以否定式分支（判斷少數協議、其餘落入單一 fallback 中介）決定撥測路徑。對照表未登記的協議 SHALL 立即以失敗結果返回，攜帶「協議不支援撥測」的機器碼與粗分類 `protocol_unsupported`，SHALL NOT 轉送任何協議代理或中介。

可建立資產的協議清單與撥測對照表 SHALL 共用單一事實源，且 SHALL 維持雙向完備：清單中的每個協議 SHALL 在對照表有登記；對照表中的每個鍵 SHALL 存在於清單。此不變式 SHALL 由常駐的守衛測試釘住，任一方向缺漏 SHALL 使測試失敗。

#### Scenario: 新增協議未登記撥測方式即轉紅

- **WHEN** 開發者將新協議加入可建立資產的協議清單，但未在撥測對照表登記撥測方式
- **THEN** 完備性守衛測試失敗，明示缺漏的協議名稱

#### Scenario: 對照表殘留不可建立的協議即轉紅

- **WHEN** 撥測對照表含有不在協議清單中的鍵（如拼寫錯誤或已移除的協議）
- **THEN** 完備性守衛測試失敗，明示多餘的鍵

#### Scenario: 未登記協議不進入中介

- **WHEN** 撥測收到對照表未登記的協議
- **THEN** 立即回傳失敗結果（`success=false`、粗分類 `protocol_unsupported`），且不建立任何往協議代理或中介的連線

### Requirement: 各協議撥測的驗證深度明確且可查

撥測 SHALL 對每種協議採用該協議適用的驗證方式，且驗證深度 SHALL 明確定義如下，SHALL NOT 讓「撥測成功」被解讀為超出該深度的保證：

- `ssh`：直連目標並完成 host key 驗證與密碼認證，成功代表可登入。
- `rdp`、`vnc`：經 guacd 完成協議連線握手，成功代表 guacd 能建立到目標的協議連線。
- `mysql`、`postgres`、`redis`、`mssql`：TCP 可達性探測，成功**僅**代表目標 host:port 的 TCP 連線可建立；SHALL NOT 進行任何協議握手或認證，SHALL NOT 在目標端產生認證嘗試記錄。
- `k8s`：對目標 API server 送出 exec 權限預檢，成功代表 API server 可達、TLS 驗證通過、且該資產憑證具備目標 namespace 的 pods/exec 權限。**成功 SHALL NOT 被解讀為目標 namespace 確實存在**——SelfSubjectAccessReview 不檢查資源存在性，本系統亦不主動偵測 namespace 是否存在。

撥測 SHALL NOT 因協議不同而改變回應結構：所有協議皆回傳同一組欄位（成功旗標、延遲、協議、測試時間、失敗機器碼與粗分類）。

協議白名單與撥測對照表 SHALL 保持雙向完備：清單有而對照表未登記、或對照表有而清單缺漏，皆 SHALL 使守衛測試轉紅——新增協議時遺漏其一會使該協議的撥測靜默落空。

#### Scenario: 資料庫資產僅驗埠可達

- **WHEN** 管理者對 postgres 資產執行撥測且目標 5432 埠可建立 TCP 連線
- **THEN** 撥測成功並回報延遲；目標資料庫未收到任何認證嘗試

#### Scenario: 資料庫埠不可達

- **WHEN** 管理者對指向已關閉埠的 mysql 資產執行撥測
- **THEN** 撥測失敗，粗分類為連線被拒或逾時，非「協議不支援」

#### Scenario: k8s 撥測驗 exec 權限

- **WHEN** 管理者對 k8s 資產執行撥測，其憑證可達 API server 但無目標 namespace 的 pods/exec 權限
- **THEN** 撥測失敗，粗分類為 `exec_forbidden`（與「無法連線」明確區分）

#### Scenario: k8s 憑證有效即成功

- **WHEN** 管理者對 k8s 資產執行撥測，其憑證可達 API server、TLS 通過且具 pods/exec 權限
- **THEN** 撥測成功並回報延遲

#### Scenario: mssql 撥測僅驗埠可達

- **WHEN** 管理者對 mssql 資產執行撥測且目標 1433 埠可建立 TCP 連線
- **THEN** 撥測成功並回報延遲；目標資料庫未收到任何登入嘗試記錄

### Requirement: 撥測在有界時間內返回

撥測 SHALL 在有界時間內返回結果。請求可指定的逾時 SHALL 夾制於 1 至 30 秒（未指定或非法值時採預設 10 秒），且所指定的時限 SHALL 涵蓋撥測全程（ssh 的認證階段、資料庫的 TCP 撥號、k8s 的 API 呼叫），SHALL NOT 僅涵蓋傳輸層撥號而讓後續階段無限等待。

前端發起撥測時 SHALL 使用大於後端逾時上界的請求等待時間，SHALL NOT 因用戶端先行逾時而使已完成的撥測結果無法呈現。

#### Scenario: 逾時參數被夾制

- **WHEN** 呼叫端以 `timeout` 為 600 送出撥測請求
- **THEN** 實際逾時取上界 30 秒，撥測不會長佔逾此時限

#### Scenario: 不可達目標於時限內返回

- **WHEN** 管理者對指向黑洞位址的資料庫資產執行撥測（預設逾時）
- **THEN** 撥測於逾時時限內回傳失敗結果，不無限等待

#### Scenario: 用戶端不先於後端逾時

- **WHEN** 撥測在後端耗時接近逾時上界後回傳結果
- **THEN** 前端仍收到並呈現該結果，不因請求等待時間不足而顯示為傳輸失敗

### Requirement: 撥測失敗以機器碼分類，原始訊息不外洩

撥測失敗 SHALL 以機器碼（`code`）與粗分類（`error_code`）表達原因，由前端查譯呈現；協議代理或用戶端函式庫的原始錯誤訊息 SHALL 僅落伺服端日誌，SHALL NOT 出現於 API 回應。

失敗分類 SHALL 至少涵蓋：協議不支援撥測、連線被拒、逾時、認證失敗、exec 權限不足、namespace 不存在、TLS 驗證失敗、未分類失敗。可跨協議共用的分類 SHALL 使用協議中性的文案，SHALL NOT 在文案中寫死單一協議名稱。

#### Scenario: k8s TLS 失敗有專屬分類

- **WHEN** k8s 資產的 CA 憑證設定錯誤導致 TLS 驗證失敗
- **THEN** 撥測失敗且粗分類為 `tls_failed`，回應不含原始 x509 錯誤字串

#### Scenario: namespace 不存在不被偵測（誠實邊界）

- **WHEN** 管理者對 k8s 資產執行撥測，其憑證具 cluster-wide 的 pods/exec 權限但目標 namespace 不存在
- **THEN** 撥測**成功**——權限預檢不驗資源存在性，此結果不代表 namespace 存在（`namespace_not_found` 分類僅在 API 確實回報 404 時產生，撥測路徑上不會主動觸發）

#### Scenario: 共用分類文案協議中性

- **WHEN** 資料庫資產因網路不可達而撥測失敗，取用與 ssh 共用的「連線失敗」分類
- **THEN** 使用者看到的文案不指名 ssh，適用於任何協議

### Requirement: 撥測結果落庫不受協議影響

撥測 SHALL 在結果產生後持久化最近一次狀態，包含以「協議不支援撥測」失敗的情形；持久化 SHALL NOT 因撥測未在有界時間內返回而被跳過。

#### Scenario: 資料庫資產撥測後有可達性記錄

- **WHEN** 管理者對 postgres 資產執行撥測
- **THEN** 該資產的最近測試狀態、延遲與時間被寫入，列表可見可達性徽章（不再恆為「從未測試」）

#### Scenario: 不支援協議亦落庫

- **WHEN** 撥測因協議未登記而失敗
- **THEN** 該資產記錄為不可達，並保留該次測試時間
