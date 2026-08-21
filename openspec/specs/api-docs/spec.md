# api-docs

## Purpose

後端 HTTP API 的文件事實源與其完備性保證。`docs/API_SPEC.md` 為唯一入口，其端點索引由測試自實際路由註冊生成並受守衛保護。

## Requirements

### Requirement: API 文件單一事實源
`docs/API_SPEC.md` SHALL 為後端 HTTP API 的唯一文件事實源。專案 SHALL NOT 同時維護第二份由註解生成的 API 文件產物。原始碼 SHALL NOT 含 swag／OpenAPI 註解，`go.mod` SHALL NOT 依賴 swag 相關套件，建置環境 SHALL NOT 安裝其 CLI——殘留的註解與工具鏈會誘使他人重新啟用雙份維護。

#### Scenario: 查詢端點語義
- **WHEN** 開發者需要查詢某端點的請求／回應格式與語義
- **THEN** `docs/API_SPEC.md` 為唯一入口，不存在第二份需要交叉比對的 API 文件

#### Scenario: swag 工具鏈已移除
- **WHEN** 檢視原始碼、`go.mod` 與建置環境
- **THEN** 不存在 `@Router`／`@Summary` 等 swag 註解、不存在 swaggo 相依、`Dockerfile` 不安裝 `swag` CLI

### Requirement: 端點索引為機器生成
`docs/API_SPEC.md` SHALL 含一個由 marker 界定的端點索引區塊（`<!-- BEGIN API-INDEX -->` 至 `<!-- END API-INDEX -->`），欄位為 `方法 | 路徑 | 註冊條件`，SHALL 由測試自實際路由註冊生成而非人工抄寫。路徑 SHALL 採 gin 形式（`/api/v1/assets/:id`），排序 SHALL 固定，使重新生成的輸出為確定性結果、diff 只反映真實路由變動。

`註冊條件` SHALL 為枚舉值，標示該路由於何種組態下註冊（無條件者為 `always`，條件註冊者為其環境變數名）。

生成 SHALL 有單一文件化指令，且 SHALL 以可寫掛載的一次性容器執行；平時執行測試的容器 SHALL 以唯讀掛載取得 `docs/`，使驗證者無法竄改被驗證對象。

該唯讀掛載點 SHALL 位於 Go module 內——`go test` 的結果快取只追蹤 module 內被開啟的檔案，掛於 module 外時對文件的修改不會使快取失效，守衛將回報 `(cached)` 通過而根本不執行。

#### Scenario: 重新生成索引
- **WHEN** 執行文件化的生成指令
- **THEN** marker 區塊被重寫為當前路由註冊的確定性結果，其餘文件內容不受影響

#### Scenario: 驗證容器無法竄改文件
- **WHEN** 一般測試容器嘗試寫入 `docs/API_SPEC.md`
- **THEN** 因唯讀掛載而失敗——守衛不得具備修改其驗證對象的能力

#### Scenario: 手改文件必使守衛重新執行
- **WHEN** 有人只修改 `docs/API_SPEC.md` 而未變更任何 Go 原始碼，隨後執行測試
- **THEN** 測試快取失效並實際重跑守衛，而非回報 `(cached)` 通過

### Requirement: 端點索引完備性守衛
專案 SHALL 具備永久測試，比對端點索引與實際路由註冊的**雙向相等**：索引缺少任一實際路由 SHALL 失敗，索引含有不存在的路由亦 SHALL 失敗。路由宇宙 SHALL 取自 `registerRoutes` 於各可達部署組態下註冊結果的聯集，使條件註冊的端點一併納入。`註冊條件` 欄的值 SHALL 與該路由實際的條件一致。

路由宇宙 SHALL 保留每條路由在各組態下的完整 membership，SHALL NOT 壓縮為單一維度的布林——壓縮會使受多個旗標共同控制的端點被誤判為無條件註冊。註冊條件的推導 SHALL 為封閉值域：無法歸入已知 pattern 的 membership SHALL 失敗，迫使新增條件註冊機制者同步檢視文件與枚舉。

控制路由註冊的旗標集合 SHALL 與組態矩陣的維度一致，並 SHALL 由結構檢查保護——新增旗標而未擴充矩陣時，受該旗標控制的路由在所有組態下皆不存在，值域檢查無從觸發，唯有結構檢查可攔截。

gin mode SHALL NOT 影響路由集合。此不變式 SHALL 於每一組態下以完整鍵集雙向比對驗證，SHALL NOT 僅比較路由數量或僅驗單一組態。

守衛的 marker 解析 SHALL 強制下列結構不變式，各配 fixture 測試：恰好一組 BEGIN／END 且 BEGIN 先於 END；區塊內每一非表頭列都 SHALL 成功解析（SHALL NOT 靜默略過無法解析的列）；SHALL NOT 存在第二個 marker 區塊。解析結果為 0 列 SHALL 視為失敗——否則表頭微調會使比對退化為空集合對空集合而靜默通過。

文件檔案缺失時守衛 SHALL 失敗，SHALL NOT skip。

#### Scenario: 新增路由未更新索引
- **WHEN** 有人新增一條路由但未重新生成索引
- **THEN** 守衛失敗並指出缺少的端點

#### Scenario: 索引含幽靈條目
- **WHEN** 索引中存在已被刪除的端點
- **THEN** 守衛失敗並指出多餘的條目

#### Scenario: 條件註冊端點納入宇宙
- **WHEN** 某端點僅於 `FEATURE_AUDIT_LOG_ENABLED=true` 時註冊
- **THEN** 該端點出現於索引且註冊條件欄標示該旗標，而非因預設組態未涵蓋而遺漏

#### Scenario: 新增註冊旗標未擴充矩陣
- **WHEN** 有人為路由依賴集合新增一個控制註冊的旗標，卻未將其納入組態矩陣
- **THEN** 結構檢查失敗——否則該旗標在測試中恆為關閉，受其控制的路由不會進入路由宇宙而從索引消失

#### Scenario: 解析退化不得靜默通過
- **WHEN** marker 區塊的表頭被改動致使解析不出任何資料列
- **THEN** 守衛失敗，而非以空集合比對空集合的方式通過
