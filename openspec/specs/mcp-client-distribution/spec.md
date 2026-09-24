# mcp-client-distribution Specification

## Purpose
定義 stdio 轉接頭 `custodexa-mcp` 的發行面：它在哪裡維護、使用者如何取得與辨識版本、它對上游與宿主的轉送行為，以及它的公開 repo 必須具備的內容。轉接頭只把 stdio 上的 MCP 呼叫原樣轉送到 Custodexa 服務端的 MCP 端點，本身不含任何授權、連線或審計邏輯。

## Requirements

### Requirement: 獨立公開 repo 為唯一原始碼所在

`custodexa-mcp` 的原始碼 SHALL 只存在於獨立的公開 repo `custodexa/custodexa-mcp`，以 Go module `github.com/custodexa/custodexa-mcp` 發行。Custodexa 主 repo SHALL NOT 含轉接頭的原始碼、建置步驟或對其 module 的依賴；服務端容器映像 SHALL NOT 附帶轉接頭二進位。

該 repo SHALL 以 `go install github.com/custodexa/custodexa-mcp@<版本>` 安裝出名為 `custodexa-mcp` 的可執行檔。

#### Scenario: 以 go install 取得

- **WHEN** 使用者執行 `go install github.com/custodexa/custodexa-mcp@v1.0.0`
- **THEN** 取得名為 `custodexa-mcp` 的可執行檔，無需 Custodexa 主 repo 的任何原始碼

#### Scenario: 服務端映像不含轉接頭

- **WHEN** 檢視服務端正式版容器映像的檔案系統
- **THEN** 其中不存在 `custodexa-mcp` 可執行檔

#### Scenario: 主 repo 不含轉接頭原始碼

- **WHEN** 在 Custodexa 主 repo 搜尋轉接頭的 main 套件或其 module 路徑
- **THEN** 查無原始碼與 module 依賴；僅對外文件以安裝點形式提及

### Requirement: 轉接頭的轉送契約

轉接頭 SHALL 從環境變數讀取設定：`CUSTODEXA_MCP_URL`（上游端點；未設或空白時為本機開發預設端點）與 `CUSTODEXA_AGENT_TOKEN`（必填）。token SHALL NOT 可經命令列參數提供。

轉接頭 SHALL 拒絕下列上游端點並以非零狀態結束、不發出任何請求：非 http／https scheme、缺少主機、含 userinfo、含 query、含 fragment。token 未提供時 SHALL 同樣結束且不發出任何請求。

對上游的每個請求 SHALL 帶 `Authorization: Bearer <token>`。上游回應轉址時轉接頭 SHALL NOT 跟隨，SHALL 以錯誤回報；token SHALL NOT 被送往轉址目標。

轉接頭 SHALL 以上游 `tools/list` 的結果作為自身對宿主提供的工具面，工具名稱、說明、輸入結構與輸出結構 SHALL 與上游逐欄相同，SHALL NOT 增刪、改名或改寫任何工具。工具呼叫 SHALL 原樣轉送參數，並原樣回傳上游結果（含內容、結構化內容與錯誤旗標）。宿主取消一次工具呼叫時，對應的上游呼叫 SHALL 被取消。

#### Scenario: 缺 token 不發請求

- **WHEN** 以未設 `CUSTODEXA_AGENT_TOKEN` 的環境啟動轉接頭
- **THEN** 轉接頭以非零狀態結束並指出缺少 token，上游未收到任何請求

#### Scenario: 端點含憑證被拒

- **WHEN** `CUSTODEXA_MCP_URL` 為含 userinfo 的 URL
- **THEN** 轉接頭以非零狀態結束，上游未收到任何請求

#### Scenario: 上游轉址不跟隨

- **WHEN** 上游對轉接頭的請求回應 3xx 轉址
- **THEN** 轉接頭回報錯誤，轉址目標未收到任何帶 token 的請求

#### Scenario: 工具面逐欄相同

- **WHEN** 宿主經轉接頭列出工具，另一客戶端以同一 token 直連上游列出工具
- **THEN** 兩份工具清單序列化後逐欄相同，涵蓋必填欄位、列舉值、整數、物件陣列、巢狀物件與禁止額外欄位等結構構造

#### Scenario: 錯誤結果原樣回傳

- **WHEN** 上游對某工具呼叫回傳錯誤旗標為真的結果
- **THEN** 宿主經轉接頭收到的結果與直連收到的結果序列化後逐欄相同

### Requirement: 獨立版號與自我識別

轉接頭 SHALL 採獨立於 Custodexa 主產品的語意化版號，首版為 `v1.0.0`。

轉接頭於 MCP `initialize` 回報的 `serverInfo.name` SHALL 為 `custodexa-mcp`，`serverInfo.version` SHALL 為轉接頭自身的建置版號：以發行流程建置者為該版號，以 `go install` 指定版本安裝者為該 module 版本，其他建置為 Go 工具鏈記錄的版本（可能是偽版本），全無時為 `devel`；版號字串 SHALL NOT 帶前綴 `v`，同一版本不論取得途徑皆回報相同字串。轉接頭版號 SHALL NOT 被表述為上游 Custodexa 的版本。

#### Scenario: Release 二進位回報自身版號

- **WHEN** 宿主與 `v1.0.0` Release 二進位完成 `initialize`
- **THEN** `serverInfo` 為 `{"name":"custodexa-mcp","version":"1.0.0"}`

#### Scenario: go install 與 Release 回報相同

- **WHEN** 宿主與以 `go install …@v1.0.0` 安裝的轉接頭完成 `initialize`
- **THEN** `serverInfo.version` 為 `1.0.0`，與 Release 二進位相同

#### Scenario: 自原始碼建置未帶版號

- **WHEN** 宿主與未經發行流程、非以指定版本安裝、且 Go 工具鏈未記錄任何版本的建置完成 `initialize`
- **THEN** `serverInfo.version` 為 `devel`

### Requirement: 發行產物

每個版本 SHALL 以 tag 觸發發行，產出 linux、darwin、windows 三個作業系統各 amd64、arm64 兩種架構的二進位封存檔，與一份涵蓋全部封存檔的 SHA-256 校驗檔。每個封存檔 SHALL 內含授權全文、第三方授權彙整與說明文件。

封存檔命名 SHALL 固定為 `custodexa-mcp_<版本>_<作業系統>_<架構>` 加副檔名，跨版本不變。

#### Scenario: 校驗檔涵蓋全部產物

- **WHEN** 某版本發行完成
- **THEN** 校驗檔列出六個封存檔各自的 SHA-256，且逐一可驗證

#### Scenario: 封存檔附授權文件

- **WHEN** 解開任一平台封存檔
- **THEN** 其中含授權全文與第三方授權彙整

### Requirement: 公開 repo 的必備內容

該 repo SHALL 以 AGPL-3.0 授權，並 SHALL 具備：授權全文、NOTICE、說明文件、貢獻指南（採 DCO）、DCO 全文、安全問題回報政策、變更紀錄、第三方授權彙整（逐一列出隨二進位散布的依賴及其授權）。

說明文件 SHALL 在開頭寫明轉接頭的定位：MCP 服務端即 Custodexa 本體的端點，本工具只為只支援 stdio 的宿主轉接；支援 streamable HTTP 的宿主可直連服務端而無需本工具。說明文件 SHALL 列出安裝途徑、兩個環境變數、宿主設定範例，並 SHALL 指示 token 只經環境變數提供。

repo 的持續整合 SHALL 對每次推送執行靜態檢查、單元測試與已知漏洞檢查；單元測試 SHALL 不需要 Custodexa 原始碼或執行中的服務即可全綠。

#### Scenario: clone 後直接測試

- **WHEN** 在無 Custodexa 服務、無主 repo 原始碼的環境 clone 該 repo 並執行其單元測試
- **THEN** 測試全綠

#### Scenario: 說明文件先講定位

- **WHEN** 讀者開啟該 repo 的說明文件
- **THEN** 首段即說明服務端位於 Custodexa 本體、本工具只是 stdio 轉接頭，以及哪類宿主不需要它
