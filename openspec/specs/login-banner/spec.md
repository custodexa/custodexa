# login-banner

## Purpose

登入前告示：管理者於安全政策設定的一段純文字，於登入頁帳密表單之前顯示，用於告知使用者本系統僅供授權者使用且操作受監控。本能力定義未認證可讀的告示端點與登入頁的呈現契約（純文字、未設定不顯示、失敗降級、不強制確認）。

## Requirements

### Requirement: 登入前告示的公開讀取端點
系統 SHALL 提供未認證可讀的端點 `GET /api/v1/auth/banner`，只回登入告示內容。回應鍵集合 SHALL 精確為：未設定（內文正規化後為空）時 `{"enabled": false}`；已設定時 `{"enabled": true, "title": <標題或空字串>, "body": <內文>}`。回應 SHALL NOT 含任何其他政策鍵、政策值、建議值、符合性、修改者或修改時間；標題有值而內文為空時 SHALL 視為未設定，SHALL NOT 單獨回標題。回應 SHALL 帶 `Cache-Control: no-store`。

本端點 SHALL NOT 產生審計列、SHALL NOT 寫入資料庫；讀取 SHALL 經政策服務快取。狀態：正常服務（含政策讀取暫時失效時退回最後已知值）回 200；封印期回 503 與封印機器碼 `SEAL_SERVICE_SEALED`，與登入方法清單端點一致；其餘失敗只來自基礎設施，前端一律視為失敗降級。

標題與內文分別讀取；管理員正在儲存的一瞬間，回應可能一鍵為更新前、另一鍵為更新後，並於政策快取有效期內收斂。此為刻意揭露的邊界。

#### Scenario: 未設定時回應不含任何文字
- **WHEN** 兩鍵皆為出廠預設，未認證請求 `GET /api/v1/auth/banner`
- **THEN** 回 200 且 body 精確為 `{"enabled": false}`，`Cache-Control` 為 `no-store`

#### Scenario: 已設定時只回標題與內文
- **WHEN** 管理員已設定標題與內文，未認證請求該端點
- **THEN** 回 200 且 body 鍵集合精確為 `enabled`、`title`、`body`；回應中不出現 `lockout_max_attempts` 等任何其他政策鍵，亦無 `updated_by`／`updated_at`

#### Scenario: 標題有值但內文為空視為未設定
- **WHEN** `login_banner_title` 有值而 `login_banner_body` 為空
- **THEN** 回 `{"enabled": false}`，不含標題

#### Scenario: 未認證可讀且不留審計列
- **WHEN** 不帶任何憑證請求該端點
- **THEN** 回 200（非 401），且審計日誌不新增任何列

#### Scenario: 封印期不可用
- **WHEN** 系統處於封印狀態時請求該端點
- **THEN** 回 503 與封印機器碼 `SEAL_SERVICE_SEALED`

### Requirement: 登入頁登入前呈現告示
登入頁 SHALL 於掛載時讀取登入前告示端點（與登入方法清單並行、互不阻塞）。已設定時 SHALL 於品牌頭之後、任何表單欄位之前顯示告示：標題（有值才顯示）與內文，內文 SHALL 保留換行、以純文字呈現——SHALL NOT 渲染 HTML、Markdown 或連結，標記字元 SHALL 以原字顯示；長內文 SHALL 於固定高度內捲動。告示 SHALL 於登入頁的每個步驟顯示，SHALL NOT 依登入方式或步驟隱藏。未設定時 SHALL NOT 渲染任何告示節點（不佔位）。端點失敗（含封印期 503 與網路錯誤）時 SHALL 不顯示告示且登入頁其餘功能不受影響，SHALL NOT 彈出錯誤提示。

告示為顯示型：系統 SHALL NOT 因告示尚未載入而停用登入控制項，SHALL NOT 要求使用者確認、勾選或點擊方可登入，SHALL NOT 記錄使用者是否閱讀。告示請求慢於使用者提交登入時，使用者可能在告示出現前完成登入；此為刻意揭露的邊界。告示內容 SHALL NOT 隨介面語言切換；告示區塊的無障礙標籤等 UI 文字 SHALL 三語齊備。本能力射程為 web 登入頁；SSH／VNC／RDP 等協議建線前 SHALL NOT 被宣稱具備告示能力。

登入頁 SHALL 於內容高於視窗時可垂直捲動，使告示頂端與登入按鈕在 390 像素寬的視窗內皆可抵達。告示捲動區 SHALL 可由鍵盤聚焦。告示元件與登入頁 SHALL NOT 使用任何原始 HTML 綁定；此約束 SHALL 由測試釘住。

#### Scenario: 有告示時顯示於表單之前
- **WHEN** 管理員已設定標題與內文，使用者開啟登入頁
- **THEN** 帳密欄位上方顯示標題與內文，內文的換行與原文一致，登入表單與 SSO 按鈕照常可用

#### Scenario: 未設定不佔位
- **WHEN** 兩鍵皆為空，使用者開啟登入頁
- **THEN** 頁面無任何告示節點

#### Scenario: 端點失敗登入頁仍可用
- **WHEN** 告示端點回 503 或請求失敗
- **THEN** 不顯示告示、不彈出錯誤提示，使用者可正常輸入帳密登入

#### Scenario: 告示尚未載入不阻擋登入
- **WHEN** 登入頁已掛載而告示請求尚未回應
- **THEN** 登入按鈕、密碼欄 Enter 與 SSO 按鈕皆可用；告示回應抵達後才顯示於表單之前

#### Scenario: 純文字呈現
- **WHEN** 內文含 `<script>alert(1)</script>` 與 `[連結](https://example.test)`
- **THEN** 兩者皆以原字顯示，頁面未執行任何腳本、未產生任何連結元素

#### Scenario: 切換語言內容不變
- **WHEN** 使用者於登入頁切換介面語言
- **THEN** 告示區塊的無障礙標籤隨語言變更，標題與內文文字不變

#### Scenario: 長內文於固定高度內捲動
- **WHEN** 內文接近 2000 字元
- **THEN** 告示區塊在固定高度內可捲動，帳密欄位與登入按鈕仍在 1440×900 首屏內可見

#### Scenario: 窄螢幕可捲到告示與登入按鈕
- **WHEN** 視窗為 390×667 且內文接近 2000 字元
- **THEN** 頁面可垂直捲動，告示頂端與登入按鈕皆可捲至可見，無水平捲動

#### Scenario: 後續步驟仍顯示告示
- **WHEN** 使用者登入後被要求變更密碼或輸入第二因素
- **THEN** 該步驟畫面仍於表單之前顯示告示
