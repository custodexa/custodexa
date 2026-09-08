# dev-test-targets Specification

## Purpose

開發版 compose 測試靶機契約：多帳號 SSH 靶機的帳號組成、登入方式與煙霧驗證要求，
以及撥線煙霧工具的連線收口一致性。為未來其他靶機契約預留歸屬。

## Requirements

### Requirement: 多帳號 SSH 靶機
開發版 compose SHALL 包含多帳號 SSH 靶機服務：至少兩個系統帳號（一枚 uid 0 特權帳號、
一枚非特權帳號）皆可密碼登入，sshd SHALL 具備切換至任一帳號建立會話的能力（rootful 執行）。
靶機 SHALL NOT 出現在正式版 compose。

#### Scenario: 兩帳號皆可建線且身分不同
- **WHEN** 對指向多帳號靶機的資產分別以特權與非特權帳號建立 SSH 會話並執行 `id -u`
- **THEN** 兩會話均成功建立，輸出分別為 `0` 與非零 uid

#### Scenario: 開發環境即得
- **WHEN** 開發者以開發版 compose `docker compose up -d` 啟動環境
- **THEN** 多帳號靶機隨環境就緒，無須手工搭建

### Requirement: 多帳號煙霧場景
e2e 煙霧腳本 SHALL 含多帳號場景：以 API 臨時建立指向多帳號靶機的資產、附加第二帳號，
分別以預設帳號與指定帳號簽發 connect token 建線，並以會話內指令輸出斷言兩者身分不同；
場景結束 SHALL 清理臨時資產。

#### Scenario: 煙霧驗證帳號切換
- **WHEN** 執行 e2e 煙霧腳本的多帳號場景
- **THEN** 預設帳號會話輸出非零 uid、指定特權帳號會話輸出 `0`，臨時資產於場景後刪除

### Requirement: 撥線煙霧工具走連線收口
SSH 撥線煙霧工具 SHALL 以 JWT 簽發一次性 connect token 後撥線（與產品連線收口一致），
SHALL 支援指定帳號簽發（省略即預設帳號），SHALL NOT 依賴任何已廢止的 WS 認證參數。

#### Scenario: 既有撥線場景復活
- **WHEN** 以有效 JWT 執行撥線煙霧工具（不指定帳號）
- **THEN** 工具自行簽發 connect token 並成功建線（非 401），echo/resize 斷言通過

#### Scenario: 指定帳號撥線
- **WHEN** 以 `-account <id>` 指定資產上的特權帳號執行撥線煙霧工具
- **THEN** connect token 綁定該帳號，會話身分為該帳號

### Requirement: OIDC 身分提供者靶機
開發版 compose SHALL 包含 OIDC 身分提供者靶機服務，提供 discovery、授權、token 與 JWKS 端點及可預期的靜態測試帳號，使 OIDC 登入鏈路可於開發環境完整重現。

靶機的 issuer SHALL 以**主機名稱**表述，且該名稱 SHALL 在後端容器內與瀏覽器端皆可解析至靶機（OIDC discovery 要求 issuer 完整字串一致，兩端位址不同即無法驗證且無合法繞法；SHALL NOT 使用回送位址字面值——容器內的回送位址指向容器自身，且名稱解析設定無法改變位址字面值的語義）。靶機 SHALL NOT 出現在正式版 compose，對外埠 SHALL 僅綁定本機回送位址。

#### Scenario: 開發環境即得
- **WHEN** 開發者以開發版 compose 啟動環境
- **THEN** OIDC 靶機隨環境就緒，無須手工搭建

#### Scenario: issuer 兩端一致可達
- **WHEN** 後端容器內與瀏覽器分別以設定的 issuer 位址取得 discovery 文件
- **THEN** 兩者皆可達且回應的 issuer 與設定值完全相同

### Requirement: OIDC 煙霧場景
e2e 煙霧腳本 SHALL 含 OIDC 場景：以靶機帳號完成授權碼流程取得會話並據以建立協議連線，並 SHALL 涵蓋至少一項拒絕路徑（准入拒絕或同名衝突）以證明 fail-close 行為；場景結束 SHALL 清理臨時建立的資產與 provider 設定。

#### Scenario: 煙霧驗證 OIDC 登入
- **WHEN** 執行 e2e 煙霧腳本的 OIDC 場景
- **THEN** 完成 SSO 登入取得會話、成功建立協議連線，拒絕路徑回預期的拒絕結果，臨時資料於場景後清除

### Requirement: Windows 單機回歸

開發環境的容器靶機 SHALL NOT 假裝提供 Windows 目標（Linux 主機無法執行 Windows 容器）；Windows 改密的機器驗證 SHALL 以持續整合環境的 Windows 單機回歸承擔：
該主機同時作為客戶端與目標，啟用 WinRM 與 OpenSSH 服務、建立臨時本機管理員帳號，以產品的 WinRM 與 SSH 到 PowerShell 執行器對回送位址完成改密與新密碼驗證。
回歸 SHALL 為手動觸發，SHALL NOT 把測試帳號密碼寫入日誌或產物；驗收報告 SHALL 附該次執行記錄的連結。
文件 SHALL 明載此驗證面的限制：只涵蓋該主機當下的單一 Windows Server 版本、回送網路不涵蓋跨機與憑證鏈情境。

#### Scenario: 單機回歸涵蓋兩通道

- **WHEN** 手動觸發 Windows 單機回歸
- **THEN** WinRM 通道與 SSH 到 PowerShell 通道各完成一次改密與驗證，結果以結構化行輸出，密碼不出現於日誌

#### Scenario: 本機開發環境誠實無靶機

- **WHEN** 開發者於開發版 compose 尋找 Windows 靶機
- **THEN** 文件說明無此靶機並指向 Windows 單機回歸，不存在假冒 Windows 的服務

### Requirement: 目錄靶機的群組資料


開發版 compose 的目錄靶機 SHALL 種入至少兩個群組與可預期的成員關係，使群組對角色映射的兩條路徑（命中與不命中）皆可於開發環境重現。群組的辨識名稱 SHALL 可預期且寫入文件，供煙霧場景與手動驗證直接引用。

靶機 SHALL 提供至少一個「屬於受映射群組」與一個「不屬任何受映射群組」的帳號，使「取得角色」與「不取得角色」兩種結果皆可斷言。搜尋帳號 SHALL 具備讀取群組屬性的權限——讀不到與不屬於在單筆目錄項目上同形，靶機若讀不到就測不出兩者的差別。

#### Scenario: 開發環境即得群組

- **WHEN** 開發者以開發版 compose 啟動環境
- **THEN** 目錄靶機隨環境就緒且已含測試群組與成員，無須手工建立

#### Scenario: 兩種結果皆可重現

- **WHEN** 分別以屬於與不屬於受映射群組的靶機帳號登入
- **THEN** 前者取得映射角色、後者不取得，兩者皆可自角色列與審計驗證

### Requirement: 身分提供者靶機的群組宣告


開發版 compose 的身分提供者靶機 SHALL 對其靜態測試帳號發出群組宣告，且該宣告的名稱與值 SHALL 可預期並寫入文件。至少一個帳號 SHALL 帶群組值、至少一個 SHALL 不帶，使空集合路徑可被測到。

宣告的形態（鍵名與值的型別）SHALL 於靶機設定就地註明，並 SHALL 提醒改動前先實際解一次身分權杖確認——靶機的連接器對宣告的處置未必與設定檔的字面直觀一致。

#### Scenario: 靶機發出群組宣告

- **WHEN** 以帶群組的靶機帳號完成授權碼流程
- **THEN** 身分權杖含設定的群組宣告，其值與文件記載相同

#### Scenario: 空集合路徑可測

- **WHEN** 以不帶群組的靶機帳號完成授權碼流程
- **THEN** 系統視為空集合並依此重算，該帳號不取得映射角色

### Requirement: 群組映射煙霧場景


e2e 煙霧腳本的目錄場景與身分提供者場景 SHALL 各自斷言登入後的**角色**，SHALL NOT 只斷言登入成功。兩個場景 SHALL 各涵蓋「群組命中取得角色」與「移出群組後再次登入失去角色」兩段，後者 SHALL 一併斷言憑證世代已推進。

場景結束 SHALL 清理其建立的映射規則與臨時帳號。清理 SHALL 沿既有的清理形態，SHALL NOT 因新增的資料表而卡住既有清理語句。

前置不成立（靶機未運行、群組未種入、宣告未設定）SHALL 跳過而非失敗，並 SHALL 印出可據以修復的原因。

#### Scenario: 煙霧驗證取得角色

- **WHEN** 映射規則已設且以屬於該群組的靶機帳號登入
- **THEN** 煙霧場景斷言該帳號的有效角色含映射角色，且審計含對應事件

#### Scenario: 煙霧驗證失去角色

- **WHEN** 該帳號被移出群組後再次登入
- **THEN** 煙霧場景斷言該角色已不在其有效角色集內、憑證世代已推進

#### Scenario: 前置不成立即跳過

- **WHEN** 目錄靶機未種入測試群組
- **THEN** 場景跳過並印出原因，SHALL NOT 判為失敗
