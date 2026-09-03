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
