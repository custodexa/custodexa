# backend/scripts — 輔助測試工具索引

本目錄收納「主線煙測不涵蓋」的專題 E2E 腳本與煙測輔助工具。
所有腳本皆需 `docker compose` 全棧運行中，且假設後端在 `http://localhost:8080`。

## 先跑一鍵煙測

連線體驗主線（SSH WS 直連、指令審計、asciicast 錄製回放、工作區 API 與統一錯誤封套、
指令阻斷、資料庫協議、K8s、SFTP 保真、多帳號切換、OIDC SSO、RDP／VNC 圖形協議）
由根目錄的煙測腳本涵蓋：

```bash
./scripts/e2e_smoke.sh   # 專案根目錄執行，失敗即非零退出
```

本目錄的腳本只補該腳本未覆蓋的面向，不重複主線場景。

## 專題 E2E 腳本（bash）

| 腳本 | 覆蓋面 |
|---|---|
| `test_command_audit.sh` | 指令審計 **API 面**：跨會話 keyword 搜尋、user_id 過濾、分頁 total、無權限 403（e2e_smoke 只斷言單一會話的真鍵流入庫） |
| `test_command_alerts.sh` | 危險指令告警：規則 CRUD 與參數驗證、權限（403/401）、告警查詢的過濾與分頁 |
| `test_alert_notifications.sh` | 告警通知通道：CRUD、權限、URL 驗證、測試發送 |
| `test_ldap_auth.sh` | LDAP 認證：首登供應影子用戶、二登不重建、錯密拒絕、改密被拒、審計 source=ldap（需 `ldap-test` 靶機） |
| `test_mfa_flow.sh` | MFA TOTP：setup / enable / 兩階段登入 / pending token 受限 / self disable / admin 救援（驗證碼由 `totp_code.go` 產生） |
| `test_user_management.sh` | 用戶管理完整生命週期：建立 → 指派角色 → 修改 → 停用 → 啟用 → 刪除，含搜尋與過濾 |

各腳本皆可重複執行、自帶清理段。

## 煙測輔助工具（Go，皆帶 `//go:build ignore`，以 `go run` 呼叫）

| 檔案 | 用途 |
|---|---|
| `sshws_smoke.go` | SSH WebSocket 連線煙測驅動；由 `scripts/e2e_smoke.sh` 呼叫 |
| `dbws_smoke.go` | 資料庫協議 WebSocket 煙測驅動；由 `scripts/e2e_smoke.sh` 呼叫 |
| `guacws_smoke.go` | RDP／VNC 圖形協議 WebSocket 煙測驅動（`/api/v1/connect`，斷言 guacd sync 幀而非僅 TCP 可達）；由 `scripts/e2e_smoke.sh` 場景 16-17 呼叫 |
| `retention_smoke.go` | 稽核保存期策略煙測；由 `backend/config/env_drift_test.go` 引用 |
| `totp_code.go` | 產生與後端同時鐘的 TOTP 驗證碼，供 `test_mfa_flow.sh` 使用 |
| `generate_hash.go` | 產生 bcrypt 密碼雜湊的一次性小工具（目前無腳本呼叫，保留供手動種資料用） |

## 連線建立一律走 connect-token

新增連線相關測試時，一律**先取 connect-token 再建 WebSocket**，
參考 `sshws_smoke.go` 與 `scripts/e2e_smoke.sh` 場景 2 的做法。

**任何形態的密碼都不得作為 query 參數**，測試腳本也不例外——那與連線收口的紅線
（前端零接觸明文憑證、憑證不出後端）直接矛盾，且會在測試環境留下一條可被複製的錯誤範例。

## 新增腳本的約定

1. 先確認該面向未被 `scripts/e2e_smoke.sh` 覆蓋，否則加進煙測而非新開腳本。
2. 可重複執行：自行建立測試資料並在結束時清理。
3. 失敗即非零退出，且訊息要指出缺什麼、怎麼補。
4. 靶機或組態未就緒時 skip 而非 fail。
