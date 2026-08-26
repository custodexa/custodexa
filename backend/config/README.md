# 功能開關配置

功能開關允許以環境變數控制個別子系統的啟用狀態，用途是風險控管
（發現問題時快速關閉）與漸進式啟用（先於測試環境驗證再開生產）。

> **權限檢查沒有開關**：它於所有模式無條件生效。
> 安全紅線中「任何組態都不該關」者，正確處置是不提供開關，而非提供後於 release
> 模式強制——後者使開發與測試組態成為「權限缺陷測不出來」的環境。

## 開關列表（與 `config.go` 的 `FeatureFlags` 對應）

| 環境變數 | 預設 | 說明 |
|---------|------|------|
| `FEATURE_AUDIT_LOG_ENABLED` | `true` | 審計日誌記錄。關閉即審計中間件不掛、`/audit-logs` 不註冊、寫入路徑短路 |
| `FEATURE_ASYNC_AUDIT_ENABLED` | `true` | 審計日誌異步寫入 |
| `FEATURE_AUDIT_FALLBACK_TO_FILE` | `true` | 資料庫寫入失敗時降級寫檔（有訊號的降級） |
| `FEATURE_ANOMALY_DETECTION_ENABLED` | `false` | 異常連線行為偵測 |
| `FEATURE_ALERTING_ENABLED` | `false` | 告警通知系統 |

## 非開關的啟動期確認值

| 環境變數 | 說明 |
|---------|------|
| `INSTANCE_GUARD_ACK` | 單實例守衛的一次性衝突確認碼（`config.InstanceGuard.Ack`）。**不是開關**：只對與本次啟動查得的持鎖者指紋碼相符的一次衝突生效，持鎖者變更即失效，每次生效皆寫審計事件。攔下訊息會當場印出要設的值；刻意不入 `.env.example`（登記於 `env_drift_test.go` 的 allowlist）。 |

## 設定方式

在專案根 `.env`（由 `.env.example` 複製）設置——dev 與 prod compose 皆以 `env_file` 消費它：

```bash
FEATURE_AUDIT_LOG_ENABLED=true
FEATURE_ALERTING_ENABLED=false
```

修改後須重啟服務才生效：`docker compose restart backend`。
啟動日誌會印出「=== 功能開關狀態 ===」區塊，以此確認實際生效值；
關閉功能不會刪除資料庫中已有的資料。

`getEnvBool` 接受的值（不區分大小寫）：
`true`／`1`／`yes`／`on`／`t`／`y` 與 `false`／`0`／`no`／`off`／`f`／`n`。

## 程式碼中使用

```go
cfg := config.Load()
if cfg.Features.AuditLogEnabled {
    auditService.Log(event)
}
```

## 新增開關

1. `config.go` 的 `FeatureFlags` 結構體加欄位。
2. `Load()` 內以 `getEnvBool("FEATURE_...", 預設值)` 綁定（新功能預設 `false`）。
3. 視需要在啟動日誌的功能開關狀態區塊補一行。
4. 更新本檔的開關列表。

## 相關文檔

- 授權與權限判定的行為規格：[`openspec/specs/authorization-management/`](../../openspec/specs/authorization-management/)
- 審計覆蓋與 fail-close 語義：[`openspec/specs/audit-coverage/`](../../openspec/specs/audit-coverage/)、
  [`docs/dev/conventions.md`](../../docs/dev/conventions.md) 第 6 節
- 全部可用環境變數：專案根 `.env.example`
