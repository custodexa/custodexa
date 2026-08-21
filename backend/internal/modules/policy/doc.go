// Package policy 是「可否／以何條件進行」的判定收斂處（modular-architecture Phase B W3）。
//
// 職責邊界（R3 §M4）：36 個政策鍵的定義／讀取／快取／更新；存取政策三段位判定；
// 傳輸安全六通道判定與同意立據；密碼政策的無狀態合規子集。
//
// # 零出向（分層聲明，不得混稱）
//
//   - **import 層**：本模組 SHALL NOT import 任何其他業務模組（asset／identity／
//     authz／audit／session／keyvault）。所需的他模組資料一律經**本模組自宣告的
//     窄介面**取得，由組裝根注入：
//     `ConnectSourceResolver`（authz 實作，§4.8）與 `ChannelInventoryProvider`
//     （audit 實作，§4.11）。`go list -deps ./internal/modules/policy` 的
//     custodexa 相依只應剩 `internal/model`／`internal/apierror`。
//   - **資料層**：**不成立**（誠實界定，比照 W2 keyvault）。本模組仍持有 `*gorm.DB`
//     並直接讀寫下列非自有表：`assets`（`access_policy_service.go` 的
//     `CheckConnectByAssetID` 單列讀、`transmission_inventory_service.go` 的聚合
//     計數，屬 asset）、`users`（`transmission_consent_service.go` 的審計反正規化
//     使用者名，屬 identity）、`audit_logs`（同檔 `writeAudit` 直寫，屬 audit）、
//     `syslog_settings`（清冊讀取，屬 audit）。這些是 W6 前置「資料邊界閘門」
//     （tasks 6.0a–6.0c）的登記對象，不在本波處置範圍。
//
// 自有表：`security_policies`、`transmission_consents`。
package policy
