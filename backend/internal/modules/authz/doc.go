// Package authz 授權模組：常設授權（資產 ACL）＋票證授權（存取申請／核准／
// break-glass／撤銷）＋審核者範圍＋有效權限解析＋路由級 RBAC 表。
//
// 模組邊界（modular-architecture W7）：
//   - **允許出向**：`asset`（`ValidateAccountUsername`／`FillNodeInfo`）、
//     `policy`（存取政策與傳輸判定）、`audit`（`port.TxSink` 交易內審計）、
//     `internal/model`、`internal/database`、`pkg/*`。
//   - **禁止出向**：`identity`、`session`、`keyvault`。對 session 的終結能力
//     以消費者側窄介面（`SessionTerminator`）宣告、由組裝根注入。
//
// 授權寫入的兩條路徑（常設 grant 與票證 grant）在本模組內收斂為單一資料存取層
// （`assetAuthorizationRepository`，W7 自 `internal/repository` 內化）。
package authz
