// Package asset 是資產模組（modular-architecture Phase B / W6）。
//
// # 職責
//
// 資產與資產樹 CRUD、資產帳號（asset-multi-account）、憑證的封裝與解封、
// 改密計劃與執行、host key TOFU。**資產憑證明文的唯一產生地**——全庫只有兩個
// 解封出口（`AssetService.GetWithCredentialsForAccount` 與 `GetSftpPassword`），
// 由 `cmd/server/asset_credential_exit_guard_test.go` 釘住，新增出口須經安全審查。
//
// # 出向依賴（import 層）
//
// 只到三個已搬包的底層模組：`audit`（交易內審計落地面 `port.TxSink`）、
// `keyvault`（密文欄的 CipherRef 常數）、`policy`（資產列表的傳輸風險徽章）。
// 對 authz／identity／session **零出向**，由 `forbiddenModuleEdges` 的 asset 列釘住。
//
// # 誠實邊界
//
// 「零出向」只在 import 層成立。資料層另有 `cmd/server/module_data_boundary_guard_test.go`
// 的 ratchet 守衛（現況 asset 對 authz 有兩處 F8 交易級聯寫入，W7 7.4 收口）。
package asset
