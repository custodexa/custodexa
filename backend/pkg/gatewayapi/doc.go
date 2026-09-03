// Package gatewayapi 定義 gateway 行程邊界的對外契約。
//
// # 定位
//
// 本包是模組拓樸序的最底層：`pkg/gatewayapi` → {keyvault, policy} → audit →
// asset → authz → {identity, session}。它只宣告「跨行程也成立」的型別與介面，
// 不含任何實作、不含任何持久層概念。七個模組共用此處的語彙，而不互相 import。
//
// # 型別純淨（硬性，由守衛釘住）
//
// 進入本包的型別 SHALL 零 `internal/model`、零 `gorm`、零 `gin` 相依，且不得相依
// 本 module 的任何 `internal/...` 包。理由：這些型別是未來 gateway 行程的線上格式，
// 一旦相依 GORM，整個公開包就把 ORM 拖進 gateway 行程；即使加註解說「不跨行程」，
// 依賴事實仍在。
//
// 直接後果：**`TxSink` 不在本包**。它的簽名帶 `*gorm.DB`，故落在
// `internal/modules/audit/port`（同行程 internal port，刻意不可跨行程）。
// 守衛 TestGatewayAPITypePurity／TestAuditTxSinkPortShape 同時釘住「本包零 GORM」
// 與「TxSink 不得出現在本包」兩件事——放錯位置即紅。
//
// # 兩條 SHALL NOT
//
//  1. `ConnectSubject.ClaimedRole`／`AuthEpoch`／`CredEpoch` 皆為 caller-asserted，
//     SHALL NOT 作為授權判定依據。判定一律由實作現查。
//  2. 審計脈絡只採信 `Decision.ResolvedRole`（服務端現查值）。把 caller 提供的角色
//     寫進審計，等於讓 caller 決定稽核紀錄怎麼寫。
//
// # 未定案的東西不進契約
//
// `SessionLimits` 刻意不含 `RecordingRequired`（尚未拍板；兌換側現況零強制，
// 本 change 內無生產者無消費者）。寫入即固化未定案行為。
package gatewayapi
