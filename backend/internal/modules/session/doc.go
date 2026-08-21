// Package session 是會話模組（modular-architecture Phase B / W9，Phase B 最後一個搬檔波）。
//
// # 職責
//
// 會話生命週期與狀態機（建立／終止／CAS 終態保護）、對帳與逾時終結、錄影管理與播放、
// 自助連線視圖（我的連線）、SFTP 檔案操作、命令片段。
//
// **3.8b「以既有身分產生新長效能力」的兩個執行點住在本包**
// （`SessionService.CreateWithGenerationGuard`／`JoinWithGenerationGuard`，
// `session_provider_termination.go`），但序列化契約的**判定**（能力鎖、憑證世代閘、
// pre-write 同步點）屬 identity——判定與建立分屬兩包是 backlog B-30 的根因，
// 收束時機為 W10（閘序統一）。
//
// # 出向依賴（import 層）
//
// 三條，皆為 R3.1 §3.2 矩陣的既有合法邊，且各自只有一個檔在用：
//
//   - `identity`（`session_provider_termination.go`）：能力鎖 `WithCapabilityLocks`、
//     交易版世代閘 `VerifyCredentialGenerationTx`、同步點 `FirePreWriteHook` 與兩個位置標籤。
//     **取鎖順序固定 provider → user（design D13）**，由
//     `identity.TestCapabilityLocksAcquireProviderBeforeUser`（順序本身）與
//     `identity_test.TestSessionCallSitesPassProviderAndUserInOrder`（本包兩個呼叫點
//     有沒有把兩個 `uint` 引數放對位置）雙向釘住。
//   - `audit`（`recording_failure_report.go`）：`CauseText` 與失效事件登記面。
//   - `asset`（`sftp_service.go`）：SFTP 建線所需的資產、帳號身分與 host key 服務。
//
// 對 `authz`、`policy`、`keyvault` 零出向。
//
// # 錄影的三個消費面（勿混為一談）
//
// 本包的 `RecordingService` 同時是三種東西的實作：HTTP 播放／下載路徑直接持有它的
// **具體型別**（`internal/api.RecordingHandler`，編譯期綁定）；審計匯出與保留期硬刪
// 則經 audit 側宣告的**消費者側窄介面** `audit.RecordingReader`／`audit.RecordingCleaner`
// （W4 4.8 的 C↔E 環反轉），由組裝根注入**同一個實例**。
// 兩種形態並存是刻意的：介面只存在於「會構成 import 環」的那兩個消費者上。
//
// # 誠實邊界
//
// 「零出向」只在 import 層成立。資料層另有 `cmd/server/module_data_boundary_guard_test.go`
// 的 ratchet 守衛：本包現況登記 3 條跨模組資料存取（`assets` 讀、`users` 讀、
// `audit_logs` 寫），搬包不改變它們，只改變它們住在哪個包。
package session
