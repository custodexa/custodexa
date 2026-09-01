package audit

import "io"

// 錄影讀取／清理的**消費者側窄介面**（C↔E 環反轉）。
//
// # 為何宣告在 audit 側
//
// 早期 `AuditExportService` 與 `RetentionService` 都直接持有 session 模組的
// `*service.RecordingService` 具體型別。session 搬包後那條參照會變成
// audit→session 的 import，而 session 反過來又消費 audit（`CauseText`／失效事件
// 登記）——**直接是 import cycle**，編譯不過。介面由消費者宣告、由 session 側的
// 既有型別隱式滿足、組裝根注入，方向即翻轉為 session→audit。
//
// **實測（session 已搬入 `internal/modules/session`）**：兩個消費面都仍只認本檔
// 的介面，唯一實作者是 `*session.RecordingService`，且組裝根注入的是**同一個實例**
// （`cmd/server/stage2.go` 的 `recordingService`）；HTTP 播放／下載／串流三條路徑
// 則不經本介面，直接持有該具體型別。
//
// # 為何切成兩個而不是一個 RecordingReader（相對原始設計的判斷，可逆）
//
// 原始設計的說法是「`NewRetentionService` 的 recording 參數同樣改
// `RecordingReader` 窄介面」。實作時發現兩個消費者要的東西沒有交集：匯出要
// 「讀」（協定別＋位元流），保留政策要「刪」（清理過期檔）。合成一個三方法介面，
// 等於讓 retention 的測試替身被迫實作兩個它永遠不呼叫的方法，也讓「誰能刪錄影」
// 這件事在型別上看不出來。故拆成 RecordingReader（2 方法）與 RecordingCleaner
// （1 方法），兩者都由同一個 `*service.RecordingService` 滿足——環一樣斷、
// 承載面更窄（export budget 取向）。
//
// # 為何是 RecordingProtocol 而不是 GetRecordingMetadata
//
// 匯出端對 metadata 的**唯一**用途是 `meta.Protocol`（決定 zip 內的副檔名，
// audit_export_service.go 的 writeRecordings）。若介面照抄
// `GetRecordingMetadata(uint) (*RecordingMetadata, error)`，回傳型別
// `RecordingMetadata` 住在 session 側，audit 就得 import 它——環根本沒斷。
// 把介面收到「只回它真的用得到的那一個字串」，型別相依隨之消失。
// session 側因此新增一個薄方法 `RecordingProtocol`（export budget 登記 1 項），
// 語義逐字等同「取 metadata、失敗即回錯、成功回 Protocol」。

// RecordingReader 錄影讀取面（匯出用）。
type RecordingReader interface {
	// RecordingProtocol 取該會話錄影的協定別（決定匯出檔副檔名）。
	// 回 error 表示無錄影或檔案缺失——呼叫端 SHALL 沿用現況處置（跳過該筆，不阻斷整包）。
	RecordingProtocol(sessionID uint) (string, error)

	// GetRecordingStream 取錄影位元流。呼叫端負責 Close。
	GetRecordingStream(sessionID uint) (io.ReadCloser, error)
}

// RecordingCleaner 錄影檔清理面（保留政策用）。
type RecordingCleaner interface {
	// CleanupOldRecordings 刪除超過保留天數的錄影檔，回傳刪除檔數。
	CleanupOldRecordings(retentionDays int) (int, error)
}

// OffsiteRecordingRetention 離機啟用後的錄影保留補充面。
//
// **另立一個 port 而非擴充 RecordingCleaner**：兩者的觸發條件不同——
// 既有那一個由錄影保留天數驅動且**恆存在**；本 port 的兩個方法只在離機子系統
// 已組裝時才有意義，把它們併進去會逼每一個既有的 RecordingCleaner 實作
// （含測試替身）為一件與它無關的功能長出兩個空方法。
//
// 同樣由 `*session.RecordingService` 滿足，故 audit → session 的零 import 不變。
type OffsiteRecordingRetention interface {
	// PurgeOffsiteLocalCache 快取清除段：刪已離機且超過快取期的本機檔，
	// **不動錄影三欄、不推進水位**（錄影仍可自離機副本播放）
	PurgeOffsiteLocalCache(cacheDays int) (int, error)
	// PurgeExpiredOffsiteRecords 政策到期段的 DB 分支：本機已無檔但仍有帳冊列的
	// 過期會話 → 帳冊標記到期＋擁有表清欄。**對遠端零呼叫**
	PurgeExpiredOffsiteRecords(retentionDays, maxPerRun int) (int, error)
}
