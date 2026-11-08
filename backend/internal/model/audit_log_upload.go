package model

import "gorm.io/gorm"

// ScopeCompletedFileUpload 選取「上傳完成」的審計列。
//
// 圖形通道的上傳在串流開啟時即留一筆 file_upload/success 的開始紀錄（details.phase=started），
// 因此「完成」不能只看 action 與 status：判準是 file_upload、success，且 phase 不是 started。
// 這同時涵蓋新版 phase=completed 與沒有 phase 欄的既有完成紀錄（網頁檔案管理、舊版圖形通道）。
// details 可能為 NULL，以 COALESCE 防護，NULL 視為沒有 phase。
func ScopeCompletedFileUpload(tx *gorm.DB) *gorm.DB {
	return tx.Where("action = ? AND status = ? AND COALESCE(details, '') NOT LIKE ?",
		ActionFileUpload, StatusSuccess, `%"phase":"started"%`)
}
