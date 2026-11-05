package keystroke

// 紀錄內標記事件（kind 0x10）的機器碼。
//
// 標記是平台寫進紀錄的狀態事件，不是使用者輸入：payload 為下列碼字串的原始位元組，
// 旗標帶 platform。讀取端以碼查譯文案；不認得的碼原樣呈現，不中斷解碼。
// 碼值是儲存格式的一部分，新增可以、改名與重用舊碼不可以。
//
// 會話結束類（每份正常收尾的紀錄至多一筆，緊接在最後一筆輸入之後、結束段之前）：
const (
	// MarkerEndUserClosed 使用者端（瀏覽器）正常關閉連線。
	MarkerEndUserClosed = "end_user_closed"
	// MarkerEndClientLost 使用者端連線中斷（非正常關閉、逾時未回應）。
	MarkerEndClientLost = "end_client_lost"
	// MarkerEndTargetClosed 目標主機端結束了這條連線（遠端 shell 結束或連線中斷）。
	MarkerEndTargetClosed = "end_target_closed"
	// MarkerEndIdleTimeout 閒置逾時，由平台收線。
	MarkerEndIdleTimeout = "end_idle_timeout"
	// MarkerEndMaxDuration 達到會話時長上限，由平台收線。
	MarkerEndMaxDuration = "end_max_duration"
	// MarkerEndBlockClearFailed 指令阻斷後清除遠端行緩衝失敗，平台為避免殘句被送出而收線。
	MarkerEndBlockClearFailed = "end_block_clear_failed"
	// MarkerEndTerminated 平台端終止（管理員中止、授權撤銷、資產停用等）。
	MarkerEndTerminated = "end_terminated"
)

// 寫入端狀態類：
const (
	// MarkerWriterStalled 輸入背壓等待逾時而判定寫入端停擺。
	// 盡力而為：寫入端仍能執行時才會落入檔案，且其後的輸入不再記錄；
	// 寫入端卡在系統呼叫時寫不進，以紀錄列的失敗原因為準。
	MarkerWriterStalled = "writer_stalled"
)

// MarkerCodes 回傳全部已定義的標記碼（供查譯完整性測試與前端對照）。
// 沒有「寫入端恢復」碼：寫入端一旦判定失敗就不再恢復，該紀錄到此為止。
func MarkerCodes() []string {
	return []string{
		MarkerEndUserClosed, MarkerEndClientLost, MarkerEndTargetClosed,
		MarkerEndIdleTimeout, MarkerEndMaxDuration, MarkerEndBlockClearFailed,
		MarkerEndTerminated, MarkerWriterStalled,
	}
}
