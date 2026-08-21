package proxy

import (
	"log"
	"os"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/recorder"
)

// graphicsRecordingDeps 圖形錄影落地鏈的外部相依（graphics-teardown-sync D4／D8）。
//
// **為什麼要參數化**：這段落地鏈原本內聯在 `ConnectionHandler.HandleConnect` 一個
// 約 60 行的 `if` 區塊內，四個失效回報點與 `Resolve` 全部無法在不起完整 WebSocket
// handler 的情況下被觸發——`internal/proxy` 對「rename / stat 失敗時到底回報了哪個
// cause」因此零覆蓋。本結構只把外部作用（檔案系統、metadata 寫入、失效通報、
// 恢復宣告）參數化，落地鏈的判斷順序、log、回報點與 `Resolve` 的相對順序**逐字不變**。
type graphicsRecordingDeps struct {
	// stat / rename 檔案系統操作（正式路徑一律傳 os.Stat／os.Rename）。
	// 參數化的唯一目的是讓「取大小失敗」這條路徑可被注入——它在真實檔案系統上
	// 只發生於 rename 成功與 stat 之間檔案被移走的競態，無法穩定重現。
	stat   func(name string) (os.FileInfo, error)
	rename func(oldPath, newPath string) error
	// updateRecording 寫入 sessions.recording_path / recording_size
	updateRecording func(sessionID uint, path string, size int64) error
	// reportFailure 落地鏈任一步失敗的失效通報（不得沉默——recording-failure-handling D3/D6）
	reportFailure func(sessionID uint, cause string, params map[string]string)
	// resolve 錄影確認落地時關閉圖形路徑自己的失效事件（機制族分列）
	resolve func()
}

// finalizeGraphicsRecording 圖形（RDP/VNC）錄影落地：
// 確認 guacd 寫的暫存檔存在 → 更名為 session-N.guac → 量測大小 → 寫入會話 metadata。
//
// **量測語義（graphics-teardown-sync D6）**：此處 `os.Stat` 取得的是「落地確認當下的
// 量測值」，不是檔案最終大小。錄影檔的 fd 由 guacd 持有，其收尾尾段（釋放顯示層時送出的
// dispose 指令）寫入於本量測之後，而協議層不提供收尾完成訊號、guacd 亦不會先行關閉與
// 後端之間的連線，故後端不存在可用的同步點。差額方向恆為**少記**（DB ≤ 磁碟），
// 上界見 `recorder.GraphicsTeardownSlackBytes`。該值不得作為完整性、對帳或配額依據。
//
// basePath 空字串＝走 `recorder.ResolveBasePath` 的既有退路（RECORDING_PATH → 出廠預設）；
// 測試以臨時目錄注入。
func finalizeGraphicsRecording(sessionID uint, basePath, recordingName string, deps graphicsRecordingDeps) {
	// 路徑一律經 recorder 的收口點組出（filepath.Join，根已 Clean）：newPath 會被
	// 寫進 sessions.recording_path，而保留期清理端是拿 filepath.Walk 的輸出做
	// `WHERE recording_path = ?` 精確比對。字串拼接在 RECORDING_PATH 帶尾斜線時
	// 會產生雙斜線，檔案刪得掉但 DB 欄位清不掉，UI 留下「可回放」的死列。
	recordingPath := recorder.GraphicsTempRecordingPath(basePath, recordingName)

	// 檢查 RDP 錄製檔案是否存在
	if _, err := deps.stat(recordingPath); err != nil {
		// guacd 錄影失敗不回傳協議層（guacamole-server 原始碼實錘 fail-open），
		// 會後檔案存在性是 backend 唯一偵測點——缺檔須標記＋告警不得沉默
		//（recording-failure-handling D3/D6）
		log.Printf("[Handler] RDP 錄製檔案不存在: %s (可能錄製未啟用或 guacd 寫入失敗)", recordingPath)
		deps.reportFailure(sessionID, model.CauseRecordingFileMissing, nil)
		return
	}

	// 檔案存在，重命名為 session-{id}.guac
	newPath := recorder.GraphicsRecordingPath(basePath, sessionID)

	// 重命名錄製檔案：落地鏈任一步失敗都不得沉默（對抗驗證 Medium-4）
	if err := deps.rename(recordingPath, newPath); err != nil {
		log.Printf("[Handler] 重命名 RDP 錄製檔案失敗: %v", err)
		deps.reportFailure(sessionID, model.CauseRecordingRenameFailed,
			map[string]string{model.CauseParamDetail: err.Error()})
		return
	}
	log.Printf("[Handler] RDP 錄製檔案已重命名: %s", newPath)

	// 更新 Session 錄製資訊
	fileInfo, err := deps.stat(newPath)
	if err != nil {
		log.Printf("[Handler] 獲取 RDP 錄製檔案大小失敗: %v", err)
		deps.reportFailure(sessionID, model.CauseRecordingFileStatFailed,
			map[string]string{model.CauseParamDetail: err.Error()})
		return
	}

	fileSize := fileInfo.Size()
	if err := deps.updateRecording(sessionID, newPath, fileSize); err != nil {
		log.Printf("[Handler] 更新 RDP 錄製資訊失敗: %v", err)
		deps.reportFailure(sessionID, model.CauseRecordingMetadataUpdateFailed,
			map[string]string{model.CauseParamDetail: err.Error()})
		return
	}

	log.Printf("[Handler] RDP 錄製資訊已更新: SessionID=%d, Path=%s, Size=%d", sessionID, newPath, fileSize)
	// 錄影確認落地：關閉圖形路徑自己的失效事件（機制族分列，
	// 不觸碰 probe/文字路徑的事件）
	deps.resolve()
}
