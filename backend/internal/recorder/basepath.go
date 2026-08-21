package recorder

import (
	"fmt"
	"os"
	"path/filepath"
)

// DefaultBasePath 錄影根目錄的出廠預設（容器內路徑，對應 .env.example 的 RECORDING_PATH）。
const DefaultBasePath = "/var/lib/custodexa/recordings"

// ResolveBasePath 解析並正規化錄影根目錄——全後端**唯一**的錄影根事實源。
//
// 語義：呼叫端顯式注入的值優先，其次 RECORDING_PATH，最後出廠預設；回傳前一律
// filepath.Clean。
//
// **為什麼收口在讀取當下、而不是各使用點各自小心**：錄影根被兩組互不相識的程式碼
// 消費——寫入端把路徑字串存進 sessions.recording_path（圖形協議在
// internal/proxy/handler.go 更名時寫、文字協議在 asciicast.go 開檔時寫），刪除端則靠
// filepath.Walk 逐檔比對那個字串（clearRecordingInDB 是 `WHERE recording_path = ?`
// 的精確比對）。Walk 產出的必然是 clean 路徑，寫入端只要有任何一處沒 clean，兩邊就
// 逐字不等：運維把 RECORDING_PATH 寫成 `/var/lib/custodexa/recordings/`（尾斜線是
// 目錄路徑再自然不過的寫法）就足以讓保留期清理**刪得掉檔案、清不掉 DB 欄位**，
// UI 上留下一列「可回放」但檔案已不存在的會話——產品顯示與實際狀態不一致，且沒有
// 任何錯誤訊號。這種不一致的成因不在任一使用點，而在「同一個根有六個各自讀 env 的
// 副本」；把正規化放在使用點等於要求未來每個新使用點都記得做一次，漏一個就重演。
//
// **為什麼住在 recorder 包**：本包已經是錄影落地語義的擁有者（ProbeWritable 用同一組
// 退路探測可寫性、asciicast.go 定義 `{base}/{YYYY-MM-DD}/session-N.cast` 佈局），且它是
// 只依賴標準庫的葉包——組裝根（cmd/server）、圖形代理（internal/proxy）、SSH 代理
// （internal/sshproxy）與 session 模組都能直接引用而不產生環或新的架構邊。
func ResolveBasePath(basePath string) string {
	if basePath == "" {
		basePath = os.Getenv("RECORDING_PATH")
	}
	if basePath == "" {
		basePath = DefaultBasePath
	}
	return filepath.Clean(basePath)
}

// GraphicsRecordingPath 圖形協議（RDP/VNC）錄影的最終落檔路徑。
//
// 圖形錄影由 guacd 直接寫在錄影根**根層**、沒有日期子目錄，會話結束後由後端更名為
// session-N.guac（internal/proxy/handler.go）——這個字串同時是存進
// sessions.recording_path 的值，故與刪除端的 Walk 結果必須逐字相同，路徑組裝因此不得
// 用字串拼接。佈局知識與文字錄影的 `.cast` 佈局同住本包，新增協議時只有一處要看。
func GraphicsRecordingPath(basePath string, sessionID uint) string {
	return filepath.Join(ResolveBasePath(basePath), fmt.Sprintf("session-%d.guac", sessionID))
}

// GraphicsTempRecordingPath guacd 在會話進行中寫入的暫存錄影路徑（`<protocol>-<nanos>`，
// 無副檔名）。與 GraphicsRecordingPath 共用同一個正規化過的根，確保「更名前找得到檔案」
// 與「更名後寫進 DB 的路徑」出自同一組字串規則。
func GraphicsTempRecordingPath(basePath, recordingName string) string {
	return filepath.Join(ResolveBasePath(basePath), recordingName)
}
