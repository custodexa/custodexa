package model

import "time"

// 降級原因機器碼。
//
// 定位與 audit_failure.go 的 `Cause*` 常數同一慣例：**碼是權威表述**，
// 三語散文由前端按碼查譯，值即 DB 與前端契約，改值等同 migration。
//
// 兩個值域，以 `SessionCommand.Degraded` 區分，**刻意不合併**：
//   - Degraded=true  → 該輪**沒有可信的指令文字**，Command 必為空（DB CHECK 釘死）。
//     此時 DegradeReason 取下列 `Degrade*` 之一。
//   - Degraded=false 且 DegradeReason 非空 → **文字已入庫、但可能不等於實際執行的指令**。
//     此時 DegradeReason 取下列 `Qualify*` 之一。
//
// 合併兩者會讓「Degraded=false ⇒ 文字可信」變成假話——那是另一種捏造。
const (
	// DegradeAltScreen 當輪落在 alternate screen 標記區間內：回顯是全螢幕程式畫的，
	// 不是 shell 的指令回顯。此時任何錨都可能只是巧合對上，故一律不發指令文字。
	DegradeAltScreen = "altscreen_round"
	// DegradeRedrawUnanchored 當輪的重組螢幕出現全螢幕重繪或跨列，且錨全部落空：
	// 手上沒有任何證據把螢幕上那一行綁回使用者的輸入，發出去即是捏造。
	DegradeRedrawUnanchored = "redraw_unanchored"
	// DegradeFullScreenInput 重放輪未能在輸出中定位自身回顯，且當輪為全螢幕重繪：
	// 那些按鍵是餵給全螢幕程式的，以輸入位元組結算會記下從未當成指令執行的字串。
	DegradeFullScreenInput = "fullscreen_input"
	// DegradeQueueDiscarded 當輪判定為全螢幕重繪時，仍排在重放佇列中的輸入一併丟棄。
	// 列數＝佇列中的 Enter 數（計數，不是猜測）。
	DegradeQueueDiscarded = "queue_discarded"
	// DegradeQueueDiscardedAtClose 會話結束時佇列殘留且當輪為全螢幕重繪。同上計數。
	DegradeQueueDiscardedAtClose = "queue_discarded_at_close"
	// DegradeQueueUncounted 同上兩者，但本連線的重放佇列曾達上限——
	// 佇列裡的 Enter 數只是**下界**，真實輪數不可知。
	// **UI 與 spec SHALL NOT 宣稱該區段的輪數正確。**
	DegradeQueueUncounted = "queue_uncounted"
	// DegradeQueueOverflow 重放佇列達上限，其後抵達的輸入不再排隊。
	// 一筆＝一次溢出的起點，不代表其後只有一輪。
	DegradeQueueOverflow = "queue_overflow"
	// DegradeNoEcho 該輪收到過實質輸入位元組，但輸出流重組不出任何文字。
	//
	// 典型成因是**對端關閉回顯**（`stty -echo`、密碼提示）；虛擬螢幕觸及記憶體
	// 上限而丟棄內容時同樣落在此碼。兩者的共同事實是「這一輪沒有可還原的文字」，
	// **UI 文案 SHALL 描述該事實、SHALL NOT 斷言成因**。
	//
	// **關閉回顯這一類連錄影都救不回**：asciicast 只有輸出方向的 "o" 事件，
	// 回顯關掉就沒有輸出，回放看到的是一片空白。故必須留下紀錄。
	// **絕不回填輸入位元組**——記錄按鍵內容是獨立能力（獨立資料流、獨立加密、
	// 查看須留痕且填理由），有自己的使用者裁決，不在本 change 的射程內。
	DegradeNoEcho = "input_without_echo"

	// QualifyReplayFallback 重放輪未能在輸出中定位自身回顯，改以使用者送出的
	// 輸入位元組結算：文字是使用者確實送出的位元組，**但 tab 補全與歷史鍵的
	// 實際執行內容只存在於回顯中**，故可能不等於實際執行的指令。
	QualifyReplayFallback = "replay_input_bytes"
)

// SessionCommand SSH 會話指令記錄
// 由 proxy 端重組 client→guacd 的 key instruction 而來（command-audit）
// user_id/asset_id 為冗餘欄位：跨會話搜尋不需 JOIN sessions
// 注意：本表由 migration v7.8 以原生 SQL 建立，不走 AutoMigrate，
// 欄位定義需與 migration 保持一致
type SessionCommand struct {
	ID        uint  `gorm:"primarykey" json:"id"`
	SessionID uint  `gorm:"not null" json:"session_id"`
	UserID    uint  `gorm:"not null" json:"user_id"`
	AssetID   *uint `json:"asset_id,omitempty"` // 手動連線可能無資產 ID，與 sessions.asset_id 一致為 nullable

	Command    string    `gorm:"type:text;not null" json:"command"`
	Seq        int       `gorm:"not null" json:"seq"` // 會話內執行順序（從 1 開始）
	ExecutedAt time.Time `gorm:"type:timestamptz;not null" json:"executed_at"`

	// Degraded 該輪的指令文字無法可信重組。
	//
	// 為真時 Command **必為空**，且此不變式由 baseline 的
	// `CHECK (NOT degraded OR command = '')` 在 DB 層釘死而非靠約定——
	// 「降級紀錄 SHALL NOT 包含推測的指令文字」是規格條文，
	// 捏造比漏記更嚴重，不該掛在任何一段可被繞過的應用層程式碼上。
	//
	// **為假不代表文字必然可信**：偵測判準（vtscreen.Redrawn／跨列）是充分條件
	// 而非必要條件，存在不觸發判準卻仍捏造的形態。UI SHALL NOT 把「無降級標記」
	// 呈現為「內容已驗證」。
	Degraded bool `gorm:"not null;default:false" json:"degraded"`
	// DegradeReason 降級／限定的機器碼，值域見本檔 Degrade*／Qualify* 常數。
	// Degraded 為真時取 Degrade*；為假而本欄非空時取 Qualify*（文字受限定）。
	DegradeReason string `gorm:"size:64;not null;default:''" json:"degrade_reason"`

	// K8s 冗餘欄（k8s-exec）：當次選定 pod/container，跨會話搜尋免 JOIN sessions
	K8sPod       string `gorm:"size:253" json:"k8s_pod,omitempty"`
	K8sContainer string `gorm:"size:63" json:"k8s_container,omitempty"`
}

// TableName 指定表名
func (SessionCommand) TableName() string {
	return "session_commands"
}
