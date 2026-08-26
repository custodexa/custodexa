package model

import "time"

// 剪貼簿內容狀態。
//
// **明確欄位，不以密文為空或長度為零推斷**：呈現端必須分得出
// 「內容可調閱」與「內容留存失敗（缺口）」——後者是加密失敗時留下的
// 缺口紀錄（事實齊、內容缺、失敗標記），使「此類永不清除、空白即無事件」
// 的誠實宣稱不被靜默缺口打破。
const (
	// ClipboardContentAvailable 內容已加密落庫，可經單筆調閱端點解密取得
	ClipboardContentAvailable = "available"
	// ClipboardContentFailed 內容留存失敗（缺口紀錄）：僅事實欄位可用，
	// 內容欄恆空。值域刻意收斂為單一失敗態——失敗細節屬內部診斷（log），
	// 不進對外契約
	ClipboardContentFailed = "failed"
)

// ClipboardEvent RDP/VNC 剪貼簿內容留存（clipboard-audit）。
//
// **內容以信封加密儲存**：明文欄已移除，
// ContentEnc 為 `enc:a1` 密文（AAD 綁 clipboard_events|content_enc，登記於
// keyvault.RefClipboardContent 與 envelopeMigrationTargets）。ContentLength 於
// 寫入時以明文位元組長度計（與 64KB 截斷上限同單位）——長度是事實非機密，
// 供列表與匯出陳述使用。
type ClipboardEvent struct {
	ID        uint   `gorm:"primarykey" json:"id"`
	SessionID uint   `gorm:"index;not null" json:"session_id"`
	Direction string `gorm:"size:8;not null" json:"direction"` // send=入遠端, recv=回拷
	// ContentEnc 信封加密密文；缺口紀錄（ContentStatus=failed）恆為空字串。
	// json:"-"：內容僅經單筆調閱端點（逐筆留痕）與證據包（匯出留痕）取得，
	// 任何 model 直接序列化的路徑都不得帶出本欄
	ContentEnc    string    `gorm:"type:text" json:"-"`
	ContentLength int       `gorm:"not null" json:"content_length"`
	ContentStatus string    `gorm:"size:16;not null" json:"content_status"`
	CreatedAt     time.Time `json:"created_at"`
}

// TableName 顯式表名：content_enc 登記於 envelopeMigrationTargets，
// 引用掃描守衛（TestEnvelopeTargetsCoverAllEncryptedColumns）要求帶密文欄的
// 結構具備可靜態解析的表名
func (ClipboardEvent) TableName() string {
	return "clipboard_events"
}
