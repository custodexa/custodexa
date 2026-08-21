package proxy

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"unicode/utf8"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"github.com/custodexa/backend/pkg/guacamole"
	"gorm.io/gorm"
)

// fileAuditMaxName 檔名留存上限（防異常長路徑撐爆審計欄）
const fileAuditMaxName = 512

// truncateAuditName 依 **rune 邊界**截斷檔名至 fileAuditMaxName 位元組以內。
//
// **原本是 `name[:fileAuditMaxName]` 的位元組切片**，會把多位元組字元從中間切開：
// 512 % 3 == 2，故中文檔名恰好在第 171 個字的中間斷裂，產生無效 UTF-8。
// 後果不是顯示難看而已——Postgres 直接拒收
// （`invalid byte sequence for encoding "UTF8"`），而審計寫入是 **fail-open**
// （失敗只記 log、不回壓會話），於是**檔案照常轉發、那筆留痕靜默消失**。
// 客戶端只要用一個夠長的中文檔名就能規避檔案傳輸審計。
//
// 這條路徑在協議長度前綴改用 codepoint 之前是走不到的——中文檔名的指令
// 那時根本解不出來就被丟棄了（guacamole-protocol-conformance）。
// 同一個 byte/codepoint 混淆家族，一併修掉。
func truncateAuditName(name string) string {
	if len(name) <= fileAuditMaxName {
		return name
	}
	// 自上限處往前退到最近的 rune 起點，確保切出來的仍是合法 UTF-8
	cut := fileAuditMaxName
	for cut > 0 && !utf8.RuneStart(name[cut]) {
		cut--
	}
	return name[:cut]
}

// guacAckClientForbidden guacamole status CLIENT_FORBIDDEN（0x0303=771）：
// 串流被伺服端政策拒絕。**必須回送**——只丟棄指令會讓客戶端的上傳進度條停在
// 原地無限等待（data-transfer-control 5.3）。前端據此狀態碼查譯三語訊息。
const guacAckClientForbidden = "771"

// TransferDecider 傳輸能力的逐次判定（data-transfer-control D4／5.6）。
//
// **每次呼叫都必須是當下值**，不得是連線建立時的一次性快照：政策改動經既有 30 秒
// 政策快取窗口後即應對進行中連線生效（SFTP 與 file_tap 屬即時層）。
// nil＝不判定（既有測試路徑，一律放行，行為與改動前一致）。
type TransferDecider func(action string) bool

// FileTapVerdict FileTap 對單一指令的處置。
//
// **零值是「不轉發」**，這是刻意的：新增分支忘了設 Forward 的失敗方向是擋住而非放行。
// 呼叫端（tunnel）SHALL 先回送 Ack（若有）再依 Forward 決定是否轉發。
type FileTapVerdict struct {
	Forward bool
	// Ack 非 nil 時 SHALL 回送給客戶端（WS 側），使其不無限等待
	Ack *guacamole.Instruction
}

// forward 放行的 verdict（多數指令的結果）
var fileTapForward = FileTapVerdict{Forward: true}

// FileTap 重組 guacamole 檔案傳輸流、寫審計並執行資料傳輸管控
// （vnc-file-transfer 審計＋data-transfer-control 強制；同時涵蓋 RDP 磁碟與
// VNC SFTP 兩條 guac 圖形通道）。比照 ClipboardTap 攔 put/blob/end 指令，
// 只記元資料（檔名＋大小），不留檔案內容；入庫失敗不影響會話。
// 掛在 client→guacd 方向（上傳 put，以及客戶端主動觸發的下載 get）。
//
// **這是 guac 通道的主強制點**，guacd 的 disable-upload／sftp-disable-* 參數是縱深
// （D3 註 3）：guacd 版本一換，只靠參數的控制就消失了。
type FileTap struct {
	db *gorm.DB
	// auditSink 檔案傳輸審計的投遞面（W4 4.6，AP-28）。**刻意是 DirectSink 而非
	// AuditLogService**：本點現況走 db.Create 直寫，從不看 AuditLogEnabled——
	// 接到受開關管制的 sink 上會在開關關閉時新增「留痕消失」行為（見
	// internal/modules/audit/async_sink.go 的 DirectSink 註解）
	auditSink gatewayapi.AsyncSink
	sessionID uint
	userID    uint
	assetID   *uint
	protocol  string
	streams   map[string]*fileUploadStream
	// deniedStreams 已被拒的上傳 stream index 集合（**串流狀態機**，
	// data-transfer-control 5.2）。`put` 擋了但後續 `blob` 照轉＝檔案照樣寫入，
	// 是本組最可能的錯誤；被拒的 stream 其 blob／end 一併丟棄
	deniedStreams map[string]bool
	// decide 逐次能力判定；nil＝不判定（既有測試路徑）
	decide TransferDecider
}

type fileUploadStream struct {
	name string
	size int64
}

// NewFileTap 建立單一連線的檔案傳輸觀察器；db/session 缺失時回傳可安全 no-op 的實例。
// 不帶管控（既有呼叫形態）——管控以 SetDecider 注入。
func NewFileTap(db *gorm.DB, auditSink gatewayapi.AsyncSink, sessionID, userID uint, assetID *uint, protocol string) *FileTap {
	return &FileTap{
		db:            db,
		auditSink:     auditSink,
		sessionID:     sessionID,
		userID:        userID,
		assetID:       assetID,
		protocol:      protocol,
		streams:       make(map[string]*fileUploadStream),
		deniedStreams: make(map[string]bool),
	}
}

// SetDecider 注入逐次能力判定。nil 時 FileTap 維持純觀察（不阻擋任何東西）。
func (t *FileTap) SetDecider(d TransferDecider) {
	if t == nil {
		return
	}
	t.decide = d
}

// allows 單動作判定；未注入 decider 時一律放行
func (t *FileTap) allows(action string) bool {
	if t.decide == nil {
		return true
	}
	return t.decide(action)
}

// via 依協議標記上傳通道（審計可讀）
func (t *FileTap) via() string {
	if t.protocol == "rdp" {
		return "guac-drive"
	}
	return "guac-sftp"
}

// Observe 觀察一條指令並回傳處置；非檔案傳輸相關指令一律放行。
//
// guac filesystem 上傳序列：put[object,stream,mimetype,name] → blob[stream,data]… → end[stream]
// 下載觸發：get[object_index, name]（guacd 回 body 開串流）。
//
// **能力判定每個 put／get 至多一次**（5.7）：判定結果登記在 stream 狀態上，
// 後續 blob／end 只查表不重查政策。
func (t *FileTap) Observe(inst *guacamole.Instruction) FileTapVerdict {
	if t == nil || t.db == nil || t.sessionID == 0 {
		return fileTapForward
	}
	switch inst.Opcode {
	case "put":
		// args: [object_index, stream_index, mimetype, name]
		if len(inst.Args) < 4 {
			return fileTapForward
		}
		streamIdx := inst.Args[1]
		name := truncateAuditName(inst.Args[3])
		if !t.allows(policy.TransferActionFileUpload) {
			// 登記為被拒 stream：後續 blob／end 一併丟棄（串流狀態機）
			t.deniedStreams[streamIdx] = true
			delete(t.streams, streamIdx)
			// 拒絕留痕：大小為 0（未收 blob）
			t.recordDenied(model.ActionFileUpload, name, 0)
			return FileTapVerdict{
				Forward: false,
				Ack: &guacamole.Instruction{
					Opcode: "ack",
					Args:   []string{streamIdx, "transfer denied by policy", guacAckClientForbidden},
				},
			}
		}
		delete(t.deniedStreams, streamIdx)
		t.streams[streamIdx] = &fileUploadStream{name: name}
		return fileTapForward
	case "blob":
		// args: [stream_index, base64data]——只累加大小，不留內容
		if len(inst.Args) < 2 {
			return fileTapForward
		}
		streamIdx := inst.Args[0]
		if t.deniedStreams[streamIdx] {
			// **本組最可能的錯誤在此**：put 擋了但 blob 照轉＝檔案照樣寫入
			return FileTapVerdict{Forward: false}
		}
		s, ok := t.streams[streamIdx]
		if !ok {
			return fileTapForward
		}
		data, err := base64.StdEncoding.DecodeString(inst.Args[1])
		if err != nil {
			return fileTapForward
		}
		s.size += int64(len(data))
		return fileTapForward
	case "end":
		// args: [stream_index]
		if len(inst.Args) < 1 {
			return fileTapForward
		}
		streamIdx := inst.Args[0]
		if t.deniedStreams[streamIdx] {
			delete(t.deniedStreams, streamIdx)
			return FileTapVerdict{Forward: false}
		}
		s, ok := t.streams[streamIdx]
		if !ok {
			return fileTapForward
		}
		delete(t.streams, streamIdx)
		t.record(s)
		return fileTapForward
	case "get":
		// 下載方向（5.4）：客戶端主動觸發的 filesystem 讀取。
		// args: [object_index, name]。被拒時只丟棄不回 ack——客戶端此時尚未持有
		// stream index（stream 由 guacd 的 body 指令建立），ack 無合法對象可指
		if len(inst.Args) < 2 {
			return fileTapForward
		}
		if !t.allows(policy.TransferActionFileDownload) {
			name := truncateAuditName(inst.Args[1])
			t.recordDenied(model.ActionFileDownload, name, 0)
			return FileTapVerdict{Forward: false}
		}
		return fileTapForward
	}
	return fileTapForward
}

// recordDenied 寫入被拒留痕（data-transfer-control D6）。
//
// **「被拒不留痕」是本題最容易犯的錯**：拒絕分支常直接 return，審計只寫在成功路徑。
// 沒有這一筆，「有沒有人試著把資料帶出去」這個稽核問題就無法回答。
func (t *FileTap) recordDenied(action model.AuditAction, name string, size int64) {
	t.submit(action, model.StatusDenied, name, size)
}

// record 非同步寫入檔案上傳審計（比照 ClipboardTap：失敗僅記 log，不回壓會話）
func (t *FileTap) record(s *fileUploadStream) {
	t.submit(model.ActionFileUpload, model.StatusSuccess, s.name, s.size)
}

// submit 檔案傳輸審計的單一投遞實作（成功與被拒共用，杜絕兩條路徑漂移）
func (t *FileTap) submit(action model.AuditAction, status model.AuditStatus, name string, size int64) {
	db := t.db
	sink := t.auditSink
	sessionID := t.sessionID
	userID := t.userID
	assetID := t.assetID
	via := t.via()
	go func() {
		var username string
		db.Model(&model.User{}).Select("username").Where("id = ?", userID).Scan(&username)
		if username == "" {
			username = fmt.Sprintf("uid:%d", userID)
		}
		if sink == nil {
			log.Printf("[FileTap] 審計投遞面未注入，檔案傳輸留痕已丟失: session=%d action=%s status=%s",
				sessionID, action, status)
			return
		}
		details := fmt.Sprintf(`{"session_id":%d,"size":%d,"via":%q}`, sessionID, size, via)
		if status == model.StatusDenied {
			// 拒絕來源（D6）：期 1 只有全域政策層可能拒絕；期 2 會多出
			// 「無匹配放寬」一種來源，屆時由解析端回傳並填入此欄
			details = fmt.Sprintf(`{"session_id":%d,"size":%d,"via":%q,"reason":"global_policy"}`,
				sessionID, size, via)
		}
		// W4 4.6 收口（AP-28）：改經 AsyncSink，繞過 AuditLogEnabled 分支。
		// 失敗處置維持現況——只記 log、不回壓會話（fail-open，刻意不改）
		if err := sink.Submit(context.Background(), gatewayapi.AuditEvent{
			Action:     string(action),
			Resource:   string(model.ResourceFile),
			ResourceID: assetID,
			// ResourceID 維持既有語義（resource=file 的既有查詢靠它），主體鍵另記：
			// 工作台的檔案傳輸類只讀 asset_id（auditor-workbench D4）
			AssetID: assetID,
			Status:  string(status),
			Actor:   gatewayapi.Actor{UserID: userID, Username: username},
			Request: gatewayapi.RequestMeta{Path: name},
			Details: details,
		}); err != nil {
			log.Printf("[FileTap] 檔案傳輸審計留存失敗: session=%d action=%s err=%v", sessionID, action, err)
		}
	}()
}
