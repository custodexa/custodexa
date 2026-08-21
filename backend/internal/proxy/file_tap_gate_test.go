package proxy

import (
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/pkg/guacamole"
	"gorm.io/gorm"
)

// denyAll 一律拒絕的 decider；calls 記錄實際判定次數（供 5.7 效能防呆斷言）
func denyAll(calls *int) TransferDecider {
	return func(string) bool {
		*calls++
		return false
	}
}

// waitDeniedCount 輪詢等待非同步的 denied 審計入庫
func waitDeniedCount(t *testing.T, db *gorm.DB, action model.AuditAction, want int64) int64 {
	t.Helper()
	var count int64
	for i := 0; i < 50; i++ {
		db.Model(&model.AuditLog{}).
			Where("action = ? AND status = ?", action, model.StatusDenied).Count(&count)
		if count >= want {
			return count
		}
		time.Sleep(20 * time.Millisecond)
	}
	return count
}

// TestFileTapDeniedStreamDropsEveryInstruction **串流狀態機自證（5.2，不得省略）**。
//
// put 被拒後送 3 個 blob 與 1 個 end，斷言**轉發至 guacd 的指令數為 0**。
// `put` 擋了但 `blob` 照轉＝檔案照樣寫入——這是本組最可能的錯誤，只斷言
// 「put 沒被轉發」的測試抓不到它。
//
// 自證：把 Observe 的 blob／end 分支中 `t.deniedStreams[streamIdx]` 的判斷拿掉，
// 本測試必須紅（forwarded 會變成 4）。
func TestFileTapDeniedStreamDropsEveryInstruction(t *testing.T) {
	db := setupFileTapDB(t)
	aid := uint(7)
	tap := NewFileTap(db, audit.NewDirectSink(db), 200, 1, &aid, "rdp")
	calls := 0
	tap.SetDecider(denyAll(&calls))

	seq := []*guacamole.Instruction{
		gi("put", "0", "3", "application/octet-stream", "secret.tar.gz"),
		gi("blob", "3", b64("AAAA")),
		gi("blob", "3", b64("BBBB")),
		gi("blob", "3", b64("CCCC")),
		gi("end", "3"),
	}

	forwarded := 0
	acks := 0
	for _, in := range seq {
		v := tap.Observe(in)
		if v.Ack != nil {
			acks++
			if v.Ack.Opcode != "ack" || len(v.Ack.Args) != 3 || v.Ack.Args[2] != guacAckClientForbidden {
				t.Errorf("拒絕 ack 形狀不符: %+v", v.Ack)
			}
			if v.Ack.Args[0] != "3" {
				t.Errorf("ack stream index = %q, want 3（指錯 stream 客戶端不會收到）", v.Ack.Args[0])
			}
		}
		if v.Forward {
			forwarded++
			t.Errorf("指令 %s 被轉發至 guacd——被拒 stream 的 put／blob／end 應一併丟棄", in.Opcode)
		}
	}

	if forwarded != 0 {
		t.Errorf("轉發至 guacd 的指令數 = %d, want 0", forwarded)
	}
	if acks != 1 {
		t.Errorf("回送客戶端的拒絕 ack 數 = %d, want 1（只在 put 時回一次）", acks)
	}
	// 5.7 效能防呆：判定每個 put 至多一次，blob 不重查
	if calls != 1 {
		t.Errorf("能力判定次數 = %d, want 1（put 一次；blob 重查即熱路徑 N 倍放大）", calls)
	}
	// 5.5 被拒留痕
	if got := waitDeniedCount(t, db, model.ActionFileUpload, 1); got != 1 {
		t.Errorf("denied 的 file_upload 審計筆數 = %d, want 1"+
			"（拒絕不留痕＝「有沒有人試著把資料帶出去」無法回答）", got)
	}
}

// TestFileTapAllowedStreamUnaffected 允許時全序列照轉，且成功審計照舊（零影響）。
func TestFileTapAllowedStreamUnaffected(t *testing.T) {
	db := setupFileTapDB(t)
	aid := uint(7)
	tap := NewFileTap(db, audit.NewDirectSink(db), 201, 1, &aid, "vnc")
	calls := 0
	tap.SetDecider(func(string) bool { calls++; return true })

	seq := []*guacamole.Instruction{
		gi("put", "0", "5", "text/plain", "ok.txt"),
		gi("blob", "5", b64("hello")),
		gi("end", "5"),
	}
	for _, in := range seq {
		v := tap.Observe(in)
		if !v.Forward {
			t.Errorf("允許時指令 %s 竟未轉發", in.Opcode)
		}
		if v.Ack != nil {
			t.Errorf("允許時不該回拒絕 ack: %+v", v.Ack)
		}
	}
	if calls != 1 {
		t.Errorf("能力判定次數 = %d, want 1", calls)
	}
	if got := waitAuditCount(t, db, 1); got != 1 {
		t.Errorf("成功的 file_upload 審計筆數 = %d, want 1", got)
	}
}

// TestFileTapPerPutDecision **逐次判定自證（5.6）**：同一連線內中途改政策，
// 第二次 put 被拒——證明不是連線建立時的一次性快照。
func TestFileTapPerPutDecision(t *testing.T) {
	db := setupFileTapDB(t)
	aid := uint(7)
	tap := NewFileTap(db, audit.NewDirectSink(db), 202, 1, &aid, "rdp")

	allow := true
	tap.SetDecider(func(string) bool { return allow })

	if v := tap.Observe(gi("put", "0", "1", "text/plain", "first.txt")); !v.Forward {
		t.Fatal("第一次 put 應放行")
	}
	_ = tap.Observe(gi("end", "1"))

	// 連線進行中改政策
	allow = false

	if v := tap.Observe(gi("put", "0", "2", "text/plain", "second.txt")); v.Forward {
		t.Error("政策改為禁止後，同一連線的第二次 put 仍被放行" +
			"——判定是連線建立時的一次性快照，不是逐次判定")
	}
}

// TestFileTapDownloadDirection 下載方向攔截（5.4）：客戶端的 get 被判 FileDownload。
func TestFileTapDownloadDirection(t *testing.T) {
	db := setupFileTapDB(t)
	aid := uint(7)
	tap := NewFileTap(db, audit.NewDirectSink(db), 203, 1, &aid, "rdp")

	var seen []string
	tap.SetDecider(func(action string) bool {
		seen = append(seen, action)
		return false
	})

	if v := tap.Observe(gi("get", "0", "/payroll.xlsx")); v.Forward {
		t.Error("file_download 禁止時 get 仍被轉發")
	}
	if len(seen) != 1 || seen[0] != policy.TransferActionFileDownload {
		t.Errorf("get 判定的 action = %v, want [file_download]（判成 upload 等於下載無控制）", seen)
	}
	if got := waitDeniedCount(t, db, model.ActionFileDownload, 1); got != 1 {
		t.Errorf("denied 的 file_download 審計筆數 = %d, want 1", got)
	}
}

// TestFileTapNoDeciderIsPureObserver 未注入 decider 時純觀察（零影響回歸）。
func TestFileTapNoDeciderIsPureObserver(t *testing.T) {
	db := setupFileTapDB(t)
	tap := NewFileTap(db, audit.NewDirectSink(db), 204, 1, nil, "rdp")
	for _, in := range []*guacamole.Instruction{
		gi("put", "0", "9", "text/plain", "x.txt"),
		gi("blob", "9", b64("x")),
		gi("end", "9"),
		gi("get", "0", "/x.txt"),
	} {
		if v := tap.Observe(in); !v.Forward {
			t.Errorf("未注入 decider 時 %s 竟被擋——那是行為變更，非零影響", in.Opcode)
		}
	}
}

// TestFileTapNilVerdictForwards nil／無 session 的 FileTap 一律放行（不得靜默擋線）。
func TestFileTapNilVerdictForwards(t *testing.T) {
	var tap *FileTap
	if v := tap.Observe(gi("put", "0", "1", "text/plain", "a")); !v.Forward {
		t.Error("nil FileTap 應放行")
	}
	empty := &FileTap{}
	if v := empty.Observe(gi("put", "0", "1", "text/plain", "a")); !v.Forward {
		t.Error("無 session 的 FileTap 應放行")
	}
}

// gi 建構 guacamole 指令（本檔專用；clipboard_tap_test.go 已有同名的 inst）
func gi(opcode string, args ...string) *guacamole.Instruction {
	return &guacamole.Instruction{Opcode: opcode, Args: args}
}
