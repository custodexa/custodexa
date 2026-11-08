package proxy

import (
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/pkg/guacamole"
	"gorm.io/gorm"
)

// 圖形通道客戶端開啟上傳串流的兩種指令（put、file）共用同一套判定與留痕：
// 開始紀錄、完成紀錄、斷線時的未完成紀錄。

// uploadRows 取出 file_upload 審計列（依 id 排序）
func uploadRows(db *gorm.DB) []model.AuditLog {
	var rows []model.AuditLog
	db.Where("action = ?", model.ActionFileUpload).Order("id ASC").Find(&rows)
	return rows
}

// waitUploadRows 輪詢等待 file_upload 審計列數達標（審計寫入走 goroutine）
func waitUploadRows(t *testing.T, db *gorm.DB, want int) []model.AuditLog {
	t.Helper()
	var rows []model.AuditLog
	for i := 0; i < 100; i++ {
		rows = uploadRows(db)
		if len(rows) >= want {
			return rows
		}
		time.Sleep(20 * time.Millisecond)
	}
	return rows
}

// byPhase 依 phase 取列（審計寫入各走 goroutine，id 先後不保證與事件先後一致）
func byPhase(rows []model.AuditLog, phase string) (model.AuditLog, bool) {
	for _, r := range rows {
		if phaseOf(r) == phase {
			return r, true
		}
	}
	return model.AuditLog{}, false
}

func phaseOf(r model.AuditLog) string {
	for _, p := range []string{"started", "completed", "incomplete"} {
		if strings.Contains(r.Details, `"phase":"`+p+`"`) {
			return p
		}
	}
	return ""
}

// openStream 依指令種類組出開串流指令：put 帶 object index，file 不帶
func openStream(kind, stream, name string) *guacamole.Instruction {
	if kind == "file" {
		return gi("file", stream, "application/octet-stream", name)
	}
	return gi("put", "0", stream, "application/octet-stream", name)
}

// 政策允許時 file→blob→end：開始與完成兩列，檔名相符，完成列帶累計大小
func TestFileTapFileOpcodeAllowed(t *testing.T) {
	db := setupFileTapDB(t)
	db.Create(&model.User{Username: "alice"})
	aid := uint(7)
	tap := NewFileTap(db, audit.NewDirectSink(db), 300, 1, &aid, "rdp")
	tap.SetDecider(func(string) bool { return true })

	for _, in := range []*guacamole.Instruction{
		gi("file", "4", "text/plain", "report.txt"),
		gi("blob", "4", b64("hello")),
		gi("blob", "4", b64("world")),
		gi("end", "4"),
	} {
		v := tap.Observe(in)
		if !v.Forward || v.Ack != nil {
			t.Fatalf("允許時指令 %s 應直接轉發: %+v", in.Opcode, v)
		}
	}
	rows := waitUploadRows(t, db, 2)
	if len(rows) != 2 {
		t.Fatalf("file_upload 列數 = %d, want 2（開始與完成）", len(rows))
	}
	started, okS := byPhase(rows, "started")
	completed, okC := byPhase(rows, "completed")
	if !okS || !okC {
		t.Fatalf("應各有一筆 started 與 completed: %+v", rows)
	}
	for _, r := range rows {
		if r.Status != model.StatusSuccess || r.Path != "report.txt" {
			t.Errorf("列狀態或檔名不符: status=%s path=%q", r.Status, r.Path)
		}
	}
	if !strings.Contains(completed.Details, `"size":10`) {
		t.Errorf("完成列應含累計大小 10: %s", completed.Details)
	}
	if !strings.Contains(started.Details, `"size":0`) {
		t.Errorf("開始列大小應為 0: %s", started.Details)
	}
	if !strings.Contains(started.Details, `"stream":`) || !strings.Contains(completed.Details, `"stream":`) {
		t.Errorf("兩筆應帶串流識別: %s | %s", started.Details, completed.Details)
	}
}

// 政策拒絕時 file→blob→end：全部不轉發，回非零 ack，留 denied 列且沒有 success 列
func TestFileTapFileOpcodeDenied(t *testing.T) {
	db := setupFileTapDB(t)
	aid := uint(7)
	tap := NewFileTap(db, audit.NewDirectSink(db), 301, 1, &aid, "rdp")
	calls := 0
	tap.SetDecider(denyAll(&calls))

	seq := []*guacamole.Instruction{
		gi("file", "6", "text/plain", "secret.txt"),
		gi("blob", "6", b64("AAAA")),
		gi("blob", "6", b64("BBBB")),
		gi("end", "6"),
	}
	acks := 0
	for _, in := range seq {
		v := tap.Observe(in)
		if v.Forward {
			t.Errorf("被拒串流的 %s 被轉發", in.Opcode)
		}
		if v.Ack != nil {
			acks++
			if v.Ack.Opcode != "ack" || len(v.Ack.Args) != 3 || v.Ack.Args[0] != "6" || v.Ack.Args[2] != guacAckClientForbidden {
				t.Errorf("拒絕 ack 形狀不符: %+v", v.Ack)
			}
		}
	}
	if acks != 1 {
		t.Errorf("拒絕 ack 數 = %d, want 1", acks)
	}
	if calls != 1 {
		t.Errorf("判定次數 = %d, want 1", calls)
	}
	if got := waitDeniedCount(t, db, model.ActionFileUpload, 1); got != 1 {
		t.Fatalf("denied 列數 = %d, want 1", got)
	}
	for _, r := range uploadRows(db) {
		if r.Status == model.StatusSuccess {
			t.Errorf("被拒的上傳不得留 success 列: %s", r.Details)
		}
	}
}

// 會話中途關閉上傳：其後以 file 開的串流被拒
func TestFileTapFileOpcodeMidSessionPolicyChange(t *testing.T) {
	db := setupFileTapDB(t)
	aid := uint(7)
	tap := NewFileTap(db, audit.NewDirectSink(db), 302, 1, &aid, "rdp")
	allow := true
	tap.SetDecider(func(string) bool { return allow })

	if v := tap.Observe(gi("file", "1", "text/plain", "first.txt")); !v.Forward {
		t.Fatal("第一個串流應放行")
	}
	tap.Observe(gi("end", "1"))
	allow = false
	v := tap.Observe(gi("file", "2", "text/plain", "second.txt"))
	if v.Forward || v.Ack == nil {
		t.Fatalf("政策改為拒絕後的新串流應被拒並回 ack: %+v", v)
	}
	if got := waitDeniedCount(t, db, model.ActionFileUpload, 1); got != 1 {
		t.Fatalf("denied 列數 = %d, want 1", got)
	}
}

// 未送 end 即斷線：put 與 file 都要有開始列與一筆 failure、phase=incomplete、含已轉送大小的未完成列
func TestFileTapIncompleteStream(t *testing.T) {
	for _, kind := range []string{"put", "file"} {
		t.Run(kind, func(t *testing.T) {
			db := setupFileTapDB(t)
			aid := uint(7)
			tap := NewFileTap(db, audit.NewDirectSink(db), 310, 1, &aid, "rdp")
			tap.SetDecider(func(string) bool { return true })
			tun := NewTunnel(nil, nil, nil, nil, tap)

			if v := tap.Observe(openStream(kind, "5", "big.iso")); !v.Forward {
				t.Fatal("開串流應放行")
			}
			// 開串流後、送 blob 前即應已有開始列
			if rows := waitUploadRows(t, db, 1); len(rows) != 1 || phaseOf(rows[0]) != "started" {
				t.Fatalf("開串流後應有 started 列，實得 %d 列", len(rows))
			}
			for _, chunk := range []string{"AAAA", "BBBBBB"} {
				if v := tap.Observe(gi("blob", "5", b64(chunk))); !v.Forward {
					t.Fatal("blob 應轉發（下游收到）")
				}
			}
			tun.Close()

			rows := waitUploadRows(t, db, 2)
			if len(rows) != 2 {
				t.Fatalf("Close 後 file_upload 列數 = %d, want 2（started、incomplete）", len(rows))
			}
			last, ok := byPhase(rows, "incomplete")
			if !ok || last.Status != model.StatusFailure {
				t.Fatalf("應有一筆 status=failure 的 incomplete 列: %+v", rows)
			}
			if !strings.Contains(last.Details, `"size":10`) || last.Path != "big.iso" {
				t.Errorf("未完成列應含已轉送大小 10 與檔名: path=%q details=%s", last.Path, last.Details)
			}
			for _, r := range rows {
				if r.Status == model.StatusSuccess && phaseOf(r) != "started" {
					t.Errorf("不得有 success 完成列: %s", r.Details)
				}
			}
			// 重複關閉不重複結算
			tun.Close()
			time.Sleep(100 * time.Millisecond)
			if got := len(uploadRows(db)); got != 2 {
				t.Errorf("重複 Close 後列數 = %d, want 2", got)
			}
		})
	}
}

// 正常送 end 的串流在 Close 後不會多出 incomplete 列
func TestFileTapIncompleteStreamNotAddedAfterEnd(t *testing.T) {
	db := setupFileTapDB(t)
	aid := uint(7)
	tap := NewFileTap(db, audit.NewDirectSink(db), 311, 1, &aid, "rdp")
	tap.SetDecider(func(string) bool { return true })
	tun := NewTunnel(nil, nil, nil, nil, tap)

	tap.Observe(gi("file", "5", "text/plain", "ok.txt"))
	tap.Observe(gi("blob", "5", b64("data")))
	tap.Observe(gi("end", "5"))
	if rows := waitUploadRows(t, db, 2); len(rows) != 2 {
		t.Fatalf("started、completed 兩列未齊: %d", len(rows))
	}
	tun.Close()
	time.Sleep(150 * time.Millisecond)
	rows := uploadRows(db)
	if len(rows) != 2 {
		t.Fatalf("Close 後列數 = %d, want 2", len(rows))
	}
	for _, r := range rows {
		if phaseOf(r) == "incomplete" {
			t.Errorf("已送 end 的串流不應有 incomplete 列")
		}
	}
}

// 上傳完成判準：斷線串流（started＋incomplete）0 筆、正常串流的 completed 與升級前無 phase 的舊列共 2 筆
func TestCompletedUploadCriterion(t *testing.T) {
	db := setupFileTapDB(t)
	mk := func(status model.AuditStatus, details string) {
		if err := db.Create(&model.AuditLog{
			Action: model.ActionFileUpload, Resource: model.ResourceFile, Status: status, Details: details,
		}).Error; err != nil {
			t.Fatalf("建列失敗: %v", err)
		}
	}
	mk(model.StatusSuccess, `{"session_id":1,"size":0,"via":"guac-drive","phase":"started","stream":"1:1"}`)
	mk(model.StatusFailure, `{"session_id":1,"size":10,"via":"guac-drive","phase":"incomplete","stream":"1:1"}`)
	mk(model.StatusSuccess, `{"session_id":1,"size":0,"via":"guac-drive","phase":"started","stream":"2:2"}`)
	mk(model.StatusSuccess, `{"session_id":1,"size":4,"via":"guac-drive","phase":"completed","stream":"2:2"}`)
	mk(model.StatusSuccess, `{"session_id":1,"size":9,"via":"guac-sftp"}`) // 升級前的舊完成列
	mk(model.StatusDenied, `{"session_id":1,"size":0,"via":"guac-drive","reason":"global_policy"}`)
	// details 為空字串的舊列（NULL 防護）
	mk(model.StatusSuccess, ``)

	var ids []uint
	if err := db.Model(&model.AuditLog{}).Scopes(model.ScopeCompletedFileUpload).Order("id ASC").Pluck("id", &ids).Error; err != nil {
		t.Fatalf("查詢失敗: %v", err)
	}
	// 完成列（id 4）、舊列（id 5）、空 details 的舊列（id 7）
	want := []uint{4, 5, 7}
	if len(ids) != len(want) {
		t.Fatalf("完成列 = %v, want %v", ids, want)
	}
	for i := range want {
		if ids[i] != want[i] {
			t.Fatalf("完成列 = %v, want %v", ids, want)
		}
	}
}
