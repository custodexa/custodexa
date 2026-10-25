package session

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/audit/port"
)

type failingTxSink struct{}

func (failingTxSink) WriteInTx(*gorm.DB, port.AuditEvent) error {
	return errors.New("注入審計失敗")
}

type failingAlertSink struct{}

func (failingAlertSink) RaiseInTx(*gorm.DB, port.SystemAlertEvent) (port.SystemAlertReceipt, error) {
	return port.SystemAlertReceipt{}, errors.New("注入告警失敗")
}

type recordingDeleteEnv struct {
	db  *gorm.DB
	svc *RecordingService
	dir string
}

func newRecordingDeleteEnv(t *testing.T) *recordingDeleteEnv {
	t.Helper()
	dir := t.TempDir()
	db, err := gorm.Open(sqlite.Open(filepath.Join(dir, "rec.db")), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&model.Session{}, &model.AuditLog{}, &model.CommandAlert{}, &model.NotificationChannel{},
		&model.SystemAlertDetail{}, &model.SystemAlertOutbox{}, &model.SystemAlertSeverityOverride{}); err != nil {
		t.Fatal(err)
	}
	prev := database.DB
	database.DB = db
	t.Cleanup(func() {
		database.DB = prev
		if s, err := db.DB(); err == nil {
			_ = s.Close()
		}
	})
	svc := NewRecordingService(filepath.Join(dir, "recordings"))
	svc.SetEvidenceSinks(audit.NewTxSink(), audit.NewSystemAlertSink(nil))
	return &recordingDeleteEnv{db: db, svc: svc, dir: dir}
}

func (e *recordingDeleteEnv) seed(t *testing.T, id uint, withFile bool) string {
	t.Helper()
	path := ""
	if withFile {
		path = filepath.Join(e.dir, "rec-"+string(rune('a'+id%26))+".cast")
		if err := os.WriteFile(path, []byte("cast"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.db.Create(&model.Session{ID: id, SessionID: "s", UserID: 1, Status: "closed",
		RecordingPath: path, RecordingSize: 4, HasRecording: withFile}).Error; err != nil {
		t.Fatal(err)
	}
	return path
}

func (e *recordingDeleteEnv) counts(t *testing.T) (audits, alerts int64) {
	t.Helper()
	e.db.Model(&model.AuditLog{}).Where("resource = ?", string(model.ResourceRecording)).Count(&audits)
	e.db.Model(&model.SystemAlertDetail{}).Where("alert_type = ?", string(port.SystemAlertRecordingDeleted)).Count(&alerts)
	return
}

func (e *recordingDeleteEnv) session(t *testing.T, id uint) model.Session {
	t.Helper()
	var s model.Session
	if err := e.db.First(&s, id).Error; err != nil {
		t.Fatal(err)
	}
	return s
}

var testDeleteActor = RecordingDeleteActor{ID: 7, Name: "sec-admin", ClientIP: "198.51.100.7"}

// TestRecordingDeleteAuditFirst 擋：刪錄影先刪檔後留痕、審計或告警失敗卻已刪檔、
// 告警與審計的關聯識別或操作者對不上、缺操作者或缺落地面時仍刪除、審計受總開關影響，
// 以及提交後刪檔失敗時沒有補記失敗審計。
func TestRecordingDeleteAuditFirst(t *testing.T) {
	t.Run("成功：一筆審計、一筆告警，關聯識別與操作者一致，欄位清空、檔案不存在", func(t *testing.T) {
		e := newRecordingDeleteEnv(t)
		path := e.seed(t, 20, true)
		if err := e.svc.DeleteRecording(20, testDeleteActor); err != nil {
			t.Fatal(err)
		}
		var rows []model.AuditLog
		e.db.Where("resource = ?", string(model.ResourceRecording)).Find(&rows)
		var al []model.SystemAlertDetail
		e.db.Where("alert_type = ?", string(port.SystemAlertRecordingDeleted)).Find(&al)
		if len(rows) != 1 || len(al) != 1 {
			t.Fatalf("審計 %d／告警 %d，want 1／1", len(rows), len(al))
		}
		d := map[string]any{}
		_ = json.Unmarshal([]byte(rows[0].Details), &d)
		if d["correlation_id"] != al[0].CorrelationID || al[0].CorrelationID == "" {
			t.Fatalf("關聯識別不同: %v vs %s", d["correlation_id"], al[0].CorrelationID)
		}
		var cmd model.CommandAlert
		e.db.First(&cmd, al[0].AlertID)
		if rows[0].UserID != 7 || rows[0].Username != "sec-admin" || rows[0].ClientIP != "198.51.100.7" || cmd.UserID != 7 {
			t.Fatalf("操作者不符: audit=%d/%s/%s alert=%d", rows[0].UserID, rows[0].Username, rows[0].ClientIP, cmd.UserID)
		}
		if s := e.session(t, 20); s.RecordingPath != "" || s.HasRecording || s.RecordingSize != 0 {
			t.Fatalf("錄影欄未清空: %+v", s)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("檔案仍在")
		}
	})

	t.Run("注入審計或告警失敗：檔案仍在、錄影欄不變", func(t *testing.T) {
		for _, inject := range []string{"audit", "alert"} {
			e := newRecordingDeleteEnv(t)
			path := e.seed(t, 21, true)
			if inject == "audit" {
				e.svc.SetEvidenceSinks(failingTxSink{}, audit.NewSystemAlertSink(nil))
			} else {
				e.svc.SetEvidenceSinks(audit.NewTxSink(), failingAlertSink{})
			}
			if err := e.svc.DeleteRecording(21, testDeleteActor); err == nil {
				t.Fatalf("注入 %s 失敗應回錯", inject)
			}
			if _, err := os.Stat(path); err != nil {
				t.Fatalf("注入 %s 失敗後檔案不見了", inject)
			}
			if s := e.session(t, 21); s.RecordingPath != path || !s.HasRecording {
				t.Fatalf("注入 %s 失敗後錄影欄被改", inject)
			}
		}
	})

	t.Run("操作者 ID 為 0：回錯、0 筆審計與告警、檔案與欄位不變", func(t *testing.T) {
		e := newRecordingDeleteEnv(t)
		path := e.seed(t, 22, true)
		if err := e.svc.DeleteRecording(22, RecordingDeleteActor{Name: "x"}); !errors.Is(err, ErrRecordingDeleteActorMissing) {
			t.Fatalf("應回缺操作者，得 %v", err)
		}
		if a, al := e.counts(t); a != 0 || al != 0 {
			t.Fatalf("不得有審計或告警：%d／%d", a, al)
		}
		if _, err := os.Stat(path); err != nil || e.session(t, 22).RecordingPath != path {
			t.Fatal("檔案或欄位被動")
		}
	})

	t.Run("審計日誌總開關關閉、政策為出廠值時審計仍寫入", func(t *testing.T) {
		t.Setenv("FEATURE_AUDIT_LOG_ENABLED", "false")
		e := newRecordingDeleteEnv(t)
		e.seed(t, 23, true)
		if err := e.svc.DeleteRecording(23, testDeleteActor); err != nil {
			t.Fatal(err)
		}
		if a, _ := e.counts(t); a != 1 {
			t.Fatalf("審計 %d 筆，want 1（交易內落地面不受總開關影響）", a)
		}
	})

	t.Run("提交後檔案移除被拒：資料庫已清空、回錯、檔案仍在，補一筆失敗審計", func(t *testing.T) {
		e := newRecordingDeleteEnv(t)
		// 非空目錄當錄影路徑：任何身分執行都移除不了，模擬提交後刪檔失敗
		stuck := filepath.Join(e.dir, "stuck.cast")
		if err := os.MkdirAll(filepath.Join(stuck, "inner"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := e.db.Create(&model.Session{ID: 24, SessionID: "s", UserID: 1, Status: "closed",
			RecordingPath: stuck, RecordingSize: 4, HasRecording: true}).Error; err != nil {
			t.Fatal(err)
		}
		err := e.svc.DeleteRecording(24, testDeleteActor)
		if !errors.Is(err, ErrRecordingFileRemove) {
			t.Fatalf("應回檔案移除失敗，得 %v", err)
		}
		if s := e.session(t, 24); s.RecordingPath != "" {
			t.Fatal("資料庫應已清空")
		}
		if _, err := os.Stat(stuck); err != nil {
			t.Fatal("檔案應仍在")
		}
		var rows []model.AuditLog
		e.db.Where("resource = ?", string(model.ResourceRecording)).Order("id").Find(&rows)
		if len(rows) != 2 || rows[1].Status != model.StatusFailure {
			t.Fatalf("應有成功列與失敗列各一，得 %d 列", len(rows))
		}
		ok, fail := map[string]any{}, map[string]any{}
		_ = json.Unmarshal([]byte(rows[0].Details), &ok)
		_ = json.Unmarshal([]byte(rows[1].Details), &fail)
		if fail["reason"] != "file_remove_failed" || fail["correlation_id"] != ok["correlation_id"] {
			t.Fatalf("失敗審計 details 不符: %v", fail)
		}
	})

	t.Run("無錄影與不存在的會話回既有碼、0 筆審計", func(t *testing.T) {
		e := newRecordingDeleteEnv(t)
		e.seed(t, 25, false)
		if err := e.svc.DeleteRecording(25, testDeleteActor); !errors.Is(err, ErrSessionHasNoRecording) {
			t.Fatalf("無錄影應回 ErrSessionHasNoRecording，得 %v", err)
		}
		if err := e.svc.DeleteRecording(9999, testDeleteActor); !errors.Is(err, ErrSessionNotFound) {
			t.Fatalf("不存在應回 ErrSessionNotFound，得 %v", err)
		}
		if a, _ := e.counts(t); a != 0 {
			t.Fatalf("不得有審計，得 %d", a)
		}
	})

	t.Run("落地面未注入：回錯且不動", func(t *testing.T) {
		e := newRecordingDeleteEnv(t)
		path := e.seed(t, 26, true)
		e.svc.SetEvidenceSinks(nil, audit.NewSystemAlertSink(nil))
		if err := e.svc.DeleteRecording(26, testDeleteActor); !errors.Is(err, port.ErrTxSinkMissing) {
			t.Fatalf("缺審計落地面應回 ErrTxSinkMissing，得 %v", err)
		}
		e.svc.SetEvidenceSinks(audit.NewTxSink(), nil)
		if err := e.svc.DeleteRecording(26, testDeleteActor); !errors.Is(err, port.ErrSystemAlertSinkMissing) {
			t.Fatalf("缺告警落地面應回錯，得 %v", err)
		}
		if _, err := os.Stat(path); err != nil || e.session(t, 26).RecordingPath != path {
			t.Fatal("檔案或欄位被動")
		}
	})
}
