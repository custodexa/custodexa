package audit_test

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/modules/session"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 證據包遇讀不到的錄影：照常完成，manifest 逐筆揭露略過的會話與原因。
//
// 外部測試包：用**真的**錄影服務（session 模組）與真的檔案系統，讓「缺檔」「路徑是目錄」
// 走到正式的判定與開檔路徑；包內測試 import session 會成環，故放在 audit_test。

type noDailyReviews struct{}

func (noDailyReviews) DailyReviewLedger(*time.Time, *time.Time, int) ([]policy.SignoffDay, int, bool, error) {
	return []policy.SignoffDay{}, 0, false, nil
}

type skippedEnv struct {
	svc     *audit.AuditExportService
	signer  *keyvault.ExportSigningService
	ids     map[string]uint
	readTxt []byte
}

func setupSkippedEnv(t *testing.T, kinds ...string) *skippedEnv {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql.DB: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })

	if err := db.Exec(`CREATE TABLE session_commands (
		id INTEGER PRIMARY KEY AUTOINCREMENT, session_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
		asset_id INTEGER, command TEXT NOT NULL, seq INTEGER NOT NULL, executed_at DATETIME NOT NULL,
		degraded BOOLEAN NOT NULL DEFAULT 0, degrade_reason TEXT NOT NULL DEFAULT '',
		event_id TEXT NOT NULL DEFAULT '', target_database TEXT NOT NULL DEFAULT '',
		result_status TEXT NOT NULL DEFAULT '', result_reason TEXT NOT NULL DEFAULT '',
		result_rows BIGINT, rows_affected BIGINT, result_sets INTEGER,
		error_code TEXT NOT NULL DEFAULT '', duration_ms INTEGER,
		result_truncated BOOLEAN NOT NULL DEFAULT 0,
		tx_state_after TEXT NOT NULL DEFAULT '')`).Error; err != nil {
		t.Fatalf("create session_commands: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.Asset{}, &model.Session{}, &model.AuditLog{},
		&model.ClipboardEvent{}, &model.UserRole{}, &model.AgentToolCall{},
		&model.ExportSigningKey{}, &model.DataKey{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	dir := t.TempDir()
	env := &skippedEnv{ids: map[string]uint{}, readTxt: []byte(`{"version":2}` + "\n" + `[0.1,"o","ok"]` + "\n")}
	for i, kind := range kinds {
		path := filepath.Join(dir, kind+".cast")
		switch kind {
		case "readable":
			if err := os.WriteFile(path, env.readTxt, 0o600); err != nil {
				t.Fatal(err)
			}
		case "missing":
		case "directory":
			if err := os.Mkdir(path, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		sess := model.Session{SessionID: "s-" + kind, UserID: 1, Protocol: model.ProtocolSSH,
			Status: model.SessionStatusClosed, StartTime: time.Now().Add(-time.Duration(i) * time.Minute),
			HasRecording: true, RecordingPath: path}
		if err := db.Create(&sess).Error; err != nil {
			t.Fatalf("seed session: %v", err)
		}
		env.ids[kind] = sess.ID
	}

	auditSvc := audit.NewAuditLogService(&config.FeatureFlags{AuditLogEnabled: true})
	env.svc = audit.NewAuditExportService(db, auditSvc, audit.NewSessionCommandService(db),
		session.NewRecordingService(dir))
	env.svc.SetDailyReviewLedger(noDailyReviews{})

	key := make([]byte, 32)
	for i := range key {
		key[i] = 7
	}
	kek, err := crypto.NewEnvKEKProvider(key)
	if err != nil {
		t.Fatalf("kek: %v", err)
	}
	km, err := keyvault.InitKeyManager(db, kek)
	if err != nil {
		t.Fatalf("key manager: %v", err)
	}
	env.signer, err = keyvault.NewExportSigningService(db, km)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	env.svc.SetSigning(env.signer)
	return env
}

func (e *skippedEnv) export(t *testing.T, types ...audit.TimelineEventType) map[string][]byte {
	t.Helper()
	var buf bytes.Buffer
	uid := uint(1)
	if _, err := e.svc.Export(&buf, &audit.ExportFilter{UserID: &uid, Types: types}, 9, "auditor1"); err != nil {
		t.Fatalf("匯出應成功（讀不到的錄影略過、不阻斷整包），實得 %v", err)
	}
	// 實際以 archive/zip 打開產物
	r, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("產物不是合法 ZIP: %v", err)
	}
	out := map[string][]byte{}
	for _, f := range r.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open %s: %v", f.Name, err)
		}
		b, _ := io.ReadAll(rc)
		rc.Close()
		out[f.Name] = b
	}
	return out
}

func recordingEntries(files map[string][]byte) []string {
	var names []string
	for name := range files {
		if strings.HasPrefix(name, "recordings/") {
			names = append(names, name)
		}
	}
	return names
}

// TestExportBundleListsSkippedRecordings 可讀、缺檔、路徑為目錄三會話：
// 只收可讀那一檔，manifest 恰列兩筆略過，原因正確且不含路徑或錯誤字樣；簽章驗證通過。
func TestExportBundleListsSkippedRecordings(t *testing.T) {
	env := setupSkippedEnv(t, "readable", "missing", "directory")
	files := env.export(t, audit.TimelineTypeSession)

	recs := recordingEntries(files)
	if len(recs) != 1 || !bytes.Equal(files[recs[0]], env.readTxt) {
		t.Fatalf("recordings/ 應只有可讀那一檔，實得 %v", recs)
	}

	raw := files["manifest.json"]
	var m struct {
		SkippedRecordings []struct {
			SessionID uint   `json:"session_id"`
			Reason    string `json:"reason"`
		} `json:"skipped_recordings"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("manifest.json 不可解析: %v", err)
	}
	got := map[uint]string{}
	for _, s := range m.SkippedRecordings {
		got[s.SessionID] = s.Reason
	}
	if len(m.SkippedRecordings) != 2 || got[env.ids["missing"]] != "missing" || got[env.ids["directory"]] != "unreadable" {
		t.Fatalf("skipped_recordings 應恰兩筆（缺檔→missing、目錄→unreadable），實得 %+v", m.SkippedRecordings)
	}
	var section struct {
		SkippedRecordings json.RawMessage `json:"skipped_recordings"`
	}
	_ = json.Unmarshal(raw, &section)
	for _, leak := range []string{".cast", "/", "directory", "no such file", "錄影檔", "錄製檔案"} {
		if strings.Contains(string(section.SkippedRecordings), leak) {
			t.Errorf("略過清單不得含路徑或錯誤字樣，命中 %q：%s", leak, section.SkippedRecordings)
		}
	}

	sig, ok := files["manifest.sig"]
	if !ok {
		t.Fatal("簽章開啟時應有 manifest.sig")
	}
	if !env.signer.VerifySignature(raw, string(sig)) {
		t.Error("manifest 簽章驗證應通過（略過清單在簽章涵蓋內）")
	}
}

// TestExportBundleSkippedRecordingsEmptyWhenAllReadable 全部可讀：欄位在、為空陣列。
func TestExportBundleSkippedRecordingsEmptyWhenAllReadable(t *testing.T) {
	env := setupSkippedEnv(t, "readable")
	files := env.export(t, audit.TimelineTypeSession)
	var m map[string]json.RawMessage
	if err := json.Unmarshal(files["manifest.json"], &m); err != nil {
		t.Fatal(err)
	}
	if v, ok := m["skipped_recordings"]; !ok || string(v) != "[]" {
		t.Fatalf("全部可讀時 skipped_recordings 應為空陣列，實得 %q（存在=%v）", v, ok)
	}
}

// TestExportBundleSkippedRecordingsAbsentWithoutSessionType 未選會話類別：無此鍵。
func TestExportBundleSkippedRecordingsAbsentWithoutSessionType(t *testing.T) {
	env := setupSkippedEnv(t, "missing")
	files := env.export(t, audit.TimelineTypeAuditLog)
	var m map[string]json.RawMessage
	if err := json.Unmarshal(files["manifest.json"], &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["skipped_recordings"]; ok {
		t.Fatal("未選會話類別時 manifest 不得帶 skipped_recordings")
	}
}
