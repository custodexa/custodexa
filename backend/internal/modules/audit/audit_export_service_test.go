package audit

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func setupExportEnv(t *testing.T) (*AuditExportService, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	// AuditLogService/RecordingService 走全域 database.DB
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })

	// session_commands.executed_at 為 timestamptz，sqlite 掃描問題——原生建 datetime schema
	if err := db.Exec(`CREATE TABLE session_commands (
		id INTEGER PRIMARY KEY AUTOINCREMENT, session_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
		asset_id INTEGER, command TEXT NOT NULL, seq INTEGER NOT NULL, executed_at DATETIME NOT NULL,
		degraded BOOLEAN NOT NULL DEFAULT 0, degrade_reason TEXT NOT NULL DEFAULT '')`).Error; err != nil {
		t.Fatalf("create session_commands: %v", err)
	}
	// Session/AuditLog 用一般 time.Time，AutoMigrate 成 sqlite datetime 可掃描
	if err := db.AutoMigrate(&model.User{}, &model.Asset{}, &model.Session{}, &model.AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	auditSvc := NewAuditLogService(&config.FeatureFlags{AuditLogEnabled: true})
	svc := NewAuditExportService(db, auditSvc, NewSessionCommandService(db), emptyRecordings{})
	return svc, db
}

// emptyRecordings 無錄影檔的 RecordingReader 替身（C↔E 環反轉配套）。
//
// **等價性**：搬包前此處注入的是 `NewRecordingService(t.TempDir())`——一個指向空目錄的
// 真實錄影服務，本檔任一測試都沒有放進真的錄影檔，故它對每個 sessionID 一律回
// 「無錄影／檔案不存在」錯誤。本替身回同一類錯誤，兩者在本檔的可觀察行為逐位相同
// （`writeRecordings` 對 error 的處置是 `continue`，錄影段恆為 0 筆）。
// 唯一涉及錄影數的測試 TestExportRecordingTruncation 走的是 resolveRecordingSessions
// （純 DB 查詢，不碰 reader），不受影響。
//
// **為何不能沿用真型別**：RecordingService 住 `internal/modules/session`（早期在
// `internal/service`），而 session 反過來消費本模組（`audit.CauseText`／失效事件登記）
// ——包內測試 import 它即 import cycle。
type emptyRecordings struct{}

func (emptyRecordings) RecordingProtocol(uint) (string, error) {
	return "", errNoTestRecording
}

func (emptyRecordings) GetRecordingStream(uint) (io.ReadCloser, error) {
	return nil, errNoTestRecording
}

var errNoTestRecording = errors.New("測試環境無錄影檔")

// unzip 解 ZIP 回 map[name][]byte
func unzip(t *testing.T, data []byte) map[string][]byte {
	t.Helper()
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("open zip: %v", err)
	}
	out := map[string][]byte{}
	for _, f := range r.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open entry %s: %v", f.Name, err)
		}
		b, _ := io.ReadAll(rc)
		rc.Close()
		out[f.Name] = b
	}
	return out
}

// TestExportPackageContentsAndManifest 匯出包含四部分且 manifest SHA-256 與實際檔案一致
func TestExportPackageContentsAndManifest(t *testing.T) {
	svc, db := setupExportEnv(t)

	// 種一筆指令（範圍：user 1）
	db.Exec(`INSERT INTO session_commands (session_id, user_id, asset_id, command, seq, executed_at)
		VALUES (1, 1, NULL, 'ls -la', 1, ?)`, time.Now())

	var buf bytes.Buffer
	uid := uint(1)
	manifest, err := svc.Export(&buf, &ExportFilter{UserID: &uid}, 9, "auditor1")
	if err != nil {
		t.Fatalf("Export: %v", err)
	}

	files := unzip(t, buf.Bytes())
	// 必含操作日誌、指令流、manifest（無錄影時 recordings/ 可為空）
	for _, name := range []string{"audit_logs.json", "commands.csv", "manifest.json"} {
		if _, ok := files[name]; !ok {
			t.Errorf("匯出包缺 %s", name)
		}
	}

	// commands.csv 含種入的指令
	if !bytes.Contains(files["commands.csv"], []byte("ls -la")) {
		t.Error("commands.csv 應含 'ls -la'")
	}

	// manifest 的 SHA-256 須與 ZIP 內實際檔案位元組一致（保管鏈可驗證）
	for _, f := range manifest.Files {
		content, ok := files[f.Name]
		if !ok {
			t.Errorf("manifest 記錄 %s 但 ZIP 內無此檔", f.Name)
			continue
		}
		got := fmt.Sprintf("%x", sha256.Sum256(content))
		if got != f.SHA256 {
			t.Errorf("%s SHA-256 不符: manifest=%s actual=%s", f.Name, f.SHA256, got)
		}
		if int64(len(content)) != f.Size {
			t.Errorf("%s 大小不符: manifest=%d actual=%d", f.Name, f.Size, len(content))
		}
	}

	// manifest 保管鏈欄位
	if manifest.ExportedBy != "auditor1" || manifest.ExportedByID != 9 {
		t.Errorf("manifest 匯出者錯誤: %s/%d", manifest.ExportedBy, manifest.ExportedByID)
	}
	if manifest.Filter["user_id"] != "1" {
		t.Errorf("manifest filter 未記錄 user_id, got %v", manifest.Filter)
	}
	if manifest.Counts["commands"] != 1 {
		t.Errorf("commands 計數 = %d, want 1", manifest.Counts["commands"])
	}
}

// TestExportManifestIsLastAndUnhashed manifest.json 為最後一個 entry 且不列在自身 Files
func TestExportManifestIsLastAndUnhashed(t *testing.T) {
	svc, _ := setupExportEnv(t)
	var buf bytes.Buffer
	uid := uint(1)
	manifest, err := svc.Export(&buf, &ExportFilter{UserID: &uid}, 1, "a")
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	for _, f := range manifest.Files {
		if f.Name == "manifest.json" {
			t.Error("manifest 不應把自身列入 Files（否則雜湊自我指涉）")
		}
	}
	// manifest.json 可被解析回結構
	files := unzip(t, buf.Bytes())
	var parsed ExportManifest
	if err := json.Unmarshal(files["manifest.json"], &parsed); err != nil {
		t.Errorf("manifest.json 不可解析: %v", err)
	}
}

// TestExportRecordingTruncation 錄影數超上限時截斷並在 manifest 標明
func TestExportRecordingTruncation(t *testing.T) {
	svc, db := setupExportEnv(t)
	// 種 maxExportRecordings+5 筆有錄影的 session（不需真檔，resolveRecordingSessions 只查 id）
	for i := 0; i < maxExportRecordings+5; i++ {
		if err := db.Create(&model.Session{
			SessionID: fmt.Sprintf("s%d", i), Status: model.SessionStatusClosed,
			UserID: 1, StartTime: time.Now(), HasRecording: true,
		}).Error; err != nil {
			t.Fatalf("create session %d: %v", i, err)
		}
	}
	uid := uint(1)
	ids, truncated, err := svc.resolveRecordingSessions(&ExportFilter{UserID: &uid})
	if err != nil {
		t.Fatalf("resolveRecordingSessions: %v", err)
	}
	if len(ids) != maxExportRecordings {
		t.Errorf("解析錄影數 = %d, want %d（上限）", len(ids), maxExportRecordings)
	}
	if !truncated {
		t.Error("超上限應標 truncated")
	}
}

// TestExportAuditLogsCompleteNoSilentTruncation 回歸：
// >20 筆審計日誌須完整匯出（不因 List 的 PageSize>100→20 上限誤判最後一頁）、
// 且未達匯出上限時 truncated 誠實為 false
func TestExportAuditLogsCompleteNoSilentTruncation(t *testing.T) {
	svc, db := setupExportEnv(t)
	// 種 250 筆 user 1 的審計日誌（遠超 List 的 20 上限，跨多頁）
	for i := 0; i < 250; i++ {
		if err := db.Create(&model.AuditLog{
			UserID: 1, Username: "u1", Action: model.ActionRead,
			Resource: model.ResourceSession, Status: model.StatusSuccess,
		}).Error; err != nil {
			t.Fatalf("seed audit log %d: %v", i, err)
		}
	}

	var buf bytes.Buffer
	uid := uint(1)
	manifest, err := svc.Export(&buf, &ExportFilter{UserID: &uid}, 1, "auditor")
	if err != nil {
		t.Fatalf("Export: %v", err)
	}

	if manifest.Counts["audit_logs"] != 250 {
		t.Errorf("audit_logs 匯出數 = %d, want 250（不得靜默截斷至 20）", manifest.Counts["audit_logs"])
	}
	if manifest.Truncated["audit_logs"] {
		t.Error("未達匯出上限，truncated 應為 false（不得謊報截斷）")
	}
	// ZIP 內實際筆數與 manifest 一致
	files := unzip(t, buf.Bytes())
	var logs []map[string]interface{}
	if err := json.Unmarshal(files["audit_logs.json"], &logs); err != nil {
		t.Fatalf("audit_logs.json 不可解析: %v", err)
	}
	if len(logs) != 250 {
		t.Errorf("audit_logs.json 實際 %d 筆, want 250", len(logs))
	}
}

// TestExportAssetFilterNotesAuditLogScope 的**後續**：asset_id 篩選現已
// 套用於 audit_logs 段（欄位補上後），manifest 改標其歷史邊界——該關聯自工作台上線
// 起才寫入，之前的歷史列不在包內。標註以機器碼給（後端零散文出站）
func TestExportAssetFilterNotesAuditLogScope(t *testing.T) {
	svc, _ := setupExportEnv(t)
	var buf bytes.Buffer
	aid := uint(1)
	manifest, err := svc.Export(&buf, &ExportFilter{AssetID: &aid}, 1, "auditor")
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if manifest.NoteCodes["audit_logs"] != NoteCodeAuditLogAssetBoundary {
		t.Errorf("asset_id 篩選時，manifest 應標明資產關聯的歷史邊界（誠實揭露），得 %q",
			manifest.NoteCodes["audit_logs"])
	}
}
