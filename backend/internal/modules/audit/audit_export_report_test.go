package audit

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// setupReportEnv 事件報告用環境：六來源的表全備齊。
//
// command_alerts.triggered_at 與 session_commands.executed_at 同為 timestamptz，
// sqlite 掃描不了，故原生建 DATETIME schema（沿 setupExportEnv 既有作法）
func setupReportEnv(t *testing.T) (*AuditExportService, *gorm.DB) {
	t.Helper()
	svc, db := setupExportEnv(t)
	if err := db.Exec(`CREATE TABLE command_alerts (
		id INTEGER PRIMARY KEY AUTOINCREMENT, rule_id INTEGER, rule_name TEXT NOT NULL,
		session_id INTEGER NOT NULL, user_id INTEGER NOT NULL, asset_id INTEGER,
		command TEXT NOT NULL, severity TEXT NOT NULL, triggered_at DATETIME NOT NULL,
		reviewed_by INTEGER, reviewed_at DATETIME, disposition TEXT NOT NULL DEFAULT 'pending',
		note TEXT NOT NULL DEFAULT '', blocked BOOLEAN NOT NULL DEFAULT 0,
		kind TEXT NOT NULL DEFAULT 'rule', reason_code TEXT NOT NULL DEFAULT '')`).Error; err != nil {
		t.Fatalf("create command_alerts: %v", err)
	}
	if err := db.AutoMigrate(&model.ClipboardEvent{}, &model.AuditRetentionWatermark{},
		&model.AuditCheckpoint{}); err != nil {
		t.Fatalf("migrate report tables: %v", err)
	}
	return svc, db
}

// reportWindow 測試共用的時間窗與窗內時刻
func reportWindow() (from, to, at time.Time) {
	to = time.Now().UTC().Truncate(time.Second)
	from = to.Add(-24 * time.Hour)
	at = to.Add(-time.Hour)
	return
}

// seedSixSources 為 user 1／asset 7 各種一筆六來源資料
func seedSixSources(t *testing.T, db *gorm.DB, at time.Time) {
	t.Helper()
	assetID := uint(7)
	if err := db.Create(&model.Session{
		SessionID: "sess-abc", Status: model.SessionStatusClosed, Protocol: model.ProtocolSSH,
		UserID: 1, AssetID: &assetID, StartTime: at, AccountUsername: "root",
		ClientIP: "10.0.0.9", HasRecording: true,
	}).Error; err != nil {
		t.Fatalf("seed session: %v", err)
	}
	if err := db.Exec(`INSERT INTO session_commands (id, session_id, user_id, asset_id, command, seq, executed_at)
		VALUES (1, 1, 1, 7, 'rm -rf /tmp/x', 3, ?)`, at).Error; err != nil {
		t.Fatalf("seed command: %v", err)
	}
	if err := db.Exec(`INSERT INTO command_alerts (id, rule_id, rule_name, session_id, user_id, asset_id,
		command, severity, triggered_at, disposition, note, blocked)
		VALUES (1, 2, '危險指令', 1, 1, 7, 'rm -rf /tmp/x', 'high', ?, 'pending', '', 1)`, at).Error; err != nil {
		t.Fatalf("seed alert: %v", err)
	}
	if err := db.Create(&model.ClipboardEvent{
		SessionID: 1, Direction: "send", Content: clipboardSecretMarker, CreatedAt: at,
	}).Error; err != nil {
		t.Fatalf("seed clipboard: %v", err)
	}
	if err := db.Create(&model.AuditLog{
		CreatedAt: at, UserID: 1, Username: "u1", Action: model.ActionUpdate,
		Resource: model.ResourceAsset, Status: model.StatusSuccess, AssetID: &assetID,
		Method: "PUT", Path: "/api/v1/assets/7",
	}).Error; err != nil {
		t.Fatalf("seed audit log: %v", err)
	}
	if err := db.Create(&model.AuditLog{
		CreatedAt: at, UserID: 1, Username: "u1", Action: model.ActionFileDownload,
		Resource: model.ResourceFile, Status: model.StatusSuccess, AssetID: &assetID,
		Method: "GET", Path: "/api/v1/sftp/download", Details: `{"name":"payroll.xlsx"}`,
	}).Error; err != nil {
		t.Fatalf("seed file transfer: %v", err)
	}
}

// clipboardSecretMarker 可辨識的剪貼簿明文，用於守衛「內容不得出現在報告任一檔」
const clipboardSecretMarker = "SUPER-SECRET-CLIPBOARD-PAYLOAD"

func exportReport(t *testing.T, svc *AuditExportService, filter *ExportFilter) (*ExportManifest, map[string][]byte) {
	t.Helper()
	var buf bytes.Buffer
	m, err := svc.Export(&buf, filter, 9, "auditor1")
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	return m, unzip(t, buf.Bytes())
}

func csvRows(t *testing.T, raw []byte) [][]string {
	t.Helper()
	rows, err := csv.NewReader(bytes.NewReader(raw)).ReadAll()
	if err != nil {
		t.Fatalf("parse csv: %v", err)
	}
	return rows
}

// TestReportCoversSixSources 六來源各出一個檔、各收錄一筆，且 manifest 記錄範圍與逐類別筆數
func TestReportCoversSixSources(t *testing.T) {
	svc, db := setupReportEnv(t)
	from, to, at := reportWindow()
	seedSixSources(t, db, at)

	uid := uint(1)
	m, files := exportReport(t, svc, &ExportFilter{
		Subject: SubjectUser, UserID: &uid, StartTime: &from, EndTime: &to,
	})

	if m.Mode != ExportModeEventReport {
		t.Errorf("mode = %s, want %s", m.Mode, ExportModeEventReport)
	}
	for _, name := range []string{"sessions.csv", "commands.csv", "alerts.csv",
		"clipboard_events.csv", "audit_logs.csv", "file_transfers.csv", "manifest.json"} {
		if _, ok := files[name]; !ok {
			t.Errorf("報告缺 %s", name)
		}
	}
	for _, tp := range allTimelineTypes {
		key := string(tp)
		if m.Counts[key] != 1 {
			t.Errorf("counts[%s] = %d, want 1", key, m.Counts[key])
		}
		if m.Totals[key] != 1 {
			t.Errorf("totals[%s] = %d, want 1（範圍內真實筆數須與收錄數並列）", key, m.Totals[key])
		}
		if m.Truncated[key] {
			t.Errorf("truncated[%s] 應為 false", key)
		}
	}
	if m.Scope == nil || m.Scope.Subject != "user" || m.Scope.SubjectID != 1 {
		t.Fatalf("scope 未記錄調查對象: %+v", m.Scope)
	}
	if !m.Scope.From.Equal(from) || !m.Scope.To.Equal(to) {
		t.Errorf("scope 時間區間不符: %v~%v", m.Scope.From, m.Scope.To)
	}
	if len(m.Scope.Types) != len(allTimelineTypes) {
		t.Errorf("scope.types = %v, want 六類", m.Scope.Types)
	}
	// 錄影不以檔案本體匯出，狀態進 sessions.csv
	for name := range files {
		if strings.HasPrefix(name, "recordings/") {
			t.Errorf("事件報告不得含錄影本體，卻有 %s", name)
		}
	}
	// 欄名與資料列必須同寬。**這一條守的是「顯示的與實際的不是同一件事」**：
	// 欄數對不上時，讀者會把某一欄的值讀成隔壁欄的語義——剪貼簿那一欄
	// 若寫錯，讀者會把明文當成長度，或反過來
	for name, raw := range files {
		if !strings.HasSuffix(name, ".csv") {
			continue
		}
		rows := csvRows(t, raw)
		for i, r := range rows[1:] {
			if len(r) != len(rows[0]) {
				t.Errorf("%s 第 %d 列欄數 %d ≠ 表頭欄數 %d", name, i+1, len(r), len(rows[0]))
			}
		}
	}
}

// TestReportRowsCarryRecordRef 每一列都帶可回溯的紀錄編號（類別:編號）
func TestReportRowsCarryRecordRef(t *testing.T) {
	svc, db := setupReportEnv(t)
	from, to, at := reportWindow()
	seedSixSources(t, db, at)

	uid := uint(1)
	_, files := exportReport(t, svc, &ExportFilter{
		Subject: SubjectUser, UserID: &uid, StartTime: &from, EndTime: &to,
	})

	want := map[string]string{
		"sessions.csv":         "session:1",
		"commands.csv":         "command:1",
		"alerts.csv":           "alert:1",
		"clipboard_events.csv": "clipboard:1",
		"audit_logs.csv":       "audit_log:1",
		"file_transfers.csv":   "file_transfer:2",
	}
	for name, ref := range want {
		rows := csvRows(t, files[name])
		if len(rows) != 2 {
			t.Fatalf("%s 應為表頭＋1 列，實得 %d 列", name, len(rows))
		}
		if rows[0][0] != "record_ref" {
			t.Errorf("%s 第一欄應為 record_ref, got %s", name, rows[0][0])
		}
		if rows[1][0] != ref {
			t.Errorf("%s 紀錄編號 = %s, want %s", name, rows[1][0], ref)
		}
	}
}

// TestReportClipboardExcludesContent 守衛：剪貼簿內容不得出現在報告的任何一個檔案裡
func TestReportClipboardExcludesContent(t *testing.T) {
	svc, db := setupReportEnv(t)
	from, to, at := reportWindow()
	seedSixSources(t, db, at)

	uid := uint(1)
	_, files := exportReport(t, svc, &ExportFilter{
		Subject: SubjectUser, UserID: &uid, StartTime: &from, EndTime: &to,
	})

	for name, content := range files {
		if bytes.Contains(content, []byte(clipboardSecretMarker)) {
			t.Fatalf("%s 含剪貼簿內容明文——報告只得含事件事實", name)
		}
	}
	rows := csvRows(t, files["clipboard_events.csv"])
	header := strings.Join(rows[0], ",")
	if strings.Contains(header, "content\"") || contains(rows[0], "content") {
		t.Errorf("clipboard_events.csv 不得有內容欄，表頭: %s", header)
	}
	idx := indexOf(rows[0], "content_length")
	if idx < 0 {
		t.Fatal("clipboard_events.csv 應有 content_length 欄（事件事實，非內容）")
	}
	if want := strconv.Itoa(len(clipboardSecretMarker)); rows[1][idx] != want {
		t.Errorf("content_length = %s, want %s", rows[1][idx], want)
	}
	if d := indexOf(rows[0], "direction"); d < 0 || rows[1][d] != "send" {
		t.Error("clipboard_events.csv 應記錄方向")
	}
}

// TestReportTypesFilterHonoured 只要兩類時，包內只有那兩類（不多送畫面外的資料）
func TestReportTypesFilterHonoured(t *testing.T) {
	svc, db := setupReportEnv(t)
	from, to, at := reportWindow()
	seedSixSources(t, db, at)

	uid := uint(1)
	m, files := exportReport(t, svc, &ExportFilter{
		Subject: SubjectUser, UserID: &uid, StartTime: &from, EndTime: &to,
		Types: []TimelineEventType{TimelineTypeClipboard, TimelineTypeFileTransfer},
	})

	for _, name := range []string{"clipboard_events.csv", "file_transfers.csv", "manifest.json"} {
		if _, ok := files[name]; !ok {
			t.Errorf("缺 %s", name)
		}
	}
	for _, name := range []string{"sessions.csv", "commands.csv", "alerts.csv", "audit_logs.csv"} {
		if _, ok := files[name]; ok {
			t.Errorf("未選取的類別 %s 不應出現在包內", name)
		}
	}
	if len(m.Counts) != 2 || len(m.Coverage) != 2 {
		t.Errorf("counts/coverage 應只涵蓋選取的兩類: counts=%v coverage=%d", m.Counts, len(m.Coverage))
	}
	if m.Filter["types"] != "clipboard,file_transfer" {
		t.Errorf("manifest filter 未記錄類別篩選: %v", m.Filter)
	}
}

// TestReportAssetSubjectExcludesOtherUsers 資產樞紐須真的套用資產維度
func TestReportAssetSubjectExcludesOtherUsers(t *testing.T) {
	svc, db := setupReportEnv(t)
	from, to, at := reportWindow()
	seedSixSources(t, db, at)
	// 另一台資產、另一個使用者的同時段操作日誌（不得出現在 asset=7 的報告內）
	other := uint(8)
	if err := db.Create(&model.AuditLog{
		CreatedAt: at, UserID: 99, Username: "intruder", Action: model.ActionUpdate,
		Resource: model.ResourceAsset, Status: model.StatusSuccess, AssetID: &other,
	}).Error; err != nil {
		t.Fatalf("seed other asset log: %v", err)
	}

	aid := uint(7)
	m, files := exportReport(t, svc, &ExportFilter{
		Subject: SubjectAsset, AssetID: &aid, StartTime: &from, EndTime: &to,
		Types: []TimelineEventType{TimelineTypeAuditLog},
	})

	if bytes.Contains(files["audit_logs.csv"], []byte("intruder")) {
		t.Error("資產樞紐匯出洩漏了其他資產的紀錄")
	}
	if m.Counts["audit_log"] != 1 {
		t.Errorf("counts[audit_log] = %d, want 1", m.Counts["audit_log"])
	}
	if m.NoteCodes[string(TimelineTypeAuditLog)] != NoteCodeAuditLogAssetBoundary {
		t.Errorf("資產樞紐須標明資產關聯的歷史邊界，得 %q", m.NoteCodes[string(TimelineTypeAuditLog)])
	}
	if !hasDisclosure(m, "export.limit.asset_scope") {
		t.Error("資產樞紐須揭露資產關聯的歷史邊界")
	}
}

// TestReportCoveragePurgedIsIdentifiable 已清除區間必須可辨識，且與「不受自動清除」可區分
func TestReportCoveragePurgedIsIdentifiable(t *testing.T) {
	svc, db := setupReportEnv(t)
	from, to, at := reportWindow()
	seedSixSources(t, db, at)
	// 操作日誌類已清除至窗中段
	if err := db.Create(&model.AuditRetentionWatermark{
		Class: model.RetentionClassAuditLog, PurgedThroughAt: at, PolicyDays: 90,
		LastPurgeAt: at.Add(time.Minute),
	}).Error; err != nil {
		t.Fatalf("seed watermark: %v", err)
	}
	if err := db.Create(&model.AuditCheckpoint{
		Seq: 11, MinCreatedAt: &from, MaxCreatedAt: &at, PurgedAt: &at,
	}).Error; err != nil {
		t.Fatalf("seed checkpoint: %v", err)
	}

	uid := uint(1)
	m, _ := exportReport(t, svc, &ExportFilter{
		Subject: SubjectUser, UserID: &uid, StartTime: &from, EndTime: &to,
		Types: []TimelineEventType{TimelineTypeAuditLog, TimelineTypeSession},
	})

	byType := map[string]ExportCoverage{}
	for _, c := range m.Coverage {
		byType[c.Type] = c
	}
	logs, ok := byType["audit_log"]
	if !ok || logs.State != CoveragePurged {
		t.Fatalf("audit_log 覆蓋狀態 = %+v, want purged", logs)
	}
	if logs.PolicyDays == nil || *logs.PolicyDays != 90 || logs.PurgedThroughAt == nil || logs.LastPurgeAt == nil {
		t.Errorf("已清除區間須附保留天數、清除截止與最近清除時刻: %+v", logs)
	}
	if logs.ArchiveUnitRange == nil || logs.ArchiveUnitRange.From != 11 {
		t.Errorf("已清除區間須附封存單位編號區間供獨立查核: %+v", logs.ArchiveUnitRange)
	}
	// 說明走機器碼＋參數：四項佐證都要出得來，讀取端才講得出「空白是清除的結果」
	if logs.NoteCode != CoverageNoteCodePurged {
		t.Errorf("已清除區間的說明碼 = %q, want %q", logs.NoteCode, CoverageNoteCodePurged)
	}
	for _, k := range []string{"policy_days", "purged_through_at", "last_purge_at",
		"archive_unit_from", "archive_unit_to"} {
		if logs.NoteParams[k] == "" {
			t.Errorf("已清除區間的說明參數缺 %s: %v", k, logs.NoteParams)
		}
	}
	if logs.NoteParams["policy_days"] != "90" || logs.NoteParams["archive_unit_from"] != "11" {
		t.Errorf("說明參數值錯誤: %v", logs.NoteParams)
	}
	sessions := byType["session"]
	if sessions.State != CoverageNotRetained {
		t.Errorf("session 覆蓋狀態 = %s, want not_retained", sessions.State)
	}
	// **兩者必須是不同的碼**：讀取端若拿到同一個碼，就會把「已清除」與
	// 「不受清除」講成同一句話，而那正是本功能要消滅的誤讀
	if sessions.NoteCode != CoverageNoteCodeNotRetained || sessions.NoteCode == logs.NoteCode {
		t.Errorf("not_retained 與 purged 必須可區分: %q vs %q", sessions.NoteCode, logs.NoteCode)
	}
}

// TestReportManifestSignedDisclosure 未簽章時 manifest 明載 signed=false 與機器碼原因
func TestReportManifestSignedDisclosure(t *testing.T) {
	svc, db := setupReportEnv(t)
	from, to, at := reportWindow()
	seedSixSources(t, db, at)

	uid := uint(1)
	m, files := exportReport(t, svc, &ExportFilter{
		Subject: SubjectUser, UserID: &uid, StartTime: &from, EndTime: &to,
		Types: []TimelineEventType{TimelineTypeSession},
	})

	if m.Signed {
		t.Fatal("測試環境未注入簽章服務，signed 應為 false")
	}
	if m.SignedReason != SignedReasonServiceUnavailable {
		t.Errorf("signed_reason = %q, want %q", m.SignedReason, SignedReasonServiceUnavailable)
	}
	if !hasDisclosure(m, "export.limit.not_signed") {
		t.Error("未簽章須以邊界條目明示「未啟用」而非「簽章被移除」")
	}
	var parsed ExportManifest
	if err := json.Unmarshal(files["manifest.json"], &parsed); err != nil {
		t.Fatalf("manifest.json 不可解析: %v", err)
	}
	if parsed.Signed || parsed.SignedReason != SignedReasonServiceUnavailable {
		t.Errorf("包內 manifest.json 未載明簽章狀態: signed=%v reason=%q", parsed.Signed, parsed.SignedReason)
	}
	if parsed.Scope == nil || len(parsed.Disclosures) == 0 || len(parsed.Coverage) == 0 {
		t.Error("包內 manifest.json 缺範圍／邊界／覆蓋狀態")
	}
}

// TestReportDisclosuresLeadWithProof 邊界說明先講能證明什麼，且不裸露內部術語
func TestReportDisclosuresLeadWithProof(t *testing.T) {
	svc, db := setupReportEnv(t)
	from, to, at := reportWindow()
	seedSixSources(t, db, at)

	uid := uint(1)
	m, _ := exportReport(t, svc, &ExportFilter{
		Subject: SubjectUser, UserID: &uid, StartTime: &from, EndTime: &to,
		Types: []TimelineEventType{TimelineTypeSession},
	})

	if len(m.Disclosures) == 0 || !strings.HasPrefix(m.Disclosures[0].Code, "export.proves.") {
		t.Fatalf("第一條邊界應是「能證明什麼」: %+v", m.Disclosures)
	}
	// 「能證明什麼」全數排在邊界之前：反過來寫，讀者先讀到一串免責
	seenLimit := false
	for _, d := range m.Disclosures {
		switch {
		case strings.HasPrefix(d.Code, "export.limit."):
			seenLimit = true
		case strings.HasPrefix(d.Code, "export.proves."):
			if seenLimit {
				t.Errorf("%s 出現在邊界之後：能證明什麼須全數在前", d.Code)
			}
		default:
			t.Errorf("邊界碼 %q 不在 export.proves.／export.limit. 兩個命名空間內", d.Code)
		}
	}
	for _, must := range []string{
		"export.proves.record_ref", "export.proves.scope",
		"export.limit.payload_excluded", "export.limit.coverage_states",
		"export.limit.manifest_required", "export.limit.scope_is_query_range",
	} {
		if !hasDisclosure(m, must) {
			t.Errorf("缺邊界條目 %s", must)
		}
	}
	// **後端不出散文**：manifest 內不得出現任何中文說明字串（文字由 i18n 依碼提供）。
	// 這一條同時擋掉「未來有人為了好讀而把中文塞回 Go」的回頭路
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	for _, r := range string(raw) {
		if r >= 0x4E00 && r <= 0x9FFF {
			t.Fatalf("manifest 含中文散文（應只出機器碼與參數）: %s", string(raw))
		}
	}
}

// TestReportOutOfWindowExcluded 窗外的紀錄不得進包（範圍宣稱要站得住）
func TestReportOutOfWindowExcluded(t *testing.T) {
	svc, db := setupReportEnv(t)
	from, to, at := reportWindow()
	seedSixSources(t, db, at)
	if err := db.Exec(`INSERT INTO session_commands (id, session_id, user_id, asset_id, command, seq, executed_at)
		VALUES (2, 1, 1, 7, 'out-of-window', 4, ?)`, from.Add(-time.Hour)).Error; err != nil {
		t.Fatalf("seed out-of-window command: %v", err)
	}

	uid := uint(1)
	m, files := exportReport(t, svc, &ExportFilter{
		Subject: SubjectUser, UserID: &uid, StartTime: &from, EndTime: &to,
		Types: []TimelineEventType{TimelineTypeCommand},
	})
	if bytes.Contains(files["commands.csv"], []byte("out-of-window")) {
		t.Error("窗外紀錄不得進包")
	}
	if m.Counts["command"] != 1 || m.Totals["command"] != 1 {
		t.Errorf("窗內筆數應為 1: counts=%d totals=%d", m.Counts["command"], m.Totals["command"])
	}
}

// TestReportTruncationIsHonest 超過單類別上限時截斷並誠實標明，且總數仍為真實筆數
func TestReportTruncationIsHonest(t *testing.T) {
	svc, db := setupReportEnv(t)
	from, to, at := reportWindow()

	// 以測試專用的小上限跑：直接種略多於一頁的資料，改以 pageExport 的分頁邏輯驗證，
	// 種滿 50000 筆不切實際——故此處驗的是「分頁不漏、不重、總數誠實」
	for i := 0; i < reportPageSize+7; i++ {
		if err := db.Exec(`INSERT INTO session_commands (session_id, user_id, asset_id, command, seq, executed_at)
			VALUES (1, 1, 7, ?, ?, ?)`, "cmd-"+string(rune('a'+i%26)), i, at.Add(time.Duration(i)*time.Millisecond)).Error; err != nil {
			t.Fatalf("seed command %d: %v", i, err)
		}
	}

	uid := uint(1)
	m, files := exportReport(t, svc, &ExportFilter{
		Subject: SubjectUser, UserID: &uid, StartTime: &from, EndTime: &to,
		Types: []TimelineEventType{TimelineTypeCommand},
	})
	want := reportPageSize + 7
	if m.Counts["command"] != want {
		t.Errorf("跨頁收錄數 = %d, want %d（分頁不得漏）", m.Counts["command"], want)
	}
	if m.Totals["command"] != int64(want) {
		t.Errorf("範圍內總數 = %d, want %d", m.Totals["command"], want)
	}
	if m.Truncated["command"] {
		t.Error("未達上限不得謊報截斷")
	}
	rows := csvRows(t, files["commands.csv"])
	if len(rows) != want+1 {
		t.Errorf("commands.csv 實際 %d 列（含表頭）, want %d", len(rows), want+1)
	}
	seen := map[string]bool{}
	for _, r := range rows[1:] {
		if seen[r[0]] {
			t.Fatalf("分頁重複輸出同一筆: %s", r[0])
		}
		seen[r[0]] = true
	}
}

// TestReportRecordingStateNotPayload 錄影以狀態呈現，不匯本體
func TestReportRecordingStateNotPayload(t *testing.T) {
	svc, db := setupReportEnv(t)
	from, to, at := reportWindow()
	seedSixSources(t, db, at)
	// 第二筆會話無錄影
	if err := db.Create(&model.Session{
		SessionID: "sess-norec", Status: model.SessionStatusClosed, Protocol: model.ProtocolSSH,
		UserID: 1, StartTime: at.Add(time.Minute), HasRecording: false,
	}).Error; err != nil {
		t.Fatalf("seed session: %v", err)
	}

	uid := uint(1)
	_, files := exportReport(t, svc, &ExportFilter{
		Subject: SubjectUser, UserID: &uid, StartTime: &from, EndTime: &to,
		Types: []TimelineEventType{TimelineTypeSession},
	})
	rows := csvRows(t, files["sessions.csv"])
	idx := indexOf(rows[0], "recording_state")
	if idx < 0 {
		t.Fatal("sessions.csv 應有 recording_state 欄")
	}
	if rows[1][idx] != RecordingStateAvailable {
		t.Errorf("有錄影會話狀態 = %s, want %s", rows[1][idx], RecordingStateAvailable)
	}
	if rows[2][idx] != RecordingStateNone {
		t.Errorf("無錄影會話狀態 = %s, want %s（未留存須可辨識）", rows[2][idx], RecordingStateNone)
	}
}

// TestLegacyBundleUnaffectedByReportMode 既有證據包模式不受影響：
// 無 subject 時仍走原路徑、原檔名、原 counts 鍵
func TestLegacyBundleUnaffectedByReportMode(t *testing.T) {
	svc, db := setupReportEnv(t)
	_, _, at := reportWindow()
	seedSixSources(t, db, at)

	uid := uint(1)
	m, files := exportReport(t, svc, &ExportFilter{UserID: &uid})
	if m.Mode != ExportModeEvidenceBundle {
		t.Errorf("mode = %s, want %s", m.Mode, ExportModeEvidenceBundle)
	}
	if _, ok := files["audit_logs.json"]; !ok {
		t.Error("既有模式應維持 audit_logs.json")
	}
	if _, ok := files["sessions.csv"]; ok {
		t.Error("既有模式不應長出報告專屬檔案")
	}
	if m.Counts["commands"] != 1 || m.Scope != nil {
		t.Errorf("既有模式的 manifest 形態改變: counts=%v scope=%v", m.Counts, m.Scope)
	}
}

// TestLegacyBundleAppliesAssetDimension 既有模式的資產樞紐不得回傳其他使用者的操作日誌
func TestLegacyBundleAppliesAssetDimension(t *testing.T) {
	svc, db := setupReportEnv(t)
	_, _, at := reportWindow()
	seedSixSources(t, db, at)
	other := uint(8)
	if err := db.Create(&model.AuditLog{
		CreatedAt: at, UserID: 99, Username: "intruder", Action: model.ActionUpdate,
		Resource: model.ResourceAsset, Status: model.StatusSuccess, AssetID: &other,
	}).Error; err != nil {
		t.Fatalf("seed other asset log: %v", err)
	}

	aid := uint(7)
	m, files := exportReport(t, svc, &ExportFilter{AssetID: &aid})
	if bytes.Contains(files["audit_logs.json"], []byte("intruder")) {
		t.Error("資產篩選未套用於 audit_logs，匯出了其他資產的紀錄（過度揭露）")
	}
	// 種入的兩筆 asset 7 日誌（一般操作＋檔案傳輸）都算，asset 8 那筆不算
	if m.Counts["audit_logs"] != 2 {
		t.Errorf("audit_logs 收錄數 = %d, want 2", m.Counts["audit_logs"])
	}
	if m.NoteCodes["audit_logs"] != NoteCodeAuditLogAssetBoundary {
		t.Errorf("仍須標明資產關聯的歷史邊界，得 %q", m.NoteCodes["audit_logs"])
	}
}

func hasDisclosure(m *ExportManifest, code string) bool {
	for _, d := range m.Disclosures {
		if d.Code == code {
			return true
		}
	}
	return false
}

func indexOf(row []string, name string) int {
	for i, v := range row {
		if v == name {
			return i
		}
	}
	return -1
}

func contains(row []string, name string) bool { return indexOf(row, name) >= 0 }
