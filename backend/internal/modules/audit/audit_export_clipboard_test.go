package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"gorm.io/gorm"
)

// 證據包剪貼簿內容段。
//
// 本檔以**真信封 codec**（keyvault key manager）驗五件事：
//  1. bundle 內容檔逐筆含事件識別、時間、方向、content_status 與解密全文，
//     解密值與 DB 密文經同一 codec 解出者一致。
//  2. 缺口列（content_status=failed）狀態標示且 content 鍵**缺席**——
//     不以空字串冒充；空內容（available、長度 0）與缺口可分辨。
//  3. manifest 三數（事件總數／內容可用數／留存失敗數）與 Counts/Totals；
//     含明文揭露只在真的裝了明文時出現。
//  4. 範圍語義：指定 session 只收該會話；時間窗套事件時刻。
//  5. fail-close：codec 未注入而範圍內有可用內容 → 整包失敗（注入點證明走到）。
//
// 雙時戳（job_requested_at＋exported_at）與 ExportForJob 的模式閘一併在此驗。

// setupClipboardBundleEnv 匯出環境＋真 keyvault codec
func setupClipboardBundleEnv(t *testing.T) (*AuditExportService, *gorm.DB, *keyvault.KeyManagerService) {
	t.Helper()
	svc, db := setupExportEnv(t)
	if err := db.AutoMigrate(&model.DataKey{}); err != nil {
		t.Fatalf("migrate data_keys: %v", err)
	}
	km := newTestKeyManager(t, db, 0x5c)
	svc.SetClipboardCodec(km)
	return svc, db, km
}

// seedClipboardSession 建一場會話與其剪貼簿事件（真密文＋一筆缺口）
func seedClipboardSession(t *testing.T, db *gorm.DB, km *keyvault.KeyManagerService,
	at time.Time) (plainSend, plainRecv string) {
	t.Helper()
	assetID := uint(7)
	if err := db.Create(&model.Session{
		SessionID: "sess-cb", Status: model.SessionStatusClosed, Protocol: model.ProtocolRDP,
		UserID: 1, AssetID: &assetID, StartTime: at, AccountUsername: "root",
	}).Error; err != nil {
		t.Fatalf("seed session: %v", err)
	}
	ctx := context.Background()
	plainSend = "clipboard-payload-送往遠端"
	plainRecv = "" // 空內容但 available：與缺口必須可分辨
	encSend, err := km.EncryptFor(ctx, keyvault.RefClipboardContent, plainSend)
	if err != nil {
		t.Fatalf("encrypt send: %v", err)
	}
	encRecv, err := km.EncryptFor(ctx, keyvault.RefClipboardContent, plainRecv)
	if err != nil {
		t.Fatalf("encrypt recv: %v", err)
	}
	rows := []model.ClipboardEvent{
		{SessionID: 1, Direction: "send", ContentEnc: encSend,
			ContentLength: len(plainSend), ContentStatus: model.ClipboardContentAvailable, CreatedAt: at},
		{SessionID: 1, Direction: "recv", ContentEnc: encRecv,
			ContentLength: 0, ContentStatus: model.ClipboardContentAvailable, CreatedAt: at.Add(time.Second)},
		// 缺口列：加密失敗時留下的事實紀錄（內容缺席、失敗標記）
		{SessionID: 1, Direction: "send", ContentEnc: "",
			ContentLength: 17, ContentStatus: model.ClipboardContentFailed, CreatedAt: at.Add(2 * time.Second)},
	}
	for i := range rows {
		if err := db.Create(&rows[i]).Error; err != nil {
			t.Fatalf("seed clipboard %d: %v", i, err)
		}
	}
	return plainSend, plainRecv
}

// decodeClipboardEntries 解出 clipboard_contents.json 的原始鍵值列
// （用 map 而非 struct：斷言「content 鍵缺席」必須看得到鍵本身）
func decodeClipboardEntries(t *testing.T, raw []byte) []map[string]any {
	t.Helper()
	var entries []map[string]any
	if err := json.Unmarshal(raw, &entries); err != nil {
		t.Fatalf("parse clipboard_contents.json: %v\n%s", err, raw)
	}
	return entries
}

func TestBundleClipboardContentsMatchDecryptedDB(t *testing.T) {
	svc, db, km := setupClipboardBundleEnv(t)
	at := time.Now().UTC().Truncate(time.Second).Add(-time.Hour)
	plainSend, plainRecv := seedClipboardSession(t, db, km, at)

	sid := uint(1)
	var buf bytes.Buffer
	m, err := svc.Export(&buf, &ExportFilter{SessionID: &sid}, 9, "auditor1")
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	files := unzip(t, buf.Bytes())
	raw, ok := files["clipboard_contents.json"]
	if !ok {
		t.Fatalf("bundle 缺 clipboard_contents.json，檔案集=%v", fileNames(files))
	}
	entries := decodeClipboardEntries(t, raw)
	if len(entries) != 3 {
		t.Fatalf("收錄筆數=%d want 3", len(entries))
	}

	// 第 1 筆：可用、內容與 DB 解密值一致、識別與時間軸同源
	e := entries[0]
	if e["record_ref"] != "clipboard:1" || e["direction"] != "send" ||
		e["content_status"] != model.ClipboardContentAvailable {
		t.Fatalf("事實欄: %v", e)
	}
	if e["content"] != plainSend {
		t.Fatalf("content=%q want %q（與 DB 解密值一致）", e["content"], plainSend)
	}
	if _, ok := e["occurred_at"]; !ok {
		t.Fatal("occurred_at 缺席")
	}
	// 第 2 筆：available 且內容為空字串——content 鍵**在場**（與缺口可分辨）
	e = entries[1]
	if v, ok := e["content"]; !ok || v != plainRecv {
		t.Fatalf("空內容列 content 鍵應在場且為空字串: ok=%v v=%q", ok, v)
	}
	// 第 3 筆：缺口列——狀態標示、content 鍵**缺席**
	e = entries[2]
	if e["content_status"] != model.ClipboardContentFailed {
		t.Fatalf("缺口列狀態: %v", e["content_status"])
	}
	if _, ok := e["content"]; ok {
		t.Fatal("缺口列不得帶 content 鍵（空字串冒充內容）")
	}
	if e["content_length"] != float64(17) {
		t.Fatalf("缺口列長度事實欄: %v", e["content_length"])
	}

	// manifest 三數＋Counts/Totals＋含明文揭露
	if m.Clipboard == nil {
		t.Fatal("manifest.Clipboard 缺席")
	}
	if m.Clipboard.Events != 3 || m.Clipboard.ContentAvailable != 2 || m.Clipboard.ContentFailed != 1 {
		t.Fatalf("三數: %+v", m.Clipboard)
	}
	if m.Counts[exportClipboardSection] != 3 || m.Totals[exportClipboardSection] != 3 {
		t.Fatalf("counts=%d totals=%d", m.Counts[exportClipboardSection], m.Totals[exportClipboardSection])
	}
	if m.Truncated[exportClipboardSection] {
		t.Fatal("未達上限不得標截斷")
	}
	if !hasDisclosure(m, DisclosureClipboardPlaintext) {
		t.Fatal("含明文內容未於 manifest 揭露")
	}
	// 密文與內容檔皆入 manifest.Files 的雜湊鏈
	found := false
	for _, f := range m.Files {
		if f.Name == "clipboard_contents.json" && f.SHA256 != "" {
			found = true
		}
	}
	if !found {
		t.Fatal("clipboard_contents.json 未入 manifest 雜湊鏈")
	}
}

func fileNames(files map[string][]byte) []string {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	return names
}

// 時間窗套事件時刻：窗外事件不入包；缺口列全缺口時不揭露含明文
func TestBundleClipboardScopeAndGapOnly(t *testing.T) {
	svc, db, km := setupClipboardBundleEnv(t)
	at := time.Now().UTC().Truncate(time.Second).Add(-time.Hour)
	seedClipboardSession(t, db, km, at)

	// 窗外（事件時刻之前收窗）
	uid := uint(1)
	from := at.Add(-48 * time.Hour)
	to := at.Add(-24 * time.Hour)
	var buf bytes.Buffer
	m, err := svc.Export(&buf, &ExportFilter{UserID: &uid, StartTime: &from, EndTime: &to}, 9, "a")
	if err != nil {
		t.Fatalf("Export 窗外: %v", err)
	}
	if m.Clipboard == nil || m.Clipboard.Events != 0 {
		t.Fatalf("窗外仍收錄: %+v", m.Clipboard)
	}
	if hasDisclosure(m, DisclosureClipboardPlaintext) {
		t.Fatal("零收錄不得宣告含明文")
	}

	// 全缺口資料集：另一場會話只有缺口列
	assetID := uint(7)
	if err := db.Create(&model.Session{
		SessionID: "sess-gap", Status: model.SessionStatusClosed, Protocol: model.ProtocolRDP,
		UserID: 2, AssetID: &assetID, StartTime: at,
	}).Error; err != nil {
		t.Fatalf("seed gap session: %v", err)
	}
	if err := db.Create(&model.ClipboardEvent{
		SessionID: 2, Direction: "recv", ContentEnc: "",
		ContentLength: 5, ContentStatus: model.ClipboardContentFailed, CreatedAt: at,
	}).Error; err != nil {
		t.Fatalf("seed gap event: %v", err)
	}
	sid := uint(2)
	buf.Reset()
	m, err = svc.Export(&buf, &ExportFilter{SessionID: &sid}, 9, "a")
	if err != nil {
		t.Fatalf("Export 全缺口: %v", err)
	}
	if m.Clipboard.Events != 1 || m.Clipboard.ContentFailed != 1 || m.Clipboard.ContentAvailable != 0 {
		t.Fatalf("全缺口三數: %+v", m.Clipboard)
	}
	if hasDisclosure(m, DisclosureClipboardPlaintext) {
		t.Fatal("全缺口包不含明文，不得宣告含明文")
	}
	entries := decodeClipboardEntries(t, unzip(t, buf.Bytes())["clipboard_contents.json"])
	if len(entries) != 1 {
		t.Fatalf("筆數: %d", len(entries))
	}
	if _, ok := entries[0]["content"]; ok {
		t.Fatal("缺口列帶了 content 鍵")
	}
}

// fail-close：codec 未注入而範圍內存在可用內容 → 整包失敗。
// 注入點證明：錯誤訊息指名解密器未注入（非其他失敗路徑冒充）
func TestBundleClipboardFailsClosedWithoutCodec(t *testing.T) {
	svc, db, km := setupClipboardBundleEnv(t)
	at := time.Now().UTC().Truncate(time.Second).Add(-time.Hour)
	seedClipboardSession(t, db, km, at)
	svc.SetClipboardCodec(nil) // 拔掉解密器

	sid := uint(1)
	var buf bytes.Buffer
	_, err := svc.Export(&buf, &ExportFilter{SessionID: &sid}, 9, "a")
	if err == nil {
		t.Fatal("codec 缺席仍出包（靜默缺證物）")
	}
	if !strings.Contains(err.Error(), "解密器未注入") {
		t.Fatalf("失敗原因不是 codec 缺席（前置早退？）: %v", err)
	}
}

// ExportForJob：雙時戳入 manifest；報告模式被模式閘擋下
func TestExportForJobDualTimestampsAndModeGate(t *testing.T) {
	svc, db, km := setupClipboardBundleEnv(t)
	at := time.Now().UTC().Truncate(time.Second).Add(-time.Hour)
	seedClipboardSession(t, db, km, at)

	requested := time.Now().Add(-10 * time.Minute).UTC().Truncate(time.Second)
	sid := uint(1)
	var buf bytes.Buffer
	m, err := svc.ExportForJob(&buf, &ExportFilter{SessionID: &sid}, 9, "auditor1", requested)
	if err != nil {
		t.Fatalf("ExportForJob: %v", err)
	}
	if m.JobRequestedAt == nil || !m.JobRequestedAt.Equal(requested) {
		t.Fatalf("job_requested_at: %v want %v", m.JobRequestedAt, requested)
	}
	if !m.ExportedAt.After(requested) {
		t.Fatalf("exported_at（實際打包時刻）應晚於發起: %v", m.ExportedAt)
	}
	// manifest.json 本體也帶雙時戳（收包方讀的是檔案不是回傳值）
	var onDisk map[string]any
	if err := json.Unmarshal(unzip(t, buf.Bytes())["manifest.json"], &onDisk); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	if _, ok := onDisk["job_requested_at"]; !ok {
		t.Fatal("包內 manifest 缺 job_requested_at")
	}
	if _, ok := onDisk["exported_at"]; !ok {
		t.Fatal("包內 manifest 缺 exported_at")
	}

	// 報告模式不走 job
	buf.Reset()
	uid := uint(1)
	from := at.Add(-time.Hour)
	to := at.Add(time.Hour)
	_, err = svc.ExportForJob(&buf, &ExportFilter{
		UserID: &uid, StartTime: &from, EndTime: &to, Subject: SubjectUser,
	}, 9, "auditor1", requested)
	if err == nil {
		t.Fatal("報告模式進了 job 打包")
	}
	// 同步 Export 的報告與 bundle 皆不帶 job_requested_at
	buf.Reset()
	m, err = svc.Export(&buf, &ExportFilter{SessionID: &sid}, 9, "auditor1")
	if err != nil {
		t.Fatalf("同步 Export: %v", err)
	}
	if m.JobRequestedAt != nil {
		t.Fatal("同步匯出不得帶 job_requested_at")
	}
}
