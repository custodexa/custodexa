package audit

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// 證據包的類別篩選（2026-08-25 使用者裁決）。
//
// 本檔釘四件事：
//  1. 未被選取的類別段**不入包**——檔案缺席，且 Counts/Truncated 鍵一併缺席
//     （寫個 0 會讓「沒選」與「選了但範圍內沒有」看起來是同一回事）。
//  2. 對映：session→錄影本體、clipboard→內容全文、audit_log／command→既有紀錄段、
//     alert／file_transfer→**事件事實 csv**（重用事件報告的寫入器）。
//  3. 類別參數缺席＝全部類別；既有呼叫端（無樞紐的 session／user 範圍）行為不變。
//  4. manifest 記類別篩選（selected_types，缺席展開為六類）與逐類別筆數。

// bundleFilter 證據包篩選（Pack 明示——Subject 一旦可帶，就不再分辨得出包型）
func bundleFilter(f *ExportFilter) *ExportFilter {
	f.Pack = ExportModeEvidenceBundle
	return f
}

func hasRecordingEntry(files map[string][]byte) bool {
	for name := range files {
		if strings.HasPrefix(name, "recordings/") {
			return true
		}
	}
	return false
}

func assertNoFiles(t *testing.T, files map[string][]byte, names ...string) {
	t.Helper()
	for _, n := range names {
		if _, ok := files[n]; ok {
			t.Errorf("未被選取的類別段入包了: %s", n)
		}
	}
}

func assertNoCountKeys(t *testing.T, m *ExportManifest, keys ...string) {
	t.Helper()
	for _, k := range keys {
		if _, ok := m.Counts[k]; ok {
			t.Errorf("未被選取的類別仍有 counts 鍵 %q（0 與「沒選」不可混同）", k)
		}
		if _, ok := m.Truncated[k]; ok {
			t.Errorf("未被選取的類別仍有 truncated 鍵 %q", k)
		}
	}
}

// TestBundleTypesSelectSections 只選剪貼簿＋指令：包內無錄影、無操作日誌段，
// 有內容段與指令段（spec Scenario「證據包依類別收錄」）
func TestBundleTypesSelectSections(t *testing.T) {
	svc, db := setupReportEnv(t)
	from, to, at := reportWindow()
	seedSixSources(t, db, at)

	uid := uint(1)
	m, files := exportReport(t, svc, bundleFilter(&ExportFilter{
		UserID: &uid, StartTime: &from, EndTime: &to, Subject: SubjectUser,
		Types: []TimelineEventType{TimelineTypeClipboard, TimelineTypeCommand},
	}))

	if m.Mode != ExportModeEvidenceBundle {
		t.Fatalf("mode = %s, want %s（帶樞紐仍須是證據包）", m.Mode, ExportModeEvidenceBundle)
	}
	for _, want := range []string{"clipboard_contents.json", "commands.csv", "manifest.json"} {
		if _, ok := files[want]; !ok {
			t.Errorf("被選取的類別段缺席: %s（包內：%v）", want, fileNames(files))
		}
	}
	assertNoFiles(t, files, "audit_logs.json", "alerts.csv", "file_transfers.csv")
	if hasRecordingEntry(files) {
		t.Error("未選取 session 卻收了錄影本體")
	}
	assertNoCountKeys(t, m, "audit_logs", "recordings", string(TimelineTypeAlert), string(TimelineTypeFileTransfer))
	if m.Counts["commands"] != 1 {
		t.Errorf("指令段收錄數 = %d, want 1", m.Counts["commands"])
	}
	if m.Counts[exportClipboardSection] != 1 {
		t.Errorf("剪貼簿段收錄數 = %d, want 1", m.Counts[exportClipboardSection])
	}
	// 內容全文確實入包（clipboard→內容全文的對映）
	if !bytes.Contains(files["clipboard_contents.json"], []byte(clipboardSecretMarker)) {
		t.Error("剪貼簿段未帶解密全文")
	}
}

// TestBundleAlertAndFileTransferAsFacts 無本體之兩類以事件事實 csv 列入
func TestBundleAlertAndFileTransferAsFacts(t *testing.T) {
	svc, db := setupReportEnv(t)
	from, to, at := reportWindow()
	seedSixSources(t, db, at)

	uid := uint(1)
	m, files := exportReport(t, svc, bundleFilter(&ExportFilter{
		UserID: &uid, StartTime: &from, EndTime: &to, Subject: SubjectUser,
		Types: []TimelineEventType{TimelineTypeAlert, TimelineTypeFileTransfer},
	}))

	for _, name := range []string{"alerts.csv", "file_transfers.csv"} {
		raw, ok := files[name]
		if !ok {
			t.Fatalf("事實 csv 缺席: %s（包內：%v）", name, fileNames(files))
		}
		rows := csvRows(t, raw)
		if len(rows) != 2 { // 表頭＋一列
			t.Errorf("%s 列數 = %d, want 2（表頭＋1 筆）", name, len(rows))
		}
	}
	if m.Counts[string(TimelineTypeAlert)] != 1 || m.Counts[string(TimelineTypeFileTransfer)] != 1 {
		t.Errorf("事實段收錄數: %v", m.Counts)
	}
	if m.Totals[string(TimelineTypeAlert)] != 1 || m.Totals[string(TimelineTypeFileTransfer)] != 1 {
		t.Errorf("事實段範圍內總數: %v", m.Totals)
	}
	// 有本體的四段一律不入包
	assertNoFiles(t, files, "audit_logs.json", "commands.csv", "clipboard_contents.json")
	if hasRecordingEntry(files) {
		t.Error("未選取 session 卻收了錄影本體")
	}
	assertNoCountKeys(t, m, "audit_logs", "commands", exportClipboardSection, "recordings")
}

// TestBundleTypesAbsentCollectsEveryType 類別參數缺席＝全部類別
func TestBundleTypesAbsentCollectsEveryType(t *testing.T) {
	svc, db := setupReportEnv(t)
	from, to, at := reportWindow()
	seedSixSources(t, db, at)

	uid := uint(1)
	m, files := exportReport(t, svc, bundleFilter(&ExportFilter{
		UserID: &uid, StartTime: &from, EndTime: &to, Subject: SubjectUser,
	}))
	for _, want := range []string{"audit_logs.json", "commands.csv", "clipboard_contents.json",
		"alerts.csv", "file_transfers.csv", "manifest.json"} {
		if _, ok := files[want]; !ok {
			t.Errorf("缺席類別參數應全收，卻缺 %s（包內：%v）", want, fileNames(files))
		}
	}
	if _, ok := m.Counts["recordings"]; !ok {
		t.Error("缺席類別參數應全收，錄影段的 counts 鍵缺席")
	}
	if len(m.SelectedTypes) != 6 {
		t.Errorf("selected_types = %v, want 六類全展開", m.SelectedTypes)
	}
}

// TestBundleLegacyScopeUnaffected 既有呼叫端（無樞紐、無類別）行為不變：
// 原四段照舊，且不長出需要樞紐的事實段
func TestBundleLegacyScopeUnaffected(t *testing.T) {
	svc, db := setupReportEnv(t)
	_, _, at := reportWindow()
	seedSixSources(t, db, at)

	sid := uint(1)
	m, files := exportReport(t, svc, &ExportFilter{SessionID: &sid})
	if m.Mode != ExportModeEvidenceBundle {
		t.Fatalf("mode = %s", m.Mode)
	}
	for _, want := range []string{"audit_logs.json", "commands.csv", "clipboard_contents.json"} {
		if _, ok := files[want]; !ok {
			t.Errorf("既有段缺席: %s", want)
		}
	}
	assertNoFiles(t, files, "alerts.csv", "file_transfers.csv")
	if _, ok := m.Counts["recordings"]; !ok {
		t.Error("既有錄影段的 counts 鍵消失")
	}
}

// TestBundleExplicitFactTypeWithoutPivotFails 明寫了需要樞紐的類別卻無樞紐：
// 整包失敗，不得安靜少一段
func TestBundleExplicitFactTypeWithoutPivotFails(t *testing.T) {
	svc, db := setupReportEnv(t)
	_, _, at := reportWindow()
	seedSixSources(t, db, at)

	sid := uint(1)
	var buf bytes.Buffer
	_, err := svc.Export(&buf, bundleFilter(&ExportFilter{
		SessionID: &sid, Types: []TimelineEventType{TimelineTypeAlert},
	}), 9, "auditor1")
	if err == nil {
		t.Fatal("明寫 alert 卻無樞紐，應整包失敗（否則是安靜缺料的證物）")
	}
	if !strings.Contains(err.Error(), string(TimelineTypeAlert)) {
		t.Errorf("失敗訊息未指出是哪一類別: %v", err)
	}
}

// TestBundleManifestRecordsTypeFilter manifest 記類別篩選，且既有欄位不回歸
func TestBundleManifestRecordsTypeFilter(t *testing.T) {
	svc, db := setupReportEnv(t)
	from, to, at := reportWindow()
	seedSixSources(t, db, at)

	uid := uint(1)
	types := []TimelineEventType{TimelineTypeClipboard, TimelineTypeCommand}
	m, files := exportReport(t, svc, bundleFilter(&ExportFilter{
		UserID: &uid, StartTime: &from, EndTime: &to, Subject: SubjectUser, Types: types,
	}))

	if got := strings.Join(m.SelectedTypes, ","); got != "clipboard,command" {
		t.Errorf("selected_types = %q, want \"clipboard,command\"", got)
	}
	// 篩選快照亦記樞紐與類別（保管鏈：包內看得出當初怎麼篩的）
	if m.Filter["types"] != "clipboard,command" || m.Filter["subject"] != "user" {
		t.Errorf("manifest.filter 未完整記錄樞紐與類別: %v", m.Filter)
	}
	// 包內 manifest 檔本體也帶得到（收包方讀的是檔案不是回傳值）
	if !bytes.Contains(files["manifest.json"], []byte(`"selected_types"`)) {
		t.Error("包內 manifest.json 缺 selected_types")
	}
	// 既有欄位不回歸
	if m.Mode != ExportModeEvidenceBundle || m.ExportedBy != "auditor1" || m.ExportedByID != 9 {
		t.Errorf("既有 manifest 欄位改變: %+v", m)
	}
	if len(m.Files) == 0 || m.Files[0].SHA256 == "" {
		t.Errorf("每檔 SHA-256 缺席: %+v", m.Files)
	}
	if m.Clipboard == nil || m.Clipboard.Events != 1 {
		t.Errorf("剪貼簿三數缺席或改變: %+v", m.Clipboard)
	}
	if m.Scope != nil {
		t.Errorf("證據包不得長出報告專屬的 scope 段: %+v", m.Scope)
	}
}

// 保留覆蓋狀態與範圍內真實筆數（驗收缺陷訂正）。
//
// spec audit-workflows「清單檔內容」對兩種包型同一要求：manifest 含
// **每類別筆數與截斷標示、每類別的保留覆蓋狀態**。證據包原本只在事實段
// （告警、檔案傳輸）寫 totals、且完全不寫 coverage——收包方讀到指令段或
// 剪貼簿段的空白時，無從分辨「這段期間沒發生」與「已被保留政策清除」。

// coverageByType manifest 覆蓋段轉成以類別為鍵
func coverageByType(m *ExportManifest) map[string]ExportCoverage {
	out := make(map[string]ExportCoverage, len(m.Coverage))
	for _, c := range m.Coverage {
		out[c.Type] = c
	}
	return out
}

// TestBundleManifestCoverageAndTotalsPerType 被選類別**逐類**都有 coverage 與
// totals，且涵蓋指令段與剪貼簿段（原本只有事實段才寫 totals）
func TestBundleManifestCoverageAndTotalsPerType(t *testing.T) {
	svc, db := setupReportEnv(t)
	from, to, at := reportWindow()
	seedSixSources(t, db, at)

	uid := uint(1)
	types := []TimelineEventType{TimelineTypeClipboard, TimelineTypeCommand}
	m, files := exportReport(t, svc, bundleFilter(&ExportFilter{
		UserID: &uid, StartTime: &from, EndTime: &to, Subject: SubjectUser, Types: types,
	}))

	byType := coverageByType(m)
	if len(m.Coverage) != len(types) {
		t.Errorf("coverage 應只涵蓋被選的兩類，得 %d 筆: %+v", len(m.Coverage), m.Coverage)
	}
	for _, ty := range types {
		c, ok := byType[string(ty)]
		if !ok {
			t.Errorf("類別 %s 的保留覆蓋狀態缺席（空白會被讀成「沒發生過」）", ty)
			continue
		}
		if c.State == "" {
			t.Errorf("類別 %s 的覆蓋狀態為空字串", ty)
		}
		if got, ok := m.Totals[string(ty)]; !ok || got != 1 {
			t.Errorf("類別 %s 的範圍內真實筆數 = %d (present=%v), want 1", ty, got, ok)
		}
	}
	// 未被選取的類別不得長出 coverage／totals（與 counts 同一紀律）
	for _, ty := range []string{string(TimelineTypeSession), string(TimelineTypeAuditLog),
		string(TimelineTypeAlert), string(TimelineTypeFileTransfer)} {
		if _, ok := byType[ty]; ok {
			t.Errorf("未被選取的類別仍有 coverage 鍵 %q", ty)
		}
		if _, ok := m.Totals[ty]; ok {
			t.Errorf("未被選取的類別仍有 totals 鍵 %q", ty)
		}
	}
	// 收包方讀的是包內的檔案，不是回傳值
	raw, ok := files["manifest.json"]
	if !ok {
		t.Fatal("manifest.json 缺席")
	}
	var parsed ExportManifest
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("parse manifest.json: %v", err)
	}
	if len(parsed.Coverage) != len(types) {
		t.Errorf("包內 manifest.json 的 coverage 不完整: %d 筆", len(parsed.Coverage))
	}
	for _, ty := range types {
		if _, ok := parsed.Totals[string(ty)]; !ok {
			t.Errorf("包內 manifest.json 的 totals 缺類別 %s: %v", ty, parsed.Totals)
		}
	}
}

// TestBundleManifestCoverageAndTotalsAllTypes 類別參數缺席＝全收時，
// coverage 與 totals 六類齊備
func TestBundleManifestCoverageAndTotalsAllTypes(t *testing.T) {
	svc, db := setupReportEnv(t)
	from, to, at := reportWindow()
	seedSixSources(t, db, at)

	uid := uint(1)
	m, _ := exportReport(t, svc, bundleFilter(&ExportFilter{
		UserID: &uid, StartTime: &from, EndTime: &to, Subject: SubjectUser,
	}))

	byType := coverageByType(m)
	for _, ty := range allTimelineTypes {
		if _, ok := byType[string(ty)]; !ok {
			t.Errorf("全收時類別 %s 的 coverage 缺席: %+v", ty, m.Coverage)
		}
		if _, ok := m.Totals[string(ty)]; !ok {
			t.Errorf("全收時類別 %s 的 totals 缺席: %v", ty, m.Totals)
		}
	}
}

// TestBundleLegacyScopeHasNoCoverage 無樞紐的既有呼叫端：coverage 與 totals
// 都以樞紐＋時間窗為前提，產不出來就整段缺席——**不寫半套**
func TestBundleLegacyScopeHasNoCoverage(t *testing.T) {
	svc, db := setupReportEnv(t)
	_, _, at := reportWindow()
	seedSixSources(t, db, at)

	sid := uint(1)
	m, _ := exportReport(t, svc, &ExportFilter{SessionID: &sid})
	if len(m.Coverage) != 0 {
		t.Errorf("無樞紐卻寫出 coverage（其時間窗無從界定）: %+v", m.Coverage)
	}
	// 各段自記的 totals（如 clipboard_contents）以段名為鍵、走該段自己的範圍，
	// 不受此影響；此處只釘「不得長出以類別為鍵的 totals」
	for _, ty := range allTimelineTypes {
		if _, ok := m.Totals[string(ty)]; ok {
			t.Errorf("無樞紐卻寫出類別 %s 的 totals: %v", ty, m.Totals)
		}
	}
}
