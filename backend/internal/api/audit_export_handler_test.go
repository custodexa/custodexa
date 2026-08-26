package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/modules/audit"
)

// 匯出端點的查詢參數解析。
//
// 這一組測試守的是同一件事：**參數看不懂就要當場拒絕**。靜默忽略會讓使用者
// 拿到一包範圍完全不同、卻看起來一切正常的證據——那比直接失敗糟得多

func parseFilterForQuery(t *testing.T, query string) (*audit.ExportFilter, int, string) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/audit-export?"+query, nil)

	filter, ok := parseExportFilter(c)
	if ok {
		return filter, http.StatusOK, ""
	}
	var body struct {
		Code   string         `json:"code"`
		Params map[string]any `json:"params"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	field, _ := body.Params["field"].(string)
	return nil, w.Code, body.Code + ":" + field
}

func TestExportRejectsUnparseableParams(t *testing.T) {
	cases := []struct {
		name  string
		query string
		field string
	}{
		{"user_id 非數字", "user_id=abc", "user_id"},
		{"asset_id 非數字", "asset_id=1.5", "asset_id"},
		{"session_id 為零", "session_id=0", "session_id"},
		{"start_time 非 RFC3339", "start_time=2026-08-13", "start_time"},
		{"end_time 非 RFC3339", "user_id=1&end_time=yesterday", "end_time"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			filter, code, detail := parseFilterForQuery(t, tc.query)
			if filter != nil {
				t.Fatalf("應拒絕，卻通過並得 filter=%+v", filter)
			}
			if code != http.StatusBadRequest {
				t.Errorf("狀態碼 = %d, want 400", code)
			}
			if want := "VALIDATION_INVALID_QUERY_PARAM:" + tc.field; detail != want {
				t.Errorf("錯誤碼／欄位 = %q, want %q", detail, want)
			}
		})
	}
}

func TestExportLegacyParamsUnchanged(t *testing.T) {
	filter, code, _ := parseFilterForQuery(t,
		"user_id=3&asset_id=7&start_time=2026-08-01T00:00:00Z&end_time=2026-08-02T00:00:00Z")
	if filter == nil {
		t.Fatalf("既有五參數應照舊通過，得 %d", code)
	}
	if filter.IsEventReport() {
		t.Error("未帶 subject 時不得進入事件報告模式")
	}
	if *filter.UserID != 3 || *filter.AssetID != 7 || len(filter.Types) != 0 || filter.Subject != "" {
		t.Errorf("既有參數解析結果改變: %+v", filter)
	}
	if _, code, _ := parseFilterForQuery(t, ""); code != http.StatusBadRequest {
		t.Errorf("零條件仍須拒絕（不得匯出整庫），得 %d", code)
	}
}

func TestExportReportScopeValidation(t *testing.T) {
	const window = "start_time=2026-08-01T00:00:00Z&end_time=2026-08-02T00:00:00Z"
	cases := []struct {
		name  string
		query string
		field string
	}{
		{"未知樞紐", "subject=group&user_id=1&" + window, "subject"},
		{"樞紐與 id 不相符", "subject=asset&user_id=1&" + window, "asset_id"},
		{"報告缺時間區間", "subject=user&user_id=1", "range"},
		{"報告區間反向", "subject=user&user_id=1&start_time=2026-08-02T00:00:00Z&end_time=2026-08-01T00:00:00Z", "range"},
		{"未知類別", "subject=user&user_id=1&types=command,telepathy&" + window, "types"},
		{"types 缺樞紐", "types=command&user_id=1&" + window, "subject"},
		{"報告模式帶 session_id", "subject=user&user_id=1&session_id=5&" + window, "session_id"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			filter, code, detail := parseFilterForQuery(t, tc.query)
			if filter != nil {
				t.Fatalf("應拒絕，卻通過: %+v", filter)
			}
			if code != http.StatusBadRequest {
				t.Errorf("狀態碼 = %d, want 400", code)
			}
			if want := "VALIDATION_INVALID_QUERY_PARAM:" + tc.field; detail != want {
				t.Errorf("錯誤碼／欄位 = %q, want %q", detail, want)
			}
		})
	}
}

func TestExportReportScopeAccepted(t *testing.T) {
	filter, code, _ := parseFilterForQuery(t,
		"subject=asset&asset_id=7&types=clipboard,file_transfer,clipboard"+
			"&start_time=2026-08-01T00:00:00Z&end_time=2026-08-02T00:00:00Z")
	if filter == nil {
		t.Fatalf("合法報告範圍應通過，得 %d", code)
	}
	if !filter.IsEventReport() || filter.Subject != audit.SubjectAsset || filter.SubjectID() != 7 {
		t.Fatalf("樞紐解析錯誤: %+v", filter)
	}
	// 重複類別去重：同一類別出現兩次會在包內寫出兩個同名檔案
	if len(filter.Types) != 2 || filter.Types[0] != audit.TimelineTypeClipboard ||
		filter.Types[1] != audit.TimelineTypeFileTransfer {
		t.Errorf("類別解析錯誤（應去重並保序）: %v", filter.Types)
	}
	if !filter.StartTime.Equal(time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("時間區間解析錯誤: %v", filter.StartTime)
	}
}

func TestExportSummaryCarriesScopeAndTotals(t *testing.T) {
	m := &audit.ExportManifest{
		Mode:      audit.ExportModeEventReport,
		Counts:    map[string]int{"command": 2, "alert": 1},
		Totals:    map[string]int64{"command": 9, "alert": 1},
		Truncated: map[string]bool{"command": true},
		Scope: &audit.ExportScope{
			Subject: "user", SubjectID: 3,
			From: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC),
			To:   time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC),
		},
	}
	got := exportSummary(m)
	for _, want := range []string{
		"mode=event_report", "subject=user:3",
		"range=2026-08-01T00:00:00Z~2026-08-02T00:00:00Z",
		"alert=1/1", "command=2/9(truncated)",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("審計摘要缺 %q: %s", want, got)
		}
	}
}

// 證據包模式的樞紐與類別參數（4b.1，2026-08-25 使用者裁決）。
//
// 守的仍是同一件事：**看不懂就當場拒絕**。另加一條——包型的分辨不得靠猜：
// 證據包也吃 subject 後，只有明示的 pack 說得準這次要的是哪一種包
func TestExportBundleScopeAccepted(t *testing.T) {
	const window = "start_time=2026-08-01T00:00:00Z&end_time=2026-08-02T00:00:00Z"

	filter, code, _ := parseFilterForQuery(t,
		"pack=evidence_bundle&subject=user&user_id=3&types=clipboard,command,clipboard&"+window)
	if filter == nil {
		t.Fatalf("證據包帶樞紐與類別應通過，得 %d", code)
	}
	if filter.IsEventReport() {
		t.Error("明示 pack=evidence_bundle 仍被判為事件報告（帶 subject 即報告的舊推斷未收口）")
	}
	if filter.Subject != audit.SubjectUser || filter.SubjectID() != 3 {
		t.Errorf("樞紐未入篩選快照: %+v", filter)
	}
	if len(filter.Types) != 2 || filter.Types[0] != audit.TimelineTypeClipboard ||
		filter.Types[1] != audit.TimelineTypeCommand {
		t.Errorf("類別解析錯誤（應去重並保序）: %v", filter.Types)
	}

	// 無樞紐的既有範圍仍合法（指定 session 匯出這場的證物），且可帶不需樞紐的類別
	filter, code, _ = parseFilterForQuery(t, "pack=evidence_bundle&session_id=42&types=command")
	if filter == nil {
		t.Fatalf("無樞紐的證據包範圍應通過，得 %d", code)
	}
	if filter.Subject != "" || len(filter.Types) != 1 {
		t.Errorf("無樞紐範圍解析錯誤: %+v", filter)
	}

	// 不帶 pack 的既有呼叫端行為逐位不變
	filter, _, _ = parseFilterForQuery(t, "subject=user&user_id=1&"+window)
	if filter == nil || !filter.IsEventReport() {
		t.Errorf("未帶 pack 時仍應沿 subject 推斷為事件報告: %+v", filter)
	}
}

func TestExportBundleScopeValidation(t *testing.T) {
	const window = "start_time=2026-08-01T00:00:00Z&end_time=2026-08-02T00:00:00Z"
	cases := []struct {
		name  string
		query string
		field string
	}{
		{"未知包型", "pack=bundle&user_id=1", "pack"},
		{"未知類別", "pack=evidence_bundle&user_id=1&types=command,telepathy", "types"},
		{"未知樞紐", "pack=evidence_bundle&subject=group&user_id=1", "subject"},
		{"樞紐與 id 不相符", "pack=evidence_bundle&subject=asset&user_id=1", "asset_id"},
		{"告警類別缺樞紐", "pack=evidence_bundle&session_id=42&types=alert", "subject"},
		{"檔案傳輸類別缺時間窗", "pack=evidence_bundle&subject=user&user_id=1&types=file_transfer", "range"},
		{"明示報告卻缺樞紐", "pack=event_report&user_id=1&" + window, "subject"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			filter, code, detail := parseFilterForQuery(t, tc.query)
			if filter != nil {
				t.Fatalf("應拒絕，卻通過: %+v", filter)
			}
			if code != http.StatusBadRequest {
				t.Errorf("狀態碼 = %d, want 400", code)
			}
			if want := "VALIDATION_INVALID_QUERY_PARAM:" + tc.field; detail != want {
				t.Errorf("錯誤碼／欄位 = %q, want %q", detail, want)
			}
		})
	}
}
