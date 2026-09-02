package sshproxy

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/dbconsole"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
)

// 結果匯出端點。
//
// # 為什麼「六態逐位元組相同」要比整個回應而不是只比 body
//
// 可探測性不只藏在 body 裡：多一個 `Content-Length`、少一個 `Content-Type`、
// 換一個狀態碼，都足以讓外部區分「這場會話不存在」與「這場會話存在但不是你的」。
// 收斂的承諾是「這六種情形對外不可分辨」，所以斷言的對象必須是外部看得到的全部
// ——狀態碼、標頭集合與 body 三者一起。

// exportFixture 一個持有結果快取的活會話 + 與生產同構的路由
type exportFixture struct {
	env       *consoleEnv
	cs        *consoleSession
	sessionID uint
	router    *gin.Engine
}

const exportRoute = "/api/v1/db-console/sessions/:id/results/:event_id/export"

// newExportFixture 建一場 active 的主控台會話並登記進活躍會話表。
// asUser 決定路由中介層放進脈絡的身分
func newExportFixture(t *testing.T, asUser uint) *exportFixture {
	t.Helper()
	env := setupConsoleEnv(t, "mysql")
	sess := &model.Session{SessionID: "console-export-main",
		UserID: 1, Status: model.SessionStatusActive, DBConsole: true}
	aid := uint(1)
	sess.AssetID = &aid
	if err := env.db.Create(sess).Error; err != nil {
		t.Fatalf("seed session: %v", err)
	}
	cs := &consoleSession{
		handler: env.h, sess: sess, userID: 1, assetID: 1,
		cache: newConsoleResultCache(),
		out:   make(chan []byte, dbconsole.OutboundQueueDepth),
	}
	env.h.consoleSessionsRef().Store(sess.ID, cs)

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("userID", asUser)
		c.Set("username", "u1")
	})
	r.GET(exportRoute, env.h.HandleDBConsoleExport)
	return &exportFixture{env: env, cs: cs, sessionID: sess.ID, router: r}
}

// putUnit 放一個可匯出的單位進快取
func (f *exportFixture) putUnit(t *testing.T, seq int, sets ...dbconsole.ResultSet) string {
	t.Helper()
	ev, err := dbconsole.NewEventID()
	if err != nil {
		t.Fatalf("事件識別產生失敗: %v", err)
	}
	f.cs.cache.put(&consoleCachedUnit{EventID: ev, Seq: seq, Database: "app", Sets: sets})
	return ev
}

func (f *exportFixture) get(path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", path, nil)
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, req)
	return w
}

// wireForm 一次請求的完整對外面：狀態碼、標頭集合、body。
// 標頭以排序後的逐行文字表達，使「多一個標頭」與「值不同」都會反映在比較裡
func wireForm(w *httptest.ResponseRecorder) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "%d\n", w.Code)
	keys := make([]string, 0, len(w.Header()))
	for k := range w.Header() {
		keys = append(keys, k)
	}
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[j] < keys[i] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	for _, k := range keys {
		fmt.Fprintf(&b, "%s: %s\n", k, strings.Join(w.Header().Values(k), "|"))
	}
	b.WriteString("\n")
	b.Write(w.Body.Bytes())
	return b.Bytes()
}

func sampleSet(rows ...[]string) dbconsole.ResultSet {
	set := dbconsole.ResultSet{SetIndex: 0, RowCount: len(rows),
		Columns: []dbconsole.ColumnMeta{
			{Name: "id", TypeName: "bigint", Kind: dbconsole.KindInteger},
			{Name: "note", TypeName: "text", Kind: dbconsole.KindText},
		}}
	for _, r := range rows {
		cells := make([]*string, len(r))
		for i := range r {
			v := r[i]
			cells[i] = &v
		}
		set.Rows = append(set.Rows, cells)
	}
	return set
}

// TestConsoleExportSixDenialsAreByteIdentical 六態逐位元組相同。
//
// 六種不成立的情形各自有一個真實原因，而那個原因只寫進審計；
// 對外六者是同一則回應——否則「這個 session_id 存不存在」就成了可探測的事實
func TestConsoleExportSixDenialsAreByteIdentical(t *testing.T) {
	f := newExportFixture(t, 1)
	ev := f.putUnit(t, 1, sampleSet([]string{"1", "a"}))

	// 他人的會話（active、非本人）
	other := &model.Session{SessionID: "console-export-other",
		UserID: 2, Status: model.SessionStatusActive, DBConsole: true}
	aid := uint(1)
	other.AssetID = &aid
	if err := f.env.db.Create(other).Error; err != nil {
		t.Fatalf("seed 他人會話: %v", err)
	}
	// 本人但已結束的會話
	closed := &model.Session{SessionID: "console-export-closed",
		UserID: 1, Status: model.SessionStatusClosed, DBConsole: true}
	closed.AssetID = &aid
	if err := f.env.db.Create(closed).Error; err != nil {
		t.Fatalf("seed 已結束會話: %v", err)
	}
	stale, err := dbconsole.NewEventID()
	if err != nil {
		t.Fatalf("事件識別: %v", err)
	}

	cases := []struct {
		name   string
		path   string
		reason string
	}{
		{"識別格式非法", fmt.Sprintf("/api/v1/db-console/sessions/%d/results/not-an-event-id/export",
			f.sessionID), consoleDenyIdentifierInvalid},
		{"會話不存在", fmt.Sprintf("/api/v1/db-console/sessions/99999/results/%s/export", ev),
			consoleDenySessionNotFound},
		{"非本人", fmt.Sprintf("/api/v1/db-console/sessions/%d/results/%s/export", other.ID, ev),
			consoleDenyNotOwner},
		{"會話非 active", fmt.Sprintf("/api/v1/db-console/sessions/%d/results/%s/export", closed.ID, ev),
			consoleDenySessionNotActive},
		{"事件非當前快取", fmt.Sprintf("/api/v1/db-console/sessions/%d/results/%s/export",
			f.sessionID, stale), consoleDenyEventNotCurrent},
		{"結果集逾界", fmt.Sprintf("/api/v1/db-console/sessions/%d/results/%s/export?set=9",
			f.sessionID, ev), consoleDenySetOutOfRange},
	}

	var baseline []byte
	for _, tc := range cases {
		w := f.get(tc.path)
		got := wireForm(w)
		if w.Code != http.StatusNotFound {
			t.Fatalf("%s：狀態碼 %d，六態一律 404", tc.name, w.Code)
		}
		if baseline == nil {
			baseline = got
			continue
		}
		if !bytes.Equal(baseline, got) {
			t.Errorf("%s 的回應與第一態不同——收斂已破：\n第一態:\n%s\n本態:\n%s",
				tc.name, baseline, got)
		}
	}

	// 真實原因必須各自進審計（收斂的代價是稽核側要看得見差別）
	rows := f.env.auditRows(t)
	seen := map[string]bool{}
	for _, row := range rows {
		var body map[string]any
		if json.Unmarshal([]byte(row.RequestBody), &body) != nil {
			continue
		}
		if body["kind"] != consoleKindResultExport {
			continue
		}
		if row.Status != model.StatusDenied {
			t.Errorf("拒絕列的 status = %s", row.Status)
		}
		if r, ok := body["reason"].(string); ok {
			seen[r] = true
		}
	}
	for _, tc := range cases {
		if !seen[tc.reason] {
			t.Errorf("審計未見原因 %s——對外收斂之後，稽核是唯一還分得出六態的地方", tc.reason)
		}
	}
}

// TestConsoleExportDeniedByTransferPolicy 傳輸政策關閉時匯出被拒且留痕。
//
// 政策判定刻意排在身分判定之後：對本人回 403 是有資訊的（他該去找管理者），
// 對非本人回同一則 403 就等於確認了「這個結果存在」
func TestConsoleExportDeniedByTransferPolicy(t *testing.T) {
	f := newExportFixture(t, 1)
	ev := f.putUnit(t, 1, sampleSet([]string{"1", "a"}))

	if err := f.env.db.Create(&model.SecurityPolicy{
		Key: policy.PolicyFileDownloadEnabled, Value: "false"}).Error; err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	f.env.h.DataTransfer = policy.NewDataTransferService(policy.NewSecurityPolicyService(f.env.db))

	w := f.get(fmt.Sprintf("/api/v1/db-console/sessions/%d/results/%s/export", f.sessionID, ev))
	if w.Code != http.StatusForbidden {
		t.Fatalf("政策關閉時狀態碼 = %d，期望 403（body=%s）", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), string(apierror.CodeTransferDenied)) {
		t.Errorf("回應未帶 %s：%s", apierror.CodeTransferDenied, w.Body.String())
	}

	found := false
	for _, row := range f.env.auditRows(t) {
		var body map[string]any
		if json.Unmarshal([]byte(row.RequestBody), &body) != nil {
			continue
		}
		if body["kind"] != consoleKindResultExport || row.Status != model.StatusDenied {
			continue
		}
		if body["reason"] == "global_policy" && body["event_id"] == ev {
			found = true
			if row.Action != model.ActionFileDownload || row.Resource != model.ResourceFile {
				t.Errorf("拒絕列的 action/resource = %s/%s", row.Action, row.Resource)
			}
		}
	}
	if !found {
		t.Errorf("政策拒絕未留痕（審計列 %d 筆）", len(f.env.auditRows(t)))
	}
}

// TestConsoleExportSuccessAuditFacts 成功列的欄位：大小、摘要、事件識別、結果集序號
func TestConsoleExportSuccessAuditFacts(t *testing.T) {
	f := newExportFixture(t, 1)
	ev := f.putUnit(t, 3, sampleSet([]string{"1", "a"}, []string{"2", "b"}))

	w := f.get(fmt.Sprintf("/api/v1/db-console/sessions/%d/results/%s/export", f.sessionID, ev))
	if w.Code != http.StatusOK {
		t.Fatalf("狀態碼 = %d（body=%s）", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Content-Type"); got != "text/csv; charset=utf-8" {
		t.Errorf("Content-Type = %q", got)
	}
	if cd := w.Header().Get("Content-Disposition"); !strings.Contains(cd, "target-db-3-") {
		t.Errorf("Content-Disposition = %q，未見資產名與單位序號", cd)
	}
	// UTF-8 無 BOM
	if bytes.HasPrefix(w.Body.Bytes(), []byte{0xEF, 0xBB, 0xBF}) {
		t.Errorf("CSV 帶了 BOM")
	}

	var body map[string]any
	found := false
	for _, row := range f.env.auditRows(t) {
		if json.Unmarshal([]byte(row.RequestBody), &body) != nil {
			continue
		}
		if body["kind"] == consoleKindResultExport && row.Status == model.StatusSuccess {
			found = true
			if body["event_id"] != ev {
				t.Errorf("event_id = %v，期望 %s", body["event_id"], ev)
			}
			if body["set_index"] != float64(0) {
				t.Errorf("set_index = %v", body["set_index"])
			}
			if body["rows"] != float64(2) {
				t.Errorf("rows = %v", body["rows"])
			}
			if n, ok := body["size"].(float64); !ok || int(n) != w.Body.Len() {
				t.Errorf("size = %v，實際送出 %d 位元組", body["size"], w.Body.Len())
			}
			if s, ok := body["sha256"].(string); !ok || len(s) != 64 {
				t.Errorf("sha256 = %v", body["sha256"])
			}
			if fn, ok := body["filename"].(string); !ok || !strings.HasSuffix(fn, ".csv") {
				t.Errorf("filename = %v", body["filename"])
			}
		}
	}
	if !found {
		t.Fatalf("成功匯出未留痕")
	}
}

// TestConsoleCSVCellFormulaEscaping 防公式注入的逐格判定。
//
// 豁免那一半與轉義那一半同等重要：把 `-5` 寫成 `'-5` 會讓數值欄在試算表裡變成
// 文字，而「數值在畫面與 CSV 逐字元相同」是這個產品對稽核的承諾之一
func TestConsoleCSVCellFormulaEscaping(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{`=cmd|' /C calc'!A0`, `'=cmd|' /C calc'!A0`},
		{`+1+1`, `'+1+1`},
		{`@SUM(A1)`, `'@SUM(A1)`},
		{"\tx", "'\tx"},
		{"\rx", "'\rx"},
		{`-cmd`, `'-cmd`},
		{`-5`, `-5`},
		{`-5.25`, `-5.25`},
		{`1e10`, `1e10`},
		{`-1.5e-10`, `-1.5e-10`},
		{`9223372036854775807`, `9223372036854775807`},
		{``, ``},
		{`plain`, `plain`},
	}
	for _, tc := range cases {
		if got := consoleCSVCell(tc.in); got != tc.want {
			t.Errorf("consoleCSVCell(%q) = %q，期望 %q", tc.in, got, tc.want)
		}
	}
}

// TestConsoleExportEscapesMaliciousCellsEndToEnd 惡意儲存格經整條匯出路徑後仍帶前綴
func TestConsoleExportEscapesMaliciousCellsEndToEnd(t *testing.T) {
	f := newExportFixture(t, 1)
	set := sampleSet(
		[]string{"=cmd|' /C calc'!A0", "-5"},
		[]string{"@SUM(A1)", "+1+1"},
	)
	ev := f.putUnit(t, 1, set)

	w := f.get(fmt.Sprintf("/api/v1/db-console/sessions/%d/results/%s/export", f.sessionID, ev))
	if w.Code != http.StatusOK {
		t.Fatalf("狀態碼 = %d", w.Code)
	}
	records, err := csv.NewReader(strings.NewReader(w.Body.String())).ReadAll()
	if err != nil {
		t.Fatalf("CSV 解析失敗: %v\n%s", err, w.Body.String())
	}
	if len(records) != 3 {
		t.Fatalf("列數 = %d，期望 1 列表頭 + 2 列資料", len(records))
	}
	want := [][]string{
		{"'=cmd|' /C calc'!A0", "-5"},
		{"'@SUM(A1)", "'+1+1"},
	}
	for i, row := range want {
		for j := range row {
			if records[i+1][j] != row[j] {
				t.Errorf("第 %d 列第 %d 欄 = %q，期望 %q", i+1, j, records[i+1][j], row[j])
			}
		}
	}
}

// consoleFailingWriter 寫到第 afterN 個位元組之後就壞掉的回應面（模擬客戶端中途離開）
type consoleFailingWriter struct {
	gin.ResponseWriter
	afterN int
	n      int
}

func (w *consoleFailingWriter) Write(p []byte) (int, error) {
	if w.n >= w.afterN {
		return 0, errors.New("客戶端已離開")
	}
	n, err := w.ResponseWriter.Write(p)
	w.n += n
	return n, err
}

// TestConsoleExportAbortLeavesFailureAudit 串流中止的痕跡。
//
// 記的是**我方寫進 socket 的**位元組與其摘要，不是客戶端實收的量——
// 後者我方無從得知，宣稱它就是宣稱一件查不到的事
func TestConsoleExportAbortLeavesFailureAudit(t *testing.T) {
	f := newExportFixture(t, 1)
	rows := make([][]string, 0, 400)
	for i := 0; i < 400; i++ {
		rows = append(rows, []string{fmt.Sprintf("%d", i), strings.Repeat("x", 32)})
	}
	ev := f.putUnit(t, 1, sampleSet(rows...))

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest("GET",
		fmt.Sprintf("/api/v1/db-console/sessions/%d/results/%s/export", f.sessionID, ev), nil)
	c.Params = gin.Params{
		{Key: "id", Value: fmt.Sprintf("%d", f.sessionID)},
		{Key: "event_id", Value: ev},
	}
	c.Set("userID", uint(1))
	c.Set("username", "u1")
	c.Writer = &consoleFailingWriter{ResponseWriter: c.Writer, afterN: 4096}

	f.env.h.HandleDBConsoleExport(c)

	found := false
	for _, row := range f.env.auditRows(t) {
		var body map[string]any
		if json.Unmarshal([]byte(row.RequestBody), &body) != nil {
			continue
		}
		if body["kind"] != consoleKindResultExport || row.Status != model.StatusFailure {
			continue
		}
		found = true
		if body["reason"] != consoleAbortClientOrEncode {
			t.Errorf("reason = %v", body["reason"])
		}
		if body["event_id"] != ev {
			t.Errorf("event_id = %v", body["event_id"])
		}
		sent, ok := body["bytes_sent"].(float64)
		if !ok || sent <= 0 {
			t.Errorf("bytes_sent = %v，中止前確實寫出過位元組就該記下來", body["bytes_sent"])
		}
		if sent >= float64(rec.Body.Len()+4096) {
			t.Errorf("bytes_sent = %v 大於實際寫出量 %d", sent, rec.Body.Len())
		}
		if s, ok := body["sha256_sent"].(string); !ok || len(s) != 64 {
			t.Errorf("sha256_sent = %v", body["sha256_sent"])
		}
	}
	if !found {
		t.Fatalf("串流中止未留痕")
	}
}

// TestConsoleExportEachBatchIsAddressable 多批次送出時每個批次各自可匯出。
//
// 定址鍵是 `(event_id, set_index)`：MSSQL 的一次送出可能是好幾個批次，
// 每個批次有自己的事件識別，匯出不能只給得到最後一個
func TestConsoleExportEachBatchIsAddressable(t *testing.T) {
	f := newExportFixture(t, 1)
	ev1 := f.putUnit(t, 1, sampleSet([]string{"1", "first"}))
	ev2 := f.putUnit(t, 2, sampleSet([]string{"2", "second"}),
		sampleSet([]string{"3", "second-set-two"}))

	for _, tc := range []struct {
		ev    string
		query string
		want  string
	}{
		{ev1, "", "first"},
		{ev2, "", "second"},
		{ev2, "?set=1", "second-set-two"},
	} {
		w := f.get(fmt.Sprintf("/api/v1/db-console/sessions/%d/results/%s/export%s",
			f.sessionID, tc.ev, tc.query))
		if w.Code != http.StatusOK {
			t.Fatalf("event=%s query=%q 狀態碼 = %d", tc.ev, tc.query, w.Code)
		}
		if !strings.Contains(w.Body.String(), tc.want) {
			t.Errorf("event=%s query=%q 的 CSV 未含 %q：%s", tc.ev, tc.query, tc.want, w.Body.String())
		}
	}
}

// TestConsoleExportRoundTripsExactText 逐字元往返。
//
// 大整數、長 decimal 與帶時區的微秒時戳在畫面上是什麼樣子，在 CSV 裡就得是什麼樣子
func TestConsoleExportRoundTripsExactText(t *testing.T) {
	f := newExportFixture(t, 1)
	values := []string{
		"9223372036854775807",
		"-9223372036854775808",
		"123456789012345678901234567890.123456789",
		"2026-09-02T03:04:05.123456+08:00",
		"NaN",
		"含逗號, 與\"引號\"與\n換行",
	}
	set := dbconsole.ResultSet{SetIndex: 0, RowCount: 1}
	cells := make([]*string, len(values))
	for i := range values {
		set.Columns = append(set.Columns,
			dbconsole.ColumnMeta{Name: fmt.Sprintf("c%d", i), TypeName: "text", Kind: dbconsole.KindText})
		v := values[i]
		cells[i] = &v
	}
	set.Rows = [][]*string{cells}
	ev := f.putUnit(t, 1, set)

	w := f.get(fmt.Sprintf("/api/v1/db-console/sessions/%d/results/%s/export", f.sessionID, ev))
	if w.Code != http.StatusOK {
		t.Fatalf("狀態碼 = %d", w.Code)
	}
	r := csv.NewReader(strings.NewReader(w.Body.String()))
	r.FieldsPerRecord = -1
	records, err := r.ReadAll()
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("CSV 解析失敗: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("列數 = %d", len(records))
	}
	for i, want := range values {
		if records[1][i] != want {
			t.Errorf("第 %d 欄往返後 = %q，期望 %q", i, records[1][i], want)
		}
	}
}

// TestConsoleExportNullIsEmptyField NULL 是空欄，不是字面的 "NULL"
func TestConsoleExportNullIsEmptyField(t *testing.T) {
	f := newExportFixture(t, 1)
	v := "present"
	set := dbconsole.ResultSet{SetIndex: 0, RowCount: 1,
		Columns: []dbconsole.ColumnMeta{
			{Name: "a", TypeName: "text", Kind: dbconsole.KindText},
			{Name: "b", TypeName: "text", Kind: dbconsole.KindText},
		},
		Rows: [][]*string{{nil, &v}}}
	ev := f.putUnit(t, 1, set)

	w := f.get(fmt.Sprintf("/api/v1/db-console/sessions/%d/results/%s/export", f.sessionID, ev))
	if w.Code != http.StatusOK {
		t.Fatalf("狀態碼 = %d", w.Code)
	}
	if got := w.Body.String(); got != "a,b\n,present\n" {
		t.Errorf("CSV = %q", got)
	}
}
