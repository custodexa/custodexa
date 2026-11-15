package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
)

// 經 API token 的請求寫下的稽核列：凡帶 token 標示的列，都帶與該次請求相同的請求識別與來源位址，
// 以操作日誌的「同一次請求」篩選能取回該次請求寫下的每一列。

// originRowString 差異列中欄位的字串值（NULL 回空字串）。
func originRowString(row map[string]any, col string) string {
	switch v := row[col].(type) {
	case nil:
		return ""
	case string:
		return v
	case []byte:
		return string(v)
	default:
		return fmt.Sprint(v)
	}
}

// cmpAuditOriginGaps 一次請求新增的稽核列中，帶 token 標示卻缺請求識別或來源位址、或與該次請求的
// 請求列（稽核中介層寫的那一列）不一致的列。requestPath 為請求路徑（不含查詢字串），用來認出請求列；
// 沒有請求列時，以帶標示列中第一個非空的請求識別與來源位址為準，各列必須彼此一致。
func cmpAuditOriginGaps(rows []map[string]any, requestPath string) []string {
	var stamped []map[string]any
	for _, r := range rows {
		if originRowString(r, "api_token_id") != "" {
			stamped = append(stamped, r)
		}
	}
	if len(stamped) == 0 {
		return nil
	}
	wantID, wantIP := "", ""
	for _, r := range stamped {
		if originRowString(r, "path") == requestPath && originRowString(r, "request_id") != "" {
			wantID, wantIP = originRowString(r, "request_id"), originRowString(r, "client_ip")
			break
		}
	}
	if wantID == "" {
		for _, r := range stamped {
			if id := originRowString(r, "request_id"); id != "" {
				wantID, wantIP = id, originRowString(r, "client_ip")
				break
			}
		}
	}
	var gaps []string
	for _, r := range stamped {
		id, ip := originRowString(r, "request_id"), originRowString(r, "client_ip")
		if id != "" && id == wantID && ip != "" && ip == wantIP {
			continue
		}
		gaps = append(gaps, fmt.Sprintf("%s %s（path=%q reason=%q details=%s）request_id=%q client_ip=%q",
			originRowString(r, "action"), originRowString(r, "resource"), originRowString(r, "path"),
			originRowString(r, "reason_code"), clipCmp(originRowString(r, "details")), id, ip))
	}
	sort.Strings(gaps)
	return gaps
}

// cmpAuditUnstamped 一次請求新增、卻不帶 token 標示的稽核列（以 token 送出的請求不應有這種列：
// 這種列不帶標示，也就不會被補上請求識別，以「同一次請求」篩選取不回）。
func cmpAuditUnstamped(rows []map[string]any) []string {
	var out []string
	for _, r := range rows {
		if originRowString(r, "api_token_id") != "" {
			continue
		}
		out = append(out, fmt.Sprintf("%s %s（path=%q details=%s）request_id=%q",
			originRowString(r, "action"), originRowString(r, "resource"), originRowString(r, "path"),
			clipCmp(originRowString(r, "details")), originRowString(r, "request_id")))
	}
	sort.Strings(out)
	return out
}

// requestPathOf 去掉查詢字串的請求路徑。
func requestPathOf(path string) string {
	if i := strings.IndexByte(path, '?'); i >= 0 {
		return path[:i]
	}
	return path
}

// TestAPITokenCreateUserRowsCarryRequestOrigin 以 token 經真的路由與中介層鏈建立使用者（帶角色）：該次請求
// 寫下的每一列（中介層的請求列、交易內的角色指派列與主體狀態列）都帶 token 標示與同一個請求識別、來源位址；
// 以操作日誌的「同一次請求」篩選取回的恰為這些列；逐列完整性驗證碼與補值後的內容相符。
func TestAPITokenCreateUserRowsCarryRequestOrigin(t *testing.T) {
	apiTokenBaselineGate(t)
	e := newBaselineEnv(t)
	super := seedAPITokenPairs(e)[0]
	defer e.apiTokenRuleRestore()

	var br baselineRequest
	found := false
	for _, r := range loadRouteCatalog(t).Routes {
		if routeKey(r) == "POST /api/v1/users" {
			br, found = e.request(r), true
			break
		}
	}
	if !found {
		t.Fatal("路由目錄沒有 POST /api/v1/users")
	}

	lo := e.maxAuditID()
	req := httptest.NewRequest(br.Method, br.Path, bytes.NewReader(br.Body))
	req.Header.Set("Content-Type", "application/json")
	super.token.authorize(req)
	w := e.serve(req)
	awaitBackground(t)
	if w.Code != http.StatusCreated {
		t.Fatalf("token 建立使用者應成功，得到 %d %s", w.Code, w.Body.String())
	}
	hi := e.maxAuditID()
	var rows []model.AuditLog
	if err := e.db.Where("id > ? AND id <= ?", lo, hi).Order("id").Find(&rows).Error; err != nil {
		t.Fatalf("讀取稽核列：%v", err)
	}

	// 前提：請求列、角色指派列與主體狀態列都產生了
	var reqRow *model.AuditLog
	var hasRole, hasPrincipal bool
	for i := range rows {
		r := &rows[i]
		// 角色指派列也帶請求的方法與路徑，先依資源認出交易內的兩種列，其餘帶路徑者為請求列
		switch {
		case r.Resource == model.ResourceUserRole:
			hasRole = true
		case r.Resource == model.ResourceUser && strings.Contains(r.Details, `"state_table"`):
			hasPrincipal = true
		case r.Path == "/api/v1/users" && r.Method == http.MethodPost:
			reqRow = r
		}
	}
	if reqRow == nil || !hasRole || !hasPrincipal {
		t.Fatalf("前提：應有請求列、角色指派列與主體狀態列（稽核列識別 %d..%d）：%s", lo, hi, describeAuditRows(rows))
	}
	if reqRow.RequestID == "" || reqRow.ClientIP == "" {
		t.Fatalf("前提：請求列應帶請求識別與來源位址：%+v", reqRow)
	}

	want := make([]uint, 0, len(rows))
	for _, r := range rows {
		want = append(want, r.ID)
		if r.APITokenID == nil || *r.APITokenID != super.tokenID {
			t.Errorf("列不帶 token 標示：%s", describeAuditRows([]model.AuditLog{r}))
		}
		if r.RequestID != reqRow.RequestID || r.ClientIP != reqRow.ClientIP {
			t.Errorf("列的請求識別或來源位址與請求列不同（request_id=%q client_ip=%q）：%s",
				r.RequestID, r.ClientIP, describeAuditRows([]model.AuditLog{r}))
		}
	}

	t.Run("same_request_filter_returns_every_row", func(t *testing.T) {
		got := e.attachLookupAuditIDs(t, reqRow.RequestID, 100)
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("同一次請求篩選的結果與該次請求寫下的列不同\n  得到 %v\n  應為 %v", got, want)
		}
	})
	t.Run("integrity_covers_filled_values", func(t *testing.T) {
		svc := audit.GetAuditIntegrity()
		if svc == nil {
			t.Fatal("前提：整合環境應裝上逐列完整性")
		}
		for _, r := range rows {
			if r.IntegrityHMAC == "" {
				t.Fatalf("前提：列應已蓋章：%s", describeAuditRows([]model.AuditLog{r}))
			}
		}
		report, err := svc.VerifyIDRange(e.db, lo+1, hi)
		if err != nil {
			t.Fatalf("驗證：%v", err)
		}
		if report.Mismatched != 0 || report.Passed != int64(len(rows)) {
			t.Errorf("逐列完整性應全數相符：通過 %d／%d，不符 %v", report.Passed, len(rows), report.MismatchedIDs)
		}
	})
}
