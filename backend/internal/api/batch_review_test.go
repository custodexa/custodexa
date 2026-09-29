package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

const testBatchID = "6f1c2a0e-8a4b-4c1d-9e2f-0a1b2c3d4e5f"

func postAlertReview(router http.Handler, id, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "/command-alerts/"+id+"/review", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func batchRespCode(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	return body.Code
}

// TestBatchDecisionPartialFailureReportsPerID 同一批逐筆送出時，每一筆各自得到自己的結果。
//
// 擋的威脅：一筆被拒（已審閱、本人觸發、理由不合）被混成整批失敗或整批成功，
// 使用者因此誤判哪些告警實際已結案。另確認不帶批次關聯碼的單筆審閱（含重新審閱）走原路徑。
func TestBatchDecisionPartialFailureReportsPerID(t *testing.T) {
	svc := new(MockCommandAlertService)
	svc.On("ReviewInBatch", uint(1), mock.Anything, "benign", "換筆電").Return(nil)
	svc.On("ReviewInBatch", uint(2), mock.Anything, "benign", "換筆電").Return(audit.ErrAlertAlreadyReviewed)
	svc.On("ReviewInBatch", uint(3), mock.Anything, "benign", "換筆電").Return(audit.ErrAlertSelfTriggered)
	svc.On("ReviewInBatch", uint(4), mock.Anything, "benign", "").Return(audit.ErrAlertBatchNote)
	svc.On("Review", uint(2), mock.Anything, "escalated", "複查改判").Return(nil)

	router := setupTestRouter()
	router.POST("/command-alerts/:id/review", NewCommandAlertHandler(svc).Review)

	batch := `{"disposition":"benign","note":"換筆電","batch_id":"` + testBatchID + `"}`
	want := map[string]struct {
		status int
		code   string
	}{
		"1": {http.StatusOK, ""},
		"2": {http.StatusConflict, "CONFLICT_ALERT_ALREADY_REVIEWED"},
		"3": {http.StatusForbidden, "RULE_ALERT_BATCH_SELF_TRIGGERED"},
	}
	for _, id := range []string{"1", "2", "3"} {
		w := postAlertReview(router, id, batch)
		assert.Equal(t, want[id].status, w.Code, "alert %s", id)
		if want[id].code != "" {
			assert.Equal(t, want[id].code, batchRespCode(t, w), "alert %s", id)
		}
	}
	w := postAlertReview(router, "4", `{"disposition":"benign","note":"","batch_id":"`+testBatchID+`"}`)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, "VALIDATION_ALERT_BATCH_NOTE", batchRespCode(t, w))

	// 單筆重新審閱：不帶 batch_id 走 Review，不受批次條件影響
	w = postAlertReview(router, "2", `{"disposition":"escalated","note":"複查改判"}`)
	assert.Equal(t, http.StatusOK, w.Code)

	// 單筆理由超過上限：與批次同一個錯誤碼（理由會進稽核列，兩條路徑同一上限）
	svc.On("Review", uint(5), mock.Anything, "benign", "過長").Return(audit.ErrAlertNoteTooLong)
	w = postAlertReview(router, "5", `{"disposition":"benign","note":"過長"}`)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, "VALIDATION_ALERT_BATCH_NOTE", batchRespCode(t, w))
	svc.AssertExpectations(t)
}

// TestBatchIDMustBeWellFormed 批次關聯碼只收固定格式，四個可批次的端點一致。
//
// 擋的威脅：以任意字串（超長、夾控制字元）當關聯碼時處置照常生效，稽核面拿它辨認
// 同批就不可靠。格式不合時整筆拒收、不做任何處置，所以帶著處置結果的每一列，
// 關聯碼都是合格式的（被拒的請求列仍照實記下送來的內容，與其他欄位相同）。
func TestBatchIDMustBeWellFormed(t *testing.T) {
	alertSvc := new(MockCommandAlertService)
	router := setupTestRouter()
	router.POST("/command-alerts/:id/review", NewCommandAlertHandler(alertSvc).Review)
	w := postAlertReview(router, "1", `{"disposition":"benign","note":"x","batch_id":"not-a-uuid"}`)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	alertSvc.AssertNotCalled(t, "ReviewInBatch", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	alertSvc.AssertNotCalled(t, "Review", mock.Anything, mock.Anything, mock.Anything, mock.Anything)

	reqSvc := new(MockAccessRequestService)
	r, _ := newAccessRequestRouter(reqSvc, new(MockApproverScopeService), 9, "user", nil)
	bad := map[string]interface{}{"note": "本週凍結", "disposition": "confirmed", "batch_id": strings.Repeat("a", 80)}
	for _, path := range []string{"/access-requests/5/approve", "/access-requests/5/reject", "/access-requests/5/review"} {
		w := doJSON(r, "POST", path, bad)
		assert.Equal(t, http.StatusBadRequest, w.Code, path)
	}
	reqSvc.AssertNotCalled(t, "Approve", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	reqSvc.AssertNotCalled(t, "Reject", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	reqSvc.AssertNotCalled(t, "Review", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)

	// 分塊傳輸（沒有 Content-Length）送來的 body 同樣要驗：核准端點允許空 body，
	// 但不能因為長度未知就把有內容的 body 當成空的、略過格式檢查直接核准
	chunked := func(r http.Handler, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/access-requests/5/approve", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.ContentLength = -1
		req.TransferEncoding = []string{"chunked"}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}
	w = chunked(r, `{"note":"本週凍結","batch_id":"not-a-uuid"}`)
	assert.Equal(t, http.StatusBadRequest, w.Code, "chunked 格式不合的 batch_id")
	reqSvc.AssertNotCalled(t, "Approve", mock.Anything, mock.Anything, mock.Anything, mock.Anything)

	// 反向：分塊傳輸的空 body 仍照申請值核准；合格的 body 內容確實被讀到
	okSvc := new(MockAccessRequestService)
	okSvc.On("Approve", uint(9), false, uint(5), authz.DecideInput{}).
		Return(&model.AccessRequest{ID: 5, Status: model.AccessRequestApproved}, nil).Once()
	okSvc.On("Approve", uint(9), false, uint(5), authz.DecideInput{Note: "本週凍結"}).
		Return(&model.AccessRequest{ID: 5, Status: model.AccessRequestApproved}, nil).Once()
	okRouter, _ := newAccessRequestRouter(okSvc, new(MockApproverScopeService), 9, "user", nil)
	assert.Equal(t, http.StatusOK, chunked(okRouter, "").Code, "chunked 空 body")
	assert.Equal(t, http.StatusOK,
		chunked(okRouter, `{"note":"本週凍結","batch_id":"`+testBatchID+`"}`).Code, "chunked 合格 body")
	okSvc.AssertExpectations(t)
}
