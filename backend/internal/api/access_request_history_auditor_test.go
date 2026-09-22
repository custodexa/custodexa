package api

import (
	"github.com/custodexa/backend/internal/model"
	"net/http"
	"testing"
)

func TestAccessRequestHistoryAuditor(t *testing.T) {
	e := setupApproverGateEnv(t)
	role := model.Role{Name: model.RoleAuditor}
	if err := e.db.Create(&role).Error; err != nil {
		t.Fatal(err)
	}
	if err := e.db.Exec("INSERT INTO user_roles(user_id,role_id) VALUES (?,?)", 4, role.ID).Error; err != nil {
		t.Fatal(err)
	}
	token := e.token(t, 4, "gate-plain", model.RoleAuditor)
	e.reqSvc.On("ListHistory", uint(4), true, 1, 20).Return([]*model.AccessRequest{}, int64(0), nil).Once()
	if w := e.call(t, http.MethodGet, "/api/v1/access-requests/history", token, nil); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	for _, action := range []string{"approve", "reject", "revoke", "review"} {
		if w := e.call(t, http.MethodPost, "/api/v1/access-requests/1/"+action, token, map[string]any{"note": "audit"}); w.Code != 403 {
			t.Fatal(action, w.Code, w.Body)
		}
	}
	if err := e.db.Exec("DELETE FROM user_roles WHERE user_id=? AND role_id=?", 4, role.ID).Error; err != nil {
		t.Fatal(err)
	}
	if w := e.call(t, http.MethodGet, "/api/v1/access-requests/history", token, nil); w.Code != 403 {
		t.Fatal("stale auditor retained access", w.Code, w.Body)
	}
	e.reqSvc.AssertExpectations(t)
}
