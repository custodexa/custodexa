package api

import (
	"encoding/json"
	"fmt"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAlertRuleSubjectKind(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	sql, _ := db.DB()
	sql.SetMaxOpenConns(1)
	defer sql.Close()
	if err := db.AutoMigrate(&model.AlertRule{}); err != nil {
		t.Fatal(err)
	}
	h := NewAlertRuleHandler(audit.NewAlertRuleService(db))
	r := gin.New()
	r.POST("/rules", h.Create)
	r.PUT("/rules/:id", h.Update)
	r.GET("/rules", h.List)
	call := func(method, path, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		q := httptest.NewRequest(method, path, strings.NewReader(body))
		q.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, q)
		return w
	}
	for i, kind := range []string{"all", "human", "agent"} {
		body := fmt.Sprintf(`{"name":"r%d","pattern":"x","severity":"high","subject_kind":%q}`, i, kind)
		w := call("POST", "/rules", body)
		if w.Code != 201 {
			t.Fatal(w.Code, w.Body)
		}
		var rule model.AlertRule
		if err := json.Unmarshal(w.Body.Bytes(), &rule); err != nil || rule.SubjectKind != kind {
			t.Fatal(rule, err)
		}
		w = call("PUT", fmt.Sprintf("/rules/%d", rule.ID), fmt.Sprintf(`{"name":"r%d","pattern":"y","severity":"low"}`, i))
		if w.Code != 200 || !strings.Contains(w.Body.String(), `"subject_kind":"`+kind+`"`) {
			t.Fatal(w.Code, w.Body)
		}
	}
	w := call("POST", "/rules", `{"name":"legacy","pattern":"x","severity":"high"}`)
	if w.Code != 201 || !strings.Contains(w.Body.String(), `"subject_kind":"all"`) {
		t.Fatal(w.Code, w.Body)
	}
	for _, value := range []string{"unknown", "", "ALL"} {
		for _, method := range []string{"POST", "PUT"} {
			path := "/rules"
			if method == "PUT" {
				path += "/1"
			}
			w = call(method, path, fmt.Sprintf(`{"name":"invalid","pattern":"x","severity":"high","subject_kind":%q}`, value))
			if w.Code != 400 {
				t.Fatal(value, method, w.Code)
			}
		}
	}
	var n int64
	db.Model(&model.AlertRule{}).Count(&n)
	if n != 4 {
		t.Fatal(n)
	}
	w = call("GET", "/rules", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"subject_kind":"all"`) {
		t.Fatal(w.Code, w.Body)
	}
}
