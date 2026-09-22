package api

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func TestAlertRuleDirectionHTTP(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	defer sqlDB.Close()
	if err := db.AutoMigrate(&model.AlertRule{}); err != nil {
		t.Fatal(err)
	}
	svc := audit.NewAlertRuleService(db)
	h := NewAlertRuleHandler(svc)
	r := gin.New()
	r.POST("/alert-rules", h.Create)
	r.PUT("/alert-rules/:id", h.Update)
	good, err := svc.Create(&audit.AlertRuleRequest{Name: "original", Pattern: "x", Severity: "high"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, body string }{
		{"unknown", `{"name":"bad","pattern":"x","severity":"high","direction":"sideways"}`},
		{"output_block", `{"name":"bad","pattern":"x","severity":"high","direction":"output","action":"block"}`},
	} {
		for _, method := range []string{"POST", "PUT"} {
			t.Run(tc.name+method, func(t *testing.T) {
				path := "/alert-rules"
				if method == "PUT" {
					path += "/1"
				}
				req := httptest.NewRequest(method, path, strings.NewReader(tc.body))
				req.Header.Set("Content-Type", "application/json")
				w := httptest.NewRecorder()
				r.ServeHTTP(w, req)
				if w.Code != 400 {
					t.Fatalf("status %d: %s", w.Code, w.Body.String())
				}
				var rows []model.AlertRule
				db.Find(&rows)
				if len(rows) != 1 || rows[0].ID != good.ID || rows[0].Name != "original" || rows[0].Direction != "input" {
					t.Fatalf("rejected request wrote: %+v", rows)
				}
			})
		}
	}
}
