package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestToolCallQueryPending(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&model.AgentToolCall{}, &model.User{}, &model.UserRole{}); err != nil {
		t.Fatal(err)
	}
	old := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = old })
	for id := uint(1); id <= 2; id++ {
		if err := db.Create(&model.User{ID: id, Username: []string{"", "auditor", "user"}[id], Password: "!", Active: true}).Error; err != nil {
			t.Fatal(err)
		}
	}
	for i, decision := range []string{model.ToolCallPending, model.ToolCallAllowed} {
		if err := db.Exec(`INSERT INTO agent_tool_calls(seq,user_id,agent_token_id,access_request_id,owner_user_id,tool,args_redacted,decision,denial_code,result_status,result_digest,result_excerpt,masked_count,duration_ms,created_at,integrity_hmac,key_version) VALUES(?,9,8,7,1,'run_command','{"asset_id":3}',?,'','','digest','excerpt',0,0,?,'fixture',1)`, i+1, decision, time.Now()).Error; err != nil {
			t.Fatal(err)
		}
	}
	r := gin.New()
	NewAuditIntegrityHandler(db, nil).RegisterRoutes(r.Group("/api/v1"), identity.NewAuthService("ledger-role-test", time.Minute))
	mgr := crypto.NewJWTManager("ledger-role-test", time.Minute)
	for _, tc := range []struct {
		name, query, role string
		id                uint
		status            int
	}{
		{"auditor pending", "?decision=pending&user_id=9&access_request_id=7", model.RoleAuditor, 1, 200},
		{"user denied", "", model.RoleUser, 2, 403},
		{"bad decision", "?decision=not-a-decision", model.RoleAuditor, 1, 400},
		{"bad id", "?access_request_id=0", model.RoleAuditor, 1, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/api/v1/agent-tool-calls"+tc.query, nil)
			req.Header.Set("Authorization", "Bearer "+tokenFor(t, mgr, tc.id, "fixture", tc.role))
			r.ServeHTTP(w, req)
			if w.Code != tc.status {
				t.Fatalf("status=%d body=%s", w.Code, w.Body)
			}
			if tc.status == 200 {
				var got struct {
					Total int
					Data  []struct {
						Decision      string                 `json:"decision"`
						ResultDigest  string                 `json:"result_digest"`
						ResultExcerpt string                 `json:"result_excerpt"`
						Args          map[string]interface{} `json:"args_redacted"`
					}
				}
				if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
					t.Fatal(err)
				}
				if got.Total != 1 || len(got.Data) != 1 || got.Data[0].Decision != model.ToolCallPending || got.Data[0].Args["asset_id"] != float64(3) || got.Data[0].ResultDigest != "digest" || got.Data[0].ResultExcerpt != "excerpt" {
					t.Fatal(w.Body.String())
				}
			}
		})
	}
}
