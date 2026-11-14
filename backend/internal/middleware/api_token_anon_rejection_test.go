package middleware

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/gin-gonic/gin"
)

// API token 認證失敗沿用既有的有界匿名留痕：同一來源大量送不存在、已撤銷、來源不符的 token，
// 逐筆列受限流上界約束，逾界部分進聚合摘要，列上的原因碼可追溯到真實原因；對外一律同一個未認證錯誤碼。
func TestAPITokenAuthFailuresUseBoundedAnonymousAudit(t *testing.T) {
	const shots = 300
	params := anonRejectionParams{
		PerKeyBurst: 5, PerKeyRefill: 6 * time.Second,
		GlobalBurst: 50, GlobalRefill: time.Second,
		AggregateWindow: time.Minute,
	}
	f := newAPITokenGateFixture(t)
	if err := f.db.AutoMigrate(&model.AuditLog{}); err != nil {
		t.Fatal(err)
	}
	old := database.DB
	database.DB = f.db
	t.Cleanup(func() { database.DB = old })
	clock := newAnonTestClock()
	r := gin.New()
	r.Use(AuditLogMiddleware(newAnonAuditService(), withAnonRejectionParams(params), withAnonRejectionClock(clock.Now)),
		AgentRouteAllowlist(f.auth), (&apiTokenGate{auth: f.auth, decide: allowAllAPITokenRoutes}).Handle)
	r.GET("/api/v1/assets", AuthMiddleware(f.auth), func(c *gin.Context) { c.Status(200) })

	shoot := func(token string) {
		for i := 0; i < shots; i++ {
			if w := bearerRequest(r, http.MethodGet, "/api/v1/assets", token); w.Code != http.StatusUnauthorized {
				t.Fatalf("認證失敗應回 401：%d", w.Code)
			}
		}
	}
	// 不存在：格式正確但查無
	unknown := f.plain[:len(f.plain)-4] + "zzzz"
	if unknown == f.plain {
		t.Fatal("測試 token 構造失敗")
	}
	shoot(unknown)
	// 來源不符：所屬帳號限定來源網段，請求來源不在其中
	if err := f.db.Model(&model.User{}).Where("id = ?", f.owner.ID).Update("allowed_cidrs", "10.0.0.0/8").Error; err != nil {
		t.Fatal(err)
	}
	shoot(f.plain)
	if err := f.db.Model(&model.User{}).Where("id = ?", f.owner.ID).Update("allowed_cidrs", "").Error; err != nil {
		t.Fatal(err)
	}
	// 已撤銷
	op := identity.Operator{UserID: f.owner.ID, Username: f.owner.Username,
		Principal: authz.NewPrincipal(f.owner.ID, authz.TokenFacts{SubjectKind: model.KindHuman}, nil)}
	if err := f.tokens.RevokeOwn(op, f.tokenID, ""); err != nil {
		t.Fatal(err)
	}
	shoot(f.plain)

	perRequest := anonRows(t, f.db)
	byReason := map[string]int{}
	for _, row := range perRequest {
		d := anonDetailsOf(t, row)
		if d["event"] != anonEventRejected {
			continue
		}
		reason, _ := d["reason"].(string)
		byReason[reason]++
		if row.APITokenID != nil || row.UserID != 0 {
			t.Fatalf("認證失敗的列不帶身分：user=%d token=%v", row.UserID, row.APITokenID)
		}
		if strings.Contains(row.Details, f.plain) || strings.Contains(row.Details, unknown) {
			t.Fatal("留痕不含 token 明文")
		}
	}
	if len(perRequest) > int(params.GlobalBurst) {
		t.Fatalf("逐筆列 %d 超過全域上界 %.0f", len(perRequest), params.GlobalBurst)
	}
	if byReason[identity.APITokenReasonNotFound] == 0 || byReason[identity.APITokenReasonRevoked] == 0 {
		t.Fatalf("原因碼應可追溯：%v", byReason)
	}
	sourceReason := ""
	for reason, n := range byReason {
		if n > int(params.PerKeyBurst) {
			t.Fatalf("原因 %s 逐筆列 %d 超過同來源上界 %.0f", reason, n, params.PerKeyBurst)
		}
		if reason != identity.APITokenReasonNotFound && reason != identity.APITokenReasonRevoked {
			sourceReason = reason
		}
	}
	if sourceReason == "" {
		t.Fatalf("來源不符應有自己的原因碼：%v", byReason)
	}

	// 窗結束後，三種原因各自的逾界次數落成聚合列
	clock.advance(2 * time.Minute)
	bearerRequest(r, http.MethodGet, "/api/v1/assets", f.plain)
	aggregated := map[string]float64{}
	for _, row := range anonRows(t, f.db) {
		d := anonDetailsOf(t, row)
		if d["event"] == anonEventRejectedAggregate {
			reason, _ := d["reason"].(string)
			n, _ := d["count"].(float64)
			aggregated[reason] += n
		}
	}
	for _, reason := range []string{identity.APITokenReasonNotFound, identity.APITokenReasonRevoked, sourceReason} {
		if want := float64(shots - byReason[reason]); aggregated[reason] < want {
			t.Errorf("原因 %s 的聚合次數 %v, want >= %v", reason, aggregated[reason], want)
		}
	}
	t.Logf("逐筆列 %v；聚合 %v", byReason, aggregated)
}
