package policy

import (
	"github.com/custodexa/backend/internal/model"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"testing"
)

func TestAgentRequestRateLimitPolicy(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err = db.AutoMigrate(&model.SecurityPolicy{}); err != nil {
		t.Fatal(err)
	}
	svc := NewSecurityPolicyService(db)
	for _, tc := range []struct {
		key  string
		want int
		max  int
	}{{PolicyAgentRequestRatePerHour, 30, 10000}, {PolicyAgentRequestPendingMax, 5, 1000}} {
		if got := svc.GetInt(tc.key); got != tc.want {
			t.Fatal(tc.key, got)
		}
		for _, bad := range []string{"0", "-1", "10001", "invalid"} {
			if _, err := svc.Update(tc.key, bad, "test"); err == nil {
				t.Fatal("invalid limit", tc.key, bad)
			}
		}
		if _, err := svc.Update(tc.key, "2", "test"); err != nil {
			t.Fatal(err)
		}
	}
	hourly, pending, err := svc.AgentRequestLimitsInTx(db)
	if err != nil || hourly != 2 || pending != 2 {
		t.Fatal(hourly, pending, err)
	}
}
