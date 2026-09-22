package audit_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"testing"
	"time"
)

type selfServiceSigner struct{ key ed25519.PrivateKey }

func (s selfServiceSigner) Verify(version int, data []byte, sig string) (bool, error) {
	decoded, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return false, err
	}
	return version == 1 && ed25519.Verify(s.key.Public().(ed25519.PublicKey), data, decoded), nil
}
func (s selfServiceSigner) ActiveVersion() int { return 1 }
func (s selfServiceSigner) Sign(b []byte) (int, string) {
	return 1, base64.StdEncoding.EncodeToString(ed25519.Sign(s.key, b))
}
func TestSnapshotPrincipalSelfService(t *testing.T) {
	db := projectionDB(t)
	if err := db.AutoMigrate(&model.SecurityPolicy{}, &model.AuditLog{}, &model.Role{}, &model.UserRole{}, &model.AuditCheckpoint{}, &model.IntegrityBaseline{}, &model.AgentToolCall{}); err != nil {
		t.Fatal(err)
	}
	audit.SetUserRolesSource(identity.SnapshotUserRolePairs)
	owner := model.User{Username: "snapshot-owner", Password: "!", Kind: model.KindHuman, Active: true}
	if err := db.Create(&owner).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := policy.NewSecurityPolicyService(db).Update(policy.PolicyAgentSelfCreateEnabled, "true", "test"); err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&model.IntegrityBaseline{ID: 1, BaselineAt: time.Now()}).Error; err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cpService := audit.NewCheckpointService(db, selfServiceSigner{key}, nil, nil)
	if err := cpService.EnsureGenesis(); err != nil {
		t.Fatal(err)
	}
	agent, err := identity.NewUserService(db, nil).CreateMyAgent(gatewayapi.Actor{UserID: owner.ID}, identity.CreateMyAgentRequest{Username: "snapshot-self-agent", Purpose: "snapshot check"})
	if err != nil {
		t.Fatal(err)
	}
	reconciler := audit.NewRoleStateReconciler(db, nil)
	reports := reconciler.ReconcileTables(context.Background())
	for _, table := range reports {
		if table.Table == audit.StateTablePrincipals && table.State != audit.RoleStateMatch {
			t.Fatalf("replay mismatch: %+v", table)
		}
	}
	cp, err := cpService.SealNow()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := audit.DecodeStateSnapshotColumn(*cp.RoleStateSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	live, err := audit.SnapshotPrincipals(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range audit.StateTableRegistry() {
		if table.Name == audit.StateTablePrincipals {
			set, err := table.Decode(sealed[table.Name])
			if err != nil {
				t.Fatal(err)
			}
			rebuilt, err := table.Apply(set, nil)
			if err != nil || rebuilt.Hash != live.Hash {
				t.Fatal("sealed snapshot/rebuild differ", err)
			}
		}
	}
	if err := db.Model(agent).Update("owner_user_id", agent.ID).Error; err != nil {
		t.Fatal(err)
	}
	reports = reconciler.ReconcileTables(context.Background())
	found := false
	for _, table := range reports {
		if table.Table == audit.StateTablePrincipals {
			found = true
			if table.State != "mismatch" {
				t.Fatalf("tamper missed: %+v", table)
			}
		}
	}
	if !found {
		t.Fatal("principal projection absent")
	}
}
