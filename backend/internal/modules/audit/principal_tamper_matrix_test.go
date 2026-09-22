package audit

import (
	"context"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
	"strings"
	"testing"
	"time"
)

type principalTamperCase struct {
	name, table, sql, field string
	id                      uint64
}

func projectionTamperCases() []principalTamperCase {
	return []principalTamperCase{
		{"principal_kind", StateTablePrincipals, `UPDATE users SET kind='agent', owner_user_id=1 WHERE id=3`, "kind", 3},
		{"principal_owner", StateTablePrincipals, `UPDATE users SET owner_user_id=3 WHERE id=2`, "owner", 2},
		{"credential_insert", StateTableAgentTokens, `INSERT INTO agent_tokens(id,user_id,name,token_hash,expires_at,created_by) SELECT 99,user_id,'private-insert','replacement',expires_at,created_by FROM agent_tokens WHERE id=1`, "extra", 99},
		{"credential_unrevoke", StateTableAgentTokens, `UPDATE agent_tokens SET revoked_at=NULL WHERE id=1`, "revoked", 1},
		{"credential_replace", StateTableAgentTokens, `UPDATE agent_tokens SET token_hash='replacement' WHERE id=1`, "fingerprint", 1},
		{"credential_extend", StateTableAgentTokens, `UPDATE agent_tokens SET expires_at='2039-01-01T00:00:00Z' WHERE id=1`, "expiry", 1},
	}
}
func principalMatrixSources(t *testing.T, db *gorm.DB) {
	t.Helper()
	oldP, oldA := principalSource, agentTokenSource
	t.Cleanup(func() { principalSource, agentTokenSource = oldP, oldA })
	SetPrincipalSource(func(ctx context.Context, tx *gorm.DB) ([]PrincipalState, error) {
		var rows []struct {
			ID          uint64
			Kind        string
			OwnerUserID *uint64
		}
		err := tx.WithContext(ctx).Table("users").Select("id,kind,owner_user_id").Where("deleted_at IS NULL").Scan(&rows).Error
		out := []PrincipalState{}
		for _, r := range rows {
			out = append(out, PrincipalState{ID: r.ID, Kind: r.Kind, OwnerID: r.OwnerUserID})
		}
		return out, err
	})
	SetAgentTokenSource(func(ctx context.Context, tx *gorm.DB) ([]AgentTokenState, error) {
		var rows []model.AgentToken
		err := tx.WithContext(ctx).Find(&rows).Error
		out := []AgentTokenState{}
		for _, r := range rows {
			out = append(out, AgentTokenState{ID: uint64(r.ID), UserID: uint64(r.UserID), Revoked: r.RevokedAt != nil, Suspended: r.SuspendedAt != nil, Fingerprint: CredentialFingerprint(r.TokenHash), ExpiresAt: r.ExpiresAt})
		}
		return out, err
	})
}
func TestCheckpointTamperMatrixPrincipal(t *testing.T) {
	for _, c := range projectionTamperCases() {
		t.Run(c.name, func(t *testing.T) {
			f := setupRoleFixture(t)
			if err := f.db.AutoMigrate(&model.User{}, &model.AgentToken{}); err != nil {
				t.Fatal(err)
			}
			principalMatrixSources(t, f.db)
			for _, sql := range []string{`INSERT INTO users(id,username,password,kind) VALUES(1,'private-owner','!','human'),(3,'private-human','!','human')`, `INSERT INTO users(id,username,password,kind,owner_user_id) VALUES(2,'private-agent','!','agent',1)`} {
				f.mustExec(t, sql)
			}
			now := time.Now()
			if err := f.db.Create(&model.AgentToken{ID: 1, UserID: 2, Name: "private-token", TokenHash: strings.Repeat("a", 64), ExpiresAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), RevokedAt: &now}).Error; err != nil {
				t.Fatal(err)
			}
			f.sealWithRoles(t)
			for _, r := range f.rec.ReconcileTables(context.Background()) {
				if r.State != RoleStateMatch {
					t.Fatal("baseline mismatch", r)
				}
			}
			f.mustExec(t, c.sql)
			for _, r := range f.rec.ReconcileTables(context.Background()) {
				if r.Table != c.table {
					if r.State != RoleStateMatch {
						t.Fatal("unrelated state changed", r)
					}
					continue
				}
				if r.State != RoleStateMismatch || len(r.Extra) != 1 || elementID(r.Extra[0]) != c.id {
					t.Fatal("tamper not identified", r)
				}
				if c.field == "extra" {
					if len(r.Missing) != 0 {
						t.Fatal("insert has missing row")
					}
				} else if len(r.Missing) != 1 || elementID(r.Missing[0]) != c.id {
					t.Fatal("changed row not identified", r)
				}
				t.Logf("%s: %s mismatch; changed=%s id=%d missing=%d extra=%d", c.name, c.table, c.field, c.id, len(r.Missing), len(r.Extra))
			}
		})
	}
}
func TestStateTableRegistryGuardMissingProjection(t *testing.T) {
	for _, remove := range []string{StateTablePrincipals, StateTableAgentTokens} {
		t.Run(remove, func(t *testing.T) {
			reg := []string{}
			for _, name := range registryTableNames() {
				if name != remove {
					reg = append(reg, name)
				}
			}
			snap := diffStrings(snapshotTestedTables(), reg)
			tamper := diffStrings(tamperCoveredTables(), reg)
			if len(snap) != 1 || snap[0] != remove || len(tamper) != 1 || tamper[0] != remove {
				t.Fatalf("removed registration escaped guard: snapshots=%v matrix=%v", snap, tamper)
			}
			t.Logf("fake registry rejected: missing %s in both directions", remove)
		})
	}
}
