package identity

import (
	"errors"
	"fmt"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
	"reflect"
	"testing"
)

func principalEnv(t *testing.T) (*UserService, *AuthService, *gorm.DB, *model.User, *model.User) {
	t.Helper()
	auth, _, db := setupRoleMappingEnv(t)
	if err := db.AutoMigrate(&model.OIDCProvider{}, &model.RoleBindingNode{}, &model.UserExternalIdentity{}); err != nil {
		t.Fatal(err)
	}
	seedMappingRole(t, db, model.RoleApprover)
	owner := &model.User{Username: "human-owner", Password: "!", Kind: model.KindHuman, Active: true}
	if err := db.Create(owner).Error; err != nil {
		t.Fatal(err)
	}
	agent := &model.User{Username: "agent-worker", Password: "!", Kind: model.KindAgent, OwnerUserID: &owner.ID, Active: true}
	if err := db.Create(agent).Error; err != nil {
		t.Fatal(err)
	}
	// 擁有者轉移的防自我授權 port 與生產組裝同形（未注入即 fail-close）；判定會讀
	// 授權規則與審核範圍兩表
	if err := db.AutoMigrate(&model.Asset{}, &model.AssetGroup{}, &model.AssetAuthorization{}, &model.ApproverScope{},
		&model.AccessRequest{}, &model.AccessRequestItem{}, &model.AccessRequestApproval{}); err != nil {
		t.Fatal(err)
	}
	users := NewUserService(db, authz.NewAssetAuthorizationService(db))
	users.SetOwnerTransferGuard(authz.SelfGrantGuard{})
	return users, auth, db, owner, agent
}
func principalCount(t *testing.T, db *gorm.DB, value any) int64 {
	t.Helper()
	var n int64
	if err := db.Model(value).Count(&n).Error; err != nil {
		t.Fatal(err)
	}
	return n
}
func TestCreateAgentPrincipal(t *testing.T) {
	for _, name := range []string{"missing owner", "owner agent", "owner inactive", "password"} {
		t.Run(name, func(t *testing.T) {
			users, _, db, owner, agent := principalEnv(t)
			req := &CreateUserRequest{Username: "new-agent", Kind: model.KindAgent, OwnerUserID: &owner.ID}
			want := error(ErrAgentOwnerRequired)
			switch name {
			case "missing owner":
				req.OwnerUserID = nil
			case "owner agent":
				req.OwnerUserID = &agent.ID
			case "owner inactive":
				if err := db.Model(owner).Update("active", false).Error; err != nil {
					t.Fatal(err)
				}
			case "password":
				req.Password = "Password12345"
				want = ErrAgentPassword
			}
			before := principalCount(t, db, &model.User{})
			if _, err := users.Create(req); !errors.Is(err, want) {
				t.Fatalf("err=%v want %v", err, want)
			}
			if principalCount(t, db, &model.User{}) != before {
				t.Fatal("rejected create wrote user")
			}
		})
	}
	t.Run("valid", func(t *testing.T) {
		users, _, _, owner, _ := principalEnv(t)
		u, err := users.Create(&CreateUserRequest{Username: "new-agent", Kind: model.KindAgent, OwnerUserID: &owner.ID, Roles: []string{model.RoleUser}})
		if err != nil {
			t.Fatal(err)
		}
		if u.Kind != model.KindAgent || u.OwnerUserID == nil || *u.OwnerUserID != owner.ID || u.MustChangePassword || u.Password != "!" {
			t.Fatalf("invalid agent: kind=%s owner=%v forced=%v", u.Kind, u.OwnerUserID, u.MustChangePassword)
		}
	})
}
func TestPrincipalKindImmutable(t *testing.T) {
	users, _, db, owner, agent := principalEnv(t)
	for _, u := range []*model.User{owner, agent} {
		next := model.KindAgent
		if u.Kind == model.KindAgent {
			next = model.KindHuman
		}
		_, _, err := users.Update(u.ID, &UpdateUserRequest{Kind: &next})
		if !errors.Is(err, ErrPrincipalKindImmutable) {
			t.Fatalf("change %s: %v", u.Kind, err)
		}
		var after model.User
		if err := db.First(&after, u.ID).Error; err != nil {
			t.Fatal(err)
		}
		if after.Kind != u.Kind {
			t.Fatal("kind changed")
		}
	}
	other := &model.User{Username: "other-owner", Password: "!", Active: true}
	if err := db.Create(other).Error; err != nil {
		t.Fatal(err)
	}
	updated, _, err := users.Update(agent.ID, &UpdateUserRequest{OwnerUserID: &other.ID})
	if err != nil || updated.OwnerUserID == nil || *updated.OwnerUserID != other.ID {
		t.Fatalf("owner update: %v", err)
	}
	if _, _, err = users.Update(owner.ID, &UpdateUserRequest{OwnerUserID: &other.ID}); !errors.Is(err, ErrAgentOwnerRequired) {
		t.Fatalf("human owner update: %v", err)
	}
}
func TestDeleteOwnerWithAgentsRejected(t *testing.T) {
	users, _, db, owner, agent := principalEnv(t)
	var refusal *PrincipalError
	if err := users.Delete(owner.ID); !errors.As(err, &refusal) || !reflect.DeepEqual(refusal.AgentIDs, []uint{agent.ID}) {
		t.Fatalf("delete error=%v", err)
	}
	for _, id := range []uint{owner.ID, agent.ID} {
		var u model.User
		if err := db.First(&u, id).Error; err != nil {
			t.Fatalf("principal deleted: %v", err)
		}
	}
}
func TestUserListExcludesAgentsByDefault(t *testing.T) {
	users, _, _, _, agent := principalEnv(t)
	req := ListUsersRequest{}
	if req.IncludeAgents {
		t.Fatal("zero-value request includes agents")
	}
	res, err := users.List(&req)
	if err != nil {
		t.Fatal(err)
	}
	if res.Total != 1 || len(res.Data) != 1 || res.Data[0].Kind != model.KindHuman {
		t.Fatalf("default=%+v", res)
	}
	req.IncludeAgents = true
	res, err = users.List(&req)
	if err != nil {
		t.Fatal(err)
	}
	if res.Total != 2 {
		t.Fatalf("explicit include total=%d agent=%d", res.Total, agent.ID)
	}
}
func TestAgentPrincipalCannotLogin(t *testing.T) {
	for _, path := range []string{"local", "ldap"} {
		t.Run(path, func(t *testing.T) {
			_, auth, db, _, agent := principalEnv(t)
			hashed, err := crypto.DefaultPasswordHasher().Hash([]byte("Password12345"))
			if err != nil {
				t.Fatal(err)
			}
			if err := db.Model(agent).Updates(map[string]any{"password": hashed, "is_ldap": path == "ldap"}).Error; err != nil {
				t.Fatal(err)
			}
			// A successful directory authenticator is available; denial must come from principal kind.
			auth.SetLDAPResolver(func() LDAPLoginResolution {
				return LDAPLoginResolution{State: LDAPLoginReady, Auth: &fakeLDAPAuthenticator{info: &LDAPUserInfo{Username: agent.Username}}}
			})
			resp, err := auth.Login(&LoginRequest{Username: agent.Username, Password: "Password12345"})
			if !errors.Is(err, ErrInvalidCredentials) || resp != nil {
				t.Fatalf("login response=%v error=%v", resp, err)
			}
			if principalCount(t, db, &model.RefreshToken{}) != 0 {
				t.Fatal("refresh credential issued")
			}
		})
	}
	t.Run("oidc callback", func(t *testing.T) {
		login, _, idp, p := setupLiveFlow(t)
		db := login.db
		owner := seedOIDCUser(t, db, "owner")
		agent := seedOIDCUser(t, db, "robot")
		if err := db.Model(agent).Updates(map[string]any{"kind": model.KindAgent, "owner_user_id": owner.ID}).Error; err != nil {
			t.Fatal(err)
		}
		seedIdentity(t, db, agent, p, "agent-subject")
		resp, err := oidcLoginOnce(t, login, idp, p, "agent-code", "agent-subject", mappingClaims(nil))
		if !errors.Is(err, ErrOIDCFlowInvalid) || resp != nil {
			t.Fatalf("callback response=%v error=%v", resp, err)
		}
		if principalCount(t, db, &model.RefreshToken{}) != 0 || principalCount(t, db, &model.OIDCLoginTicket{}) != 0 {
			t.Fatal("intermediate or refresh credential issued")
		}
	})
	t.Run("password and MFA", func(t *testing.T) {
		users, _, db, _, agent := principalEnv(t)
		auth := newMFAAuthService(t)
		for _, tc := range []struct {
			name string
			run  func() error
		}{
			{"admin password", func() error { return users.ChangePassword(agent.ID, "NewPassword12345") }},
			{"self password", func() error { return users.SelfChangePassword(agent.ID, "old", "NewPassword12345") }},
			{"MFA registration", func() error { _, err := auth.GenerateMFASetup(agent.ID); return err }},
			{"MFA verification", func() error { return auth.VerifyMFACode(agent.ID, "123456") }},
		} {
			t.Run(tc.name, func(t *testing.T) {
				if err := tc.run(); !errors.Is(err, ErrAgentHumanOnly) {
					t.Fatalf("err=%v", err)
				}
			})
		}
		var stored model.User
		if err := db.First(&stored, agent.ID).Error; err != nil {
			t.Fatal(err)
		}
		if stored.MustChangePassword || stored.TOTPSecretEnc != "" || stored.Password != "!" {
			t.Fatal("password/MFA state changed")
		}
		if principalCount(t, db, &model.RefreshToken{}) != 0 {
			t.Fatal("refresh issued")
		}
	})
}
func principalRoleRows(t *testing.T, db *gorm.DB, uid uint) []model.UserRole {
	t.Helper()
	var rows []model.UserRole
	if err := db.Where("user_id = ?", uid).Order("role_id").Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	return rows
}
func TestAgentRoleGuard(t *testing.T) {
	for _, path := range []string{"AssignRoles", "AddRole", "PinMappedRole"} {
		for _, role := range []string{model.RoleAdmin, model.RoleAuditor, model.RoleApprover, model.RoleUser} {
			t.Run(path+"/"+role, func(t *testing.T) {
				users, _, db, _, agent := principalEnv(t)
				id := seedMappingRole(t, db, role)
				if path == "PinMappedRole" {
					setupRoleState(t, db, agent.ID, id, model.RoleSourceMapped, "provider:1")
				}
				before := principalRoleRows(t, db, agent.ID)
				var err error
				switch path {
				case "AssignRoles":
					_, err = users.AssignRoles(agent.ID, []string{role})
				case "AddRole":
					err = users.AddRole(agent.ID, role)
				case "PinMappedRole":
					_, err = users.PinMappedRole(agent.ID, role)
				}
				if role != model.RoleUser {
					if !errors.Is(err, ErrAgentRoleForbidden) {
						t.Fatalf("error=%v", err)
					}
					if !reflect.DeepEqual(before, principalRoleRows(t, db, agent.ID)) {
						t.Fatal("rejected roles changed")
					}
				} else {
					if err != nil {
						t.Fatal(err)
					}
					if got := principalRoleRows(t, db, agent.ID); len(got) != 1 || got[0].RoleID != id {
						t.Fatalf("normal role missing: %v", got)
					}
				}
			})
		}
	}
	t.Run("能力類別", agentRoleGuardCapabilitySubtests)
}

// agentRoleGuardCapabilitySubtests 依能力類別判定的子測試（能力類別），由 TestAgentRoleGuard 呼叫：
// 角色的內建識別與權限點類別決定能否指派給 agent，角色名稱不是依據。
func agentRoleGuardCapabilitySubtests(t *testing.T) {
	// 環境已有四個內建角色列；rename 非空時先把該內建範本的列改名（識別不變，名稱不再是內建名）
	assign := func(t *testing.T, builtinKey, rename string) error {
		users, _, db, _, agent := principalEnv(t)
		var role model.Role
		if err := db.Where("builtin_key = ?", builtinKey).First(&role).Error; err != nil {
			t.Fatal(err)
		}
		if rename != "" {
			if err := db.Model(&role).Update("name", rename).Error; err != nil {
				t.Fatal(err)
			}
			role.Name = rename
		}
		return users.AddRole(agent.ID, role.Name)
	}

	t.Run("持管理類權限點的角色（內建超管範本，名稱非內建名）被拒", func(t *testing.T) {
		if err := assign(t, model.BuiltinSuperAdmin, "ops-root"); !errors.Is(err, ErrAgentRoleForbidden) {
			t.Fatalf("error=%v", err)
		}
	})
	t.Run("持稽核類權限點的角色（內建稽核員範本，名稱非內建名）被拒", func(t *testing.T) {
		if err := assign(t, model.BuiltinAuditor, "night-watch"); !errors.Is(err, ErrAgentRoleForbidden) {
			t.Fatalf("error=%v", err)
		}
	})
	t.Run("追加審核者被拒", func(t *testing.T) {
		if err := assign(t, model.BuiltinApprover, ""); !errors.Is(err, ErrAgentRoleForbidden) {
			t.Fatalf("error=%v", err)
		}
	})
	t.Run("一般使用者可指派", func(t *testing.T) {
		if err := assign(t, model.BuiltinUser, ""); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("名稱叫 admin 但不是內建範本的角色不因名稱被拒（判定依能力類別）", func(t *testing.T) {
		users, _, db, _, agent := principalEnv(t)
		// 把內建超管範本改名讓出名稱，再以原始 SQL 寫入同名的非內建角色（繞過保留名稱的寫入規則）；
		// 目前非內建角色沒有權限點存放處，能力集合為空
		if err := db.Model(&model.Role{}).Where("builtin_key = ?", model.BuiltinSuperAdmin).Update("name", "ops-root").Error; err != nil {
			t.Fatal(err)
		}
		if err := db.Exec("INSERT INTO roles (name, description, created_at, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)", model.RoleAdmin, "name only").Error; err != nil {
			t.Fatal(err)
		}
		if err := users.AddRole(agent.ID, model.RoleAdmin); err != nil {
			t.Fatalf("非內建角色（能力集合為空）應可指派: %v", err)
		}
	})
	t.Run("權限點類別判定：含管理、稽核、審核類即受限，基本類不受限", func(t *testing.T) {
		if !authz.CapabilityRestrictedForAgent([]authz.Permission{authz.PermAssetView, authz.PermAlertRuleManage}) {
			t.Fatal("含管理類權限點的集合應受限")
		}
		if !authz.CapabilityRestrictedForAgent([]authz.Permission{authz.PermAuditView}) {
			t.Fatal("含稽核類權限點的集合應受限")
		}
		if authz.CapabilityRestrictedForAgent([]authz.Permission{authz.PermAssetView}) {
			t.Fatal("僅基本類權限點的集合不應受限")
		}
		if !authz.CapabilityRestrictedForAgent([]authz.Permission{"unknown:perm"}) {
			t.Fatal("目錄外的權限點應 fail-closed 視為受限")
		}
	})
}

func TestMappedRoleRecomputeGuardsAgent(t *testing.T) {
	for _, role := range []string{model.RoleAdmin, model.RoleAuditor, model.RoleApprover, model.RoleUser} {
		t.Run(role, func(t *testing.T) {
			_, _, db, _, agent := principalEnv(t)
			// Exercise the write path even if an agent was bound to an external identity.
			agent.ExternalCredential = true
			if err := db.Model(agent).Update("external_credential", true).Error; err != nil {
				t.Fatal(err)
			}
			seedProviderMappingRule(t, db, 1, "matched", role)
			before := principalRoleRows(t, db, agent.ID)
			_, err := RecomputeMappedRoles(db, audit.NewTxSink(), agent, GroupObservation{Kind: model.RoleMappingChannelKindProvider, SourceID: 1, State: GroupObservationKnown, Groups: []string{"matched"}})
			if role != model.RoleUser {
				if !errors.Is(err, ErrAgentRoleForbidden) {
					t.Fatalf("error=%v", err)
				}
				if !reflect.DeepEqual(before, principalRoleRows(t, db, agent.ID)) {
					t.Fatal("rejected mapping changed roles")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if got := userRolesOf(t, db, agent.ID); !reflect.DeepEqual(got, []string{model.RoleUser}) {
					t.Fatal(fmt.Sprint(got))
				}
			}
		})
	}
}
