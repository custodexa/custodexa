package identity

import (
	"encoding/json"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
	"golang.org/x/crypto/bcrypt"
)

// 「我的 agent」入口資格：登入回應與 GET /auth/me
// 共用 UserInfo，兩條出口都要帶 owns_agents 與 can_self_create_agent，
// 前端的選單與路由守衛讀的就是這兩欄。
//
// 以 JSON 鍵斷言而非結構欄位：前端拿到的是序列化後的鍵名，
// 欄位存在但 tag 拼錯時前端照樣讀不到。
func TestUserInfoAgentEntryFlags(t *testing.T) {
	cases := []struct {
		name        string
		asOwner     bool // 以 principalEnv 的負責人登入（名下有一個 agent）
		policyOn    bool
		deleteAgent bool
		admin       bool
		wantOwns    bool
		wantCreate  bool
	}{
		{name: "沒有 agent、政策關閉", wantOwns: false, wantCreate: false},
		{name: "負責一個 agent、政策關閉", asOwner: true, wantOwns: true, wantCreate: false},
		{name: "系統管理者負責一個 agent", asOwner: true, admin: true, wantOwns: true, wantCreate: false},
		{name: "沒有 agent、政策開啟", policyOn: true, wantOwns: false, wantCreate: true},
		{name: "負責一個 agent、政策開啟", asOwner: true, policyOn: true, wantOwns: true, wantCreate: true},
		{name: "名下 agent 已刪除即不再算負責", asOwner: true, deleteAgent: true, wantOwns: false, wantCreate: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, auth, db, owner, agent := principalEnv(t)
			hash, err := bcrypt.GenerateFromPassword([]byte("entry-pass-1"), bcrypt.MinCost)
			if err != nil {
				t.Fatal(err)
			}
			solo := &model.User{Username: "solo-human", Password: string(hash), Kind: model.KindHuman, Active: true}
			if err := db.Create(solo).Error; err != nil {
				t.Fatal(err)
			}
			if err := db.Model(owner).Update("password", string(hash)).Error; err != nil {
				t.Fatal(err)
			}
			subject := solo
			if tc.asOwner {
				subject = owner
			}
			if tc.admin {
				if err := db.Exec("INSERT INTO user_roles (user_id, role_id) SELECT ?, id FROM roles WHERE name = ?", subject.ID, model.RoleAdmin).Error; err != nil {
					t.Fatal(err)
				}
			}
			selfPolicy(t, db, policy.PolicyAgentSelfCreateEnabled, map[bool]string{true: "true", false: "false"}[tc.policyOn])
			if tc.deleteAgent {
				if err := db.Delete(agent).Error; err != nil {
					t.Fatal(err)
				}
			}

			resp, err := auth.Login(&LoginRequest{Username: subject.Username, Password: "entry-pass-1"})
			if err != nil {
				t.Fatalf("login: %v", err)
			}
			if resp.Token == "" || resp.User == nil {
				t.Fatalf("login did not issue a session: %+v", resp)
			}
			if tc.admin && !containsString(resp.User.Roles, model.RoleAdmin) {
				t.Fatalf("fixture: admin role not bound, roles=%v", resp.User.Roles)
			}
			assertAgentEntryKeys(t, "登入回應", resp.User, tc.wantOwns, tc.wantCreate)

			me, err := auth.GetUserByID(subject.ID)
			if err != nil {
				t.Fatalf("GetUserByID: %v", err)
			}
			assertAgentEntryKeys(t, "GET /auth/me", me, tc.wantOwns, tc.wantCreate)
		})
	}
}

func assertAgentEntryKeys(t *testing.T, where string, info *UserInfo, wantOwns, wantCreate bool) {
	t.Helper()
	raw, err := json.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]bool{"owns_agents": wantOwns, "can_self_create_agent": wantCreate} {
		got, ok := body[key]
		if !ok {
			t.Errorf("%s 缺少 %q 欄（body=%s）", where, key, raw)
			continue
		}
		if got != want {
			t.Errorf("%s 的 %q = %v，期望 %v", where, key, got, want)
		}
	}
}

func containsString(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
