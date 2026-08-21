package identity

import (
	"github.com/custodexa/backend/internal/modules/authz"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 使用者列表的來源呈現與篩選（idp-oidc-integration D14.1，批 5 前端所需）。
//
// 「來源」在多 provider 並存下必須是**實例名**（「Azure AD」而非籠統的「OIDC」），
// 且篩選必須在伺服端完成——列表是分頁的，前端篩當頁會讓使用者看到
// 「第 2 頁明明有 oidc 帳號，篩選後卻說沒有」。

// seedSourceFixture 三種來源的帳號各一，其中 OIDC 帳號綁兩個 provider
func seedSourceFixture(t *testing.T, db *gorm.DB) (azure, okta *model.OIDCProvider) {
	t.Helper()
	azure = seedProvider(t, db, func(p *model.OIDCProvider) {
		p.Name = "Azure AD"
		p.ClientID = "cid-azure"
	})
	okta = seedProvider(t, db, func(p *model.OIDCProvider) {
		p.Name = "Okta"
		p.ClientID = "cid-okta"
	})

	local := &model.User{Username: "local-user", Password: "x", Active: true,
		ProvisioningOrigin: model.AuthSourceLocal}
	ldap := &model.User{Username: "ldap-user", Password: "x", Active: true,
		IsLDAP: true, ProvisioningOrigin: model.AuthSourceLDAP}
	for _, u := range []*model.User{local, ldap} {
		if err := db.Create(u).Error; err != nil {
			t.Fatalf("create user: %v", err)
		}
	}

	both := seedOIDCUser(t, db, "sso-both")
	seedIdentity(t, db, both, azure, "sub-a")
	seedIdentity(t, db, both, okta, "sub-o")

	onlyOkta := seedOIDCUser(t, db, "sso-okta")
	seedIdentity(t, db, onlyOkta, okta, "sub-o2")
	return azure, okta
}

func newUserServiceFor(db *gorm.DB) *UserService {
	return NewUserService(db, authz.NewAssetAuthorizationService(db))
}

func TestUserListCarriesProviderInstanceNames(t *testing.T) {
	_, _, db := setupOIDCEnv(t)
	seedSourceFixture(t, db)
	svc := newUserServiceFor(db)

	resp, err := svc.List(&ListUsersRequest{Page: 1, PageSize: 50})
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	byName := map[string][]string{}
	for _, u := range resp.Data {
		byName[u.Username] = u.AuthProviderNames
	}
	// 綁兩個 provider 的帳號要兩個名字都出現——只顯示第一個會讓管理者
	// 誤以為解綁一個就切斷了這個人的全部 SSO 途徑
	if got := byName["sso-both"]; len(got) != 2 || got[0] != "Azure AD" || got[1] != "Okta" {
		t.Errorf("sso-both 的來源 = %v, want [Azure AD Okta]（依名稱排序）", got)
	}
	if got := byName["sso-okta"]; len(got) != 1 || got[0] != "Okta" {
		t.Errorf("sso-okta 的來源 = %v, want [Okta]", got)
	}
	if got := byName["local-user"]; len(got) != 0 {
		t.Errorf("本地帳號不應有 provider 名，實得 %v", got)
	}
	if got := byName["ldap-user"]; len(got) != 0 {
		t.Errorf("LDAP 帳號不應有 OIDC provider 名，實得 %v", got)
	}
}

func TestUserListFilterByProvisioningOrigin(t *testing.T) {
	_, _, db := setupOIDCEnv(t)
	seedSourceFixture(t, db)
	svc := newUserServiceFor(db)

	cases := map[string][]string{
		model.AuthSourceLocal: {"local-user"},
		model.AuthSourceLDAP:  {"ldap-user"},
		model.AuthSourceOIDC:  {"sso-both", "sso-okta"},
	}
	for origin, want := range cases {
		resp, err := svc.List(&ListUsersRequest{ProvisioningOrigin: origin, Page: 1, PageSize: 50})
		if err != nil {
			t.Fatalf("List(%s): %v", origin, err)
		}
		// total 必須反映篩選後的數量，否則分頁器會顯示不存在的頁數
		if resp.Total != int64(len(want)) {
			t.Errorf("origin=%s: total = %d, want %d", origin, resp.Total, len(want))
		}
		got := make([]string, 0, len(resp.Data))
		for _, u := range resp.Data {
			got = append(got, u.Username)
		}
		if len(got) != len(want) {
			t.Errorf("origin=%s: 結果 = %v, want %v", origin, got, want)
			continue
		}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("origin=%s: 結果 = %v, want %v", origin, got, want)
				break
			}
		}
	}
}

func TestUserListFilterByProviderInstance(t *testing.T) {
	_, _, db := setupOIDCEnv(t)
	azure, okta := seedSourceFixture(t, db)
	svc := newUserServiceFor(db)

	resp, err := svc.List(&ListUsersRequest{AuthProviderID: azure.ID, Page: 1, PageSize: 50})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if resp.Total != 1 || len(resp.Data) != 1 || resp.Data[0].Username != "sso-both" {
		t.Fatalf("依 Azure AD 篩選 = total %d / %+v, want 僅 sso-both", resp.Total, resp.Data)
	}

	// 綁多個身分的帳號在依 provider 篩選時**不得重複出現**：
	// 以 JOIN 實作會讓它出現兩次，連帶使 total 與分頁失準
	resp, err = svc.List(&ListUsersRequest{AuthProviderID: okta.ID, Page: 1, PageSize: 50})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if resp.Total != 2 {
		t.Errorf("依 Okta 篩選 total = %d, want 2（兩個帳號各一筆，不得因多身分重複）", resp.Total)
	}
	seen := map[string]int{}
	for _, u := range resp.Data {
		seen[u.Username]++
	}
	for name, n := range seen {
		if n != 1 {
			t.Errorf("%s 出現 %d 次，應恰一次", name, n)
		}
	}
}

func TestUserListUnfilteredKeepsAllOrigins(t *testing.T) {
	_, _, db := setupOIDCEnv(t)
	seedSourceFixture(t, db)
	svc := newUserServiceFor(db)

	resp, err := svc.List(&ListUsersRequest{Page: 1, PageSize: 50})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if resp.Total != 4 {
		t.Fatalf("未篩選應回全部 4 個帳號，實得 %d", resp.Total)
	}
}

func TestProviderListCarriesIdentityCount(t *testing.T) {
	_, providers, db := setupOIDCEnv(t)
	azure, okta := seedSourceFixture(t, db)

	list, err := providers.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	counts := map[uint]int64{}
	for _, d := range list {
		counts[d.ID] = d.IdentityCount
	}
	// 具體數字是為了「切換 prebound_only 影響 N 人」「刪除前需解綁 N 筆」
	// 這兩個管理決策——只說「有既有身分」無從判斷影響面
	if counts[azure.ID] != 1 {
		t.Errorf("Azure AD 的身分數 = %d, want 1", counts[azure.ID])
	}
	if counts[okta.ID] != 2 {
		t.Errorf("Okta 的身分數 = %d, want 2", counts[okta.ID])
	}
}

func TestProviderIdentityCountZeroWhenUnbound(t *testing.T) {
	_, providers, db := setupOIDCEnv(t)
	p := seedProvider(t, db, nil)

	list, err := providers.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, d := range list {
		if d.ID == p.ID && d.IdentityCount != 0 {
			t.Errorf("無綁定時身分數應為 0，實得 %d", d.IdentityCount)
		}
	}
}
