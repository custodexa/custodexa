package identity

import (
	"testing"

	"github.com/go-ldap/ldap/v3"
)

// 目錄途徑取群組資料的三格：同一次搜尋索取一次、項目沒有該屬性即空集合、
// 拿不到即未知。三者對應 spec 的已知判準與失敗方向。

// TestLDAPAuthenticatorRequestsGroupAttrOnce 群組屬性搭同一次搜尋回來，且只出現一次。
//
// 兩件事各自會壞掉：另發一次搜尋（成本翻倍，且兩次之間可能讀到不一致的目錄
// 狀態）、同一個屬性描述在清單裡出現兩次（部分目錄伺服器會回兩份屬性項，
// 而屬性值的筆數正是我們拿來當群組集合的東西）。
//
// 未設定時的清單**逐字不變**——那是「未啟用群組映射的部署零影響」在搜尋
// 請求上的形態。
func TestLDAPAuthenticatorRequestsGroupAttrOnce(t *testing.T) {
	t.Run("未設定時清單逐字不變", func(t *testing.T) {
		got := ldapSearchAttributes("mail", "cn", "")
		want := []string{"mail", "cn"}
		if len(got) != len(want) {
			t.Fatalf("屬性清單 = %v, want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("屬性清單 = %v, want %v", got, want)
			}
		}
	})

	t.Run("已設定時只多一項且只出現一次", func(t *testing.T) {
		got := ldapSearchAttributes("mail", "cn", "memberOf")
		if len(got) != 3 {
			t.Fatalf("屬性清單 = %v, want 三項", got)
		}
		n := 0
		for _, a := range got {
			if a == "memberOf" {
				n++
			}
		}
		if n != 1 {
			t.Errorf("memberOf 出現 %d 次, want 1（重複的屬性描述會讓群組值筆數失真）", n)
		}
	})

	t.Run("與既有屬性同名時不重複列入", func(t *testing.T) {
		// 屬性描述在目錄協定上不分大小寫，故 MAIL 與 mail 是同一個屬性
		got := ldapSearchAttributes("mail", "cn", "MAIL")
		if len(got) != 2 {
			t.Errorf("屬性清單 = %v, want 兩項（同名不重複列入）", got)
		}
	})
}

// TestLDAPEntryWithoutGroupAttrIsEmptySet 項目沒有群組屬性＝空集合，不是未知。
//
// 這一格釘住的是失敗方向的選擇：判成未知即保留既有映射，被移出最後一個群組的
// 人就永遠撤不掉權限，而那正是本能力要解的場景。
func TestLDAPEntryWithoutGroupAttrIsEmptySet(t *testing.T) {
	entry := &ldap.Entry{
		DN: "cn=someone,ou=users,dc=example,dc=org",
		Attributes: []*ldap.EntryAttribute{
			{Name: "mail", Values: []string{"someone@example.org"}},
			{Name: "cn", Values: []string{"Some One"}},
		},
	}

	groups, known := ldapGroupsOf(entry, "memberOf")
	if !known {
		t.Fatal("搜尋成功而項目沒有該屬性時應為已知（空集合），不得判為未知")
	}
	if len(groups) != 0 {
		t.Errorf("群組集合 = %v, want 空集合", groups)
	}

	// 對照組：屬性真的有值時照樣讀得回來（避免上面那格因為讀不到任何屬性而假綠）
	entry.Attributes = append(entry.Attributes, &ldap.EntryAttribute{
		Name: "memberOf", Values: []string{"cn=inner,ou=groups,dc=example,dc=org"},
	})
	groups, known = ldapGroupsOf(entry, "memberOf")
	if !known || len(groups) != 1 {
		t.Errorf("有值時 groups=%v known=%v, want 一筆且已知", groups, known)
	}
}

// TestLDAPGroupAttrCaseInsensitive 屬性名大小寫不同時照樣取得群組值。
//
// 屬性描述在目錄協定上不分大小寫，管理者填 memberof、目錄回 memberOf 是正常
// 設定就會出現的組合。逐字比對取不到值時，上游會把它當成「這個人不屬於任何
// 群組」而以空集合重算——誤撤的是該通道所有映射角色，方向朝著降權。
func TestLDAPGroupAttrCaseInsensitive(t *testing.T) {
	entry := &ldap.Entry{
		DN: "cn=someone,ou=users,dc=example,dc=org",
		Attributes: []*ldap.EntryAttribute{
			{Name: "mail", Values: []string{"someone@example.org"}},
			{Name: "memberOf", Values: []string{
				"cn=ops,ou=groups,dc=example,dc=org",
				"cn=auditors,ou=groups,dc=example,dc=org",
			}},
		},
	}

	groups, known := ldapGroupsOf(entry, "memberof")
	if !known {
		t.Fatal("GroupsKnown = false, want true（設定拼法與目錄回傳拼法不同不代表沒問過）")
	}
	if len(groups) != 2 {
		t.Fatalf("群組集合 = %v, want 兩筆（大小寫不同仍應取得值）", groups)
	}
	if groups[0] != "cn=ops,ou=groups,dc=example,dc=org" ||
		groups[1] != "cn=auditors,ou=groups,dc=example,dc=org" {
		t.Errorf("群組集合 = %v, want 原樣保留目錄回傳值", groups)
	}
}

// TestLDAPSearchFailureIsUnknown 拿不到群組資料即未知——既有映射保留、不推進世代。
//
// 目錄側的搜尋失敗會讓整次認證失敗（沒有認證結果可談），故這一格釘的是
// **觀測的組出規則**：屬性名已設定、卻沒有一份帶群組的認證結果時，
// 一律落未知，絕不可退化成「已知的空集合」——後者會把讀不到當成「他不在
// 任何群組」，一次目錄故障就能把所有人的映射角色清光。
func TestLDAPSearchFailureIsUnknown(t *testing.T) {
	resolution := LDAPLoginResolution{
		State:       LDAPLoginReady,
		DirectoryID: 1,
		GroupAttr:   "memberOf",
	}

	if got := ldapGroupObservation(resolution, nil).State; got != GroupObservationUnknown {
		t.Errorf("無認證結果時 state = %q, want %q", got, GroupObservationUnknown)
	}

	// 有認證結果、但那次沒取得群組（GroupsKnown 為 false）同樣是未知
	info := &LDAPUserInfo{Username: "testldap"}
	if got := ldapGroupObservation(resolution, info).State; got != GroupObservationUnknown {
		t.Errorf("認證結果未帶群組時 state = %q, want %q", got, GroupObservationUnknown)
	}

	// 對照組一：屬性名未設定＝來源根本不依群組決定角色，不是未知
	unset := resolution
	unset.GroupAttr = ""
	if got := ldapGroupObservation(unset, info).State; got != GroupObservationUnconfigured {
		t.Errorf("屬性名未設定時 state = %q, want %q", got, GroupObservationUnconfigured)
	}

	// 對照組二：真的取得了（即使是空集合）就是已知
	known := &LDAPUserInfo{Username: "testldap", GroupsKnown: true}
	obs := ldapGroupObservation(resolution, known)
	if obs.State != GroupObservationKnown || len(obs.Groups) != 0 {
		t.Errorf("取得空集合時 state=%q groups=%v, want 已知且為空", obs.State, obs.Groups)
	}
}
