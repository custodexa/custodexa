package authz

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// 凍結表（範圍判定契約）。刻意以字面字串寫在測試內，不引用常數，
// 常數被改動時才抓得到。
var frozenAssetAdminKeys = []string{
	"asset:view", "asset:create", "asset:update", "asset:delete", "asset:test",
	"assetgroup:manage", "changesecret:manage", "account:rotate",
	"credential:view", "credential:create", "credential:update", "credential:set-secret",
	"credential:rotate", "credential:convert-scope", "credential:detach",
	"credential:delete", "credential:bind",
}

var frozenAuthzAdminKeys = []string{
	"authorization:manage", "approverscope:manage", "access_policy:manage",
}

func keyStrings(ps []Permission) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = string(p)
	}
	sort.Strings(out)
	return out
}

func sortedStrings(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func TestScopedTemplatePermissionSets(t *testing.T) {
	cases := []struct {
		name   string
		got    []Permission
		frozen []string
	}{
		{"asset_admin", ScopedTemplateAssetAdminPermissions(), frozenAssetAdminKeys},
		{"authorization_admin", ScopedTemplateAuthorizationAdminPermissions(), frozenAuthzAdminKeys},
	}
	if len(frozenAssetAdminKeys) != 17 || len(frozenAuthzAdminKeys) != 3 {
		t.Fatalf("凍結表筆數應為 17 與 3，實際 %d 與 %d", len(frozenAssetAdminKeys), len(frozenAuthzAdminKeys))
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := keyStrings(c.got)
			want := sortedStrings(c.frozen)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("集合不等於凍結表\n got=%v\nwant=%v", got, want)
			}
			// 回傳須依鍵排序且為副本。
			if !sort.SliceIsSorted(c.got, func(i, j int) bool { return c.got[i] < c.got[j] }) {
				t.Errorf("回傳未依鍵排序")
			}
			var defs []PermissionDef
			for _, k := range c.got {
				def, ok := LookupPermission(k)
				if !ok {
					t.Errorf("%s 不在目錄", k)
					continue
				}
				if !IsAssignable(k) {
					t.Errorf("%s 不可指派", k)
				}
				if def.Scope == ScopeGlobalOnly {
					t.Errorf("%s 為 global-only", k)
				}
				if strings.HasPrefix(string(k), UIPrefix) {
					t.Errorf("%s 為 ui: 鍵", k)
				}
				defs = append(defs, def)
			}
			// 保留能力名稱片段由目錄載入規則拒絕。
			if err := ValidateCatalog(defs); err != nil {
				t.Errorf("含保留能力或不合法的鍵: %v", err)
			}
			// 副本：改動回傳值不影響下一次回傳。
			if len(c.got) > 0 {
				c.got[0] = "mutated"
			}
		})
	}
	// 副本性（改動不外溢）。
	if keyStrings(ScopedTemplateAssetAdminPermissions())[0] == "mutated" {
		t.Errorf("回傳值不是副本")
	}
	// 兩集合互斥。
	asset := map[string]bool{}
	for _, k := range frozenAssetAdminKeys {
		asset[k] = true
	}
	for _, k := range frozenAuthzAdminKeys {
		if asset[k] {
			t.Errorf("兩集合重疊: %s", k)
		}
	}

	t.Run("applicant_key_excluded", func(t *testing.T) {
		// 授權管理員集合含審核範圍管理鍵、不含申請人型管理鍵；資產管理員兩者皆無。
		// 重新取回傳值：上方子測試改寫過 cases 內的副本，不能拿它判定。
		for name, got := range map[string][]Permission{
			"asset_admin":         ScopedTemplateAssetAdminPermissions(),
			"authorization_admin": ScopedTemplateAuthorizationAdminPermissions(),
		} {
			for _, k := range keyStrings(got) {
				if k == string(PermApproverScopeApplicantManage) {
					t.Errorf("%s 集合不應含申請人型管理鍵", name)
				}
			}
		}
		if def, ok := LookupPermission(PermApproverScopeApplicantManage); !ok || def.Scope != ScopeGlobalOnly {
			t.Errorf("申請人型管理鍵應為 global-only: %+v", def)
		}
	})

	t.Run("seeded", func(t *testing.T) {
		// 兩個內建識別的分支回與凍結常數逐鍵相同的副本；改回傳值不影響下一次呼叫。
		for name, want := range map[string][]string{
			"asset_admin": sortedStrings(frozenAssetAdminKeys),
			"authz_admin": sortedStrings(frozenAuthzAdminKeys),
		} {
			got := TemplatePermissions(name)
			if !reflect.DeepEqual(sortedStrings(keyStrings(got)), want) {
				t.Errorf("內建範本 %s 與凍結常數不同: %v", name, keyStrings(got))
			}
			if len(got) > 0 {
				got[0] = "tampered"
				if again := TemplatePermissions(name); len(again) > 0 && again[0] == "tampered" {
					t.Errorf("內建範本 %s 回傳的不是副本", name)
				}
			}
			if !IsLockedManagementTemplate(name) {
				t.Errorf("%s 未列入鎖定管理範本識別", name)
			}
		}
		for _, name := range []string{"authorization_admin", "scoped_asset_admin"} {
			if got := TemplatePermissions(name); got != nil {
				t.Errorf("內建範本表出現 %q", name)
			}
		}
		for _, name := range []string{"asset_admin", "authz_admin", "authorization_admin", "scoped_asset_admin"} {
			if _, ok := LookupPermission(Permission(name)); ok {
				t.Errorf("目錄出現 %q", name)
			}
		}
		// 其他內建範本的集合都不得恰等於兩個範圍化集合。
		for _, key := range []string{"super_admin", "auditor", "user", "approver", "identity_admin", "security_admin"} {
			g := keyStrings(TemplatePermissions(key))
			if reflect.DeepEqual(g, sortedStrings(frozenAssetAdminKeys)) || reflect.DeepEqual(g, sortedStrings(frozenAuthzAdminKeys)) {
				t.Errorf("內建範本 %s 等於範圍化範本集合", key)
			}
		}
		// 範本名稱只出現在種子與內建識別登記處：database 與 identity 的其他非測試原始碼不得出現。
		allowed := map[string]bool{"migration_scoped_template_builtin_keys.go": true, "migrations.go": true, "scoped_template_seed.go": true}
		for _, dir := range []string{"../../database", "../identity"} {
			_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
				if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
					return nil
				}
				if allowed[filepath.Base(p)] {
					return nil
				}
				b, rerr := os.ReadFile(p)
				if rerr != nil {
					return nil
				}
				s := string(b)
				if strings.Contains(s, "asset_admin") || strings.Contains(s, "authz_admin") ||
					strings.Contains(s, "ScopedTemplate") {
					t.Errorf("%s 出現範圍化範本名稱", p)
				}
				return nil
			})
		}
	})
}
