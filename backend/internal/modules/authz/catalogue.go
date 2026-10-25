package authz

import (
	"fmt"

	"gorm.io/gorm"
)

// Catalogue 一份建構後不可變的權限目錄。主體建構、角色集合解析與路由判定都取同一份，
// 讓測試可在不改寫套件層目錄的前提下注入不同的範圍屬性。
type Catalogue struct {
	defs map[Permission]PermissionDef
}

func catalogueOf(defs []PermissionDef) Catalogue {
	m := make(map[Permission]PermissionDef, len(defs))
	for _, d := range defs {
		m[d.Key] = d
	}
	return Catalogue{defs: m}
}

// ProductCatalogue 正式目錄。
func ProductCatalogue() Catalogue { return catalogueOf(permissionCatalog) }

// Lookup 依鍵查目錄。
func (c Catalogue) Lookup(key Permission) (PermissionDef, bool) {
	if c.defs == nil {
		return LookupPermission(key) // 零值目錄視為正式目錄
	}
	d, ok := c.defs[key]
	return d, ok
}

// CatalogueWithScopedEnforcedForTest 測試用：把指定的 scoped-reserved 鍵改標 scoped-enforced。
// 正式目錄已逐鍵啟用（已是 scoped-enforced）的鍵照原樣沿用，測試的注入清單不因逐鍵啟用而失效；
// 目錄外或 global-only 的鍵回錯誤。回傳的目錄與正式目錄互不共用狀態。
func CatalogueWithScopedEnforcedForTest(keys ...Permission) (Catalogue, error) {
	m := ProductCatalogue().defs // 每次呼叫新建，與正式目錄不共用
	for _, k := range keys {
		d, ok := m[k]
		if !ok {
			return Catalogue{}, fmt.Errorf("authz: permission %q not in catalogue", k)
		}
		if d.Scope == ScopeEnforced {
			continue
		}
		if d.Scope != ScopeReserved {
			return Catalogue{}, fmt.Errorf("authz: permission %q is not scoped-reserved", k)
		}
		d.Scope = ScopeEnforced
		m[k] = d
	}
	return Catalogue{defs: m}, nil
}

// ResolveUserOnWithCatalogue 在給定連線上以指定目錄解析主體（與 ResolveUserOn 同流程）。
func ResolveUserOnWithCatalogue(db *gorm.DB, cat Catalogue, userID uint, facts TokenFacts) (*Principal, error) {
	return resolveUserWith(db, cat, userID, facts)
}
