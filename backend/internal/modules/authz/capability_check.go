package authz

import (
	"errors"
	"fmt"
	"sort"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// 服務層的能力檢核（不經 HTTP 中介層）。
//
// 背景工作、內嵌寫入與直接呼叫服務的入口沒有請求內的主體，也不該信任記憶體內的 DTO：
// 這裡由使用者識別重新自資料庫解析主體、重新計算聯集能力，並回報判定當下的權限世代版本。
// 解析失敗（資料庫錯誤、未知權限鍵）回 error，呼叫端一律拒絕，不以 JWT 角色兜底。

// CapabilityDecision 能力檢核結果。Allowed 為 false 時 Missing 是第一個缺少的鍵
// （主體不存在或已停用時為 "principal"）。Version 是判定時的權限世代版本。
type CapabilityDecision struct {
	Allowed bool
	Missing string
	Version int64
	// Sources 判定當下主體權限的來源種類（去重排序）：direct（手動直接指派）、
	// mapped（外部群組映射產生的直接指派）、both（兩者皆有）、group（經使用者群組）。
	Sources []string
}

// ErrCapabilityUnknown 請求了不在權限目錄內的鍵：程式錯誤，不能當成「沒有」處理。
var ErrCapabilityUnknown = errors.New("能力檢核請求了目錄外的權限點")

// ErrCapabilityEmpty 沒有宣告任何能力的檢核：不允許「空需求恆為真」。
var ErrCapabilityEmpty = errors.New("能力檢核未宣告任何權限點")

// HasAllCapabilities 檢查使用者目前是否持有 caps 的全部權限點。
// db 非 nil 時在該連線（可為交易）上解析，nil 時用 Resolver 自己的連線。
// 主體的種類取自資料庫的 users.kind；不存在、已刪除或已停用的主體一律不通過。
// 這裡沒有判定目標：scoped-enforced 的權限點只認全域來源（見 targetlessGrant）。
func (r *Resolver) HasAllCapabilities(db *gorm.DB, userID uint, caps []string) (CapabilityDecision, error) {
	if db == nil {
		db = r.db
	}
	if len(caps) == 0 {
		return CapabilityDecision{}, ErrCapabilityEmpty
	}
	for _, c := range caps {
		if _, ok := LookupPermission(Permission(c)); !ok {
			return CapabilityDecision{}, fmt.Errorf("%w: %s", ErrCapabilityUnknown, c)
		}
	}
	if userID == 0 {
		return CapabilityDecision{Missing: "principal"}, nil
	}
	var u struct {
		Kind   string
		Active bool
	}
	res := db.Model(&model.User{}).Select("kind", "active").Where("id = ?", userID).Limit(1).Scan(&u)
	if res.Error != nil {
		return CapabilityDecision{}, fmt.Errorf("讀取主體失敗: %w", res.Error)
	}
	version, err := CurrentVersion(db)
	if err != nil {
		return CapabilityDecision{}, err
	}
	if res.RowsAffected == 0 || !u.Active {
		return CapabilityDecision{Missing: "principal", Version: version}, nil
	}
	p, err := resolveUserWith(db, ProductCatalogue(), userID, TokenFacts{SubjectKind: u.Kind})
	if err != nil {
		return CapabilityDecision{}, err
	}
	sources := p.ProvenanceLabels()
	for _, c := range caps {
		if !p.targetlessGrant(Permission(c)) {
			return CapabilityDecision{Missing: c, Version: version, Sources: sources}, nil
		}
	}
	return CapabilityDecision{Allowed: true, Version: version, Sources: sources}, nil
}

// targetlessGrant 不帶判定目標的能力檢核。scoped-enforced 的權限點只認全域來源（全域指派、
// 超管、相容範本）：節點範圍來源只在判得出目標的入口生效，這裡沒有目標可比對，照 Has 放行
// 等於把節點範圍當成全域。其他範圍屬性的權限點本來只有全域來源會生效，結果與 Has 相同。
func (p *Principal) targetlessGrant(perm Permission) bool {
	if !p.Has(perm) {
		return false
	}
	if p.IsSuperAdmin() {
		return true
	}
	if d, ok := p.cat.Lookup(perm); !ok || d.Scope != ScopeEnforced {
		return true
	}
	global, _ := p.scopeSources(perm)
	return global
}

// ProvenanceLabels 主體有效指派的來源種類（去重、排序）。
func (p *Principal) ProvenanceLabels() []string {
	seen := map[string]bool{}
	for _, a := range p.Assignments {
		label := "direct"
		switch {
		case a.Via == ViaGroup:
			label = "group"
		case a.RoleSource == "mapped":
			label = "mapped"
		case a.RoleSource == "both":
			label = "both"
		}
		seen[label] = true
	}
	out := make([]string, 0, len(seen))
	for l := range seen {
		out = append(out, l)
	}
	sort.Strings(out)
	return out
}
