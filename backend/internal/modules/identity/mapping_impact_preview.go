package identity

import (
	"fmt"

	"github.com/custodexa/backend/internal/modules/authz"
	"gorm.io/gorm"
)

// mappingPreviewSubjectCap 單次規則寫入最多預覽的命中帳號數（升冪取前段）。
// 預覽是建議性輸入，在規則寫入交易內執行：目錄很大時不拿全部帳號逐一求值拖慢寫入。
const mappingPreviewSubjectCap = 200

// MappingImpactObserver 收下一次規則寫入的危險組合預覽結果。
// 結果只供畫面或後續告警使用；回傳錯誤會使整筆寫入回滾，所以消費端應只做不會失敗的記錄。
type MappingImpactObserver func(in MappingImpact, res authz.PreviewResult)

// AuthzMappingImpactPreview 以 authz 的危險組合預覽實作 MappingImpactPreview：
// 假設規則生效後，快照命中的帳號各自多出目標角色或使用者群組成員身分，求出各帳號的入口變化與新命中的危險組合。
// 只讀，不寫入任何資料，也不阻擋規則寫入（預覽不是關卡）。
type AuthzMappingImpactPreview struct {
	observe MappingImpactObserver
}

// NewAuthzMappingImpactPreview 建立預覽轉接器；observe 可為 nil（只驗證預覽可求值）。
func NewAuthzMappingImpactPreview(observe MappingImpactObserver) *AuthzMappingImpactPreview {
	return &AuthzMappingImpactPreview{observe: observe}
}

// ObserveMappingImpact 實作 MappingImpactPreview。
func (p *AuthzMappingImpactPreview) ObserveMappingImpact(tx *gorm.DB, in MappingImpact) error {
	if len(in.Subjects) == 0 || in.TargetID == 0 {
		return nil
	}
	subjects := in.Subjects
	if len(subjects) > mappingPreviewSubjectCap {
		subjects = subjects[:mappingPreviewSubjectCap]
	}
	req := authz.PreviewRequest{Kind: authz.PreviewMappingGrant, SubjectIDs: subjects}
	switch in.RuleType {
	case mappingRuleRole:
		req.RoleID = in.TargetID
	case mappingRuleUserGroup:
		req.GroupID = in.TargetID
	default:
		return fmt.Errorf("映射預覽的規則類別不明: %q", in.RuleType)
	}
	res, err := authz.PreviewEffectiveCapabilities(tx, req)
	if err != nil {
		return err
	}
	if p.observe != nil {
		p.observe(in, res)
	}
	return nil
}
