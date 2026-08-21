package asset

import (
	"encoding/json"
	"errors"

	"github.com/custodexa/backend/internal/kernel/dberr"
	"github.com/custodexa/backend/internal/model"
	"github.com/robfig/cron/v3"
	"gorm.io/gorm"
)

// 計劃驗證錯誤：handler 以 errors.Is 區分 400/404/409 與 500
var (
	ErrPlanNotFound       = errors.New("改密計劃不存在")
	ErrPlanNameExists     = errors.New("計劃名稱已存在")
	ErrPlanNoAssets       = errors.New("計劃必須包含至少一個資產")
	ErrPlanBadCron        = errors.New("排程格式錯誤（標準 5 欄 cron）")
	ErrPlanBadSecretType  = errors.New("秘密型別僅支援 password 或 ssh_key")
	ErrPlanBadKeyStrategy = errors.New("金鑰策略僅支援 append_replace 或 exclusive")
)

// ChangeSecretPlanRequest 計劃建立/更新請求
type ChangeSecretPlanRequest struct {
	Name     string `json:"name" binding:"required"`
	AssetIDs []uint `json:"asset_ids" binding:"required"`
	// Accounts 帳號範圍：空／含 @ALL ＝ 該資產全部帳號（回歸安全的既有慣例）
	Accounts []string `json:"accounts"`
	Cron     string   `json:"cron"`
	Enabled  *bool    `json:"enabled"`

	SecretType  string `json:"secret_type"`
	KeyStrategy string `json:"key_strategy"`

	PasswordLength           int   `json:"password_length"`
	PasswordIncludeSymbol    *bool `json:"password_include_symbol"`
	PasswordExcludeAmbiguous *bool `json:"password_exclude_ambiguous"`
}

// ChangeSecretPlanService 改密計劃 CRUD（change-secret 階段 1）
type ChangeSecretPlanService struct {
	db *gorm.DB
}

// NewChangeSecretPlanService 建立服務
func NewChangeSecretPlanService(db *gorm.DB) *ChangeSecretPlanService {
	return &ChangeSecretPlanService{db: db}
}

var cronParser = cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)

// planFields 計劃的正規化欄位（驗證通過後套用到 model）
type planFields struct {
	assetIDs string
	accounts string
}

func validatePlan(req *ChangeSecretPlanRequest) (planFields, error) {
	var out planFields
	if len(req.AssetIDs) == 0 {
		return out, ErrPlanNoAssets
	}
	if req.Cron != "" {
		if _, err := cronParser.Parse(req.Cron); err != nil {
			return out, ErrPlanBadCron
		}
	}
	switch req.SecretType {
	case "", model.ChangeSecretTypePassword, model.ChangeSecretTypeSSHKey:
	default:
		return out, ErrPlanBadSecretType
	}
	switch req.KeyStrategy {
	case "", model.KeyStrategyAppendReplace, model.KeyStrategyExclusive:
	default:
		return out, ErrPlanBadKeyStrategy
	}
	if err := ValidatePasswordLength(req.PasswordLength); err != nil {
		return out, err
	}
	ids, err := json.Marshal(req.AssetIDs)
	if err != nil {
		return out, err
	}
	out.assetIDs = string(ids)

	scope := model.NormalizeAccountScope(req.Accounts)
	if len(scope) == 0 {
		scope = model.AccountScope{model.AccountScopeAll}
	}
	accounts, err := json.Marshal(scope)
	if err != nil {
		return out, err
	}
	out.accounts = string(accounts)
	return out, nil
}

// applyPlanFields 把請求套進 model（建立與更新共用，避免兩處漂移）
func applyPlanFields(plan *model.ChangeSecretPlan, req *ChangeSecretPlanRequest, f planFields) {
	plan.Name = req.Name
	plan.AssetIDs = f.assetIDs
	plan.Accounts = f.accounts
	plan.Cron = req.Cron
	plan.SecretType = req.SecretType
	if plan.SecretType == "" {
		plan.SecretType = model.ChangeSecretTypePassword
	}
	plan.KeyStrategy = req.KeyStrategy
	if plan.KeyStrategy == "" {
		plan.KeyStrategy = model.KeyStrategyAppendReplace
	}
	plan.PasswordLength = req.PasswordLength
	if plan.PasswordLength == 0 {
		plan.PasswordLength = model.PasswordLengthDefault
	}
	// 兩個布林以指標接收：未帶欄位時取出廠預設（含符號、排除易混淆），
	// 而非 Go 零值 false——後者會讓「沒填」靜默變成「關閉」
	plan.PasswordIncludeSymbol = true
	if req.PasswordIncludeSymbol != nil {
		plan.PasswordIncludeSymbol = *req.PasswordIncludeSymbol
	}
	plan.PasswordExcludeAmbiguous = true
	if req.PasswordExcludeAmbiguous != nil {
		plan.PasswordExcludeAmbiguous = *req.PasswordExcludeAmbiguous
	}
}

// PlanAccountScope 解析計劃的帳號範圍。空值一律讀成 @ALL（回歸安全方向：
// 漏設此欄若被讀成「零帳號」，計劃會靜默什麼都不做而看起來一切正常）
func PlanAccountScope(plan *model.ChangeSecretPlan) model.AccountScope {
	var scope model.AccountScope
	if plan.Accounts != "" {
		_ = json.Unmarshal([]byte(plan.Accounts), &scope)
	}
	if len(scope) == 0 {
		return model.AccountScope{model.AccountScopeAll}
	}
	return scope
}

// List 全部計劃
func (s *ChangeSecretPlanService) List() ([]model.ChangeSecretPlan, error) {
	var plans []model.ChangeSecretPlan
	if err := s.db.Order("id").Find(&plans).Error; err != nil {
		return nil, err
	}
	return plans, nil
}

// Get 單一計劃
func (s *ChangeSecretPlanService) Get(id uint) (*model.ChangeSecretPlan, error) {
	var plan model.ChangeSecretPlan
	if err := s.db.First(&plan, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrPlanNotFound
		}
		return nil, err
	}
	return &plan, nil
}

// Create 建立計劃
func (s *ChangeSecretPlanService) Create(req *ChangeSecretPlanRequest) (*model.ChangeSecretPlan, error) {
	fields, err := validatePlan(req)
	if err != nil {
		return nil, err
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	plan := &model.ChangeSecretPlan{Enabled: enabled}
	applyPlanFields(plan, req, fields)
	if err := s.db.Create(plan).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) || dberr.IsUniqueViolation(err) {
			return nil, ErrPlanNameExists
		}
		return nil, err
	}
	return plan, nil
}

// Update 更新計劃
func (s *ChangeSecretPlanService) Update(id uint, req *ChangeSecretPlanRequest) (*model.ChangeSecretPlan, error) {
	plan, err := s.Get(id)
	if err != nil {
		return nil, err
	}
	fields, err := validatePlan(req)
	if err != nil {
		return nil, err
	}
	applyPlanFields(plan, req, fields)
	if req.Enabled != nil {
		plan.Enabled = *req.Enabled
	}
	if err := s.db.Save(plan).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) || dberr.IsUniqueViolation(err) {
			return nil, ErrPlanNameExists
		}
		return nil, err
	}
	return plan, nil
}

// Delete 刪除計劃（保留歷史 record）
func (s *ChangeSecretPlanService) Delete(id uint) error {
	result := s.db.Delete(&model.ChangeSecretPlan{}, id)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrPlanNotFound
	}
	return nil
}

// Records 計劃的執行記錄（新到舊）
func (s *ChangeSecretPlanService) Records(planID uint, limit int) ([]model.ChangeSecretRecord, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var records []model.ChangeSecretRecord
	if err := s.db.Where("plan_id = ?", planID).Order("id desc").Limit(limit).Find(&records).Error; err != nil {
		return nil, err
	}
	return records, nil
}

// AssetIDList 解析計劃的資產 ID 集合
func AssetIDList(plan *model.ChangeSecretPlan) []uint {
	var ids []uint
	_ = json.Unmarshal([]byte(plan.AssetIDs), &ids)
	return ids
}
