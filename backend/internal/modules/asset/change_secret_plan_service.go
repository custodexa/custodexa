package asset

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

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
	// ErrPlanBadMaxAgeDays 憑證最長使用天數覆蓋越界（0＝沿用全域，否則 1–3650）
	ErrPlanBadMaxAgeDays = errors.New("憑證最長使用天數覆蓋須為 0（沿用全域）或 1 至 3650")
)

// planMaxAgeDaysUpper 計劃層天數覆蓋的上界，與全域安全政策鍵同值（10 年）。
//
// **本地常數而非引用政策模組**：改密計劃屬 asset 模組，向 policy 取一個純數字
// 會為此建立一條新的模組相依邊。兩處值必須相同，由 spec 條文與雙方的測試各自釘住。
const planMaxAgeDaysUpper = 3650

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

	// MaxAgeDays 憑證最長使用天數覆蓋：0＝沿用全域安全政策鍵。
	// 只影響輪替證據報告的適用天數計算，不改變本計劃的執行時機
	MaxAgeDays int `json:"max_age_days"`
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
	// 0＝沿用全域，其餘須落在值域內。**負值與超界都要擋**：覆蓋值直接進報告的
	// 適用天數計算，一個負數會讓每個被涵蓋的帳號都算出逾期
	if req.MaxAgeDays < 0 || req.MaxAgeDays > planMaxAgeDaysUpper {
		return out, ErrPlanBadMaxAgeDays
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
	plan.MaxAgeDays = req.MaxAgeDays
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

// recordAccountBatchSize 帳號 id 的分批大小。
//
// `IN (…)` 的參數數量在資料庫端有上限（postgres 的綁定參數上限為 65535），
// 而報告的範圍可以是全系統——帳號數沒有結構性上界。分批把上限問題變成迴圈次數
// 問題；1,000 遠低於任何驅動的上限，且單批的計畫仍走 account_id 索引。
const recordAccountBatchSize = 1000

// RecordsByAccounts 依帳號查改密記錄（新到舊）。
//
// **以 account_id 比對，不用帳號名快照**：帳號改名後，以名字比對會漏掉改名前的
// 記錄，而報告據此推導的「最後改密時刻」會憑空變舊或消失。名字快照仍留在記錄上
// 供顯示（帳號已刪時那是唯一還讀得出來的東西），但不作為比對鍵。
//
// from／to 為 nil 即該側不設限；有值時區間為 [from, to)——右開使連續兩期的
// 區間首尾相接而不重複計入同一筆。status 為空即不限狀態（區間明細要含
// failed 與 skipped，那正是稽核要看的東西）。
//
// 回傳不含任何秘密材料：記錄表本身就不存秘密，Error 欄只有機器碼。
func (s *ChangeSecretPlanService) RecordsByAccounts(accountIDs []uint, from, to *time.Time,
	status string) ([]model.ChangeSecretRecord, error) {

	if len(accountIDs) == 0 {
		return nil, nil
	}
	var out []model.ChangeSecretRecord
	for start := 0; start < len(accountIDs); start += recordAccountBatchSize {
		end := start + recordAccountBatchSize
		if end > len(accountIDs) {
			end = len(accountIDs)
		}
		q := s.db.Where("account_id IN ?", accountIDs[start:end])
		if from != nil {
			q = q.Where("executed_at >= ?", *from)
		}
		if to != nil {
			q = q.Where("executed_at < ?", *to)
		}
		if status != "" {
			q = q.Where("status = ?", status)
		}
		var batch []model.ChangeSecretRecord
		if err := q.Order("id desc").Find(&batch).Error; err != nil {
			return nil, err
		}
		out = append(out, batch...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out, nil
}

// LastSuccessByAccount 每個帳號在 asOf（含）之前最後一次改密成功的執行時刻。
//
// asOf 為零值時不設上界。**帶上界是為了讓截止時點真的是截止**：報告把時點往回
// 移時，晚於該時點才發生的改密不得計入，否則算出來的「距今天數」會描述一個當時
// 還沒發生的事實。
//
// 查無成功記錄的帳號**不出現在回傳的 map 內**——那是「本系統無成功改密記錄」，
// 與「很久以前改過」是兩件事，用零值時間表示會讓兩者在下游無法分辨。
//
// 單一 GROUP BY 而非逐帳號查詢：報告的範圍可達全系統，逐筆查會把一次報告產出
// 變成上萬次往返。
func (s *ChangeSecretPlanService) LastSuccessByAccount(accountIDs []uint,
	asOf time.Time) (map[uint]time.Time, error) {
	out := make(map[uint]time.Time, len(accountIDs))
	if len(accountIDs) == 0 {
		return out, nil
	}
	for start := 0; start < len(accountIDs); start += recordAccountBatchSize {
		end := start + recordAccountBatchSize
		if end > len(accountIDs) {
			end = len(accountIDs)
		}
		// **走原生 Rows 而非 Scan 進結構**：聚合結果失去欄位的宣告型別，各驅動
		// 因而回傳不同的 Go 型別（時間值或其字串表示）。以 any 逐列接收後在
		// coerceTime 收斂一次，勝過讓每個驅動各有一套隱性假設。
		q := s.db.Model(&model.ChangeSecretRecord{}).
			Select("account_id, MAX(executed_at) AS executed_at").
			Where("account_id IN ?", accountIDs[start:end]).
			Where("status = ?", model.ChangeSecretSuccess)
		if !asOf.IsZero() {
			q = q.Where("executed_at <= ?", asOf)
		}
		rows, err := q.Group("account_id").Rows()
		if err != nil {
			return nil, err
		}
		if err := scanLastSuccessRows(rows, out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// scanLastSuccessRows 逐列讀出「帳號 → 最後成功時刻」，並確保結果集被關閉。
func scanLastSuccessRows(rows *sql.Rows, out map[uint]time.Time) error {
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var accountID uint
		var raw any
		if err := rows.Scan(&accountID, &raw); err != nil {
			return err
		}
		ts, ok := coerceTime(raw)
		if !ok {
			return fmt.Errorf("最後成功改密時刻無法解讀（帳號 %d）", accountID)
		}
		out[accountID] = ts
	}
	return rows.Err()
}

// coerceTime 把驅動回傳的聚合值轉成時間。
//
// **不靜默吞掉無法解讀的值**：回傳 false 讓呼叫端明確失敗，而不是塞一個零值時間
// ——零值會讓「無成功記錄」與「有記錄但讀不出來」在報告上長得一模一樣。
func coerceTime(v any) (time.Time, bool) {
	switch t := v.(type) {
	case time.Time:
		return t, true
	case *time.Time:
		if t == nil {
			return time.Time{}, false
		}
		return *t, true
	case string:
		return parseTimeText(t)
	case []byte:
		return parseTimeText(string(t))
	}
	return time.Time{}, false
}

// parseTimeText 依序試幾種常見的時間文字表示（含驅動慣用的空白分隔形式）
func parseTimeText(s string) (time.Time, bool) {
	for _, layout := range []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999 -0700 MST",
		"2006-01-02 15:04:05.999999-07:00",
		"2006-01-02 15:04:05.999999",
		"2006-01-02 15:04:05",
	} {
		if ts, err := time.Parse(layout, s); err == nil {
			return ts, true
		}
	}
	return time.Time{}, false
}
