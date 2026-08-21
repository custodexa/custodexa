package audit

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/custodexa/backend/internal/kernel/dberr"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 規則驗證錯誤：handler 以 errors.Is 區分 400（輸入問題）與 500（系統問題）
var (
	ErrAlertRuleNotFound = errors.New("告警規則不存在")
	ErrInvalidPattern    = errors.New("regex pattern 無效")
	ErrInvalidSeverity   = errors.New("severity 必須為 high/medium/low")
	ErrInvalidAction     = errors.New("action 必須為 alert/block")
	ErrInvalidProtocols  = errors.New("protocols 僅接受 ssh/k8s/mysql/postgres/redis/mssql（逗號分隔，空=全協議）")
	// ErrAlertRuleNameExists 規則名撞上 alert_rules.name 的唯一索引。
	//
	// 該索引是種子冪等的前提（migration-baseline-compression D4），但規則名在
	// UI／API 是可編輯欄位：admin 建規則或改名到既有名稱時必然撞得到，沒有這條
	// 轉譯就會冒成 500。判定一律取自「資料庫回傳的唯一鍵衝突」而非先查後寫——
	// 後者在並發下仍會撞（TOCTOU），且多一次無用查詢。
	ErrAlertRuleNameExists = errors.New("告警規則名稱已存在")
)

// isNameConflict 判定寫入錯誤是否為 alert_rules.name 的唯一鍵衝突。
//
// 雙判定沿用專案既有形狀（change_secret_candidate_service.go:102）：GORM 的
// ErrDuplicatedKey 轉譯不涵蓋全部驅動組合，故再以方言無關的字串比對兜底。
// 本表只有 name 一條唯一索引（主鍵由 DB 產生，不會由請求撞上），故命中即為名稱衝突。
func isNameConflict(err error) bool {
	return errors.Is(err, gorm.ErrDuplicatedKey) || dberr.IsUniqueViolation(err)
}

// AlertRuleRequest 規則建立/更新請求（Create 與 Update 欄位相同，共用一個結構）
type AlertRuleRequest struct {
	Name      string  `json:"name" binding:"required"`
	Pattern   string  `json:"pattern" binding:"required"`
	Severity  string  `json:"severity" binding:"required"`
	Action    string  `json:"action"`    // 空=alert；alert/block
	Enabled   *bool   `json:"enabled"`   // 指標區分「未傳」與「false」；未傳預設啟用
	Protocols *string `json:"protocols"` // 指標區分「未傳」（Create=全協議、Update=不變）與空字串（全協議）
}

// commandAuditedProtocols 具指令審計的文字終端協議（協議分流值域）；
// rdp/vnc 無指令流，設了也不會被比對，故直接拒絕以及早暴露設定錯誤
var commandAuditedProtocols = map[string]bool{
	"ssh": true, "k8s": true, "mysql": true, "postgres": true, "redis": true, "mssql": true,
}

// normalizeProtocols 驗證並正規化協議清單：小寫、去空白、逗號重組；空＝全協議。
// 正規化後的儲存格式與 alert_matcher.ruleAppliesToProtocol 的解析方式一致
func normalizeProtocols(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", nil
	}
	parts := strings.Split(raw, ",")
	normalized := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		if !commandAuditedProtocols[p] {
			return "", fmt.Errorf("%w：收到 %q", ErrInvalidProtocols, p)
		}
		normalized = append(normalized, p)
	}
	return strings.Join(normalized, ","), nil
}

// AlertRuleService 告警規則 CRUD 服務（command-alerts D4）
type AlertRuleService struct {
	db *gorm.DB
}

// NewAlertRuleService 創建告警規則服務
func NewAlertRuleService(db *gorm.DB) *AlertRuleService {
	return &AlertRuleService{db: db}
}

// validateRule 驗證請求：regex 以 regexp.Compile 驗證後才入庫（design D4），
// 編譯錯誤原文附在錯誤訊息中，讓 API 呼叫端知道 pattern 哪裡壞
func validateRule(req *AlertRuleRequest) error {
	if !model.ValidAlertSeverity(req.Severity) {
		return ErrInvalidSeverity
	}
	if _, err := regexp.Compile(req.Pattern); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPattern, err)
	}
	if req.Action != "" && req.Action != "alert" && req.Action != "block" {
		return ErrInvalidAction
	}
	if req.Protocols != nil {
		if _, err := normalizeProtocols(*req.Protocols); err != nil {
			return err
		}
	}
	return nil
}

// normalizeAction 空值預設 alert（向後相容）
func normalizeAction(a string) string {
	if a == "" {
		return "alert"
	}
	return a
}

// List 列出所有規則（量級數十條，不分頁）
func (s *AlertRuleService) List() ([]model.AlertRule, error) {
	var rules []model.AlertRule
	if err := s.db.Order("id ASC").Find(&rules).Error; err != nil {
		return nil, fmt.Errorf("查詢告警規則失敗: %w", err)
	}
	return rules, nil
}

// Create 建立規則；成功後刷新比對快取（design D1）
func (s *AlertRuleService) Create(req *AlertRuleRequest) (*model.AlertRule, error) {
	if err := validateRule(req); err != nil {
		return nil, err
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	protocols := ""
	if req.Protocols != nil {
		protocols, _ = normalizeProtocols(*req.Protocols) // validateRule 已驗證過
	}
	rule := model.AlertRule{
		Name:      req.Name,
		Pattern:   req.Pattern,
		Severity:  req.Severity,
		Action:    normalizeAction(req.Action),
		Protocols: protocols,
		Enabled:   enabled,
	}
	if err := s.db.Create(&rule).Error; err != nil {
		if isNameConflict(err) {
			// 轉哨兵而非原樣上拋：驅動訊息含表名／索引名／SQL 片段，
			// 那些是內部實作細節，不得經由 API 回應外洩（handler 只取碼）
			return nil, ErrAlertRuleNameExists
		}
		return nil, fmt.Errorf("建立告警規則失敗: %w", err)
	}

	ReloadAlertMatcher()
	return &rule, nil
}

// Update 更新規則；成功後刷新比對快取
func (s *AlertRuleService) Update(id uint, req *AlertRuleRequest) (*model.AlertRule, error) {
	if err := validateRule(req); err != nil {
		return nil, err
	}

	var rule model.AlertRule
	if err := s.db.First(&rule, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrAlertRuleNotFound
		}
		return nil, fmt.Errorf("查詢告警規則失敗: %w", err)
	}

	updates := map[string]interface{}{
		"name":     req.Name,
		"pattern":  req.Pattern,
		"severity": req.Severity,
		"action":   normalizeAction(req.Action),
	}
	if req.Enabled != nil {
		updates["enabled"] = *req.Enabled
	}
	if req.Protocols != nil {
		normalized, _ := normalizeProtocols(*req.Protocols) // validateRule 已驗證過
		updates["protocols"] = normalized
	}
	// 改名撞既有規則同樣走唯一索引；改回自己原本的名字**不算**衝突
	// （唯一索引比對的是其他列，同列自更新不觸發），故編輯其他欄位而不改名的
	// 常見操作不會被誤擋——這條是本轉譯最容易漏掉的一格
	if err := s.db.Model(&rule).Updates(updates).Error; err != nil {
		if isNameConflict(err) {
			return nil, ErrAlertRuleNameExists
		}
		return nil, fmt.Errorf("更新告警規則失敗: %w", err)
	}

	ReloadAlertMatcher()
	return &rule, nil
}

// Delete 刪除規則；成功後刷新比對快取。
// 既有告警保留 rule_name/severity 快照，刪規則不影響歷史告警可讀性
func (s *AlertRuleService) Delete(id uint) error {
	result := s.db.Delete(&model.AlertRule{}, id)
	if result.Error != nil {
		return fmt.Errorf("刪除告警規則失敗: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return ErrAlertRuleNotFound
	}

	ReloadAlertMatcher()
	return nil
}
