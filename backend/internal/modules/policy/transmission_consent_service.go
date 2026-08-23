package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var (
	// ErrConsentNoRisks 資產當下無風險項，無事可同意
	ErrConsentNoRisks = errors.New("資產目前無傳輸風險項，無需同意")
	// ErrConsentRisksChanged 使用者看到的風險集合與當下不符（TOCTOU 守衛）：
	// 同意必須立在使用者實際看到的風險上，不符即要求重新確認
	ErrConsentRisksChanged = errors.New("風險項已變更，請重新確認")
	// ErrConsentNotApplicable warn 檔以外不受理同意（strict 不吃同意、off 無需同意）
	ErrConsentNotApplicable = errors.New("目前政策檔位不受理連線同意")
)

// TransmissionConsentService 傳輸風險同意立據與連線閘：
// 立據（Record）與用據（CheckConnect）分離——同意是獨立審計事件，
// 簽發端點唯讀記錄不寫
type TransmissionConsentService struct {
	db     *gorm.DB
	policy *TransmissionPolicyService
}

// NewTransmissionConsentService 建立同意服務
func NewTransmissionConsentService(db *gorm.DB, policy *TransmissionPolicyService) *TransmissionConsentService {
	return &TransmissionConsentService{db: db, policy: policy}
}

// ConnectGateDecision 連線閘判定結果（handler 據此映射 HTTP 語義）
type ConnectGateDecision struct {
	Allowed bool
	// Status 建議 HTTP 狀態：400=strict 拒絕、428=warn 需同意
	Status  int
	Channel string
	Level   string
	Risks   []RiskItem
	Message string
}

// CheckConnect connect-token 簽發閘（授權檢查之後呼叫）：
// off 或無風險＝放行；strict 命中＝拒絕（不吃同意）＋入審計；
// warn 無有效同意＝428 要求同意。判定與清冊共用同一套規則
func (s *TransmissionConsentService) CheckConnect(userID uint, asset *model.Asset, clientIP string) ConnectGateDecision {
	channel := s.policy.AssetChannel(asset)
	if channel == "" {
		return ConnectGateDecision{Allowed: true}
	}
	level := s.policy.ChannelLevel(channel)
	if level == TransportLevelOff {
		return ConnectGateDecision{Allowed: true}
	}
	risks := s.policy.AssetRisks(asset)
	if len(risks) == 0 {
		return ConnectGateDecision{Allowed: true}
	}

	decision := ConnectGateDecision{Channel: channel, Level: level, Risks: risks}
	switch level {
	case TransportLevelStrict:
		decision.Allowed = false
		decision.Status = http.StatusBadRequest
		decision.Message = "傳輸安全政策（嚴格）拒絕連線：資產傳輸設定不符要求"
		s.auditGateDenied(userID, asset, channel, risks, clientIP)
	case TransportLevelWarn:
		if s.HasValidConsent(userID, asset.ID, TransmissionRiskFingerprint(risks)) {
			decision.Allowed = true
			return decision
		}
		decision.Allowed = false
		decision.Status = http.StatusPreconditionRequired
		decision.Message = "連線前需確認傳輸風險"
	}
	return decision
}

// HasValidConsent 是否存在有效同意：fingerprint 相符且未逾政策 TTL
// （效期動態判定：consented_at＋當下 TTL，政策改動立即全域生效）
func (s *TransmissionConsentService) HasValidConsent(userID, assetID uint, fingerprint string) bool {
	var consent model.TransmissionConsent
	err := s.db.Where("user_id = ? AND asset_id = ?", userID, assetID).First(&consent).Error
	if err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			// 讀取失敗 fail-closed：當作無同意（多按一次確認優於靜默放行）
			log.Printf("[TransmissionConsent] 讀取同意記錄失敗 (user=%d asset=%d): %v", userID, assetID, err)
		}
		return false
	}
	if consent.RiskFingerprint != fingerprint {
		return false
	}
	if ttl := s.policy.ConsentTTLDays(); ttl > 0 {
		if time.Since(consent.ConsentedAt) > time.Duration(ttl)*24*time.Hour {
			return false
		}
	}
	return true
}

// Record 立據：使用者對資產提交同意。clientRiskKeys＝使用者實際看到的
// 風險項 key 集合，與當下重算集合不符即拒（TOCTOU 守衛——同意不能立在
// 已過期的風險認知上）。冪等 upsert per user×asset，成功即入審計
func (s *TransmissionConsentService) Record(userID uint, asset *model.Asset, clientRiskKeys []string, clientIP string) (*model.TransmissionConsent, error) {
	channel := s.policy.AssetChannel(asset)
	if channel == "" {
		return nil, ErrConsentNoRisks
	}
	// strict 不吃同意、off 無需同意：不受理立據，防「先囤同意等政策開 warn」的語義混淆
	if s.policy.ChannelLevel(channel) != TransportLevelWarn {
		return nil, ErrConsentNotApplicable
	}
	risks := s.policy.AssetRisks(asset)
	if len(risks) == 0 {
		return nil, ErrConsentNoRisks
	}

	current := TransmissionRiskFingerprint(risks)
	seen := TransmissionRiskFingerprint(riskItemsFromKeys(clientRiskKeys))
	if current != seen {
		return nil, ErrConsentRisksChanged
	}

	itemsJSON, err := json.Marshal(risks)
	if err != nil {
		return nil, fmt.Errorf("序列化風險項失敗: %w", err)
	}
	consent := model.TransmissionConsent{
		UserID:          userID,
		AssetID:         asset.ID,
		RiskFingerprint: current,
		RiskItems:       string(itemsJSON),
		ConsentedAt:     time.Now(),
	}
	// 冪等 upsert：同 user×asset 重複同意即刷新 fingerprint/items/consented_at
	err = s.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "user_id"}, {Name: "asset_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"risk_fingerprint", "risk_items", "consented_at", "updated_at"}),
	}).Create(&consent).Error
	if err != nil {
		return nil, fmt.Errorf("寫入同意記錄失敗: %w", err)
	}

	s.auditConsent(userID, asset, channel, risks, clientIP)
	return &consent, nil
}

// riskItemsFromKeys 把 key 集合包成 RiskItem 供 fingerprint 比對（label 不參與雜湊）
func riskItemsFromKeys(keys []string) []RiskItem {
	items := make([]RiskItem, 0, len(keys))
	for _, k := range keys {
		items = append(items, RiskItem{Key: k})
	}
	return items
}

// auditConsent 同意立據入審計（誰／何時／資產／風險項）
func (s *TransmissionConsentService) auditConsent(userID uint, asset *model.Asset, channel string, risks []RiskItem, clientIP string) {
	s.writeAudit(&model.AuditLog{
		Action:     model.ActionCreate,
		Resource:   model.ResourceTransmission,
		ResourceID: &asset.ID,
		// resource=transmission 使 (resource, resource_id) 反推不到資產；同意立據
		// 是「對這台資產做的事」，主體鍵須直接釘上（auditor-workbench）
		AssetID:  &asset.ID,
		Status:   model.StatusSuccess,
		UserID:   userID,
		Username: s.usernameOf(userID),
		ClientIP: clientIP,
		Details:  s.gateDetails("consent", asset, channel, risks),
	})
}

// auditGateDenied strict 拒絕入審計
func (s *TransmissionConsentService) auditGateDenied(userID uint, asset *model.Asset, channel string, risks []RiskItem, clientIP string) {
	s.writeAudit(&model.AuditLog{
		Action:     model.ActionExecute,
		Resource:   model.ResourceTransmission,
		ResourceID: &asset.ID,
		AssetID:    &asset.ID,
		Status:     model.StatusDenied,
		UserID:     userID,
		Username:   s.usernameOf(userID),
		ClientIP:   clientIP,
		ErrorMsg:   "傳輸安全政策（嚴格）拒絕 connect-token 簽發",
		Details:    s.gateDetails("strict_reject", asset, channel, risks),
	})
}

// gateDetails 審計詳情 JSON（事件型態／資產／通道／風險項）
func (s *TransmissionConsentService) gateDetails(event string, asset *model.Asset, channel string, risks []RiskItem) string {
	payload, err := json.Marshal(map[string]interface{}{
		"event":      event,
		"asset_id":   asset.ID,
		"asset_name": asset.Name,
		"channel":    channel,
		"risks":      risks,
	})
	if err != nil {
		return fmt.Sprintf(`{"event":%q,"channel":%q}`, event, channel)
	}
	return string(payload)
}

// usernameOf 審計反正規化用（低頻路徑，查庫可接受）；查無回空
func (s *TransmissionConsentService) usernameOf(userID uint) string {
	var user model.User
	if err := s.db.Select("username").Where("id = ?", userID).First(&user).Error; err != nil {
		return ""
	}
	return user.Username
}

// writeAudit 審計寫入（同意/拒絕事件低頻，直寫；失敗記 log 不阻斷主流程）
func (s *TransmissionConsentService) writeAudit(entry *model.AuditLog) {
	if err := s.db.Create(entry).Error; err != nil {
		log.Printf("[TransmissionConsent] 審計寫入失敗: %v", err)
	}
}
