package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"gorm.io/gorm"
)

// 系統告警目錄與明細的服務層。
//
// 目錄只提供「讀」與「調分級」兩個動作：系統告警沒有停用或刪除入口，分級調到最低仍會
// 產生告警並送到每個啟用通道。分級覆寫與審計在同一交易內，審計寫不進去則分級不變。

// 目錄近期筆數的統計窗。
const systemAlertRecentWindow = 30 * 24 * time.Hour

// SystemAlertCatalogEntry 目錄一列的視圖。
type SystemAlertCatalogEntry struct {
	Key               port.SystemAlertType
	Group             SystemAlertGroup
	DefaultSeverity   string
	EffectiveSeverity string
	Adjusted          bool
	// Recent30d 近 30 天該類型的告警筆數；nil＝呼叫者無稽核檢視，不帶此欄。
	Recent30d *int64
}

// SystemAlertSeverityActor 調整分級的操作者。
type SystemAlertSeverityActor struct {
	ID   uint
	Name string
	IP   string
}

// SystemAlertCatalogService 目錄與明細服務。
type SystemAlertCatalogService struct {
	db      *gorm.DB
	auditTx port.TxSink
	now     func() time.Time
}

// NewSystemAlertCatalogService 建立目錄服務；auditTx 是交易內審計落地面（建構參數，
// 組裝根傳入已通過自檢的實例；nil 時調分級回錯而不是無審計寫入）。
func NewSystemAlertCatalogService(db *gorm.DB, auditTx port.TxSink) *SystemAlertCatalogService {
	return &SystemAlertCatalogService{db: db, auditTx: auditTx, now: time.Now}
}

// List 依登錄順序回傳全部類型；withRecent 為真時附近 30 天筆數。
func (s *SystemAlertCatalogService) List(withRecent bool) ([]SystemAlertCatalogEntry, error) {
	views, err := ListSystemAlertSeverities(s.db)
	if err != nil {
		return nil, err
	}
	var counts map[string]int64
	if withRecent {
		counts, err = s.recentCounts()
		if err != nil {
			return nil, err
		}
	}
	out := make([]SystemAlertCatalogEntry, 0, len(views))
	for _, v := range views {
		def, ok := LookupSystemAlertType(v.Type)
		if !ok {
			continue
		}
		e := SystemAlertCatalogEntry{
			Key: v.Type, Group: def.Group, DefaultSeverity: v.Default,
			EffectiveSeverity: v.Effective, Adjusted: v.Adjusted,
		}
		if withRecent {
			n := counts[string(v.Type)]
			e.Recent30d = &n
		}
		out = append(out, e)
	}
	return out, nil
}

func (s *SystemAlertCatalogService) recentCounts() (map[string]int64, error) {
	var rows []struct {
		ReasonCode string
		N          int64
	}
	since := s.now().Add(-systemAlertRecentWindow)
	if err := s.db.Table("command_alerts").
		Select("reason_code, COUNT(*) AS n").
		Where("kind = ? AND triggered_at >= ?", model.AlertKindSystemSecurity, since).
		Group("reason_code").Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("統計系統告警筆數失敗: %w", err)
	}
	out := make(map[string]int64, len(rows))
	for _, r := range rows {
		out[r.ReasonCode] = r.N
	}
	return out, nil
}

// SetSeverity 調整一個類型的分級，覆寫與審計同交易。
// 未登錄回 ErrSystemAlertTypeUnknown，非三值回 ErrSystemAlertSeverityInvalid。
func (s *SystemAlertCatalogService) SetSeverity(key, severity string, actor SystemAlertSeverityActor) (SystemAlertSeverityChange, error) {
	t := port.SystemAlertType(key)
	if _, ok := LookupSystemAlertType(t); !ok {
		return SystemAlertSeverityChange{}, ErrSystemAlertTypeUnknown
	}
	if !ValidSystemAlertSeverity(severity) {
		return SystemAlertSeverityChange{}, ErrSystemAlertSeverityInvalid
	}
	if s.auditTx == nil {
		return SystemAlertSeverityChange{}, errors.New("系統告警分級調整未注入交易內審計落地面")
	}
	var change SystemAlertSeverityChange
	err := s.db.Transaction(func(tx *gorm.DB) error {
		c, err := SetSystemAlertSeverityInTx(tx, t, severity, actor.ID)
		if err != nil {
			return err
		}
		change = c
		raw, err := json.Marshal(map[string]string{
			"event": "system_alert_severity_change", "alert_type": key,
			"severity_before": c.Before, "severity_after": c.After,
		})
		if err != nil {
			return fmt.Errorf("編碼分級調整審計詳情失敗: %w", err)
		}
		if err := port.WriteInTx(s.auditTx, tx, port.AuditEvent{
			Actor:    gatewayapi.Actor{UserID: actor.ID, Username: actor.Name},
			Action:   string(model.ActionUpdate),
			Resource: string(model.ResourceSystemAlertType),
			Status:   string(model.StatusSuccess),
			Request:  gatewayapi.RequestMeta{ClientIP: actor.IP},
			Details:  string(raw),
		}); err != nil {
			return fmt.Errorf("分級調整審計留痕失敗: %w", err)
		}
		return nil
	})
	if err != nil {
		return SystemAlertSeverityChange{}, err
	}
	return change, nil
}

// SystemAlertDeliveryView 單一目的地的投遞狀態（不含網址、密鑰與錯誤原文）。
type SystemAlertDeliveryView struct {
	DestType      string
	DestName      string
	State         string
	Attempts      int
	DeliveredAt   *time.Time
	NextAttemptAt time.Time
}

// SystemAlertScopeNode 管理類發放的節點範圍中的一個節點；節點已刪除時 Path 為空。
type SystemAlertScopeNode struct {
	ID   uint   `json:"id"`
	Path string `json:"path"`
}

// SystemAlertDetailView 一筆系統告警的結構化明細。
type SystemAlertDetailView struct {
	AlertID       uint
	AlertType     string
	Group         SystemAlertGroup
	Severity      string
	TriggeredAt   time.Time
	ActorName     string
	TargetKind    string
	TargetID      string
	Params        map[string]string
	CorrelationID string
	// AuditLogID 同交易審計列（以 correlation_id 對應）；找不到為 nil。
	AuditLogID *uint
	// ClientIP 來源位址，取自同交易審計列（告警明細不另存一份）；找不到對應審計列時為空。
	ClientIP   string
	Deliveries []SystemAlertDeliveryView
	// ScopeNodes 管理類發放的節點範圍（由接入層依參數 scope_node_ids 換算路徑後填入）；
	// 沒有節點範圍時為空。
	ScopeNodes []SystemAlertScopeNode
}

// Detail 回傳系統告警明細；告警不存在或不是系統告警回 ErrAlertNotFound。
func (s *SystemAlertCatalogService) Detail(alertID uint) (*SystemAlertDetailView, error) {
	var alert model.CommandAlert
	res := s.db.Where("id = ? AND kind = ?", alertID, model.AlertKindSystemSecurity).Limit(1).Find(&alert)
	if res.Error != nil {
		return nil, fmt.Errorf("讀取系統告警失敗: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return nil, ErrAlertNotFound
	}
	var detail model.SystemAlertDetail
	res = s.db.Where("alert_id = ?", alertID).Limit(1).Find(&detail)
	if res.Error != nil {
		return nil, fmt.Errorf("讀取系統告警明細失敗: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return nil, ErrAlertNotFound
	}
	params := map[string]string{}
	if detail.Params != "" {
		if err := json.Unmarshal([]byte(detail.Params), &params); err != nil {
			return nil, fmt.Errorf("解析系統告警參數失敗: %w", err)
		}
	}
	// actor 是保留鍵：操作者名快照，另列欄位呈現，不混在宣告參數裡。
	actor := params["actor"]
	delete(params, "actor")
	delete(params, "severity")
	view := &SystemAlertDetailView{
		AlertID: alert.ID, AlertType: detail.AlertType, Severity: alert.Severity,
		TriggeredAt: alert.TriggeredAt, ActorName: actor,
		TargetKind: detail.TargetKind, TargetID: detail.TargetID,
		Params: params, CorrelationID: detail.CorrelationID,
	}
	if def, ok := LookupSystemAlertType(port.SystemAlertType(detail.AlertType)); ok {
		view.Group = def.Group
	}
	auditID, clientIP, err := s.auditLogByCorrelation(detail.CorrelationID)
	if err != nil {
		return nil, err
	}
	view.AuditLogID = auditID
	view.ClientIP = clientIP
	var outbox []model.SystemAlertOutbox
	if err := s.db.Where("alert_id = ?", alertID).Find(&outbox).Error; err != nil {
		return nil, fmt.Errorf("讀取投遞狀態失敗: %w", err)
	}
	sort.Slice(outbox, func(i, j int) bool { return outbox[i].ID < outbox[j].ID })
	for _, o := range outbox {
		view.Deliveries = append(view.Deliveries, SystemAlertDeliveryView{
			DestType: o.DestType, DestName: o.DestName, State: o.State,
			Attempts: o.Attempts, DeliveredAt: o.DeliveredAt, NextAttemptAt: o.NextAttemptAt,
		})
	}
	return view, nil
}

// auditLogByCorrelation 以關聯識別找同交易審計列，回傳其編號與來源位址。
func (s *SystemAlertCatalogService) auditLogByCorrelation(corr string) (*uint, string, error) {
	if corr == "" {
		return nil, "", nil
	}
	pattern := `%"correlation_id":"` + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(corr) + `"%`
	var rows []model.AuditLog
	if err := s.db.Select("id", "client_ip").Where("details LIKE ? ESCAPE '\\'", pattern).
		Order("id ASC").Limit(1).Find(&rows).Error; err != nil {
		return nil, "", fmt.Errorf("對應操作日誌失敗: %w", err)
	}
	if len(rows) == 0 {
		return nil, "", nil
	}
	id := rows[0].ID
	return &id, rows[0].ClientIP, nil
}
