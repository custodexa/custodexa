package audit

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 每日簽核的計數與明細共用同一組查詢範圍：抽屜寫「5 筆」、列出來就是那 5 筆，
// 簽核時固化的快照與同一交易內的明細範圍一致。

// DailyReviewDetailLimit 單日明細中登入失敗與高危操作各列的筆數上限
const DailyReviewDetailLimit = 20

// 來源類別（保留水位的類別鍵，亦為明細回應 sources 的鍵）
const (
	dailyReviewSourceAuditLog     = string(model.RetentionClassAuditLog)
	dailyReviewSourceCommandAlert = string(model.RetentionClassCommandAlert)
)

// loginFailureScope 登入失敗：action=login 且狀態為 failure 或 denied，排除例行的憑證到期。
//
// 涵蓋**兩種狀態值**：認證失敗記 `failure`（密碼錯誤、憑證交換失敗），授權拒絕記
// `denied`（准入規則拒絕、外部帳號以本地密碼登入、傳輸嚴格拒絕）。只數其一會讓
// 外部身分提供者的登入拒絕全數漏算。**判準是 `action=login` 而非 `resource=auth`**：
// 資源授權拒絕的 action 依方法推導，永遠不是 login，故不會被誤計；反之以 resource
// 收斂會排除 `resource=user`／`resource=transmission` 的登入拒絕。
//
// **例行的 token 到期不計入**：存取憑證週期性到期並由前端自動刷新，照單全收會讓
// 這個數字被正常流量淹沒。排除的是審計側的原因碼，對外回應與簽章無效不可區分。
// `COALESCE` 不可省：`NOT LIKE` 遇 NULL 得 NULL，會把 details 為 NULL 的列靜默排除。
func loginFailureScope(db *gorm.DB, start, end time.Time) *gorm.DB {
	return db.Model(&model.AuditLog{}).
		Where("action = ? AND status IN ? AND created_at >= ? AND created_at < ?",
			model.ActionLogin, []model.AuditStatus{model.StatusFailure, model.StatusDenied},
			start.UTC(), end.UTC()).
		Where("COALESCE(details, '') NOT LIKE ?", `%"reason":"`+model.AuditReasonTokenExpired+`"%`)
}

// highRiskSyncExportPath 同步匯出端點：審計慣例把匯出記成 read＋資源，
// 但它把稽核證據整包帶出系統，屬於「稽核證據匯出」，以完整路徑收錄
const highRiskSyncExportPath = "/api/v1/audit-export"

// highRiskScope 高危操作（白名單）：任何資源的刪除；安全政策、syslog 設定、稽核證據
// 匯出三類資源的寫入類動作（建立、更新、刪除），加上同步匯出；使用者帳號的建立與更新。
//
// **判準是 action 而非 HTTP 方法**：三類資源的讀取（政策清單、條文定義、syslog 設定、
// 匯出清單、公鑰、產物下載）與預覽都不改狀態，例行瀏覽不得灌大這個數字。
// 已固化的簽核快照不重算，口徑只影響此後的即時計數、明細與新簽核
func highRiskScope(db *gorm.DB, start, end time.Time) *gorm.DB {
	// 設定與證據類資源：只有寫入類動作算高危
	configResources := []model.AuditResource{
		model.ResourceSecurityPolicy, model.ResourceSyslogSetting, model.ResourceAuditExport,
	}
	writeActions := []model.AuditAction{model.ActionCreate, model.ActionUpdate, model.ActionDelete}
	// 安全政策的唯讀試算端點：現行審計已記為 read；升級前的版本記成 create，
	// 以完整路徑排除，避免舊列繼續灌大尚未簽核的日子
	previewPaths := []string{
		"/api/v1/security-policies/apply-preview",
		"/api/v1/security-policies/compliance/preview",
	}
	return db.Model(&model.AuditLog{}).
		Where("created_at >= ? AND created_at < ?", start.UTC(), end.UTC()).
		Where("action = ? OR (resource IN ? AND action IN ? AND COALESCE(path, '') NOT IN ?) "+
			"OR (resource = ? AND action = ? AND path = ?) OR (resource = ? AND action IN ?)",
			model.ActionDelete,
			configResources, writeActions, previewPaths,
			model.ResourceAuditExport, model.ActionRead, highRiskSyncExportPath,
			model.ResourceUser,
			[]model.AuditAction{model.ActionCreate, model.ActionUpdate})
}

// alertScope 觸發時刻落在該日起訖內的告警
func alertScope(db *gorm.DB, start, end time.Time) *gorm.DB {
	return db.Model(&model.CommandAlert{}).
		Where("triggered_at >= ? AND triggered_at < ?", start.UTC(), end.UTC())
}

// sourceStatus 依保留水位判定來源在 [start, end) 的完整性：
// 水位不早於該日結束為 purged、落在起訖之間為 partial、否則 complete；無水位列為 complete
func sourceStatus(watermarks map[model.RetentionClass]model.AuditRetentionWatermark, class model.RetentionClass, start, end time.Time) string {
	wm, ok := watermarks[class]
	if !ok {
		return model.DailyReviewSourceComplete
	}
	switch {
	case !end.After(wm.PurgedThroughAt):
		return model.DailyReviewSourcePurged
	case start.Before(wm.PurgedThroughAt):
		return model.DailyReviewSourcePartial
	default:
		return model.DailyReviewSourceComplete
	}
}

func sourceRank(status string) int {
	switch status {
	case model.DailyReviewSourcePurged:
		return 2
	case model.DailyReviewSourcePartial:
		return 1
	}
	return 0
}

// DailyReviewSnapshot 一個所屬日的安全事件計數。
//
// 每一項計數旁記其來源狀態：purged 的計數為 null（未知，不得當成 0）、partial 為
// 現存筆數（下限）。簽核時固化入列，供稽核者比對簽核者當時審閱的內容。
type DailyReviewSnapshot struct {
	Date string `json:"date"`
	// LoginFailures 登入失敗數（來源：操作日誌）
	LoginFailures       *int64 `json:"login_failures"`
	LoginFailuresSource string `json:"login_failures_source"`
	// HighRiskOps 高危操作數（來源：操作日誌）
	HighRiskOps       *int64 `json:"high_risk_ops"`
	HighRiskOpsSource string `json:"high_risk_ops_source"`
	// UnreviewedAlerts 未審閱告警數；AlertsTotal／Benign／Escalated 為該日告警總數與處置分布
	UnreviewedAlerts *int64 `json:"unreviewed_alerts"`
	AlertsTotal      *int64 `json:"alerts_total"`
	AlertsBenign     *int64 `json:"alerts_benign"`
	AlertsEscalated  *int64 `json:"alerts_escalated"`
	AlertsSource     string `json:"alerts_source"`
}

func (s *DailyReviewSnapshot) worstSource() string {
	worst := model.DailyReviewSourceComplete
	for _, st := range []string{s.LoginFailuresSource, s.HighRiskOpsSource, s.AlertsSource} {
		if sourceRank(st) > sourceRank(worst) {
			worst = st
		}
	}
	return worst
}

func countOrNull(q *gorm.DB, status string) (*int64, error) {
	if status == model.DailyReviewSourcePurged {
		return nil, nil
	}
	var n int64
	if err := q.Count(&n).Error; err != nil {
		return nil, err
	}
	return &n, nil
}

// computeSnapshot 以共用查詢範圍計算一天的計數與來源狀態
func computeSnapshot(db *gorm.DB, date string, start, end time.Time, watermarks map[model.RetentionClass]model.AuditRetentionWatermark) (*DailyReviewSnapshot, error) {
	logStatus := sourceStatus(watermarks, model.RetentionClassAuditLog, start, end)
	alertStatus := sourceStatus(watermarks, model.RetentionClassCommandAlert, start, end)
	snap := &DailyReviewSnapshot{Date: date, LoginFailuresSource: logStatus, HighRiskOpsSource: logStatus, AlertsSource: alertStatus}
	var err error
	if snap.LoginFailures, err = countOrNull(loginFailureScope(db, start, end), logStatus); err != nil {
		return nil, fmt.Errorf("統計登入失敗數: %w", err)
	}
	if snap.HighRiskOps, err = countOrNull(highRiskScope(db, start, end), logStatus); err != nil {
		return nil, fmt.Errorf("統計高危操作數: %w", err)
	}
	if snap.UnreviewedAlerts, err = countOrNull(alertScope(db, start, end).Where("reviewed_at IS NULL"), alertStatus); err != nil {
		return nil, fmt.Errorf("統計未審閱告警數: %w", err)
	}
	if snap.AlertsTotal, err = countOrNull(alertScope(db, start, end), alertStatus); err != nil {
		return nil, fmt.Errorf("統計告警總數: %w", err)
	}
	if snap.AlertsBenign, err = countOrNull(alertScope(db, start, end).Where("reviewed_at IS NOT NULL AND disposition = ?", model.AlertDispositionBenign), alertStatus); err != nil {
		return nil, fmt.Errorf("統計無害告警數: %w", err)
	}
	if snap.AlertsEscalated, err = countOrNull(alertScope(db, start, end).Where("reviewed_at IS NOT NULL AND disposition = ?", model.AlertDispositionEscalated), alertStatus); err != nil {
		return nil, fmt.Errorf("統計升級處理告警數: %w", err)
	}
	return snap, nil
}

// Snapshot 以目前的資料計算指定起訖的計數（未簽日的即時計數）
func (s *DailyReviewService) Snapshot(date string, start, end time.Time) (*DailyReviewSnapshot, error) {
	watermarks, err := NewRetentionWatermarkService(s.db).Load()
	if err != nil {
		return nil, fmt.Errorf("讀取保留水位: %w", err)
	}
	return computeSnapshot(s.db, date, start, end, watermarks)
}

// DailyReviewAlertItem 單日明細中的一筆告警
type DailyReviewAlertItem struct {
	ID          uint       `json:"id"`
	RuleName    string     `json:"rule_name"`
	Kind        string     `json:"kind"`
	Severity    string     `json:"severity"`
	Command     string     `json:"command"`
	UserID      uint       `json:"user_id"`
	AssetID     *uint      `json:"asset_id,omitempty"`
	TriggeredAt time.Time  `json:"triggered_at"`
	ReviewedAt  *time.Time `json:"reviewed_at,omitempty"`
	Disposition string     `json:"disposition"`
}

// DailyReviewEventItem 單日明細中的一筆操作日誌（登入失敗或高危操作）
type DailyReviewEventItem struct {
	ID        uint                `json:"id"`
	CreatedAt time.Time           `json:"created_at"`
	UserID    uint                `json:"user_id"`
	Username  string              `json:"username"`
	Action    model.AuditAction   `json:"action"`
	Resource  model.AuditResource `json:"resource"`
	Status    model.AuditStatus   `json:"status"`
	ClientIP  string              `json:"client_ip"`
	Path      string              `json:"path"`
	ErrorMsg  string              `json:"error_msg"`
}

// DailyReviewEventList 一類事件的明細：最早的 20 筆與目前可查的總數。
//
// 總數描述的是「此刻查得到幾筆」，連同 SourceStatus 一起讀：purged 時查得到的
// 是 0 筆，這不等於當天沒有發生——快照語義的計數（counts）在 purged 時為 null
type DailyReviewEventList struct {
	Total        int64                  `json:"total"`
	Items        []DailyReviewEventItem `json:"items"`
	SourceStatus string                 `json:"source_status"`
}

func eventList(scope *gorm.DB, status string) (DailyReviewEventList, error) {
	out := DailyReviewEventList{SourceStatus: status, Items: []DailyReviewEventItem{}}
	var total int64
	if err := scope.Session(&gorm.Session{}).Count(&total).Error; err != nil {
		return out, err
	}
	out.Total = total
	if err := scope.Session(&gorm.Session{}).
		Select("id, created_at, user_id, username, action, resource, status, client_ip, path, error_msg").
		Order("created_at ASC, id ASC").Limit(DailyReviewDetailLimit).Scan(&out.Items).Error; err != nil {
		return out, err
	}
	return out, nil
}

func unreviewedAlerts(db *gorm.DB, start, end time.Time) ([]DailyReviewAlertItem, error) {
	items := []DailyReviewAlertItem{}
	err := alertScope(db, start, end).Where("reviewed_at IS NULL").
		Select("id, rule_name, kind, severity, command, user_id, asset_id, triggered_at, reviewed_at, disposition").
		Order("triggered_at ASC, id ASC").Scan(&items).Error
	return items, err
}

// parseSnapshot 解析簽核列的快照（舊制快照的計數為整數，同樣解得出）
func parseSnapshot(raw string) (map[string]any, error) {
	var out map[string]any
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, err
	}
	return out, nil
}

// jsonUnmarshalSnapshot 把簽核列的快照解回結構（舊制快照的整數計數同樣解得出）
func jsonUnmarshalSnapshot(raw string, v *DailyReviewSnapshot) error {
	return json.Unmarshal([]byte(raw), v)
}
