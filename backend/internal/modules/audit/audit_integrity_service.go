package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"gorm.io/gorm"
)

// integrityVerifyBatch 驗證掃描的分頁批次
const integrityVerifyBatch = 1000

// integrityMismatchIDCap 回報不符列 ID 的上限（防巨量結果撐爆回應）
const integrityMismatchIDCap = 100

// AuditIntegrityService audit_logs 逐列 HMAC（audit-log-compliance，
// PCI 10.3.4 補償控制之一）：寫入時計算（model BeforeCreate hook，覆蓋
// 全部**入庫**路徑）、驗證端點掃描比對。
// 限制（design D6 誠實聲明）：可偵測「改內容」與「基準後清空 HMAC」；
// 整筆刪除（連 HMAC 一起刪）本層不可偵測——該職責自 audit-checkpoint-chain
// 起由檢查點鏈承擔（本層是「內容真不真」，鏈是「序列少沒少」，兩層不得互相
// 宣稱對方的保證）。降級與丟棄的事件不入庫故不在任一層覆蓋內（誠實邊界 R2）
type AuditIntegrityService struct {
	// keyFn 版本→蓋章鑰（key-management-envelope D4）；未知版本回 nil，
	// 驗證端計為不符。activeFn 現行版本與鑰（Stamp 寫入 key_version）。
	keyFn    func(version int) []byte
	activeFn func() (int, []byte)
	// baselineMaxID 功能啟用基準（首啟持久化的當下最大 audit_logs.id）：
	// 之後寫入的列（id 更大）必帶 HMAC，空 HMAC 判不符——堵「竄改＋清空
	// HMAC」規避（對抗驗證實證的真洞）。以 id 而非 created_at 判定：
	// created_at 可隨列回填偽裝歷史列，自增 id 不可（H2 修正）
	baselineMaxID uint
}

// 套件級單例：計算點在 audit worker 批次寫入路徑，getter 取用、main 注入
var (
	auditIntegrityMu       sync.RWMutex
	auditIntegrityInstance *AuditIntegrityService
)

// loadBaseline 首次啟動持久化啟用基準；讀取失敗回錯（啟動期 DB 必須可用）。
// 回傳基準當下最大 audit_logs.id——Verify 的 legacy 判定錨點
func loadBaseline(db *gorm.DB) (uint, error) {
	var baseline model.IntegrityBaseline
	switch err := db.First(&baseline, 1).Error; {
	case err == nil:
		// 既有基準沿用（max_log_id 由 migration 回填）
	case errors.Is(err, gorm.ErrRecordNotFound):
		var maxID uint
		if err := db.Table("audit_logs").Select("COALESCE(MAX(id), 0)").Scan(&maxID).Error; err != nil {
			return 0, fmt.Errorf("讀取 audit_logs 基準 id 失敗: %w", err)
		}
		baseline = model.IntegrityBaseline{ID: 1, BaselineAt: time.Now(), MaxLogID: maxID}
		if err := db.Create(&baseline).Error; err != nil {
			return 0, fmt.Errorf("寫入完整性基準失敗: %w", err)
		}
	default:
		return 0, fmt.Errorf("讀取完整性基準失敗: %w", err)
	}
	return baseline.MaxLogID, nil
}

func registerAuditIntegrity(svc *AuditIntegrityService) {
	auditIntegrityMu.Lock()
	auditIntegrityInstance = svc
	auditIntegrityMu.Unlock()
}

// InitAuditIntegrityVersioned 建立並註冊單例（**唯一建構子**，
// key-management-envelope D4；legacy 單鑰模式已於 release-transitional-cleanup
// 拆除）：蓋章鑰由 key manager 供給——新列以現行版本蓋章並記 key_version，
// 驗證按列版本取鑰。版本鏈自 v1 起，不存在 v0 快照鑰；`HMACKeyByVersion` 對
// 不存在的版本（含 0）回 nil＝驗證不符，天然覆蓋偽造 v0。
func InitAuditIntegrityVersioned(db *gorm.DB, km *keyvault.KeyManagerService) (*AuditIntegrityService, error) {
	baselineMaxID, err := loadBaseline(db)
	if err != nil {
		return nil, err
	}
	svc := &AuditIntegrityService{
		keyFn:         km.HMACKeyByVersion,
		activeFn:      km.ActiveHMACKey,
		baselineMaxID: baselineMaxID,
	}
	registerAuditIntegrity(svc)
	return svc, nil
}

// GetAuditIntegrity 取得單例；未初始化（單測）回 nil，呼叫端需 nil 檢查
func GetAuditIntegrity() *AuditIntegrityService {
	auditIntegrityMu.RLock()
	defer auditIntegrityMu.RUnlock()
	return auditIntegrityInstance
}

// integrityPayload HMAC 涵蓋欄位的 canonical 序列化（固定 struct = 固定鍵序）。
// 不含 ID（insert 前為 0）；CreatedAt 取 UnixMicro——postgres timestamptz
// 保存微秒精度，nano 會在 round-trip 後不一致
type integrityPayload struct {
	CreatedAtUs int64  `json:"created_at_us"`
	Action      string `json:"action"`
	Resource    string `json:"resource"`
	ResourceID  *uint  `json:"resource_id"`
	// AssetID 資產主體鍵（auditor-workbench）。**omitempty 是刻意的**：
	// 指標為 nil 時整個鍵不出現，payload 位元組與本欄存在前完全相同，
	// 既有已蓋章列不會集體誤判為竄改；有值的列則納入涵蓋，把「事件被改掛到
	// 另一台資產」納入逐列偵測——資產樞紐的正確性正是靠這個鍵，不涵蓋等於
	// 樞紐的主鍵無防護
	AssetID *uint  `json:"asset_id,omitempty"`
	Status  string `json:"status"`
	UserID      uint   `json:"user_id"`
	Username    string `json:"username"`
	ClientIP    string `json:"client_ip"`
	Method      string `json:"method"`
	Path        string `json:"path"`
	ErrorMsg    string `json:"error_msg"`
	Details     string `json:"details"`
	RequestBody string `json:"request_body"`
	RequestID   string `json:"request_id"`
}

// ComputeHMAC 依列的 key_version 取鑰計算完整性驗證碼（hex）；
// 未知版本回空字串（驗證端計為不符）。
// payload 不含 key_version——格式必須與叢集 B 上線時完全一致，否則
// 既有已蓋章列全數誤判；版本被竄改時取錯鑰重算必不符，偵測不受影響
func (s *AuditIntegrityService) ComputeHMAC(l *model.AuditLog) string {
	key := s.keyFn(l.KeyVersion)
	if key == nil {
		return ""
	}
	return s.computeWith(key, l)
}

func (s *AuditIntegrityService) computeWith(key []byte, l *model.AuditLog) string {
	payload, err := json.Marshal(integrityPayload{
		CreatedAtUs: l.CreatedAt.UnixMicro(),
		Action:      string(l.Action),
		Resource:    string(l.Resource),
		ResourceID:  l.ResourceID,
		AssetID:     l.AssetID,
		Status:      string(l.Status),
		UserID:      l.UserID,
		Username:    l.Username,
		ClientIP:    l.ClientIP,
		Method:      l.Method,
		Path:        l.Path,
		ErrorMsg:    l.ErrorMsg,
		Details:     l.Details,
		RequestBody: l.RequestBody,
		RequestID:   l.RequestID,
	})
	if err != nil {
		return ""
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// Stamp 為一批待寫入列填 HMAC（以現行蓋章鑰，並記 key_version）
func (s *AuditIntegrityService) Stamp(logs []*model.AuditLog) {
	ver, key := s.activeFn()
	for _, l := range logs {
		l.KeyVersion = ver
		l.IntegrityHMAC = s.computeWith(key, l)
	}
}

// StampOne 單列填 HMAC（model BeforeCreate hook 注入點——覆蓋 middleware
// 批次以外的直寫路徑：asset GORM hook、file_tap、k8s cp）
func (s *AuditIntegrityService) StampOne(l *model.AuditLog) {
	ver, key := s.activeFn()
	l.KeyVersion = ver
	l.IntegrityHMAC = s.computeWith(key, l)
}

// IntegrityReport 驗證結果（三計數誠實分類：基準前的無 HMAC 列獨立計數，不算不符）
type IntegrityReport struct {
	From          time.Time `json:"from"`
	To            time.Time `json:"to"`
	Checked       int64     `json:"checked"`
	Passed        int64     `json:"passed"`
	Mismatched    int64     `json:"mismatched"`
	MismatchedIDs []uint    `json:"mismatched_ids"`
	// Legacy 完整性基準之前的既有列（id <= 基準 max_log_id 且 HMAC 空）。
	// 基準之後的空 HMAC 列計入 Mismatched——防「竄改＋清空」規避；
	// 以 id 判定而非 created_at（時間可回填偽裝，id 不可）
	Legacy int64 `json:"legacy"`
}

// VerifyIDRange 以 **id 區間**掃描重算列級 HMAC（audit-checkpoint-chain 8.3）。
//
// 與 Verify 的差別只有切窗維度：Verify 以 created_at 切窗回答「這段時間的列
// 內容真不真」，本方法以 id 切窗，因為檢查點的區間主軸是 id（D1——回灌列的
// created_at 是過去時刻，時間切窗必然切不齊檢查點區間）。
//
// 判定規則與 Verify 逐條相同（含基準前空 HMAC 列獨立計為 Legacy 不算不符），
// **刻意不另寫一套**：兩把尺會讓「列級端點說沒事、檢查點端點說有事」成為
// 無法歸因的常態
func (s *AuditIntegrityService) VerifyIDRange(db *gorm.DB, idFrom, idTo uint) (*IntegrityReport, error) {
	report := &IntegrityReport{MismatchedIDs: []uint{}}
	if idFrom > idTo {
		return report, nil
	}
	lastID := idFrom - 1
	for {
		var batch []model.AuditLog
		if err := db.Unscoped().
			Where("id > ? AND id <= ?", lastID, idTo).
			Order("id").Limit(integrityVerifyBatch).Find(&batch).Error; err != nil {
			return nil, fmt.Errorf("掃描 audit_logs [%d,%d] 失敗: %w", idFrom, idTo, err)
		}
		if len(batch) == 0 {
			break
		}
		for i := range batch {
			l := &batch[i]
			lastID = l.ID
			report.Checked++
			if l.IntegrityHMAC == "" && l.ID <= s.baselineMaxID {
				report.Legacy++
				continue
			}
			if l.IntegrityHMAC != "" && hmac.Equal([]byte(l.IntegrityHMAC), []byte(s.ComputeHMAC(l))) {
				report.Passed++
			} else {
				report.Mismatched++
				if len(report.MismatchedIDs) < integrityMismatchIDCap {
					report.MismatchedIDs = append(report.MismatchedIDs, l.ID)
				}
			}
		}
	}
	return report, nil
}

// Verify 掃描時間範圍內全部列重算比對（admin 驗證端點）
func (s *AuditIntegrityService) Verify(db *gorm.DB, from, to time.Time) (*IntegrityReport, error) {
	report := &IntegrityReport{From: from, To: to, MismatchedIDs: []uint{}}
	lastID := uint(0)
	for {
		var batch []model.AuditLog
		// Unscoped：軟刪列也在驗證範圍（守衛防的就是暗中軟刪）
		if err := db.Unscoped().
			Where("created_at >= ? AND created_at < ? AND id > ?", from, to, lastID).
			Order("id").Limit(integrityVerifyBatch).Find(&batch).Error; err != nil {
			return nil, fmt.Errorf("掃描 audit_logs 失敗: %w", err)
		}
		if len(batch) == 0 {
			break
		}
		for i := range batch {
			l := &batch[i]
			lastID = l.ID
			report.Checked++
			// 空 HMAC：基準前（id 不大於基準 max_log_id）=歷史列（誠實獨立
			// 計數）；基準後=可疑——上線後所有寫入路徑必經 BeforeCreate
			// 蓋章，空值即異常。判 id 不判 created_at：新插列必拿更大的
			// 自增 id，回填時間欄無法偽裝歷史列（H2 修正）
			if l.IntegrityHMAC == "" && l.ID <= s.baselineMaxID {
				report.Legacy++
				continue
			}
			if l.IntegrityHMAC != "" && hmac.Equal([]byte(l.IntegrityHMAC), []byte(s.ComputeHMAC(l))) {
				report.Passed++
			} else {
				report.Mismatched++
				if len(report.MismatchedIDs) < integrityMismatchIDCap {
					report.MismatchedIDs = append(report.MismatchedIDs, l.ID)
				}
			}
		}
	}
	return report, nil
}
