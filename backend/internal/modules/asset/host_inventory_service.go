package asset

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/sshmaterial"
	"github.com/custodexa/backend/pkg/gatewayapi"
)

// 主機帳號盤點服務：發起（同交易建列與審計）、背景工作池執行、結束交易寫結果與告警、啟動收尾。

const (
	// inventoryWorkerSlots 全系統同時執行的盤點數。
	inventoryWorkerSlots = 4
	// inventoryRunDeadline 單次執行期限（撥號＋四個指令＋餘裕）。
	inventoryRunDeadline = 90 * time.Second
	// inventoryOrphanGrace 判定 running 列為殘留的額外寬限。
	inventoryOrphanGrace = 30 * time.Second
	// inventoryUpsertBatch 結果批次寫入的每批列數。
	inventoryUpsertBatch = 1000
)

var (
	// ErrInventoryScanRunning 該資產已有未結束的盤點。
	ErrInventoryScanRunning = errors.New("inventory: scan already running")
	// ErrInventoryAssetNotFound 資產不存在或已刪除。
	ErrInventoryAssetNotFound = errors.New("inventory: asset not found")

	errInventoryScanNotRunning = errors.New("inventory: scan no longer running")
)

// InventoryActor 發起或處置的操作者。
type InventoryActor struct {
	UserID   uint
	Username string
	ClientIP string
	// APIToken 該次請求經由的 API token（親自操作與背景執行時為零值），供稽核歸因。
	APIToken model.APITokenRef
}

// requestMeta 稽核列的請求欄位：來源位址與經由的 API token。
func (a InventoryActor) requestMeta() gatewayapi.RequestMeta {
	return gatewayapi.RequestMeta{ClientIP: a.ClientIP}.WithAPIToken(a.APIToken.ID, a.APIToken.Name)
}

// InventoryPolicyReader 讀取政策鍵現值的窄介面（*policy.SecurityPolicyService 實作）。
type InventoryPolicyReader interface {
	Get(key string) string
}

// inventoryCollector 撥號、執行與判定（測試可替換）。
type inventoryCollector func(ctx context.Context, scanID uint, addr string, creds *AssetCredentials, hostKey ssh.HostKeyCallback, privGroups string) (*invScanResult, *inventoryError)

func defaultInventoryCollector(ctx context.Context, scanID uint, addr string, creds *AssetCredentials, hostKey ssh.HostKeyCallback, privGroups string) (*invScanResult, *inventoryError) {
	var escPassword []byte
	if inventoryExecutorFrom(ctx) {
		// 專用帳號身分：密碼型的密碼副本只供提權讀取第二段使用，collectInventoryWith 用完清零
		escPassword = []byte{}
		if creds.Password != nil {
			_ = creds.Password.Borrow(func(b []byte) error {
				escPassword = append(escPassword, b...)
				return nil
			})
		}
	}
	password := sshmaterial.NewPassword(creds.Password)
	privateKey := creds.PrivateKey
	creds.Password, creds.PrivateKey = nil, nil
	return collectInventoryWith(ctx, scanID, addr, creds.Username, password, privateKey, hostKey, privGroups, escPassword)
}

// HostAccountInventoryService 主機帳號盤點。
type HostAccountInventoryService struct {
	db       *gorm.DB
	identity inventoryIdentitySource
	hostKeys *HostKeyService
	policies InventoryPolicyReader
	auditTx  port.TxSink
	alerts   port.SystemAlertSink
	limiter  *executorCheckLimiter

	collect inventoryCollector
	// executorLockWait 盤點等專用帳號互斥的上限（0＝預設 30 秒）；beforeExecutorLock 僅供測試，
	// 停在「身分判定通過、取鎖之前」。
	executorLockWait   time.Duration
	beforeExecutorLock func()
	hostKeyFor         func(dc HostKeyDialContext) ssh.HostKeyCallback
	runDeadline        time.Duration
	slots              chan struct{}

	mu     sync.Mutex
	active map[uint]bool
	wg     sync.WaitGroup
}

// NewHostAccountInventoryService 以資產預設帳號為登入身分建立盤點服務。
func NewHostAccountInventoryService(db *gorm.DB, creds inventoryCredentialFetcher, hostKeys *HostKeyService,
	policies InventoryPolicyReader, auditTx port.TxSink, alerts port.SystemAlertSink) *HostAccountInventoryService {
	s := &HostAccountInventoryService{
		db: db, identity: newDefaultAccountIdentitySource(creds), hostKeys: hostKeys, policies: policies,
		auditTx: auditTx, alerts: alerts, collect: defaultInventoryCollector,
		runDeadline: inventoryRunDeadline, slots: make(chan struct{}, inventoryWorkerSlots), active: map[uint]bool{},
	}
	s.hostKeyFor = func(dc HostKeyDialContext) ssh.HostKeyCallback {
		cb, _ := s.hostKeys.CallbackFor(dc)
		return cb
	}
	return s
}

// UseExecutorIdentity 換上專用帳號身分來源：有專用帳號掛載的資產以它登入，其餘照預設帳號。
// limiter 與測試登入共用，專用帳號模式發起前先取目標身分令牌。組裝根呼叫一次。
func (s *HostAccountInventoryService) UseExecutorIdentity(resolver inventoryExecutorResolver, limiter *executorCheckLimiter) {
	s.identity = newExecutorAwareIdentitySource(s.db, s.identity, resolver)
	s.limiter = limiter
}

func (s *HostAccountInventoryService) setActive(id uint, on bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if on {
		s.active[id] = true
	} else {
		delete(s.active, id)
	}
}

func (s *HostAccountInventoryService) isActive(id uint) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active[id]
}

// Wait 等候已收下的盤點全部結束（測試與關機用）。
func (s *HostAccountInventoryService) Wait() { s.wg.Wait() }

// Initiate 發起一次盤點：同一交易內解析身分、收尾殘留、建列與發起審計；提交後交給工作池。
func (s *HostAccountInventoryService) Initiate(assetID uint, actor InventoryActor) (*model.HostAccountScan, error) {
	var scan model.HostAccountScan
	err := s.db.Transaction(func(tx *gorm.DB) error {
		var a model.Asset
		if err := tx.First(&a, assetID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrInventoryAssetNotFound
			}
			return err
		}
		id, err := s.identity.Resolve(tx, &a)
		if err != nil {
			return err
		}
		if id.Mode == model.HostAccountIdentityExecutor && s.limiter != nil &&
			!s.limiter.allowTarget(executorTargetKey(a.Host, a.Port, id.Username)) {
			return ErrInventoryExecutorRateLimited
		}
		if err := s.collectOrphans(tx, assetID); err != nil {
			return err
		}
		scan = model.HostAccountScan{
			AssetID: assetID, Platform: model.HostAccountPlatformPOSIX, IdentityMode: id.Mode,
			IdentityAccountID: id.AccountID, InitiatedBy: actor.UserID, InitiatedByName: actor.Username,
			Status: model.HostAccountScanQueued, PrivilegedGroups: s.privilegedGroups(), Coverage: "[]",
		}
		if err := tx.Create(&scan).Error; err != nil {
			if isInventoryActiveConflict(err) {
				return ErrInventoryScanRunning
			}
			return err
		}
		// 提交前登記：併發發起的另一交易讀到這列時，它必然在登記表內，不會被誤收為殘留
		s.setActive(scan.ID, true)
		details, _ := json.Marshal(map[string]any{
			"asset_id": assetID, "identity_mode": id.Mode, "identity_account_id": id.AccountID, "scan_id": scan.ID,
			"identity_username": id.Username,
		})
		return s.writeScanAudit(tx, model.ActionInventoryScan, &scan, actor, string(details))
	})
	if err != nil {
		if scan.ID != 0 {
			s.setActive(scan.ID, false)
		}
		return nil, err
	}
	s.dispatch(scan.ID)
	return &scan, nil
}

func isInventoryActiveConflict(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "uniq_host_account_scans_active") ||
		(strings.Contains(msg, "UNIQUE constraint failed") && strings.Contains(msg, "host_account_scans"))
}

func (s *HostAccountInventoryService) privilegedGroups() string {
	if s.policies == nil {
		return ""
	}
	return s.policies.Get(policy.PolicyHostPrivilegedGroupsPOSIX)
}

// collectOrphans 該資產的未結束列：不在本行程登記表、或 running 超過期限加寬限者收為中斷；其餘回衝突。
func (s *HostAccountInventoryService) collectOrphans(tx *gorm.DB, assetID uint) error {
	var rows []model.HostAccountScan
	if err := tx.Where("asset_id = ? AND status IN ?", assetID,
		[]string{model.HostAccountScanQueued, model.HostAccountScanRunning}).Find(&rows).Error; err != nil {
		return err
	}
	cutoff := time.Now().Add(-(s.runDeadline + inventoryOrphanGrace))
	for i := range rows {
		r := &rows[i]
		stale := r.Status == model.HostAccountScanRunning && r.StartedAt != nil && r.StartedAt.Before(cutoff)
		if s.isActive(r.ID) && !stale {
			return ErrInventoryScanRunning
		}
		if err := s.markInterrupted(tx, r); err != nil {
			return err
		}
	}
	return nil
}

// markInterrupted 以中斷結束一筆未結束的盤點並寫結束審計（同交易）。
func (s *HostAccountInventoryService) markInterrupted(tx *gorm.DB, r *model.HostAccountScan) error {
	now := time.Now()
	res := tx.Model(&model.HostAccountScan{}).
		Where("id = ? AND status IN ?", r.ID, []string{model.HostAccountScanQueued, model.HostAccountScanRunning}).
		Updates(map[string]any{"status": model.HostAccountScanInterrupted, "failure_reason": model.InventoryInterrupted, "finished_at": now})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return nil
	}
	r.Status, r.FailureReason, r.FinishedAt = model.HostAccountScanInterrupted, model.InventoryInterrupted, &now
	return s.writeDoneAudit(tx, r, nil, "")
}

// RecoverInterrupted 啟動收尾：工作池接單之前，把全部未結束的盤點改為中斷並各寫結束審計。
func (s *HostAccountInventoryService) RecoverInterrupted() (int, error) {
	var rows []model.HostAccountScan
	if err := s.db.Where("status IN ?", []string{model.HostAccountScanQueued, model.HostAccountScanRunning}).
		Find(&rows).Error; err != nil {
		return 0, err
	}
	n := 0
	for i := range rows {
		r := &rows[i]
		if s.isActive(r.ID) {
			continue
		}
		if err := s.db.Transaction(func(tx *gorm.DB) error { return s.markInterrupted(tx, r) }); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// dispatch 交給工作池；每個工作以 recover 包住，panic 只結束該筆。
func (s *HostAccountInventoryService) dispatch(scanID uint) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer s.setActive(scanID, false)
		s.slots <- struct{}{}
		defer func() { <-s.slots }()
		defer func() {
			if p := recover(); p != nil {
				log.Printf("[HostAccountInventory] scan=%d worker panic recovered", scanID)
				s.finishInterrupted(scanID)
			}
		}()
		s.run(scanID)
	}()
}

func (s *HostAccountInventoryService) finishInterrupted(scanID uint) {
	err := s.db.Transaction(func(tx *gorm.DB) error {
		var r model.HostAccountScan
		if err := tx.First(&r, scanID).Error; err != nil {
			return err
		}
		return s.markInterrupted(tx, &r)
	})
	if err != nil {
		log.Printf("[HostAccountInventory] scan=%d interrupt close failed", scanID)
	}
}

// defaultIdentitySource 預設帳號身分的來源：發起時記下預設帳號的盤點，執行時不看專用帳號掛載。
func (s *HostAccountInventoryService) defaultIdentitySource() inventoryIdentitySource {
	if aware, ok := s.identity.(*executorAwareIdentitySource); ok {
		return aware.fallback
	}
	return s.identity
}

// run 執行一筆盤點：開頭重新判定資產與身分、撥號與判定、結束交易。
func (s *HostAccountInventoryService) run(scanID uint) {
	var scan model.HostAccountScan
	var a model.Asset
	var id inventoryIdentity
	reason := ""
	err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.First(&scan, scanID).Error; err != nil {
			return err
		}
		if scan.Status != model.HostAccountScanQueued {
			return errInventoryScanNotRunning
		}
		now := time.Now()
		if err := tx.Model(&scan).Updates(map[string]any{"status": model.HostAccountScanRunning, "started_at": now}).Error; err != nil {
			return err
		}
		scan.Status, scan.StartedAt = model.HostAccountScanRunning, &now
		err := tx.First(&a, scan.AssetID).Error
		switch {
		case errors.Is(err, gorm.ErrRecordNotFound):
			reason = model.InventoryAssetChanged
			return nil
		case err != nil:
			return err
		case !inventoryPlatformSupported(&a):
			reason = model.InventoryAssetChanged
			return nil
		}
		if scan.IdentityMode == model.HostAccountIdentityExecutor {
			// 專用帳號身分：掛載的重讀與解封在取鎖之後（取鎖時不得持有交易），這裡只帶發起時記下的身分
			id = inventoryIdentity{AccountID: scan.IdentityAccountID, Mode: scan.IdentityMode}
			return nil
		}
		id, err = s.defaultIdentitySource().Resolve(tx, &a)
		switch {
		case errors.Is(err, ErrInventoryPlatformUnsupported):
			reason = model.InventoryAssetChanged
		case errors.Is(err, ErrInventoryNoAccount):
			reason = model.InventoryNoAccount
		case errors.Is(err, ErrInventoryNoSecret):
			reason = model.InventoryNoSecret
		case err != nil:
			return err
		case id.AccountID != scan.IdentityAccountID:
			reason = model.InventoryNoAccount
		}
		return nil
	})
	if errors.Is(err, errInventoryScanNotRunning) {
		return
	}
	if err != nil {
		log.Printf("[HostAccountInventory] scan=%d start failed", scanID)
		s.finishFailed(scanID, model.InventoryPersistFailed)
		return
	}
	if reason != "" {
		s.finishFailed(scanID, reason)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.runDeadline)
	defer cancel()
	if id.Mode == model.HostAccountIdentityExecutor {
		ctx = withInventoryExecutor(ctx)
	}
	var creds *AssetCredentials
	if id.Mode == model.HostAccountIdentityExecutor {
		c, unlock, why := s.acquireExecutorCredentials(ctx, &a, &scan)
		if why != "" {
			s.finishFailed(scanID, why)
			return
		}
		defer unlock()
		creds = c
	} else {
		c, err := s.defaultIdentitySource().Credentials(&a, id)
		if err != nil {
			switch {
			case errors.Is(err, ErrInventoryNoAccount):
				s.finishFailed(scanID, model.InventoryNoAccount)
			default:
				s.finishFailed(scanID, model.InventoryNoSecret)
			}
			return
		}
		creds = c
	}
	defer creds.Destroy()
	hostKey := s.hostKeyFor(HostKeyDialContext{
		AssetID: a.ID, Path: HostKeyPathAccountInventory, UserID: scan.InitiatedBy, Username: scan.InitiatedByName,
		AccountID: id.AccountID, ConnectionRef: fmt.Sprintf("inventory:%d", scanID),
	})
	addr := fmt.Sprintf("%s:%d", a.Host, a.Port)
	res, ierr := s.collect(ctx, scanID, addr, creds, hostKey, scan.PrivilegedGroups)
	if ierr != nil {
		s.finishFailed(scanID, ierr.Reason)
		return
	}
	if err := s.finishSucceeded(&scan, res); err != nil {
		if !errors.Is(err, errInventoryScanNotRunning) {
			log.Printf("[HostAccountInventory] scan=%d persist failed", scanID)
			s.finishFailed(scanID, model.InventoryPersistFailed)
		}
	}
}

// finishFailed 以失敗結束（另一交易），不動既有結果。
func (s *HostAccountInventoryService) finishFailed(scanID uint, reason string) {
	err := s.db.Transaction(func(tx *gorm.DB) error {
		now := time.Now()
		res := tx.Model(&model.HostAccountScan{}).
			Where("id = ? AND status IN ?", scanID, []string{model.HostAccountScanQueued, model.HostAccountScanRunning}).
			Updates(map[string]any{"status": model.HostAccountScanFailed, "failure_reason": reason, "finished_at": now})
		if res.Error != nil || res.RowsAffected == 0 {
			return res.Error
		}
		var r model.HostAccountScan
		if err := tx.First(&r, scanID).Error; err != nil {
			return err
		}
		return s.writeDoneAudit(tx, &r, nil, "")
	})
	if err != nil {
		log.Printf("[HostAccountInventory] scan=%d failure close failed", scanID)
	}
}

func (s *HostAccountInventoryService) writeScanAudit(tx *gorm.DB, action model.AuditAction, scan *model.HostAccountScan, actor InventoryActor, details string) error {
	assetID, scanID := scan.AssetID, scan.ID
	return port.WriteInTx(s.auditTx, tx, port.AuditEvent{
		OccurredAt: time.Now(),
		Actor:      gatewayapi.Actor{UserID: actor.UserID, Username: actor.Username},
		Action:     string(action),
		Resource:   model.AuditResourceHostAccountScan,
		ResourceID: &scanID,
		AssetID:    &assetID,
		Status:     string(model.StatusSuccess),
		Request:    actor.requestMeta(),
		Details:    details,
	})
}

// writeDoneAudit 結束審計：狀態、原因碼、四個計數與檢查範圍狀態摘要，不含帳號名。
func (s *HostAccountInventoryService) writeDoneAudit(tx *gorm.DB, r *model.HostAccountScan, coverage []invCoverageItem, escalation string) error {
	type covState struct {
		Check string `json:"check"`
		State string `json:"state"`
	}
	cs := make([]covState, 0, len(coverage))
	for _, c := range coverage {
		cs = append(cs, covState{Check: c.Check, State: c.State})
	}
	body := map[string]any{
		"scan_id": r.ID, "status": r.Status, "failure_reason": r.FailureReason,
		"accounts_total": r.AccountsTotal, "privileged_total": r.PrivilegedTotal,
		"unmanaged_privileged_total": r.UnmanagedPrivilegedTotal, "reopened_total": r.ReopenedTotal,
		"coverage": cs,
	}
	if escalation != "" {
		body["escalation"] = escalation // 只在專用帳號身分出現：not_needed／used／denied
	}
	details, err := json.Marshal(body)
	if err != nil {
		return err
	}
	return s.writeScanAudit(tx, model.ActionInventoryScanDone, r,
		InventoryActor{UserID: r.InitiatedBy, Username: r.InitiatedByName}, string(details))
}
