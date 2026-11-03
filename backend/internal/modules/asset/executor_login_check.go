package asset

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/sshmaterial"
	"github.com/custodexa/backend/pkg/gatewayapi"
)

// 堡壘機專用帳號的測試登入：以專用帳號登入目標主機，實際執行一次不帶任何帳號列的改密程式
// （空 stdin，不改任何密碼），確認「能登入」與「有改密所需的權限」，非 root 時再確認能不能
// 讀取 sudo 規則。只讀不寫；結果寫入結果表並留兩筆審計（開始、結束一一配對）。

var (
	// ErrExecutorCheckPlatformUnsupported 資產不是有效改密通道為 posix_ssh 的 ssh 資產。
	ErrExecutorCheckPlatformUnsupported = errors.New("executor check: platform unsupported")
	// ErrExecutorCheckRateLimited 任一道限流用盡（只進日誌，不附數值）。
	ErrExecutorCheckRateLimited = errors.New("executor check: rate limited")
	// ErrExecutorCheckBusy 等不到專用帳號的互斥。
	ErrExecutorCheckBusy = errors.New("executor check: account busy")
	// ErrExecutorCheckInternal 內部錯誤：查詢、審計或結果交易失敗，或 panic。
	ErrExecutorCheckInternal = errors.New("executor check: internal error")
	// ErrExecutorCheckAssetNotFound 資產不存在。
	ErrExecutorCheckAssetNotFound = errors.New("executor check: asset not found")
)

const (
	executorCheckLockWait       = 5 * time.Second
	executorCheckDialTimeout    = 15 * time.Second
	executorCheckSessionTimeout = 10 * time.Second
	executorCheckTotalTimeout   = 40 * time.Second
)

// ExecutorLoginCheckResult 一次測試登入的結果（HTTP 200 的回應本體）。
type ExecutorLoginCheckResult struct {
	Success         bool      `json:"success"`
	Code            string    `json:"code"`
	Method          string    `json:"method"`
	InventoryRead   string    `json:"inventory_read"`
	AccountUsername string    `json:"account_username"`
	CheckedAt       time.Time `json:"checked_at"`
	Stale           bool      `json:"stale"`
}

// ExecutorLoginCheckService 測試登入服務。
type ExecutorLoginCheckService struct {
	db       *gorm.DB
	resolver inventoryExecutorResolver
	hostKeys *HostKeyService
	auditTx  port.TxSink
	limiter  *executorCheckLimiter

	// 以下僅供測試注入
	lockWait      time.Duration
	hostKeyFor    func(dc HostKeyDialContext) ssh.HostKeyCallback
	readPin       func(db *gorm.DB, assetID uint) (*ExecutorPin, error)
	afterPrecheck func()
	beforeResult  func()
}

// NewExecutorLoginCheckService 建立服務。limiter 與盤點共用同一個實例。
func NewExecutorLoginCheckService(db *gorm.DB, resolver inventoryExecutorResolver, hostKeys *HostKeyService,
	auditTx port.TxSink, limiter *executorCheckLimiter) *ExecutorLoginCheckService {
	s := &ExecutorLoginCheckService{db: db, resolver: resolver, hostKeys: hostKeys, auditTx: auditTx, limiter: limiter,
		readPin: readExecutorPin}
	s.hostKeyFor = func(dc HostKeyDialContext) ssh.HostKeyCallback {
		cb, _ := s.hostKeys.CallbackFor(dc)
		return cb
	}
	return s
}

// State 讀該資產最近一次測試登入的狀態；沒有專用帳號回 ErrAssetExecutorNotFound。
func (s *ExecutorLoginCheckService) State(assetID uint) (*ExecutorLoginCheckState, error) {
	st, pin, err := loadExecutorLoginCheck(s.db, assetID)
	if err != nil {
		return nil, ErrExecutorCheckInternal
	}
	if pin == nil {
		return nil, ErrAssetExecutorNotFound
	}
	return st, nil
}

func mountFromPin(pin *ExecutorPin) model.AssetAccount {
	m := model.AssetAccount{ID: pin.AccountID, AssetID: 0, Username: pin.Username, CredentialID: pin.CredentialID}
	if pin.EffectiveVersionID != 0 {
		v := pin.EffectiveVersionID
		m.EffectiveVersionID = &v
	}
	return m
}

// checkOutcome 第 4–7 步的產出。
type checkOutcome struct {
	code, method, inventoryRead string
	versionID                   uint
}

// Run 執行一次測試登入（步驟見設計的 5.2）。
func (s *ExecutorLoginCheckService) Run(reqCtx context.Context, assetID uint, actor InventoryActor) (res *ExecutorLoginCheckResult, err error) {
	if s.limiter != nil {
		release, ok := s.limiter.acquire(actor.UserID, assetID)
		if !ok {
			return nil, ErrExecutorCheckRateLimited
		}
		defer release()
	}
	corr := uuid.NewString()
	var (
		a     model.Asset
		pin   *ExecutorPin
		early *ExecutorLoginCheckResult
	)
	txErr := s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Limit(1).Find(&a, assetID).Error; err != nil {
			return fmt.Errorf("%w: %v", ErrExecutorCheckInternal, err)
		}
		if a.ID == 0 {
			return ErrExecutorCheckAssetNotFound
		}
		if !inventoryPlatformSupported(&a) {
			return ErrExecutorCheckPlatformUnsupported
		}
		p, err := s.readPin(tx, assetID)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrExecutorCheckInternal, err)
		}
		if p == nil {
			return ErrAssetExecutorNotFound
		}
		pin = p
		mount := mountFromPin(pin)
		code := ""
		switch merr := executorMountState(tx, &mount); {
		case errors.Is(merr, ErrExecutorBusy):
			code = model.ExecCheckRotationPending
		case merr != nil:
			code = model.ExecCheckUnavailable
		}
		if code == "" && s.limiter != nil && !s.limiter.allowTarget(executorTargetKey(a.Host, a.Port, pin.Username)) {
			return ErrExecutorCheckRateLimited
		}
		if err := s.writeStartAudit(tx, &a, pin, actor, corr); err != nil {
			return fmt.Errorf("%w: %v", ErrExecutorCheckInternal, err)
		}
		if code != "" {
			out := checkOutcome{code: code, versionID: pin.EffectiveVersionID}
			r, err := s.persistResult(tx, a.ID, pin, actor, corr, out)
			if err != nil {
				return fmt.Errorf("%w: %v", ErrExecutorCheckInternal, err)
			}
			early = r
		}
		return nil
	})
	if txErr != nil {
		return nil, txErr
	}
	if early != nil {
		return early, nil
	}
	if s.afterPrecheck != nil {
		s.afterPrecheck()
	}

	// 第 4–8 步與請求 ctx 脫鉤：用戶端斷線不會讓結束審計寫不進去
	ctx, cancel := context.WithTimeout(context.WithoutCancel(reqCtx), executorCheckTotalTimeout)
	defer cancel()
	defer func() {
		if p := recover(); p != nil {
			log.Printf("[ExecutorLoginCheck] corr=%s panic recovered", corr)
			s.endOnly(assetID, pin, actor, corr, model.ExecutorCheckEndInterrupted)
			res, err = nil, ErrExecutorCheckInternal
		}
	}()
	return s.runLocked(ctx, &a, pin, actor, corr)
}

// runLocked 第 4–8 步。
func (s *ExecutorLoginCheckService) runLocked(ctx context.Context, a *model.Asset, pin *ExecutorPin, actor InventoryActor, corr string) (*ExecutorLoginCheckResult, error) {
	wait := s.lockWait
	if wait <= 0 {
		wait = executorCheckLockWait
	}
	unlock, err := waitRotationAccountLock(ctx, pin.AccountID, wait)
	if err != nil {
		s.endOnly(a.ID, pin, actor, corr, model.ExecutorCheckEndBusy)
		return nil, ErrExecutorCheckBusy
	}
	defer unlock()
	pin2, err := s.readPin(s.db, a.ID)
	switch {
	case err != nil:
		s.endOnly(a.ID, pin, actor, corr, model.ExecutorCheckEndInterrupted)
		return nil, ErrExecutorCheckInternal
	case pin2 == nil || pin2.AccountID != pin.AccountID:
		s.endOnly(a.ID, pin, actor, corr, model.ExecutorCheckEndStateChanged)
		return nil, ErrExecutorStateChanged
	}
	ec, err := s.resolver.ResolveExecutorCredentials(ctx, a.ID, *pin2)
	var out checkOutcome
	switch {
	case errors.Is(err, ErrExecutorChanged):
		s.endOnly(a.ID, pin, actor, corr, model.ExecutorCheckEndStateChanged)
		return nil, ErrExecutorStateChanged
	case errors.Is(err, ErrExecutorBusy):
		out = checkOutcome{code: model.ExecCheckRotationPending, versionID: pin2.EffectiveVersionID}
	case err != nil:
		out = checkOutcome{code: model.ExecCheckUnavailable, versionID: pin2.EffectiveVersionID}
	default:
		out = s.dialAndCheck(ctx, a, pin2, ec, actor, corr)
	}
	return s.finish(a.ID, pin2, actor, corr, out)
}

// finish 第 8 步：結果交易（upsert 加結束審計）；失敗另以獨立短交易只寫結束審計。
func (s *ExecutorLoginCheckService) finish(assetID uint, pin *ExecutorPin, actor InventoryActor, corr string, out checkOutcome) (*ExecutorLoginCheckResult, error) {
	if s.beforeResult != nil {
		s.beforeResult()
	}
	var r *ExecutorLoginCheckResult
	err := s.db.Transaction(func(tx *gorm.DB) error {
		var perr error
		r, perr = s.persistResult(tx, assetID, pin, actor, corr, out)
		return perr
	})
	if err != nil {
		s.endOnly(assetID, pin, actor, corr, model.ExecutorCheckEndPersistFailed)
		return nil, ErrExecutorCheckInternal
	}
	return r, nil
}

// dialAndCheck 第 5–7 步。ec 的秘密在本函式內抹除。
func (s *ExecutorLoginCheckService) dialAndCheck(ctx context.Context, a *model.Asset, pin *ExecutorPin, ec *ExecutorCredentials, actor InventoryActor, corr string) checkOutcome {
	out := checkOutcome{versionID: ec.VersionID, inventoryRead: model.ExecutorCheckInventoryNotChecked}
	defer ec.Destroy()
	var pw []byte
	if ec.Password != nil {
		_ = ec.Password.Borrow(func(b []byte) error {
			pw = append(pw, b...)
			return nil
		})
	}
	defer func() {
		for i := range pw {
			pw[i] = 0
		}
	}()
	hostKey := s.hostKeyFor(HostKeyDialContext{
		AssetID: a.ID, Path: HostKeyPathExecutorLoginCheck, UserID: actor.UserID, Username: actor.Username,
		AccountID: pin.AccountID, ClientIP: actor.ClientIP, ConnectionRef: "executor-check:" + corr,
	})
	password := sshmaterial.NewPassword(ec.Password)
	privateKey := ec.PrivateKey
	ec.Password, ec.PrivateKey = nil, nil
	dialCtx, dialCancel := context.WithTimeout(ctx, executorCheckDialTimeout)
	client, err := dialSSHCredentials(dialCtx, fmt.Sprintf("%s:%d", a.Host, a.Port), ec.Username, password, privateKey, hostKey)
	dialCancel()
	if err != nil {
		out.code = classifyExecutorCheckDialError(ctx, err)
		return out
	}
	defer client.Close()
	method, code := runExecutorCheckEscalation(ctx, client, ec.Username, pw)
	if code != "" {
		out.code = code
		return out
	}
	out.method = method
	if method == model.ExecutorCheckMethodRoot {
		out.inventoryRead = model.ExecutorCheckInventoryNotNeeded
		return out
	}
	out.inventoryRead = executorCheckInventoryRead(ctx, client, pw)
	if ctx.Err() != nil {
		out.code, out.method, out.inventoryRead = model.ExecCheckTimeout, "", model.ExecutorCheckInventoryNotChecked
	}
	return out
}

func classifyExecutorCheckDialError(ctx context.Context, err error) string {
	switch {
	case errors.Is(err, ErrHostKeyChanged):
		return model.ExecCheckHostKeyMismatch
	case errors.Is(err, ErrHostKeyCheckFailed):
		return model.ExecCheckHostKeyCheckFailed
	case ctx.Err() != nil:
		return model.ExecCheckTimeout
	case strings.Contains(err.Error(), "unable to authenticate"):
		return model.ExecCheckLoginFailed
	default:
		return model.ExecCheckConnectionFailed
	}
}

// sessionDeadline 為一個 session 設定期限：到期即關閉連線以解除阻塞。回傳的 stop 要在 session 結束後呼叫。
func sessionDeadline(ctx context.Context, client *ssh.Client, d time.Duration) (context.Context, func()) {
	sctx, cancel := context.WithTimeout(ctx, d)
	done := make(chan struct{})
	go func() {
		select {
		case <-sctx.Done():
			select {
			case <-done:
			default:
				_ = client.Close()
			}
		case <-done:
		}
	}()
	return sctx, func() {
		close(done)
		cancel()
	}
}

// runExecutorCheckEscalation 第 6 步：與代改同一組指令，stdin 不含任何帳號列。回傳方式或結果碼。
func runExecutorCheckEscalation(ctx context.Context, client *ssh.Client, username string, password []byte) (method, code string) {
	runOne := func(cmd string, stdin []byte) (string, error) {
		sctx, stop := sessionDeadline(ctx, client, executorCheckSessionTimeout)
		defer stop()
		msg, err := runElevatedSession(client, cmd, stdin)
		if err != nil && sctx.Err() != nil {
			return msg, sctx.Err()
		}
		return msg, err
	}
	failCode := func(err error) string {
		var exitErr *ssh.ExitError
		switch {
		case errors.As(err, &exitErr):
			return model.ExecCheckEscalationDenied
		case ctx.Err() != nil || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled):
			return model.ExecCheckTimeout
		default:
			return model.ExecCheckConnectionFailed
		}
	}
	if username == "root" {
		if _, err := runOne(elevatedCmdRoot, []byte{}); err != nil {
			return "", failCode(err)
		}
		return model.ExecutorCheckMethodRoot, ""
	}
	msg, err := runOne(elevatedCmdSudoNoPass, []byte{})
	if err == nil {
		return model.ExecutorCheckMethodSudoNopasswd, ""
	}
	var exitErr *ssh.ExitError
	if !errors.As(err, &exitErr) || !strings.Contains(msg, sudoPasswordRequiredMarker) {
		return "", failCode(err)
	}
	if len(password) == 0 {
		return "", model.ExecCheckEscalationNeedsNopass
	}
	stdin := append(append([]byte(nil), password...), '\n')
	if _, err := runOne(elevatedCmdSudoPass, stdin); err != nil {
		return "", failCode(err)
	}
	return model.ExecutorCheckMethodSudoPassword, ""
}

// executorCheckInventoryRead 第 7 步：提權讀取的兩段式讀取，輸出邊讀邊丟（上限同盤點、只計數與判定、不保留內容），只看封存內容。
func executorCheckInventoryRead(ctx context.Context, client *ssh.Client, password []byte) string {
	sctx, stop := sessionDeadline(ctx, client, executorCheckSessionTimeout)
	defer stop()
	denied, err := runEscalatedCheck(sctx, client, password)
	if err != nil || denied {
		return model.ExecutorCheckInventoryDenied
	}
	return model.ExecutorCheckInventoryOK
}

// persistResult 在 tx 內 upsert 結果並寫結束審計。
func (s *ExecutorLoginCheckService) persistResult(tx *gorm.DB, assetID uint, pin *ExecutorPin, actor InventoryActor, corr string, out checkOutcome) (*ExecutorLoginCheckResult, error) {
	now := time.Now()
	if out.inventoryRead == "" {
		out.inventoryRead = model.ExecutorCheckInventoryNotChecked
	}
	row := &model.ExecutorLoginCheck{
		AssetAccountID: pin.AccountID, AssetID: assetID, CredentialID: pin.CredentialID,
		CredentialVersionID: out.versionID, Result: out.code, Method: out.method, InventoryRead: out.inventoryRead,
		CheckedBy: actor.UserID, CheckedByName: actor.Username, CheckedAt: now,
	}
	if err := upsertExecutorLoginCheck(tx, row); err != nil {
		return nil, err
	}
	if err := s.writeEndAudit(tx, assetID, pin, actor, corr, out.code, out.method, out.inventoryRead, out.versionID); err != nil {
		return nil, err
	}
	return &ExecutorLoginCheckResult{
		Success: out.code == "", Code: out.code, Method: out.method, InventoryRead: out.inventoryRead,
		AccountUsername: pin.Username, CheckedAt: now,
	}, nil
}

// endOnly 不更新結果表的出口：以獨立短交易只寫結束審計。寫不進去只記錯誤日誌（含關聯識別，不含秘密）。
func (s *ExecutorLoginCheckService) endOnly(assetID uint, pin *ExecutorPin, actor InventoryActor, corr, result string) {
	err := s.db.Transaction(func(tx *gorm.DB) error {
		return s.writeEndAudit(tx, assetID, pin, actor, corr, result, "", "", pin.EffectiveVersionID)
	})
	if err != nil {
		log.Printf("[ExecutorLoginCheck] corr=%s end audit failed result=%s", corr, result)
	}
}

func (s *ExecutorLoginCheckService) writeStartAudit(tx *gorm.DB, a *model.Asset, pin *ExecutorPin, actor InventoryActor, corr string) error {
	body, _ := json.Marshal(map[string]any{
		"asset_id": a.ID, "executor_account_id": pin.AccountID, "executor_username": pin.Username,
		"credential_id": pin.CredentialID, "credential_version_id": pin.EffectiveVersionID, "correlation_id": corr,
	})
	assetID, mountID := a.ID, pin.AccountID
	return port.WriteInTx(s.auditTx, tx, port.AuditEvent{
		OccurredAt: time.Now(),
		Actor:      gatewayapi.Actor{UserID: actor.UserID, Username: actor.Username},
		Action:     string(model.ActionExecutorLoginCheck),
		Resource:   model.AuditResourceAssetExecutor,
		ResourceID: &mountID,
		AssetID:    &assetID,
		Status:     string(model.StatusSuccess),
		Request:    gatewayapi.RequestMeta{ClientIP: actor.ClientIP},
		Details:    string(body),
	})
}

func (s *ExecutorLoginCheckService) writeEndAudit(tx *gorm.DB, assetID uint, pin *ExecutorPin, actor InventoryActor, corr, result, method, invRead string, versionID uint) error {
	body, _ := json.Marshal(map[string]any{
		"correlation_id": corr, "result": result, "method": method, "inventory_read": invRead,
		"credential_version_id": versionID,
	})
	mountID := pin.AccountID
	return port.WriteInTx(s.auditTx, tx, port.AuditEvent{
		OccurredAt: time.Now(),
		Actor:      gatewayapi.Actor{UserID: actor.UserID, Username: actor.Username},
		Action:     string(model.ActionExecutorLoginCheckDone),
		Resource:   model.AuditResourceAssetExecutor,
		ResourceID: &mountID,
		AssetID:    &assetID,
		Status:     string(model.StatusSuccess),
		Request:    gatewayapi.RequestMeta{ClientIP: actor.ClientIP},
		Details:    string(body),
	})
}
