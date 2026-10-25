package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
)

// restoreAwareJWTSecret 回傳登入簽章鑰的執行期材料：
// 簽發端與全部驗證端（access、MFA、改密、解封中繼 token）必須都用這個值建 JWTManager。
// 空世代＝原 JWT_SECRET；非空世代＝由世代派生的鑰，還原前簽出的 token 因此全數失效。
// 世代讀取失敗時 fail-close：改用一把隨機不可重現的鑰，使任何 token 都驗不過，絕不退回原鑰。
func restoreAwareJWTSecret(db *gorm.DB, secret string) string {
	gen, err := authz.RestoreGeneration(db)
	if err != nil {
		log.Printf("[Auth] 還原世代讀取失敗，本行程拒絕驗證所有登入簽章（fail-close）: %v", err)
		var b [16]byte
		_, _ = rand.Read(b[:])
		return authz.DeriveRestoreJWTKey(secret, "unreadable:"+hex.EncodeToString(b[:]))
	}
	return authz.DeriveRestoreJWTKey(secret, gen)
}

// pendingRestoreSealer 完成恢復後立即封章所需的最小能力（*audit.CheckpointService 滿足）。
type pendingRestoreSealer interface {
	SealNow() (*model.AuditCheckpoint, error)
}

// restoreSealSink 補封失敗時的告警與審計出口、以及成功後的解除。
// 由 restoreSealWrap 附在封章器上；沒有出口（測試替身）時只記日誌。
type restoreSealSink interface {
	sealDeferred(err error)
	sealStateUnreadable(err error)
	sealResolved()
}

// sealHookRegistrar 例行封章成功後回呼的註冊能力（*audit.CheckpointService 滿足）。
type sealHookRegistrar interface{ SetAfterSealHook(func()) }

type failureReporter interface {
	Report(mechanism, causeCode string, params map[string]string)
	ResolveFailure(mechanism string)
}

// auditFailureAdapter 把審計失效服務接到補封流程的窄介面。方法刻意不叫 Resolve：
// 該名稱留給認證脈絡的簽發／解析，不與失效標記混用。
type auditFailureAdapter struct{ svc *audit.AuditFailureService }

func (a auditFailureAdapter) Report(mechanism, causeCode string, params map[string]string) {
	a.svc.Report(mechanism, causeCode, params)
}

func (a auditFailureAdapter) ResolveFailure(mechanism string) { a.svc.Resolve(mechanism) }

type restoreAuditLogger interface {
	Log(entry *audit.AuditLogEntry)
}

// restoreSealEnv 把封章器與告警、審計出口綁在一起（stage2.go 以單行呼叫 restoreSealWrap）。
type restoreSealEnv struct {
	restoreSealer
	failures failureReporter
	audit    restoreAuditLogger
}

func restoreSealWrap(c restoreSealer, f failureReporter, a restoreAuditLogger) restoreSealer {
	return &restoreSealEnv{restoreSealer: c, failures: f, audit: a}
}

func (e *restoreSealEnv) SetAfterSealHook(fn func()) {
	if h, ok := e.restoreSealer.(sealHookRegistrar); ok {
		h.SetAfterSealHook(fn)
	}
}

// sealDeferred 補封失敗：不阻擋開放，改為系統告警＋審計各一筆。
func (e *restoreSealEnv) sealDeferred(err error) {
	e.reportRestoreSeal(model.CauseRestoreSealDeferred, err, "seal_pending")
}

// sealStateUnreadable 啟動時讀不到待封狀態：不阻擋開放，告警＋審計各一筆，並照「可能待封」補封。
func (e *restoreSealEnv) sealStateUnreadable(err error) {
	e.reportRestoreSeal(model.CauseRestoreSealStateUnreadable, err, "unknown")
}

// reportRestoreSeal 告警帶底層錯誤原文（只進失效事件參數），審計列只記事件名與狀態。
func (e *restoreSealEnv) reportRestoreSeal(cause string, err error, status string) {
	if e.failures != nil {
		e.failures.Report(model.MechanismRestoreSeal, cause, map[string]string{model.CauseParamDetail: err.Error()})
	}
	if e.audit != nil {
		body, _ := json.Marshal(map[string]string{"event": cause, "status": status})
		e.audit.Log(&audit.AuditLogEntry{
			UserID: 0, Username: "system",
			Action:   model.ActionExecute,
			Resource: model.ResourceAuditFailure,
			Status:   model.StatusFailure,
			Path:     "/system/restore-seal",
			Details:  string(body),
		})
	}
}

func (e *restoreSealEnv) sealResolved() {
	if e.failures != nil {
		e.failures.ResolveFailure(model.MechanismRestoreSeal)
	}
}

// completeRestoreBeforeStage2 在段 2 建構任何服務之前完成待完成的恢復：
// 寫 restore 事件、狀態改 seal_pending（持久的待封狀態）。呼叫點是 runStage2Graph 進入 runStage2 之前，
// 因此早於段 2 內所有背景工作（各排程器、轉發器）的啟動、早於完整路由（登入、代理）的換手；
// 解封前的段 1 路由只有健康檢查與解封端點。沒有待完成的恢復（一般重啟）時為 no-op。
//
// 事件寫入失敗即回錯：段 2 不建、狀態轉 sealed-faulted，恢復維持 pending 供重試，
// 不會在恢復未完成時開放服務。權限來源在此先注入（只是函式指標賦值，stage2.go 稍後
// 再注入一次無害）：未注入時事件寫入是 no-op，會把「沒寫事件」誤當成完成。
//
// 待封狀態在資料庫：事件已記成功後若封章尚未成功就重啟，這裡會從 seal_pending 重新設起旗標，
// 啟動時先補封再啟動排程器。補封失敗**不阻擋開放**（見 settleRestoreSeal）。
func completeRestoreBeforeStage2(ctx context.Context, s1 *stage1) error {
	audit.SetPermissionSources(authz.PermissionStateAuthzPart, identity.PermissionStateIdentityPart)
	audit.SetPermissionActivationLock(authz.LockStateForPermissionActivation)
	done, err := authz.CompletePendingRestore(ctx, database.DB)
	if err != nil {
		return fmt.Errorf("完成待完成的恢復失敗: %w", err)
	}
	if done {
		s1.restoreSealPending = true
		return nil
	}
	pending, err := authz.RestoreSealPending(database.DB)
	if err != nil {
		// 讀不到待封狀態不阻擋開放：照「可能待封」處理（啟動時補封一次，封章成功即清除），
		// 告警與審計在段 2 的出口就緒後由 settleRestoreSeal 上報。
		log.Printf("[Restore] %v（不阻擋啟動，照待封補封）", err)
		s1.restoreSealPending, s1.restoreSealStateErr = true, err
		return nil
	}
	s1.restoreSealPending = pending
	return nil
}

// settleRestoreSeal 補封待封的恢復。成功：清除資料庫待封狀態與告警。
// 失敗：**不回錯、不阻擋開放**；資料庫維持 seal_pending（重啟會再補），
// 發系統告警並寫審計，下次封章成功（例行封章亦算）時由 onSealed 回呼清除。
// 同一次啟動只失敗上報一次：失敗後記憶體旗標即清。
func settleRestoreSeal(s1 *stage1, c pendingRestoreSealer, ensureGenesis func() error) {
	if !s1.restoreSealPending {
		return
	}
	sink, _ := c.(restoreSealSink)
	if s1.restoreSealStateErr != nil {
		if sink != nil {
			sink.sealStateUnreadable(s1.restoreSealStateErr)
		}
		s1.restoreSealStateErr = nil
	}
	if h, ok := c.(sealHookRegistrar); ok && !s1.restoreSealHooked {
		s1.restoreSealHooked = true
		h.SetAfterSealHook(func() {
			if err := authz.MarkRestoreSealed(database.DB); err != nil {
				log.Printf("[Restore] %v", err)
				return
			}
			if sink != nil {
				sink.sealResolved()
			}
		})
	}
	var err error
	if ensureGenesis != nil {
		err = ensureGenesis()
	}
	if err == nil {
		_, err = c.SealNow()
	}
	s1.restoreSealPending = false
	if err != nil {
		log.Printf("[Restore] 恢復完成後封章失敗，服務照常開放，待封狀態保留（下次封章或重啟補封）: %v", err)
		if sink != nil {
			sink.sealDeferred(err)
		}
		return
	}
	if s1.restoreSealHooked {
		return // 封章成功的回呼已清除待封狀態與告警
	}
	if err := authz.MarkRestoreSealed(database.DB); err != nil {
		log.Printf("[Restore] %v", err)
	}
	if sink != nil {
		sink.sealResolved()
	}
}

// sealAfterRestore 檢查點步驟成功後，若有待封的恢復，立即封章產出涵蓋新世代的附證。
// 封章失敗不回錯（見 settleRestoreSeal）；旗標已被 sealBeforeFirstStart 清掉時為 no-op。
func sealAfterRestore(s1 *stage1, sealer pendingRestoreSealer, next func() error) func() error {
	return func() error {
		if err := next(); err != nil {
			return err
		}
		settleRestoreSeal(s1, sealer, nil)
		return nil
	}
}

// restoreSealer 恢復完成後先封章所需的能力（*audit.CheckpointService 滿足）。
type restoreSealer interface {
	pendingRestoreSealer
	EnsureGenesis() error
}

// sealBeforeFirstStart 掛在段 2 第一個背景工作（starts[0]）的啟動前：有待封的恢復時，
// 先確保創世檢查點、立即封章產出涵蓋新世代的附證，之後才啟動任何排程器（新附證先於開放 worker）。
// 沒有待封（一般重啟）時等同 next。封章失敗不阻擋啟動，
// 改為告警＋審計（settleRestoreSeal）。檢查點步驟的 sealAfterRestore 在旗標已清時為 no-op
// （啟動閘關閉的測試路徑不啟動 starts[0]，仍由該步驟補封）。
func sealBeforeFirstStart(s1 *stage1, c restoreSealer, next func() error) func() error {
	return func() error {
		settleRestoreSeal(s1, c, c.EnsureGenesis)
		return next()
	}
}

// newRestoreAwareAuthService 建立認證服務：簽章鑰用還原世代派生值，並接上 refresh／agent 的世代閘。
// 單行呼叫以免在 stage2.go 內增行（審計點 manifest 以 file:line 為錨）。
func newRestoreAwareAuthService(db *gorm.DB, secret string, ttl time.Duration, codec crypto.ColumnCodec) (*identity.AuthService, error) {
	svc, err := identity.NewAuthServiceWithMFA(restoreAwareJWTSecret(db, secret), ttl, codec)
	if err != nil {
		return nil, err
	}
	svc.SetRestoreGenerationSource(authz.RestoreGeneration)
	return svc, nil
}
