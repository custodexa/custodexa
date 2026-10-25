package audit

import (
	"context"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/seal"
	"gorm.io/gorm"
)

// NewAuditFailureServiceForTest 建一個不註冊單例的失效事件服務（持久去重以資料庫為準）。
func NewAuditFailureServiceForTest(db *gorm.DB) *AuditFailureService {
	return &AuditFailureService{db: db, policy: policy.NewSecurityPolicyService(db)}
}

// 測試用接縫（只在本目錄的測試編譯）：注入固定的完整性密鑰、模擬只持資料庫帳密者自算的事件列。

func staticIntegrity(key []byte) *AuditIntegrityService {
	return &AuditIntegrityService{
		keyFn: func(v int) []byte {
			if v == 1 {
				return append([]byte(nil), key...)
			}
			return nil
		},
		activeFn: func() (int, []byte) { return 1, append([]byte(nil), key...) },
	}
}

// UsePermissionEventRevokingKey 註冊一個在取鑰當下關閉解封世代的完整性服務：模擬計算驗證碼途中
// lease 被撤回（密鑰材料隨世代關閉作廢）。回傳的函式還原先前的註冊。
func UsePermissionEventRevokingKey(key []byte) func() {
	auditIntegrityMu.RLock()
	prev := auditIntegrityInstance
	auditIntegrityMu.RUnlock()
	gate := &seal.MaterialGate{}
	s := staticIntegrity(key)
	s.gate = gate
	s.activeFn = func() (int, []byte) {
		gate.CloseWith(nil)
		return 1, append([]byte(nil), key...)
	}
	registerAuditIntegrity(s)
	return func() { registerAuditIntegrity(prev) }
}

// UsePermissionEventTestKey 以固定 v1 鑰註冊完整性服務；回傳的函式還原先前的註冊。
func UsePermissionEventTestKey(key []byte) func() {
	auditIntegrityMu.RLock()
	prev := auditIntegrityInstance
	auditIntegrityMu.RUnlock()
	registerAuditIntegrity(staticIntegrity(key))
	return func() { registerAuditIntegrity(prev) }
}

// UnregisterIntegrityForTest 模擬段 2 之前（完整性服務尚未建立）；回傳的函式還原。
func UnregisterIntegrityForTest() func() {
	auditIntegrityMu.RLock()
	prev := auditIntegrityInstance
	auditIntegrityMu.RUnlock()
	registerAuditIntegrity(nil)
	return func() { registerAuditIntegrity(prev) }
}

// ForgePermissionEvent 模擬只持資料庫帳密的人：照公開格式算出摘要、接上鏈頭，以目前實際狀態
// 寫一筆 kind 事件（rebase 指定是否帶重設標記）。attackerKey 為 nil 時驗證碼留空，否則以
// 攻擊者自備的鑰（不是伺服器的完整性密鑰）計算。不經任何服務、不寫審計列。
func ForgePermissionEvent(db *gorm.DB, kind string, rebase bool, attackerKey []byte) (*model.PermissionStateEvent, error) {
	var out *model.PermissionStateEvent
	err := db.Transaction(func(tx *gorm.DB) error {
		head, err := latestPermissionEvent(tx)
		if err != nil {
			return err
		}
		var before *PermissionState
		if head != nil {
			if before, err = DecodePermissionState([]byte(head.AfterBody)); err != nil {
				before = nil
			}
		}
		now, err := ReadPermissionState(context.Background(), tx)
		if err != nil {
			return err
		}
		restore := UnregisterIntegrityForTest()
		if attackerKey != nil {
			registerAuditIntegrity(staticIntegrity(attackerKey))
		}
		out, err = insertPermissionEvent(tx, head, kind, "forged", before, now, nil, permissionRebase{On: rebase})
		restore()
		DrainPendingPermissionStampsForTest() // 攻擊者的寫入不在伺服器行程的記憶裡
		return err
	})
	return out, err
}

// DrainPendingPermissionStampsForTest 清空段 2 前未蓋章的記錄（避免跨測試殘留）。
func DrainPendingPermissionStampsForTest() {
	pendingPermissionStampMu.Lock()
	pendingPermissionStamps = map[int64][]byte{}
	pendingPermissionStampMu.Unlock()
}

// SetSealClockForTest 固定封章器的時鐘（sealed_at），讓保存期限修剪在測試內可立即到期。
func SetSealClockForTest(s *CheckpointService, at time.Time) { s.now = func() time.Time { return at } }

// SetSealSchemeForTest 以指定載荷版本封章（模擬升級前的封章器；空字串還原為最新版本）。
func SetSealSchemeForTest(s *CheckpointService, scheme string) { s.scheme = scheme }

// SetSealActivationBarrierForTest 在封章交易讀完權限狀態之後、取 authz_state 列鎖之前呼叫 fn
// （僅首次啟用路徑；nil 清除）。
func SetSealActivationBarrierForTest(s *CheckpointService, fn func()) { s.faults.beforeActivationLock = fn }

// SetSealAfterActivationLockForTest 在封章交易取得 authz_state 列鎖之後呼叫 fn（僅首次啟用路徑；nil 清除）。
func SetSealAfterActivationLockForTest(s *CheckpointService, fn func()) { s.faults.afterActivationLock = fn }

// PermissionLineageForTest 起點判定的事實摘要（契約測試用）。
type PermissionLineageForTest struct {
	Clean       bool
	TrimHistory string
	Reason      string
}

// ReadPermissionLineageForTest 以 db 讀起點判定的事實。
func ReadPermissionLineageForTest(db *gorm.DB, signer permissionSigner) (PermissionLineageForTest, error) {
	l, err := readPermissionLineage(db, signer)
	if err != nil {
		return PermissionLineageForTest{}, err
	}
	return PermissionLineageForTest{Clean: l.clean(), TrimHistory: l.trimHistory, Reason: l.noBaseReason()}, nil
}

// CheckpointChainStructureForTest 結構層共用純函式（純度斷言用）。
var CheckpointChainStructureForTest = checkpointChainStructure

// PermissionEventDigestForTest 事件摘要的公開算法（模擬只持資料庫帳密者照算）。
func PermissionEventDigestForTest(e *model.PermissionStateEvent) string { return permissionEventDigest(e) }
