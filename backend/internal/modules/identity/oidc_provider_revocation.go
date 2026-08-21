package identity

import (
	"fmt"
	"log"
	"time"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// provider 停用／刪除／密鑰輪替的全面失效（idp-oidc-integration 3.8 / design 行 64）。
//
// 五條管道，缺一即留下一類存活的存取：
//
//	auth_epoch 推進   先行動作；使既簽 access／ticket／connect grant 的世代比對必敗
//	refresh 撤銷      否則舊 refresh 可換發新 access（換發會被世代閘拒，但撤銷讓成因可稽核）
//	既簽 access       由認證中介層的世代閘自然拒絕（既有機制，本檔不重複實作）
//	協議連線終斷      sessions.auth_provider_id 命中者；連線建立後不再出示憑證，對世代免疫
//	監看／分享訂閱    不建 sessions 列，會話掃描完全掃不到
//	錄影 token        in-memory 且不做世代比對，唯一失效途徑是直接撤銷
//
// **刪除亦走全套**（design 行 64，codex MEDIUM）：軟刪後管理端再也無從按 provider
// 收線，若刪除只推進世代而不掃描，「外部身分已全數解綁、但先前建立的協議連線仍在」
// 的狀態下刪除 provider，那些連線會永久存活。
//
// **順序不可交換**：先推進 epoch 再掃描。反過來的話，掃描與推進之間兌換成功的
// 連線既不在掃描集合內、又帶著舊 epoch 而通不過任何後續驗證點——但協議連線根本
// 沒有後續驗證點，於是存活。先推進則該窗口內的兌換必然讀到新 epoch 而被拒。

// ProviderSessionTerminator 按 provider 終斷進行中協議會話的**兩階段**管道。
//
// 拆成兩階段是 design 行 268 的硬性要求：鎖內只做 DB 判定與標記，實際關閉 WS
// 移到鎖外。合成單一方法會使關閉 WS（可能因對端已死而阻塞至 TCP 逾時）發生在
// provider 列鎖內，把「單次 DB 往返級」的持鎖時長變成秒級。
type ProviderSessionTerminator interface {
	// MarkTerminatedByProvider 鎖內標記：把該 provider 建立的進行中會話寫成
	// disconnected，回傳實際標記到的 sessionID（供鎖外關閉）
	MarkTerminatedByProvider(tx *gorm.DB, providerID uint, reason string) ([]uint, error)
	// CloseTerminated 鎖外關閉：對已標記的會話實際斷開 WebSocket
	CloseTerminated(sessionIDs []uint)
}

// ProviderSubscriptionTerminator 按 provider 收線唯讀訂閱（MonitorHub）
type ProviderSubscriptionTerminator interface {
	DisconnectByProvider(providerID uint) int
}

// ProviderRecordingTokenRevoker 按 provider 撤銷錄影存取 token（RecordingTokenManager）
type ProviderRecordingTokenRevoker interface {
	RevokeByProvider(providerID uint) int
}

// SetSessionTerminator 注入協議會話終斷管道（SessionService）
func (s *OIDCProviderService) SetSessionTerminator(t ProviderSessionTerminator) {
	if t != nil {
		s.sessions = t
	}
}

// SetSubscriptionTerminator 注入唯讀訂閱收線管道（MonitorHub）
func (s *OIDCProviderService) SetSubscriptionTerminator(t ProviderSubscriptionTerminator) {
	if t != nil {
		s.subscriptions = t
	}
}

// SetRecordingTokenRevoker 注入錄影 token 撤銷管道（RecordingTokenManager）
func (s *OIDCProviderService) SetRecordingTokenRevoker(r ProviderRecordingTokenRevoker) {
	if r != nil {
		s.recordingTokens = r
	}
}

// providerRevocationPlan 鎖內判定的結果，交由鎖外執行實際收線
type providerRevocationPlan struct {
	// SessionIDs 已於鎖內標記為終止、待鎖外關閉 WS 的會話
	SessionIDs []uint
	// RefreshRevoked 已撤銷的 refresh 憑證數（僅供日誌與審計）
	RefreshRevoked int64
}

// invalidateProviderLocked 鎖內的 provider 失效：推進世代 → 撤 refresh → 標記會話。
//
// 呼叫端 SHALL 已持該 provider 的列鎖（WithOIDCProviderLock），且 SHALL 於鎖外
// 呼叫 revokeProviderAccess 完成實際收線。
func (s *OIDCProviderService) invalidateProviderLocked(tx *gorm.DB, providerID uint,
	reason string) (*providerRevocationPlan, error) {

	// 1. **先推進 auth_epoch**（順序不可交換，見檔頭）。
	// Unscoped：刪除路徑上本列可能已被軟刪，仍須推進——否則殘留憑證的世代比對
	// 會與軟刪前的值相符
	res := tx.Unscoped().Model(&model.OIDCProvider{}).Where("id = ?", providerID).
		UpdateColumn("auth_epoch", gorm.Expr("auth_epoch + 1"))
	if res.Error != nil {
		return nil, fmt.Errorf("推進 provider 憑證世代失敗: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return nil, ErrOIDCProviderNotFound
	}

	if oidcProviderPreWriteHook != nil {
		oidcProviderPreWriteHook(oidcSiteProviderInvalidate)
	}

	plan := &providerRevocationPlan{}

	// 2. 撤銷該 provider 簽出的全部 refresh 憑證
	n, err := revokeRefreshTokensByProvider(tx, providerID)
	if err != nil {
		return nil, err
	}
	plan.RefreshRevoked = n

	// 3. 標記該 provider 建立的進行中協議會話為終止（實際關 WS 於鎖外）
	if s.sessions != nil {
		ids, err := s.sessions.MarkTerminatedByProvider(tx, providerID, model.EndReasonAdminTerminate)
		if err != nil {
			return nil, err
		}
		plan.SessionIDs = ids
	}

	log.Printf("[OIDC] provider %d 失效流程（鎖內）：reason=%s 撤 refresh=%d 標記會話=%d",
		providerID, reason, plan.RefreshRevoked, len(plan.SessionIDs))
	return plan, nil
}

// revokeProviderAccess 鎖外收線：關閉已標記的會話、收線訂閱、撤銷錄影 token。
//
// 個別失敗不回滾主操作——provider 已停用／刪除且世代已推進是主要安全目標，
// 收線失敗記日誌人工跟進（同 revokeUserAccess 的既有取捨）。
// 鎖外的收線失敗不影響正確性：已標記終止的 session 不得啟動 proxy（見
// SessionService.IsTerminated 的兌換點複查）。
func (s *OIDCProviderService) revokeProviderAccess(providerID uint,
	plan *providerRevocationPlan, reason string) {

	if plan != nil && s.sessions != nil && len(plan.SessionIDs) > 0 {
		s.sessions.CloseTerminated(plan.SessionIDs)
		log.Printf("[OIDC] 已終斷 %d 個進行中會話 (providerID=%d, reason=%s)",
			len(plan.SessionIDs), providerID, reason)
	}
	if s.subscriptions != nil {
		if n := s.subscriptions.DisconnectByProvider(providerID); n > 0 {
			log.Printf("[OIDC] 已收線 %d 個唯讀訂閱 (providerID=%d, reason=%s)", n, providerID, reason)
		}
	}
	if s.recordingTokens != nil {
		if n := s.recordingTokens.RevokeByProvider(providerID); n > 0 {
			log.Printf("[OIDC] 已撤銷 %d 個錄影存取憑證 (providerID=%d, reason=%s)", n, providerID, reason)
		}
	}
}

// revokeRefreshTokensByProvider 撤銷某 provider 簽出的全部未撤銷 refresh 憑證。
//
// **provider_id = 0 不得視為萬用字元**：0 是本地／LDAP 登入的語義，
// 以 0 呼叫會撤掉全體本地帳號的會話。
func revokeRefreshTokensByProvider(db *gorm.DB, providerID uint) (int64, error) {
	if providerID == 0 {
		return 0, nil
	}
	res := db.Model(&model.RefreshToken{}).
		Where("provider_id = ? AND revoked_at IS NULL", providerID).
		Updates(map[string]interface{}{
			"revoked_at":     time.Now(),
			"revoked_reason": model.RefreshRevokeProviderDisabled,
		})
	if res.Error != nil {
		return 0, fmt.Errorf("撤銷 provider 刷新憑證失敗: %w", res.Error)
	}
	return res.RowsAffected, nil
}
