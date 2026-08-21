package session

import (
	"errors"
	"fmt"
	"github.com/custodexa/backend/internal/modules/identity"
	"log"
	"time"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
)

// 按 provider 的協議會話收線與「兌換建 session」的序列化
// （idp-oidc-integration 3.8／3.8a／3.8b）。
//
// 兩階段拆分（MarkTerminatedByProvider ／ CloseTerminated）與 TerminateAllByUser
// 的單階段語義不同，理由見 ProviderSessionTerminator 的介面說明：
// 實際關閉 WS 可能阻塞，不得發生在 provider 列鎖內。

// MarkTerminatedByProvider 鎖內標記：把該 provider 認證所建立的進行中會話寫成
// disconnected，回傳實際標記到的 sessionID。
//
// **在呼叫端的交易／鎖內執行**（參數為 tx 而非 database.DB）：標記與
// 「推進 auth_epoch」必須同鎖同交易，否則兩者之間兌換成功的連線兩頭落空。
//
// 條件更新（status=active）沿用 Terminate 的 CAS 語義：與被動 WS 關閉、
// reconciler 收斂或並發終止競態時「先到者贏」，不復活終態、不覆寫他者的 end_reason。
func (s *SessionService) MarkTerminatedByProvider(tx *gorm.DB, providerID uint,
	reason string) ([]uint, error) {

	if providerID == 0 {
		// 0 是「本地／LDAP 登入」的語義而非萬用字元：以 0 掃描會終斷全體本地會話
		return nil, nil
	}

	var sessions []model.Session
	if err := tx.Select("id", "start_time").
		Where("auth_provider_id = ? AND status = ?", providerID, model.SessionStatusActive).
		Find(&sessions).Error; err != nil {
		return nil, fmt.Errorf("查詢 provider 進行中會話失敗: %w", err)
	}

	now := time.Now()
	marked := make([]uint, 0, len(sessions))
	for _, sess := range sessions {
		duration := int(now.Sub(sess.StartTime).Seconds())
		if duration < 0 {
			// 時鐘異常/損毀列的負值夾 0（與 Terminate 的非負契約一致）
			duration = 0
		}
		res := tx.Model(&model.Session{}).
			Where("id = ? AND status = ?", sess.ID, model.SessionStatusActive).
			Updates(map[string]interface{}{
				"status":     model.SessionStatusDisconnected,
				"end_time":   now,
				"duration":   duration,
				"end_reason": reason,
			})
		if res.Error != nil {
			// 標記失敗 SHALL 中止整個失效流程：這是鎖內的 DB 判定，
			// 放行等於留下一條「provider 已停用但連線仍在且不會再被掃到」的會話
			return nil, fmt.Errorf("標記 provider 會話終止失敗 (sessionID=%d): %w", sess.ID, res.Error)
		}
		if res.RowsAffected > 0 {
			marked = append(marked, sess.ID)
		}
	}
	return marked, nil
}

// CloseTerminated 鎖外關閉已標記終止的會話 WebSocket。
//
// 個別失敗只記日誌：DB 狀態已是終態，且兌換點的 IsTerminated 複查會擋下
// 「已標記終止卻仍在啟動」的 proxy，故收線失敗不影響正確性。
func (s *SessionService) CloseTerminated(sessionIDs []uint) {
	if s.registry == nil {
		return
	}
	for _, id := range sessionIDs {
		if err := s.registry.Close(id); err != nil {
			log.Printf("[SessionService] provider 收線關閉 WebSocket 失敗 (SessionID=%d): %v", id, err)
		}
	}
}

// IsTerminated 該會話是否已非 active（供兌換點於啟動 proxy 前複查）。
//
// design 行 268 的收尾要求：「已標記終止的 session SHALL NOT 啟動 proxy」。
// 序列化保證「停用在前 → 兌換必被世代閘拒」與「兌換在前 → 停用必掃到該會話」，
// 但後者的鎖外關閉可能早於 WS 註冊完成（此時 registry.Close 是 no-op）——
// 本複查即該殘留窗口的封口。讀取失敗一律回 true（fail-close）：
// 讀不到就無法證明會話仍有效，不得放行。
func (s *SessionService) IsTerminated(sessionID uint) bool {
	// Pluck 的 dest 必須是 slice（純量 dest 會使 GORM 回 Scan 錯誤，
	// 令本函式恆走 fail-close 分支——所有協議連線建立即被砍，e2e 場景 12 實測抓到）
	var statuses []model.SessionStatus
	if err := database.DB.Model(&model.Session{}).
		Where("id = ?", sessionID).Limit(1).Pluck("status", &statuses).Error; err != nil {
		log.Printf("[SessionService] 複查會話終止狀態失敗 (SessionID=%d): %v", sessionID, err)
		return true
	}
	if len(statuses) == 0 {
		// 查無此列：無法證明會話仍有效，同 fail-close
		return true
	}
	return statuses[0] != model.SessionStatusActive
}

// CreateWithGenerationGuard 序列化的「兌換建 session」（3.8b 通則的執行點）。
//
// 「以既有身分或憑證產生新長效能力」——協議連線是其中最長效的一種（建立後
// 不再出示憑證，對任何世代比對免疫）。故 SHALL 於鎖內完成三步：
//
//	重查前提（provider 啟用與否、使用者狀態）→ 讀世代（現查 DB 比對）→ 建立 session
//
// 少了序列化即為 design 行 266 的 TOCTOU：兌換讀到 epoch=7 → 停用推進至 8 並
// 掃完既有會話 → 兌換才插入 epoch=7 的 session → 該連線永久存活。
//
// 呼叫端於兌換點**已**做過一次鎖外的世代複查（fast-fail，避免為必敗的請求取鎖）；
// 本函式的鎖內複查不是重複，而是唯一具有序列化保證的那一次。
func (s *SessionService) CreateWithGenerationGuard(authCtx crypto.AuthContext,
	session *model.Session) error {

	return identity.WithCapabilityLocks(database.DB, authCtx.ProviderID, session.UserID,
		func(tx *gorm.DB) error {
			// 前提與世代於鎖內重讀（現查 DB，不得沿用鎖外預讀的值）
			var user model.User
			if err := tx.Select("id", "credential_epoch", "active").
				First(&user, session.UserID).Error; err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return identity.ErrUserNotFound
				}
				return fmt.Errorf("重讀使用者狀態失敗: %w", err)
			}
			if !user.Active {
				return identity.ErrCredentialGenerationStale
			}
			if err := identity.VerifyCredentialGenerationTx(tx, authCtx, &user); err != nil {
				return err
			}
			identity.FirePreWriteHook(identity.OIDCSiteSessionCreate)
			return s.createInTx(tx, session)
		})
}

// JoinWithGenerationGuard 序列化的唯讀訂閱建立（3.8b：`Join` 亦是長效能力）。
//
// 監看／分享訂閱建立後**不再重驗任何憑證**，且不建 sessions 列——它是所有長效
// 能力裡最容易被忽略的一種。design 行 263 明列其競態：
//
//	OIDC 觀察者通過 epoch 檢查後暫停 → admin 停用 provider 並掃完既有訂閱 →
//	舊請求才完成 Join → 該訂閱錯過掃描，可持續讀取他人終端內容。
//
// 故 `Join` 在觀察者 providerID != 0 時 SHALL 持 provider 鎖；user 鎖一律持
// （credential_epoch 推進的按-user 收線有同型競態，且本地觀察者 providerID=0
// 只有 user 這一個維度可守）。
//
// join 於鎖內執行且**必須是非阻塞的集合操作**（MonitorHub.Join 僅寫回放緩衝）；
// 收線／關閉連線一律於鎖外，由 DisconnectByProvider／DisconnectByUser 負責。
func JoinWithGenerationGuard(authCtx crypto.AuthContext, userID uint, join func() bool) (bool, error) {
	joined := false
	err := identity.WithCapabilityLocks(database.DB, authCtx.ProviderID, userID, func(tx *gorm.DB) error {
		var user model.User
		if err := tx.Select("id", "credential_epoch", "active").First(&user, userID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return identity.ErrUserNotFound
			}
			return fmt.Errorf("重讀觀察者狀態失敗: %w", err)
		}
		if !user.Active {
			return identity.ErrCredentialGenerationStale
		}
		// 世代於鎖內現查（不得沿用 JWT claims 通過中介層時的那次讀取）
		if err := identity.VerifyCredentialGenerationTx(tx, authCtx, &user); err != nil {
			return err
		}
		identity.FirePreWriteHook(identity.OIDCSiteMonitorJoin)
		joined = join()
		return nil
	})
	return joined, err
}

// createInTx Create 的交易版（欄位預設與 Create 同源）
func (s *SessionService) createInTx(tx *gorm.DB, session *model.Session) error {
	if session.SessionID == "" {
		session.SessionID = fmt.Sprintf("sess_%d_%d", time.Now().UnixNano(), session.UserID)
	}
	if session.Status == "" {
		session.Status = model.SessionStatusActive
	}
	if session.StartTime.IsZero() {
		session.StartTime = time.Now()
	}
	if err := tx.Create(session).Error; err != nil {
		return fmt.Errorf("創建 Session 失敗: %w", err)
	}
	return nil
}
