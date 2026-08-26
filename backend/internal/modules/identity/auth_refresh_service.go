package identity

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/custodexa/backend/internal/modules/policy"
	"log"
	"strings"
	"time"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/sourceip"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
)

// AccessTokenTTL 正式 access token 固定短效：它是撤銷後殘餘存活的上限，
// 屬隱形防護常數，不進政策頁、不隨閒置政策放寬而變大
const AccessTokenTTL = 15 * time.Minute

// refreshTokenBytes refresh 憑證隨機長度（32 bytes = 256 bit，明文為 64 字元 hex）
const refreshTokenBytes = 32

// defaultWebIdleMinutes / defaultWebMaxSessionHours：政策服務未注入（僅測試建構路徑）
// 時的退路值，與政策常數表出廠預設一致
const (
	defaultWebIdleMinutes     = 60
	defaultWebMaxSessionHours = 12
)

// unlimitedSessionLifetime web_max_session_hours=0（不限）時的遠期哨兵；
// expires_at 欄位 NOT NULL，以遠期時間表達「不限」比 nullable 少一種空值分支
const unlimitedSessionLifetime = 87600 * time.Hour // 10 年

var (
	// ErrRefreshInvalid refresh 憑證無效/已撤銷/逾時——對外一律同文案，
	// 不給攻擊者區分「猜錯」與「猜對但已失效」的訊號
	ErrRefreshInvalid = errors.New("會話已失效，請重新登入")
)

// RefreshReuseError 已輪替憑證被重放（RFC 9700 reuse detection）：
// typed error 攜帶用戶識別供 handler 審計；對外回應仍泛化為 ErrRefreshInvalid 同文案
type RefreshReuseError struct {
	UserID   uint
	Username string
}

func (e *RefreshReuseError) Error() string {
	return "refresh 憑證重放（已輪替），已撤銷該使用者全部會話"
}

// RefreshFamilyRevokeError reuse detection 的家族撤銷**失敗**（DB 短暫故障等）。
//
// 與 RefreshReuseError 刻意分型：後者的語義是「已偵測重放且已撤銷全部憑證」，
// handler 據以寫下審計。撤銷失敗時仍回該型別，等於在稽核紀錄裡寫下與現實相反的
// 事實，而攻擊者持有的分叉鏈其實仍存活至絕對壽命
type RefreshFamilyRevokeError struct {
	UserID uint
	Err    error
}

func (e *RefreshFamilyRevokeError) Error() string {
	return fmt.Sprintf("refresh 憑證重放偵測的家族撤銷失敗 (userID=%d): %v", e.UserID, e.Err)
}

func (e *RefreshFamilyRevokeError) Unwrap() error { return e.Err }

// RefreshSourceDeniedError 刷新被來源限定擋下（或政策不可用）。
//
// **零寫入的證明就在型別上**：本錯誤只可能在交易早退時產生，此時舊憑證未撤、
// 新憑證未插、`last_used_at` 未動。handler 據此走既有的統一 401，
// 對外與其他刷新失敗逐字相同——成因（來源不對／政策壞了、位址、清單快照）
// 只出現在審計註記裡。
//
// 與 RefreshReuseError 分型而非共用：後者的語義是「已撤銷該使用者全部憑證」，
// 兩者若共用一個型別，稽核就分不出「憑證被作廢了」與「什麼都沒動」
type RefreshSourceDeniedError struct {
	UserID   uint
	Username string
	SourceIP string
	Verdict  sourceip.Verdict
}

func (e *RefreshSourceDeniedError) Error() string {
	return "refresh 來源不在允許範圍（或來源政策不可用）；憑證未被消耗"
}

// AuditNote 審計註記（**只進審計**）：原因碼、成因類別、位址與清單快照。
//
// 回應端不得使用本字串——對外只有統一 401。
func (e *RefreshSourceDeniedError) AuditNote() string {
	note := "refresh_" + e.Verdict.Reason
	if e.Verdict.Cause != "" {
		note += "; cause=" + e.Verdict.Cause
	}
	if e.SourceIP != "" {
		note += "; ip=" + e.SourceIP
	}
	if len(e.Verdict.Policy) > 0 {
		note += "; policy=" + strings.Join(e.Verdict.Policy, ",")
	}
	return note
}

// sourcePolicyCauseOf 把 sourceip 的成因類別對映到失效面的 cause 常數。
//
// 兩套常數各有其邊界：sourceip 不該認識審計失效面的詞彙，失效面也不該
// 依賴判定實作的內部命名。對映寫成一個函式，使新增成因時只有一處要改
func sourcePolicyCauseOf(cause string) string {
	if cause == sourceip.CauseParseError {
		return model.CauseSourcePolicyCorrupt
	}
	return model.CauseSourcePolicyUnreadable
}

// refreshPostRotateHook 測試用同步點：於「輪替交易已提交、access token 尚未簽發」
// 的精確位置呼叫。
//
// **可覆寫的唯一理由是測試**（同 localAdminPreWriteHook 的慣例）：本區間的競態
// （交易內驗過世代之後、簽發之前世代被推進）靠時間競賽觸發不穩定，本 hook 讓
// 「簽發改用現查世代」的突變被**確定性**地抓到。生產路徑此值恆為 nil。
var refreshPostRotateHook func()

// RefreshResponse 刷新回應：新 access token 與輪替後的新 refresh 憑證
type RefreshResponse struct {
	Token string `json:"token"`
	// RefreshToken 輪替後的新憑證明文。
	//
	// **`json:"-"` 是本 change 的結構層保證**（決策 3）：
	// 欄位保留（handler 需讀它來下 httpOnly cookie），但任何序列化路徑都不可能再把
	// 明文帶進回應 body——不依賴每個 handler 記得抹除欄位
	RefreshToken string `json:"-"`
	// RefreshExpiresAt 該憑證的絕對到期時刻，供 handler 把 cookie 效期對齊憑證。
	// 輪替沿用原 `expires_at`（不重算絕對壽命），故此值即原列的 ExpiresAt
	RefreshExpiresAt time.Time `json:"-"`
	// UserID／Username 本次輪替的主體：
	// handler 需要它們才寫得出「誰在何處輪替了憑證」的審計列，而
	// `/auth/refresh` 是公開端點，中介層取不到身分。
	//
	// **`json:"-"` 是實質**：對外回應零變化——輪替回應多帶身分欄不會讓
	// 前端更安全，卻多一處可被觀察的帳號資訊。
	UserID   uint   `json:"-"`
	Username string `json:"-"`
}

// hashRefreshToken refresh 憑證入庫前雜湊（SHA-256 hex）：DB 洩漏不等於憑證洩漏
func hashRefreshToken(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}

// generateRefreshPlain 產生 refresh 憑證明文（密碼學隨機 256 bit）
func generateRefreshPlain() (string, error) {
	buf := make([]byte, refreshTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("產生 refresh 憑證失敗: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// webMaxSessionDuration 讀絕對壽命政策；0=不限 → 遠期哨兵
func (s *AuthService) webMaxSessionDuration() time.Duration {
	hours := defaultWebMaxSessionHours
	if s.policies != nil {
		hours = s.policies.GetInt(policy.PolicyWebMaxSessionHours)
	}
	if hours == 0 {
		return unlimitedSessionLifetime
	}
	return time.Duration(hours) * time.Hour
}

// issueRefreshToken 發放 refresh 憑證（登入/換發正式會話時）。
// sessionStart 為絕對壽命錨點；rotation 路徑沿用原錨點與原 expires_at，不經此函式。
//
// 一併回傳 `expires_at`：憑證遷入 httpOnly cookie 後，handler 必須知道絕對到期時刻
// 才能把 cookie 效期對齊憑證（決策 1）——由此處回傳而非讓 handler 另查 DB，
// 兩個事實源會在「政策改動當下發放」這類邊界上分岔
func (s *AuthService) issueRefreshToken(userID uint, sessionStart time.Time, authCtx crypto.AuthContext) (string, time.Time, error) {
	plain, err := generateRefreshPlain()
	if err != nil {
		return "", time.Time{}, err
	}
	row := model.RefreshToken{
		UserID:           userID,
		TokenHash:        hashRefreshToken(plain),
		SessionStartedAt: sessionStart,
		ExpiresAt:        sessionStart.Add(s.webMaxSessionDuration()),
		LastUsedAt:       sessionStart,
		AuthMethod:       authCtx.AuthMethod,
		ProviderID:       authCtx.ProviderID,
		AuthEpoch:        authCtx.AuthEpoch,
		CredEpoch:        authCtx.CredEpoch,
	}
	if err := database.DB.Create(&row).Error; err != nil {
		return "", time.Time{}, fmt.Errorf("寫入 refresh 憑證失敗: %w", err)
	}
	return plain, row.ExpiresAt, nil
}

// RefreshSession 以 refresh 憑證換發新 access token 並輪替 refresh。
// 判定順序：存在 → reuse detection → 絕對壽命 → 閒置窗口 → 用戶狀態複查 →
// **交易內世代複查 → 來源限定 →** CAS 輪替。
// 任何失敗對外統一 ErrRefreshInvalid（reuse 與來源拒絕以 typed error 供 handler 審計）
//
// # sourceIP 為何是參數而不是服務自取
//
// 服務拿不到 `*gin.Context`，而來源位址的取法（是否採信轉送標頭）只有一份。
// 由 handler 交進來，判定與該次請求的審計列因此讀到同一個位址。
//
// # 來源判定的位置：交易內、世代複查之後、CAS 撤舊之前
//
// 放在輪替**之後**判會留下兩個缺陷（起草版即如此）：舊憑證已標 rotated、
// 新憑證已寫，拒絕就留下一枚孤兒憑證；更糟的是持竊憑證者得以自清單外
// **消耗**受害者手上仍有效的 refresh token——受害者下次刷新命中 reuse
// detection，整個家族被撤，等於攻擊者拿到一個免費的登出原語。
// 放在交易內、撤舊之前，拒絕路徑就是**零寫入**：不撤舊、不插新、不動
// `last_used_at`，同一枚憑證隨後自清單內來源刷新照常成功。
func (s *AuthService) RefreshSession(plain, sourceIP string) (*RefreshResponse, error) {
	var row model.RefreshToken
	err := database.DB.Where("token_hash = ?", hashRefreshToken(plain)).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrRefreshInvalid
	}
	if err != nil {
		return nil, err
	}

	if row.RevokedAt != nil {
		// 已輪替的憑證再現身 = 憑證洩漏訊號（合法端已持有新憑證，不會重放舊的）
		// → 家族撤銷（RFC 9700）。其他撤銷原因（登出/改密後殘留）重放只拒絕：
		// 該用戶可能已重新登入，撤銷全部會誤殺新會話，反成騷擾原語
		if row.RevokedReason == model.RefreshRevokeRotated {
			return nil, s.detectReuse(&row)
		}
		return nil, ErrRefreshInvalid
	}

	now := time.Now()
	if now.After(row.ExpiresAt) {
		s.markRevoked(&row, model.RefreshRevokeExpired)
		return nil, ErrRefreshInvalid
	}
	if idleMin := s.webIdleMinutes(); idleMin > 0 && now.Sub(row.LastUsedAt) > time.Duration(idleMin)*time.Minute {
		s.markRevoked(&row, model.RefreshRevokeIdleTimeout)
		return nil, ErrRefreshInvalid
	}

	// 用戶狀態複查（深度防禦）：停用/鎖定的撤銷點若因競態漏掉，刷新這關仍要擋
	if err := s.CheckUserConnectable(row.UserID); err != nil {
		return nil, ErrRefreshInvalid
	}

	// 新憑證沿用絕對壽命錨點：持續刷新也無法超過 max session（spec：達絕對壽命須重登）
	newPlain, err := generateRefreshPlain()
	if err != nil {
		return nil, err
	}

	// CAS 撤舊 + 插新在單一交易內原子提交：消除「舊已標 rotated、
	// 新憑證尚未寫入」的窗口——否則改密/停用的 RevokeAllRefreshTokens 若落在此窗，
	// 新憑證會逃過撤銷而續活至絕對壽命。CAS 條件 UPDATE 保證同一憑證併發刷新只有
	// 一個成功，輸家 RowsAffected==0 視同 reuse（已有另一持有者拿走輪替權）。
	// 殘餘（可接受）：RevokeAll 的語句快照理論上可錯過本交易「提交後才可見」的新列，
	// 屬 sub-ms 且需改密同時進行的競態，不對所有 RevokeAll 路徑加 user 級序列化
	//
	// **輪替亦是「以既有憑證產生新長效能力」**：
	// 少了鎖內的世代複查，一枚在 provider 密鑰輪替前簽出的 refresh 列會換出帶
	// **現行**世代的 access token——provider 仍啟用（只是換了 secret），
	// Enabled 檢查擋不住，等於密鑰輪替對已登入者完全無效。故交易改由
	// WithCapabilityLocks 開啟（provider → user 固定順序），並於鎖內以 refresh 列
	// 自身攜帶的世代對 DB 現值比對後才輪替。
	casRotated := false
	stale := false
	// sourceVerdict 零值＝未判定；非零且不放行時走「零寫入」早退
	var sourceVerdict sourceip.Verdict
	sourceJudged := false
	sourceUsername := ""
	txErr := WithCapabilityLocks(database.DB, row.ProviderID, row.UserID, func(tx *gorm.DB) error {
		var user model.User
		// allowed_cidrs 併入這次既有的 Select：使用者列本來就要載入，
		// 來源判定因此不多一次查詢，也不會與世代複查讀到不同的列
		// username 一併帶出：來源拒絕的審計列要指得出「是誰被擋」，
		// 只有 user_id 的列在稽核頁上得再查一次才知道是誰
		if err := tx.Select("id", "username", "credential_epoch", "active", "allowed_cidrs").
			First(&user, row.UserID).Error; err != nil {
			// 使用者列讀不到＝政策不可讀：拒絕，但走**零寫入**路徑
			// ——把它當交易錯誤丟出去會回 500，且無法與「憑證有問題」區分
			sourceVerdict = sourceip.Verdict{
				Reason: sourceip.ReasonPolicyUnreadable, Cause: sourceip.CauseReadError}
			sourceJudged = true
			return nil
		}
		if err := VerifyCredentialGenerationTx(tx, crypto.AuthContext{
			AuthMethod: row.AuthMethod, ProviderID: row.ProviderID,
			AuthEpoch: row.AuthEpoch, CredEpoch: row.CredEpoch,
		}, &user); err != nil {
			stale = true
			return nil // 交易正常結束；輪替不執行，交易外統一回 ErrRefreshInvalid
		}
		// 來源限定（順序約束）：世代複查通過、**尚未變更任何狀態**時判定。
		// 不落清單者在此早退，交易正常結束而一個位元組都沒寫
		sourceVerdict = sourceip.Evaluate(user.AllowedCIDRs, nil, sourceIP)
		sourceJudged = true
		sourceUsername = user.Username
		if !sourceVerdict.Allowed {
			return nil
		}
		res := tx.Model(&model.RefreshToken{}).
			Where("id = ? AND revoked_at IS NULL", row.ID).
			Updates(map[string]interface{}{
				"revoked_at":     now,
				"revoked_reason": model.RefreshRevokeRotated,
			})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return nil // CAS 輸家：交易外以 detectReuse 處理（不在交易內做家族撤銷）
		}
		casRotated = true
		// 認證脈絡與 SessionStartedAt 同屬「會話不變量」，rotation 必須顯式沿用：
		// 漏帶則 access token 到期輪替一次（分鐘級）後，provider 停用的撤銷查詢
		// 即命中 0 列——正在使用中的會話一個都撤不到，可續命至絕對壽命
		return tx.Create(&model.RefreshToken{
			UserID:           row.UserID,
			TokenHash:        hashRefreshToken(newPlain),
			SessionStartedAt: row.SessionStartedAt,
			ExpiresAt:        row.ExpiresAt,
			LastUsedAt:       now,
			AuthMethod:       row.AuthMethod,
			ProviderID:       row.ProviderID,
			AuthEpoch:        row.AuthEpoch,
			CredEpoch:        row.CredEpoch,
		}).Error
	})
	if txErr != nil {
		return nil, fmt.Errorf("refresh 憑證輪替失敗: %w", txErr)
	}
	if sourceJudged {
		// 可用性記帳在交易之外（Report 會寫 audit_failure_events，
		// 不可掛在能力鎖的交易裡）
		if sourceVerdict.Cause != "" {
			reportSourcePolicyFailure(sourcePolicyCauseOf(sourceVerdict.Cause), row.UserID)
		} else if sourcePolicyDegraded.Load() {
			EvaluateSourcePolicyHealth(database.DB)
		}
	}
	if sourceJudged && !sourceVerdict.Allowed {
		// **不呼叫 markRevoked**：憑證本身沒有問題，來源不對而已。
		// 標撤等於讓清單外的一次嘗試把受害者的憑證作廢
		return nil, &RefreshSourceDeniedError{
			UserID: row.UserID, Username: sourceUsername,
			Verdict: sourceVerdict, SourceIP: sourceIP}
	}
	if stale {
		// 世代已失效（provider 停用／刪除／密鑰輪替，或使用者憑證世代推進）：
		// 一併撤銷本列，使後續重放走「已撤銷」快路徑且成因可稽核
		s.markRevoked(&row, model.RefreshRevokeCredentialEpoch)
		return nil, ErrRefreshInvalid
	}
	if !casRotated {
		return nil, s.detectReuse(&row)
	}

	if refreshPostRotateHook != nil {
		refreshPostRotateHook()
	}

	var user model.User
	if err := database.DB.Preload("Roles").First(&user, row.UserID).Error; err != nil {
		return nil, err
	}
	// 換發的 access token 的四個脈絡欄位**一律取自 refresh 列自身**，世代不得現查
	// 交易內剛以列世代對 DB 現值驗過，非競態情況下兩者相等，
	// 現查沒有任何好處；競態情況下（驗證通過之後、簽發之前發生改密／停用／解綁／
	// provider 密鑰輪替）現查會簽出帶**新**世代的 access token，使該次刷新把本應
	// 失效的舊能力洗白並續活一個完整 TTL。沿用列世代則此時簽出的 token 對現值不符
	// 而立即失效＝正確的 fail-close（合法使用者重新登入即可，攻擊者拿不到有效期）。
	//
	// 註：原註解顧慮「沿用舊世代會使剛換發的 token 立即失效」，該顧慮已由交易內的
	// VerifyCredentialGenerationTx 消解——世代不符者根本走不到這裡（stale 分支已回拒）。
	//
	// 到期以會話絕對期限裁切（4.12）：否則期限前最後一次刷新可讓 access 多活一個
	// TTL，經 WS 旁路仍能開新連線
	accessToken, err := s.jwtManager.GenerateTokenNotAfter(user.ID, user.Username, user.EmailString(), primaryRoleOf(&user),
		crypto.AuthContext{
			AuthMethod: row.AuthMethod, ProviderID: row.ProviderID,
			AuthEpoch: row.AuthEpoch, CredEpoch: row.CredEpoch,
		}, row.ExpiresAt)
	if err != nil {
		return nil, err
	}
	return &RefreshResponse{
		Token: accessToken, RefreshToken: newPlain,
		RefreshExpiresAt: row.ExpiresAt,
		UserID:           user.ID, Username: user.Username,
	}, nil
}

// webIdleMinutes 讀 sliding 閒置窗口政策；0=停用閒置判定（政策頁顯示不符 PCI 建議）
func (s *AuthService) webIdleMinutes() int {
	if s.policies == nil {
		return defaultWebIdleMinutes
	}
	return s.policies.GetInt(policy.PolicyWebIdleMinutes)
}

// detectReuse 家族撤銷（RFC 9700）：撤銷該使用者全部 refresh 憑證，
// 令攻擊者以竊得憑證換到的存活會話一併失效；回 typed error 供 handler 審計。
//
// **撤銷失敗一律回 RefreshFamilyRevokeError，不得續走成功路徑**：
// 舊行為只記日誌卻仍回 RefreshReuseError，handler 據以寫下「已撤銷該使用者
// 全部 refresh」的審計事件——DB 短暫失敗時這句話與現實相反，攻擊者持有的分叉鏈
// 仍存活至絕對壽命，而稽核紀錄反倒宣告事件已處理，無人會回頭重試。
//
// 取捨（回錯 vs 重試）：此處刻意**不重試**。撤銷失敗的成因是 DB 不可用，同一
// request 內立即重試幾乎必然同樣失敗，只會拖長持有連線的時間；回錯則使呼叫端
// 拒絕本次刷新（fail-close），並讓失敗以 500＋內部錯誤日誌浮現，由運維以既有的
// 撤銷端點重試。攻擊者能得到的僅是「刷新被拒」——與成功撤銷時的結果一致
func (s *AuthService) detectReuse(row *model.RefreshToken) error {
	if _, err := RevokeAllRefreshTokens(database.DB, row.UserID, model.RefreshRevokeReuseDetected); err != nil {
		log.Printf("[AuthService] reuse detection 家族撤銷失敗，本次刷新以 fail-close 拒絕 (userID=%d): %v",
			row.UserID, err)
		return &RefreshFamilyRevokeError{UserID: row.UserID, Err: err}
	}
	var user model.User
	username := ""
	if err := database.DB.Select("username").First(&user, row.UserID).Error; err == nil {
		username = user.Username
	}
	log.Printf("[AuthService] refresh 憑證重放偵測 (userID=%d)：已撤銷該使用者全部 refresh 憑證", row.UserID)
	return &RefreshReuseError{UserID: row.UserID, Username: username}
}

// markRevoked 標記單一憑證撤銷（逾時/過期路徑）；失敗僅記日誌——
// 呼叫端已決定拒絕刷新，標記只是讓後續重放走「已撤銷」快路徑
func (s *AuthService) markRevoked(row *model.RefreshToken, reason string) {
	if err := database.DB.Model(&model.RefreshToken{}).
		Where("id = ? AND revoked_at IS NULL", row.ID).
		Updates(map[string]interface{}{
			"revoked_at":     time.Now(),
			"revoked_reason": reason,
		}).Error; err != nil {
		log.Printf("[AuthService] 標記 refresh 憑證撤銷失敗 (id=%d, reason=%s): %v", row.ID, reason, err)
	}
}

// RevokeRefreshToken 撤銷單一 refresh 憑證（登出）。
// 若登出提交的憑證「已被 rotation 作廢」，這是分叉訊號——
// 合法端登出時 localStorage 持有的應是最新未撤銷憑證；提交一枚已 rotated 的
// 舊憑證意味該憑證曾被他人（竊得後）輪替出分叉鏈。此時只做冪等 no-op 會讓
// 攻擊者的分叉鏈存活至絕對壽命（登出正好移除了受害者「重放舊憑證」才會觸發的
// reuse detection 網），故改走家族撤銷並回 RefreshReuseError 供 handler 記審計。
// 查無憑證、或已因登出/改密等非 rotation 原因撤銷者，視為冪等成功
func (s *AuthService) RevokeRefreshToken(plain, reason string) error {
	var row model.RefreshToken
	err := database.DB.Where("token_hash = ?", hashRefreshToken(plain)).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil // 冪等：查無視為已登出
	}
	if err != nil {
		return err
	}
	if row.RevokedAt != nil {
		if row.RevokedReason == model.RefreshRevokeRotated {
			return s.detectReuse(&row) // 分叉訊號 → 家族撤銷（RFC 9700）
		}
		return nil // 已因其他原因撤銷，冪等成功
	}
	return database.DB.Model(&model.RefreshToken{}).
		Where("id = ? AND revoked_at IS NULL", row.ID).
		Updates(map[string]interface{}{
			"revoked_at":     time.Now(),
			"revoked_reason": reason,
		}).Error
}

// RevokeAllRefreshTokens 撤銷使用者全部未撤銷 refresh 憑證（改密/停用/鎖定/家族撤銷）。
// package 函式而非方法：UserService（改密/停用）與 AuthService（鎖定/reuse）共用，
// 不引入 service 間相互依賴
func RevokeAllRefreshTokens(db *gorm.DB, userID uint, reason string) (int64, error) {
	res := db.Model(&model.RefreshToken{}).
		Where("user_id = ? AND revoked_at IS NULL", userID).
		Updates(map[string]interface{}{
			"revoked_at":     time.Now(),
			"revoked_reason": reason,
		})
	return res.RowsAffected, res.Error
}
