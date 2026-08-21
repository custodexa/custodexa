package identity

import (
	"errors"
	"fmt"
	"github.com/custodexa/backend/internal/modules/audit"
	"log"
	"strings"
	"time"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 外部身分管理（idp-oidc-integration 2.8 / spec user-account-administration）。
//
// 四個授權操作，全部含審計且失敗零副作用：
//
//	(a) BindExternalIdentity            admin 為既有帳號綁定外部身分
//	(b) UnbindExternalIdentity          解綁（判定於 user-scoped 鎖內重讀）
//	(c) UnbindExternalIdentityAndDisable 原子「解綁＋停用帳號」
//	(d) ConvertToExternalOnly           改為僅外部登入
//
// (b)(c)(d) 皆 SHALL 推進 credential_epoch 並執行三管道收線——僅移除關聯而不撤銷
// 存取等於「管理員執行的身分收回沒有真正收回」（design 行 337）：帳號同時綁
// Google 與遭入侵的 Okta 時，解綁 Okta 後攻擊者先前建立的 refresh／access／協議
// 連線在 provider 仍啟用、provider epoch 未變的情況下**全部繼續有效**。

var (
	// ErrExternalIdentityNotFound 指定的外部身分不存在（或不屬於該帳號）
	ErrExternalIdentityNotFound = errors.New("外部身分不存在")
	// ErrExternalIdentityExists 身分域三元組 (issuer, client_id, subject) 已被占用。
	// **不回填占用者是誰**：那會使綁定端點成為「某 subject 是否已在本系統」的探測器
	ErrExternalIdentityExists = errors.New("此外部身分已綁定至某個帳號")
	// ErrExternalIdentitySubjectInvalid subject 空白或逾長。
	// 空 subject 會使第一個異常 token 吸附該 provider 後續全部異常 token（D2）
	ErrExternalIdentitySubjectInvalid = errors.New("subject 不得為空且長度不得超過 255")
	// ErrExternalIdentityRequired 「改為僅外部登入」要求帳號至少已有一筆外部身分——
	// 否則轉換當下即製造出零登入途徑的孤兒帳號
	ErrExternalIdentityRequired = errors.New("帳號尚無任何外部身分，不可改為僅外部登入")
	// ErrUserAlreadyExternal 帳號憑證已由外部提供者管理（含 LDAP），無須也不可再轉換
	ErrUserAlreadyExternal = errors.New("此帳號的憑證已由外部身分提供者管理")
)

// LastLoginPathError 解綁被拒：操作後該帳號將失去全部可用登入途徑。
//
// 判準是「操作後是否仍有可用登入途徑」而非「是否還有其他外部身分」（spec）：
// 仍具本地密碼者可解綁最後一筆；目錄供應帳號的登入不依賴外部身分記錄故不受限；
// 憑證已外部化且僅剩此途徑者拒絕，並由 (c) 的「解綁＋停用」提供正當出路。
//
// 比照 LastLocalAdminError 帶精確出口碼，呼叫端以 errors.As 取用
type LastLoginPathError struct {
	Code apierror.ErrCode
}

func (e *LastLoginPathError) Error() string {
	return "解除此外部身分將使該帳號失去全部可用登入途徑；如需移除請改用「解除綁定並停用帳號」"
}

// ErrLastLoginPath 解綁判準拒絕的哨兵值（errors.Is 比對用）
var ErrLastLoginPath error = &LastLoginPathError{Code: apierror.CodeLastLoginPath}

// SubscriptionTerminator 唯讀訂閱（監看／分享觀看）的按-user 收線管道。
//
// 介面而非直接依賴 sshproxy.MonitorHub：service 不得反向依賴傳輸層。
// **監看訂閱不建 sessions 列**（sshproxy/monitor.go 只登記 WS），故 SessionTerminator
// 完全掃不到它；缺這條管道時，被解綁／停用者正在進行的監看會繼續存活並可讀他人終端
type SubscriptionTerminator interface {
	DisconnectByUser(userID uint) int
}

// RecordingTokenRevoker 錄影存取 token 的按-user 撤銷管道。
//
// 錄影 token 為 in-memory、TTL 120 秒且**不做世代比對**（Resolve 是 HTTP Range
// 熱路徑，見 api/recording_token.go 的取捨），故唯一的失效途徑是直接撤銷；
// 缺這條時「已撤銷憑證的人在 120 秒內仍能下載錄影」，而錄影是最敏感的稽核資產
type RecordingTokenRevoker interface {
	RevokeByUser(userID uint) int
}

// SetSubscriptionTerminator 注入唯讀訂閱收線管道（MonitorHub）
func (s *UserService) SetSubscriptionTerminator(t SubscriptionTerminator) {
	s.subscriptions = t
}

// SetRecordingTokenRevoker 注入錄影 token 撤銷管道（RecordingTokenManager）
func (s *UserService) SetRecordingTokenRevoker(r RecordingTokenRevoker) {
	s.recordingTokens = r
}

// SetAuditSink 注入審計出口（外部身分管理的四個操作皆留痕）
func (s *UserService) SetAuditSink(a *audit.AuditLogService) {
	// 具型別的 nil 指標存入介面欄位會使 s.audit != nil 成立而在呼叫時 panic
	if a != nil {
		s.audit = a
	}
}

// IdentityAdminActor 執行操作的管理者身分（審計歸屬）。
// 由 handler 自認證脈絡取得後傳入——service 不接觸 gin context
type IdentityAdminActor struct {
	UserID   uint
	Username string
	ClientIP string
}

// ExternalIdentityDTO 外部身分的管理端呈現。
//
// ClaimUsername／ClaimEmail 為 **IdP 自報值**（低權使用者可把自己的
// preferred_username 設成 "admin"），UI 須與本地使用者名稱分欄並標示來源
type ExternalIdentityDTO struct {
	ID            uint       `json:"id"`
	UserID        uint       `json:"user_id"`
	ProviderID    uint       `json:"provider_id"`
	ProviderName  string     `json:"provider_name"`
	Issuer        string     `json:"issuer"`
	ClientID      string     `json:"client_id"`
	Subject       string     `json:"subject"`
	ClaimUsername string     `json:"claim_username"`
	ClaimEmail    string     `json:"claim_email"`
	LastLoginAt   *time.Time `json:"last_login_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
}

// ListExternalIdentities 列出帳號的外部身分（admin 檢視）
func (s *UserService) ListExternalIdentities(userID uint) ([]ExternalIdentityDTO, error) {
	if _, err := s.loadUser(s.db, userID); err != nil {
		return nil, err
	}
	var rows []model.UserExternalIdentity
	if err := s.db.Where("user_id = ?", userID).Order("id").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("查詢外部身分失敗: %w", err)
	}
	names := map[uint]string{}
	if len(rows) > 0 {
		var providers []model.OIDCProvider
		if err := s.db.Select("id", "name").Find(&providers).Error; err == nil {
			for _, p := range providers {
				names[p.ID] = p.Name
			}
		}
	}
	out := make([]ExternalIdentityDTO, 0, len(rows))
	for _, r := range rows {
		out = append(out, ExternalIdentityDTO{
			ID: r.ID, UserID: r.UserID, ProviderID: r.ProviderID,
			ProviderName: names[r.ProviderID],
			Issuer:       r.Issuer, ClientID: r.ClientID, Subject: r.Subject,
			ClaimUsername: r.ClaimUsername, ClaimEmail: r.ClaimEmail,
			LastLoginAt: r.LastLoginAt, CreatedAt: r.CreatedAt,
		})
	}
	return out, nil
}

// BindExternalIdentity (a) admin 為既有帳號綁定外部身分。
//
// **issuer 與 client_id 一律取自 provider 列，不收請求輸入**：它們是身分域的組成，
// 若可由請求指定，admin 就能綁出一個不對應任何 provider 的身分域，或把某人的
// subject 掛到偽造的 issuer 下——登入時以三元組查找即會命中錯誤的帳號。
// 請求端只提供 provider_id 與 subject。
//
// 綁定**不推進** credential_epoch：新增登入途徑不使既有憑證失效
func (s *UserService) BindExternalIdentity(userID, providerID uint, subject string,
	actor IdentityAdminActor) (*ExternalIdentityDTO, error) {

	subject = strings.TrimSpace(subject)
	// 大小寫敏感、不做任何正規化（D2）：subject 的比對語義由 IdP 定義，
	// 我方任何「順手」的正規化都可能把兩個不同身分折疊成一個
	if subject == "" || len(subject) > 255 {
		return nil, ErrExternalIdentitySubjectInvalid
	}

	user, err := s.loadUser(s.db, userID)
	if err != nil {
		return nil, err
	}

	var provider model.OIDCProvider
	if err := s.db.First(&provider, providerID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrOIDCProviderNotFound
		}
		return nil, fmt.Errorf("查詢 provider 失敗: %w", err)
	}

	// **claim 快照（ClaimUsername／ClaimEmail）刻意留空**（1.11）：admin 綁定時
	// 我方尚未見過該 subject 的任何 id_token，沒有任何 IdP 自報值可填。
	// 以 admin 手打的值頂替會使該欄的語義失真——它宣稱是「IdP 現況」，管理端
	// 據以辨識「這個 subject 到底是誰」，填入我方輸入等於自證自話。
	// 兩欄為空即代表「尚未經此身分登入過」，首次登入時由 touchIdentity
	// （oidc_login_service.go）補上快照
	identity := model.UserExternalIdentity{
		UserID: userID, ProviderID: provider.ID,
		Issuer: provider.Issuer, ClientID: provider.ClientID, Subject: subject,
	}

	// 唯一性由 partial unique index 把關（migrations.go idx_user_external_identities_domain）。
	// 先查後寫有 TOCTOU 窗，故**以約束失敗為準**：預查僅為了回可讀錯誤，
	// 真正的裁決在 DB。約束失敗後重查以區分「撞既有身分」與其他寫入錯誤
	createErr := s.db.Create(&identity).Error
	if createErr != nil {
		var existing model.UserExternalIdentity
		if err := s.db.Where("issuer = ? AND client_id = ? AND subject = ?",
			provider.Issuer, provider.ClientID, subject).First(&existing).Error; err == nil {
			s.writeIdentityAudit(actor, userID, model.ActionCreate, model.StatusFailure, map[string]any{
				"event": "external_identity_bind_rejected", "reason": "identity_domain_taken",
				"provider_id": provider.ID,
			})
			return nil, ErrExternalIdentityExists
		}
		return nil, fmt.Errorf("建立外部身分關聯失敗: %w", createErr)
	}

	s.writeIdentityAudit(actor, userID, model.ActionCreate, model.StatusSuccess, map[string]any{
		"event": "external_identity_bound", "provider_id": provider.ID,
		"identity_id": identity.ID, "target_username": user.Username,
	})
	log.Printf("[ExternalIdentity] 已綁定外部身分 (userID=%d, providerID=%d, identityID=%d)",
		userID, provider.ID, identity.ID)

	dto := ExternalIdentityDTO{
		ID: identity.ID, UserID: identity.UserID, ProviderID: identity.ProviderID,
		ProviderName: provider.Name, Issuer: identity.Issuer,
		ClientID: identity.ClientID, Subject: identity.Subject,
		CreatedAt: identity.CreatedAt,
	}
	return &dto, nil
}

// UnbindExternalIdentity (b) 解除外部身分綁定。
//
// 判定 SHALL 於 user-scoped 鎖內重讀（design 行 341）：帳號有兩筆身分時，
// 兩個並發解綁各自看見「還有另一筆」即可同時成功，留下零登入途徑。
//
// 成功時同交易推進 credential_epoch 並撤銷 refresh；鎖外執行三管道收線。
func (s *UserService) UnbindExternalIdentity(userID, identityID uint, actor IdentityAdminActor) error {
	err := WithUserCredentialLock(s.db, userID, func(tx *gorm.DB) error {
		return s.unbindLocked(tx, userID, identityID)
	})
	if err != nil {
		s.auditIdentityFailure(actor, userID, "external_identity_unbind_rejected", identityID, err)
		return err
	}

	s.writeIdentityAudit(actor, userID, model.ActionDelete, model.StatusSuccess, map[string]any{
		"event": "external_identity_unbound", "identity_id": identityID,
		"revocation_scope": "user",
	})
	// 鎖外收線（design D13：關閉連線於鎖外，持鎖時長維持單次 DB 往返級）
	s.revokeUserAccess(userID, "external_identity_unbound")
	return nil
}

// UnbindExternalIdentityAndDisable (c) 原子「解綁＋停用帳號」。
//
// 外部化帳號移除最後一筆身分的正當出路：(b) 的判準會拒絕該操作，但管理者仍須
// 有辦法收回身分；此操作把「收回身分」與「帳號不再可登入」綁成同一交易，
// 使系統不會停在「已解綁但帳號仍宣稱可登入」的中間態。**交易失敗時兩者皆不變**。
//
// 停用會移除該帳號的本地 admin 資格，故外層經系統級的本地 admin 不變式鎖；
// 取鎖順序 system → user（design D13）。
func (s *UserService) UnbindExternalIdentityAndDisable(userID, identityID uint, actor IdentityAdminActor) error {
	err := WithLocalAdminInvariant(s.db, userID, func(tx *gorm.DB) error {
		return withUserCredentialLockTx(tx, userID, func(tx *gorm.DB) error {
			// 解綁本身在此**不套用登入途徑判準**：帳號同一交易內即被停用，
			// 「保留可用登入途徑」的目的（不製造無法登入的活躍帳號）已由停用滿足
			if _, err := s.deleteIdentity(tx, userID, identityID); err != nil {
				return err
			}
			if err := tx.Model(&model.User{}).Where("id = ?", userID).
				Update("active", false).Error; err != nil {
				return fmt.Errorf("停用帳號失敗: %w", err)
			}
			return s.invalidateCredentialsLocked(tx, userID, "external_identity_unbound_and_disabled")
		})
	})
	if err != nil {
		s.auditIdentityFailure(actor, userID, "external_identity_unbind_disable_rejected", identityID, err)
		return err
	}

	s.writeIdentityAudit(actor, userID, model.ActionDelete, model.StatusSuccess, map[string]any{
		"event":       "external_identity_unbound_and_account_disabled",
		"identity_id": identityID, "revocation_scope": "user",
	})
	s.revokeUserAccess(userID, "external_identity_unbound_and_disabled")
	return nil
}

// ConvertToExternalOnly (d) 改為僅外部登入。
//
// 同交易清除密碼雜湊（不留可比對殘值）＋標記 external_credential＋推進
// credential_epoch。要求帳號至少已有一筆外部身分（否則即製造孤兒帳號），
// 並受最後本地 admin 不變式約束——本操作會移除該帳號的本地 admin 資格。
//
// **推進世代是本操作的安全核心，不只是清密碼**：MFA 待驗證憑證（scoped token）
// 是以本地密碼啟動的，若不失效，其持有者可於轉換後完成 MFA 驗證，且 finishLogin
// 會因帳號此時已外部化而跳過密碼 gate，直接取得正式會話（spec 明列的失效情境）。
func (s *UserService) ConvertToExternalOnly(userID uint, actor IdentityAdminActor) error {
	err := WithLocalAdminInvariant(s.db, userID, func(tx *gorm.DB) error {
		return withUserCredentialLockTx(tx, userID, func(tx *gorm.DB) error {
			user, err := s.loadUser(tx, userID)
			if err != nil {
				return err
			}
			if user.IsExternal() {
				return ErrUserAlreadyExternal
			}
			// 前提於鎖內重讀：並發解綁最後一筆身分與本轉換若各自預讀，
			// 兩者皆會通過而使帳號歸零登入途徑
			identities, err := countUsableExternalIdentities(tx, userID, 0)
			if err != nil {
				return err
			}
			if identities == 0 {
				return ErrExternalIdentityRequired
			}
			if userCredentialPreWriteHook != nil {
				userCredentialPreWriteHook()
			}
			// must_change_password 一併清除：外部化帳號永遠走不到改密流程，
			// 殘留旗標會讓登入後卡在無法完成的強制改密 gate
			if err := tx.Model(&model.User{}).Where("id = ?", userID).
				Updates(map[string]interface{}{
					"password":             "",
					"external_credential":  true,
					"must_change_password": false,
				}).Error; err != nil {
				return fmt.Errorf("轉換為僅外部登入失敗: %w", err)
			}
			return s.invalidateCredentialsLocked(tx, userID, "converted_to_external_only")
		})
	})
	if err != nil {
		s.auditIdentityFailure(actor, userID, "user_external_only_conversion_rejected", 0, err)
		return err
	}

	s.writeIdentityAudit(actor, userID, model.ActionUpdate, model.StatusSuccess, map[string]any{
		"event": "user_converted_to_external_only", "revocation_scope": "user",
	})
	s.revokeUserAccess(userID, "converted_to_external_only")
	return nil
}

// --- 鎖內共用步驟 ---

// unbindLocked (b) 的鎖內部分：重讀判準 → 刪除 → 推進世代 → 撤 refresh。
func (s *UserService) unbindLocked(tx *gorm.DB, userID, identityID uint) error {
	user, err := s.loadUser(tx, userID)
	if err != nil {
		return err
	}
	identity, err := s.findIdentity(tx, userID, identityID)
	if err != nil {
		return err
	}

	// 判準的三個輸入全部於鎖內重讀（帳號的外部化狀態、供應來源、剩餘可用身分數）
	remaining, err := countUsableExternalIdentities(tx, userID, identity.ID)
	if err != nil {
		return err
	}
	if !hasLoginPathAfterUnbind(user, remaining) {
		log.Printf("[ExternalIdentity] 拒絕解綁：帳號將失去全部登入途徑 (userID=%d, identityID=%d)",
			userID, identityID)
		return ErrLastLoginPath
	}

	if userCredentialPreWriteHook != nil {
		userCredentialPreWriteHook()
	}
	if err := tx.Delete(identity).Error; err != nil {
		return fmt.Errorf("解除外部身分綁定失敗: %w", err)
	}
	return s.invalidateCredentialsLocked(tx, userID, "external_identity_unbound")
}

// countUsableExternalIdentities 帳號「仍能用來登入」的外部身分數（判準的單一查詢源）。
//
// **不只是未軟刪的身分列**（codex 對抗審查 F-B）：身分能不能登入取決於它所屬的
// provider——provider 已停用或已刪除時，該身分的登入流程一律被 Begin／Callback／
// Exchange 的啟用檢查擋下。只數身分列會讓「剩下的那筆屬於已停用 provider」被當成
// 可用途徑：解綁最後一筆可用身分照樣放行、或把仍有本地密碼的帳號轉成僅外部登入，
// 兩者的結果都是零可用登入途徑的孤兒帳號。
//
// excludeIdentityID > 0 時排除該筆（解綁判準問的是「移除它之後還剩幾筆」）。
// 解綁（b）與轉換（d）共用本查詢，兩處判準不得再各自實作而漂移。
func countUsableExternalIdentities(tx *gorm.DB, userID, excludeIdentityID uint) (int64, error) {
	q := tx.Model(&model.UserExternalIdentity{}).
		Joins("JOIN oidc_providers ON oidc_providers.id = user_external_identities.provider_id").
		Where("user_external_identities.user_id = ? AND user_external_identities.deleted_at IS NULL", userID).
		Where("oidc_providers.enabled = ? AND oidc_providers.deleted_at IS NULL", true)
	if excludeIdentityID > 0 {
		q = q.Where("user_external_identities.id <> ?", excludeIdentityID)
	}
	var n int64
	if err := q.Count(&n).Error; err != nil {
		return 0, fmt.Errorf("統計可用外部身分失敗: %w", err)
	}
	return n, nil
}

// hasLoginPathAfterUnbind 解綁後是否仍有可用登入途徑（spec 判準的單一事實源）。
//
//	remaining > 0                     → 仍有**可用**外部身分（其 provider 啟用中且未刪除）
//	目錄供應（LDAP）                  → 登入不依賴外部身分記錄，不受此限
//	未外部化且尚存密碼雜湊            → 仍可本地密碼登入
//
// 密碼雜湊非空是**額外的 fail-close**：external_credential 若因某條建號路徑漏設
// 而為 false、密碼卻是空字串，單看旗標會誤判為「仍可本地登入」而放行解綁
func hasLoginPathAfterUnbind(user *model.User, remaining int64) bool {
	if remaining > 0 {
		return true
	}
	if user.IsLDAP || user.ProvisioningOrigin == model.AuthSourceLDAP {
		return true
	}
	return !user.IsExternal() && strings.TrimSpace(user.Password) != ""
}

// invalidateCredentialsLocked 鎖內的憑證失效：推進使用者世代 ＋ 撤銷 refresh。
//
// 兩者同交易：世代推進了卻沒撤 refresh，使用者仍可用舊 refresh 換發（換發會現查
// 世代故會被拒，但撤銷讓失效原因可稽核）；反之撤了 refresh 卻沒推進世代，則
// 既簽 access 與尚未兌換的 ticket／MFA pending／connect grant 全部存活
func (s *UserService) invalidateCredentialsLocked(tx *gorm.DB, userID uint, reason string) error {
	if err := BumpCredentialEpoch(tx, userID, reason); err != nil {
		return err
	}
	if _, err := RevokeAllRefreshTokens(tx, userID, model.RefreshRevokeCredentialEpoch); err != nil {
		return fmt.Errorf("撤銷刷新憑證失敗: %w", err)
	}
	return nil
}

// deleteIdentity 鎖內刪除指定身分（歸屬校驗一併完成）
func (s *UserService) deleteIdentity(tx *gorm.DB, userID, identityID uint) (*model.UserExternalIdentity, error) {
	identity, err := s.findIdentity(tx, userID, identityID)
	if err != nil {
		return nil, err
	}
	if userCredentialPreWriteHook != nil {
		userCredentialPreWriteHook()
	}
	if err := tx.Delete(identity).Error; err != nil {
		return nil, fmt.Errorf("解除外部身分綁定失敗: %w", err)
	}
	return identity, nil
}

// findIdentity 取身分並校驗歸屬。**必須帶 user_id 條件**：只用 identityID 查，
// 會讓管理端誤傳（或惡意構造）他人身分 ID 時解到別的帳號頭上
func (s *UserService) findIdentity(tx *gorm.DB, userID, identityID uint) (*model.UserExternalIdentity, error) {
	var identity model.UserExternalIdentity
	if err := tx.Where("id = ? AND user_id = ?", identityID, userID).
		First(&identity).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrExternalIdentityNotFound
		}
		return nil, fmt.Errorf("查詢外部身分失敗: %w", err)
	}
	return &identity, nil
}

func (s *UserService) loadUser(tx *gorm.DB, userID uint) (*model.User, error) {
	var user model.User
	if err := tx.First(&user, userID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("查詢使用者失敗: %w", err)
	}
	return &user, nil
}

// --- 鎖外收線 ---

// revokeUserAccess 使用者級的三管道收線（credential_epoch 推進後的主動終斷）。
//
// 世代閘只能拒絕「下一次使用憑證」的請求；**已建立的長連線在建立後不再出示憑證**，
// 對世代完全免疫，故必須主動終斷。三條管道各自涵蓋世代閘掃不到的一塊：
//
//	協議會話    sessions 列存在，但 WS 已建立、不再過認證中介層
//	唯讀訂閱    不建 sessions 列（監看／分享），SessionTerminator 掃不到
//	錄影 token  in-memory、不做世代比對，僅能直接撤銷
//
// 一律於鎖外呼叫，且個別失敗不回滾主操作——身分已解除是主要安全目標，
// 收線失敗記日誌人工跟進（同 UpdateStatus 的既有取捨）
func (s *UserService) revokeUserAccess(userID uint, reason string) {
	if s.sessionTerminator != nil {
		if n, err := s.sessionTerminator.TerminateAllByUser(userID); err != nil {
			log.Printf("[ExternalIdentity] 終斷協議會話失敗 (userID=%d, reason=%s): %v", userID, reason, err)
		} else if n > 0 {
			log.Printf("[ExternalIdentity] 已終斷 %d 個進行中會話 (userID=%d, reason=%s)", n, userID, reason)
		}
	}
	if s.subscriptions != nil {
		if n := s.subscriptions.DisconnectByUser(userID); n > 0 {
			log.Printf("[ExternalIdentity] 已收線 %d 個唯讀訂閱 (userID=%d, reason=%s)", n, userID, reason)
		}
	}
	if s.recordingTokens != nil {
		if n := s.recordingTokens.RevokeByUser(userID); n > 0 {
			log.Printf("[ExternalIdentity] 已撤銷 %d 個錄影存取憑證 (userID=%d, reason=%s)", n, userID, reason)
		}
	}
}

// --- 審計 ---

func (s *UserService) writeIdentityAudit(actor IdentityAdminActor, targetUserID uint,
	action model.AuditAction, status model.AuditStatus, details map[string]any) {
	if s.audit == nil {
		return
	}
	target := targetUserID
	details["target_user_id"] = targetUserID
	s.audit.Log(&audit.AuditLogEntry{
		UserID:     actor.UserID,
		Username:   actor.Username,
		Action:     action,
		Resource:   model.ResourceUser,
		ResourceID: &target,
		Status:     status,
		ClientIP:   actor.ClientIP,
		Details:    mustJSON(details),
	})
}

// auditIdentityFailure 拒絕與失敗一律留痕（規則拒絕是稽核關注的事件本身，
// 不是雜訊）。**成因只寫機器可辨的分類**，不回填外部可控字串
func (s *UserService) auditIdentityFailure(actor IdentityAdminActor, targetUserID uint,
	event string, identityID uint, err error) {
	details := map[string]any{"event": event, "reason": identityFailureReason(err)}
	if identityID > 0 {
		details["identity_id"] = identityID
	}
	s.writeIdentityAudit(actor, targetUserID, model.ActionUpdate, model.StatusFailure, details)
}

func identityFailureReason(err error) string {
	switch {
	case errors.Is(err, ErrLastLoginPath):
		return "last_login_path"
	case errors.Is(err, ErrLastLocalAdmin):
		return "last_local_admin"
	case errors.Is(err, ErrExternalIdentityNotFound):
		return "identity_not_found"
	case errors.Is(err, ErrExternalIdentityRequired):
		return "no_external_identity"
	case errors.Is(err, ErrUserAlreadyExternal):
		return "already_external"
	case errors.Is(err, ErrUserNotFound):
		return "user_not_found"
	default:
		return "internal_error"
	}
}
