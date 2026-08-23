package identity

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/policy"
	"log"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"gorm.io/gorm"
)

var (
	// ErrInvalidCredentials 無效的認證憑證
	ErrInvalidCredentials = errors.New("使用者名稱或密碼錯誤")
	// ErrUserInactive 使用者未啟用
	ErrUserInactive = errors.New("使用者帳號未啟用")
	// ErrUserNotFound 使用者不存在
	ErrUserNotFound = errors.New("使用者不存在")
	// ErrAccountLocked 帳號因連續失敗被鎖定（明示訊息：不透露剩餘時間/次數）
	ErrAccountLocked = errors.New("嘗試次數過多，帳號已暫時鎖定，請稍後再試或聯繫管理員")
	// ErrConnectionNotAuthorized WS 連線授權失敗（scoped token / 停用 / 鎖定）
	ErrConnectionNotAuthorized = errors.New("此 token 不可用於建立連線")
	// ErrLDAPTransportRejected LDAP 登入被傳輸安全政策（strict）拒絕。
	// 明確原因是 spec 要求：否則使用者
	// 只看到「密碼錯誤」，支援負擔轉嫁給目錄管理員。
	//
	// **文案指向身分管理 UI**：設定自 env 遷入 DB
	// 後，修復動作不再是「請部署方改 LDAP_URL 重啟」，而是 admin 於目錄設定頁
	// 改用 ldaps://。指錯修復位置的錯誤訊息比沒有訊息更浪費時間。
	// **同一句話在兩處各寫一次**：此處與 apierror.CodeLDAPTransportRejected 的
	// zh fallback（bijection 測試釘住 zh-TW locale == ZhFallback），改一處必改另一處
	ErrLDAPTransportRejected = errors.New("LDAP 登入被傳輸安全政策拒絕：目錄連線未達加密要求，請管理員於身分管理的目錄設定頁改用 ldaps://")
	// ErrInvalidDisplayName 自助顯示名格式驗證失敗（長度上限/控制字元/換行）
	ErrInvalidDisplayName = errors.New("顯示名稱格式不正確")
)

// maxDisplayNameLen 自助顯示名長度上限（rune 數，與 users.local_display_name varchar(100) 對齊）
const maxDisplayNameLen = 100

// passwordChangeTokenTTL 強制改密 scoped token 存活時間（流程機制常數，不進政策）
const passwordChangeTokenTTL = 15 * time.Minute

// AuthService 認證服務
type AuthService struct {
	jwtManager *crypto.JWTManager
	// mfaCrypto 用於加解密 TOTP secret（users.totp_secret_enc）；nil 表示 MFA 功能未啟用。
	// **ColumnCodec**：介面上
	// **沒有** Encrypt(plaintext)，故持有者在**建構上**不可能寫出無 AAD 的 enc:v 密文。
	// **建構時注入**（無 SetMFACodec 事後覆寫）
	mfaCrypto crypto.ColumnCodec
	// ldapResolver LDAP 登入路徑的單次設定解析。
	// nil 表示本組裝完全不接目錄，登入流程跳過 LDAP 路徑；
	// 「有接但未設定／已停用」由解析結果的 unavailable 態表達，兩者不混用
	ldapResolver LDAPLoginResolver
	// policies nil 表示不啟用鎖定/強制改密等政策 gate（僅測試建構路徑，生產組裝一律注入）
	policies *policy.SecurityPolicyService
	// transmission LDAP 登入傳輸閘；nil＝閘不生效。
	// 判定撥號當下最終參數（scheme/SkipTLSVerify），與設定存放位置解耦
	transmission *policy.TransmissionPolicyService
	// extLoginAgg 外部帳號本地登入嘗試的聚合審計；延遲建立，
	// 見 external_login_attempt_audit.go 的 externalLoginAttempts()
	extLoginAgg     *externalLoginAttemptAggregator
	extLoginAggOnce sync.Once
	// epochGateDB 憑證世代閘的資料來源（原為包級函式直讀
	// 全域 database.DB）。nil＝未注入，回退全域，
	// 見 auth_epoch_gate.go 的 epochDB() 註解
	epochGateDB *gorm.DB
}

// SetTransmissionPolicy 注入傳輸政策服務（LDAP 登入閘，main 組裝時）
func (s *AuthService) SetTransmissionPolicy(tp *policy.TransmissionPolicyService) {
	s.transmission = tp
}

// SetSecurityPolicies 注入安全政策服務（鎖定門檻等政策 gate 的讀取來源）
func (s *AuthService) SetSecurityPolicies(policies *policy.SecurityPolicyService) {
	s.policies = policies
}

// SetLDAPResolver 注入 LDAP 登入解析器（原
// SetLDAPAuthenticator）。
//
// **注入 resolver 而非 authenticator**：設定存於 DB 可隨時變更，啟動時建構
// 一次的認證器會停在舊值。resolver 於每次登入解析一次，且同一份解析結果同時
// 供傳輸閘與撥號使用——閘與撥號不同源即是 spec 明令禁止的 TOCTOU 交錯。
//
// 為什麼仍用 setter：比照 NewAuthServiceWithMFA 的精神——不需 LDAP 的呼叫端
// （含全部既有測試）零改動，啟用方在組裝階段顯式開啟
func (s *AuthService) SetLDAPResolver(resolver LDAPLoginResolver) {
	s.ldapResolver = resolver
}

// NewAuthService 建立認證服務
func NewAuthService(jwtSecret string, tokenDuration time.Duration) *AuthService {
	return &AuthService{
		jwtManager: crypto.NewJWTManager(jwtSecret, tokenDuration),
	}
}

// NewAuthServiceWithMFA 建立含 MFA（TOTP secret 加密）能力的認證服務。
// codec 為必要參數（建構期零 env 依賴），nil 即拒絕建構
func NewAuthServiceWithMFA(jwtSecret string, tokenDuration time.Duration, codec crypto.ColumnCodec) (*AuthService, error) {
	if codec == nil {
		return nil, fmt.Errorf("初始化 MFA 加密服務失敗: codec 為必要參數（不得於建構期自 env 材料自建）")
	}
	return &AuthService{
		jwtManager: crypto.NewJWTManager(jwtSecret, tokenDuration),
		mfaCrypto:  codec,
	}, nil
}

// 強制改密觸發原因值域
const (
	PasswordChangeReasonMustChange   = "must_change"
	PasswordChangeReasonNoncompliant = "policy_noncompliant"
	PasswordChangeReasonExpired      = "password_expired"
)

// LoginRequest 登入請求
type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// LoginResponse 登入回應。
// Token/User 加 omitempty 是為了 MFA 兩階段回應不出現空 token/null user；
// 非 MFA 用戶兩欄位必有值，序列化結果與既有完全相同
type LoginResponse struct {
	Token string    `json:"token,omitempty"`
	User  *UserInfo `json:"user,omitempty"`

	// RefreshToken 會話刷新憑證：access 固定短效 15 分，前端以此透明換發。
	//
	// **`json:"-"` 是本 change 的結構層保證**（決策 3）：
	// 憑證改由 httpOnly cookie 下發，欄位保留僅供 handler 讀它來寫 cookie。
	// 任何序列化路徑——含 OIDC 交換的巢狀 `gin.H{"login": resp}`——都不可能再把
	// 明文帶進回應 body，不依賴每個 handler 記得抹除欄位。
	//
	// 副作用即是要的行為：未來新增的發放端點若忘了下 cookie，該路徑的會話
	// 15 分鐘後必斷（refresh 無憑證可用），是**吵鬧的失敗**而非靜默回退到 localStorage
	RefreshToken string `json:"-"`

	// RefreshExpiresAt 上述憑證的絕對到期時刻，供 handler 把 cookie 效期對齊憑證
	RefreshExpiresAt time.Time `json:"-"`

	// MFA 兩階段登入：第一階段僅回 mfa_required + pending_token
	MFARequired  bool   `json:"mfa_required,omitempty"`
	PendingToken string `json:"pending_token,omitempty"`

	// MFA 強制註冊（8.4.2）：受強制但未註冊 TOTP 者密碼驗證通過後回此，
	// 持 enrollment_token 走 TOTP 綁定端點，綁定完成直接換發正式 token
	MFAEnrollmentRequired bool   `json:"mfa_enrollment_required,omitempty"`
	EnrollmentToken       string `json:"enrollment_token,omitempty"`

	// 強制改密（8.3.5/2.2.2）：密碼（與 MFA，如有）驗證通過但須先改密，
	// 回 change_token（僅可打 /auth/change-password），改密成功直接換發正式 token。
	// PolicyHint 為改密表單的政策提示文案（task 2.4：長度/組成），政策頁 API 是 admin-only，
	// 未登入的改密表單拿不到，故隨登入回應附帶
	PasswordChangeRequired bool   `json:"password_change_required,omitempty"`
	ChangeToken            string `json:"change_token,omitempty"`
	PolicyHint             string `json:"policy_hint,omitempty"`

	// 強制改密觸發原因：must_change（首登/重設）、
	// policy_noncompliant（現行密碼不符政策，附 reason_code+reason_params 供 i18n 插值）、
	// password_expired（逾 password_max_age_days）。MFA 用戶的合規偵測在第一階段持久化
	// 旗標，第二階段 gate 以 must_change 呈現（明文已不可得，細節仍在 PolicyHint）
	PasswordChangeReason string           `json:"password_change_reason,omitempty"`
	ReasonCode           apierror.ErrCode `json:"reason_code,omitempty"`
	ReasonParams         map[string]any   `json:"reason_params,omitempty"`

	// PolicyNoncompliantCategory 登入時偵測到現行密碼不符政策的違規類別
	//（apierror 碼字串，無密碼材料），僅供 handler 落審計事件，不輸出 JSON
	PolicyNoncompliantCategory string `json:"-"`

	// 僅供 handler 審計使用，不輸出至 JSON（第一階段回應不得洩漏用戶資訊）
	PendingUserID   uint   `json:"-"`
	PendingUsername string `json:"-"`

	// AuthSource 認證來源（"ldap" 或空字串表示本地），僅供 handler 審計標註
	AuthSource string `json:"-"`

	// AuthProviderID／AuthProviderName 本次登入所經的外部身分提供者，僅供 handler
	// 審計標註（spec「登入審計 SHALL 標註認證方式與 provider」）。本地／LDAP 登入為零值
	AuthProviderID   uint   `json:"-"`
	AuthProviderName string `json:"-"`
}

// UserInfo 使用者資訊
type UserInfo struct {
	ID       uint   `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	FullName string `json:"full_name"`
	// LocalDisplayName 自助顯示名原始值（可為 null＝未自訂）：供 Profile 編輯欄回填。
	// 顯示一律用 DisplayName（已 resolve）；此欄僅編輯用
	LocalDisplayName *string `json:"local_display_name"`
	// DisplayName 後端 resolve 的顯示名（local_display_name || full_name || username，
	// 單一事實源）：僅裝飾/自我檢視場景使用，身分敏感場景一律 username
	DisplayName string   `json:"display_name"`
	Active      bool     `json:"active"`
	Roles       []string `json:"roles"`
	TOTPEnabled bool     `json:"totp_enabled"`
	// IsLDAP：目錄服務供應的影子帳號——密碼由 LDAP 管理，前端據此隱藏自助改密
	IsLDAP bool `json:"is_ldap"`
	// ExternalCredential：憑證由外部提供者管理，一切本地密碼路徑皆不適用。
	// 前端的自助改密與密碼到期提示一律依此欄泛化——
	// **不可續用 is_ldap**：OIDC 影子帳號的 is_ldap 為 false，只看它會讓
	// OIDC 使用者看到一個按下去必然失敗的改密表單
	ExternalCredential bool `json:"external_credential"`
	// ProvisioningOrigin：帳號的供應來源（local/ldap/oidc），建立後不可變。
	// 與 ExternalCredential 分離是刻意的——混合帳號（OIDC 供應但保有本地密碼）
	// 兩者不同值，UI 需要分別呈現「哪裡來的」與「密碼歸誰管」
	ProvisioningOrigin string `json:"provisioning_origin"`
	// IsApprover：有效審核資格（群組即資格）＝
	// 具 approver 角色 OR 屬任一審核方群組——前端審核中心入口/badge 依此判定
	//（roles 陣列蓋不到群組成員的情形）
	IsApprover bool `json:"is_approver"`
}

// Login 使用者登入。gate chain（登入狀態機，順序固定）：
// 鎖定檢查 → 密碼/LDAP 驗證（失敗計數）→ MFA 分流 → 強制改密 → 發正式 token。
// 本地查到非 is_ldap 用戶 -> bcrypt 原路徑；
// 查到 is_ldap 用戶或查無且 LDAP 啟用 -> LDAP 驗證（成功且查無時供應影子用戶）
func (s *AuthService) Login(req *LoginRequest) (*LoginResponse, error) {
	user, authSource, err := s.verifyCredentials(req)
	if err != nil {
		return nil, err
	}

	// 本次認證脈絡：本地與 LDAP 路徑皆無 provider，
	// providerID 留 0 表「不受任何 provider 停用影響」。世代現查（buildAuthContext）
	authMethod := crypto.AuthMethodLocalPassword
	if authSource == model.AuthSourceLDAP {
		authMethod = crypto.AuthMethodLDAP
	}
	authCtx := s.buildAuthContext(user, authMethod, 0)

	// 登入時政策合規偵測：明文僅此刻可得，
	// 於 MFA 分流前偵測並持久化旗標；gate 判定統一留在 finishLogin（MFA 之後，
	// 防竊得弱密碼者持改密 token 繞過 MFA）。旗標已為 true 者毋須偵測（gate 必
	// 命中且依優先序取 must_change 原因）；LDAP 密碼由目錄管理不評估
	var violation *policy.PasswordPolicyViolation
	persistFailed := false
	if !user.IsLDAP && !user.MustChangePassword {
		if errors.As(policy.CheckCompliance(s.policies, req.Password), &violation) {
			persistFailed = s.persistMustChange(user) != nil
		}
	}

	// MFA 兩階段的 gate 依賴持久化旗標（第二階段重載使用者、明文不可得），
	// 偵測命中但寫入失敗時 fail-close 拒絕進入第二階段——否則暫時性 DB 故障
	// 會讓違規判定遺失、不合規者過完 MFA 取得正式會話。
	// 純密碼路徑不受此限：in-memory 旗標在本請求內即完成 gate
	if persistFailed && (user.TOTPEnabled || s.mfaEnrollmentRequired(user)) {
		return nil, fmt.Errorf("登入時政策偵測狀態寫入失敗，拒絕進入 MFA 階段（user=%d）", user.ID)
	}

	// MFA 用戶：密碼/目錄驗證正確仍不發正式 token，改發短效 pending token 進入第二階段。
	// 失敗計數歸零留給第二階段全過後（否則被竊密碼者可反覆過一階段重置 TOTP 失敗計數）
	if user.TOTPEnabled {
		pendingToken, err := s.jwtManager.GenerateScopedToken(
			user.ID, user.Username, user.EmailString(), primaryRoleOf(user),
			crypto.ScopeMFAPending, mfaPendingTokenTTL, authCtx,
		)
		if err != nil {
			return nil, err
		}
		return &LoginResponse{
			MFARequired:                true,
			PendingToken:               pendingToken,
			PendingUserID:              user.ID,
			PendingUsername:            user.Username,
			AuthSource:                 authSource,
			PolicyNoncompliantCategory: violationCategory(violation),
		}, nil
	}

	// 受強制但未註冊 TOTP：密碼驗證通過，改發 enrollment token 走綁定流程，
	// 綁定完成前不得取得正式會話。同樣不歸零計數（留給綁定完成後 finishLogin）
	if s.mfaEnrollmentRequired(user) {
		enrollmentToken, err := s.jwtManager.GenerateScopedToken(
			user.ID, user.Username, user.EmailString(), primaryRoleOf(user),
			crypto.ScopeMFAEnrollment, mfaEnrollmentTokenTTL, authCtx,
		)
		if err != nil {
			return nil, err
		}
		return &LoginResponse{
			MFAEnrollmentRequired:      true,
			EnrollmentToken:            enrollmentToken,
			PendingUserID:              user.ID,
			PendingUsername:            user.Username,
			AuthSource:                 authSource,
			PolicyNoncompliantCategory: violationCategory(violation),
		}, nil
	}

	resp, err := s.finishLogin(user, violation, authCtx)
	if err != nil {
		return nil, err
	}
	resp.AuthSource = authSource
	resp.PolicyNoncompliantCategory = violationCategory(violation)
	return resp, nil
}

// violationCategory 違規類別（apierror 碼字串，無密碼材料），供審計事件標註
func violationCategory(v *policy.PasswordPolicyViolation) string {
	if v == nil {
		return ""
	}
	return string(v.Code)
}

// persistMustChange 合規偵測命中時持久化旗標（僅 false→true，冪等）並回報結果。
// in-memory 旗標一律設定（純密碼路徑的本次 gate 不依賴寫入成功，下次登入重判自癒）；
// 呼叫端對「gate 依賴持久化」的 MFA 路徑須檢查錯誤 fail-close
func (s *AuthService) persistMustChange(user *model.User) error {
	err := database.DB.Model(&model.User{}).
		Where("id = ? AND must_change_password = ?", user.ID, false).
		Update("must_change_password", true).Error
	if err != nil {
		log.Printf("[WARN] persist must_change_password failed: user=%d err=%v", user.ID, err)
	}
	user.MustChangePassword = true
	return err
}

// passwordExpired 密碼有效期判定：政策 0=關閉不評估；
// NULL 時間戳視為已過期（fail-secure：欄位引入前的 legacy 列不得恰好豁免，
// 改密後時間戳寫入即永久自癒）
func (s *AuthService) passwordExpired(user *model.User) bool {
	if s.policies == nil {
		return false
	}
	days := s.policies.GetInt(policy.PolicyPasswordMaxAgeDays)
	if days <= 0 {
		return false
	}
	if user.PasswordChangedAt == nil {
		return true
	}
	return time.Since(*user.PasswordChangedAt) > time.Duration(days)*24*time.Hour
}

// verifyCredentials 認證前段：鎖定 gate + 密碼/LDAP 驗證 + 失敗計數。
// 回傳已驗證的用戶與認證來源
func (s *AuthService) verifyCredentials(req *LoginRequest) (*model.User, string, error) {
	var user model.User
	result := database.DB.Preload("Roles").Where("username = ?", req.Username).First(&user)

	notFound := errors.Is(result.Error, gorm.ErrRecordNotFound)
	if result.Error != nil && !notFound {
		return nil, "", result.Error
	}

	// 鎖定 gate 先於密碼驗證（判定順序）；查無帳號者無計數對象、直接走驗證失敗路徑
	if !notFound {
		if err := s.gateLockout(&user); err != nil {
			return nil, "", err
		}
	}

	var authSource string
	switch {
	case !notFound && !user.IsLDAP && user.IsExternal():
		// 外部但非目錄供應（OIDC 帳號）→ 顯式拒絕本地密碼路徑。
		//
		// 此分支不可省略、也不可靠「把原本的 !user.IsLDAP 條件改成 !user.IsExternal()」
		// 達成：那樣寫會讓 OIDC 帳號落入下方的 else（目錄路徑），而 authenticateLDAP
		// 對已存在帳號直接 resolved = existing——於是任何能以同名在目錄完成 bind 的人
		//（含目錄側同名帳號、目錄管理員重設密碼）即可登入該 OIDC 帳號，且因
		// authMethod=ldap 而不套密碼 gate。目標部署正是「地端 LDAP＋多路 OIDC 並存」。
		//
		// 失敗計數與回應形狀：**不計入 recordFailedAttempt**——該帳號本
		// 就無本地密碼可驗，計數只會讓任何未認證者用本地表單把 SSO 帳號鎖死（鎖定後
		// 連正常的 OIDC 登入都會被 finishLogin 的複查擋掉）。對外回應沿用一般憑證錯誤，
		// 專屬錯誤碼只用於已認證的管理操作，否則即成「此帳號是 OIDC 帳號」的枚舉 oracle。
		s.auditExternalLocalLoginAttempt(&user)
		return nil, "", ErrInvalidCredentials

	case !notFound && !user.IsLDAP:
		// 本地路徑。
		//
		// **停用判定必須在密碼驗證之後**：
		// 放在之前等於對未認證者提供帳號存在性預言機——送任意密碼，存在但停用的
		// 帳號回 403 user_inactive、不存在的帳號回 401 invalid_credentials，兩者可辨。
		// 同函式的 OIDC 分支早已為此刻意收斂回應（見上方 case 的註解），本分支補齊。
		//
		// 密碼正確後才回 ErrUserInactive：此時對方已證明持有該帳號憑證，告知停用
		// 事實不構成洩漏，且正當使用者需要據此知道該找管理員而非反覆重試。
		if err := crypto.DefaultPasswordVerifier().Verify(user.Password, []byte(req.Password)); err != nil {
			return nil, "", s.recordFailedAttempt(user.ID)
		}
		// 漸進遷移：登入成功是**唯一**同時握有
		// 明文與該帳號雜湊的時機，故重雜湊只能掛在這裡。
		//
		// **射程嚴格限於本地路徑的 `users.password`**：本 case 已排除 LDAP／外部帳號，
		// 且不觸碰 `password_histories`（歷史列不可重雜湊，見 password_policy.go）。
		//
		// 失敗不阻斷登入：這是機會性升級，不是認證的一部分。寫不進去就下次再說，
		// 讓一個 DB 暫時性錯誤把使用者擋在門外是不對的代價。
		s.rehashPasswordIfNeeded(&user, []byte(req.Password))
		if !user.Active {
			return nil, "", ErrUserInactive
		}

	default:
		// LDAP 路徑：is_ldap 用戶或查無帳號。未接目錄時維持原「查無 -> 憑證錯誤」語義
		if s.ldapResolver == nil {
			return nil, "", ErrInvalidCredentials
		}
		// **每次登入單次解析**：本次的傳輸閘判定
		// 與實際撥號共用這一份結果，設定並發變更不產生「閘檢查新值、撥號舊值」
		// 的窗口
		resolution := s.ldapResolver()
		switch resolution.State {
		case LDAPLoginUnavailable:
			// 未設定或已停用：與 LDAP 未啟用同語義（本地帳號不受影響）
			return nil, "", ErrInvalidCredentials
		case LDAPLoginFailed:
			// fail-close：DB 錯誤或密文無法解密。對外收斂為憑證錯誤（不洩漏內部
			// 狀態），對內留可辨識的 log 與審計——**不得偽裝成「未啟用」**。
			// 不計入失敗次數：這不是使用者輸錯密碼，計數只會讓金鑰事故連帶把
			// 全體目錄使用者鎖死
			log.Printf("[AuthService] LDAP 設定解析失敗，本次登入 fail-close 拒絕 (username=%s): %v",
				req.Username, resolution.Err)
			s.auditLDAPResolveFailure(&user, req.Username, notFound)
			return nil, "", ErrInvalidCredentials
		}
		ldapUser, err := s.authenticateLDAP(req, &user, notFound, resolution)
		if err != nil {
			// LDAP 帳戶納入應用層計數（兩層並行）；影子用戶尚未供應（查無）時無計數對象
			if !notFound && errors.Is(err, ErrInvalidCredentials) {
				return nil, "", s.recordFailedAttempt(user.ID)
			}
			return nil, "", err
		}
		user = *ldapUser
		authSource = model.AuthSourceLDAP
	}

	return &user, authSource, nil
}

// auditExternalLocalLoginAttempt 外部身分帳號被嘗試以本地密碼登入時落審計。
// 對外回應與一般憑證錯誤無異，偵測訊號只走審計——
// 此類嘗試多為攻擊探測或使用者誤用，兩者都值得管理員看見。
//
// **聚合而非逐筆**：本分支未認證可達、不計入鎖定計數、
// 且在密碼比對之前就返回，逐筆落審計等於把偵測訊號變成無界寫入載體。
// 每個（使用者, 分鐘窗）最多兩筆：窗首即時筆＋窗尾彙總筆。
// 詳見 external_login_attempt_audit.go
func (s *AuthService) auditExternalLocalLoginAttempt(user *model.User) {
	emits := s.externalLoginAttempts().record(user.ID, user.Username, user.ProvisioningOrigin)
	writeExternalLoginAttemptAudits(emits)
}

// mfaEnrollmentRequired 判定用戶是否受 MFA 強制且尚未註冊：
// 政策 off→從不；admin_only→僅 admin 角色；all→所有人。已註冊 TOTP 者不需 enrollment
func (s *AuthService) mfaEnrollmentRequired(user *model.User) bool {
	if user.TOTPEnabled || s.policies == nil {
		return false
	}
	switch s.policies.Get(policy.PolicyMFARequired) {
	case policy.MFARequiredAll:
		return true
	case policy.MFARequiredAdminOnly:
		return primaryRoleOf(user) == "admin"
	default: // off 或未知值 → 不強制（未知值一律最寬鬆，避免鎖死登入）
		return false
	}
}

// gateLockout 鎖定 gate：鎖定中拒絕；locked_until 到期放行時計數一併歸零（防死循環）
func (s *AuthService) gateLockout(user *model.User) error {
	if user.LockedUntil == nil {
		return nil
	}
	if time.Now().Before(*user.LockedUntil) {
		return ErrAccountLocked
	}

	if err := database.DB.Model(&model.User{}).Where("id = ?", user.ID).Updates(map[string]interface{}{
		"failed_login_attempts": 0,
		"locked_until":          nil,
	}).Error; err != nil {
		return err
	}
	user.FailedLoginAttempts = 0
	user.LockedUntil = nil
	return nil
}

// rehashPasswordIfNeeded 登入成功後的機會性密碼雜湊升級。
//
// **為什麼漸進遷移是唯一可行的做法**：把一筆舊演算法的雜湊轉成新演算法需要**明文密碼**，
// 而系統沒有明文——那正是雜湊存在的意義。任何「一鍵把所有帳號遷移過去」的功能
// 都做不出來，除非要求全體重設密碼。故只能在使用者自己送上明文的那一刻（登入、改密）順手升級。
//
// **射程限縮**：只寫 `users.password`（GORM 另會帶上 `updated_at`，
// 那是 model 的既有行為、非本路徑刻意寫入），不觸碰 `password_histories`
// ——歷史列 write-once 且不可重雜湊（見 `password_policy.go` 的 isPasswordReused）。
//
// **失敗不阻斷登入**：這是機會性升級而非認證的一部分。DB 暫時性錯誤不該把使用者擋在門外，
// 下次登入會再試一次。
func (s *AuthService) rehashPasswordIfNeeded(user *model.User, plaintext []byte) {
	if user == nil || user.IsExternal() {
		return
	}
	verifier := crypto.DefaultPasswordVerifier()
	if !verifier.NeedsRehash(user.Password) {
		return
	}
	updated, err := crypto.DefaultPasswordHasher().Hash(plaintext)
	if err != nil {
		log.Printf("[Auth] 密碼雜湊升級失敗（不影響本次登入）: userID=%d err=%v", user.ID, err)
		return
	}
	// 條件 UPDATE：只在 password 仍是我們剛驗過的那一份時才覆寫。
	// 並發的改密若先落地，這裡就不該把它蓋回去——那會讓剛改的新密碼失效。
	res := database.DB.Model(&model.User{}).
		Where("id = ? AND password = ?", user.ID, user.Password).
		Update("password", updated)
	if res.Error != nil {
		log.Printf("[Auth] 密碼雜湊升級寫入失敗（不影響本次登入）: userID=%d err=%v", user.ID, res.Error)
		return
	}
	if res.RowsAffected == 0 {
		// 並發改密先落地，本次升級作廢——正確結果，不是錯誤
		return
	}
	user.Password = updated
	log.Printf("[Auth] 密碼雜湊已升級至現行演算法參數: userID=%d", user.ID)
}

// recordFailedAttempt 失敗計數 +1 並在達門檻時設鎖——**單一原子 UPDATE**（LOCK-2）。
// 回傳值即呼叫端應回的錯誤：鎖定回 ErrAccountLocked（明示訊息），否則 ErrInvalidCredentials。
// 若 policies 未注入（僅測試建構路徑），鎖定不生效並記可見警告（LOCK-3，不再靜默）
func (s *AuthService) recordFailedAttempt(userID uint) error {
	if s.policies == nil {
		warnLockoutDisabled()
		return ErrInvalidCredentials
	}
	maxAttempts := s.policies.GetInt(policy.PolicyLockoutMaxAttempts)
	// 0=停用鎖定（政策 sentinel，dev/E2E 需要此開關；政策頁顯示不符 PCI 建議）
	if maxAttempts == 0 {
		return ErrInvalidCredentials
	}

	durationMin := s.policies.GetInt(policy.PolicyLockoutDurationMinutes)
	lockedUntil := time.Now().Add(time.Duration(durationMin) * time.Minute)

	// 遞增與「遞增後達門檻即設鎖」在同一 UPDATE 完成，消除 gate（讀當下 row）與
	// act（遞增後才判門檻）非原子造成的並發突發繞過。CASE 中的 failed_login_attempts
	// 為 UPDATE 前的舊值，+1 即本次遞增後的值，與計數欄賦值一致
	if err := database.DB.Model(&model.User{}).Where("id = ?", userID).
		UpdateColumns(map[string]interface{}{
			"failed_login_attempts": gorm.Expr("failed_login_attempts + 1"),
			"locked_until": gorm.Expr(
				"CASE WHEN failed_login_attempts + 1 >= ? THEN ? ELSE locked_until END",
				maxAttempts, lockedUntil),
		}).Error; err != nil {
		return err
	}

	var user model.User
	if err := database.DB.Select("failed_login_attempts", "locked_until").First(&user, userID).Error; err != nil {
		return err
	}
	if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
		log.Printf("[AuthService] 帳號因連續失敗被鎖定 (userID=%d, attempts=%d, until=%s)",
			userID, user.FailedLoginAttempts, user.LockedUntil.Format(time.RFC3339))
		// 鎖定即撤銷全部 refresh（spec 會話撤銷）：阻新登入也阻既有 Web 會話續命；
		// 協議會話不砍（避免鎖定成為遠端斷線武器），殘餘 access ≤15 分
		if _, err := RevokeAllRefreshTokens(database.DB, userID, model.RefreshRevokeLocked); err != nil {
			log.Printf("[AuthService] 鎖定撤銷 refresh 憑證失敗 (userID=%d): %v", userID, err)
		}
		return ErrAccountLocked
	}
	return ErrInvalidCredentials
}

// lockoutWarnOnce 讓「政策服務未注入→鎖定失效」的警告每進程只印一次（LOCK-3）
var lockoutWarnOnce sync.Once

func warnLockoutDisabled() {
	lockoutWarnOnce.Do(func() {
		log.Println("[AuthService] 安全政策服務未注入，帳號鎖定（PCI 8.3.4）不生效——" +
			"生產環境須呼叫 SetSecurityPolicies")
	})
}

// finishLogin 認證後段（密碼與 MFA 全過後）：計數歸零、更新 last_login_at，
// 再走強制改密 gate 或核發正式 token。Login 與 MFA 第二階段共用
func (s *AuthService) finishLogin(user *model.User, violation *policy.PasswordPolicyViolation, authCtx crypto.AuthContext) (*LoginResponse, error) {
	// 發 token 前複查鎖定（LOCK-2）：並發突發中，本請求密碼 gate 通過後、發 token 前，
	// 帳號可能已被其他失敗請求鎖定——此刻夾帶正確密碼者不得放行
	var fresh model.User
	if err := database.DB.Select("locked_until").First(&fresh, user.ID).Error; err != nil {
		return nil, err
	}
	if fresh.LockedUntil != nil && time.Now().Before(*fresh.LockedUntil) {
		return nil, ErrAccountLocked
	}

	if err := database.DB.Model(&model.User{}).Where("id = ?", user.ID).Updates(map[string]interface{}{
		"failed_login_attempts": 0,
		"locked_until":          nil,
		"last_login_at":         time.Now(),
	}).Error; err != nil {
		return nil, err
	}

	// 登入時密碼 gate（排在 MFA 之後防繞過；LDAP 用戶密碼由目錄管理，三觸發源
	// 皆不適用）。優先序＝旗標 → 政策合規 → 有效期；
	// violation 僅在本次登入偵測（原旗標為 false）時非 nil，故排前不違反旗標優先——
	// 它攜帶具體違規碼，比壓成 must_change 更有指引價值
	// 密碼類 gate 依**本次登入方式**判定，非帳號屬性——
	// 混合帳號（同時有本地密碼與外部身分）才能兩條路徑各依其性質判定。
	// 雙條件 fail-secure：缺值視為 local_password（升級期舊 token），此時仍需
	// !IsExternal() 才套用，故任一訊號缺失都不會使 gate 靜默失效。
	if authCtx.EffectiveMethod() == crypto.AuthMethodLocalPassword && !user.IsExternal() {
		reason := ""
		var reasonCode apierror.ErrCode
		var reasonParams map[string]any
		switch {
		case violation != nil:
			reason = PasswordChangeReasonNoncompliant
			reasonCode = violation.Code
			reasonParams = violation.Params
		case user.MustChangePassword:
			reason = PasswordChangeReasonMustChange
		case s.passwordExpired(user):
			reason = PasswordChangeReasonExpired
		}
		if reason != "" {
			changeToken, err := s.jwtManager.GenerateScopedToken(
				user.ID, user.Username, user.EmailString(), primaryRoleOf(user),
				crypto.ScopePasswordChange, passwordChangeTokenTTL, authCtx,
			)
			if err != nil {
				return nil, err
			}
			return &LoginResponse{
				PasswordChangeRequired: true,
				ChangeToken:            changeToken,
				PolicyHint:             s.passwordPolicyHint(),
				PasswordChangeReason:   reason,
				ReasonCode:             reasonCode,
				ReasonParams:           reasonParams,
				PendingUserID:          user.ID,
				PendingUsername:        user.Username,
			}, nil
		}
	}

	return s.buildLoginResponse(user, authCtx)
}

// authenticateLDAP 對目錄驗證帳密；首次成功登入時供應影子用戶。
// 所有 LDAP 失敗對外收斂為 ErrInvalidCredentials：不洩漏目錄拓撲與連線狀態
// （例外：傳輸政策 strict 拒絕回明確原因——spec 要求，否則使用者誤判密碼錯誤）
func (s *AuthService) authenticateLDAP(
	req *LoginRequest, existing *model.User, notFound bool, resolution LDAPLoginResolution,
) (*model.User, error) {
	// LDAP 登入傳輸閘：檢查撥號當下最終參數。
	// strict＝通道不安全即拒絕，撥號前擋下（密碼不出門）；本地帳號路徑不經此處。
	//
	// **風險項取自本次解析結果**：與下方
	// resolution.Auth 撥號用的是同一份 snapshot，型別上不可能是兩次讀取
	risks := resolution.Risks
	if len(risks) > 0 && s.transmission != nil &&
		s.transmission.ChannelLevel(policy.TransportChannelLDAP) == policy.TransportLevelStrict {
		s.auditLDAPTransport(0, req.Username, risks, model.StatusDenied, "ldap_strict_reject")
		return nil, ErrLDAPTransportRejected
	}

	info, err := resolution.Auth.Authenticate(req.Username, req.Password)
	if err != nil {
		// 詳細原因只進伺服器日誌，回應端維持與本地失敗相同形狀
		log.Printf("[AuthService] LDAP 認證失敗 (username=%s): %v", req.Username, err)
		return nil, ErrInvalidCredentials
	}

	// 已停用的 is_ldap 用戶於**目錄認證通過後**才拒絕（
	// 與本地路徑的檢查順序一致）。原先在打目錄前就回 ErrUserInactive，省下一次目錄
	// 請求，代價是未認證者送任意密碼即可分辨「此帳號存在但已停用」與「此帳號不存在」
	// ——同一個枚舉 oracle 的 LDAP 側。一次目錄請求換掉存在性洩漏，值得
	if !notFound && !existing.Active {
		return nil, ErrUserInactive
	}

	resolved := existing
	if notFound {
		if resolved, err = s.provisionShadowUser(info); err != nil {
			return nil, err
		}
	}

	// warn＝放行但每次成功登入落傳輸偏離審計（留痕對象是稽核與管理員，
	// 不彈同意對話框——登入者無權修復部署層設定。失敗嘗試由既有登入失敗
	// 審計涵蓋，不另落偏離事件以免探測流量灌爆審計）
	if len(risks) > 0 && s.transmission != nil &&
		s.transmission.ChannelLevel(policy.TransportChannelLDAP) == policy.TransportLevelWarn {
		s.auditLDAPTransport(resolved.ID, resolved.Username, risks, model.StatusSuccess, "ldap_transport_deviation")
	}
	return resolved, nil
}

// auditLDAPResolveFailure 設定解析失敗的 fail-close 審計。
//
// spec 要求「內部 log 與審計事件可辨識為解析失敗而非帳密錯誤」：金鑰事故下
// 全體目錄使用者同時登不進來，若審計只留一片「密碼錯誤」，管理員會去查
// 目錄與使用者，而真因在金鑰。**不記錯誤細節**——對外回應已收斂，審計是
// admin 可見面，只留可辨識的事件碼與帳號
func (s *AuthService) auditLDAPResolveFailure(existing *model.User, username string, notFound bool) {
	var userID uint
	if !notFound {
		userID = existing.ID
	}
	entry := &model.AuditLog{
		Action:   model.ActionLogin,
		Resource: model.ResourceAuth,
		Status:   model.StatusFailure,
		UserID:   userID,
		Username: username,
		Details:  `{"event":"ldap_resolve_failed"}`,
	}
	if err := database.DB.Create(entry).Error; err != nil {
		log.Printf("[AuthService] LDAP 設定解析失敗審計寫入失敗: %v", err)
	}
}

// auditLDAPTransport LDAP 傳輸閘審計事件（偏離留痕/嚴格拒絕）
func (s *AuthService) auditLDAPTransport(userID uint, username string, risks []policy.RiskItem, status model.AuditStatus, event string) {
	details, err := json.Marshal(map[string]interface{}{
		"event":   event,
		"channel": policy.TransportChannelLDAP,
		"risks":   risks,
	})
	if err != nil {
		details = []byte(fmt.Sprintf(`{"event":%q,"channel":"ldap"}`, event))
	}
	entry := &model.AuditLog{
		Action:   model.ActionLogin,
		Resource: model.ResourceTransmission,
		Status:   status,
		UserID:   userID,
		Username: username,
		Details:  string(details),
	}
	if err := database.DB.Create(entry).Error; err != nil {
		log.Printf("[AuthService] LDAP 傳輸閘審計寫入失敗: %v", err)
	}
}

// provisionShadowUser 首次 LDAP 登入自動建立影子用戶：
// is_ldap=true、預設 user 角色；password 填隨機 bcrypt 是因為欄位 NOT NULL，
// 且即使誤走本地路徑也無人知道此密碼，杜絕影子帳號被本地密碼登入
func (s *AuthService) provisionShadowUser(info *LDAPUserInfo) (*model.User, error) {
	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		return nil, fmt.Errorf("產生影子用戶隨機密碼失敗: %w", err)
	}
	hashed, err := crypto.DefaultPasswordHasher().Hash([]byte(hex.EncodeToString(randomBytes)))
	if err != nil {
		return nil, fmt.Errorf("影子用戶密碼雜湊失敗: %w", err)
	}

	// email 未知/衝突以 NULL 表達：trim+小寫正規化後
	// 以大小寫不敏感比對（與 admin Update 的 normalizeEmail 一致），衝突時存 NULL
	//（非空字串），唯一性僅約束非 NULL，故多個無 email 影子帳號可並存；
	// 登入不可因附屬欄位失敗（既有風險項）
	emailPtr := normalizeEmail(info.Email)
	if emailPtr != nil {
		var emailCount int64
		if err := database.DB.Model(&model.User{}).Where("LOWER(email) = ?", *emailPtr).Count(&emailCount).Error; err != nil {
			return nil, fmt.Errorf("檢查影子用戶 email 衝突失敗: %w", err)
		}
		if emailCount > 0 {
			emailPtr = nil
		}
	}

	user := &model.User{
		Username: info.Username,
		Password: string(hashed),
		Email:    emailPtr,
		FullName: info.FullName,
		Active:   true,
		IsLDAP:   true,
		// 身分欄位顯式賦值：目錄供應帳號的憑證在目錄端，
		// external_credential=true 使其本地密碼路徑全數關閉（自助改密、admin 重設、
		// 本地登入分派）。此欄語義刻意是「外部化＝true」——若採「有本地密碼＝true」
		// 並配 default:true，GORM 會把顯式寫入的 false 覆寫成 true（已實測），
		// 使全部影子帳號被判為本地帳號、LDAP 登入改走 bcrypt 而全滅
		ProvisioningOrigin: model.AuthSourceLDAP,
		ExternalCredential: true,
	}

	// 建用戶與綁角色必須同生共死：半成品帳號（無角色）會造成權限判斷異常
	tx := database.DB.Begin()
	if tx.Error != nil {
		return nil, fmt.Errorf("開始影子用戶供應事務失敗: %w", tx.Error)
	}

	if err := tx.Create(user).Error; err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("建立影子用戶失敗: %w", err)
	}

	var role model.Role
	if err := tx.Where("name = ?", model.RoleUser).First(&role).Error; err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("查詢預設角色失敗: %w", err)
	}

	// 顯式寫入關聯表而非 GORM Association：影子供應固定單一角色，顯式 SQL 行為最可預期
	if err := tx.Exec("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)", user.ID, role.ID).Error; err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("綁定預設角色失敗: %w", err)
	}

	if err := tx.Commit().Error; err != nil {
		return nil, fmt.Errorf("提交影子用戶供應事務失敗: %w", err)
	}

	user.Roles = []model.Role{role}
	log.Printf("[AuthService] LDAP 影子用戶已供應 (username=%s, id=%d)", user.Username, user.ID)
	return user, nil
}

// primaryRoleOf 取得有效角色，優先序固定 admin > auditor > user：
// 不得依 Roles[0] 綁定順序取值——[user,auditor] 帳號若取到 user，後端 403 而前端依
// 完整 roles 陣列放行，會造成前後端判定不一致的破版。無已知角色時退回第一個角色名，
// 無角色預設 user
func primaryRoleOf(user *model.User) string {
	if len(user.Roles) == 0 {
		return "user"
	}
	priority := map[string]int{"admin": 3, "auditor": 2, "user": 1}
	best := ""
	bestRank := 0
	for _, role := range user.Roles {
		if rank := priority[role.Name]; rank > bestRank {
			best = role.Name
			bestRank = rank
		}
	}
	if best == "" {
		// 全為未知角色：沿舊行為取第一個（未知角色在權限層一律拒，見 hasPermission）
		return user.Roles[0].Name
	}
	return best
}

// passwordPolicyHint 組裝改密表單的政策提示文案（依現行政策動態產生）
func (s *AuthService) passwordPolicyHint() string {
	if s.policies == nil {
		return ""
	}
	hint := fmt.Sprintf("新密碼至少 %d 字元", s.policies.GetInt(policy.PolicyPasswordMinLength))
	if s.policies.GetBool(policy.PolicyPasswordRequireAlnum) {
		hint += "，須同時包含字母與數字"
	}
	if n := s.policies.GetInt(policy.PolicyPasswordHistoryCount); n > 0 {
		hint += fmt.Sprintf("，不可與最近 %d 次使用過的密碼相同", n)
	}
	return hint
}

// buildAuthContext 組裝簽發當下的認證脈絡。
//
// method 與 providerID 由呼叫端指定——它們描述「本次是怎麼認證的」，不隨時間變，
// 換發路徑可自來源憑證繼承。但兩個世代**一律現查**，絕不可繼承：改密會推進
// credential_epoch，若換發的 token 沿用舊世代，該 token 下次請求即被比對拒絕，
// 強制改密者將永久卡在改密迴圈（改密成功卻拿不到可用會話）。
//
// user 須為剛自 DB 讀出的實體（呼叫端保證），其 CredentialEpoch 即現行值。
func (s *AuthService) buildAuthContext(user *model.User, method string, providerID uint) crypto.AuthContext {
	ctx := crypto.AuthContext{
		AuthMethod: method,
		ProviderID: providerID,
		CredEpoch:  user.CredentialEpoch,
	}
	if providerID != 0 {
		// provider 世代同樣現查；查無（provider 已軟刪）時留 0，
		// 由驗證點的 fail-close 判定拒絕——「宣稱某 provider 但它已不存在」
		// 與「沒有 provider」是兩件事，不可混為一談
		var p model.OIDCProvider
		if err := database.DB.Select("auth_epoch").First(&p, providerID).Error; err == nil {
			ctx.AuthEpoch = p.AuthEpoch
		}
	}
	return ctx
}

// buildLoginResponse 核發正式 session token 並組裝登入回應。
// 抽出共用是因為一階段登入與 MFA 第二階段交換必須回完全相同的形狀
func (s *AuthService) buildLoginResponse(user *model.User, authCtx crypto.AuthContext) (*LoginResponse, error) {
	roles := make([]string, len(user.Roles))
	for i, role := range user.Roles {
		roles[i] = role.Name
	}

	// 生成 JWT token
	token, err := s.jwtManager.GenerateToken(user.ID, user.Username, user.EmailString(), primaryRoleOf(user), authCtx)
	if err != nil {
		return nil, err
	}

	// refresh 憑證與 access 同時發放：發放失敗即整體失敗——
	// 沒有 refresh 的會話 15 分後必斷，fail-open 等於會話治理不存在
	refreshToken, refreshExpiresAt, err := s.issueRefreshToken(user.ID, time.Now(), authCtx)
	if err != nil {
		return nil, err
	}

	// 有效審核資格：登入回應也帶 is_approver，
	// 否則群組審核方（roles 不含 approver）的 localStorage.user 缺此欄，前端路由守衛
	// 只認 cached 角色 → 看得到審核中心卻被踢回 dashboard。查失敗不阻斷登入（顯示性欄位）
	isApprover, err := authz.NewAssetAuthorizationService(database.DB).
		IsEffectiveApprover(user.ID)
	if err != nil {
		isApprover = false
	}

	userInfo := &UserInfo{
		ID:                 user.ID,
		Username:           user.Username,
		Email:              user.EmailString(),
		FullName:           user.FullName,
		LocalDisplayName:   user.LocalDisplayName,
		DisplayName:        user.DisplayName(),
		Active:             user.Active,
		Roles:              roles,
		TOTPEnabled:        user.TOTPEnabled,
		IsLDAP:             user.IsLDAP,
		ExternalCredential: user.ExternalCredential,
		ProvisioningOrigin: user.ProvisioningOrigin,
		IsApprover:         isApprover,
	}

	return &LoginResponse{
		Token:            token,
		User:             userInfo,
		RefreshToken:     refreshToken,
		RefreshExpiresAt: refreshExpiresAt,
	}, nil
}

// ValidateToken 驗證 token
func (s *AuthService) ValidateToken(tokenString string) (*crypto.Claims, error) {
	return s.jwtManager.ValidateToken(tokenString)
}

// ValidateConnectionToken WS 連線端點統一認證（認證邊界一致性）：
//  1. token 簽章/過期驗證；
//  2. deny-by-default：任何 scoped token（MFA pending/enrollment/改密）不得建立連線——
//     與 middleware 同一判定，堵住既有 MFA 繞過；
//  3. 重載用戶拒 inactive 與鎖定中——剛被停用/鎖定者不得用未過期 token 開新特權 shell
func (s *AuthService) ValidateConnectionToken(tokenString string) (*crypto.Claims, error) {
	claims, err := s.jwtManager.ValidateToken(tokenString)
	if err != nil {
		return nil, err
	}
	if claims.Scope != "" {
		return nil, ErrConnectionNotAuthorized
	}
	if err := s.CheckUserConnectable(claims.UserID); err != nil {
		return nil, err
	}
	// 憑證世代閘——**這條旁路絕不可漏**：
	// /connect、/ssh、/sessions/:id/monitor 三個路由不掛 AuthMiddleware（各自
	// 「手動處理認證，支援 WebSocket query token」），故中介層的世代比對救不到它們。
	// 漏此檢查則 provider 停用後，攻擊者持停用前簽發的 access token 仍可開啟會話監看
	// 而持續讀取他人終端內容。本專案已為同一條旁路修過一次繞過（見本函式 (2) 的
	// scoped token deny-by-default），同型缺口不得再犯。
	//
	// 判定不放進 CheckUserConnectable：該函式不收 claims，且被兌換路徑共用——
	// 那些路徑全程無 JWT，硬塞只能靠反查身分表（design 明令禁止，會誤殺混合帳號）。
	if err := s.VerifyCredentialGenerationByUserID(claims.AuthContext, claims.UserID); err != nil {
		return nil, ErrConnectionNotAuthorized
	}
	return claims, nil
}

var _ gatewayapi.SessionVerifier = (*AuthService)(nil)

// VerifySession 驗 web session JWT 並套用認證世代閘，回傳已驗證身分快照。
// **`gatewayapi.SessionVerifier` 的實作**。
//
// 判定本體即 ValidateConnectionToken——本方法只做 claims → Principal 的欄位對映，
// **不新增、不放寬任何判定**：scope deny-by-default、重載用戶拒停用/鎖定、
// 憑證世代閘三者逐字沿用。分成兩個方法而非改 ValidateConnectionToken 的回傳型別，
// 是因為後者仍被 identity 內部與其既有測試以 *crypto.Claims 消費。
//
// ctx 未被使用（下游以 database.DB 直查，不吃 ctx）：刻意保留參數而不改契約，
// 同 gatewayapi.AsyncSink.Submit 的既定紀律。
//
// **Principal.Role 是登入當下的角色快照，SHALL NOT 作為授權判定依據**：
// 連線閘序的角色一律由 CurrentConnectRole 現查。
func (s *AuthService) VerifySession(_ context.Context, rawJWT string) (gatewayapi.Principal, error) {
	claims, err := s.ValidateConnectionToken(rawJWT)
	if err != nil {
		return gatewayapi.Principal{}, err
	}
	return gatewayapi.Principal{
		UserID:     claims.UserID,
		Username:   claims.Username,
		Role:       claims.Role,
		Scope:      claims.Scope,
		AuthMethod: claims.AuthMethod,
		ProviderID: claims.ProviderID,
		AuthEpoch:  claims.AuthEpoch,
		CredEpoch:  claims.CredEpoch,
	}, nil
}

// CheckUserConnectable 重載用戶並拒 inactive 與鎖定中（即時撤權）。
// 抽出共用是因為連線經兩階段入口：connect-token 簽發（HandleCreateConnectToken，
// 經 ValidateConnectionToken 認證）、connect-token 消費（HandleSSH/HandleConnect）——
// 消費端 AUTH-1 原本漏了重載，停用/鎖定者仍能鑄 token 開新 shell。
// 資產連線的 query-JWT 直連模式已收口（繞過簽發閘）；
// ValidateConnectionToken 仍供監看/分享/同意等輔助 WS 端點的 query token 認證
func (s *AuthService) CheckUserConnectable(userID uint) error {
	var user model.User
	if err := database.DB.Select("active", "locked_until").First(&user, userID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrUserNotFound
		}
		return err
	}
	if !user.Active {
		return ErrUserInactive
	}
	if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
		return ErrAccountLocked
	}
	return nil
}

// CurrentConnectRole 一次查詢完成 connect 路徑的「可連線複查」與「現查有效角色」：
// 載入 active/locked_until/Roles，不可連線
// 回既有 sentinel（與 CheckUserConnectable 對齊），可連線回 primaryRoleOf 折疊後的現時
// 角色。connect token 簽發與兌換 SHALL 以此現況角色判定 admin 特權，不得憑 JWT／token
// 攜帶的角色快照——降權即時生效、撤權殘窗歸零。
// 與 CheckUserConnectable 並存：後者仍供 refresh／bridge 啟動前複查以 error 語義使用
func (s *AuthService) CurrentConnectRole(userID uint) (string, error) {
	var user model.User
	if err := database.DB.Preload("Roles").First(&user, userID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", ErrUserNotFound
		}
		return "", err
	}
	if !user.Active {
		return "", ErrUserInactive
	}
	if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
		return "", ErrAccountLocked
	}
	return primaryRoleOf(&user), nil
}

// LoginWithExternalIdentity 外部身分認證通過後的登入後段。
//
// **必須走 finishLogin**（不可自建捷徑）：該函式內含發 token 前的鎖定複查
// （並發窗）與 last_login_at 更新——後者是閒置停用判定的依據，跳過會使天天以
// SSO 登入的使用者被閒置停用排程停權。
//
// 密碼類 gate 由 finishLogin 依 authCtx.EffectiveMethod() 判定：本次為 oidc
// 故不適用，混合帳號（同時有本地密碼與外部身分）以本地密碼登入時仍照常適用。
func (s *AuthService) LoginWithExternalIdentity(user *model.User, authCtx crypto.AuthContext) (*LoginResponse, error) {
	if !user.Active {
		return nil, ErrUserInactive
	}
	if err := s.gateLockout(user); err != nil {
		return nil, err
	}

	// MFA 疊加：已註冊 TOTP 者不直接發正式會話，進入既有兩階段流程；
	// scoped token 攜帶本次認證脈絡，使 MFA 完成點能複查 provider 與世代
	if user.TOTPEnabled {
		pendingToken, err := s.jwtManager.GenerateScopedToken(
			user.ID, user.Username, user.EmailString(), primaryRoleOf(user),
			crypto.ScopeMFAPending, mfaPendingTokenTTL, authCtx,
		)
		if err != nil {
			return nil, err
		}
		return &LoginResponse{
			MFARequired: true, PendingToken: pendingToken,
			PendingUserID: user.ID, PendingUsername: user.Username,
			AuthSource: model.AuthSourceOIDC,
		}, nil
	}
	if s.mfaEnrollmentRequired(user) {
		enrollmentToken, err := s.jwtManager.GenerateScopedToken(
			user.ID, user.Username, user.EmailString(), primaryRoleOf(user),
			crypto.ScopeMFAEnrollment, mfaEnrollmentTokenTTL, authCtx,
		)
		if err != nil {
			return nil, err
		}
		return &LoginResponse{
			MFAEnrollmentRequired: true, EnrollmentToken: enrollmentToken,
			PendingUserID: user.ID, PendingUsername: user.Username,
			AuthSource: model.AuthSourceOIDC,
		}, nil
	}

	resp, err := s.finishLogin(user, nil, authCtx)
	if err != nil {
		return nil, err
	}
	resp.AuthSource = model.AuthSourceOIDC
	return resp, nil
}

// IssueSessionResponse 對已完成必要驗證的用戶直接換發正式會話（
// enrollment/改密完成後不重走登入）。呼叫端負責確認前置驗證已完成
// authCtx 的 method/provider 由呼叫端自其 scoped token 繼承（描述本次怎麼認證的），
// 但**世代於此重新現查**——改密會推進 credential_epoch，若沿用 scoped token 內的
// 舊世代，換發的 token 下次請求即被拒，強制改密者永久卡在改密迴圈。
func (s *AuthService) IssueSessionResponse(userID uint, method string, providerID uint) (*LoginResponse, error) {
	var user model.User
	if err := database.DB.Preload("Roles").First(&user, userID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	if !user.Active {
		return nil, ErrUserInactive
	}
	return s.buildLoginResponse(&user, s.buildAuthContext(&user, method, providerID))
}

// GetUserByID 根據 ID 取得使用者資訊
func (s *AuthService) GetUserByID(userID uint) (*UserInfo, error) {
	var user model.User
	result := database.DB.Preload("Roles").First(&user, userID)

	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, result.Error
	}

	roles := make([]string, len(user.Roles))
	for i, role := range user.Roles {
		roles[i] = role.Name
	}

	// 有效審核資格：查失敗不阻斷主流程（顯示性欄位，守衛另有強制）
	isApprover, err := authz.NewAssetAuthorizationService(database.DB).
		IsEffectiveApprover(user.ID)
	if err != nil {
		isApprover = false
	}

	return &UserInfo{
		ID:                 user.ID,
		Username:           user.Username,
		Email:              user.EmailString(),
		FullName:           user.FullName,
		LocalDisplayName:   user.LocalDisplayName,
		DisplayName:        user.DisplayName(),
		Active:             user.Active,
		Roles:              roles,
		TOTPEnabled:        user.TOTPEnabled,
		IsLDAP:             user.IsLDAP,
		ExternalCredential: user.ExternalCredential,
		ProvisioningOrigin: user.ProvisioningOrigin,
		IsApprover:         isApprover,
	}, nil
}

// UpdateOwnDisplayName 自助更新顯示名。
// 身分綁定：userID 由 handler 從 token claims 取得（不接受 path/body 指定他人）。
// 重查帳號 active——AuthMiddleware 只驗 token 不重查 active 的補正，拒絕已停用/刪除帳號。
// 只寫 local_display_name 一欄（其他欄位不可經此寫入）；輸入驗證：長度上限、
// 拒控制字元/換行、全空白 trim 後寫回 NULL（清除）。回傳 canonical UserInfo（含 resolve 後 display_name）
func (s *AuthService) UpdateOwnDisplayName(userID uint, raw *string) (*UserInfo, error) {
	var user model.User
	if err := database.DB.First(&user, userID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	// 停用重查：剛被停用/刪除者不得再自助改資料
	if !user.Active {
		return nil, ErrUserInactive
	}

	// 正規化 + 驗證：nil/全空白 → NULL（清除）；非空則驗長度上限與控制字元
	value, err := validateDisplayName(raw)
	if err != nil {
		return nil, err
	}

	// 只寫 local_display_name 一欄（白名單，杜絕經此端點寫其他欄位）；
	// UPDATE 帶 active=true 條件（CAS）閉合「載入後、寫入前帳號被停用/刪除」的 TOCTOU：
	// RowsAffected==0 表示該窗內帳號已停用（或軟刪，GORM scope 自帶 deleted_at IS NULL），
	// 回 ErrUserInactive。明確 Update 單欄：nil *string 寫 NULL（清除），非 nil 寫值
	res := database.DB.Model(&model.User{}).
		Where("id = ? AND active = ?", userID, true).
		Update("local_display_name", value)
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		return nil, ErrUserInactive
	}

	return s.GetUserByID(userID)
}

// validateDisplayName 校驗並正規化自助顯示名：
// nil 或 trim 後空白 → nil（清除為 NULL）；否則檢查 rune 長度上限與控制字元/換行
func validateDisplayName(raw *string) (*string, error) {
	if raw == nil {
		return nil, nil
	}
	trimmed := strings.TrimSpace(*raw)
	if trimmed == "" {
		return nil, nil
	}
	if utf8.RuneCountInString(trimmed) > maxDisplayNameLen {
		return nil, ErrInvalidDisplayName
	}
	for _, r := range trimmed {
		// 拒控制字元（含 \n \r \t 等）——防止顯示名夾帶換行/控制序列干擾 UI 或審計
		if unicode.IsControl(r) {
			return nil, ErrInvalidDisplayName
		}
	}
	return &trimmed, nil
}
