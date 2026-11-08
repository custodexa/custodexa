package identity

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/custodexa/backend/internal/branding"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
	"github.com/pquerna/otp/totp"
	"gorm.io/gorm"
)

const (
	// totpIssuer otpauth URL 的發行者名稱（顯示於驗證器 App）
	totpIssuer = branding.Name
	// mfaPendingTokenTTL pending token 短效設計：縮小重放窗口
	mfaPendingTokenTTL = 5 * time.Minute
	// mfaEnrollmentTokenTTL 強制註冊 token TTL（需裝 App＋掃 QR＋輸碼，5 分太緊）
	mfaEnrollmentTokenTTL = 15 * time.Minute
	// totpPeriod/totpSkew 與 pquerna/otp 預設一致（SHA1、6 位、30 秒、skew 1）
	totpPeriod = 30
	totpSkew   = 1
)

var (
	// ErrMFACryptoUnavailable MFA 加密服務未初始化（以 NewAuthService 建構時）
	ErrMFACryptoUnavailable = errors.New("MFA 加密服務未初始化")
	// ErrMFAInvalidCode TOTP 驗證碼錯誤
	ErrMFAInvalidCode = errors.New("MFA 驗證碼錯誤")
	// ErrMFAReplay TOTP 碼已被消耗（step ≤ 最後消耗索引，8.5.1 防重放）
	ErrMFAReplay = errors.New("MFA 驗證碼已使用過")
	// ErrMFANotEnabled 此帳號未啟用 MFA
	ErrMFANotEnabled = errors.New("此帳號未啟用 MFA")
	// ErrMFASetupRequired 尚未產生 MFA 設定
	ErrMFASetupRequired = errors.New("請先產生 MFA 設定")
	// ErrMFAPendingTokenInvalid pending token 無效、過期或 scope 不符
	ErrMFAPendingTokenInvalid = errors.New("無效或過期的 MFA 驗證 token")
	// ErrMFAAlreadyEnrolled 帳號已註冊 TOTP，不得再走強制註冊流程：
	// enrollment token 洩漏後不得用以重置/改綁已註冊帳號的第二因子
	ErrMFAAlreadyEnrolled = errors.New("此帳號已完成 MFA 註冊")
	// ErrMFACurrentCodeRequired 已啟用 MFA 的帳號重新產生密鑰時未附現行驗證碼，
	// 或讀取後狀態已被另一請求改變而不得覆寫
	ErrMFACurrentCodeRequired = errors.New("重新產生驗證器密鑰須附上現行驗證碼")
)

// matchTOTPStep 在 skew 窗內逐 step 驗證 TOTP，回傳命中的 step 索引（⌊unix/30⌋）。
// pquerna/otp 的 totp.Validate 只回 bool、不外露命中 step，故複製其內部迴圈以取回索引，
// 供防重放（8.5.1）記錄「已消耗 step」；試序與套件一致：center, +1, -1, ...
func matchTOTPStep(code, secret string, now time.Time) (uint64, bool) {
	base := uint64(now.Unix()) / totpPeriod
	candidates := []uint64{base}
	for i := uint64(1); i <= totpSkew; i++ {
		candidates = append(candidates, base+i, base-i)
	}
	for _, step := range candidates {
		ok, err := hotp.ValidateCustom(code, step, secret, hotp.ValidateOpts{
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
		})
		if err == nil && ok {
			return step, true
		}
	}
	return 0, false
}

// consumeTOTP 驗證 TOTP 碼並以 CAS 條件 UPDATE 原子推進已消耗 step（8.5.1）。
// 回傳：nil=通過且 step 已推進；ErrMFAInvalidCode=碼錯；ErrMFAReplay=step 已被消耗
// （並發或跨 skew 窗同碼重放）。涵蓋登入驗證與綁定確認兩路徑
func (s *AuthService) consumeTOTP(userID uint, secret, code string) error {
	step, ok := matchTOTPStep(code, secret, s.mfaClock())
	if !ok {
		return ErrMFAInvalidCode
	}
	// 僅當 step 嚴格大於已消耗值（或從未消耗）才推進；RowsAffected==0 即重放
	res := database.DB.Model(&model.User{}).
		Where("id = ? AND (totp_last_step IS NULL OR totp_last_step < ?)", userID, step).
		Update("totp_last_step", step)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrMFAReplay
	}
	return nil
}

// mfaClock TOTP 驗證使用的時間來源；未注入時取系統時間。
func (s *AuthService) mfaClock() time.Time {
	if s.mfaNow != nil {
		return s.mfaNow()
	}
	return time.Now()
}

// mfaStage 在讀取狀態與寫入之間的固定位置通知觀測掛勾；未注入時不做事。
func (s *AuthService) mfaStage(stage string) {
	if s.mfaStageHook != nil {
		s.mfaStageHook(stage)
	}
}

// MFASetupResponse MFA 設定回應（secret 僅在 setup 當下回傳一次）
type MFASetupResponse struct {
	Secret     string `json:"secret"`
	OTPAuthURL string `json:"otpauth_url"`
	// Reset 本次是已啟用帳號的驗證器重設（供審計標示，不出現在回應本文）
	Reset bool `json:"-"`
}

// MFAVerifyRequest MFA 第二階段驗證請求
type MFAVerifyRequest struct {
	PendingToken string `json:"pending_token" binding:"required"`
	Code         string `json:"code" binding:"required"`
}

// GenerateMFASetup 產生 TOTP secret 並以密文暫存（enabled 維持 false）。
//
// 已啟用 MFA 的帳號須附上現行驗證器的有效驗證碼（沿用登入驗證的防重放）：
// 缺碼回 ErrMFACurrentCodeRequired，碼錯或重放回 ErrMFAInvalidCode，皆不改動儲存的密文與啟用狀態。
// 未啟用者（首次註冊、管理員救援後重註冊）免碼。
//
// 覆寫為條件式更新，條件綁讀取當下看到的狀態與密文：兩次讀寫之間若被另一請求改動，
// 不覆寫並回 ErrMFACurrentCodeRequired，由前端重新讀取狀態後依新狀態重送。
// 為什麼直接落 DB 而非快取：避免引入 server-side 狀態，重做 setup 即覆蓋舊 secret
func (s *AuthService) GenerateMFASetup(userID uint, code string) (*MFASetupResponse, error) {
	if s.mfaCrypto == nil {
		return nil, ErrMFACryptoUnavailable
	}

	user, err := s.findUserByID(userID)
	if err != nil {
		return nil, err
	}
	readEnabled := user.TOTPEnabled
	readEnc := user.TOTPSecretEnc

	if readEnabled {
		if code == "" {
			return nil, ErrMFACurrentCodeRequired
		}
		current, err := s.mfaCrypto.DecryptFor(context.Background(), keyvault.RefUserTOTPSecret, readEnc)
		if err != nil {
			return nil, err
		}
		// 鎖定 gate 與失敗計數沿用登入第二階段的同一套（共用計數），
		// 避免重設入口成為不受次數限制的驗證碼試誤途徑
		if err := s.gateLockout(user); err != nil {
			return nil, err
		}
		if err := s.consumeTOTP(userID, current, code); err != nil {
			// 重放與碼錯皆計入鎖定，並各自回原錯（與登入第二階段、啟用步驟同一組回應碼）
			if errors.Is(err, ErrMFAInvalidCode) || errors.Is(err, ErrMFAReplay) {
				if lockErr := s.recordFailedAttempt(userID); errors.Is(lockErr, ErrAccountLocked) {
					return nil, lockErr
				}
				return nil, err
			}
			return nil, err
		}
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      totpIssuer,
		AccountName: user.Username,
	})
	if err != nil {
		return nil, err
	}

	// 帶欄位身分加密：AAD 綁 users.totp_secret_enc，
	// 密文搬到別表別欄即解不開
	encSecret, err := s.mfaCrypto.EncryptFor(context.Background(), keyvault.RefUserTOTPSecret, key.Secret())
	if err != nil {
		return nil, err
	}

	s.mfaStage("setup-before-write")
	// enabled 強制重設為 false：重新 setup 後舊驗證器立即失效，需重新驗碼啟用
	q := database.DB.Model(&model.User{})
	if readEnabled {
		q = q.Where("id = ? AND totp_enabled = ? AND totp_secret_enc = ?", userID, true, readEnc)
	} else {
		// 從未註冊者的密文可能為 NULL 或空字串，以 COALESCE 對齊後比對
		q = q.Where("id = ? AND totp_enabled = ? AND COALESCE(totp_secret_enc, '') = ?", userID, false, readEnc)
	}
	res := q.Updates(map[string]interface{}{
		"totp_secret_enc": encSecret,
		"totp_enabled":    false,
	})
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		return nil, ErrMFACurrentCodeRequired
	}

	return &MFASetupResponse{
		Secret:     key.Secret(),
		OTPAuthURL: key.URL(),
		Reset:      readEnabled,
	}, nil
}

// EnableMFA 驗證 TOTP 碼成功後才啟用 MFA（證明用戶已正確設定驗證器）。
// 啟用只對驗碼所用的那把密鑰生效：驗碼後密鑰若被另一請求換掉，回 ErrMFASetupRequired
func (s *AuthService) EnableMFA(userID uint, code string) error {
	user, secret, err := s.loadTOTPSecret(userID)
	if err != nil {
		return err
	}
	if secret == "" {
		return ErrMFASetupRequired
	}

	// 驗證＋消耗 step（8.5.1）：綁定確認亦防重放，且推進 last_step 供後續登入比對
	if err := s.consumeTOTP(user.ID, secret, code); err != nil {
		return err
	}

	s.mfaStage("enable-before-write")
	res := database.DB.Model(&model.User{}).
		Where("id = ? AND totp_secret_enc = ?", user.ID, user.TOTPSecretEnc).
		Updates(map[string]interface{}{"totp_enabled": true})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrMFASetupRequired
	}
	return nil
}

// VerifyMFACode 驗證已啟用 MFA 用戶的 TOTP 碼（登入第二階段使用）
func (s *AuthService) VerifyMFACode(userID uint, code string) error {
	user, secret, err := s.loadTOTPSecret(userID)
	if err != nil {
		return err
	}
	if !user.TOTPEnabled || secret == "" {
		return ErrMFANotEnabled
	}

	// 驗證＋消耗 step（8.5.1 防重放）：拒絕 step ≤ 最後消耗索引
	return s.consumeTOTP(user.ID, secret, code)
}

// DisableMFA 用戶自行停用 MFA；要求重新驗證密碼以防 token 被竊後直接降級安全性
func (s *AuthService) DisableMFA(userID uint, password string) error {
	user, err := s.findUserByID(userID)
	if err != nil {
		return err
	}

	if err := crypto.DefaultPasswordVerifier().Verify(user.Password, []byte(password)); err != nil {
		return ErrInvalidCredentials
	}

	return s.clearMFA(userID)
}

// AdminDisableMFA 管理員救援：用戶遺失驗證器時由管理員停用其 MFA（呼叫端負責權限與審計）
func (s *AuthService) AdminDisableMFA(targetUserID uint) error {
	if _, err := s.findUserByID(targetUserID); err != nil {
		return err
	}
	return s.clearMFA(targetUserID)
}

// VerifyMFALogin 第二階段登入：以 pending token + TOTP 碼交換正式 session token。
// TOTP 失敗與密碼失敗共用同一鎖定計數（8.3.4 原文是 invalid authentication attempts
// 不限密碼——否則持被竊密碼者可在每個 pending 窗內無限暴力猜 6 位 TOTP）
func (s *AuthService) VerifyMFALogin(req *MFAVerifyRequest) (*LoginResponse, error) {
	// 專用解析：僅接受 scope=mfa_pending 的 token，正式 token 不得走此通道
	claims, err := s.jwtManager.ValidateToken(req.PendingToken)
	if err != nil || claims.Scope != crypto.ScopeMFAPending {
		return nil, ErrMFAPendingTokenInvalid
	}

	// 重新載入用戶與角色：pending token 簽發後角色或狀態可能已變更
	var user model.User
	if err := database.DB.Preload("Roles").First(&user, claims.UserID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	if user.Kind == model.KindAgent {
		return nil, ErrAgentHumanOnly
	}

	if !user.Active {
		return nil, ErrUserInactive
	}

	// 憑證世代閘：pending token 是「第一因子已通過」
	// 的能力憑證，**尚未兌換**故不在任何連線掃描的涵蓋範圍內。缺此判定時，
	// 管理者把帳號改為僅外部登入（或解綁身分、停用帳號）之後，持有 pending token 者
	// 仍可完成 TOTP 驗證；且 finishLogin 會因帳號此時已外部化而跳過密碼 gate，
	// 直接發出正式會話——spec「轉換撤銷本地密碼建立的存取」明列的失效情境。
	// 對外收斂為與過期／偽造相同的回應，不洩漏成因
	if err := s.VerifyCredentialGeneration(claims.AuthContext, &user); err != nil {
		log.Printf("[MFA] pending token 憑證世代已失效 (userID=%d): %v", claims.UserID, err)
		return nil, ErrMFAPendingTokenInvalid
	}

	// 鎖定 gate：pending 窗內密碼路徑觸發的鎖定同樣擋在此（共用計數）
	if err := s.gateLockout(&user); err != nil {
		return nil, err
	}

	if err := s.VerifyMFACode(claims.UserID, req.Code); err != nil {
		// 碼錯與重放皆計入鎖定並回原錯（重放對外仍以碼錯呈現，不洩漏）
		if errors.Is(err, ErrMFAInvalidCode) || errors.Is(err, ErrMFAReplay) {
			if lockErr := s.recordFailedAttempt(user.ID); errors.Is(lockErr, ErrAccountLocked) {
				return nil, lockErr
			}
			return nil, err
		}
		return nil, err
	}

	// 密碼與 MFA 全過：計數歸零、last_login_at、強制改密 gate、發正式 token
	// 自 pending/enrollment token 繼承 method 與 provider（描述本次怎麼認證的），
	// 但世代由 buildAuthContext 現查——期間可能已推進（例如 provider 被停用、
	// 或使用者憑證世代因管理動作而推進），沿用舊值會使剛換發的 token 立即失效
	return s.finishLoginCarryingContext(&user, claims)
}

// finishLoginCarryingContext 完成登入並**回帶本次的認證脈絡**供 handler 落審計。
//
// spec（oidc-auth「登入 gate chain 匯流」）要求登入審計標註認證方式與 provider，
// 且「於 MFA 完成路徑一併保留」——正式會話的成功列由 MFA 完成點寫出，此處不回帶
// 脈絡的話，經 SSO 且啟用 MFA 的登入在審計上與本地密碼登入完全無法區分。
// 本地密碼登入不附註，維持既有審計輸出零變化
func (s *AuthService) finishLoginCarryingContext(user *model.User, claims *crypto.Claims) (*LoginResponse, error) {
	resp, err := s.finishLogin(user, nil, s.buildAuthContext(user, claims.EffectiveMethod(), claims.ProviderID))
	if err != nil {
		return nil, err
	}
	if claims.EffectiveMethod() != crypto.AuthMethodLocalPassword {
		resp.AuthSource = claims.EffectiveMethod()
		resp.AuthProviderID = claims.ProviderID
		// **provider 名稱一併回帶**：spec 要求標的是「認證方式**與 provider**」，
		// 只回帶 ID 時稽核端看到的是一個裸數字，而 provider 可被改名或刪除，
		// 事後未必查得回當時的身分來源（OIDC 直登路徑同此形態，
		// 見 oidc_login_service.go 的 providerNameOf）
		resp.AuthProviderName = s.authProviderName(claims.ProviderID)
	}
	return resp, nil
}

// authProviderName 取 provider 顯示名供審計標註。
//
// 查不到一律回空字串並記日誌——**標註不得中斷登入**：provider 已被刪除或
// DB 短暫不可用時，正確處置是留下一筆「provider_name 空」的審計列，
// 而不是讓一個已通過全部認證閘的使用者登不進來
func (s *AuthService) authProviderName(providerID uint) string {
	if providerID == 0 {
		return ""
	}
	db := s.epochDB()
	if db == nil {
		return ""
	}
	var p model.OIDCProvider
	if err := db.Select("id", "name").First(&p, providerID).Error; err != nil {
		log.Printf("[MFA] 稽核標註取 provider 名稱失敗 (id=%d): %v", providerID, err)
		return ""
	}
	return p.Name
}

// validateEnrollmentClaims 專用解析 enrollment scoped token（僅接受 ScopeMFAEnrollment）
func (s *AuthService) validateEnrollmentClaims(tokenString string) (*crypto.Claims, error) {
	claims, err := s.jwtManager.ValidateToken(tokenString)
	if err != nil || claims.Scope != crypto.ScopeMFAEnrollment {
		return nil, ErrMFAPendingTokenInvalid
	}
	return claims, nil
}

// EnrollmentTokenSubject 解析 enrollment token 取出主體 userID（**不含任何狀態變更**）。
//
// 供強制註冊兩個端點在呼叫服務之前判定來源：規格要求判定落在
// 「票證驗證之後、狀態寫入之前」，而 EnrollmentSetup／CompleteEnrollment 是
// 「驗證＋寫入」一體的服務呼叫，handler 必須先自己知道是誰。
//
// **票證不成立時回 ok=false 而非錯誤回應**：此時 handler 不判來源，
// 逕行走既有服務呼叫，由它產生原本那份 401 與審計列——來源政策不得讓
// 「票證無效」的回應形狀出現分岔（那會是一個票證有效性的預言機）。
func (s *AuthService) EnrollmentTokenSubject(enrollmentToken string) (uint, bool) {
	claims, err := s.validateEnrollmentClaims(enrollmentToken)
	if err != nil {
		return 0, false
	}
	return claims.UserID, true
}

// requireNotEnrolled 強制註冊流程的前置守衛：重載用戶並拒已註冊者。
// enrollment 的前提是「受強制但未註冊」，token 簽發後 15 分內用戶可能已在他處完成綁定；
// 若不重查，持洩漏的 enrollment token 可重置並改綁已註冊帳號的第二因子
func (s *AuthService) requireNotEnrolled(userID uint) error {
	user, err := s.findUserByID(userID)
	if err != nil {
		return err
	}
	if user.TOTPEnabled {
		return ErrMFAAlreadyEnrolled
	}
	return nil
}

// EnrollmentSetup 以 enrollment token 產生 TOTP 設定（強制註冊流程，userID 取自 token）
func (s *AuthService) EnrollmentSetup(enrollmentToken string) (*MFASetupResponse, error) {
	claims, err := s.validateEnrollmentClaims(enrollmentToken)
	if err != nil {
		return nil, err
	}
	// 已註冊者不得用 enrollment token 重置因子
	if err := s.requireNotEnrolled(claims.UserID); err != nil {
		return nil, err
	}
	resp, err := s.GenerateMFASetup(claims.UserID, "")
	if errors.Is(err, ErrMFACurrentCodeRequired) {
		// 檢查後帳號已被他處完成註冊：與已註冊同處置
		return nil, ErrMFAAlreadyEnrolled
	}
	return resp, err
}

// CompleteEnrollment 以 enrollment token + TOTP 碼完成綁定並直接換發正式會話。
// 綁定成功即證明持有因子，不重走登入；若同時須強制改密，finishLogin 會回改密 token
func (s *AuthService) CompleteEnrollment(enrollmentToken, code string) (*LoginResponse, error) {
	claims, err := s.validateEnrollmentClaims(enrollmentToken)
	if err != nil {
		return nil, err
	}
	// 已註冊者不得改綁：即使搶在 setup 後、他處完成綁定前重放也擋下
	if err := s.requireNotEnrolled(claims.UserID); err != nil {
		return nil, err
	}
	// 憑證世代閘（同 VerifyMFALogin，理由見該處）。**必須在 EnableMFA 之前**：
	// 該呼叫會實際寫入 TOTP 因子，放在其後等於讓已失效的憑證仍能改變帳號狀態
	if err := s.VerifyCredentialGenerationByUserID(claims.AuthContext, claims.UserID); err != nil {
		log.Printf("[MFA] enrollment token 憑證世代已失效 (userID=%d): %v", claims.UserID, err)
		return nil, ErrMFAPendingTokenInvalid
	}
	if err := s.EnableMFA(claims.UserID, code); err != nil {
		// 綁定碼錯/重放計入共用鎖定計數（MFA-2：與 VerifyMFALogin 一致的暴力防護）
		if errors.Is(err, ErrMFAInvalidCode) || errors.Is(err, ErrMFAReplay) {
			if lockErr := s.recordFailedAttempt(claims.UserID); errors.Is(lockErr, ErrAccountLocked) {
				return nil, lockErr
			}
		}
		return nil, err
	}

	var user model.User
	if err := database.DB.Preload("Roles").First(&user, claims.UserID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	if !user.Active {
		return nil, ErrUserInactive
	}
	// 自 pending/enrollment token 繼承 method 與 provider（描述本次怎麼認證的），
	// 但世代由 buildAuthContext 現查——期間可能已推進（例如 provider 被停用、
	// 或使用者憑證世代因管理動作而推進），沿用舊值會使剛換發的 token 立即失效
	return s.finishLoginCarryingContext(&user, claims)
}

// findUserByID 查詢用戶（不含角色），統一 not found 錯誤
func (s *AuthService) findUserByID(userID uint) (*model.User, error) {
	var user model.User
	if err := database.DB.First(&user, userID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	if user.Kind == model.KindAgent {
		return nil, ErrAgentHumanOnly
	}

	return &user, nil
}

// loadTOTPSecret 載入用戶並解密 TOTP secret
func (s *AuthService) loadTOTPSecret(userID uint) (*model.User, string, error) {
	if s.mfaCrypto == nil {
		return nil, "", ErrMFACryptoUnavailable
	}
	user, err := s.findUserByID(userID)
	if err != nil {
		return nil, "", err
	}
	// DecryptFor 依前綴分派：既有 enc:v／legacy 值於 strict 未啟用時照常可解
	secret, err := s.mfaCrypto.DecryptFor(context.Background(), keyvault.RefUserTOTPSecret, user.TOTPSecretEnc)
	if err != nil {
		return nil, "", err
	}
	return user, secret, nil
}

// clearMFA 清空 MFA 設定（secret 一併清除，重新啟用需重做 setup）
func (s *AuthService) clearMFA(userID uint) error {
	return database.DB.Model(&model.User{}).Where("id = ?", userID).
		Updates(map[string]interface{}{
			"totp_secret_enc": "",
			"totp_enabled":    false,
		}).Error
}
