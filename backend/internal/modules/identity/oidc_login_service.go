package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/custodexa/backend/internal/modules/audit"
	"log"
	"strings"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
	"golang.org/x/oauth2"
	"gorm.io/gorm"
)

var (
	// ErrOIDCFlowInvalid 流程狀態不存在、已消費或已過期（三者對外不可區分）
	ErrOIDCFlowInvalid = errors.New("登入流程已失效，請重新發起")
	// ErrOIDCFlowStateNotFound state 查找階段即失敗（未知／缺失／已消費／已過期）。
	//
	// **包裝 ErrOIDCFlowInvalid**：對外回應與其他流程失敗完全不可區分（errors.Is
	// 仍成立），區分只給呼叫端內部用——此路徑無須接觸 IdP、不受 flow state 容量
	// 限制，是最便宜的洪水面，其失敗須走聚合審計而非逐筆落庫（3.7a）
	ErrOIDCFlowStateNotFound = fmt.Errorf("%w", ErrOIDCFlowInvalid)
	// ErrOIDCFlowCapacity flow state 全表容量已達上限，暫不接受新流程。
	//
	// **拒新不淘舊**：淘汰既有列會讓洪水把正常進行中的流程掃掉（使用者正在
	// IdP 頁面輸入密碼），等於把儲存問題換成可用性攻擊
	ErrOIDCFlowCapacity = errors.New("登入流程建立過於頻繁，請稍後再試")
	// ErrOIDCProviderUnavailable provider 已停用或設定不完整
	ErrOIDCProviderUnavailable = errors.New("此登入方式目前不可用")
	// ErrOIDCAdmissionDenied 未通過准入判定
	ErrOIDCAdmissionDenied = errors.New("您的帳號不符合此登入方式的准入條件，請聯繫管理員")
	// ErrOIDCUsernameConflict 映射所得使用者名稱已被占用
	ErrOIDCUsernameConflict = errors.New("帳號名稱衝突，請聯繫管理員處理")
	// ErrOIDCTicketInvalid 交棒憑證無效（不存在／已消費／過期／綁定不符，對外不可區分）
	ErrOIDCTicketInvalid = errors.New("登入憑證已失效，請重新登入")
)

const (
	// oidcFlowTTL 流程狀態存活時間：涵蓋使用者在 IdP 完成認證所需時間
	oidcFlowTTL = 10 * time.Minute
	// oidcTicketTTL 交棒憑證存活時間：SPA 拿到後立即兌換，短時效即足夠
	oidcTicketTTL = 60 * time.Second
	// oidcTicketMaxBindingFailures 綁定不符的容忍次數。
	// 不消耗憑證（否則「回原分頁重試」不可能成立）但計次，達此值即作廢
	oidcTicketMaxBindingFailures = 3
	// oidcFlowStateCapacity flow state 全表容量上限（「儲存量有界」）。
	//
	// begin 是未認證端點且每次呼叫產生一列持久化狀態，沒有帳號可綁、也沒有
	// 成本可收，唯一不依賴客戶端可控輸入的保證就是全表上限。量級取「TTL 10 分鐘
	// 內的正常發起量」的數十倍：正常部署不會接近，攻擊時則把 DB 成長壓在
	// 常數級（單列百餘位元組，滿載約數 MB）
	oidcFlowStateCapacity = 20000
)

// oidcTicketBindingFailureHook 測試用同步點：於「本次請求已讀出 ticket、尚未
// 遞增綁定失敗計數」的位置呼叫。
//
// 同 oidcProviderPreWriteHook／userCredentialPreWriteHook 的理由（見
// oidc_provider_lock.go）：門檻判定的競態只在特定交錯下成立，靠 goroutine
// 搶跑會在「剛好沒撞上」時假綠。生產路徑此值恆為 nil，改寫者僅限 _test.go。
var oidcTicketBindingFailureHook func()

// oidcAuditSink 審計出口。
//
// 抽成介面的理由是可驗收性：本流程有數個「**不該**落安全事件」的要求
// （並發收斂不得落冒名衝突），而「沒有落」這件事無法從真實的非同步審計服務
// 觀察——它有 worker、channel 與 2 秒 flush，測試只能等，等不到也證明不了什麼
type oidcAuditSink interface {
	Log(entry *audit.AuditLogEntry)
}

// OIDCAuditEvent 登入流程產出的**審計意向**：只描述「發生了什麼」，不落地。
//
// service 一律不自寫流程審計（design Non-Goals）：它拿不到
// `*gin.Context`，來源位址／路徑／方法／狀態碼四欄必然為空，而那四欄正是稽核
// 判讀「誰、從哪裡、打了什麼」的全部依據。解法是由持有請求脈絡的 handler 寫，
// **不是**給 service 傳 context 或 IP——後者把 HTTP 關注點推進 service 層。
type OIDCAuditEvent struct {
	Action     model.AuditAction
	Resource   model.AuditResource
	ResourceID *uint
	Status     model.AuditStatus
	UserID     uint
	Username   string
	Details    map[string]any
}

// DetailsJSON 序列化 Details（失敗時退為最小可用內容，審計不得因序列化而遺失）
func (e OIDCAuditEvent) DetailsJSON() string { return mustJSON(e.Details) }

// OIDCLoginError 攜帶審計意向的登入流程失敗。
//
// **包裝既有 sentinel**：`errors.Is` 續可比對，故對外回應映射（respondLoginError／
// oidcErrorSlug）與既有的錯誤斷言零改動，新增的只有「這次失敗該留什麼痕」這一面
type OIDCLoginError struct {
	sentinel error
	// Events 本次失敗應留下的審計意向（依發生順序）
	Events []OIDCAuditEvent
}

func (e *OIDCLoginError) Error() string { return e.sentinel.Error() }

// Unwrap 讓 errors.Is 可比對底層 sentinel
func (e *OIDCLoginError) Unwrap() error { return e.sentinel }

// OIDCAuditEventsOf 取出 err 攜帶的審計意向（無則回 nil）
func OIDCAuditEventsOf(err error) []OIDCAuditEvent {
	var le *OIDCLoginError
	if errors.As(err, &le) {
		return le.Events
	}
	return nil
}

// oidcAuditTrail 單次流程的審計意向累積器。
//
// 為何要累積而非「發生即回傳」：一次 callback 可能先建帳號（成功事件）再於簽
// ticket 時被拒（失敗事件），只帶回最後一個會使 JIT 建帳號無痕
type oidcAuditTrail struct {
	events []OIDCAuditEvent
}

func (t *oidcAuditTrail) add(ev OIDCAuditEvent) { t.events = append(t.events, ev) }

// fail 把已累積的意向掛到錯誤上。無意向時原樣回傳——不平白包一層，
// 使 `err == ErrOIDCFlowInvalid` 這類等值比對在無留痕路徑上維持原行為
func (t *oidcAuditTrail) fail(err error) error {
	if err == nil || len(t.events) == 0 {
		return err
	}
	return &OIDCLoginError{sentinel: err, Events: t.events}
}

// flowError 流程失敗（provider 不可用／授權碼交換失敗／id_token 缺失或驗證失敗）。
//
// status 為 `failure` 而非 `denied`（狀態語義分流）：這些是**憑證不成立**的
// 認證失敗，與「身分成立但不准」的授權拒絕（准入規則）語義不同，混為一談會使
// 既有授權拒絕列不可解釋
func (t *oidcAuditTrail) flowError(providerID uint, reason string) {
	t.add(OIDCAuditEvent{
		Action: model.ActionLogin, Resource: model.ResourceAuth, Status: model.StatusFailure,
		Details: map[string]any{
			"event": "oidc_flow_error", "reason": reason, "provider_id": providerID,
		},
	})
}

// admissionDenied 准入規則拒絕：身分於 IdP 驗證通過，但不符本系統的准入條件——
// 授權拒絕語義，故 `denied`。不記 claim 明文，只記未通過的規則類別
func (t *oidcAuditTrail) admissionDenied(p *model.OIDCProvider, subject, failedRule string) {
	t.add(OIDCAuditEvent{
		Action: model.ActionLogin, Resource: model.ResourceAuth, Status: model.StatusDenied,
		Details: map[string]any{
			"event": "oidc_admission_denied", "provider_id": p.ID,
			"provider_name": p.Name, "failed_rule": failedRule,
			"subject_fingerprint": sha256Hex(subject)[:16],
		},
	})
}

// usernameConflict 映射所得名稱撞既有帳號：身分成立但不得接管該帳號，
// 同屬授權拒絕語義
func (t *oidcAuditTrail) usernameConflict(p *model.OIDCProvider, subject, username, hint string, existingUserID uint) {
	t.add(OIDCAuditEvent{
		Action: model.ActionLogin, Resource: model.ResourceAuth, Status: model.StatusDenied,
		UserID: existingUserID, Username: username,
		Details: map[string]any{
			"event": "oidc_username_conflict", "provider_id": p.ID,
			"provider_name": p.Name, "hint": hint,
			"subject_fingerprint": sha256Hex(subject)[:16],
		},
	})
}

// provisioned JIT 首登建帳號。
//
// **資源歸 user 而非 auth**：這是一筆帳號寫入（PCI 10.4.1 的高危操作口徑即
// `resource=user` 且 `action IN (create,update)`），歸 auth 會使它從高危操作
// 覆核中消失。原實作只在**衝突時**留痕，成功建帳號反而無痕
func (t *oidcAuditTrail) provisioned(p *model.OIDCProvider, subject string, user *model.User) {
	uid := user.ID
	t.add(OIDCAuditEvent{
		Action: model.ActionCreate, Resource: model.ResourceUser, ResourceID: &uid,
		Status: model.StatusSuccess, UserID: user.ID, Username: user.Username,
		Details: map[string]any{
			"event": "oidc_user_provisioned", "provider_id": p.ID,
			"provider_name": p.Name, "auth_method": crypto.AuthMethodOIDC,
			"subject_fingerprint": sha256Hex(subject)[:16],
		},
	})
}

// OIDCLoginService OIDC 登入流程（begin → callback → exchange）
type OIDCLoginService struct {
	db        *gorm.DB
	providers *OIDCProviderService
	discovery *OIDCDiscoveryService
	auth      *AuthService
	audit     oidcAuditSink
	// flowCapacity flow state 全表容量上限（0＝用預設常數）。可注入使測試不必
	// 真的塞兩萬列
	flowCapacity int64
}

// NewOIDCLoginService 建立登入流程服務
func NewOIDCLoginService(db *gorm.DB, providers *OIDCProviderService,
	discovery *OIDCDiscoveryService, auth *AuthService, audit *audit.AuditLogService) *OIDCLoginService {
	s := &OIDCLoginService{db: db, providers: providers, discovery: discovery, auth: auth}
	// 具型別的 nil 指標存入介面欄位會使 s.audit != nil 成立而在呼叫時 panic，
	// 故顯式判空後才指派
	if audit != nil {
		s.audit = audit
	}
	return s
}

// randomToken 產生高熵隨機值（state／nonce／ticket 共用）
func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// BeginResult begin 端點的結果
type BeginResult struct {
	AuthorizationURL string
}

// Begin 發起登入流程。
//
// bindingHash 為發起端瀏覽器 secret 的 SHA256——DB 保存 state 只證明「伺服器
// 簽發且未用過」，**不證明 callback 發生在發起的瀏覽器**。攻擊者可自行發起流程、
// 以自己的 IdP 帳號完成授權但攔住 callback，再把該 URL 交給受害者：state/nonce/PKCE
// 全部有效，受害者會被登入攻擊者帳號（login CSRF），其後操作與審計全歸屬錯誤。
func (s *OIDCLoginService) Begin(ctx context.Context, providerID uint,
	bindingHash, redirectNext string) (*BeginResult, error) {
	// 容量判定置於一切工作之前：它要擋的正是「便宜地製造持久化狀態」，
	// 若排在 discovery 出站往返之後，洪水仍能把每次請求放大成一次對 IdP 的連線
	if err := s.reserveFlowCapacity(); err != nil {
		return nil, err
	}
	p, secret, err := s.providers.GetForAuth(providerID)
	if err != nil {
		return nil, err
	}
	if !p.Enabled {
		return nil, ErrOIDCProviderUnavailable
	}
	redirectURI, err := s.providers.RedirectURI()
	if err != nil {
		return nil, ErrOIDCProviderUnavailable
	}

	cfg, err := s.discovery.OAuth2Config(ctx, p, secret, redirectURI)
	if err != nil {
		return nil, err
	}

	state, err := randomToken()
	if err != nil {
		return nil, err
	}
	nonce, err := randomToken()
	if err != nil {
		return nil, err
	}
	verifier := oauth2.GenerateVerifier()

	flow := model.OIDCFlowState{
		State: state, Nonce: nonce, PKCEVerifier: verifier,
		ProviderID: p.ID, AuthEpoch: p.AuthEpoch,
		BindingHash: bindingHash, RedirectNext: redirectNext,
		ExpiresAt: time.Now().Add(oidcFlowTTL),
	}
	if err := s.db.Create(&flow).Error; err != nil {
		return nil, fmt.Errorf("建立登入流程狀態失敗: %w", err)
	}

	url := cfg.AuthCodeURL(state,
		oidc_nonceOption(nonce),
		oauth2.S256ChallengeOption(verifier),
	)
	return &BeginResult{AuthorizationURL: url}, nil
}

// reserveFlowCapacity 全表容量判定（驗收條件：begin 洪水下 DB 大小有界）。
//
// 達上限時**先清過期列再重數**——清理排程週期未到不該讓可回收的空間算進佔用，
// 否則系統會在真正滿載前就開始拒絕。重數後仍達上限即拒新（不淘舊）。
//
// 計數失敗一律視為達上限（fail-close）：此處的查詢極輕，失敗代表儲存層已有
// 問題，此時繼續寫入只會讓情況更糟
func (s *OIDCLoginService) reserveFlowCapacity() error {
	limit := s.flowCapacity
	if limit <= 0 {
		limit = oidcFlowStateCapacity
	}
	var cnt int64
	if err := s.db.Model(&model.OIDCFlowState{}).Count(&cnt).Error; err != nil {
		log.Printf("[OIDC] 流程狀態計數失敗，暫停接受新流程: %v", err)
		return ErrOIDCFlowCapacity
	}
	if cnt < limit {
		return nil
	}
	if err := s.db.Where("expires_at <= ?", time.Now()).
		Delete(&model.OIDCFlowState{}).Error; err != nil {
		log.Printf("[OIDC] 清理過期流程狀態失敗: %v", err)
		return ErrOIDCFlowCapacity
	}
	if err := s.db.Model(&model.OIDCFlowState{}).Count(&cnt).Error; err != nil {
		log.Printf("[OIDC] 流程狀態重新計數失敗，暫停接受新流程: %v", err)
		return ErrOIDCFlowCapacity
	}
	if cnt >= limit {
		return ErrOIDCFlowCapacity
	}
	return nil
}

// oidc_nonceOption nonce 授權參數
func oidc_nonceOption(nonce string) oauth2.AuthCodeOption {
	return oauth2.SetAuthURLParam("nonce", nonce)
}

// CallbackResult callback 完成後交給 SPA 的交棒憑證
type CallbackResult struct {
	Ticket       string
	RedirectNext string
	// AuditEvents 本次流程應留下的審計意向（成功路徑亦可能有，例如 JIT 建帳號）。
	// 由 handler 補上請求脈絡後寫入，見 OIDCAuditEvent
	AuditEvents []OIDCAuditEvent
}

// Callback 處理 IdP 回呼。
//
// 固定順序（**身分已存在不使准入判定被略過**）：
// 消費 flow state → 驗證 id_token → 查身分 → 求值 admission → 對應或供應 → 簽出 ticket。
func (s *OIDCLoginService) Callback(ctx context.Context, state, code string) (*CallbackResult, error) {
	trail := &oidcAuditTrail{}
	res, err := s.callback(ctx, state, code, trail)
	if err != nil {
		return nil, trail.fail(err)
	}
	res.AuditEvents = trail.events
	return res, nil
}

// callback 流程本體。**所有 return 路徑的審計意向都掛在 trail 上**——外層統一
// 掛到錯誤或結果上，故新增一條失敗分支不會漏掉留痕（漏掉 trail 就等於漏掉留痕，
// 而不是靜默地少一筆）
func (s *OIDCLoginService) callback(ctx context.Context, state, code string,
	trail *oidcAuditTrail) (*CallbackResult, error) {
	flow, err := s.consumeFlowState(state)
	if err != nil {
		return nil, err
	}

	p, secret, err := s.providers.GetForAuth(flow.ProviderID)
	if err != nil {
		return nil, ErrOIDCProviderUnavailable
	}
	// provider 於流程期間被停用或推進世代 → 拒絕（涵蓋「begin 之後、callback 之前
	// 被停用（並可能已重新啟用）」的窗口）
	if !p.Enabled || p.AuthEpoch != flow.AuthEpoch {
		trail.flowError(p.ID, "provider_unavailable")
		return nil, ErrOIDCProviderUnavailable
	}

	redirectURI, err := s.providers.RedirectURI()
	if err != nil {
		return nil, ErrOIDCProviderUnavailable
	}
	cfg, err := s.discovery.OAuth2Config(ctx, p, secret, redirectURI)
	if err != nil {
		return nil, err
	}

	tok, err := cfg.Exchange(ctx, code, oauth2.VerifierOption(flow.PKCEVerifier))
	if err != nil {
		trail.flowError(p.ID, "code_exchange_failed")
		return nil, ErrOIDCFlowInvalid
	}
	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		trail.flowError(p.ID, "id_token_missing")
		return nil, ErrOIDCFlowInvalid
	}

	claims, err := s.discovery.VerifyIDToken(ctx, p, rawIDToken, flow.Nonce)
	if err != nil {
		trail.flowError(p.ID, "id_token_invalid")
		return nil, ErrOIDCFlowInvalid
	}

	user, err := s.resolveOrProvision(p, claims, trail)
	if err != nil {
		return nil, err
	}

	ticket, err := s.issueTicket(user, p, flow.BindingHash, flow.RedirectNext)
	if err != nil {
		return nil, err
	}
	return &CallbackResult{Ticket: ticket, RedirectNext: flow.RedirectNext}, nil
}

// consumeFlowState 原子消費流程狀態：**僅在未過期時取用並失效**。
//
// 過期記錄即使清理排程尚未執行亦須拒絕——排程延遲不得擴大有效窗口
func (s *OIDCLoginService) consumeFlowState(state string) (*model.OIDCFlowState, error) {
	if strings.TrimSpace(state) == "" {
		return nil, ErrOIDCFlowStateNotFound
	}
	var flow model.OIDCFlowState
	err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("state = ? AND expires_at > ?", state, time.Now()).
			First(&flow).Error; err != nil {
			return err
		}
		// 條件刪除即為「一次性」的執行點：兩個並發 callback 只有一個能刪到
		res := tx.Where("state = ?", state).Delete(&model.OIDCFlowState{})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return gorm.ErrRecordNotFound
		}
		return nil
	})
	if err != nil {
		return nil, ErrOIDCFlowStateNotFound
	}
	return &flow, nil
}

// resolveOrProvision 身分對應或供應（固定順序）
func (s *OIDCLoginService) resolveOrProvision(p *model.OIDCProvider, claims *VerifiedClaims,
	trail *oidcAuditTrail) (*model.User, error) {
	rules, err := s.providers.AdmissionRulesOf(p)
	if err != nil {
		return nil, err
	}

	var identity model.UserExternalIdentity
	found := true
	err = s.db.Where("issuer = ? AND client_id = ? AND subject = ?",
		p.Issuer, p.ClientID, claims.Subject).First(&identity).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		found = false
	} else if err != nil {
		return nil, err
	}

	// **准入判定於每次認證求值**，不只首次供應——規則收緊或使用者 claim
	// 變更後，既有身分再次登入須依現行規則判定。身分已存在不使判定被略過。
	if p.AdmissionMode == model.AdmissionJITWithRules {
		if ok, failedRule := EvaluateAdmission(rules, claims.Raw); !ok {
			trail.admissionDenied(p, claims.Subject, failedRule)
			return nil, ErrOIDCAdmissionDenied
		}
	} else if !found {
		// prebound_only：判定條件即「身分是否已綁定」
		trail.admissionDenied(p, claims.Subject, "not_prebound")
		return nil, ErrOIDCAdmissionDenied
	}

	if found {
		var user model.User
		if err := s.db.Preload("Roles").First(&user, identity.UserID).Error; err != nil {
			return nil, err
		}
		s.touchIdentity(&identity, p.ID, claims)
		return &user, nil
	}

	// **自動供應前重驗規則集合規性**（spec L161-163）：issuer kind 不持久化、
	// 每次現算，故部署層移除某 issuer 的專用宣告後，原本合法的「僅 email 網域」
	// 規則就地變成不合規——但沒有任何寫入發生，寫入期的 ValidateAdmissionConfig
	// 永遠不會被觸發。缺這一步，共用身分域（如整個 Google／Entra）上任何符合
	// email 網域的人都會被自動供應成本系統帳號，而 email 網域可由 IdP 端偽造。
	//
	// **fail-close 只擋自動供應**：既有已綁身分的登入（found）不受影響——
	// 它們在上方已回傳，管理者收拾殘局期間不會被鎖在門外
	if err := s.providers.AdmissionComplianceOf(p); err != nil {
		trail.admissionDenied(p, claims.Subject, "rules_noncompliant:"+admissionIssueCode(err))
		log.Printf("[OIDC] provider %d 規則集現算不合規（%s），已 fail-close 停止自動供應",
			p.ID, admissionIssueCode(err))
		return nil, ErrOIDCAdmissionDenied
	}
	return s.provisionFromClaims(p, claims, trail)
}

// touchIdentity 回訪更新：**僅更新身分列的最近登入與 claim 快照**。
//
// users 本體的 username/email/full_name 一律不改寫——本體是授權主體識別
// （授權綁定與審計歸屬皆依它），靜默變更會使既有授權與稽核歸屬失準。
// 快照則是 IdP 現況的觀測值，供管理端辨識
func (s *OIDCLoginService) touchIdentity(identity *model.UserExternalIdentity, providerID uint, claims *VerifiedClaims) {
	now := time.Now()
	updates := map[string]any{
		"last_login_at":  &now,
		"provider_id":    providerID, // provider 重建後修正指向
		"claim_username": truncate(claims.PreferredUsername, 255),
	}
	// 快照僅保存已驗證的 email——未驗證值若被管理端當作可信現況即成誤導
	if claims.EmailVerified {
		updates["claim_email"] = truncate(claims.Email, 255)
	}
	if err := s.db.Model(identity).Updates(updates).Error; err != nil {
		log.Printf("[OIDC] 更新外部身分快照失敗 (id=%d): %v", identity.ID, err)
	}
}

// provisionFromClaims 首登供應影子用戶。
//
// 三合一交易：建 user＋綁 user 角色＋建外部身分。並發首登以「唯一約束失敗後
// 重查身分鍵」收斂——命中即視為另一分頁贏得競賽，正常登入且**不落衝突安全事件**
// （否則使用者雙擊 SSO 就會產生冒名衝突的誤報）
func (s *OIDCLoginService) provisionFromClaims(p *model.OIDCProvider, claims *VerifiedClaims,
	trail *oidcAuditTrail) (*model.User, error) {
	username := s.mapUsername(claims)
	if username == "" {
		return nil, ErrOIDCUsernameConflict
	}

	// 同名不接管：映射所得 username 已存在且該帳號無此外部身分 → 拒絕。
	// 不做以 username 為鍵的 get_or_create 靜默接管——接管會讓 SSO 使用者直接登進
	// 同名的本地帳號
	var existing model.User
	err := s.db.Where("username = ?", username).First(&existing).Error
	if err == nil {
		// **宣告撞名前先重驗前提**：呼叫端查到「身分不存在」之後、走到這裡之前，
		// 另一個並發請求可能已完成供應——此時佔用該 username 的正是那個新帳號。
		// 少了這一步，使用者雙擊 SSO 的落後分頁會拿到撞名錯誤並落下冒名衝突的
		// 誤報安全事件（同一 TOCTOU 通則的又一個執行點）
		if u, ok := s.convergeToExistingIdentity(p, claims); ok {
			return u, nil
		}
		s.auditUsernameConflict(trail, p, claims.Subject, username, existing.ID)
		return nil, ErrOIDCUsernameConflict
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		return nil, err
	}
	hashed, err := crypto.DefaultPasswordHasher().Hash([]byte(hex.EncodeToString(randomBytes)))
	if err != nil {
		return nil, err
	}

	var emailPtr *string
	if claims.EmailVerified && claims.Email != "" {
		// email 僅在已驗證時採用；衝突時存 NULL 不阻斷供應（沿用既有規則）
		normalized := normalizeEmail(claims.Email)
		if normalized != nil {
			var cnt int64
			if err := s.db.Model(&model.User{}).Where("LOWER(email) = ?", *normalized).Count(&cnt).Error; err == nil && cnt == 0 {
				emailPtr = normalized
			}
		}
	}

	user := &model.User{
		Username: username, Password: string(hashed), Email: emailPtr,
		FullName: truncate(claims.Name, 100), Active: true,
		ProvisioningOrigin: model.AuthSourceOIDC,
		ExternalCredential: true,
	}

	txErr := s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(user).Error; err != nil {
			return err
		}
		var role model.Role
		if err := tx.Where("name = ?", model.RoleUser).First(&role).Error; err != nil {
			return err
		}
		if err := tx.Exec("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)", user.ID, role.ID).Error; err != nil {
			return err
		}
		now := time.Now()
		identity := model.UserExternalIdentity{
			UserID: user.ID, ProviderID: p.ID,
			Issuer: p.Issuer, ClientID: p.ClientID, Subject: claims.Subject,
			ClaimUsername: truncate(claims.PreferredUsername, 255),
			LastLoginAt:   &now,
		}
		if claims.EmailVerified {
			identity.ClaimEmail = truncate(claims.Email, 255)
		}
		user.Roles = []model.Role{role}
		return tx.Create(&identity).Error
	})

	if txErr != nil {
		// 並發收斂：唯一約束失敗後重查身分鍵，命中即視為另一請求已完成供應
		if u, ok := s.convergeToExistingIdentity(p, claims); ok {
			return u, nil
		}
		// 交易失敗但身分不是自己的：最可能是**另一個 subject** 的並發首登
		// 搶先占用了同一個 username。此時對外必須是撞名（含審計事件），
		// 而非 500——後者既無指引也不留下可稽核的痕跡。
		// 判準用「重查 username 是否存在」而非解析各家 DB 的唯一鍵錯誤字串：
		// 錯誤訊息格式不在我方掌控，pg 與 sqlite 的措辭也不同
		var taken model.User
		if err := s.db.Where("username = ?", username).First(&taken).Error; err == nil {
			s.auditUsernameConflict(trail, p, claims.Subject, username, taken.ID)
			return nil, ErrOIDCUsernameConflict
		}
		return nil, fmt.Errorf("供應外部身分帳號失敗: %w", txErr)
	}

	// JIT 首登建帳號留痕（spec「首次登入即時建立帳號 SHALL 另留一筆帳號建立的
	// 審計列」）：原本只有**衝突時**才有事件，成功建出一個可登入的帳號反而無痕——
	// 稽核看到的是「這個帳號憑空出現」
	trail.provisioned(p, claims.Subject, user)
	log.Printf("[OIDC] 已供應外部身分帳號 (username=%s, provider=%d)", user.Username, p.ID)
	return user, nil
}

// convergeToExistingIdentity 以身分域三元組重查，命中即視為另一並發請求已完成供應。
//
// 供應路徑上有兩處會走到「疑似失敗」而其實只是輸掉競賽：撞名預查命中、
// 以及交易因唯一約束失敗。兩處皆須先重驗前提再宣告失敗，且**收斂不落安全事件**——
// 誤報的冒名衝突比漏報更糟，它會使真正的衝突淹沒在雙擊 SSO 的雜訊裡
func (s *OIDCLoginService) convergeToExistingIdentity(p *model.OIDCProvider, claims *VerifiedClaims) (*model.User, bool) {
	var identity model.UserExternalIdentity
	if err := s.db.Where("issuer = ? AND client_id = ? AND subject = ?",
		p.Issuer, p.ClientID, claims.Subject).First(&identity).Error; err != nil {
		return nil, false
	}
	var u model.User
	if err := s.db.Preload("Roles").First(&u, identity.UserID).Error; err != nil {
		return nil, false
	}
	// 收斂後的行為須與「既有身分正常回訪」完全相同：少了這一步，
	// 雙擊 SSO 的落後請求會登入成功卻不更新 last_login_at 與 claim 快照
	s.touchIdentity(&identity, p.ID, claims)
	return &u, true
}

// mapUsername 固定映射順序：preferred_username → 已驗證 email 的本地部分 → subject。
//
// **未驗證的 email 不得用於映射**——它可被任意設定，據以產生 username 等同讓
// 外部使用者自選本地身分
func (s *OIDCLoginService) mapUsername(claims *VerifiedClaims) string {
	if v := sanitizeUsername(claims.PreferredUsername); v != "" {
		return v
	}
	if claims.EmailVerified && claims.Email != "" {
		if at := strings.Index(claims.Email, "@"); at > 0 {
			if v := sanitizeUsername(claims.Email[:at]); v != "" {
				return v
			}
		}
	}
	return sanitizeUsername(claims.Subject)
}

// sanitizeUsername 使用者名稱正規化與長度限制
func sanitizeUsername(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return ""
		}
	}
	return truncate(s, 50)
}

func truncate(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max])
}

// issueTicket 簽出交棒憑證。DB 僅存雜湊，明文只回給呼叫端一次。
//
// **本函式是 3.8b 通則最關鍵的執行點**：flow state 不帶使用者世代（begin 時尚未
// 認證），ticket 是使用者世代的**第一個攜帶者**。未序列化則序列
//
//	callback 讀到 cred_epoch=3 → admin 解綁該身分（推進至 4、掃完既有連線）
//	→ callback 才簽出 ticket
//
// 會簽出一張帶「簽出當下最新世代」的憑證：後續每個驗證點的比對都會通過，
// 解綁等於沒做。故三步「重查前提 → 讀世代 → 建立」須於 provider＋user 鎖內完成。
func (s *OIDCLoginService) issueTicket(user *model.User, p *model.OIDCProvider,
	bindingHash, redirectNext string) (string, error) {
	plain, err := randomToken()
	if err != nil {
		return "", err
	}

	lockErr := WithCapabilityLocks(s.db, p.ID, user.ID, func(tx *gorm.DB) error {
		// 前提於鎖內重讀：帳號可能於 IdP 往返期間被停用，provider 可能被停用／
		// 刪除／輪替密鑰。鎖外預讀的值一律不採用
		var freshUser model.User
		if err := tx.Select("id", "active", "credential_epoch").
			First(&freshUser, user.ID).Error; err != nil {
			return ErrOIDCTicketInvalid
		}
		if !freshUser.Active {
			return ErrUserInactive
		}
		var freshProvider model.OIDCProvider
		if err := tx.Select("id", "enabled", "auth_epoch").
			First(&freshProvider, p.ID).Error; err != nil {
			return ErrOIDCProviderUnavailable
		}
		if !freshProvider.Enabled {
			return ErrOIDCProviderUnavailable
		}
		if oidcProviderPreWriteHook != nil {
			oidcProviderPreWriteHook(oidcSiteTicketIssue)
		}
		// 世代取鎖內重讀值（非呼叫端傳入的快照）
		ticket := model.OIDCLoginTicket{
			TokenHash: sha256Hex(plain), UserID: freshUser.ID, ProviderID: freshProvider.ID,
			AuthEpoch: freshProvider.AuthEpoch, CredEpoch: freshUser.CredentialEpoch,
			AuthMethod:      crypto.AuthMethodOIDC,
			FlowBindingHash: bindingHash, RedirectNext: redirectNext,
			ExpiresAt: time.Now().Add(oidcTicketTTL),
		}
		if err := tx.Create(&ticket).Error; err != nil {
			return fmt.Errorf("建立交棒憑證失敗: %w", err)
		}
		return nil
	})
	if lockErr != nil {
		return "", lockErr
	}
	return plain, nil
}

// Exchange 以交棒憑證換取正式登入回應。
//
// 回應與 /auth/login 同形（含 MFA 分支），故前端既有的登入狀態機零改動即可承接
func (s *OIDCLoginService) Exchange(ticketPlain, browserSecret string) (*LoginResponse, string, error) {
	hash := sha256Hex(ticketPlain)

	var ticket model.OIDCLoginTicket
	if err := s.db.Where("token_hash = ? AND expires_at > ?", hash, time.Now()).
		First(&ticket).Error; err != nil {
		return nil, "", ErrOIDCTicketInvalid
	}

	// 瀏覽器綁定驗證：**不符時不消耗憑證**（否則「請回到原分頁重試」不可能成立，
	// 憑證已被落錯的分頁消耗掉），但原子累計失敗次數，達上限即作廢。
	//
	// **空的 browser secret 一律視為不符**：否則攻擊者可用
	// `SHA256("")` 當 binding 發起流程，而受害者的 SPA 在 sessionStorage 沒有
	// secret 時若送出空字串，雜湊即恰好相符——綁定形同虛設，login CSRF 復活。
	// 判定放在後端而非依賴前端「無 secret 就不呼叫 exchange」的自律
	if ticket.FlowBindingHash != "" &&
		(strings.TrimSpace(browserSecret) == "" || sha256Hex(browserSecret) != ticket.FlowBindingHash) {
		if oidcTicketBindingFailureHook != nil {
			oidcTicketBindingFailureHook()
		}
		res := s.db.Model(&model.OIDCLoginTicket{}).
			Where("token_hash = ?", hash).
			UpdateColumn("binding_failures", gorm.Expr("binding_failures + 1"))
		if res.Error == nil {
			// **門檻以 DB 現值判定，不用本次請求開頭讀出的 ticket.BindingFailures**：
			// 遞增雖是原子的，但陳舊值判門檻會讓三個並發的錯誤綁定各自算出
			// `0+1 < 3` 而都不刪除——DB 早已是 3，憑證卻要到第 4 次才作廢。
			// 條件式刪除把「是否達上限」交給同一句 SQL 判斷，與並發次序無關
			s.db.Where("token_hash = ? AND binding_failures >= ?", hash, oidcTicketMaxBindingFailures).
				Delete(&model.OIDCLoginTicket{})
		}
		return nil, "", ErrOIDCTicketInvalid
	}

	// 世代比對：撤銷動作（解綁／停用／provider 停用）可能發生於 ticket 簽出之後。
	authCtx := crypto.AuthContext{
		AuthMethod: ticket.AuthMethod, ProviderID: ticket.ProviderID,
		AuthEpoch: ticket.AuthEpoch, CredEpoch: ticket.CredEpoch,
	}
	// **消費與世代比對須序列化**（3.8b：exchange 換發亦是「以既有憑證產生新長效
	// 能力」）：兩者分離時，「比對通過 → 停用推進世代並掃完 → 才消費並簽出會話」
	// 的序列會產出一個不在任何掃描集合內的正式會話。
	// 三步全在 provider＋user 鎖內：重查前提（user 載入）→ 讀世代（現查比對）→
	// 建立（原子消費 ticket）。實際簽出 JWT／refresh 於鎖外（見下）
	var user model.User
	if lockErr := WithCapabilityLocks(s.db, ticket.ProviderID, ticket.UserID,
		func(tx *gorm.DB) error {
			if err := tx.Preload("Roles").First(&user, ticket.UserID).Error; err != nil {
				return ErrOIDCTicketInvalid
			}
			if err := VerifyCredentialGenerationTx(tx, authCtx, &user); err != nil {
				return ErrOIDCTicketInvalid
			}
			if oidcProviderPreWriteHook != nil {
				oidcProviderPreWriteHook(oidcSiteTicketExchange)
			}
			// 原子消費：兩個並發 exchange 只有一個刪得到
			res := tx.Where("token_hash = ?", hash).Delete(&model.OIDCLoginTicket{})
			if res.Error != nil || res.RowsAffected == 0 {
				return ErrOIDCTicketInvalid
			}
			return nil
		}); lockErr != nil {
		return nil, "", lockErr
	}

	// 簽出於鎖外：JWT／refresh 皆帶 ticket 上的世代（非現查值），故即使此刻
	// 恰有停用發生，簽出的憑證仍帶舊世代而必被後續每個驗證點拒絕——
	// 持鎖跨越 bcrypt／JWT 簽章這類 CPU 工作反而違反「單次 DB 往返級」的約束
	resp, err := s.auth.LoginWithExternalIdentity(&user, authCtx)
	if err != nil {
		return nil, "", err
	}
	// provider 標註供 handler 落審計（spec「標註認證方式並帶出 provider 識別」）。
	// **在此帶出而非讓 handler 自己查**：handler 只有 ticket 明文，回查等於把
	// 「這次登入用的是哪個 provider」重算一次，兩處算法一旦分歧就會標錯 provider。
	// MFA 待驗證回應亦適用（同一次登入的前半段）
	resp.AuthProviderID = ticket.ProviderID
	resp.AuthProviderName = s.providerNameOf(ticket.ProviderID)
	return resp, ticket.RedirectNext, nil
}

// providerNameOf 取 provider 顯示名（查不到回空字串——審計標註不得因此中斷登入）
func (s *OIDCLoginService) providerNameOf(providerID uint) string {
	var p model.OIDCProvider
	if err := s.db.Select("id", "name").First(&p, providerID).Error; err != nil {
		log.Printf("[OIDC] 審計標註取 provider 名稱失敗 (id=%d): %v", providerID, err)
		return ""
	}
	return p.Name
}

// CleanupExpired 清理過期的流程狀態與交棒憑證（排程呼叫）。
// 週期須 ≤ TTL——但過期判定不依賴此清理（消費時即檢查），清理只為控制儲存量
func (s *OIDCLoginService) CleanupExpired() {
	now := time.Now()
	if err := s.db.Where("expires_at <= ?", now).Delete(&model.OIDCFlowState{}).Error; err != nil {
		log.Printf("[OIDC] 清理過期流程狀態失敗: %v", err)
	}
	if err := s.db.Where("expires_at <= ?", now).Delete(&model.OIDCLoginTicket{}).Error; err != nil {
		log.Printf("[OIDC] 清理過期交棒憑證失敗: %v", err)
	}
}

// LogAggregatedFailure 聚合失敗事件的審計出口（3.7a）。
//
// 公開端點的失敗**不逐筆落審計**：偵測訊號本身不得成為 DoS 載體——攻擊者
// 持續送隨機 state／ticket 即等於持續寫 DB。改由呼叫端（api 層的濫用防護）
// 以（事件, 來源 IP, 時間窗）聚合，窗結束時落一筆帶計數與首末時間的記錄。
//
// **status 由呼叫端給**（狀態語義分流）：事件語義的常數在 api 層（限流拒絕
// 屬授權拒絕、隨機 state／ticket 屬憑證不成立），在此處反推事件名會把那份對照
// 表複製成兩份各自演化
func (s *OIDCLoginService) LogAggregatedFailure(event, clientIP string, status model.AuditStatus,
	count int, firstAt, lastAt time.Time) {
	// **來源位址取聚合鍵而非落地當下的請求**：本列描述的是一個已結束的時間窗，
	// 觸發結清的那個請求可能來自別處，拿它的脈絡蓋上去是錯的歸屬。
	// 路徑／方法／狀態碼同理留空——一個窗涵蓋多個請求，沒有單一值可填
	s.writeAuditFrom(clientIP, 0, "", status, map[string]any{
		"event": "oidc_abuse_aggregate", "reason": event,
		"client_ip": clientIP, "count": count,
		"first_at": firstAt.UTC().Format(time.RFC3339),
		"last_at":  lastAt.UTC().Format(time.RFC3339),
	})
}

// auditUsernameConflict 撞名事件的成因判定（需查庫，故留在 service）。
//
// 成因區分：既有帳號若已有「相同 issuer、不同 client_id」的身分，
// 提示很可能是同一 IdP 建了多個 provider，而非真正的撞名
func (s *OIDCLoginService) auditUsernameConflict(trail *oidcAuditTrail,
	p *model.OIDCProvider, subject, username string, existingUserID uint) {
	hint := "name_collision"
	var sameIssuer int64
	if err := s.db.Model(&model.UserExternalIdentity{}).
		Where("user_id = ? AND issuer = ? AND client_id <> ?", existingUserID, p.Issuer, p.ClientID).
		Count(&sameIssuer).Error; err == nil && sameIssuer > 0 {
		hint = "same_issuer_other_client"
	}
	trail.usernameConflict(p, subject, username, hint, existingUserID)
}

// mustJSON 審計 Details 序列化；失敗時退為最小可用內容（審計不得因序列化而遺失）
func mustJSON(v map[string]any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return `{"event":"serialize_failed"}`
	}
	return string(b)
}

// writeAuditFrom 本服務**唯一**的直接落地點（僅聚合列使用；逐請求的流程留痕
// 一律交由 handler 落地，見 OIDCAuditEvent）。
//
// Resource 為 `auth` 而非 `user`：本列描述的是一次**認證流程**的結果，不是對
// 某個使用者資源的操作。歸 `user` 會使登入拒絕混進帳號管理的稽核視圖，
// 也使「認證類事件」無法以 resource 收斂查詢
func (s *OIDCLoginService) writeAuditFrom(clientIP string, userID uint, username string,
	status model.AuditStatus, details map[string]any) {
	if s.audit == nil {
		return
	}
	s.audit.Log(&audit.AuditLogEntry{
		UserID: userID, Username: username,
		Action: model.ActionLogin, Resource: model.ResourceAuth,
		ClientIP: clientIP,
		Status:   status, Details: mustJSON(details),
	})
}
