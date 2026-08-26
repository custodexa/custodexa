package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp/totp"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
)

// G1 web 強制點的行為矩陣（盤點表 #1–#19）。
//
// # 為什麼是一張表而不是幾格
//
// 判定點有十八個，散在四個 handler 檔裡。漏掉任何一個都不會有錯誤訊息、
// 不會有既有測試轉紅——只會讓那條路徑對清單外來源靜默放行，而那正是本功能
// 唯一要擋的事。表把「哪些點該判」變成可機器檢查的資料；哪些 handler 函式
// 必須呼叫 helper 另由 `cmd/server/source_gate_coverage_guard_test.go` 的
// AST 閉集合守衛釘住（兩者互補：本表驗行為，那支驗涵蓋面）。
//
// # 每個點三態
//
//	空清單   → 放行（不限）
//	清單內   → 放行
//	清單外   → 403 AUTH_SOURCE_NOT_ALLOWED，且回應不回顯位址與清單
//
// 三態齊備是刻意的：只驗「清單外被擋」的測試，在 helper 被寫成「一律拒絕」時
// 照樣全綠，而那會讓所有人都登不進來。

const (
	// gateSourceInside 涵蓋測試請求的來源（fixture 的 RemoteAddr 為 203.0.113.5）
	gateSourceInside = "203.0.113.0/24"
	// gateSourceOutside 不涵蓋測試請求的來源
	gateSourceOutside = "10.0.0.0/8"
	// gateSourceCorrupt 無法解析的儲存字串（政策不可用）
	gateSourceCorrupt = "10.0.0.0/8,not-a-cidr"
)

// setSourcePolicy 直寫使用者的允許來源網段。
//
// **繞過 service 驗證是刻意的**：損壞字串那一態按定義造不出於 service 層
// （唯一寫入路徑是驗證後寫入）。
func (e *refreshCookieEnv) setSourcePolicy(t *testing.T, raw string) {
	t.Helper()
	if err := e.db.Model(&model.User{}).Where("id = ?", e.user.ID).
		Update("allowed_cidrs", raw).Error; err != nil {
		t.Fatalf("set allowed_cidrs=%q: %v", raw, err)
	}
}

// useRealSourcePolicy 讓兩個 handler 改讀真實的 users.allowed_cidrs 欄。
//
// fixture 預設注入「不限」替身（既有案例的表態）；本檔要驗的正是欄位驅動的判定，
// 故換成真實服務。
func (e *refreshCookieEnv) useRealSourcePolicy() {
	e.h.SetSourcePolicyReader(e.auth)
	e.oidc.SetSourcePolicyReader(e.auth)
}

// assertSourceDenied 拒絕回應的完整斷言：403、專屬機器碼、**不回顯位址與清單**。
func assertSourceDenied(t *testing.T, point string, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code != http.StatusForbidden {
		t.Fatalf("[%s] 清單外來源應回 403，實得 %d：body=%s", point, w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if got, _ := resp["code"].(string); got != string(apierror.CodeAuthSourceNotAllowed) {
		t.Fatalf("[%s] 拒絕碼 = %q, want %q：body=%s",
			point, got, apierror.CodeAuthSourceNotAllowed, w.Body.String())
	}
	body := w.Body.String()
	for _, leak := range []string{"203.0.113.5", gateSourceOutside, "10.0.0.0"} {
		if strings.Contains(body, leak) {
			t.Errorf("[%s] 拒絕回應洩漏了 %q——位址與清單只准進審計，"+
				"回應只有「此來源不允許」。body=%s", point, leak, body)
		}
	}
}

// assertNotSourceDenied 放行側的斷言：**不是**來源拒絕。
//
// 刻意不斷言 200：有些點在放行後仍可能因其他原因失敗（例如密碼政策），
// 那與本閘無關。要證明的只有「這一格沒有被來源閘擋下」。
func assertNotSourceDenied(t *testing.T, point string, w *httptest.ResponseRecorder) {
	t.Helper()
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if got, _ := resp["code"].(string); got == string(apierror.CodeAuthSourceNotAllowed) {
		t.Fatalf("[%s] 被來源閘擋下，但本格的清單應放行：status=%d body=%s",
			point, w.Code, w.Body.String())
	}
}

// gateWebPoint 一個 web 判定點。
type gateWebPoint struct {
	// name 形如 "#5 MFA 完成 → 正式會話"，前綴為盤點表的列編號
	name string
	// exec 在指定的清單狀態下打一次該端點
	exec func(t *testing.T, e *refreshCookieEnv) *httptest.ResponseRecorder
}

// gateWebPoints 盤點表 #1–#19 中**由 web handler 承擔**的判定點。
//
// #9（refresh）走服務層交易內判定，形狀不同（零寫入、不消耗憑證），
// 由 TestRefreshSourceDeniedDoesNotConsumeToken 單獨驗；此處不列。
func gateWebPoints() []gateWebPoint {
	return []gateWebPoint{
		{"#1/#3/#4 密碼登入（正式會話與受限票證）", execGateLogin},
		{"#5/#13 MFA 完成 → 正式會話", execGateMFAVerify},
		{"#6/#12 強制註冊完成 → 正式會話", execGateMFAEnrollConfirm},
		{"#7/#10 /auth/change-password", execGateChangePassword},
		{"#8 OIDC exchange", execGateOIDCExchange},
		{"#11 /auth/mfa/enroll/setup", execGateMFAEnrollSetup},
		{"#14 /auth/mfa/setup", execGateMFASetup},
		{"#15 /auth/mfa/enable", execGateMFAEnable},
		{"#16 /auth/mfa/disable", execGateMFADisable},
		{"#17 POST /users/:id/mfa/disable", execGateAdminDisableMFA},
		{"#18 PUT /users/:id/password", execGateAdminChangePassword},
		{"#19 POST /users/:id/unlock", execGateAdminUnlock},
	}
}

func TestSourceGateWebPointsThreeStates(t *testing.T) {
	points := gateWebPoints()
	// 盤點表列 21 個點：18 判、3 類明列不判。18 判之中 refresh（#9）在服務層，
	// 其餘由 12 個 handler 函式承擔（多個編號共用同一次判定，見表的「同一請求，判一次」）
	if len(points) != 12 {
		t.Fatalf("web 判定點表長度 = %d，want 12（盤點表 #1–#19 扣掉服務層的 #9）", len(points))
	}
	states := []struct {
		name   string
		policy string
		denied bool
	}{
		{"空清單＝不限", "", false},
		{"來源在清單內", gateSourceInside, false},
		{"來源在清單外", gateSourceOutside, true},
	}
	for _, p := range points {
		for _, st := range states {
			t.Run(p.name+"／"+st.name, func(t *testing.T) {
				e := setupRefreshCookieEnv(t)
				e.useRealSourcePolicy()
				e.setSourcePolicy(t, st.policy)
				w := p.exec(t, e)
				if st.denied {
					assertSourceDenied(t, p.name, w)
					return
				}
				assertNotSourceDenied(t, p.name, w)
			})
		}
	}
}

// --- 各點的執行器（清單狀態已由呼叫端設好） ---

func execGateLogin(t *testing.T, e *refreshCookieEnv) *httptest.ResponseRecorder {
	return e.post(t, "/api/v1/auth/login", e.h.Login, map[string]string{
		"username": e.user.Username, "password": refreshCookieGuardPassword,
	}, "")
}

func execGateMFAVerify(t *testing.T, e *refreshCookieEnv) *httptest.ResponseRecorder {
	e.enableTOTP(t)
	first, err := e.auth.Login(&identity.LoginRequest{
		Username: e.user.Username, Password: refreshCookieGuardPassword})
	if err != nil || first.PendingToken == "" {
		t.Fatalf("前提不成立：應進入 MFA 第二階段，err=%v resp=%+v", err, first)
	}
	code, err := totp.GenerateCode(e.totpSecret, time.Now())
	if err != nil {
		t.Fatalf("TOTP code: %v", err)
	}
	return e.post(t, "/api/v1/auth/mfa/verify", e.h.MFAVerify, map[string]string{
		"pending_token": first.PendingToken, "code": code,
	}, "")
}

// gateEnrollmentToken 造一張合法的 enrollment 票證（強制註冊流程）。
//
// **票證於清單設定前取得**：判定落在「票證已驗、狀態未寫」之間，
// 若連票證都拿不到就測不到那一段。真實情境同形——管理者可能在使用者拿到
// 票證之後才收緊清單。
func gateEnrollmentToken(t *testing.T, e *refreshCookieEnv) string {
	t.Helper()
	saved := e.currentSourcePolicy(t)
	e.setSourcePolicy(t, "")
	e.policies.Update(policy.PolicyMFARequired, policy.MFARequiredAll, "admin")
	first, err := e.auth.Login(&identity.LoginRequest{
		Username: e.user.Username, Password: refreshCookieGuardPassword})
	if err != nil || first.EnrollmentToken == "" {
		t.Fatalf("前提不成立：應進入強制註冊流程，err=%v resp=%+v", err, first)
	}
	e.setSourcePolicy(t, saved)
	return first.EnrollmentToken
}

// currentSourcePolicy 讀回目前的儲存字串（票證取得前後需還原清單狀態）
func (e *refreshCookieEnv) currentSourcePolicy(t *testing.T) string {
	t.Helper()
	var row model.User
	if err := e.db.Select("allowed_cidrs").First(&row, e.user.ID).Error; err != nil {
		t.Fatalf("read allowed_cidrs: %v", err)
	}
	return row.AllowedCIDRs
}

func execGateMFAEnrollSetup(t *testing.T, e *refreshCookieEnv) *httptest.ResponseRecorder {
	token := gateEnrollmentToken(t, e)
	return e.post(t, "/api/v1/auth/mfa/enroll/setup", e.h.MFAEnrollSetup,
		map[string]string{}, token)
}

func execGateMFAEnrollConfirm(t *testing.T, e *refreshCookieEnv) *httptest.ResponseRecorder {
	token := gateEnrollmentToken(t, e)
	saved := e.currentSourcePolicy(t)
	e.setSourcePolicy(t, "")
	setup, err := e.auth.EnrollmentSetup(token)
	if err != nil {
		t.Fatalf("EnrollmentSetup: %v", err)
	}
	e.setSourcePolicy(t, saved)
	code, err := totp.GenerateCode(setup.Secret, time.Now())
	if err != nil {
		t.Fatalf("TOTP code: %v", err)
	}
	return e.post(t, "/api/v1/auth/mfa/enroll/confirm", e.h.MFAEnrollConfirm,
		map[string]string{"code": code}, token)
}

func execGateChangePassword(t *testing.T, e *refreshCookieEnv) *httptest.ResponseRecorder {
	token := e.gateSessionToken(t)
	return e.post(t, "/api/v1/auth/change-password", e.h.ChangePassword, map[string]string{
		"old_password": refreshCookieGuardPassword, "new_password": refreshCookieGuardNewPw,
	}, token)
}

func execGateOIDCExchange(t *testing.T, e *refreshCookieEnv) *httptest.ResponseRecorder {
	ticket := e.issueTicket(t)
	return e.post(t, "/api/v1/auth/oidc/exchange", e.oidc.Exchange,
		map[string]string{"ticket": ticket}, "")
}

// gateSessionToken 取一張正式 access token（登入路徑本身不受本次清單影響：
// 服務層的 Login 不判來源，判定在 handler）
func (e *refreshCookieEnv) gateSessionToken(t *testing.T) string {
	t.Helper()
	resp, err := e.auth.Login(&identity.LoginRequest{
		Username: e.user.Username, Password: refreshCookieGuardPassword})
	if err != nil || resp.Token == "" {
		t.Fatalf("前提不成立：登入未取得正式 token，err=%v resp=%+v", err, resp)
	}
	return resp.Token
}

// authenticated 打一個掛在「已認證」脈絡下的端點（模擬 AuthMiddleware 已設好 context）
func (e *refreshCookieEnv) authenticated(t *testing.T, method, path string,
	handler gin.HandlerFunc, actorID uint, payload any, params map[string]string,
) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Handle(method, path, func(c *gin.Context) {
		c.Set("userID", actorID)
		c.Set("username", e.user.Username)
		handler(c)
	})
	body, _ := json.Marshal(payload)
	target := path
	for k, v := range params {
		target = strings.ReplaceAll(target, ":"+k, v)
	}
	req := httptest.NewRequest(method, target, strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.5:41000"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func execGateMFASetup(t *testing.T, e *refreshCookieEnv) *httptest.ResponseRecorder {
	return e.authenticated(t, http.MethodPost, "/api/v1/auth/mfa/setup",
		e.h.MFASetup, e.user.ID, map[string]string{}, nil)
}

func execGateMFAEnable(t *testing.T, e *refreshCookieEnv) *httptest.ResponseRecorder {
	return e.authenticated(t, http.MethodPost, "/api/v1/auth/mfa/enable",
		e.h.MFAEnable, e.user.ID, map[string]string{"code": "000000"}, nil)
}

func execGateMFADisable(t *testing.T, e *refreshCookieEnv) *httptest.ResponseRecorder {
	return e.authenticated(t, http.MethodPost, "/api/v1/auth/mfa/disable",
		e.h.MFADisable, e.user.ID, map[string]string{"password": refreshCookieGuardPassword}, nil)
}

func execGateAdminDisableMFA(t *testing.T, e *refreshCookieEnv) *httptest.ResponseRecorder {
	target := e.seedTargetUser(t)
	return e.authenticated(t, http.MethodPost, "/api/v1/users/:id/mfa/disable",
		e.h.AdminDisableMFA, e.user.ID, map[string]string{},
		map[string]string{"id": uintToStr(target.ID)})
}

func execGateAdminChangePassword(t *testing.T, e *refreshCookieEnv) *httptest.ResponseRecorder {
	target := e.seedTargetUser(t)
	return e.authenticated(t, http.MethodPut, "/api/v1/users/:id/password",
		e.gateUserHandler().ChangePassword, e.user.ID,
		map[string]string{"password": refreshCookieGuardNewPw},
		map[string]string{"id": uintToStr(target.ID)})
}

func execGateAdminUnlock(t *testing.T, e *refreshCookieEnv) *httptest.ResponseRecorder {
	target := e.seedTargetUser(t)
	return e.authenticated(t, http.MethodPost, "/api/v1/users/:id/unlock",
		e.gateUserHandler().Unlock, e.user.ID, map[string]string{},
		map[string]string{"id": uintToStr(target.ID)})
}

// seedTargetUser 造一個「被操作的對象」帳號（管理者三個端點的目標）。
//
// **目標帳號自身不設清單**：本組要證明的是判定依據為**操作者**的清單，
// 目標的清單不參與——被救援的帳號往往正因來源受限而進不來。
func (e *refreshCookieEnv) seedTargetUser(t *testing.T) *model.User {
	t.Helper()
	u := &model.User{
		Username: "gate-target", Password: "x", Active: true,
		ProvisioningOrigin: model.AuthSourceLocal,
	}
	if err := e.db.Create(u).Error; err != nil {
		t.Fatalf("seed target: %v", err)
	}
	return u
}

// gateUserHandler 使用者管理 handler（讀真實的清單欄）
func (e *refreshCookieEnv) gateUserHandler() *UserHandler {
	users := identity.NewUserService(e.db, authz.NewAssetAuthorizationService(e.db))
	users.SetSecurityPolicies(e.policies)
	h := NewUserHandler(users)
	h.SetSourcePolicyReader(e.auth)
	return h
}

// --- 情境格：表格驗不到的那些 ---

// TestSourceGateMFAFirstStageDoesNotDiverge 盤點表 #2：密碼通過但 MFA 未完成的
// 第一階段回應，在清單內與清單外**逐字相同**。
//
// 提前判定會給持有密碼但無第二因素者一個「這個帳號的來源政策長怎樣」的訊號
// ——他還沒證明自己是本人。
func TestSourceGateMFAFirstStageDoesNotDiverge(t *testing.T) {
	run := func(policyRaw string) (int, string) {
		e := setupRefreshCookieEnv(t)
		e.useRealSourcePolicy()
		e.enableTOTP(t)
		e.setSourcePolicy(t, policyRaw)
		w := execGateLogin(t, e)
		// pending_token 每次不同，比對前抹去（判定依據是「形狀」而非隨機值）
		return w.Code, gateStripVolatile(w.Body.String())
	}
	insideCode, inside := run(gateSourceInside)
	outsideCode, outside := run(gateSourceOutside)
	if insideCode != http.StatusOK || outsideCode != http.StatusOK {
		t.Fatalf("MFA 第一階段兩側都應 200：inside=%d outside=%d", insideCode, outsideCode)
	}
	if inside != outside {
		t.Fatalf("MFA 第一階段回應在清單內外分歧——持有密碼但無第二因素者因此探知來源政策：\n"+
			"清單內=%s\n清單外=%s", inside, outside)
	}
}

// gateStripVolatile 抹去回應中每次不同的隨機欄（token 類），只留形狀
func gateStripVolatile(body string) string {
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		return body
	}
	for _, k := range []string{"pending_token", "enrollment_token", "token", "change_token"} {
		if _, ok := m[k]; ok {
			m[k] = "<redacted>"
		}
	}
	out, err := json.Marshal(m)
	if err != nil {
		return body
	}
	return string(out)
}

// TestSourceGateDeniedMatchesWrongPasswordShape 清單外＋憑證錯誤的回應，
// 與帳號不存在**逐字相同**。
//
// 憑證不成立時判定尚未發生（來源判定一律在憑證驗證之後），
// 故清單外的錯密碼不得比清單內的錯密碼多說任何一個字——否則就是一個
// 「這個帳號設了來源限制」的預言機，而且不需要知道密碼。
func TestSourceGateDeniedMatchesWrongPasswordShape(t *testing.T) {
	e := setupRefreshCookieEnv(t)
	e.useRealSourcePolicy()
	e.setSourcePolicy(t, gateSourceOutside)

	wrong := e.post(t, "/api/v1/auth/login", e.h.Login, map[string]string{
		"username": e.user.Username, "password": "definitely-not-the-password",
	}, "")
	missing := e.post(t, "/api/v1/auth/login", e.h.Login, map[string]string{
		"username": "no-such-user", "password": "definitely-not-the-password",
	}, "")

	if wrong.Code != missing.Code {
		t.Fatalf("清單外的錯密碼與帳號不存在狀態碼分歧：wrong=%d missing=%d", wrong.Code, missing.Code)
	}
	if wrong.Body.String() != missing.Body.String() {
		t.Fatalf("清單外的錯密碼與帳號不存在回應分歧（來源政策成為存在性預言機）：\n"+
			"錯密碼=%s\n不存在=%s", wrong.Body.String(), missing.Body.String())
	}
}

// TestSourceGateEnrollmentTicketNotIssuedFromOutside 盤點表 #3：
// 清單外的密碼登入不得拿到 enrollment 票證。
//
// 只擋正式會話是不夠的——受強制但尚無第二因素者，其密碼就是完整憑證，
// 拿到票證即可綁定第二因子並取得正式會話。
func TestSourceGateEnrollmentTicketNotIssuedFromOutside(t *testing.T) {
	e := setupRefreshCookieEnv(t)
	e.useRealSourcePolicy()
	e.policies.Update(policy.PolicyMFARequired, policy.MFARequiredAll, "admin")
	e.setSourcePolicy(t, gateSourceOutside)

	w := execGateLogin(t, e)
	assertSourceDenied(t, "#3 enrollment 票證發放", w)
	if strings.Contains(w.Body.String(), "enrollment_token") {
		t.Fatalf("清單外的登入仍回了 enrollment 票證：body=%s", w.Body.String())
	}
}

// TestSourceGateScopedTicketConsumptionFromOutside 盤點表 #11／#12：
// scoped 票證自清單外消費 → 403、**且狀態未變**（MFA 未啟用、無 secret 回傳、
// 無正式會話）。
//
// 票證在允許位址發出、換個位址來消費，是本閘與「只在發放點判」的差別所在。
func TestSourceGateScopedTicketConsumptionFromOutside(t *testing.T) {
	e := setupRefreshCookieEnv(t)
	e.useRealSourcePolicy()
	token := gateEnrollmentToken(t, e)
	e.setSourcePolicy(t, gateSourceOutside)

	setupResp := e.post(t, "/api/v1/auth/mfa/enroll/setup", e.h.MFAEnrollSetup,
		map[string]string{}, token)
	assertSourceDenied(t, "#11 enrollment setup 消費", setupResp)
	if strings.Contains(setupResp.Body.String(), "secret") ||
		strings.Contains(setupResp.Body.String(), "otpauth") {
		t.Fatalf("清單外的 enrollment setup 回了 TOTP 材料：body=%s", setupResp.Body.String())
	}

	confirmResp := e.post(t, "/api/v1/auth/mfa/enroll/confirm", e.h.MFAEnrollConfirm,
		map[string]string{"code": "000000"}, token)
	assertSourceDenied(t, "#12 enrollment confirm 消費", confirmResp)
	if findRefreshCookie(confirmResp) != nil {
		t.Fatal("清單外的 enrollment confirm 下發了 refresh cookie（等於發出正式會話）")
	}

	var after model.User
	if err := e.db.First(&after, e.user.ID).Error; err != nil {
		t.Fatalf("reload user: %v", err)
	}
	if after.TOTPEnabled {
		t.Fatal("清單外的票證消費把 MFA 啟用了——判定必須在狀態寫入之前")
	}
	if after.TOTPSecretEnc != "" {
		t.Fatal("清單外的票證消費寫入了 pending secret——判定必須在產生 secret 之前")
	}
}

// TestSourceGateFormalSessionWriteEndpointsBlockedButProfileWorks
// 盤點表 #10／#14–#16 與 #20 的邊界：正式會話下自清單外改密與 MFA 三端點被擋，
// 而**非認證因子**的 `PATCH /auth/me` 照常。
//
// 這一格是「範圍止於認證因子」這條原則的機器證據：擴到全部請求就等於
// AuthMiddleware 每請求判一次（非目標），縮到只有登入則改密與 MFA 全裸。
func TestSourceGateFormalSessionWriteEndpointsBlockedButProfileWorks(t *testing.T) {
	e := setupRefreshCookieEnv(t)
	e.useRealSourcePolicy()
	e.setSourcePolicy(t, gateSourceOutside)
	token := e.gateSessionToken(t)

	blocked := []struct {
		name string
		w    *httptest.ResponseRecorder
	}{
		{"#10 /auth/change-password", e.post(t, "/api/v1/auth/change-password",
			e.h.ChangePassword, map[string]string{
				"old_password": refreshCookieGuardPassword, "new_password": refreshCookieGuardNewPw,
			}, token)},
		{"#14 /auth/mfa/setup", execGateMFASetup(t, e)},
		{"#15 /auth/mfa/enable", execGateMFAEnable(t, e)},
		{"#16 /auth/mfa/disable", execGateMFADisable(t, e)},
	}
	for _, b := range blocked {
		assertSourceDenied(t, b.name, b.w)
	}

	// 狀態未變：密碼仍是舊的、MFA 仍未啟用
	if _, err := e.auth.Login(&identity.LoginRequest{
		Username: e.user.Username, Password: refreshCookieGuardPassword}); err != nil {
		t.Fatalf("清單外的改密請求改動了密碼（舊密碼已登不進去）：%v", err)
	}
	var after model.User
	if err := e.db.First(&after, e.user.ID).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	if after.TOTPEnabled || after.TOTPSecretEnc != "" {
		t.Fatal("清單外的 MFA 端點改動了因子狀態")
	}

	// 邊界另一側：非認證因子的自助更新照常
	profile := e.authenticated(t, http.MethodPatch, "/api/v1/auth/me", e.h.UpdateMe,
		e.user.ID, map[string]any{"local_display_name": "改個顯示名"}, nil)
	assertNotSourceDenied(t, "#20 PATCH /auth/me（明列不判）", profile)
	if profile.Code != http.StatusOK {
		t.Fatalf("PATCH /auth/me 應照常（非認證因子，明列不判），實得 %d：%s",
			profile.Code, profile.Body.String())
	}
}

// TestSourceGateAdminEndpointsUseOperatorPolicy 盤點表 #17–#19：
// 管理者自清單外對他人的三個認證因子端點 → 403，**且目標未變**。
//
// 判定依據是操作者本人的清單，不是目標的——後者會讓救援永遠做不成
// （被救援的帳號往往正因為來源受限而進不來）。
func TestSourceGateAdminEndpointsUseOperatorPolicy(t *testing.T) {
	e := setupRefreshCookieEnv(t)
	e.useRealSourcePolicy()
	e.setSourcePolicy(t, gateSourceOutside)

	target := e.seedTargetUser(t)
	lockUntil := time.Now().Add(time.Hour)
	if err := e.db.Model(&model.User{}).Where("id = ?", target.ID).
		Updates(map[string]any{"locked_until": lockUntil, "totp_enabled": true}).Error; err != nil {
		t.Fatalf("seed target state: %v", err)
	}
	before := gateLoadUser(t, e, target.ID)

	users := e.gateUserHandler()
	cases := []struct {
		name string
		w    *httptest.ResponseRecorder
	}{
		{"#17 POST /users/:id/mfa/disable", e.authenticated(t, http.MethodPost,
			"/api/v1/users/:id/mfa/disable", e.h.AdminDisableMFA, e.user.ID,
			map[string]string{}, map[string]string{"id": uintToStr(target.ID)})},
		{"#18 PUT /users/:id/password", e.authenticated(t, http.MethodPut,
			"/api/v1/users/:id/password", users.ChangePassword, e.user.ID,
			map[string]string{"password": refreshCookieGuardNewPw},
			map[string]string{"id": uintToStr(target.ID)})},
		{"#19 POST /users/:id/unlock", e.authenticated(t, http.MethodPost,
			"/api/v1/users/:id/unlock", users.Unlock, e.user.ID,
			map[string]string{}, map[string]string{"id": uintToStr(target.ID)})},
	}
	for _, c := range cases {
		assertSourceDenied(t, c.name, c.w)
	}

	after := gateLoadUser(t, e, target.ID)
	if after.Password != before.Password {
		t.Fatal("清單外的管理者改密改動了目標帳號的密碼")
	}
	if !after.TOTPEnabled {
		t.Fatal("清單外的管理者 MFA 重設改動了目標帳號的因子狀態")
	}
	if after.LockedUntil == nil {
		t.Fatal("清單外的管理者解鎖改動了目標帳號的鎖定狀態")
	}
}

func gateLoadUser(t *testing.T, e *refreshCookieEnv, id uint) model.User {
	t.Helper()
	var u model.User
	if err := e.db.First(&u, id).Error; err != nil {
		t.Fatalf("load user %d: %v", id, err)
	}
	return u
}

// TestSourceGateUnwiredReaderFailsClosed 讀取面未接線＝拒絕，**不是放行**。
//
// 一條漏接注入的組裝路徑不得讓整套來源限定靜默關掉。方向與世代閘
// `ErrEpochGateUnavailable` 同源。
func TestSourceGateUnwiredReaderFailsClosed(t *testing.T) {
	e := setupRefreshCookieEnv(t)
	e.h.SetSourcePolicyReader(nil)
	e.setSourcePolicy(t, "") // 清單為空：接線正常時本該放行
	assertSourceDenied(t, "讀取面未接線", execGateLogin(t, e))
}

// TestSourceGateCorruptPolicyIsNotTreatedAsEmpty 儲存字串損壞 → 拒絕。
//
// **不得視為空清單**：唯一寫入路徑是驗證後寫入，損壞只可能來自 DB 直寫或
// 程式缺陷；把它當「不限」等於限制設了卻靜默失效，而且沒有任何訊號。
// 對外與「來源不對」同一個碼——歸因只在審計（見 identity 側的失效面測試）。
func TestSourceGateCorruptPolicyIsNotTreatedAsEmpty(t *testing.T) {
	e := setupRefreshCookieEnv(t)
	e.useRealSourcePolicy()
	e.setSourcePolicy(t, gateSourceCorrupt)
	assertSourceDenied(t, "政策字串損壞", execGateLogin(t, e))
}
