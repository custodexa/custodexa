package identity_test

import (
	"context"
	"errors"
	"fmt"
	"github.com/custodexa/backend/internal/modules/identity"
	"sync"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
)

// provider 停用撤銷的七個驗證點矩陣（idp-oidc-integration tasks 4.11）。
//
// 與 oidc_provider_revocation_test.go 的分工：
//
//	該檔  「停用這個動作做了什麼」——五條管道（推進世代、撤 refresh、終斷會話、
//	      收線訂閱、撤錄影 token）與兩個並發交錯的序列化。
//	本檔  「停用之後每一類憑證還能不能用」——七個驗證點逐一被拒、**重新啟用後
//	      仍逐一被拒**、新登入正常，且混合帳號的本地會話不受牽連。
//
// 七個驗證點與其覆蓋位置（4.11 對照）：
//
//	(1) flow state           本檔（既有：oidc_callback_test.go 的停用／重新啟用兩支）
//	(2) ticket               本檔（既有：oidc_flow_test.go 的停用／重新啟用兩支）
//	(3) scoped pending       本檔（新增）
//	(4) access（中介層）      internal/middleware/oidc_epoch_gate_test.go（新增）
//	(5) access（WS ?token=）  本檔（新增）
//	(6) refresh              本檔（新增）
//	(7) connect grant        internal/sshproxy（既有：connect_generation_test.go 的停用案；
//	                          重新啟用案為新增：connect_generation_reenable_test.go）
//
// **為什麼一定要先輪替一次 refresh**：rotation 是唯一會「以既有憑證重新產生長效
// 憑證」的路徑，且它必須顯式沿用 AuthMethod／ProviderID／AuthEpoch／CredEpoch
// （auth_refresh_service.go 的 tx.Create）。若在登入後立刻停用，被撤銷的是登入當下
// 那一列，四個脈絡欄位漏帶與否完全不影響結果——測試恆綠而無效。輪替一次之後，
// 停用要撤到的是**新產生的那一列**，脈絡欄位漏帶即 provider_id 落 0，
// revokeRefreshTokensByProvider 命中 0 列，第 (6) 點立刻轉紅。

// oidcCapabilitySet 一組「停用前簽出、停用後應全數失效」的能力憑證。
//
// 每個 set 各用自己的使用者：TOTP 的已消耗 step 是 per-user 欄位，
// 共用使用者會使「若世代閘被拿掉，VerifyMFALogin 應該成功」退化為
// 「因為 step 重放所以還是失敗」——那樣拿掉閘也不會轉紅
type oidcCapabilitySet struct {
	tag       string
	user      *model.User
	access    string // 已經過一次 refresh 輪替換發的 access token
	refresh   string // 輪替後的 refresh 憑證
	ticket    string // 未兌換的交棒憑證
	state     string // 未完成的 flow state
	code      string // 對應的授權碼（已登錄於 fake IdP）
	challenge string // 該流程的 PKCE challenge
	mfaUser   *model.User
	pending   string // 未完成的 MFA pending token
}

const capabilityBrowserSecret = "browser-secret"

// newCapabilitySet 在 provider 仍啟用時備妥一整組能力憑證。
//
// 過程本身即為五個驗證點的**正向控制**：ticket 兌換成功、refresh 輪替成功、
// flow state 發起成功、pending token 簽出成功。少了這一段，後面的「全部被拒」
// 無法排除「其實這些路徑本來就不通」
func (e *oidcLifecycleEnv) newCapabilitySet(t *testing.T, tag string) *oidcCapabilitySet {
	t.Helper()
	s := &oidcCapabilitySet{tag: tag}

	s.user = e.seedIdentityUser(t, "alice-"+tag, "sub-"+tag, nil)

	// 登入：以交棒憑證兌換正式會話（正向控制之一）
	first := issueTestTicket(t, e.login, s.user, e.provider, capabilityBrowserSecret)
	resp, _, err := e.login.Exchange(first, capabilityBrowserSecret)
	if err != nil {
		t.Fatalf("[%s] 停用前的兌換應成功: %v", tag, err)
	}
	if resp.Token == "" || resp.RefreshToken == "" {
		t.Fatalf("[%s] 登入應同時發出 access 與 refresh", tag)
	}

	// **至少一次輪替**（見檔頭）：其後所有 access／refresh 斷言都打在輪替後的憑證上
	rotated, err := e.auth.RefreshSession(resp.RefreshToken)
	if err != nil {
		t.Fatalf("[%s] 停用前的刷新輪替應成功: %v", tag, err)
	}
	s.access, s.refresh = rotated.Token, rotated.RefreshToken

	// 輪替後那一列必須仍帶認證脈絡——這是「停用能撤到它」的前提，
	// 前提不成立時後面的斷言會因錯誤的理由變綠
	row := reloadRefresh(t, e.db, hashRefreshToken(s.refresh))
	if row.ProviderID != e.provider.ID || row.AuthMethod != crypto.AuthMethodOIDC {
		t.Fatalf("[%s] 輪替換發的 refresh 列遺失認證脈絡: provider_id=%d method=%q",
			tag, row.ProviderID, row.AuthMethod)
	}

	// 未兌換的交棒憑證（掃描既有連線管不到「尚未兌換」的能力憑證）
	s.ticket = issueTestTicket(t, e.login, s.user, e.provider, capabilityBrowserSecret)

	// 在途的授權流程：使用者已被導向 IdP，停用發生在 callback 回來之前
	nonce := ""
	s.state, nonce, s.challenge = beginFlowWithChallenge(t, e.login, e.provider, capabilityBrowserSecret)
	s.code = "code-" + tag
	e.idp.stageCode(s.code, e.idp.issueIDToken(t, idTokenOpts{
		subject: "sub-" + tag, audience: "test-client", nonce: nonce,
		extra: map[string]any{
			"hd": "corp.example", "preferred_username": "alice-" + tag,
		},
	}))

	// 第一因子已過、第二因子未完成的 scoped token
	s.mfaUser = e.seedMFAIdentityUser(t, "carol-"+tag, "sub-mfa-"+tag)
	mresp, err := e.auth.LoginWithExternalIdentity(s.mfaUser, e.oidcCtxFor(s.mfaUser))
	if err != nil {
		t.Fatalf("[%s] MFA 使用者的 OIDC 登入應進入第二階段: %v", tag, err)
	}
	if !mresp.MFARequired || mresp.PendingToken == "" {
		t.Fatalf("[%s] 應簽出 pending token，實得 %+v", tag, mresp)
	}
	s.pending = mresp.PendingToken

	return s
}

// assertCapabilitySetRejected 五個可於本層觀測的驗證點逐一被拒。
//
// 每一項的錯誤型別都寫死：只斷言「有錯」會讓 PKCE 不符、憑證過期之類的
// 無關失敗也算通過
func (e *oidcLifecycleEnv) assertCapabilitySetRejected(t *testing.T, s *oidcCapabilitySet, phase string) {
	t.Helper()

	// (1) flow state：在途授權完成回來。校準 PKCE 期望值，使「若閘被拿掉就會成功」
	// 成立——否則 callback 會因 challenge 被後續流程覆寫而失敗，變成假綠
	expectFlowChallenge(e.idp, s.challenge)
	if _, err := e.login.Callback(context.Background(), s.state, s.code); !errors.Is(err, identity.ErrOIDCProviderUnavailable) {
		t.Errorf("[%s] (1) flow state 完成 = %v, want identity.ErrOIDCProviderUnavailable", phase, err)
	}

	// (2) ticket：尚未兌換的交棒憑證
	if _, _, err := e.login.Exchange(s.ticket, capabilityBrowserSecret); !errors.Is(err, identity.ErrOIDCTicketInvalid) {
		t.Errorf("[%s] (2) ticket 兌換 = %v, want identity.ErrOIDCTicketInvalid", phase, err)
	}

	// (3) scoped pending：第一因子已過、尚未兌換為正式會話
	if _, err := e.auth.VerifyMFALogin(&identity.MFAVerifyRequest{
		PendingToken: s.pending, Code: validTestCode(t)}); !errors.Is(err, identity.ErrMFAPendingTokenInvalid) {
		t.Errorf("[%s] (3) MFA 完成 = %v, want identity.ErrMFAPendingTokenInvalid", phase, err)
	}

	// (5) access 的 WS `?token=` 旁路：/connect、/ssh、/sessions/:id/monitor 三個路由
	// 不掛 AuthMiddleware，中介層的世代比對救不到它們
	if _, err := e.auth.ValidateConnectionToken(s.access); !errors.Is(err, identity.ErrConnectionNotAuthorized) {
		t.Errorf("[%s] (5) WS 旁路 access = %v, want identity.ErrConnectionNotAuthorized", phase, err)
	}

	// (6) refresh
	if _, err := e.auth.RefreshSession(s.refresh); !errors.Is(err, identity.ErrRefreshInvalid) {
		t.Errorf("[%s] (6) refresh 輪替 = %v, want identity.ErrRefreshInvalid", phase, err)
	}
}

// Scenario: provider 停用後七個驗證點逐一被拒；重新啟用後仍逐一被拒（tasks 4.11）
func TestProviderDisableRejectsAllPointsAndReEnableDoesNotRevive(t *testing.T) {
	e := setupOIDCLifecycleEnv(t)

	// 兩組能力憑證：flow state 是一次性的（Callback 一進門就消費），
	// 停用階段用掉之後就沒有第二次可用於重新啟用階段
	afterDisable := e.newCapabilitySet(t, "x")
	afterReEnable := e.newCapabilitySet(t, "y")

	// 停用前的正向控制：WS 旁路此刻必須是通的（不消耗任何憑證，可安全先驗）
	if _, err := e.auth.ValidateConnectionToken(afterDisable.access); err != nil {
		t.Fatalf("停用前 WS 旁路應通過（前提不成立則後續斷言無意義）: %v", err)
	}

	baseEpoch := e.providerAuthEpoch(t)
	e.setProviderEnabled(t, false)
	if got := e.providerAuthEpoch(t); got <= baseEpoch {
		t.Fatalf("停用應推進 auth_epoch: %d → %d", baseEpoch, got)
	}
	e.assertCapabilitySetRejected(t, afterDisable, "停用後")

	// 重新啟用：enabled 已復原，僅靠布林檢查會全數放行——世代不回退才是擋住
	// 這個窗口的機制（純 stateless JWT 靠撤 refresh 救不了既簽的 access）
	disabledEpoch := e.providerAuthEpoch(t)
	e.setProviderEnabled(t, true)
	if p := reloadProvider(t, e.db, e.provider.ID); !p.Enabled {
		t.Fatal("provider 應已重新啟用（前提不成立則本階段無意義）")
	}
	if got := e.providerAuthEpoch(t); got < disabledEpoch {
		t.Fatalf("重新啟用不得回退 auth_epoch: %d → %d", disabledEpoch, got)
	}
	e.assertCapabilitySetRejected(t, afterReEnable, "重新啟用後")

	// 新登入正常：撤銷是針對既簽憑證，不得把 provider 變成永久不可用
	fresh := e.newCapabilitySet(t, "z")
	if _, err := e.auth.ValidateConnectionToken(fresh.access); err != nil {
		t.Errorf("重新啟用後的新登入應完全可用: %v", err)
	}
	expectFlowChallenge(e.idp, fresh.challenge)
	res, err := e.login.Callback(context.Background(), fresh.state, fresh.code)
	if err != nil {
		t.Errorf("重新啟用後的新授權流程應可完成: %v", err)
	} else if res.Ticket == "" {
		t.Error("重新啟用後的 callback 應簽出交棒憑證")
	}
}

// Scenario: 混合帳號的本地會話不受 provider 停用牽連（tasks 4.11）。
//
// 同一個帳號同時持有本地密碼與外部身分時，兩條路徑各自產生一組會話。
// 停用 provider 必須只切斷 OIDC 那一組——按帳號一刀切會把「以本地密碼登入」的
// 工作階段一併殺掉，而那組會話與被停用的 provider 毫無關係
func TestProviderDisableSparesHybridAccountLocalSession(t *testing.T) {
	e := setupOIDCLifecycleEnv(t)

	const password = "Str0ng-Passw0rd!x"
	// ProvisioningOrigin=local 且 ExternalCredential=false ⟹ IsExternal()==false，
	// 本地密碼路徑仍可用；同時綁一筆外部身分即構成混合帳號
	mixed := e.seedLocalUser(t, "mixed", password, nil)
	if err := e.db.Create(&model.UserExternalIdentity{
		UserID: mixed.ID, ProviderID: e.provider.ID,
		Issuer: e.provider.Issuer, ClientID: e.provider.ClientID, Subject: "sub-mixed",
	}).Error; err != nil {
		t.Fatalf("建立混合帳號的外部身分: %v", err)
	}
	if mixed.IsExternal() {
		t.Fatal("混合帳號須可走本地密碼路徑（前提不成立則本測試無意義）")
	}

	// 本地路徑的會話（authCtx.ProviderID = 0）
	localLogin, err := e.auth.Login(&identity.LoginRequest{Username: "mixed", Password: password})
	if err != nil {
		t.Fatalf("本地登入: %v", err)
	}
	if localLogin.Token == "" {
		t.Fatalf("本地登入應直接發正式 token，實得 %+v", localLogin)
	}
	localRotated, err := e.auth.RefreshSession(localLogin.RefreshToken)
	if err != nil {
		t.Fatalf("本地會話的刷新輪替: %v", err)
	}

	// OIDC 路徑的會話（同一個帳號）
	ticket := issueTestTicket(t, e.login, mixed, e.provider, capabilityBrowserSecret)
	oidcLogin, _, err := e.login.Exchange(ticket, capabilityBrowserSecret)
	if err != nil {
		t.Fatalf("OIDC 兌換: %v", err)
	}
	oidcRotated, err := e.auth.RefreshSession(oidcLogin.RefreshToken)
	if err != nil {
		t.Fatalf("OIDC 會話的刷新輪替: %v", err)
	}

	e.setProviderEnabled(t, false)

	// OIDC 那一組全滅
	if _, err := e.auth.ValidateConnectionToken(oidcRotated.Token); !errors.Is(err, identity.ErrConnectionNotAuthorized) {
		t.Errorf("OIDC 會話的 access = %v, want identity.ErrConnectionNotAuthorized", err)
	}
	if _, err := e.auth.RefreshSession(oidcRotated.RefreshToken); !errors.Is(err, identity.ErrRefreshInvalid) {
		t.Errorf("OIDC 會話的 refresh = %v, want identity.ErrRefreshInvalid", err)
	}

	// 本地那一組完全不受影響
	if _, err := e.auth.ValidateConnectionToken(localRotated.Token); err != nil {
		t.Errorf("本地會話的 access 不應被牽連: %v", err)
	}
	localAgain, err := e.auth.RefreshSession(localRotated.RefreshToken)
	if err != nil {
		t.Errorf("本地會話的 refresh 不應被牽連: %v", err)
	} else if localAgain.Token == "" {
		t.Error("本地會話應仍可換發 access")
	}
	// 撤銷成因落在 OIDC 那一列，本地列未被標記（provider_id=0 不是萬用字元）
	if row := reloadRefresh(t, e.db, hashRefreshToken(oidcRotated.RefreshToken)); row.RevokedAt == nil {
		t.Error("OIDC 會話的 refresh 列應已被撤銷")
	}
}

// --- 併發兌換洪水 vs 停用（tasks 4.11 的競態項；pg-gated） ---
//
// 既有的 TestPGConcurrentExchangeVsDisable 以同步點製造**單一**精確交錯，
// 驗的是「鎖有沒有被拿掉」。本測試補的是另一種形狀：不掛同步點、多個兌換同時
// 湧入、停用夾在中間發動——覆蓋的是「鎖存在但序列化不完整」時才會出現的殘留
// （例如某條路徑漏持 provider 鎖、或掃描與推進之間有窗口）。
//
// 不變量與交錯無關：停用完成後，該 provider 名下不得有任何 active 會話。
// 每一筆兌換的合法結局只有兩種——早於停用而落入掃描集合被終斷，或晚於停用被
// 鎖內世代重讀拒絕。故本測試不會因時序抖動而偽陽性。
//
// sqlite 不做此測試：單寫者引擎本身就提供了與 provider 鎖等價的互斥，
// 拿掉鎖也不會轉紅（見 oidc_provider_revocation_test.go 的說明）。
func TestPGConcurrentExchangeFloodVsDisable(t *testing.T) {
	env, dbA := newPGRaceEnv(t)
	dto := seedRevocationProvider(t, env, "cid-pg-flood")
	base := reloadProvider(t, env.db, dto.ID).AuthEpoch
	u := seedRevocationUser(t, dbA, "pgflood")

	newSession := func(tag string) *model.Session {
		assetID := uint(1)
		pid := dto.ID
		return &model.Session{
			SessionID: "sess-pg-flood-" + tag, UserID: u.ID, AssetID: &assetID,
			Protocol: model.ProtocolSSH, StartTime: time.Now(), AuthEpoch: base,
			AuthProviderID: &pid,
		}
	}
	redeem := func(s *model.Session) error {
		return env.sessions.CreateWithGenerationGuard(crypto.AuthContext{
			AuthMethod: crypto.AuthMethodOIDC, ProviderID: dto.ID,
			AuthEpoch: base, CredEpoch: 0,
		}, s)
	}

	// 第一波（停用之前完成）：這幾筆必然落在停用的掃描集合內。
	// 沒有這一波，洪水可能整批輸給停用而全數被世代閘拒——那樣的「零殘留」
	// 只證明了「一筆都沒建成」，對序列化毫無鑑別力
	const settled = 4
	settledIDs := make([]uint, 0, settled)
	for i := 0; i < settled; i++ {
		s := newSession(fmt.Sprintf("pre-%d", i))
		if err := redeem(s); err != nil {
			t.Fatalf("停用前的第 %d 筆兌換應成功: %v", i, err)
		}
		settledIDs = append(settledIDs, s.ID)
	}

	// 第二波：與停用同時湧入
	const flood = 8
	var wg sync.WaitGroup
	errs := make([]error, flood)
	for i := 0; i < flood; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = redeem(newSession(fmt.Sprintf("race-%d", i)))
		}(i)
	}
	// 停用於副本 B 發動（跨連線池＝跨後端副本，行程內 mutex 對此無效）
	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, err := env.svc.Update(dto.ID, &identity.OIDCProviderRequest{Enabled: boolPtr(false)}); err != nil {
			t.Errorf("停用: %v", err)
		}
	}()
	wg.Wait()

	// 不變量：停用完成後，該 provider 名下不得有任何 active 會話
	var lingering int64
	if err := dbA.Model(&model.Session{}).
		Where("auth_provider_id = ? AND status = ?", dto.ID, model.SessionStatusActive).
		Count(&lingering).Error; err != nil {
		t.Fatalf("統計殘留會話: %v", err)
	}
	if lingering != 0 {
		t.Fatalf("停用後仍有 %d 筆 active 會話殘留（createErrs=%v）——"+
			"洪水中至少一筆兌換既躲過掃描又躲過世代重讀，該連線建立後不再出示憑證，將永久存活",
			lingering, errs)
	}

	// 第一波確實是被停用掃描終斷的（而非「剛好沒建成」）
	for _, id := range settledIDs {
		var s model.Session
		if err := dbA.First(&s, id).Error; err != nil {
			t.Fatalf("重讀會話 %d: %v", id, err)
		}
		if s.EndReason != model.EndReasonAdminTerminate {
			t.Errorf("停用前建立的會話 %d 須被掃描終斷: status=%q end_reason=%q",
				id, s.Status, s.EndReason)
		}
	}
}
