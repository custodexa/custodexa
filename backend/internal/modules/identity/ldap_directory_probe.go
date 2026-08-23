package identity

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/custodexa/backend/internal/modules/policy"
	"log"
	"strconv"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/custodexa/backend/internal/model"
)

// LDAP 目錄設定的連線測試。
//
// 測的是**請求中的表單當下值**（先測後存），admin-only。四階梯，順序固定且
// 各階段可辨識：
//
//	(1) URL 文法＋出站位址政策＋撥號
//	(2) service bind
//	(3) 以 user_filter 對 base_dn 搜尋
//	(4) 回報比對筆數與屬性映射抽樣
//
// # 錯誤揭露的 oracle 收斂（設計三輪審查的核心裁決）
//
// 階梯設計本身即是 oracle：回「撥號失敗」＝埠關、回「bind 失敗」＝埠開。
// 要真降精度只能讓兩階段在回應與時間上不可分辨，那等於廢掉階梯。故裁決是
// **在階梯之內不再增加解析度**：
//
//   - bind 之後各階段失敗回專屬機器碼（除錯體驗的主要來源）。
//   - **撥號失敗只回單一「無法連線」碼**——不細分 DNS／逾時／拒絕／TLS。
//     細分等於把「該位址上跑的是什麼」的解析度直接送給呼叫端。
//   - 粗分類原因只寫入伺服端 operational log，需主機營運權限才能對照；
//     一般 admin 無從藉此提升掃描解析度。
//   - 失敗回應附 diagnostic_id：不透明關聯識別碼，**同一值同時出現於 API
//     回應、審計事件與 operational log 三處**，使「請提供畫面上的 ID」即可
//     由維運端查到真正原因，除錯體驗不因收斂而消失。
//
// 出站政策拒絕（egress_blocked）是唯一與「無法連線」分開的碼：它是**本地政策
// 判定**、實際連線從未發生，且封鎖範圍（loopback／link-local／metadata／
// multicast）是產品明文公告的常數——回它不揭露目標主機的任何狀態，卻能讓
// admin 立刻知道「這個位址本產品不允許」而非誤以為目錄掛了。
//
// # 殘餘面誠實記載
//
// egress 政策對 LDAP 刻意放行私有網段（目錄的常態位置就是內網），故本端點
// **未消除「內網埠掃」這件事本身**。殘餘面的收斂手段是：admin-only ＋ 成功
// 與失敗皆入審計 ＋ per-actor/per-target 限流（見 ldap_probe_limiter.go）。

const (
	// ldapProbeSizeLimit 搜尋筆數上限。達上限時回報語義為「至少 N 筆」——
	// 目錄可能有數萬人，測試只需回答「filter 是否對得上人」
	ldapProbeSizeLimit = 1000

	// ldapProbeBindPasswordMaxLen bind 密碼長度上限（欄位長度上限的最後一格：
	// 其餘欄位由 ValidateLDAPDirectoryInput 涵蓋，密碼因不落 DB 欄位而不在其內）
	ldapProbeBindPasswordMaxLen = 512
)

// ldapProbeStageTimeout 各階段逾時。
//
// **逾時誠實化**：dial／bind／search 各 5 秒，端點最壞約 15 秒。
// 不宣稱「context 封頂」——go-ldap 的阻塞呼叫不受 handler context 中止，
// 唯一能讓它返回的手段是主動關閉連線（見 ldapProbeRunStage）。
//
// 宣告為 var 而非 const **僅為讓測試能縮短等待**（逾時語義若要靠真的等 5 秒
// 才驗得到，就不會有人驗它）；生產路徑不改寫此值
var ldapProbeStageTimeout = ldapDialTimeout

// 階梯階段（靜態字串；3.1 據此對應三語文案，前端逐階段呈現）
const (
	LDAPTestStageDial   = "dial"
	LDAPTestStageBind   = "bind"
	LDAPTestStageSearch = "search"
)

// 階梯失敗碼（靜態字串，供 3.1 對應機器碼）。
//
// **恆不含撥號失敗的粗分類**（dns／timeout／refused／tls）——那是 operational
// log 的內容，不是回應的內容
const (
	// LDAPTestCodeConnectFailed 撥號失敗的**唯一**對外碼（見檔頭 oracle 收斂）
	LDAPTestCodeConnectFailed = "connect_failed"
	// LDAPTestCodeEgressBlocked 出站位址政策拒絕（本地判定，未發生實際連線）
	LDAPTestCodeEgressBlocked = "egress_blocked"
	// LDAPTestCodeBindPasswordMissing 無可用的 bind 密碼——本機即擋，
	// 不對目錄發出任何 bind 請求（空密碼被部分目錄視為匿名 bind 而回成功）
	LDAPTestCodeBindPasswordMissing = "bind_password_missing"
	// LDAPTestCodeBindFailed service bind 被目錄拒絕
	LDAPTestCodeBindFailed = "bind_failed"
	// LDAPTestCodeSearchFailed 搜尋失敗（base_dn 不存在、權限不足、filter 被拒等）
	LDAPTestCodeSearchFailed = "search_failed"
	// LDAPTestCodeStageTimeout 階段逾時（連線已主動關閉）
	LDAPTestCodeStageTimeout = "stage_timeout"
)

// ErrLDAPTestRateLimited 連線測試超出資源上限（3.1 對應 429）。
//
// **不揭露命中哪一道界線、不回 Retry-After**：那些數值會讓攻擊者精確地把
// 流量調到門檻之下持續消耗，而正當使用者只需要「稍後再試」
var ErrLDAPTestRateLimited = errors.New("LDAP 連線測試過於頻繁，請稍後再試")

// ErrLDAPTestStoredSettingsUnavailable 需沿用既存密碼但既存設定讀取／解密失敗。
//
// **不靜默改以空密碼測試**：那會讓 admin 得到「bind 失敗」而去查目錄權限，
// 真因卻是本地金鑰事故——與「故障不得偽裝為其他狀態」同一裁決
var ErrLDAPTestStoredSettingsUnavailable = errors.New("既存 LDAP 目錄設定讀取失敗，無法沿用既存 bind 密碼")

// ErrLDAPProbeStageTimeout 階段逾時的內部哨兵（不外洩為回應文案）
var errLDAPProbeStageTimeout = errors.New("LDAP 連線測試階段逾時")

// LDAPDirectoryTestRequest 連線測試請求：表單當下值（未儲存）。
//
// wire 欄名與 PUT 一致，使前端「同一份表單狀態送兩個端點」不需轉換
type LDAPDirectoryTestRequest struct {
	URL          string `json:"url"`
	BindDN       string `json:"bind_dn"`
	BaseDN       string `json:"base_dn"`
	UserFilter   string `json:"user_filter"`
	AttrEmail    string `json:"attr_email"`
	AttrFullName string `json:"attr_fullname"`

	// BindPassword 空＝在三條件全數成立時沿用既存（見 resolveTestBindPassword）
	BindPassword string `json:"bind_password"`
	// ClearBindPassword 表單上「清除密碼」已勾選但尚未存檔——此時**不沿用**
	ClearBindPassword bool `json:"clear_bind_password"`

	SkipTLSVerify bool `json:"skip_tls_verify"`
	// Enabled 表單當下的啟用開關。**不影響傳輸閘判定**（見 TestConnection），
	// 只入審計供事後對照
	Enabled bool `json:"enabled"`

	// RiskAcknowledged 傳輸風險確認聲明（欄名與存檔閘一致）
	RiskAcknowledged bool `json:"risk_acknowledged"`

	// Actor 操作者；由 handler 填入，不接受請求端指定
	Actor LDAPDirectoryActor `json:"-"`
}

// LDAPDirectoryTestStage 單一階段的結果
type LDAPDirectoryTestStage struct {
	Stage string `json:"stage"`
	OK    bool   `json:"ok"`
	// Code 失敗碼；成功時為空
	Code string `json:"code,omitempty"`
}

// LDAPDirectoryTestAttrSample 屬性映射抽樣（首筆 entry 的兩個映射屬性是否有值）。
//
// **只回布林、不回值**：抽樣的用途是回答「映射設對了嗎」，回實際值等於讓
// 連線測試變成免認證的目錄內容讀取管道
type LDAPDirectoryTestAttrSample struct {
	// Sampled 是否有可抽樣的 entry（比對筆數為 0 時為 false）
	Sampled         bool `json:"sampled"`
	EmailPresent    bool `json:"email_present"`
	FullNamePresent bool `json:"fullname_present"`
}

// LDAPDirectoryTestResult 階梯測試結果。
//
// 本結構於「測試確實執行過」時回傳（含失敗）；前置拒絕（驗證、傳輸閘、限流）
// 一律以 error 表達，由 3.1 對應 400／429
type LDAPDirectoryTestResult struct {
	Success bool                     `json:"success"`
	Stages  []LDAPDirectoryTestStage `json:"stages"`

	// FailedStage／Code 失敗時的定位；成功時為空
	FailedStage string `json:"failed_stage,omitempty"`
	Code        string `json:"code,omitempty"`
	// DiagnosticID 失敗時的不透明關聯識別碼（回應／審計／operational log 三處同值）
	DiagnosticID string `json:"diagnostic_id,omitempty"`

	// MatchedCount 比對到的使用者數；MatchedAtLeast 為真時語義是「至少 N 筆」
	MatchedCount   int  `json:"matched_count"`
	MatchedAtLeast bool `json:"matched_at_least"`

	AttrSample LDAPDirectoryTestAttrSample `json:"attr_sample"`

	// ReusedStoredPassword 本次是否沿用既存 bind 密碼（審計與 UI 皆需要——
	// 「測試成功但用的是舊密碼」與「用你剛填的密碼成功」是兩件事）
	ReusedStoredPassword bool `json:"reused_stored_password"`
	// Target 測試目標的 canonical origin（解析失敗時為空）
	Target string `json:"target"`
}

// ldapProbeConn 測試階梯用到的連線能力（*ldap.Conn 實作之）。
//
// 抽成介面**只為測試接縫**：階梯的分支語義（哪一階段失敗、失敗碼、是否沿用
// 密碼）必須能在無真實目錄的環境下逐格驗證，否則這些安全相關的分支只能靠
// 手測。生產路徑恆為 *ldap.Conn
type ldapProbeConn interface {
	Bind(username, password string) error
	Search(request *ldap.SearchRequest) (*ldap.SearchResult, error)
	SetTimeout(timeout time.Duration)
	Close() error
}

// ldapProbeRuntime 連線測試的執行期資源（撥號接縫與限流器）
type ldapProbeRuntime struct {
	// dial 撥號接縫。生產恆為 ldapProbeDefaultDial（收口於 LDAPEgressPolicy）
	dial func(rawURL string, skipTLSVerify bool, correlationID string) (ldapProbeConn, error)
	// limiter 資源上限（跨請求狀態，故掛在 runtime 而非每次呼叫新建）
	limiter *ldapProbeLimiter
}

// ldapProbeCurrentRuntime 現行執行期資源。
//
// package 層級單例（生產只有一個 LDAPDirectoryService，且限流的全域 in-flight
// 上限本就該是 process 級）。唯一改寫者是 _test.go，沿本檔案群既有的
// ldapDirectoryPreWriteHook 先例
var ldapProbeCurrentRuntime = newLDAPProbeRuntime()

// newLDAPProbeRuntime 生產用執行期資源
func newLDAPProbeRuntime() *ldapProbeRuntime {
	return &ldapProbeRuntime{
		dial:    ldapProbeDefaultDial,
		limiter: newLDAPProbeLimiter(ldapProbeLimits{}),
	}
}

// ldapProbeDefaultDial 生產撥號路徑：**收口於 LDAPEgressPolicy.DialURL**。
//
// 測試路徑不自建 dialer——自建即繞過 Control 接縫上的位址檢查，出站政策形同
// 不存在。政策每次現讀 env（成本為一次 os.Getenv），使允許清單的調整不需重啟
func ldapProbeDefaultDial(rawURL string, skipTLSVerify bool, correlationID string) (ldapProbeConn, error) {
	conn, err := NewLDAPEgressPolicyFromEnv().DialURL(rawURL, skipTLSVerify, correlationID)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// TestConnection 以請求中的表單當下值執行分階段連線測試。
//
// 回傳語義：
//   - err != nil：測試**未執行**（欄位驗證、傳輸閘、限流、既存設定不可讀）。
//   - err == nil：階梯已執行，結果（含失敗階段與碼）在 LDAPDirectoryTestResult。
//
// 判定順序刻意如此：
//
//	(1) 限流 → (2) 欄位長度與存檔驗證 → (3) 傳輸閘 → (4) 密碼取用 → (5) 階梯
//
// 限流排第一，因為它保護的資源包含後續每一步的副作用（含審計寫入）——把限流
// 放在拒絕路徑之後，等於讓「被拒絕的請求」成為審計儲存的放大器。
func (s *LDAPDirectoryService) TestConnection(ctx context.Context, req LDAPDirectoryTestRequest) (LDAPDirectoryTestResult, error) {
	rt := ldapProbeCurrentRuntime

	// 限流鍵需要目標身分，故先解析一次 URL。解析失敗不豁免限流（否則送壞 URL
	// 即可無限打）——此時目標鍵落在共用的 unparsed 桶。
	// **本次解析只供限流鍵**；下游一律用驗證產出的 validation.ParsedURL，
	// 維持「存檔驗證、端點比較、egress 輸入共用同一份解析結果」的不變式
	preParsed, _ := ParseLDAPURL(req.URL)
	target := preParsed.CanonicalOrigin()

	release, limitReason, ok := rt.limiter.acquire(ldapProbeActorKey(req.Actor), ldapProbeTargetKey(target))
	if !ok {
		// 限流事件只入 operational log，不入審計：審計寫入正是本界線要保護的
		// 資源之一，在此落審計等於把防護本身變成放大器
		log.Printf("[LDAPDirectoryTest] 限流拒絕 actor=%s target=%s limit=%s",
			ldapProbeActorKey(req.Actor), ldapProbeTargetKey(target), limitReason)
		return LDAPDirectoryTestResult{}, ErrLDAPTestRateLimited
	}
	defer release()

	// (1.5) 密碼輸入衝突：與存檔路徑**同一判定**，且必須在任何撥號之前。
	//
	// 兩個互斥意圖同時出現時，若比照「有填就用填的」而實際送出 bind，等於讓
	// clear_bind_password 這個明確意圖在測試路徑上完全失效——admin 勾了清除卻
	// 看到「測試成功」，而存檔後密碼已不存在。存檔路徑拒絕、測試路徑照跑，
	// 兩個端點對同一份表單狀態給出互相矛盾的裁決
	if req.BindPassword != "" && req.ClearBindPassword {
		s.auditTestRejected(req, target, LDAPRejectBindPasswordConflict, "", nil)
		return LDAPDirectoryTestResult{}, ErrLDAPBindPasswordConflict
	}

	// (2) 欄位長度上限：bind 密碼不落 DB 欄位，故不在存檔驗證的涵蓋內
	if len(req.BindPassword) > ldapProbeBindPasswordMaxLen {
		err := newLDAPFieldError("bind_password", LDAPFieldReasonTooLong)
		s.auditTestRejected(req, target, LDAPRejectValidation, ldapValidationDetail(err), nil)
		return LDAPDirectoryTestResult{}, err
	}

	// 以「啟用態」規則驗證：測試當下就會撥號、搜尋與讀屬性，欄位不齊全根本
	// 跑不完階梯。**HasBindPassword 傳 true 不是放水**——密碼的有無由階梯的
	// bind 階段回報（空密碼是 spec 明訂可執行的測試形態：改 URL 或勾選清除後
	// 不沿用既存密碼，此時仍應讓 admin 看到「卡在 bind」而非收到一則存檔錯誤）
	validation, err := ValidateLDAPDirectoryInput(LDAPDirectoryInput{
		Name:            "",
		URL:             req.URL,
		BindDN:          req.BindDN,
		BaseDN:          req.BaseDN,
		UserFilter:      req.UserFilter,
		AttrEmail:       req.AttrEmail,
		AttrFullName:    req.AttrFullName,
		SkipTLSVerify:   req.SkipTLSVerify,
		Enabled:         true,
		HasBindPassword: true,
	})
	if err != nil {
		s.auditTestRejected(req, validation.ParsedURL.CanonicalOrigin(),
			LDAPRejectValidation, ldapValidationDetail(err), nil)
		return LDAPDirectoryTestResult{}, err
	}
	input := validation.Input
	endpoint := validation.ParsedURL
	target = endpoint.CanonicalOrigin()

	// (3) 傳輸閘：與存檔閘同一判定語義與請求欄名（strict 拒測、warn 缺確認即拒、
	// 帶確認則放行並留痕）。
	//
	// **風險判定強制以 Enabled=true 計算，不受請求的 enabled 值限縮**：
	// 存檔閘只在「儲存後啟用」時生效，是因為停用的設定不會撥號；但測試端點
	// **當下就會撥號並送出 bind 密碼**。若比照存檔閘，admin 只要把表單的啟用
	// 開關關掉，就能在 strict 檔位下照樣把 service bind 憑證以明文送上網路——
	// 這正是「測試端點須過閘」要堵的洞原樣復活。
	risks := policy.LDAPRisksOf(policy.LDAPRiskView{Enabled: true, URL: input.URL, SkipTLSVerify: input.SkipTLSVerify})
	// **閘缺席 fail-close**：測試端點當下就會把 bind 密碼送上網路，nil 閘若視為
	// 放行，一個漏掉的 setter 就等於 strict 檔位在此端點完全不存在
	if s.gate == nil {
		log.Print("[LDAPDirectoryTest] 傳輸政策閘未接線，拒絕測試（fail-close）")
		s.auditTestRejected(req, target, LDAPRejectTransmissionGateUnavailable, "", risks)
		return LDAPDirectoryTestResult{}, ErrLDAPTransmissionGateUnavailable
	}
	if gateErr := s.gate.CheckSettingSave(policy.TransportChannelLDAP, risks, req.RiskAcknowledged); gateErr != nil {
		detail := ""
		var typed *policy.TransmissionGateError
		if errors.As(gateErr, &typed) {
			detail = typed.Code
		}
		s.auditTestRejected(req, target, LDAPRejectTransmissionGate, detail, risks)
		return LDAPDirectoryTestResult{}, gateErr
	}

	// (4) 密碼取用
	password, reused, err := s.resolveTestBindPassword(ctx, req, endpoint)
	if err != nil {
		return LDAPDirectoryTestResult{}, err
	}

	// (5) 階梯
	result := rt.probeLadder(input, endpoint, password, ldapProbeDiagnosticID())
	result.ReusedStoredPassword = reused
	s.auditTestOutcome(req, result, risks)
	return result, nil
}

// resolveTestBindPassword 決定本次測試使用的 bind 密碼。
//
// **三條件缺一不可**，全部成立才代入既存密碼：
//
//  1. 請求密碼為空（有填就用填的，不查 DB）；
//  2. 請求 URL 與既存列的 **canonical origin 相等**——否則等於把既存的 service
//     bind 憑證送往另一台伺服器（憑證外送不變式，測試路徑同樣適用）；
//  3. 請求**未帶** clear_bind_password——admin 勾了清除但尚未存檔就按測試，
//     若仍沿用即將被清除的密碼會回報成功，存檔後卻實際不可用，測試結果誤導。
//
// 三條件任一不成立即以空密碼測試（階梯會停在 bind 階段並明確回報）。
//
// # 判定順序：先證明同源，才解密
//
// 三條件的檢查順序不是風格問題。**解密是有副作用的一步**——它把既存的 bind
// 明文具現化到本次呼叫棧，且會因密文損壞而失敗。若先解密再比對端點：
//
//   - 既存密文損壞時，admin 想測試**另一個**端點也會被 stored_settings_unavailable
//     擋下——但該路徑本來就不會沿用既存密碼，密文可不可解與這次測試無關。
//     金鑰事故因此連帶癱瘓「換一台目錄重新設定」這條復原路徑。
//   - 即使最終判定不沿用，明文仍已被不必要地取出。
//
// 故改為單次讀取列後**先**比較 canonical origin 與密文存在性，只有確定同源且
// 需沿用時才解密。DB 讀取錯誤仍回 stored_settings_unavailable（那確實表示
// 「無從判定要不要沿用」）
func (s *LDAPDirectoryService) resolveTestBindPassword(
	ctx context.Context, req LDAPDirectoryTestRequest, endpoint LDAPEndpoint,
) (password string, reused bool, err error) {
	if req.BindPassword != "" {
		return req.BindPassword, false, nil
	}
	if req.ClearBindPassword {
		return "", false, nil
	}
	if s == nil || s.db == nil {
		log.Print("[LDAPDirectoryTest] 目錄服務未接線，無法判定密碼沿用（fail-close）")
		return "", false, ErrLDAPTestStoredSettingsUnavailable
	}

	// 單次讀取列——不走 ResolveDialSnapshot（那會連帶解密）
	row, rerr := ldapDirectoryLiveRow(s.db)
	if rerr != nil {
		// 讀取失敗：不靜默降級為空密碼測試（見哨兵註解）
		log.Printf("[LDAPDirectoryTest] 既存設定讀取失敗，無法判定密碼沿用: %v", rerr)
		return "", false, ErrLDAPTestStoredSettingsUnavailable
	}
	if row == nil || row.BindPasswordEnc == "" {
		// 無列或無既存密碼：沒有東西可沿用，密文是否可解無從談起
		return "", false, nil
	}
	// 既存 URL 無法解析時 ldapSameStoredEndpoint 回 false
	// ——證明不了同源就不沿用（fail-close），且**不解密**
	if !ldapSameStoredEndpoint(row.URL, endpoint) {
		return "", false, nil
	}

	// 至此才確定「需要沿用」：解密的失敗此刻才真正阻斷本次測試
	stored, derr := s.decryptBindPassword(ctx, row.BindPasswordEnc)
	if derr != nil {
		// derr 恆為靜態哨兵（底層錯誤已於 decryptBindPassword 淨化）
		log.Printf("[LDAPDirectoryTest] 既存 bind 密碼不可解，無法沿用 directory_id=%d", row.ID)
		return "", false, ErrLDAPTestStoredSettingsUnavailable
	}
	if stored == "" {
		return "", false, nil
	}
	return stored, true, nil
}

// probeLadder 執行四階梯。任一階段失敗即停止並回報該階段
func (rt *ldapProbeRuntime) probeLadder(
	input LDAPDirectoryInput, endpoint LDAPEndpoint, password, diagnosticID string,
) LDAPDirectoryTestResult {
	result := LDAPDirectoryTestResult{Target: endpoint.CanonicalOrigin()}

	// ── 階段 1：URL 文法（已於前置驗證通過）＋出站位址政策＋撥號 ──
	conn, err := rt.dial(input.URL, input.SkipTLSVerify, diagnosticID)
	if err != nil {
		// **撥號失敗只回單一碼**（見檔頭）：粗分類寫入 operational log。
		// 出站政策拒絕是唯一例外——本地判定、未發生實際連線
		code := LDAPTestCodeConnectFailed
		if errors.Is(err, ErrLDAPEgressBlocked) {
			code = LDAPTestCodeEgressBlocked
		}
		logLDAPProbeFailure(diagnosticID, LDAPTestStageDial, result.Target,
			string(classifyLDAPDialError(err)))
		return result.fail(LDAPTestStageDial, code, diagnosticID)
	}
	defer conn.Close()
	conn.SetTimeout(ldapProbeStageTimeout)
	result.pass(LDAPTestStageDial)

	// ── 階段 2：service bind ──
	if password == "" {
		// 本機即擋，不對目錄發出任何 bind 請求：部分目錄把空密碼視為匿名 bind
		// 而回成功，送出去只會得到一個誤導的「測試通過」
		logLDAPProbeFailure(diagnosticID, LDAPTestStageBind, result.Target, "no_credentials")
		return result.fail(LDAPTestStageBind, LDAPTestCodeBindPasswordMissing, diagnosticID)
	}
	if err := ldapProbeRunStage(conn, func() error { return conn.Bind(input.BindDN, password) }); err != nil {
		code := LDAPTestCodeBindFailed
		if errors.Is(err, errLDAPProbeStageTimeout) {
			code = LDAPTestCodeStageTimeout
		}
		logLDAPProbeFailure(diagnosticID, LDAPTestStageBind, result.Target, ldapProbeResultClass(err))
		return result.fail(LDAPTestStageBind, code, diagnosticID)
	}
	result.pass(LDAPTestStageBind)

	// ── 階段 3：以 user_filter 對 base_dn 搜尋 ──
	//
	// **全系統唯一不經 ldap.EscapeFilter 的 `%s` 展開**：測試要回答「這個
	// filter 對得到多少人」，故以未轉義的萬用字元 `*` 展開。登入路徑不受影響
	// ——該路徑恆走 EscapeFilter（ldap_authenticator.go 的 searchUser），且此處
	// 展開的是常數 `*` 而非任何請求端輸入，filter 模板本身已於前置驗證通過
	// 兩層檢查（`%s` 恰一次、無其他 verb、placeholder 非 OR／NOT 之下）
	searchReq := ldap.NewSearchRequest(
		input.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		ldapProbeSizeLimit, int(ldapProbeStageTimeout.Seconds()), false,
		fmt.Sprintf(input.UserFilter, "*"),
		[]string{input.AttrEmail, input.AttrFullName},
		nil,
	)
	// EnforceSizeLimit：由客戶端自行封頂，不倚賴目錄是否遵守 SizeLimit——
	// 資源上限若取決於對端的善意就不是上限
	searchReq.EnforceSizeLimit = true

	var searchResult *ldap.SearchResult
	err = ldapProbeRunStage(conn, func() error {
		var serr error
		searchResult, serr = conn.Search(searchReq)
		return serr
	})
	capped := false
	if err != nil {
		if isLDAPProbeSizeLimit(err) {
			// 達上限不是失敗：語義轉為「至少 N 筆」
			capped = true
		} else {
			code := LDAPTestCodeSearchFailed
			if errors.Is(err, errLDAPProbeStageTimeout) {
				code = LDAPTestCodeStageTimeout
			}
			logLDAPProbeFailure(diagnosticID, LDAPTestStageSearch, result.Target, ldapProbeResultClass(err))
			return result.fail(LDAPTestStageSearch, code, diagnosticID)
		}
	}
	result.pass(LDAPTestStageSearch)

	// ── 階段 4：比對筆數與屬性映射抽樣 ──
	var entries []*ldap.Entry
	if searchResult != nil {
		entries = searchResult.Entries
	}
	result.MatchedCount = len(entries)
	result.MatchedAtLeast = capped || result.MatchedCount >= ldapProbeSizeLimit
	if len(entries) > 0 {
		first := entries[0]
		result.AttrSample = LDAPDirectoryTestAttrSample{
			Sampled:         true,
			EmailPresent:    first.GetAttributeValue(input.AttrEmail) != "",
			FullNamePresent: first.GetAttributeValue(input.AttrFullName) != "",
		}
	}
	result.Success = true
	return result
}

// pass 記錄一個成功階段
func (r *LDAPDirectoryTestResult) pass(stage string) {
	r.Stages = append(r.Stages, LDAPDirectoryTestStage{Stage: stage, OK: true})
}

// fail 記錄失敗階段並收斂結果（回值形式便於階梯內直接 return）
func (r LDAPDirectoryTestResult) fail(stage, code, diagnosticID string) LDAPDirectoryTestResult {
	r.Stages = append(r.Stages, LDAPDirectoryTestStage{Stage: stage, OK: false, Code: code})
	r.Success = false
	r.FailedStage = stage
	r.Code = code
	r.DiagnosticID = diagnosticID
	return r
}

// ldapProbeRunStage 以階段逾時執行一次阻塞呼叫。
//
// go-ldap 的 Bind／Search 是阻塞呼叫且**不受 handler context 中止**；逾時的
// 唯一正解是主動關閉連線讓它返回（同時立刻歸還 socket）。goroutine 於 Close
// 後隨即返回並寫入緩衝 channel，不外洩
func ldapProbeRunStage(conn ldapProbeConn, fn func() error) error {
	done := make(chan error, 1)
	go func() { done <- fn() }()

	timer := time.NewTimer(ldapProbeStageTimeout)
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-timer.C:
		_ = conn.Close()
		return errLDAPProbeStageTimeout
	}
}

// isLDAPProbeSizeLimit 是否為「達筆數上限」——客戶端自行封頂與目錄回報
// sizeLimitExceeded 兩種形態都算
func isLDAPProbeSizeLimit(err error) bool {
	return errors.Is(err, ldap.ErrSizeLimitExceeded) ||
		ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded)
}

// ldapProbeResultClass bind／search 失敗的粗分類（**僅供 operational log**）。
//
// 目錄回傳的 LDAP result code 對排錯極有價值（49=憑證錯、32=base_dn 不存在、
// 50=權限不足），但同樣不進 API 回應——bind 之後的階段已由專屬機器碼定位，
// 再回 result code 只是多給一份目錄內部狀態
func ldapProbeResultClass(err error) string {
	if err == nil {
		return "none"
	}
	if errors.Is(err, errLDAPProbeStageTimeout) {
		return "stage_timeout"
	}
	var ldapErr *ldap.Error
	if errors.As(err, &ldapErr) {
		return "ldap_result_" + strconv.FormatUint(uint64(ldapErr.ResultCode), 10)
	}
	return "other"
}

// logLDAPProbeFailure 失敗事件的 operational log。
//
// **diagnostic_id 三處同值的第三處**（另兩處為 API 回應與審計事件）：粗分類
// 原因只出現在這裡，需主機營運權限才看得到。不記密碼、密文與 socket 細節。
//
// # 為什麼不收 error
//
// LDAP 端點的 diagnostic message 是**對端可控的自由文字**，且部分實作會在
// bind 失敗的訊息中回顯收到的憑證。把原始錯誤格式化進日誌，等於讓一個惡意或
// 異常的目錄端點只要回顯密碼，就能把 service bind 明文寫進我方伺服器日誌
// ——而該日誌的存取面遠大於密文本身。
//
// 排錯所需的資訊全部由**我方產生的靜態值**承擔：class 是本地分類器的固定字串
// （撥號側 classifyLDAPDialError、bind／search 側 ldapProbeResultClass 的
// `ldap_result_<數值>`），stage／target／diagnostic_id 同理。要看對端原文，
// 走封包擷取或目錄自身的日誌，不經由本管道
func logLDAPProbeFailure(diagnosticID, stage, target, class string) {
	log.Printf("[LDAPDirectoryTest] 階梯失敗 diagnostic_id=%s stage=%s target=%s class=%s",
		diagnosticID, stage, target, class)
}

// ldapProbeDiagnosticID 產生不透明關聯識別碼（8 bytes → 16 hex 字元：
// 夠短到 admin 能唸給維運聽，夠長到不可預測）。
//
// **恆不回空字串**：熵源失敗時退回時間戳記形式——ID 缺席會讓失敗事件在三處
// 之間失去關聯，而那正是本機制存在的理由
func ldapProbeDiagnosticID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "t" + strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(b)
}

// ldapProbeActorKey 限流的操作者鍵。
//
// 以已認證的使用者 id 為鍵（非 IP）——本端點恆在認證之後，id 是請求端無法
// 自選的值；退回 IP 只在 id 缺席時發生（不應出現，但不能因此變成無鍵可限）
func ldapProbeActorKey(actor LDAPDirectoryActor) string {
	if actor.ID != 0 {
		return "u" + strconv.FormatUint(uint64(actor.ID), 10)
	}
	if actor.IP != "" {
		return "ip:" + actor.IP
	}
	return "anonymous"
}

// ldapProbeTargetKey 限流的目標鍵；URL 無法解析時共用單一桶
// （送壞 URL 不得成為繞過 per-target 限流的手段）
func ldapProbeTargetKey(canonicalOrigin string) string {
	if canonicalOrigin == "" {
		return "(unparsed)"
	}
	return canonicalOrigin
}

// ── 審計（成功與失敗皆入）────────────────────────────────────────────────

// LDAPAuditEventTest 連線測試審計事件碼
const (
	LDAPAuditEventTest         = "ldap_directory_test"
	LDAPAuditEventTestRejected = "ldap_directory_test_rejected"
)

// auditTestOutcome 測試執行結果入審計（成功與失敗皆入）。
//
// 記 actor、canonical 目標、失敗階段、diagnostic_id、是否沿用既存密碼與
// outcome；**不記密碼、密文、socket 細節，也不記失敗的粗分類原因**——後者只
// 屬 operational log，進了 admin 可見的審計欄位等於把掃描解析度還回去
func (s *LDAPDirectoryService) auditTestOutcome(req LDAPDirectoryTestRequest,
	result LDAPDirectoryTestResult, risks []policy.RiskItem) {
	status := model.StatusSuccess
	if !result.Success {
		status = model.StatusFailure
	}
	details := map[string]any{
		"event":                  LDAPAuditEventTest,
		"url":                    result.Target,
		"outcome":                ldapProbeOutcome(result.Success),
		"enabled":                req.Enabled,
		"skip_tls_verify":        req.SkipTLSVerify,
		"reused_stored_password": result.ReusedStoredPassword,
		"risk_acknowledged":      req.RiskAcknowledged,
	}
	if len(risks) > 0 {
		details["transmission_risks"] = risks
	}
	if result.Success {
		details["matched_count"] = result.MatchedCount
		details["matched_at_least"] = result.MatchedAtLeast
	} else {
		details["stage"] = result.FailedStage
		details["code"] = result.Code
		details["diagnostic_id"] = result.DiagnosticID
	}
	if err := s.ldapDirectoryAuditLog(s.db, req.Actor, model.ActionExecute, status, nil, details); err != nil {
		log.Printf("[LDAPDirectoryTest] 測試結果審計寫入失敗（結果不受影響）: %v", err)
	}
}

// auditTestRejected 前置拒絕（欄位驗證、傳輸閘）入審計。
//
// 拒絕原因碼沿用存檔路徑的同一組常數——同一件事在兩個端點用兩套碼，稽核端
// 就得維護兩份對照表
func (s *LDAPDirectoryService) auditTestRejected(req LDAPDirectoryTestRequest,
	target, reason, detail string, risks []policy.RiskItem) {
	details := map[string]any{
		"event":             LDAPAuditEventTestRejected,
		"reason":            reason,
		"enabled":           req.Enabled,
		"skip_tls_verify":   req.SkipTLSVerify,
		"risk_acknowledged": req.RiskAcknowledged,
	}
	if detail != "" {
		details["detail"] = detail
	}
	if target != "" {
		details["url"] = target
	}
	if len(risks) > 0 {
		details["transmission_risks"] = risks
	}
	if err := s.ldapDirectoryAuditLog(s.db, req.Actor, model.ActionExecute,
		model.StatusDenied, nil, details); err != nil {
		log.Printf("[LDAPDirectoryTest] 被拒測試審計寫入失敗（拒絕結果不受影響）: %v", err)
	}
}

func ldapProbeOutcome(success bool) string {
	if success {
		return "success"
	}
	return "failed"
}
