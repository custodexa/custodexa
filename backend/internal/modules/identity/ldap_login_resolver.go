package identity

import (
	"context"
	"github.com/custodexa/backend/internal/modules/policy"
	"log"

	"github.com/custodexa/backend/config"
)

// LDAP 登入路徑的單次設定解析（ldap-settings-migration D2；tasks 2.8）。
//
// # 為什麼登入路徑注入的是 resolver 而不是 authenticator
//
// 設定自 env 遷入 DB 後即可於執行期變更，啟動時建構一次的認證器會停在
// 舊值。改注入 resolver 後，每次登入觸發時解析一次現行設定。
//
// **關鍵不變式：閘判定與撥號共用同一次解析結果。** 若傳輸風險判定讀一次
// DB、撥號再讀一次，兩次之間的設定變更會產生「閘看見 ldaps:// 而放行、
// 撥號用 ldap:// 把密碼明文送出」的交錯——strict 檔位的唯一職責正是防止
// 這件事。故本檔的 resolution 一次同時產出 Risks 與 Auth，兩者出自同一份
// snapshot，型別上不可能不同源。
//
// 未設定／已停用／故障三態的處置見 LDAPLoginState。

// LDAPLoginState 登入路徑可辨識的解析結果三態。
//
// 與 LDAPResolveState 的差別：本型別是**登入路徑的視角**——「有設定列但
// 停用」對登入而言與「沒有設定列」等價（都不可撥號），但對清冊而言是兩種
// 不同的呈現，故非撥號消費端另有 LDAPRiskResult 的三態，不共用本型別。
type LDAPLoginState string

const (
	// LDAPLoginUnavailable 無設定列或設定為停用——維持既有「LDAP 未啟用」語義：
	// 查無帳號回憑證錯誤，本地帳號完全不受影響
	LDAPLoginUnavailable LDAPLoginState = "unavailable"
	// LDAPLoginReady 可撥號；Risks 與 Auth 出自同一份 snapshot
	LDAPLoginReady LDAPLoginState = "ready"
	// LDAPLoginFailed 解析失敗（DB 錯誤或密文解密失敗）——**fail-close**。
	//
	// 不得降級為 Unavailable：那會讓金鑰事故看起來像「管理員把 LDAP 關掉了」，
	// 排錯方向整個指錯邊；更嚴重的是若日後 LDAP 未啟用被賦予任何放行語義，
	// 故障即成繞過。對外仍收斂為憑證錯誤（不洩漏內部狀態），可辨識性走 log 與審計
	LDAPLoginFailed LDAPLoginState = "failed"
)

// LDAPLoginResolution 單次登入的解析結果（immutable，僅存活於該次登入呼叫棧）
type LDAPLoginResolution struct {
	State LDAPLoginState
	// Risks 傳輸風險項；與 Auth 出自同一份 snapshot（不變式所在）
	Risks []policy.RiskItem
	// Auth 該次登入使用的認證器；僅 State=ready 時非 nil
	Auth LDAPAuthenticator
	// Err 僅 State=failed 時非 nil；供伺服端 log，不對外呈現
	Err error
}

// LDAPLoginResolver 登入路徑的解析入口（AuthService 以 setter 注入）
type LDAPLoginResolver func() LDAPLoginResolution

// NewLDAPLoginResolver 生產組裝用的 resolver：每次登入現讀 DB＋解密一次。
//
// 不快取（D2）：LDAP 登入頻率低，且信封解密走行程內 DEK 快取，相對 LDAP
// 撥號成本可忽略；快取則要再添一份 HA 一致性債
func NewLDAPLoginResolver(dir *LDAPDirectoryService) LDAPLoginResolver {
	return newLDAPLoginResolverWith(dir, newLDAPAuthenticatorFromSnapshot)
}

// newLDAPLoginResolverWith 可注入 authenticator 工廠的版本。
//
// 工廠是測試觀察「撥號實際用了哪一份設定」的唯一接縫——沒有它就無從證明
// 閘與撥號同源（真認證器會直接去撥網路）
func newLDAPLoginResolverWith(
	dir *LDAPDirectoryService, factory func(LDAPDialSnapshot) LDAPAuthenticator,
) LDAPLoginResolver {
	return func() LDAPLoginResolution {
		// **closure 入口的依賴檢查**：factory 在 nil 依賴下仍能成功建出 closure
		//（Go 允許 nil 接收者），錯誤只會延遲到實際登入當下才以 panic 形態爆發
		// ——那既不是三態的任何一格，也讓一次組裝疏漏變成整條認證路徑的崩潰。
		// 收斂為 failed 而**非 unavailable**：後者會把組裝疏漏偽裝成「LDAP 未
		// 啟用」，與 D2 禁止的併吞形態同一件事
		if dir == nil || factory == nil {
			log.Print("[LDAPLogin] 登入解析器依賴未接線（fail-close，非 LDAP 未啟用）")
			return LDAPLoginResolution{State: LDAPLoginFailed, Err: ErrLDAPDirectoryServiceUnavailable}
		}
		result := dir.ResolveDialSnapshot(context.Background())
		switch result.State {
		case policy.LDAPResolveFailed:
			return LDAPLoginResolution{State: LDAPLoginFailed, Err: result.Err}
		case policy.LDAPResolveUnconfigured:
			return LDAPLoginResolution{State: LDAPLoginUnavailable}
		}
		if !result.Snapshot.Enabled {
			return LDAPLoginResolution{State: LDAPLoginUnavailable}
		}
		return LDAPLoginResolution{
			State: LDAPLoginReady,
			// 風險判定就地取自本次 snapshot 的 risk view：撥號用的是同一個
			// snapshot，兩者不可能指向不同設定
			Risks: policy.LDAPRisksOf(result.Snapshot.LDAPRiskView),
			Auth:  factory(result.Snapshot),
		}
	}
}

// newLDAPAuthenticatorFromSnapshot 由撥號快照建構該次登入的認證器。
//
// config.LDAPConfig 於此僅作為認證器的**撥號參數結構**——自本 change 起它
// 不再由 env 供給（config.Load 已移除 LDAP 段），執行期唯一事實源是
// ldap_directories 表
func newLDAPAuthenticatorFromSnapshot(snap LDAPDialSnapshot) LDAPAuthenticator {
	return NewLDAPAuthenticator(config.LDAPConfig{
		Enabled:       snap.Enabled,
		URL:           snap.URL,
		BindDN:        snap.BindDN,
		BindPassword:  snap.BindPassword,
		BaseDN:        snap.BaseDN,
		UserFilter:    snap.UserFilter,
		AttrEmail:     snap.AttrEmail,
		AttrFullName:  snap.AttrFullName,
		SkipTLSVerify: snap.SkipTLSVerify,
	})
}
