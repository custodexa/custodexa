package identity

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/custodexa/backend/config"
)

// ldapDialTimeout 連線逾時上限：目錄無回應時不可拖垮登入端點（既有風險項）
const ldapDialTimeout = 5 * time.Second

// ErrLDAPAuthFailed LDAP 認證失敗（含查無用戶、密碼錯誤）。
// 對外一律收斂為 ErrInvalidCredentials，避免洩漏目錄內部狀態
var ErrLDAPAuthFailed = errors.New("LDAP 認證失敗")

// LDAPUserInfo LDAP 認證成功後回傳的目錄屬性，供影子用戶供應使用
type LDAPUserInfo struct {
	Username string
	Email    string
	FullName string
}

// LDAPAuthenticator LDAP 認證介面。
// 以介面注入 AuthService 是為了單元測試可用 fake 實作，不依賴真實目錄
type LDAPAuthenticator interface {
	Authenticate(username, password string) (*LDAPUserInfo, error)
}

// ldapAuthenticator go-ldap/v3 實作：service bind -> search -> user bind
type ldapAuthenticator struct {
	cfg    config.LDAPConfig
	egress *LDAPEgressPolicy
}

// NewLDAPAuthenticator 建立 LDAP 認證器。
//
// 撥號一律經出站位址政策——登入與連線測試兩條
// 路徑共用同一入口，任一路徑繞過即等於政策不存在
func NewLDAPAuthenticator(cfg config.LDAPConfig) LDAPAuthenticator {
	return &ldapAuthenticator{cfg: cfg, egress: NewLDAPEgressPolicyFromEnv()}
}

// Authenticate 以 search-then-bind 驗證帳密：
// 1) service account bind  2) 以 filter 搜尋用戶 DN  3) 以用戶 DN + 密碼 bind 驗密
func (a *ldapAuthenticator) Authenticate(username, password string) (*LDAPUserInfo, error) {
	// 空密碼防護：部分 LDAP 伺服器將空密碼 bind 視為匿名成功，必須在客戶端先擋
	if strings.TrimSpace(password) == "" {
		return nil, ErrLDAPAuthFailed
	}

	conn, err := a.dial()
	if err != nil {
		return nil, fmt.Errorf("LDAP 連線失敗: %w", err)
	}
	defer conn.Close()

	// service account bind：搜尋階段使用受控帳號，不暴露用戶密碼
	if err := conn.Bind(a.cfg.BindDN, a.cfg.BindPassword); err != nil {
		return nil, fmt.Errorf("LDAP service bind 失敗: %w", err)
	}

	entry, err := a.searchUser(conn, username)
	if err != nil {
		return nil, err
	}

	// user bind 驗密：bind 成功即代表目錄端認可此帳密
	if err := conn.Bind(entry.DN, password); err != nil {
		return nil, ErrLDAPAuthFailed
	}

	return &LDAPUserInfo{
		Username: username,
		Email:    entry.GetAttributeValue(a.cfg.AttrEmail),
		FullName: entry.GetAttributeValue(a.cfg.AttrFullName),
	}, nil
}

// dial 建立 LDAP 連線；統一 5 秒逾時避免目錄無回應拖垮登入。
//
// 撥號本身（含 dialer 逾時、TLS 設定、出站位址政策）收口於 LDAPEgressPolicy.DialURL，
// 登入路徑不自建 dialer——自建即繞過 Control 接縫上的位址檢查
func (a *ldapAuthenticator) dial() (*ldap.Conn, error) {
	// correlationID 留空：登入路徑不對外回報診斷識別碼（該機制屬連線測試端點）
	return a.egress.DialURL(a.cfg.URL, a.cfg.SkipTLSVerify, "")
}

// searchUser 以設定的 filter 模板搜尋用戶，要求唯一命中
func (a *ldapAuthenticator) searchUser(conn *ldap.Conn, username string) (*ldap.Entry, error) {
	// EscapeFilter 防 LDAP injection：登入帳號是未受信任輸入
	filter := fmt.Sprintf(a.cfg.UserFilter, ldap.EscapeFilter(username))

	searchReq := ldap.NewSearchRequest(
		a.cfg.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, int(ldapDialTimeout.Seconds()), false,
		filter,
		[]string{a.cfg.AttrEmail, a.cfg.AttrFullName},
		nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil {
		return nil, fmt.Errorf("LDAP 搜尋失敗: %w", err)
	}

	// 查無或多筆命中都視為認證失敗：多筆代表 filter 設定有誤，放行會有冒名風險
	if len(result.Entries) != 1 {
		return nil, ErrLDAPAuthFailed
	}
	return result.Entries[0], nil
}
