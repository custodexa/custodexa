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

	// Groups 目錄回傳的群組成員資格原始值。**原樣保留**——比對在後續步驟以
	// 辨識名稱解析後進行，在這裡先改寫等於在比對規則之外再造一套
	Groups []string
	// GroupsKnown 本次是否真的取得了群組資料。
	//
	// **與「Groups 是空的」是兩件事**：目錄協定不回傳零值屬性，
	// 「不屬於任何群組」與「這次沒去問」在資料上同形。前者該收回映射角色，
	// 後者必須保留既有映射；分不出來就只能二選一，而兩個方向都會錯。
	GroupsKnown bool
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

	info := &LDAPUserInfo{
		Username: username,
		Email:    entry.GetAttributeValue(a.cfg.AttrEmail),
		FullName: entry.GetAttributeValue(a.cfg.AttrFullName),
	}
	info.Groups, info.GroupsKnown = ldapGroupsOf(entry, a.cfg.AttrGroup)
	return info, nil
}

// ldapGroupsOf 由搜尋回來的項目取群組值。
//
// **項目上沒有這個屬性＝空集合，不是未知**：目錄協定不回傳零值屬性，
// 「不屬於任何群組」與「這一筆恰好沒帶」在項目上同形，判不出來。
// 若照「未知即保留」處置，被移出最後一個群組的人就永遠撤不掉——
// 而誤清的代價是使用者暫時降回基本角色、看得見、改好設定重登即復原。
// 失敗方向不對稱，選看得見的那一側。
//
// 屬性名沒設就不是「空集合」而是「沒問過」，故 known 回 false：
// 那條路徑上呼叫端根本不會走到重算。
func ldapGroupsOf(entry *ldap.Entry, attrGroup string) (groups []string, known bool) {
	attr := strings.TrimSpace(attrGroup)
	if attr == "" || entry == nil {
		return nil, false
	}
	return ldapAttributeValues(entry, attr), true
}

// ldapAttributeValues 以不分大小寫的屬性名自項目取值。
//
// **屬性描述在目錄協定上不分大小寫**：管理者填 memberof、目錄回 memberOf 是
// 正常設定下就會出現的組合。逐字比對會取不到值，而上游把「取不到」與「這個人
// 不屬於任何群組」視為同一件事——結果是誤撤該通道的映射角色。索取清單那邊
// 本來就以不分大小寫判同名，取值這側必須用同一把尺，兩邊才對得起來。
func ldapAttributeValues(entry *ldap.Entry, attr string) []string {
	for _, a := range entry.Attributes {
		if a == nil {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(a.Name), attr) {
			return a.Values
		}
	}
	return nil
}

// ldapSearchAttributes 一次搜尋要索取的屬性清單。
//
// **群組屬性搭同一次搜尋回來，不另發一次**：另發一次要嘛重複整條搜尋成本，
// 要嘛在兩次之間讀到不一致的目錄狀態。屬性名未設定時清單逐字不變——
// 未啟用群組映射的部署，送出去的搜尋請求與加這個功能之前一模一樣。
func ldapSearchAttributes(attrEmail, attrFullName, attrGroup string) []string {
	attrs := []string{attrEmail, attrFullName}
	group := strings.TrimSpace(attrGroup)
	if group == "" {
		return attrs
	}
	// 群組屬性與既有兩欄同名時不重複列入：重複的屬性描述會讓部分目錄
	// 伺服器回傳重複的屬性項，而屬性值的筆數正是我們拿來當群組集合的東西
	for _, existing := range attrs {
		// 同名判定不分大小寫，取值那側（ldapAttributeValues）用的是同一把尺；
		// 兩邊尺不同就會出現「清單留了既有拼法、取值卻照設定拼法找」的落差
		if strings.EqualFold(strings.TrimSpace(existing), group) {
			return attrs
		}
	}
	return append(attrs, group)
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
		ldapSearchAttributes(a.cfg.AttrEmail, a.cfg.AttrFullName, a.cfg.AttrGroup),
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
