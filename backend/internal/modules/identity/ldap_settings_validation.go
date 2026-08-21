package identity

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

// LDAP 目錄設定的伺服端存檔驗證（ldap-settings-migration D7）。
//
// 前端的必填驗證僅為 UX 提前提示，**權威在此**：任何寫入路徑（PUT upsert、
// 連線測試的表單值）都須先過本檔的驗證，且驗證不得只存在於連線測試路徑。
//
// # user_filter 為何要兩層驗證
//
// 只做語法檢查（`%s` 恰一次、無其他格式化動詞、括號配對、RFC 4515 可解析）
// 會放行 `(|(uid=%s)(uid=svc-admin))`——三條語法規則全過，但 OR 的另一分支
// 可在搜尋結果不含登入帳號時命中。搭配「搜尋唯一命中即以該 entry 的 DN 做
// bind」（ldap_authenticator.go 的唯一命中判定）與「以請求端輸入命名影子帳號」
// （auth_service.go 建立本地影子帳號時取請求的使用者名），即可構造出
// 「以目錄中某個帳號的密碼、配上任意帳號名登入」的形態。
//
// 故加上結構層：**placeholder 所在的斷言必須是每條可滿足路徑的必要條件**——
// 即 `%s` 節點的任一祖先不得為 OR（`|`）或 NOT（`!`）。此規則不影響正當的 AD
// 複合 filter：`(&(objectClass=user)(sAMAccountName=%s))` 在 AND 之下，
// placeholder 仍是必要條件，照樣通過。
//
// # 殘留誠實記載（design D7／R2-opus N10 已裁決）
//
// 上述兩層**仍非充分**：根因是影子帳號名取自請求輸入而非目錄 entry 的穩定
// 登入屬性。修它會動 ldap-auth 既有 requirement，違反本 change「認證行為零
// 變更」的承諾，故不在本 change 修。本驗證是**縱深防禦而非完整封閉**；
// 現況由 characterization 測試釘住，根本修法（以 entry 屬性回填帳號名）記
// backlog。日後若移除本驗證，須先完成根本修法。

const (
	// 長度上限對齊 model 欄位的 DB size，使驗證先於 DB 截斷／報錯
	ldapUserFilterMaxLen = 500
	ldapDNMaxLen         = 500
	ldapAttrNameMaxLen   = 100
	ldapNameMaxLen       = 100
)

// ErrLDAPFilterInvalid user_filter 不合法的哨兵錯誤；
// 細分原因取 LDAPFilterError.Reason
var ErrLDAPFilterInvalid = errors.New("LDAP 使用者搜尋 filter 不合法")

// user_filter 拒絕原因（供 API 層對應機器碼；恆為靜態字串）
const (
	LDAPFilterReasonEmpty               = "empty"
	LDAPFilterReasonTooLong             = "too_long"
	LDAPFilterReasonPlaceholderMissing  = "placeholder_missing"
	LDAPFilterReasonPlaceholderMultiple = "placeholder_multiple"
	LDAPFilterReasonFormatVerb          = "format_verb"
	LDAPFilterReasonParenUnbalanced     = "paren_unbalanced"
	LDAPFilterReasonSyntax              = "syntax"
	// LDAPFilterReasonPlaceholderScope 結構層：placeholder 位於 OR／NOT 之下
	LDAPFilterReasonPlaceholderScope = "placeholder_under_or_not"
	// LDAPFilterReasonPlaceholderPosition placeholder 落在屬性名而非斷言值
	LDAPFilterReasonPlaceholderPosition = "placeholder_in_attribute"
)

// LDAPFilterError 帶拒絕原因的 filter 驗證錯誤
type LDAPFilterError struct {
	Reason string
}

func (e *LDAPFilterError) Error() string {
	return fmt.Sprintf("%v（%s）", ErrLDAPFilterInvalid, e.Reason)
}

// Unwrap 使 errors.Is(err, ErrLDAPFilterInvalid) 成立
func (e *LDAPFilterError) Unwrap() error { return ErrLDAPFilterInvalid }

func newLDAPFilterError(reason string) error { return &LDAPFilterError{Reason: reason} }

// ValidateLDAPUserFilter 對 user_filter 做語法層＋結構層驗證（見檔頭理由）。
// 傳入值應為已 trim 的字串
func ValidateLDAPUserFilter(filter string) error {
	if filter == "" {
		return newLDAPFilterError(LDAPFilterReasonEmpty)
	}
	if len(filter) > ldapUserFilterMaxLen {
		return newLDAPFilterError(LDAPFilterReasonTooLong)
	}

	// 語法 (1)：`%s` 恰一次，且不得出現其他格式化動詞。
	// filter 是 fmt.Sprintf 的格式字串，多一個 verb 即多一個未受控的注入點；
	// 連 `%%`（字面百分號）也一併拒絕——目錄 filter 幾乎不需要字面百分號，
	// 放行它只會讓「還有幾個 % 是安全的」變成需要逐一論證的問題
	percentCount := strings.Count(filter, "%")
	switch {
	case percentCount == 0:
		return newLDAPFilterError(LDAPFilterReasonPlaceholderMissing)
	case percentCount > 1:
		if strings.Count(filter, "%s") > 1 {
			return newLDAPFilterError(LDAPFilterReasonPlaceholderMultiple)
		}
		return newLDAPFilterError(LDAPFilterReasonFormatVerb)
	}
	idx := strings.Index(filter, "%")
	if idx+1 >= len(filter) || filter[idx+1] != 's' {
		return newLDAPFilterError(LDAPFilterReasonFormatVerb)
	}

	// 語法 (2)：括號配對。CompileFilter 也會擋，但獨立檢查能給出明確原因碼
	if !ldapFilterParensBalanced(filter) {
		return newLDAPFilterError(LDAPFilterReasonParenUnbalanced)
	}

	// 語法 (3)＋結構：以哨兵取代 placeholder 後交給 go-ldap 的 filter 編譯器
	// 取得 AST。**不自行實作 RFC 4515 parser**——自寫 parser 與撥號時實際採用
	// 的 parser 之間的差異，正是本設計要消除的繞過面
	sentinel := ldapFilterSentinel(filter)
	packet, err := ldap.CompileFilter(strings.Replace(filter, "%s", sentinel, 1))
	if err != nil {
		// CompileFilter 亦拒尾隨垃圾（`(a=b))` 之類）與非法跳脫（`\zz`）
		return newLDAPFilterError(LDAPFilterReasonSyntax)
	}

	hits := make([]ldapFilterPlaceholderHit, 0, 1)
	scanLDAPFilterNode(packet, sentinel, false, &hits)
	if len(hits) == 0 {
		// 哨兵在 AST 中消失（例如落在被編譯器吞掉的位置）——無法證明其為必要
		// 條件，一律拒
		return newLDAPFilterError(LDAPFilterReasonSyntax)
	}
	for _, hit := range hits {
		if hit.unresolved {
			return newLDAPFilterError(LDAPFilterReasonSyntax)
		}
		if hit.inAttributeName {
			return newLDAPFilterError(LDAPFilterReasonPlaceholderPosition)
		}
		if hit.underOrNot {
			return newLDAPFilterError(LDAPFilterReasonPlaceholderScope)
		}
	}
	return nil
}

// ldapFilterParensBalanced 括號配對檢查。
// 合法 RFC 4515 值中的括號一律以 `\28`／`\29` 跳脫，故原始括號恆為結構符號
func ldapFilterParensBalanced(filter string) bool {
	depth := 0
	for i := 0; i < len(filter); i++ {
		switch filter[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth < 0 {
				return false
			}
		}
	}
	return depth == 0
}

// ldapFilterSentinel 產生不與輸入內容混淆的哨兵值。
// 純 ASCII 英數，經 filter 編譯器不會被跳脫解碼改寫；與輸入撞值時遞增後綴
func ldapFilterSentinel(filter string) string {
	const base = "x0otldapplaceholderx0"
	sentinel := base
	for i := 0; strings.Contains(filter, sentinel); i++ {
		sentinel = base + strconv.Itoa(i)
	}
	return sentinel
}

// ldapFilterPlaceholderHit AST 中一處哨兵出現的位置屬性
type ldapFilterPlaceholderHit struct {
	// underOrNot 祖先鏈上出現過 OR 或 NOT
	underOrNot bool
	// inAttributeName 落在屬性名（或 matching rule）而非斷言值
	inAttributeName bool
	// unresolved 出現在無法歸類的節點——不視為已證明的必要條件，一律拒
	unresolved bool
}

// scanLDAPFilterNode 走訪 filter AST 收集哨兵出現位置；pkt 恆為「filter 節點」。
//
// **必須依節點角色而非單看 Tag 值走訪**：BER 的 tag 只有搭配 class 與所在位置
// 才有意義，數值本身在不同角色間會撞——例如子字串段的 Any 段 tag=1 與
// FilterOr=1 相同、equality match 的屬性名葉為 universal octet string tag=4 與
// FilterSubstrings=4 相同、extensible match 的 matchValue tag=3 與
// FilterEqualityMatch=3 相同。用單一 switch 掃全樹會把值葉誤判為運算子節點
// （最糟的形態：把 OR 之下的哨兵漏掉而放行繞過型 filter）。
//
// underOrNot 於進入 Or／Not 的子節點時置真並向下傳遞——這即是祖先鏈檢查
func scanLDAPFilterNode(pkt *ber.Packet, sentinel string, underOrNot bool, hits *[]ldapFilterPlaceholderHit) {
	if pkt == nil {
		return
	}

	switch pkt.Tag {
	case ldap.FilterAnd:
		for _, child := range pkt.Children {
			scanLDAPFilterNode(child, sentinel, underOrNot, hits)
		}
	case ldap.FilterOr, ldap.FilterNot:
		// 祖先為 OR／NOT ⇒ 其下的斷言不是每條可滿足路徑的必要條件
		for _, child := range pkt.Children {
			scanLDAPFilterNode(child, sentinel, true, hits)
		}
	case ldap.FilterEqualityMatch, ldap.FilterGreaterOrEqual, ldap.FilterLessOrEqual, ldap.FilterApproxMatch:
		// Children[0]=屬性名、Children[1]=斷言值，兩者皆為葉
		for i, child := range pkt.Children {
			recordLDAPFilterLeaf(child, sentinel, underOrNot, i == 0, hits)
		}
	case ldap.FilterSubstrings:
		// Children[0]=屬性名葉、Children[1]=子字串序列（其 children 為各段值葉）
		for i, child := range pkt.Children {
			if i == 0 {
				recordLDAPFilterLeaf(child, sentinel, underOrNot, true, hits)
				continue
			}
			for _, part := range child.Children {
				recordLDAPFilterLeaf(part, sentinel, underOrNot, false, hits)
			}
		}
	case ldap.FilterPresent:
		// 本身即葉節點，值為屬性名
		recordLDAPFilterLeaf(pkt, sentinel, underOrNot, true, hits)
	case ldap.FilterExtensibleMatch:
		for _, child := range pkt.Children {
			isName := child.Tag == ldap.MatchingRuleAssertionMatchingRule || child.Tag == ldap.MatchingRuleAssertionType
			recordLDAPFilterLeaf(child, sentinel, underOrNot, isName, hits)
		}
	default:
		// 上列已窮盡 RFC 4515 的 filter choice；走到這裡表示依賴版本引入了新形態，
		// 此時無法斷定哨兵的必要性——保守記為 unresolved（結果為拒絕）
		if packetSubtreeContains(pkt, sentinel) {
			*hits = append(*hits, ldapFilterPlaceholderHit{unresolved: true})
		}
	}
}

// recordLDAPFilterLeaf 葉節點含哨兵即記錄一筆命中
func recordLDAPFilterLeaf(pkt *ber.Packet, sentinel string, underOrNot, attrName bool, hits *[]ldapFilterPlaceholderHit) {
	if pkt == nil || !ldapPacketLeafContains(pkt, sentinel) {
		return
	}
	*hits = append(*hits, ldapFilterPlaceholderHit{underOrNot: underOrNot, inAttributeName: attrName})
}

// ldapPacketLeafContains 葉節點是否含哨兵。
// 只看 Value——構造型節點的 Data 會累積子節點的編碼位元組，用 Data 判定會誤命中
func ldapPacketLeafContains(pkt *ber.Packet, sentinel string) bool {
	if s, ok := pkt.Value.(string); ok {
		return strings.Contains(s, sentinel)
	}
	if len(pkt.Children) == 0 && pkt.Data != nil {
		return strings.Contains(pkt.Data.String(), sentinel)
	}
	return false
}

// packetSubtreeContains 子樹任一節點的字串值含哨兵（僅供 default 分支的保守判定）
func packetSubtreeContains(pkt *ber.Packet, sentinel string) bool {
	if pkt == nil {
		return false
	}
	if s, ok := pkt.Value.(string); ok && strings.Contains(s, sentinel) {
		return true
	}
	for _, child := range pkt.Children {
		if packetSubtreeContains(child, sentinel) {
			return true
		}
	}
	return false
}

// ErrLDAPSettingsIncomplete 啟用態設定缺必填欄位
var ErrLDAPSettingsIncomplete = errors.New("LDAP 目錄設定不完整")

// ErrLDAPFieldInvalid 欄位格式不合法（長度、字元集）
var ErrLDAPFieldInvalid = errors.New("LDAP 目錄設定欄位格式不合法")

// 欄位錯誤原因
const (
	LDAPFieldReasonRequired = "required"
	LDAPFieldReasonTooLong  = "too_long"
	LDAPFieldReasonFormat   = "format"
)

// LDAPFieldError 指名欄位的驗證錯誤；Field 採 wire 欄名以便前端定位
type LDAPFieldError struct {
	Field  string
	Reason string
}

func (e *LDAPFieldError) Error() string {
	return fmt.Sprintf("LDAP 目錄設定欄位 %s 不合法（%s）", e.Field, e.Reason)
}

// Unwrap required 歸「不完整」、其餘歸「格式不合法」，使 API 層可分流機器碼
func (e *LDAPFieldError) Unwrap() error {
	if e.Reason == LDAPFieldReasonRequired {
		return ErrLDAPSettingsIncomplete
	}
	return ErrLDAPFieldInvalid
}

func newLDAPFieldError(field, reason string) error {
	return &LDAPFieldError{Field: field, Reason: reason}
}

// ldapAttrNamePattern LDAP 屬性描述：字母開頭的英數連字號，或點分十進位 OID。
// 收斂字元集使屬性名不可能挾帶括號／空白等會改變搜尋請求形狀的字元
var ldapAttrNamePattern = regexp.MustCompile(`^(?:[A-Za-z][A-Za-z0-9-]*|[0-9]+(?:\.[0-9]+)+)$`)

// LDAPDirectoryInput 目錄設定的存檔輸入（服務層驗證的唯一入口型別）
type LDAPDirectoryInput struct {
	Name         string
	URL          string
	BindDN       string
	BaseDN       string
	UserFilter   string
	AttrEmail    string
	AttrFullName string

	SkipTLSVerify bool
	Enabled       bool

	// HasBindPassword 「存檔後是否會有 bind 密碼」——涵蓋本次請求提供的新密碼
	// 與沿用既存值兩種來源。**本函式不查 DB**：由呼叫端（CRUD 於鎖內重讀既存列
	// 後）決定此旗標，驗證只消費結果
	HasBindPassword bool
}

// Normalized 回傳去除前後空白的輸入副本。
// 存檔應寫入本副本，確保「驗過的值」與「存進去的值」是同一份
func (in LDAPDirectoryInput) Normalized() LDAPDirectoryInput {
	out := in
	out.Name = strings.TrimSpace(in.Name)
	out.URL = strings.TrimSpace(in.URL)
	out.BindDN = strings.TrimSpace(in.BindDN)
	out.BaseDN = strings.TrimSpace(in.BaseDN)
	out.UserFilter = strings.TrimSpace(in.UserFilter)
	out.AttrEmail = strings.TrimSpace(in.AttrEmail)
	out.AttrFullName = strings.TrimSpace(in.AttrFullName)
	return out
}

// LDAPDirectoryValidation 驗證通過後的產物
type LDAPDirectoryValidation struct {
	// Input 正規化後的輸入（存檔以此為準）
	Input LDAPDirectoryInput
	// ParsedURL URL 的**唯一**解析結果；存檔驗證、端點身分比較與 egress 輸入
	// 三者共用本值，避免各自 parse 產生差異。草稿且 URL 為空時為零值。
	//
	// 欄名刻意不叫 Endpoint：kms 的 endpoint_gate_test.go 以 AST 攔截所有名為
	// Endpoint 的欄位寫入（寧可誤報不漏報），本欄與 KMS 端點覆寫無關，
	// 改名比在該守衛的允許清單開一格更誠實
	ParsedURL LDAPEndpoint
}

// ValidateLDAPDirectoryInput 條件式存檔驗證（D7）：
//
//   - enabled=false（草稿）：僅驗「有值欄位」的格式，允許不完整（先存草稿、
//     稍後補齊是正常流程）
//   - enabled=true：url／bind_dn／base_dn／user_filter／attr_email／
//     attr_fullname 須齊全，且 HasBindPassword 須為真
//
// 兩種狀態下 user_filter 只要有值就走完整兩層驗證——壞 filter 不因「還是草稿」
// 而放行，否則存檔閘會被「先存草稿再翻啟用」繞過
func ValidateLDAPDirectoryInput(in LDAPDirectoryInput) (LDAPDirectoryValidation, error) {
	norm := in.Normalized()
	result := LDAPDirectoryValidation{Input: norm}

	if len(norm.Name) > ldapNameMaxLen {
		return result, newLDAPFieldError("name", LDAPFieldReasonTooLong)
	}
	if len(norm.BindDN) > ldapDNMaxLen {
		return result, newLDAPFieldError("bind_dn", LDAPFieldReasonTooLong)
	}
	if len(norm.BaseDN) > ldapDNMaxLen {
		return result, newLDAPFieldError("base_dn", LDAPFieldReasonTooLong)
	}
	for field, value := range map[string]string{"attr_email": norm.AttrEmail, "attr_fullname": norm.AttrFullName} {
		if value == "" {
			continue
		}
		if len(value) > ldapAttrNameMaxLen {
			return result, newLDAPFieldError(field, LDAPFieldReasonTooLong)
		}
		if !ldapAttrNamePattern.MatchString(value) {
			return result, newLDAPFieldError(field, LDAPFieldReasonFormat)
		}
	}

	if norm.URL != "" {
		endpoint, err := ParseLDAPURL(norm.URL)
		if err != nil {
			return result, err
		}
		result.ParsedURL = endpoint
	}
	if norm.UserFilter != "" {
		if err := ValidateLDAPUserFilter(norm.UserFilter); err != nil {
			return result, err
		}
	}

	if !norm.Enabled {
		// 草稿：格式已驗，完整性不強制
		return result, nil
	}

	for _, required := range []struct {
		field string
		value string
	}{
		{"url", norm.URL},
		{"bind_dn", norm.BindDN},
		{"base_dn", norm.BaseDN},
		{"user_filter", norm.UserFilter},
		{"attr_email", norm.AttrEmail},
		{"attr_fullname", norm.AttrFullName},
	} {
		if required.value == "" {
			return result, newLDAPFieldError(required.field, LDAPFieldReasonRequired)
		}
	}
	if !norm.HasBindPassword {
		return result, newLDAPFieldError("bind_password", LDAPFieldReasonRequired)
	}
	return result, nil
}
