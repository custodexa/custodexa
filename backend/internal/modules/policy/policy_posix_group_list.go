package policy

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// PolicyListPOSIXGroups 清單格式：以逗號分隔的 POSIX 群組名稱。
const PolicyListPOSIXGroups = "posix_group_list"

// posixGroupList 上限：單項位元組數與項數。
const (
	posixGroupNameMaxBytes = 256
	posixGroupListMaxItems = 32
)

// normalizePOSIXGroupList 逗號分隔群組清單的正規化與逐項驗證。
//
// 各項去首尾空白、略過空項、去除重複並保留先後次序；項內空白允許（目錄服務常見
// 「domain admins」）。名稱規則與盤點的解析端一致：合法 UTF-8、1–256 位元組、
// 不含 `:` 與控制字元（Cc）。逗號是分隔符，群組名本來就不能含逗號，不需轉義。
// 空值合法，代表不以群組判定特權。
func normalizePOSIXGroupList(def *PolicyDef, v string) (string, error) {
	if v == "" {
		return "", nil
	}
	seen := map[string]bool{}
	var out []string
	for _, raw := range strings.Split(v, ",") {
		item := strings.TrimSpace(raw)
		if item == "" {
			continue
		}
		if err := validatePOSIXGroupName(item); err != nil {
			return "", &PolicyInvalidValueError{Key: def.Key, Reason: err.Error()}
		}
		if seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	if len(out) > posixGroupListMaxItems {
		return "", &PolicyInvalidValueError{
			Key:    def.Key,
			Reason: fmt.Sprintf("群組數 %d 超過上限 %d", len(out), posixGroupListMaxItems),
		}
	}
	return strings.Join(out, ","), nil
}

func validatePOSIXGroupName(name string) error {
	if !utf8.ValidString(name) {
		return fmt.Errorf("群組名須為合法 UTF-8")
	}
	if len(name) > posixGroupNameMaxBytes {
		return fmt.Errorf("群組名超過 %d 位元組", posixGroupNameMaxBytes)
	}
	for _, r := range name {
		if r == ':' || r == ',' {
			return fmt.Errorf("群組名不可含 %q", r)
		}
		if unicode.IsControl(r) {
			return fmt.Errorf("群組名不可含控制字元")
		}
	}
	return nil
}
