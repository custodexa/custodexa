package asset

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"

	"github.com/custodexa/backend/internal/model"
)

// 密碼生成字集。
//
// **硬排除不可經任何設定放寬**：shell 敏感字元（單引號、雙引號、反引號、反斜線、$）、
// 控制字元與空白一律不進字集。理由有二：
//  1. 相容性——改密走 shell 通道（chpasswd 經 sudo -S sh -c），這些字元會使目標系統
//     的指令解析出錯，密碼設進去卻登不回來；
//  2. 縱深防禦——即使日後某段路徑被改回 shell 拼接，可用字集裡也不存在能逃逸的字元。
//
// 因此本檔**不提供**「自訂可用字元」的設定面。可調的只有長度、是否含符號、
// 是否排除易混淆字元。
const (
	// passwordUpper／passwordLower／passwordDigit 恆為必要字類，不開放關閉
	passwordUpper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	passwordLower = "abcdefghijklmnopqrstuvwxyz"
	passwordDigit = "0123456789"
	// passwordSymbol 已剔除全部 shell 敏感字元：不含 ' " ` \ $ 亦不含空白。
	// 另剔除 ! 與 ; 與 & 與 | 與 < > ( ) * ? [ ] { } # ~ 等在 shell 具語法意義者，
	// 只留在 POSIX shell 的雙引號外亦無特殊語義、且各家 PAM 模組普遍接受的字元
	passwordSymbol = "@%^-_=+.,:/"
	// passwordAmbiguous 易混淆字元（視覺上難以區分，人工轉抄時易錯）
	passwordAmbiguous = "il1LoO0"
)

// shellSensitiveChars 硬排除字元集，供守衛測試與生成器共用單一事實源。
// 任何時候都不得出現於生成的密碼中。
const shellSensitiveChars = "'\"`\\$"

// PasswordPolicy 改密的密碼生成策略（per-plan）
type PasswordPolicy struct {
	Length           int
	IncludeSymbol    bool
	ExcludeAmbiguous bool
}

// ErrPasswordLengthOutOfRange 長度越界（handler 映射 400）
var ErrPasswordLengthOutOfRange = fmt.Errorf("密碼長度須介於 %d 與 %d 之間",
	model.PasswordLengthMin, model.PasswordLengthMax)

// PolicyFromPlan 自計劃取出密碼策略。長度為 0（欄位未設）時取預設值——
// 讀取端不因缺欄而生出長度 0 的密碼
func PolicyFromPlan(plan *model.ChangeSecretPlan) PasswordPolicy {
	length := plan.PasswordLength
	if length == 0 {
		length = model.PasswordLengthDefault
	}
	return PasswordPolicy{
		Length:           length,
		IncludeSymbol:    plan.PasswordIncludeSymbol,
		ExcludeAmbiguous: plan.PasswordExcludeAmbiguous,
	}
}

// ValidatePasswordLength 儲存計劃時的範圍檢查。0 視為「用預設」而非越界
func ValidatePasswordLength(length int) error {
	if length == 0 {
		return nil
	}
	if length < model.PasswordLengthMin || length > model.PasswordLengthMax {
		return ErrPasswordLengthOutOfRange
	}
	return nil
}

// charSets 依策略組出「必要字類」清單。回傳的每一組都保證至少貢獻一個字元
func (p PasswordPolicy) charSets() []string {
	filter := func(set string) string {
		if !p.ExcludeAmbiguous {
			return set
		}
		var b strings.Builder
		for _, r := range set {
			if strings.ContainsRune(passwordAmbiguous, r) {
				continue
			}
			b.WriteRune(r)
		}
		return b.String()
	}
	sets := []string{filter(passwordUpper), filter(passwordLower), filter(passwordDigit)}
	if p.IncludeSymbol {
		// 符號集不含易混淆字元，不需過濾
		sets = append(sets, passwordSymbol)
	}
	return sets
}

// GeneratePassword 依策略產生隨機密碼：每個必要字類至少一個字元，其餘自聯集取樣，
// 最後 Fisher-Yates 洗牌以免字類位置可預測。
//
// 長度越界一律回錯誤，SHALL NOT 靜默夾到邊界——靜默修正會讓「設定 200 字」的
// 計劃看起來成功卻產出不合預期的密碼
func GeneratePassword(p PasswordPolicy) (string, error) {
	if p.Length < model.PasswordLengthMin || p.Length > model.PasswordLengthMax {
		return "", ErrPasswordLengthOutOfRange
	}
	sets := p.charSets()
	all := strings.Join(sets, "")
	if len(all) == 0 {
		return "", fmt.Errorf("密碼字集為空")
	}

	buf := make([]byte, p.Length)
	for i := range buf {
		set := all
		if i < len(sets) {
			set = sets[i]
		}
		c, err := pickChar(set)
		if err != nil {
			return "", err
		}
		buf[i] = c
	}
	for i := len(buf) - 1; i > 0; i-- {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return "", err
		}
		j := n.Int64()
		buf[i], buf[j] = buf[j], buf[i]
	}
	return string(buf), nil
}

func pickChar(set string) (byte, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(set))))
	if err != nil {
		return 0, err
	}
	return set[n.Int64()], nil
}
