package policy

import (
	"errors"
	"fmt"
	"unicode"
	"unicode/utf8"

	"github.com/custodexa/backend/internal/apierror"
)

// 密碼政策的**無狀態合規子集**（自 identity 拆出，modular-architecture W3 3.3／R3.1 §5.2）。
//
// **為何只拆這一半**：`password_policy.go` 原本一檔混住兩種歸屬——政策判定
// （純函式、只讀政策鍵、零 DB）與密碼歷史的讀寫（`password_histories` 表、bcrypt
// 逐筆比對、裁剪保留筆數）。後者是 identity 自有表的存取，掛在 `*UserService` 上
// 且 Go 語法上不可分割；前者才是政策域。故拆檔而非整檔搬遷：判定入 policy，
// 歷史留 identity（`ValidateNewPassword`／`CheckPasswordCompliance`／
// `isPasswordReused`／`recordPasswordHistory` 四個方法）。
//
// 違規型別與 4 個哨兵一併遷入：它們是**判定的產物**，identity 的
// `ValidateNewPassword` 也建構其中兩種（TooLong／Reused），留在 identity 會讓
// policy 判定回傳的錯誤型別反向依賴 identity。

var (
	// ErrPasswordTooShort 密碼長度不足（訊息由 validator 依政策組裝）
	ErrPasswordTooShort = errors.New("密碼長度不足")
	// ErrPasswordTooLong 密碼超過 bcrypt 72-byte 上限
	ErrPasswordTooLong = errors.New("密碼過長")
	// ErrPasswordComplexity 密碼組成不符（須含字母與數字）
	ErrPasswordComplexity = errors.New("密碼必須同時包含字母與數字")
	// ErrPasswordReused 密碼與最近使用過的密碼重複
	ErrPasswordReused = errors.New("新密碼不可與最近使用過的密碼相同")
)

// PasswordPolicyViolation 密碼政策違規（帶使用者可讀訊息，handler 直接回 400）。
// Code/Params 為 i18n 機器碼與插值：service 在建構時綁定（handler 無法從 Reason
// 反推動態數值，且 ErrPasswordReused 對應兩種訊息，故由此處指定唯一 code）。
// Message 保留給審計慣例欄位與 legacy error 欄，不隨 code 化移除。
type PasswordPolicyViolation struct {
	Reason  error
	Message string
	Code    apierror.ErrCode
	Params  map[string]any
}

func (e *PasswordPolicyViolation) Error() string { return e.Message }

// Unwrap 讓 errors.Is 可比對底層 sentinel
func (e *PasswordPolicyViolation) Unwrap() error { return e.Reason }

// CheckCompliance 無狀態政策合規子集：rune 長度＋字母數字組成，零 DB 存取。
// 登入 gate 以此對現行明文回溯執法（明文僅登入時可得）。
// 不含歷史比對（歷史重用屬設密時政策，現行密碼必在歷史內）、不含 72-byte
// 上界（到得了登入 gate 的密碼已通過 bcrypt 比對，必 <=72 bytes）。
//
// 原名 `checkPasswordCompliance`（`internal/service` 的未匯出包級函式）；
// 拆包後改為 policy 的匯出面，消費者為 identity 的
// `UserService.CheckPasswordCompliance` 與 `AuthService` 的登入回溯執法閘。
func CheckCompliance(policies *SecurityPolicyService, password string) error {
	if policies == nil {
		return nil
	}

	// 以字元數（rune）而非位元組數判長度（PW-1）：否則多位元組字元讓
	// 「6 個中文字」滿足「12 字元」政策，弱化 8.3.6
	minLength := policies.GetInt(PolicyPasswordMinLength)
	if utf8.RuneCountInString(password) < minLength {
		return &PasswordPolicyViolation{
			Reason:  ErrPasswordTooShort,
			Message: fmt.Sprintf("密碼長度至少需 %d 字元", minLength),
			Code:    apierror.CodePasswordTooShort,
			Params:  map[string]any{"min": minLength},
		}
	}

	if policies.GetBool(PolicyPasswordRequireAlnum) && !hasLetterAndDigit(password) {
		return &PasswordPolicyViolation{
			Reason:  ErrPasswordComplexity,
			Message: ErrPasswordComplexity.Error(),
			Code:    apierror.CodePasswordComplexity,
		}
	}

	return nil
}

// hasLetterAndDigit 檢查同時含字母與數字（PCI 8.3.6: numeric and alphabetic）
func hasLetterAndDigit(s string) bool {
	hasLetter, hasDigit := false, false
	for _, r := range s {
		switch {
		case unicode.IsLetter(r):
			hasLetter = true
		case unicode.IsDigit(r):
			hasDigit = true
		}
		if hasLetter && hasDigit {
			return true
		}
	}
	return false
}
