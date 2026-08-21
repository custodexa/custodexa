package middleware

// emailPtr 測試輔助：model.User.Email 改為 *string 後（profile-display-name D7），
// 測試以此包裝字面 email。
func emailPtr(s string) *string { return &s }
