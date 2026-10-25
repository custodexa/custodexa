package identity

import (
	"errors"
	"fmt"
	"reflect"
)

// 組裝自檢：指派關卡、授權變更分級與帳號身分操作關卡是否都已注入。
//
// 這三件缺任何一件，服務會退回「只有相容目錄、沒有分級與留痕落地面」的內部入口語義，
// 而 API 層照常運作、測試照常全綠。生產組裝呼叫這些檢查，缺件即拒絕啟動，
// 不降級為無留痕的預設。

// ErrControlsNotWired 指派與身分控制的注入不完整。
var ErrControlsNotWired = errors.New("指派關卡、授權變更分級或帳號身分操作關卡未注入")

func isNil(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Ptr, reflect.Interface, reflect.Map, reflect.Func, reflect.Slice, reflect.Chan:
		return rv.IsNil()
	}
	return false
}

func (g *GrantGrader) wired() bool {
	return g != nil && !isNil(g.auditTx) && !isNil(g.alerts)
}

func (o *ProtectedAccountOps) wired() bool {
	return o != nil && !isNil(o.auditTx) && !isNil(o.alerts)
}

// RequireControls 使用者服務的控制注入自檢。
func (s *UserService) RequireControls() error {
	if s.guard == nil || !s.grader.wired() || !s.acctOps.wired() {
		return fmt.Errorf("使用者服務: %w", ErrControlsNotWired)
	}
	return nil
}

// RequireControls 使用者群組服務的控制注入自檢。
func (s *UserGroupService) RequireControls() error {
	if s.guard == nil || !s.grader.wired() || isNil(s.auditTx) {
		return fmt.Errorf("使用者群組服務: %w", ErrControlsNotWired)
	}
	return nil
}

// RequireControls 認證服務的控制注入自檢（管理端停用 MFA 的身分控制權）。
func (s *AuthService) RequireControls() error {
	if !s.acctOps.wired() {
		return fmt.Errorf("認證服務: %w", ErrControlsNotWired)
	}
	return nil
}
