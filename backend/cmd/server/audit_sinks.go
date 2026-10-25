package main

import (
	"fmt"
	"reflect"

	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/pkg/gatewayapi"
)

// 審計落地面的注入自檢。
//
// # 為何是啟動 fail-close，而不是「未注入就跳過」
//
// 現況有兩種前例：
//
//	cmd/server/stage2.go:239/242  InitAuditIntegrityVersioned 失敗即 return fail(...)（啟動不成立）
//	internal/modules/audit/alert_matcher.go  `if notifier := Get...(); notifier != nil` 靜默跳過
//
// **本檔比照前者，SHALL NOT 沿用後者**。理由不是風格偏好：sink 是「全操作審計」
// 這條紅線的唯一落地路徑，未注入時寬鬆跳過的後果是**審計靜默消失而系統看起來正常**
// ——而且測試會更綠（fail-close 路徑永遠成功）。alert_matcher 那種寬鬆跳過所適用的
// 對象是**下游 tee**（通知、syslog 轉發），漏掉只損失附加價值，主軌證據仍在；
// 兩者不可類比。
//
// # 為何要 reflect
//
// Go 的 typed-nil 陷阱：`var s *audit.TxSink; var i port.TxSink = s` 之下 `i != nil`
// 為真，但任何方法呼叫都會打到 nil 接收器。若只寫 `if sink == nil`，一個
// 「有型別但沒有值」的注入會通過自檢、在第一次寫審計時才 panic（或更糟：
// 對值型別接收器而言根本不 panic，而是寫進一個零值物件）。故一併驗 Kind 為指標／
// 介面／map／func 時的 IsNil。

// requireAuditTxSink 交易內審計落地面（強制審計）的注入自檢。
//
// **落點 SHALL 早於任何 TxSink 消費者的建構**——LDAP seed 遷移在段 2 期間就會
// 寫審計（post-unseal 佇列），自檢晚於它等於沒檢查。
func requireAuditTxSink(sink port.TxSink) error {
	if isNilSink(sink) {
		return fmt.Errorf("交易內稽核落地面（port.TxSink）未注入：" +
			"強制稽核是「全操作稽核」紅線的唯一落地路徑，未接線即拒絕啟動，" +
			"不得降級為靜默略過")
	}
	return nil
}

// requireAlertSink 指令告警落地面的注入自檢。
//
// **落點 SHALL 早於 alertMatcher 與 sshHandler 的建構**——兩者是它僅有的消費者，
// 自檢晚於任一者等於讓「未注入」在第一次告警時才以 log 現形。
//
// 為何告警也 fail-close 到啟動失敗：「漏 tee」那次的教訓不是「有人寫錯欄位」，而是
// **一整類安全證據可以在沒有任何東西變紅的情況下停止離機**。sink 未注入的後果
// 與它完全同型（阻斷告警不入庫、不 tee），差別只在它更徹底；
// 允許它靜默啟動等於把剛修好的洞留一個開關在外面。
func requireAlertSink(sink gatewayapi.AlertSink) error {
	if isNilSink(sink) {
		return fmt.Errorf("指令告警落地面（gatewayapi.AlertSink）未注入：" +
			"阻斷告警的入庫、通知與 syslog 離機轉發共用本出口，未接線即拒絕啟動，" +
			"不得降級為 no-op 而使阻斷證據靜默消失")
	}
	return nil
}

// requireSystemAlertSink 交易內系統告警落地面的注入自檢。
//
// 與 requireAuditTxSink 同理由：這個出口是系統告警「發生就一定產生」的唯一路徑，
// 未注入時寬鬆跳過會讓告警靜默消失而業務照樣成立，所以未接線即拒絕啟動。
// 同樣以 reflect 驗 typed-nil。
func requireSystemAlertSink(sink port.SystemAlertSink) error {
	if isNilSink(sink) {
		return fmt.Errorf("交易內系統告警落地面（port.SystemAlertSink）未注入：" +
			"系統告警是補償控制的唯一出口，未接線即拒絕啟動，" +
			"不得降級為空實作而使告警靜默消失")
	}
	return nil
}

// requireAuditAsyncSinks 非同步審計投遞面的注入自檢（可變參數：主 sink 與 C-plain 直寫 sink）。
func requireAuditAsyncSinks(sinks ...gatewayapi.AsyncSink) error {
	for i, sink := range sinks {
		if isNilSink(sink) {
			return fmt.Errorf("第 %d 個非同步稽核投遞面（gatewayapi.AsyncSink）未注入："+
				"未接線即拒絕啟動，不得降級為 no-op", i+1)
		}
	}
	return nil
}

// isNilSink 判定介面值是否「沒有可用的實作」（含 typed-nil）。
func isNilSink(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Ptr, reflect.Interface, reflect.Map, reflect.Func, reflect.Slice, reflect.Chan:
		return rv.IsNil()
	default:
		return false
	}
}

// verifyIdentitySourceSinks 身分來源設定變更與映射寫入留痕的啟動自檢：目錄與身分提供者兩個服務的
// 稽核與告警落地面都已注入，映射規則與釘住的授權變更分級已注入。檢的是服務實際持有的欄位（含 typed-nil），不只是組裝根的變數，
// 所以接線那一行被刪掉或換成別的值都會在啟動時現形。
func verifyIdentitySourceSinks(ldap, oidc interface{ SourceChangeSinksReady() error },
	graded ...interface{ GrantGraderReady() error }) error {
	if isNilSink(ldap) || isNilSink(oidc) {
		return fmt.Errorf("身分來源服務未建構，無法確認留痕落地面")
	}
	if err := ldap.SourceChangeSinksReady(); err != nil {
		return err
	}
	if err := oidc.SourceChangeSinksReady(); err != nil {
		return err
	}
	// 映射規則寫入與釘住的授權變更分級與留痕（自我授權、管理類發放）
	for _, g := range graded {
		if isNilSink(g) {
			return fmt.Errorf("映射規則寫入服務未建構，無法確認授權變更分級與留痕")
		}
		if err := g.GrantGraderReady(); err != nil {
			return err
		}
	}
	return nil
}

// requireIdentityControls 指派關卡、授權變更分級與帳號身分操作關卡的注入自檢。
// 三者是指派與身分操作的留痕出口：缺任何一件，服務退回只有相容目錄、沒有分級與留痕的內部入口語義，
// 而 API 與測試都照常通過——所以啟動時 fail-close，不降級。
func requireIdentityControls(guard *identity.AssignmentGuard, grader *identity.GrantGrader, ops *identity.ProtectedAccountOps) error {
	if isNilSink(guard) || isNilSink(grader) || isNilSink(ops) {
		return fmt.Errorf("指派關卡、授權變更分級或帳號身分操作關卡未注入：" +
			"授權變更與系統安全管理員帳號操作的留痕由它們承擔，未接線即拒絕啟動，不得降級為無留痕的預設")
	}
	return nil
}
