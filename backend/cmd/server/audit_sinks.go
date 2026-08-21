package main

import (
	"fmt"
	"reflect"

	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/pkg/gatewayapi"
)

// 審計落地面的注入自檢（modular-architecture W4 任務 4.7）。
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
		return fmt.Errorf("交易內審計落地面（port.TxSink）未注入：" +
			"強制審計是「全操作審計」紅線的唯一落地路徑，未接線即拒絕啟動，" +
			"不得降級為靜默略過")
	}
	return nil
}

// requireAlertSink 指令告警落地面的注入自檢（modular-architecture W5 5.4）。
//
// **落點 SHALL 早於 alertMatcher 與 sshHandler 的建構**——兩者是它僅有的消費者，
// 自檢晚於任一者等於讓「未注入」在第一次告警時才以 log 現形。
//
// 為何告警也 fail-close 到啟動失敗：BD-1 的教訓不是「有人寫錯欄位」，而是
// **一整類安全證據可以在沒有任何東西變紅的情況下停止離機**。sink 未注入的後果
// 與 BD-1 完全同型（阻斷告警不入庫、不 tee），差別只在它更徹底；
// 允許它靜默啟動等於把剛修好的洞留一個開關在外面。
func requireAlertSink(sink gatewayapi.AlertSink) error {
	if isNilSink(sink) {
		return fmt.Errorf("指令告警落地面（gatewayapi.AlertSink）未注入：" +
			"阻斷告警的入庫、通知與 syslog 離機轉發共用本出口，未接線即拒絕啟動，" +
			"不得降級為 no-op 而使阻斷證據靜默消失（BD-1）")
	}
	return nil
}

// requireAuditAsyncSinks 非同步審計投遞面的注入自檢（可變參數：主 sink 與 C-plain 直寫 sink）。
func requireAuditAsyncSinks(sinks ...gatewayapi.AsyncSink) error {
	for i, sink := range sinks {
		if isNilSink(sink) {
			return fmt.Errorf("第 %d 個非同步審計投遞面（gatewayapi.AsyncSink）未注入："+
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
