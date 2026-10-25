package main

import (
	"fmt"
	"strings"
)

// revalidationWired 背景工作的授權重驗判定器是否已注入。
type revalidationWired interface{ RevalidationWired() bool }

// credentialAuthorizationWiringGaps 回傳授權重驗判定器沒有注入的背景工作入口名稱。
//
// 三處（改密執行器、候選重試、輪替引擎）缺任一都會讓失權者的背景工作失去最後一道關卡；
// 執行端雖然對未注入一律拒絕，這裡仍在啟動時直接擋下，讓漏接的症狀是啟動失敗而不是
// 每次排程都被拒絕並告警。
func credentialAuthorizationWiringGaps(named map[string]revalidationWired) []string {
	var gaps []string
	for _, name := range credentialAuthorizationWiringNames() {
		w, ok := named[name]
		if !ok || w == nil || !w.RevalidationWired() {
			gaps = append(gaps, name)
		}
	}
	return gaps
}

// credentialAuthorizationWiringNames 需要注入重驗判定器的入口（順序固定，供錯誤訊息與測試比對）。
func credentialAuthorizationWiringNames() []string {
	return []string{"changeSecretRunner", "changeSecretRetryRunner", "credentialRotations"}
}

func credentialAuthorizationWiringError(gaps []string) error {
	if len(gaps) == 0 {
		return nil
	}
	return fmt.Errorf("背景工作授權重驗判定器未注入: %s", strings.Join(gaps, ", "))
}

// hostIdentityTakeoverWiringError 人工承接服務依賴缺口轉成啟動錯誤（無缺口回 nil）。
func hostIdentityTakeoverWiringError(gaps []string) error {
	if len(gaps) == 0 {
		return nil
	}
	return fmt.Errorf("主機身分承接服務依賴未注入: %s", strings.Join(gaps, ", "))
}
