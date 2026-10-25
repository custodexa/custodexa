package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestStartupRecoveryPrecedesSchedulersAndRoutes 啟動收束（含未消耗的承接紀錄）所在的
// RecoverInterruptedMembers 呼叫，必須早於改密排程、重試排程與路由掛載。
// 以 stage2.go 的字面順序釘住；任何一個被挪到收束之前即轉紅。
func TestStartupRecoveryPrecedesSchedulersAndRoutes(t *testing.T) {
	body, err := os.ReadFile(filepath.Join(lifecycleModuleRoot(t), "cmd", "server", "stage2.go"))
	if err != nil {
		t.Fatalf("讀取 stage2.go 失敗: %v", err)
	}
	src := string(body)
	at := func(needle string) int {
		t.Helper()
		if strings.Count(src, needle) != 1 {
			t.Fatalf("stage2.go 內 %q 應恰出現一次，實際 %d 次", needle, strings.Count(src, needle))
		}
		return strings.Index(src, needle)
	}
	recovery := at("credentialRotations.RecoverInterruptedMembers()")
	for _, later := range []string{
		"changeSecretScheduler.Start()",
		"changeSecretRetryScheduler.Start()",
		`mark("apiHandlers")`,
	} {
		if recovery >= at(later) {
			t.Errorf("RecoverInterruptedMembers 必須早於 %s（承接紀錄的收束要在任何推進或請求開始之前）", later)
		}
	}
}
