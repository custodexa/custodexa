package main

import (
	"context"
	"testing"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/pkg/crypto/vaulttransit"
)

// 冷啟動語義的守衛（本次的破壞性變更）。
//
// 委託模式的憑證只存在於解封世代的記憶體，行程結束即無處可取，故冷啟動必然取不到
// 憑證。既有語義（無憑證即非零退出）會讓委託部署的每一次重啟都表現為組態錯誤，
// 而它其實是設計上的正常狀態——改為進入已封存並等待人工解封。
//
// **`env` 的無人值守不受影響**：它的材料在部署檔內，缺或錯仍 fail-close。
// 這兩件事必須分開守，否則「把 env 也改成等人」會在同一次改動裡靜默發生。

// TestDelegatedColdStartSealed 委託模式的冷啟動進入已封存，不建構 provider。
func TestDelegatedColdStartSealed(t *testing.T) {
	d := &config.KEKDecision{Mode: config.KEKModeKMS}
	d.KMS.Provider = vaulttransit.ProviderVault
	s1 := &stage1{kekDecision: d}

	// (1) 段 2 延後至解封成功後執行——這正是「進入已封存」的實作表現。
	if !s1.sealedMode() {
		t.Fatal("委託模式的冷啟動應進入已封存（段 2 延後），而不是在段 1 建構 provider")
	}

	// (2) 段 1 的建構路徑對委託模式一律拒絕，且**拒絕的理由是「憑證由解封端點提供」**
	//     ——不是組態錯誤。呼叫端據此不得非零退出。
	if _, _, err := buildOwnedKEKProviderWithConstructors(
		context.Background(), d, nil, nil, nil); err == nil {
		t.Fatal("委託模式在無憑證持有者時仍建得出 provider——冷啟動會以無憑證的狀態往下走")
	}

	// (3) 錯誤不得洩漏任何組態值（此處連組態都還沒有）。
	_, _, err := buildOwnedKEKProviderWithConstructors(context.Background(), d, nil, nil, nil)
	if err == nil || !containsAll(err.Error(), "kms", "解封") {
		t.Fatalf("錯誤應指向解封路徑而非組態不齊：%v", err)
	}
}

// TestEnvColdStartUnattended `env` 的無人值守與 fail-close 皆不受本次改動影響。
func TestEnvColdStartUnattended(t *testing.T) {
	material := "0123456789abcdef0123456789abcdef"
	good := &config.KEKDecision{Mode: config.KEKModeEnv, Material: material, MaterialSource: "ENCRYPTION_KEY"}
	s1 := &stage1{kekDecision: good}

	// env 不延後段 2：有效材料即自動完成解封，無人值守。
	if s1.sealedMode() {
		t.Fatal("env 模式不得改為等待人工解封——無人值守是它的既有語義")
	}
	p, owner, err := buildOwnedKEKProviderWithConstructors(context.Background(), good, nil, nil, nil)
	if err != nil || p == nil {
		t.Fatalf("有效材料應建得出 provider: %v", err)
	}
	owner.Destroy()

	// 材料不合格仍 fail-close（回錯 → 呼叫端非零退出），不得改為等待人工輸入。
	bad := &config.KEKDecision{Mode: config.KEKModeEnv, Material: "too-short", MaterialSource: "ENCRYPTION_KEY"}
	if _, _, err := buildOwnedKEKProviderWithConstructors(context.Background(), bad, nil, nil, nil); err == nil {
		t.Fatal("env 的不合格材料應 fail-close，不得回落為等待人工解封")
	}

	// ui 的既有語義同樣不變：材料只由解封端點進入。
	ui := &stage1{kekDecision: &config.KEKDecision{Mode: config.KEKModeUI}}
	if !ui.sealedMode() {
		t.Fatal("ui 模式應維持啟動即封存")
	}
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		found := false
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
