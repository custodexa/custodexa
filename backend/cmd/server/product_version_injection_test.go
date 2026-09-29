package main

// 產品版本號的組裝根注入。
//
// 介面側欄的版本行讀 GET /auth/me 的 product_version，其值必須就是 /health 揭露的
// 那個 Version 變數（單一事實源）。identity 套件不持有版本字面值，只在組裝根被
// SetProductVersion 注入；漏接線時欄位因 omitempty 靜默消失、側欄就不顯示，
// 沒有任何錯誤訊號——故以組裝根建構出的真 AuthService 釘住。
//
// 判別式：未經組裝根的裸 AuthService 必為空字串（對照組先確認會亮）。

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/identity"
)

// TestAssemblyInjectsProductVersion 組裝根建構的 AuthService，其使用者資訊帶的
// product_version 等於 main.Version（/health 的同一個變數）。
func TestAssemblyInjectsProductVersion(t *testing.T) {
	env := newSealIntegrationEnv(t)

	if w := env.do(http.MethodPost, "/api/v1/seal/unseal", initPayload(testInitialKEK)); w.Code != http.StatusOK {
		t.Fatalf("初始化解封回 %d：%s", w.Code, w.Body.String())
	}

	snap := env.machine.Snapshot()
	g, ok := snap.Services.(*appGraph)
	if !ok || g == nil || g.deps.authService == nil {
		t.Fatalf("服務圖不可用：%T", snap.Services)
	}

	var u model.User
	if err := database.DB.Order("id ASC").First(&u).Error; err != nil {
		t.Fatalf("讀取 seed 使用者失敗: %v", err)
	}

	if Version == "" {
		t.Fatal("前提不成立：Version 為空，本測試分辨不出注入與否")
	}

	// 對照組：未注入的裸 AuthService 不帶版本
	bare := identity.NewAuthService(strings.Repeat("v", 48), time.Minute)
	bareInfo, err := bare.GetUserByID(u.ID)
	if err != nil {
		t.Fatalf("對照組 GetUserByID: %v", err)
	}
	if bareInfo.ProductVersion != "" {
		t.Fatalf("對照組（未注入）ProductVersion = %q，want 空——判別式不成立", bareInfo.ProductVersion)
	}

	info, err := g.deps.authService.GetUserByID(u.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if info.ProductVersion != Version {
		t.Fatalf("組裝根的 AuthService ProductVersion = %q，want %q（main.Version）", info.ProductVersion, Version)
	}
}
