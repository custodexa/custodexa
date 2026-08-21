package main

import (
	"net/http/httptest"
	"testing"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

// CORS 設定守衛。
//
// 迴歸背景：release 模式未設 CORS_ALLOWED_ORIGINS 時，原實作的分支只印 log 而不對
// config 做任何設定，使 cors.New() 於 Validate 失敗時 panic
// （"conflict settings: all origins disabled"）。而 .env.example 的出廠值即為空，
// 等於「照專案自身文件部署 release，backend 起不來」。
//
// 該缺陷未被既有測試涵蓋，因 CORS 設定原本內嵌於 main() 不可測；抽出
// buildCORSConfig 後始能以單測鎖住。

// TestBuildCORSConfigNeverPanics 三種組態皆須通過 cors 套件的 Validate。
//
// 直接呼叫 cors.New 而非只檢查欄位——Validate 的規則屬該套件契約，
// 自行複製判斷條件會與套件升版脫節，實際呼叫才是真正的驗證。
func TestBuildCORSConfigNeverPanics(t *testing.T) {
	cases := []struct {
		name      string
		origins   []string
		isRelease bool
	}{
		{"有 allowlist（dev）", []string{"https://example.com"}, false},
		{"有 allowlist（release）", []string{"https://example.com"}, true},
		{"無 allowlist（release）——原缺陷情境", nil, true},
		{"無 allowlist（dev）", nil, false},
		{"空切片（release）——等同未設", []string{}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := buildCORSConfig(c.origins, c.isRelease)
			if err := cfg.Validate(); err != nil {
				t.Fatalf("CORS 設定未通過 cors 套件 Validate：%v\n"+
					"這會使 cors.New() panic，backend 無法啟動", err)
			}
			// Validate 過不代表 New 一定安全，實際建構一次
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("cors.New() panic：%v", r)
				}
			}()
			_ = cors.New(cfg)
		})
	}
}

// TestReleaseWithoutAllowlistRejectsCrossOrigin release 且無 allowlist 時須拒絕所有跨源。
//
// 不只驗「不 panic」——若為了避開 panic 而誤設成 AllowAllOrigins，
// 反而會在生產環境全面放行跨源，比原本的 panic 更危險。
func TestReleaseWithoutAllowlistRejectsCrossOrigin(t *testing.T) {
	cfg := buildCORSConfig(nil, true)

	if cfg.AllowAllOrigins {
		t.Fatal("release 未設 allowlist 時竟啟用 AllowAllOrigins——生產環境全面放行跨源")
	}
	if cfg.AllowCredentials {
		t.Error("release 未設 allowlist 時不應允許帶憑證")
	}
	if cfg.AllowOriginFunc == nil {
		t.Fatal("release 未設 allowlist 時須以 AllowOriginFunc 顯式表達拒絕；" +
			"留空會使 Validate 判定為 conflict 而 panic")
	}
	for _, origin := range []string{
		"https://evil.example", "http://localhost:3000", "null", "https://custodexa.example",
	} {
		if cfg.AllowOriginFunc(origin) {
			t.Errorf("origin %q 竟被允許——release 未設 allowlist 應拒絕所有跨源", origin)
		}
	}

	// 行為層：跨源請求不得取得 Access-Control-Allow-Origin
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(cors.New(cfg))
	r.GET("/probe", func(c *gin.Context) { c.Status(200) })

	req := httptest.NewRequest("GET", "/probe", nil)
	req.Header.Set("Origin", "https://evil.example")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("跨源請求取得 Access-Control-Allow-Origin=%q，應為空", got)
	}
}

// TestCORSAllowlistGrantsCredentials 有顯式 allowlist 時才允許帶憑證。
func TestCORSAllowlistGrantsCredentials(t *testing.T) {
	cfg := buildCORSConfig([]string{"https://ops.example"}, true)
	if !cfg.AllowCredentials {
		t.Error("顯式 allowlist（來源受限）應允許帶憑證")
	}
	if cfg.AllowAllOrigins {
		t.Error("有 allowlist 時不應同時啟用 AllowAllOrigins（Validate 會判為衝突）")
	}
	if len(cfg.AllowOrigins) != 1 || cfg.AllowOrigins[0] != "https://ops.example" {
		t.Errorf("allowlist 未正確帶入：%v", cfg.AllowOrigins)
	}
}

// TestDevWithoutAllowlistAllowsAll dev 無 allowlist 時全開且不帶憑證。
func TestDevWithoutAllowlistAllowsAll(t *testing.T) {
	cfg := buildCORSConfig(nil, false)
	if !cfg.AllowAllOrigins {
		t.Error("dev 未設 allowlist 應全開，便於本地前後端分離開發")
	}
	if cfg.AllowCredentials {
		t.Error("AllowAllOrigins 時 AllowCredentials 必須為 false（否則 Validate 衝突）")
	}
}
