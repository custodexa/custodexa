package audit

import (
	"errors"
	"testing"
)

func TestNormalizeProtocols(t *testing.T) {
	t.Run("空字串為全協議且合法", func(t *testing.T) {
		got, err := normalizeProtocols("")
		if err != nil || got != "" {
			t.Fatalf("期望 (\"\", nil)，得到 (%q, %v)", got, err)
		}
	})

	t.Run("合法清單正規化為小寫去空白", func(t *testing.T) {
		got, err := normalizeProtocols(" MySQL, postgres ,SSH")
		if err != nil {
			t.Fatalf("不應報錯: %v", err)
		}
		if got != "mysql,postgres,ssh" {
			t.Fatalf("正規化結果錯誤: %q", got)
		}
	})

	t.Run("未知協議被拒", func(t *testing.T) {
		for _, raw := range []string{"rdp", "vnc", "foo", "ssh,foo"} {
			if _, err := normalizeProtocols(raw); !errors.Is(err, ErrInvalidProtocols) {
				t.Fatalf("%q 應回 ErrInvalidProtocols，得到 %v", raw, err)
			}
		}
	})

	t.Run("純逗號與空白視同全協議", func(t *testing.T) {
		got, err := normalizeProtocols(" , ,")
		if err != nil || got != "" {
			t.Fatalf("期望 (\"\", nil)，得到 (%q, %v)", got, err)
		}
	})
}

func TestValidateRuleProtocols(t *testing.T) {
	base := func() *AlertRuleRequest {
		return &AlertRuleRequest{Name: "r", Pattern: `rm\s+-rf`, Severity: "high"}
	}

	t.Run("未傳 protocols 合法", func(t *testing.T) {
		if err := validateRule(base()); err != nil {
			t.Fatalf("不應報錯: %v", err)
		}
	})

	t.Run("合法 protocols 通過", func(t *testing.T) {
		req := base()
		p := "mysql,postgres"
		req.Protocols = &p
		if err := validateRule(req); err != nil {
			t.Fatalf("不應報錯: %v", err)
		}
	})

	t.Run("非法 protocols 擋下", func(t *testing.T) {
		req := base()
		p := "rdp"
		req.Protocols = &p
		if err := validateRule(req); !errors.Is(err, ErrInvalidProtocols) {
			t.Fatalf("應回 ErrInvalidProtocols，得到 %v", err)
		}
	})
}
