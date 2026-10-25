package notifycat

import (
	"strings"
	"testing"
)

// TestHostKeyMismatchAlertStatesCredentialExposure 主機金鑰不符告警三語都明示：放行時平台已代為送出登入憑證，
// 拒絕時未送出；路徑以詞庫呈現（含 agent 終端）。
func TestHostKeyMismatchAlertStatesCredentialExposure(t *testing.T) {
	base := map[string]string{
		"actor": "alice", "severity": "high", "record_source": "own",
		"recorded_fingerprint": "SHA256:aaa", "observed_fingerprint": "SHA256:bbb", "observed_algorithm": "ssh-ed25519",
	}
	want := map[string]struct{ allowed, refused, agent string }{
		"zh-TW": {"送出登入憑證", "未送出", "代理"},
		"en-US": {"credentials", "not sent", "agent"},
		"ja-JP": {"認証情報", "送信していません", "エージェント"},
	}
	for lang, w := range want {
		p := map[string]string{"path": "terminal", "outcome": "allowed"}
		for k, v := range base {
			p[k] = v
		}
		_, text := Render(lang, EventSystemAlertHostKeyMismatch, p)
		if !strings.Contains(text, w.allowed) {
			t.Fatalf("%s 放行告警應明示憑證已送出（含 %q）: %s", lang, w.allowed, text)
		}
		if strings.Contains(text, "allowed") && lang != "en-US" {
			t.Fatalf("%s 告警不得直接吐 enum 機器碼: %s", lang, text)
		}
		p["outcome"], p["path"] = "refused", "agent_terminal"
		_, text = Render(lang, EventSystemAlertHostKeyMismatch, p)
		if !strings.Contains(text, w.refused) || !strings.Contains(text, w.agent) {
			t.Fatalf("%s 拒絕告警應明示未送出且路徑含代理終端（%q、%q）: %s", lang, w.refused, w.agent, text)
		}
	}
}
