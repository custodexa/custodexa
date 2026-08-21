package localpty

import "testing"

func TestSafeArg(t *testing.T) {
	cases := []struct {
		name, value string
		ok          bool
	}{
		{"正常主機", "db.internal", true},
		{"空值放行", "", true},
		{"flag 注入 psql command", "--command=SELECT 1", false},
		{"flag 注入短旗標", "-h", false},
		{"換行注入", "host\nmalicious", false},
		{"歸位注入", "host\rx", false},
		{"NUL 截斷", "host\x00x", false},
		{"含 - 但非開頭合法", "my-pod-0", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := SafeArg("欄位", c.value)
			if (err == nil) != c.ok {
				t.Errorf("SafeArg(%q) err=%v, 期望 ok=%v", c.value, err, c.ok)
			}
		})
	}
}

func TestSafeSecret(t *testing.T) {
	// token 可合法以 - 開頭，但不得含換行（防 kubeconfig YAML 注入）
	if err := SafeSecret("Token", "-starts-with-dash-ok"); err != nil {
		t.Errorf("token 以 - 開頭應放行: %v", err)
	}
	if err := SafeSecret("Token", "tok\n    server: https://evil"); err == nil {
		t.Error("token 含換行應拒絕（kubeconfig YAML 注入）")
	}
}
