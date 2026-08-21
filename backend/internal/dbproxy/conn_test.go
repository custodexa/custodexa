package dbproxy

import "testing"

// PTY 生命週期測試在 internal/localpty（共用實體）；此處僅驗 dbproxy 自身分支

func TestStartUnsupportedProtocol(t *testing.T) {
	_, err := Start(Target{Protocol: "mongodb"}, 80, 24)
	if err == nil {
		t.Fatal("不支援協議應回錯")
	}
}

func TestBuildCommandRejectsFlagInjection(t *testing.T) {
	cases := []struct {
		name string
		t    Target
	}{
		{"dbname flag 注入", Target{Protocol: "postgres", Host: "h", Username: "u", DBName: "--command=SELECT 1"}},
		{"host flag 注入", Target{Protocol: "mysql", Host: "-h evil", Username: "u"}},
		{"username 換行", Target{Protocol: "postgres", Host: "h", Username: "u\nx"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, _, _, err := BuildCommand(c.t, ""); err == nil {
				t.Errorf("%s 應被拒絕", c.name)
			}
		})
	}
}
