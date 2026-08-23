package dbproxy

import (
	"strings"
	"testing"
)

func TestBuildCommandPostgres(t *testing.T) {
	prog, args, env, err := BuildCommand(Target{
		Protocol: "postgres", Host: "db", Port: 0, Username: "u", Password: "secret", DBName: "app",
	}, "")
	if err != nil || prog != "psql" {
		t.Fatalf("prog=%s err=%v", prog, err)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "-p 5432") || !strings.Contains(joined, "app") {
		t.Errorf("args=%v", args)
	}
	// 密碼不得進 argv
	if strings.Contains(joined, "secret") {
		t.Error("password leaked into argv")
	}
	if strings.Contains(strings.Join(env, " "), "secret") {
		t.Errorf("password leaked into env=%v", env)
	}
}

func TestBuildCommandMySQLRedis(t *testing.T) {
	_, args, _, _ := BuildCommand(Target{Protocol: "mysql", Host: "h", Username: "u", Password: "p"}, "")
	if !containsStr(args, "-p") {
		t.Errorf("mariadb 有密碼時須帶不帶值的 -p（提示密碼）args=%v", args)
	}
	prog, args, _, _ := BuildCommand(Target{Protocol: "redis", Host: "h", Port: 6380}, "")
	if prog != "redis-cli" || !strings.Contains(strings.Join(args, " "), "6380") {
		t.Errorf("redis prog=%s args=%v", prog, args)
	}
	if containsStr(args, "--askpass") {
		t.Errorf("redis 無密碼時不應帶 --askpass args=%v", args)
	}
	_, args, _, _ = BuildCommand(Target{Protocol: "redis", Host: "h", Password: "p"}, "")
	if !containsStr(args, "--askpass") {
		t.Errorf("redis 有密碼時須帶 --askpass args=%v", args)
	}
}

// TestCredentialNeverEntersChildProcess 憑證面的守衛：
// 三種協議在有密碼時，密碼值與其歷史環境變數名一律不得出現在 argv 或環境。
// 這條擋住的是「有人為了省事把密碼放回 PGPASSWORD/MYSQL_PWD/REDISCLI_AUTH」——
// 那等於重新打開 `\lo_import '/proc/<pid>/environ'` 的憑證外洩路徑（含跨會話）。
func TestCredentialNeverEntersChildProcess(t *testing.T) {
	const pw = "s3cr3t-sentinel-value"
	legacyKeys := []string{"PGPASSWORD", "MYSQL_PWD", "REDISCLI_AUTH"}
	for _, proto := range []string{"postgres", "mysql", "redis"} {
		_, args, env, err := BuildCommand(Target{
			Protocol: proto, Host: "h", Username: "u", Password: pw, DBName: "app",
		}, "")
		if err != nil {
			t.Fatalf("%s: %v", proto, err)
		}
		for _, s := range append(append([]string{}, args...), env...) {
			if strings.Contains(s, pw) {
				t.Errorf("%s: 密碼出現在子程序啟動參數/環境", proto)
			}
			for _, k := range legacyKeys {
				if strings.HasPrefix(s, k+"=") {
					t.Errorf("%s: 憑證環境變數 %s 已復活（%s 面重新開啟）", proto, k, "/proc/<pid>/environ")
				}
			}
		}
		// 有密碼就必須有提示注入設定，否則會話會卡在看不見的密碼提示
		if p := PasswordPrompt(Target{Protocol: proto, Username: "u", Password: pw}); p == nil {
			t.Errorf("%s: 缺提示注入設定", proto)
		} else if p.Password != pw || p.Prompt == "" {
			t.Errorf("%s: 提示注入設定不完整 prompt=%q", proto, p.Prompt)
		}
	}
	if p := PasswordPrompt(Target{Protocol: "postgres", Username: "u"}); p != nil {
		t.Error("無密碼時不應武裝提示注入")
	}
}

// TestPasswordPromptStrings 提示字串為實測值（psql 16.14／mariadb 15.2／redis-cli 8.4.2）：
// 這些字串是注入的唯一觸發條件，寫錯即整個 DB 會話卡在看不見的提示
func TestPasswordPromptStrings(t *testing.T) {
	pg := PasswordPrompt(Target{Protocol: "postgres", Username: "postgres", Password: "x"})
	if pg.Prompt != "Password for user postgres: " || !pg.RequireCanonical {
		t.Errorf("psql prompt=%q canonical=%v", pg.Prompt, pg.RequireCanonical)
	}
	my := PasswordPrompt(Target{Protocol: "mysql", Username: "root", Password: "x"})
	if my.Prompt != "Enter password: " || !my.RequireCanonical {
		t.Errorf("mariadb prompt=%q canonical=%v", my.Prompt, my.RequireCanonical)
	}
	rd := PasswordPrompt(Target{Protocol: "redis", Password: "x"})
	if rd.Prompt != "Please input password: " || rd.RequireCanonical {
		t.Errorf("redis prompt=%q canonical=%v", rd.Prompt, rd.RequireCanonical)
	}
}

// TestBuildCommandLocalSurfaceFlags CLI 啟動即關閉可被間接利用的本機面
// psqlrc、pager、client 原生 sandbox、歷史檔
func TestBuildCommandLocalSurfaceFlags(t *testing.T) {
	_, args, env, _ := BuildCommand(Target{Protocol: "postgres", Host: "h", Username: "u"}, "")
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "-X") {
		t.Errorf("psql 須帶 -X（不讀 psqlrc）args=%v", args)
	}
	if !strings.Contains(joined, "-P pager=off") {
		t.Errorf("psql 須關 pager（pager 經 popen 進 shell）args=%v", args)
	}
	if !containsStr(env, "PSQL_HISTORY=/dev/null") {
		t.Errorf("psql 歷史檔須導向 /dev/null env=%v", env)
	}

	_, args, env, _ = BuildCommand(Target{Protocol: "mysql", Host: "h", Username: "u"}, "")
	if !containsStr(args, "--sandbox") {
		t.Errorf("mariadb 須帶 --sandbox args=%v", args)
	}
	// LOAD DATA LOCAL INFILE 是等價於 psql \lo_import 的本機讀檔原語，
	// 且不在 --sandbox 守備範圍內
	if !containsStr(args, "--local-infile=0") {
		t.Errorf("mariadb 須帶 --local-infile=0 args=%v", args)
	}
	if !containsStr(env, "MYSQL_HISTFILE=/dev/null") {
		t.Errorf("mariadb 歷史檔須導向 /dev/null env=%v", env)
	}

	_, _, env, _ = BuildCommand(Target{Protocol: "redis", Host: "h"}, "")
	if !containsStr(env, "REDISCLI_HISTFILE=/dev/null") {
		t.Errorf("redis-cli 歷史檔須導向 /dev/null env=%v", env)
	}
}

func TestBuildCommandUnsupported(t *testing.T) {
	if _, _, _, err := BuildCommand(Target{Protocol: "mongodb"}, ""); err == nil {
		t.Error("expected error for unsupported protocol")
	}
}

func TestBuildCommandTLSModes(t *testing.T) {
	// postgres：TLS 走 PGSSLMODE/PGSSLROOTCERT 環境
	_, _, env, _ := BuildCommand(Target{Protocol: "postgres", Host: "h", Username: "u", TLSMode: "disable"}, "")
	if !containsStr(env, "PGSSLMODE=disable") {
		t.Errorf("postgres disable env=%v", env)
	}
	_, _, env, _ = BuildCommand(Target{Protocol: "postgres", Host: "h", Username: "u", TLSMode: "verify-ca"}, "/tmp/ca.pem")
	if !containsStr(env, "PGSSLMODE=verify-ca") || !containsStr(env, "PGSSLROOTCERT=/tmp/ca.pem") {
		t.Errorf("postgres verify-ca env=%v", env)
	}

	// mysql(mariadb)：TLS 走旗標
	_, args, _, _ := BuildCommand(Target{Protocol: "mysql", Host: "h", Username: "u", TLSMode: "disable"}, "")
	if !strings.Contains(strings.Join(args, " "), "--skip-ssl") {
		t.Errorf("mysql disable args=%v", args)
	}
	_, args, _, _ = BuildCommand(Target{Protocol: "mysql", Host: "h", Username: "u", TLSMode: "verify-ca"}, "/tmp/ca.pem")
	j := strings.Join(args, " ")
	if !strings.Contains(j, "--ssl-verify-server-cert") || !strings.Contains(j, "--ssl-ca=/tmp/ca.pem") {
		t.Errorf("mysql verify-ca args=%v", args)
	}

	// verify-full：postgres 原生檔位含主機名核對；mysql 同 verify-ca 映射
	//（--ssl-verify-server-cert 即含主機名核對）；redis 等同 verify-ca
	_, _, env, _ = BuildCommand(Target{Protocol: "postgres", Host: "h", Username: "u", TLSMode: "verify-full"}, "/tmp/ca.pem")
	if !containsStr(env, "PGSSLMODE=verify-full") || !containsStr(env, "PGSSLROOTCERT=/tmp/ca.pem") {
		t.Errorf("postgres verify-full env=%v", env)
	}
	_, args, _, _ = BuildCommand(Target{Protocol: "mysql", Host: "h", Username: "u", TLSMode: "verify-full"}, "/tmp/ca.pem")
	if !strings.Contains(strings.Join(args, " "), "--ssl-verify-server-cert") {
		t.Errorf("mysql verify-full args=%v", args)
	}
	_, args, _, _ = BuildCommand(Target{Protocol: "redis", Host: "h", TLSMode: "verify-full"}, "/tmp/ca.pem")
	j = strings.Join(args, " ")
	if !strings.Contains(j, "--tls") || !strings.Contains(j, "--cacert") || strings.Contains(j, "--insecure") {
		t.Errorf("redis verify-full args=%v", args)
	}

	// 預設（空 TLSMode）不啟用 TLS，但須明示關掉憑證核對：MariaDB client 11.4
	// 起「有提供密碼」會自動打開 --ssl-verify-server-cert，密碼改走 -p 提示注入
	// 後若不明示，等於讓每個沒設 TLS 檔位的既有資產突然要求可信憑證鏈
	_, args, env, _ = BuildCommand(Target{Protocol: "mysql", Host: "h", Username: "u", Password: "p"}, "")
	joinedTLS := strings.Join(args, " ")
	if strings.Contains(joinedTLS, "--ssl ") || containsStr(args, "--ssl") {
		t.Errorf("預設不應主動啟用 TLS args=%v", args)
	}
	if !containsStr(args, "--ssl-verify-server-cert=0") {
		t.Errorf("預設須明示關閉憑證核對（避免 -p 觸發 client 自動核對）args=%v", args)
	}
	// require＝加密但不驗憑證，同樣須明示，否則被自動升級成等同 verify-full
	_, args, _, _ = BuildCommand(Target{Protocol: "mysql", Host: "h", Username: "u", Password: "p", TLSMode: "require"}, "")
	if !containsStr(args, "--ssl") || !containsStr(args, "--ssl-verify-server-cert=0") {
		t.Errorf("require 須為「加密不驗憑證」args=%v", args)
	}
	_, _, env, _ = BuildCommand(Target{Protocol: "postgres", Host: "h", Username: "u"}, "")
	if containsStr(env, "PGSSLMODE=disable") || containsStr(env, "PGSSLMODE=require") {
		t.Errorf("預設不應設 PGSSLMODE env=%v", env)
	}
}

func containsStr(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
