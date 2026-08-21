package dbproxy

import (
	"strings"
	"testing"
)

// mssql 的憑證紅線守衛（database-protocol 准入準則的唯一問題：
// 真憑證是否離開後端進入 CLI 子程序）。sqlcmd 有兩條會違反的預設路徑——
// argv 的 -P 與環境的 SQLCMDPASSWORD——本測試雙向釘死兩者皆不存在。
func TestBuildCommandMSSQLNoCredentialInArgvOrEnv(t *testing.T) {
	const secret = "sup3r-s3cret-pw"
	prog, args, env, err := BuildCommand(Target{
		Protocol: "mssql", Host: "sqlhost", Port: 0,
		Username: "sa", Password: secret, DBName: "app",
	}, "")
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if prog != "sqlcmd" {
		t.Fatalf("prog=%q, want sqlcmd", prog)
	}

	joinedArgs := strings.Join(args, " ")
	joinedEnv := strings.Join(env, " ")

	if strings.Contains(joinedArgs, secret) {
		t.Errorf("密碼洩漏進 argv: %v", args)
	}
	if strings.Contains(joinedEnv, secret) {
		t.Errorf("密碼洩漏進 env: %v", env)
	}
	// -P 是 sqlcmd 的密碼旗標；出現即代表有人把密碼搬回 argv
	if containsStr(args, "-P") || strings.Contains(joinedArgs, "--password") {
		t.Errorf("argv 不得含 -P／--password: %v", args)
	}
	for _, e := range env {
		if strings.HasPrefix(e, "SQLCMDPASSWORD=") {
			t.Errorf("env 不得含 SQLCMDPASSWORD: %v", env)
		}
		// SQLCMD_LANG 會讓提示字串經 localizer 在地化，PasswordPrompt 的
		// matcher 隨即失準、注入永不觸發（無聲斷線）
		if strings.HasPrefix(e, "SQLCMD_LANG=") {
			t.Errorf("env 不得含 SQLCMD_LANG（提示字串在地化會使 matcher 失準）: %v", env)
		}
	}
}

// -X 是 cobra 的 Int 旗標且無 NoOptDefVal：必須是 "-X" "0" 兩個獨立 argv 元素，
// 裸 -X 或合併成 "-X0" 都會被 cobra 拒絕（會話直接起不來）。
func TestBuildCommandMSSQLDisableCmdFlagShape(t *testing.T) {
	_, args, _, err := BuildCommand(Target{
		Protocol: "mssql", Host: "h", Username: "sa", Password: "p",
	}, "")
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	idx := -1
	for i, a := range args {
		if a == "-X" {
			idx = i
			break
		}
	}
	if idx < 0 {
		t.Fatalf("argv 缺 -X（:!! 與 :ED 未關閉）: %v", args)
	}
	if idx+1 >= len(args) || args[idx+1] != "0" {
		t.Fatalf("-X 之後須緊接獨立的 \"0\" 元素: %v", args)
	}
	// 合併形式（-X0）與 -X 1（遇到即結束程序）皆不可出現
	if containsStr(args, "-X0") || containsStr(args, "-X=0") {
		t.Errorf("-X 不得寫成合併形式: %v", args)
	}
	if idx+1 < len(args) && args[idx+1] == "1" {
		t.Errorf("-X 取 1 會使誤打 :!! 直接斷線，應取 0: %v", args)
	}
}

func TestBuildCommandMSSQLServerAndPort(t *testing.T) {
	cases := []struct {
		name     string
		port     int
		dbName   string
		wantServ string
		wantDB   bool
	}{
		{"預設埠", 0, "", "h,1433", false},
		{"自訂埠與資料庫", 14330, "app", "h,14330", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, args, _, err := BuildCommand(Target{
				Protocol: "mssql", Host: "h", Port: c.port, Username: "sa", DBName: c.dbName,
			}, "")
			if err != nil {
				t.Fatalf("err=%v", err)
			}
			if !adjacentPair(args, "-S", c.wantServ) {
				t.Errorf("argv 缺 -S %s: %v", c.wantServ, args)
			}
			if adjacentPair(args, "-d", "app") != c.wantDB {
				t.Errorf("-d app 的存在與預期不符 (want=%v): %v", c.wantDB, args)
			}
		})
	}
}

// host 含逗號會被 -S host,port 解讀成埠，故 mssql 分支須自行拒絕
// （localpty.SafeArg 的通用語義不動——逗號對其餘協議合法）
func TestBuildCommandMSSQLRejectsHostComma(t *testing.T) {
	if _, _, _, err := BuildCommand(Target{
		Protocol: "mssql", Host: "h,1234", Username: "sa",
	}, ""); err == nil {
		t.Error("mssql host 含逗號應被拒絕")
	}
	// 對照組：同樣的 host 在其他協議合法（不得誤傷）
	if _, _, _, err := BuildCommand(Target{
		Protocol: "postgres", Host: "h,1234", Username: "u",
	}, ""); err != nil {
		t.Errorf("逗號不應影響 postgres: %v", err)
	}
}

func TestBuildCommandMSSQLTLSModes(t *testing.T) {
	cases := []struct {
		mode    string
		caFile  string
		want    []string
		notWant []string
	}{
		{"", "", nil, []string{"-N", "-C", "-J"}},
		{"disable", "", []string{"-N", "false"}, []string{"-C", "-J"}},
		{"require", "", []string{"-N", "true", "-C"}, []string{"-J"}},
		{"verify-ca", "", []string{"-N", "true"}, []string{"-C", "-J"}},
		{"verify-ca", "/tmp/ca.pem", []string{"-N", "true", "-J", "/tmp/ca.pem"}, []string{"-C"}},
		{"verify-full", "/tmp/ca.pem", []string{"-N", "true", "-J", "/tmp/ca.pem"}, []string{"-C"}},
	}
	for _, c := range cases {
		t.Run(c.mode+"|"+c.caFile, func(t *testing.T) {
			_, args, _, err := BuildCommand(Target{
				Protocol: "mssql", Host: "h", Username: "sa", TLSMode: c.mode,
			}, c.caFile)
			if err != nil {
				t.Fatalf("err=%v", err)
			}
			for _, w := range c.want {
				if !containsStr(args, w) {
					t.Errorf("mode=%q 缺旗標 %q: %v", c.mode, w, args)
				}
			}
			for _, n := range c.notWant {
				if containsStr(args, n) {
					t.Errorf("mode=%q 不應含旗標 %q: %v", c.mode, n, args)
				}
			}
		})
	}
}

// 提示字串是注入器的唯一觸發條件，字面錯一個字元即永不命中。
// sqlcmd 上游為 localizer.Sprintf("Password:")——**冒號後無尾隨空白**，
// 與 psql 的 "Password for user X: " 不同型。
func TestPasswordPromptMSSQL(t *testing.T) {
	auth := PasswordPrompt(Target{Protocol: "mssql", Username: "sa", Password: "p"})
	if auth == nil {
		t.Fatal("mssql 有密碼時須回提示注入設定")
	}
	if auth.Prompt != "Password:" {
		t.Errorf("Prompt=%q, want %q（尾隨空白會使 matcher 不命中）", auth.Prompt, "Password:")
	}
	if strings.HasSuffix(auth.Prompt, " ") {
		t.Error("mssql 的提示不得有尾隨空白")
	}
	// sqlcmd 經 peterh/liner 讀密碼，liner 自行下 raw mode（ICANON 關），
	// 與 redis-cli --askpass 同型，無 termios 判準可用
	if auth.RequireCanonical {
		t.Error("mssql 走 liner raw 模式，RequireCanonical 必須為 false")
	}
	if auth.Password != "p" {
		t.Errorf("Password=%q", auth.Password)
	}
	// 無密碼時不得注入
	if PasswordPrompt(Target{Protocol: "mssql", Username: "sa"}) != nil {
		t.Error("無密碼時不應回提示注入設定")
	}
}

// liner 在終端寬度為 0 時直接回錯誤且不印提示——注入永不觸發、使用者只看到
// 無原因的斷線。此夾值是 mssql 獨有的前提，且不得波及其餘三協議。
func TestClampWinsizeMSSQLOnly(t *testing.T) {
	cases := []struct {
		protocol           string
		cols, rows         int
		wantCols, wantRows int
	}{
		{"mssql", 0, 0, 80, 24},
		{"mssql", -1, -5, 80, 24},
		{"mssql", 120, 40, 120, 40},
		// 其餘協議一律原樣傳遞（既有行為不得改變）
		{"postgres", 0, 0, 0, 0},
		{"mysql", 0, 0, 0, 0},
		{"redis", 0, 0, 0, 0},
	}
	for _, c := range cases {
		gotCols, gotRows := clampWinsize(c.protocol, c.cols, c.rows)
		if gotCols != c.wantCols || gotRows != c.wantRows {
			t.Errorf("clampWinsize(%q, %d, %d) = (%d, %d), want (%d, %d)",
				c.protocol, c.cols, c.rows, gotCols, gotRows, c.wantCols, c.wantRows)
		}
	}
}

// adjacentPair 判斷 args 內是否存在相鄰的 (flag, value) 組
func adjacentPair(args []string, flag, value string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag && args[i+1] == value {
			return true
		}
	}
	return false
}
