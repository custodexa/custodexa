package dbproxy

import "testing"

// TestReconnectDirective 逐列斷言三值判定：
// 命中（含寧可誤擋的字面指令名）、不命中、無法確定。
func TestReconnectDirective(t *testing.T) {
	cases := []struct {
		name     string
		protocol string
		line     string
		want     ReconnectVerdict
	}{
		// redis：命中
		{"redis 直接改連", "redis", `connect 203.0.113.5 6379`, ReconnectHit},
		{"redis 大小寫", "redis", `CoNnEcT 203.0.113.5 6379`, ReconnectHit},
		{"redis 前置空白", "redis", `   connect 203.0.113.5 6379`, ReconnectHit},
		{"redis 雙引號", "redis", `"connect" 203.0.113.5 6379`, ReconnectHit},
		{"redis 單引號", "redis", `'connect' 203.0.113.5 6379`, ReconnectHit},
		{"redis 十六進位跳脫", "redis", `"\x63onnect" 203.0.113.5 6379`, ReconnectHit},
		{"redis 跳脫取字元本身", "redis", `"c\onnect" 203.0.113.5 6379`, ReconnectHit},
		{"redis 非行首 token（寧可誤擋）", "redis", `GET connect`, ReconnectHit},
		// redis：不命中
		{"redis 子字串", "redis", `GET connected_clients`, ReconnectAllow},
		{"redis 一般指令", "redis", `INFO clients`, ReconnectAllow},
		{"redis 前綴", "redis", `GET disconnect`, ReconnectAllow},
		{"redis 引號內空白不拆 token", "redis", `SET k "a connect b"`, ReconnectAllow},
		{"redis 空行", "redis", ``, ReconnectAllow},
		{"redis x 後非十六進位依 redis-cli 取字元", "redis", `SET k "\xZZ"`, ReconnectAllow},
		// redis：無法確定
		{"redis 雙引號未閉合", "redis", `"connect`, ReconnectUncertain},
		{"redis 單引號未閉合", "redis", `'connect 1.2.3.4 6379`, ReconnectUncertain},
		{"redis 閉合引號後緊接字元", "redis", `"connect"x 1.2.3.4 6379`, ReconnectUncertain},
		{"redis 行尾孤立反斜線", "redis", `SET k "a\`, ReconnectUncertain},

		// mysql／mariadb：命中
		{"mysql 短指令", "mysql", `\r db 203.0.113.5`, ReconnectHit},
		{"mysql connect 大寫", "mysql", `CONNECT db 203.0.113.5;`, ReconnectHit},
		{"mysql connect 小寫", "mysql", `connect db 203.0.113.5`, ReconnectHit},
		{"mysql 同行後段短指令", "mysql", `SELECT 1; \r db 203.0.113.5`, ReconnectHit},
		{"mysql 同行後段 connect", "mysql", `SELECT 1;connect db 203.0.113.5`, ReconnectHit},
		{"mysql 引號包住（寧可誤擋）", "mysql", `SELECT 'connect';`, ReconnectHit},
		{"mysql 反引號", "mysql", "`connect` db host", ReconnectHit},
		{"mysql 短指令緊貼", "mysql", `\rdb 203.0.113.5`, ReconnectHit},
		{"mysql \\g 後接 connect", "mysql", `SELECT 1\gconnect db host`, ReconnectHit},
		// mysql：不命中
		{"mysql 一般查詢", "mysql", `SELECT 1;`, ReconnectAllow},
		{"mysql 子字串", "mysql", `SELECT disconnect_time FROM t;`, ReconnectAllow},
		{"mysql 大寫 R 是另一個指令", "mysql", `\R prompt>`, ReconnectAllow},
		{"mysql 欄名含 connected", "mysql", `SELECT connected_clients FROM t;`, ReconnectAllow},
		{"mysql 空行", "mysql", ``, ReconnectAllow},
		{"mysql 引號未閉合不算無法確定（SQL 字串可跨行）", "mysql", `SELECT 'abc`, ReconnectAllow},

		// mssql
		{"mssql 前置空白大小寫混用", "mssql", `  :Connect 203.0.113.5`, ReconnectHit},
		{"mssql 小寫", "mssql", `:connect host`, ReconnectHit},
		{"mssql 非行首（寧可誤擋）", "mssql", `GO :connect host`, ReconnectHit},
		{"mssql 讀入腳本檔", "mssql", `:r /tmp/script.sql`, ReconnectHit},
		{"mssql 輸出導向檔", "mssql", `:OUT /tmp/out.txt`, ReconnectHit},
		{"mssql 執行外部命令", "mssql", `!! ls`, ReconnectHit},
		{"mssql :r 前綴不算", "mssql", `SELECT 1 AS :ref`, ReconnectAllow},
		{"mssql 一般查詢", "mssql", `SELECT name FROM sys.databases;`, ReconnectAllow},
		{"mssql 沒有冒號的 connect 不算", "mssql", `SELECT 1 AS connect_count`, ReconnectAllow},

		// 其他協議一律放行
		{"postgres 反斜線改連不在此判定", "postgres", `\c db user otherhost`, ReconnectAllow},
		{"ssh 不適用", "ssh", `connect 1.2.3.4`, ReconnectAllow},
	}
	for _, c := range cases {
		if got := ReconnectDirective(c.protocol, c.line); got != c.want {
			t.Errorf("%s: ReconnectDirective(%q, %q) = %v, want %v", c.name, c.protocol, c.line, got, c.want)
		}
	}
}

func TestReconnectGuardedProtocol(t *testing.T) {
	for p, want := range map[string]bool{
		"mysql": true, "redis": true, "mssql": true,
		"postgres": false, "ssh": false, "k8s": false, "": false,
	} {
		if got := ReconnectGuardedProtocol(p); got != want {
			t.Errorf("ReconnectGuardedProtocol(%q) = %v, want %v", p, got, want)
		}
	}
}
