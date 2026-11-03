package dbconsole

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func TestOpenControlMySQLConfig(t *testing.T) {
	for _, mode := range []string{TLSModeDefault, TLSModeDisable, TLSModeRequire} {
		tlsSet, err := resolveTLS(mode, "")
		if err != nil {
			t.Fatalf("resolveTLS(%q): %v", mode, err)
		}
		c := mysqlControlConfig(Config{Protocol: ProtocolMySQL, Host: "db", Port: 3306, Username: "u",
			Password: []byte("x"), TLSMode: mode}, tlsSet)
		if !(c.MultiStatements == false && c.InterpolateParams == false) {
			t.Fatalf("檔位 %q：控制連線須關閉多語句與客戶端插值，得 MultiStatements=%v InterpolateParams=%v",
				mode, c.MultiStatements, c.InterpolateParams)
		}
		// TLS 檔位語義與主控台同源：同一檔位下兩邊的 TLS 設定是否掛上必須一致
		console := mysqlDriverConfig(Config{Host: "db", Port: 3306, TLSMode: mode}, tlsSet)
		if (c.TLS == nil) != (console.TLS == nil) {
			t.Fatalf("檔位 %q：控制連線與主控台的 TLS 設定不一致", mode)
		}
	}
}

func TestOpenControlAppNames(t *testing.T) {
	if ControlAppName == mssqlConsoleAppName {
		t.Fatal("控制連線識別名不得與主控台相同")
	}
	tlsSet, _ := resolveTLS(TLSModeDefault, "")
	cfg := Config{Host: "db", Port: 1, Username: "u", Password: []byte("x")}

	my := mysqlControlConfig(cfg, tlsSet)
	if my.ConnectionAttributes != "program_name:"+ControlAppName || my.ConnectionAttributes == "program_name:custodexa-db-console" {
		t.Fatalf("mysql 連線屬性 = %q", my.ConnectionAttributes)
	}
	pg, err := pgxControlConfig(cfg, tlsSet)
	if err != nil {
		t.Fatal(err)
	}
	if got := pg.RuntimeParams["application_name"]; got != ControlAppName || got == "custodexa-db-console" {
		t.Fatalf("postgres application_name = %q", got)
	}
	ms, err := mssqlDriverConfig(cfg, tlsSet, ControlAppName)
	if err != nil {
		t.Fatal(err)
	}
	if ms.AppName != ControlAppName || ms.AppName == "custodexa-db-console" {
		t.Fatalf("mssql AppName = %q", ms.AppName)
	}
}

// 連不上的目標（本機未開放的埠）：三方言都失敗，且返回時密碼已全為零。
func TestOpenControlZeroesPassword(t *testing.T) {
	for _, p := range []Protocol{ProtocolMySQL, ProtocolPostgres, ProtocolMSSQL} {
		pw := []byte("control-secret-xyz")
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		conn, err := OpenControl(ctx, Config{Protocol: p, Host: "127.0.0.1", Port: 1, Username: "u",
			Password: pw, TLSMode: TLSModeDisable})
		cancel()
		if err == nil {
			_ = conn.Close()
			t.Fatalf("%s：預期連線失敗", p)
		}
		if !bytes.Equal(pw, make([]byte, len(pw))) {
			t.Fatalf("%s：OpenControl 返回後 cfg.Password 未清零", p)
		}
	}
	pw := []byte("x")
	if _, err := OpenControl(context.Background(), Config{Protocol: "redis", Password: pw}); err == nil {
		t.Fatal("不支援的協定須回錯")
	}
	if pw[0] != 0 {
		t.Fatal("不支援的協定也要清零")
	}
}
