package dbrotate

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/dbconsole"
	"github.com/custodexa/backend/internal/model"
)

func TestDBRotatePreconditions(t *testing.T) {
	long := strings.Repeat("a", MaxNewSecretLen)
	cases := []struct {
		name     string
		p        dbconsole.Protocol
		user     string
		old, new string
		want     string
	}{
		{"合格", dbconsole.ProtocolMySQL, "app", "old-pw", "New-Pw_123", ""},
		{"新密碼恰 128 字元", dbconsole.ProtocolMSSQL, "app", "old", long, ""},
		{"帳號名空", dbconsole.ProtocolMySQL, "", "old", "new", model.ChangeSecretReasonInvalidAccountName},
		{"帳號名含換行", dbconsole.ProtocolMySQL, "app\nx", "old", "new", model.ChangeSecretReasonInvalidAccountName},
		{"帳號名含 DEL", dbconsole.ProtocolMySQL, "app\x7f", "old", "new", model.ChangeSecretReasonInvalidAccountName},
		{"新密碼空", dbconsole.ProtocolMySQL, "app", "old", "", model.ChangeSecretReasonInvalidNewSecret},
		{"新密碼含單引號", dbconsole.ProtocolMySQL, "app", "old", "a'b", model.ChangeSecretReasonInvalidNewSecret},
		{"新密碼含雙引號", dbconsole.ProtocolMySQL, "app", "old", "a\"b", model.ChangeSecretReasonInvalidNewSecret},
		{"新密碼含反斜線", dbconsole.ProtocolMySQL, "app", "old", "a\\b", model.ChangeSecretReasonInvalidNewSecret},
		{"新密碼含控制字元", dbconsole.ProtocolMySQL, "app", "old", "a\tb", model.ChangeSecretReasonInvalidNewSecret},
		{"新密碼非 ASCII", dbconsole.ProtocolMySQL, "app", "old", "密碼", model.ChangeSecretReasonInvalidNewSecret},
		{"新密碼超過 128", dbconsole.ProtocolMySQL, "app", "old", long + "a", model.ChangeSecretReasonInvalidNewSecret},
		{"舊密碼含 NUL", dbconsole.ProtocolMySQL, "app", "o\x00ld", "new", model.ChangeSecretReasonInvalidOldSecret},
		{"PostgreSQL 舊密碼非 ASCII", dbconsole.ProtocolPostgres, "app", "舊密碼", "new", model.ChangeSecretReasonInvalidOldSecret},
		{"MySQL 舊密碼非 ASCII 放行", dbconsole.ProtocolMySQL, "app", "舊密碼", "new", ""},
		{"舊密碼含引號與反斜線放行", dbconsole.ProtocolMySQL, "app", "a'b\\c", "new", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := CheckPreconditions(c.p, c.user, []byte(c.old), []byte(c.new)); got != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestDBRotateStatements(t *testing.T) {
	my := dbconsole.ProtocolMySQL
	t.Run("MySQL 字元集", func(t *testing.T) {
		for cs, ok := range map[string]bool{"gbk": false, "sjis": false, "big5": false, "utf8mb4": true, "latin1": true} {
			_, reason := checkProbe(my, "app", []string{"8.4.13", "app@%", "", cs})
			if (reason == "") != ok {
				t.Errorf("charset %s: reason=%q", cs, reason)
			}
			if !ok && reason != model.ChangeSecretReasonRemoteRejected {
				t.Errorf("charset %s 應回遠端拒絕，得 %q", cs, reason)
			}
		}
	})
	t.Run("版本門檻", func(t *testing.T) {
		cases := []struct {
			p    dbconsole.Protocol
			row  []string
			want string
		}{
			{my, []string{"10.11.6-MariaDB", "app@%", "", "utf8mb4"}, model.ChangeSecretReasonTargetVersionUnsupported},
			{my, []string{"8.0.12", "app@%", "", "utf8mb4"}, model.ChangeSecretReasonTargetVersionUnsupported},
			{my, []string{"5.7.44-log", "app@%", "", "utf8mb4"}, model.ChangeSecretReasonTargetVersionUnsupported},
			{my, []string{"8.0.13", "app@%", "", "utf8mb4"}, ""},
			{my, []string{"8.4.13", "app@%", "", "utf8mb4"}, ""},
			{my, []string{"9.1.0", "app@%", "", "utf8mb4"}, ""},
			{dbconsole.ProtocolPostgres, []string{"90600", "app"}, model.ChangeSecretReasonTargetVersionUnsupported},
			{dbconsole.ProtocolPostgres, []string{"160015", "app"}, ""},
			{dbconsole.ProtocolMSSQL, []string{"16", "APP"}, ""},
		}
		for _, c := range cases {
			if _, got := checkProbe(c.p, "app", c.row); got != c.want {
				t.Errorf("%s %v: got %q want %q", c.p, c.row, got, c.want)
			}
		}
	})
	t.Run("身分釘選", func(t *testing.T) {
		if _, r := checkProbe(my, "app", []string{"8.4.13", "proxied@%", "", "utf8mb4"}); r != model.ChangeSecretReasonRemoteRejected {
			t.Errorf("MySQL 代理帳號應拒絕，得 %q", r)
		}
		if _, r := checkProbe(dbconsole.ProtocolPostgres, "app", []string{"160015", "other"}); r != model.ChangeSecretReasonRemoteRejected {
			t.Errorf("PostgreSQL session_user 不符應拒絕，得 %q", r)
		}
		if _, r := checkProbe(dbconsole.ProtocolMSSQL, "app", []string{"16", "sa"}); r != model.ChangeSecretReasonRemoteRejected {
			t.Errorf("SQL Server ORIGINAL_LOGIN 不符應拒絕，得 %q", r)
		}
	})
	t.Run("MySQL 跳脫兩分支", func(t *testing.T) {
		old := []byte(`a'b\c`)
		with := buildAlter(my, probeResult{sqlMode: "STRICT_TRANS_TABLES"}, old, []byte("NewPw1"), "")
		if want := `ALTER USER USER() IDENTIFIED BY 'NewPw1' REPLACE 'a''b\\c'`; with.query != want {
			t.Errorf("反斜線為跳脫字元時：\n got %s\nwant %s", with.query, want)
		}
		without := buildAlter(my, probeResult{sqlMode: "ANSI,NO_BACKSLASH_ESCAPES"}, old, []byte("NewPw1"), "")
		if want := `ALTER USER USER() IDENTIFIED BY 'NewPw1' REPLACE 'a''b\c'`; without.query != want {
			t.Errorf("NO_BACKSLASH_ESCAPES 時：\n got %s\nwant %s", without.query, want)
		}
		if string(old) != `a'b\c` {
			t.Error("組句改動了呼叫端的舊密碼")
		}
	})
	t.Run("PostgreSQL 語句不含明文", func(t *testing.T) {
		v, err := SCRAMVerifier([]byte("NewSecret-77"))
		if err != nil {
			t.Fatal(err)
		}
		st := buildAlter(dbconsole.ProtocolPostgres, probeResult{}, []byte("OldSecret-66"), []byte("NewSecret-77"), v)
		if strings.Contains(st.query, "NewSecret-77") || strings.Contains(st.query, "OldSecret-66") {
			t.Fatalf("PostgreSQL 改密語句含明文：%s", st.query)
		}
		if !strings.HasPrefix(st.query, "ALTER ROLE SESSION_USER PASSWORD 'SCRAM-SHA-256$4096:") {
			t.Fatalf("PostgreSQL 改密語句格式不符：%s", st.query)
		}
	})
	t.Run("SQL Server 密碼只在參數", func(t *testing.T) {
		st := buildAlter(dbconsole.ProtocolMSSQL, probeResult{}, []byte("OldSecret-66"), []byte("NewSecret-77"), "")
		if strings.Contains(st.query, "NewSecret-77") || strings.Contains(st.query, "OldSecret-66") {
			t.Fatal("SQL Server 語句文字含密碼")
		}
		got := map[string]string{}
		for _, a := range st.args {
			na := a.(sql.NamedArg)
			got[na.Name] = na.Value.(string)
		}
		if got["p_new"] != "NewSecret-77" || got["p_old"] != "OldSecret-66" {
			t.Fatalf("SQL Server 參數 = %v", got)
		}
		if !strings.Contains(st.query, "ORIGINAL_LOGIN()") || strings.Contains(st.query, "QUOTENAME(@p_") {
			t.Fatal("SQL Server 登入名須由伺服器端取得，密碼不得以 QUOTENAME 包")
		}
	})
}

// RFC 7677 §3 的測試向量。RFC 不公開 StoredKey／ServerKey 本身，以算出的金鑰與 AuthMessage
// 重算 ServerSignature 與 ClientProof 比對。
func TestSCRAMVerifier(t *testing.T) {
	salt, _ := base64.StdEncoding.DecodeString("W22ZaJ0SNY7soEsUEjb6gQ==")
	clientKey, storedKey, serverKey, err := scramKeys([]byte("pencil"), salt, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(clientKey); !hmac.Equal(sum[:], storedKey) {
		t.Fatal("StoredKey 不等於 SHA-256(ClientKey)")
	}
	authMessage := "n=user,r=rOprNGfwEbeRWgbNEkqO," +
		"r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096," +
		"c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0"
	serverSig := base64.StdEncoding.EncodeToString(hmacSHA256(serverKey, []byte(authMessage)))
	if serverSig != "6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=" {
		t.Fatalf("ServerSignature = %s", serverSig)
	}
	clientSig := hmacSHA256(storedKey, []byte(authMessage))
	proof := make([]byte, len(clientKey))
	for i := range proof {
		proof[i] = clientKey[i] ^ clientSig[i]
	}
	if got := base64.StdEncoding.EncodeToString(proof); got != "dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=" {
		t.Fatalf("ClientProof = %s", got)
	}

	v, err := scramVerifierWithSalt([]byte("pencil"), salt, 4096)
	if err != nil {
		t.Fatal(err)
	}
	want := "SCRAM-SHA-256$4096:W22ZaJ0SNY7soEsUEjb6gQ==$" +
		base64.StdEncoding.EncodeToString(storedKey) + ":" + base64.StdEncoding.EncodeToString(serverKey)
	if v != want {
		t.Fatalf("verifier 格式：\n got %s\nwant %s", v, want)
	}

	pw := []byte("pencil")
	a, err1 := SCRAMVerifier(pw)
	b, err2 := SCRAMVerifier(pw)
	if err1 != nil || err2 != nil {
		t.Fatal(err1, err2)
	}
	saltOf := func(s string) string { return strings.SplitN(strings.SplitN(s, ":", 2)[1], "$", 2)[0] }
	if saltOf(a) == saltOf(b) {
		t.Fatal("兩次產生的鹽相同")
	}
	if raw, _ := base64.StdEncoding.DecodeString(saltOf(a)); len(raw) != 16 {
		t.Fatalf("鹽長度 %d，應為 16", len(raw))
	}
	if string(pw) != "pencil" {
		t.Fatal("SCRAMVerifier 改動了輸入")
	}
}
