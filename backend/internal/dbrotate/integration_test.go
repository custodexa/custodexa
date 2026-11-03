package dbrotate

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/dbconsole"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/testgate"
)

// 對真實目標端的整合測試。單元測試以替身證明流程分流；這裡證明的是目標端真的照
// 我方假設的語意回應：單句改密生效、舊密碼失效、回滾語句能把狀態換回去、
// MySQL 控制連線拒絕多語句、只動連線所匹配的那一列。
//
// 每案在靶機建一次性帳號（rot_ 加隨機尾碼），結束時刪除。座標為五段式
// `host|port|admin|password|database`，須是具管理權限的帳號。
//
// 跑法（靶機須先 up，且測試容器在同一個 compose 網路）：
//
//	TEST_DBROTATE_MYSQL="mysql-test|3306|root|testpass123|testdb" \
//	TEST_DBROTATE_POSTGRES="postgres-test|5432|postgres|testpass123|postgres" \
//	REQUIRE_INTEGRATION=1 go test ./internal/dbrotate -run Integration -v
//
// 密碼是只用於一次性帳號的測試常數。

const (
	itOldPw = "RotIntOld#7Qx!"
	itNewPw = "RotIntNew#9Zk!"
)

type itTarget struct {
	proto dbconsole.Protocol
	admin dbconsole.Config
}

func itTargetOf(t *testing.T, proto dbconsole.Protocol, env string) itTarget {
	t.Helper()
	parts := strings.Split(testgate.Value(t, env), "|")
	if len(parts) != 5 {
		t.Fatalf("%s 的值需為 host|port|user|password|database 五段，實得 %d 段", env, len(parts))
	}
	port, err := strconv.Atoi(parts[1])
	if err != nil {
		t.Fatalf("%s 的埠非數字: %v", env, err)
	}
	return itTarget{proto: proto, admin: dbconsole.Config{
		Protocol: proto, Host: parts[0], Port: port, Username: parts[2],
		Password: []byte(parts[3]), Database: parts[4],
	}}
}

func (it itTarget) open(t *testing.T, user, pw, tlsMode string) (dbconsole.ControlConn, error) {
	t.Helper()
	cfg := it.admin
	cfg.Username, cfg.Password, cfg.TLSMode = user, []byte(pw), tlsMode
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return dbconsole.OpenControl(ctx, cfg)
}

func (it itTarget) adminExec(t *testing.T, query string) {
	t.Helper()
	c, err := it.open(t, string(it.admin.Username), string(it.admin.Password), "")
	if err != nil {
		t.Fatalf("管理帳號連線失敗: %v", dbconsole.ClassifyConnect(it.proto, err))
	}
	defer c.Close()
	if err := c.Exec(context.Background(), query); err != nil {
		t.Fatalf("管理語句失敗（%s）: %v", strings.SplitN(query, " ", 3)[0], err)
	}
}

func (it itTarget) adminRow(t *testing.T, query string) []string {
	t.Helper()
	c, err := it.open(t, it.admin.Username, string(it.admin.Password), "")
	if err != nil {
		t.Fatalf("管理帳號連線失敗: %v", dbconsole.ClassifyConnect(it.proto, err))
	}
	defer c.Close()
	row, err := c.QueryRow(context.Background(), query)
	if err != nil {
		t.Fatalf("管理查詢失敗: %v", err)
	}
	return row
}

func (it itTarget) target(user, tlsMode string) Target {
	return Target{Protocol: it.proto, Host: it.admin.Host, Port: it.admin.Port,
		Database: it.admin.Database, TLSMode: tlsMode, Username: user}
}

// newUser 建一次性帳號（舊密碼 itOldPw），並登記結束時刪除。
func (it itTarget) newUser(t *testing.T) string {
	t.Helper()
	var b [4]byte
	_, _ = rand.Read(b[:])
	user := "rot_" + hex.EncodeToString(b[:])
	switch it.proto {
	case dbconsole.ProtocolMySQL:
		it.adminExec(t, fmt.Sprintf("CREATE USER '%s'@'%%' IDENTIFIED BY '%s'", user, itOldPw))
		it.adminExec(t, fmt.Sprintf("GRANT SELECT ON `%s`.* TO '%s'@'%%'", it.admin.Database, user))
		t.Cleanup(func() { it.adminExec(t, fmt.Sprintf("DROP USER IF EXISTS '%s'@'%%', '%s'@'192.0.2.99'", user, user)) })
	default:
		// 以 verifier 建立，DDL 日誌裡不會出現明文
		v, err := SCRAMVerifier([]byte(itOldPw))
		if err != nil {
			t.Fatal(err)
		}
		it.adminExec(t, fmt.Sprintf("CREATE ROLE %s LOGIN PASSWORD '%s'", user, v))
		t.Cleanup(func() { it.adminExec(t, "DROP ROLE IF EXISTS "+user) })
	}
	return user
}

func (it itTarget) loginOK(t *testing.T, user, pw, tlsMode string) bool {
	t.Helper()
	c, err := it.open(t, user, pw, tlsMode)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func (it itTarget) loginClass(t *testing.T, user, pw string) dbconsole.ErrorClass {
	t.Helper()
	_, err := it.open(t, user, pw, "")
	if err == nil {
		return ""
	}
	return dbconsole.ClassifyConnect(it.proto, err)
}

func itTargets(t *testing.T) map[string]itTarget {
	t.Helper()
	return map[string]itTarget{
		"mysql":    itTargetOf(t, dbconsole.ProtocolMySQL, testgate.EnvDBRotateMySQL),
		"postgres": itTargetOf(t, dbconsole.ProtocolPostgres, testgate.EnvDBRotatePostgres),
	}
}

func TestIntegrationRotateSuccess(t *testing.T) {
	for _, name := range []string{"mysql", "postgres"} {
		t.Run(name, func(t *testing.T) {
			it := itTargets(t)[name]
			user := it.newUser(t)
			oldB, newB := []byte(itOldPw), []byte(itNewPw)
			oldCopy, newCopy := bytes.Clone(oldB), bytes.Clone(newB)

			if err := Rotate(context.Background(), dbconsole.OpenControl, it.target(user, ""), oldB, newB); err != nil {
				t.Fatalf("Rotate 失敗: %v", err)
			}
			if !bytes.Equal(oldB, oldCopy) || !bytes.Equal(newB, newCopy) {
				t.Fatal("呼叫端的新舊密碼切片被改動")
			}
			if !it.loginOK(t, user, itNewPw, "") {
				t.Fatal("改密後新密碼登入失敗")
			}
			if c := it.loginClass(t, user, itOldPw); c != dbconsole.ClassAuth {
				t.Fatalf("改密後舊密碼應被拒（auth），實得 %q", c)
			}
			err := Verify(context.Background(), dbconsole.OpenControl, it.target(user, ""), newB,
				[]time.Duration{0}, func(context.Context, time.Duration) error { return nil })
			if err != nil {
				t.Fatalf("Verify 失敗: %v", err)
			}
		})
	}
}

func TestIntegrationRotateWrongOldPassword(t *testing.T) {
	for _, name := range []string{"mysql", "postgres"} {
		t.Run(name, func(t *testing.T) {
			it := itTargets(t)[name]
			user := it.newUser(t)
			err := Rotate(context.Background(), dbconsole.OpenControl, it.target(user, ""),
				[]byte("WrongOld#1Aa!"), []byte(itNewPw))
			var f *Failure
			if !errors.As(err, &f) || f.Kind != KindRemoteRejected ||
				f.Reason != model.ChangeSecretReasonOldCredentialLoginFailed {
				t.Fatalf("應為 remote rejected／舊密碼登入失敗，實得 %v", err)
			}
			if !it.loginOK(t, user, itOldPw, "") {
				t.Fatal("失敗後原密碼應仍有效")
			}
		})
	}
}

// 回滾語句實跑：在真靶機改密後立即執行第 5 步，原密碼登入成功、新密碼被拒；
// 改密後的第一條連線仍可執行語句；呼叫端切片不變。
func TestIntegrationRollbackLive(t *testing.T) {
	for _, name := range []string{"mysql", "postgres"} {
		t.Run(name, func(t *testing.T) {
			it := itTargets(t)[name]
			user := it.newUser(t)
			oldB, newB := []byte(itOldPw), []byte(itNewPw)
			oldCopy, newCopy := bytes.Clone(oldB), bytes.Clone(newB)
			tg := it.target(user, "")
			ctx := context.Background()

			connA, err := dbconsole.OpenControl(ctx, tg.config(oldB))
			if err != nil {
				t.Fatalf("舊密碼連線失敗: %v", dbconsole.ClassifyConnect(it.proto, err))
			}
			defer connA.Close()
			row, err := connA.QueryRow(ctx, probeQuery(it.proto))
			if err != nil {
				t.Fatalf("探測失敗: %v", err)
			}
			probe, reason := checkProbe(it.proto, user, row)
			if reason != "" {
				t.Fatalf("探測判定未通過: %s", reason)
			}
			var newV, oldV string
			if it.proto == dbconsole.ProtocolPostgres {
				newV, _ = SCRAMVerifier(newB)
				oldV, _ = SCRAMVerifier(oldB)
			}
			fwd := buildAlter(it.proto, probe, oldB, newB, newV)
			if err := connA.Exec(ctx, fwd.query, fwd.args...); err != nil {
				t.Fatalf("改密語句失敗: %v", err)
			}
			if _, err := connA.QueryRow(ctx, "SELECT 1"); err != nil {
				t.Fatalf("改密後第一條連線無法執行語句: %v", err)
			}
			if !it.loginOK(t, user, itNewPw, "") {
				t.Fatal("改密後新密碼登入失敗")
			}
			back := buildAlter(it.proto, probe, newB, oldB, oldV)
			if err := connA.Exec(ctx, back.query, back.args...); err != nil {
				t.Fatalf("回滾語句失敗: %v", err)
			}
			if !it.loginOK(t, user, itOldPw, "") {
				t.Fatal("回滾後舊密碼登入應成功")
			}
			if c := it.loginClass(t, user, itNewPw); c != dbconsole.ClassAuth {
				t.Fatalf("回滾後新密碼應被拒（auth），實得 %q", c)
			}
			if !bytes.Equal(oldB, oldCopy) || !bytes.Equal(newB, newCopy) {
				t.Fatal("呼叫端切片被改動")
			}
		})
	}
}

// MySQL 帳號以 user@host 為單位：同名另一列（不同 host）的認證資料不得被動到。
func TestIntegrationMySQLOtherHostRowUntouched(t *testing.T) {
	it := itTargets(t)["mysql"]
	user := it.newUser(t)
	it.adminExec(t, fmt.Sprintf("CREATE USER '%s'@'192.0.2.99' IDENTIFIED BY 'OtherRow#5Mm!'", user))
	q := fmt.Sprintf("SELECT authentication_string FROM mysql.user WHERE User='%s' AND Host='192.0.2.99'", user)
	before := it.adminRow(t, q)[0]
	if before == "" {
		t.Fatal("另一列的認證資料讀不到")
	}
	if err := Rotate(context.Background(), dbconsole.OpenControl, it.target(user, ""),
		[]byte(itOldPw), []byte(itNewPw)); err != nil {
		t.Fatalf("Rotate 失敗: %v", err)
	}
	if after := it.adminRow(t, q)[0]; after != before {
		t.Fatal("另一個 host 列的 authentication_string 被改動")
	}
	main := fmt.Sprintf("SELECT authentication_string FROM mysql.user WHERE User='%s' AND Host='%%'", user)
	if it.adminRow(t, main)[0] == "" {
		t.Fatal("匹配列的認證資料為空")
	}
}

// 伺服器端拒絕：PASSWORD HISTORY 2（歷史含現行密碼，故兩格才擋得住改回上一個）下改回上一個密碼，語句被拒，分流為遠端確定未變更。
func TestIntegrationMySQLServerRejects(t *testing.T) {
	it := itTargets(t)["mysql"]
	user := it.newUser(t)
	// 歷史政策要在建立帳號時一併設定，初始密碼才會算進歷史
	it.adminExec(t, fmt.Sprintf("DROP USER '%s'@'%%'", user))
	it.adminExec(t, fmt.Sprintf("CREATE USER '%s'@'%%' IDENTIFIED BY '%s' PASSWORD HISTORY 2", user, itOldPw))
	it.adminExec(t, fmt.Sprintf("GRANT SELECT ON `%s`.* TO '%s'@'%%'", it.admin.Database, user))
	if err := Rotate(context.Background(), dbconsole.OpenControl, it.target(user, ""),
		[]byte(itOldPw), []byte(itNewPw)); err != nil {
		t.Fatalf("第一次 Rotate 失敗: %v", err)
	}
	err := Rotate(context.Background(), dbconsole.OpenControl, it.target(user, ""),
		[]byte(itNewPw), []byte(itOldPw))
	var f *Failure
	if !errors.As(err, &f) || f.Kind != KindRemoteRejected || f.Reason != model.ChangeSecretReasonRemoteRejected {
		t.Fatalf("改回歷史密碼應被伺服器拒絕（remote rejected），實得 %v", err)
	}
	if !it.loginOK(t, user, itNewPw, "") {
		t.Fatal("被拒後現行密碼應仍有效")
	}
}

// 控制連線關閉多語句：送兩句得到語法錯誤 1064。
func TestIntegrationMySQLNoMultiStatement(t *testing.T) {
	it := itTargets(t)["mysql"]
	c, err := it.open(t, it.admin.Username, string(it.admin.Password), "")
	if err != nil {
		t.Fatal(dbconsole.ClassifyConnect(it.proto, err))
	}
	defer c.Close()
	_, qerr := c.QueryRow(context.Background(), "SELECT 1; SELECT 2")
	if qerr == nil {
		t.Fatal("多語句應被拒")
	}
	d := dbconsole.DBErrorOf(dbconsole.ProtocolMySQL, qerr, false)
	if d == nil || d.Code != "1064" {
		t.Fatalf("應為錯誤碼 1064，實得 %+v", d)
	}
}

// MySQL 的 TLS 檔位：預設（未設定）與 require 兩檔各跑一次完整改密。
func TestIntegrationMySQLTLSModes(t *testing.T) {
	it := itTargets(t)["mysql"]
	for _, mode := range []string{"", "require"} {
		t.Run("tls="+mode, func(t *testing.T) {
			user := it.newUser(t)
			if err := Rotate(context.Background(), dbconsole.OpenControl, it.target(user, mode),
				[]byte(itOldPw), []byte(itNewPw)); err != nil {
				t.Fatalf("Rotate 失敗: %v", err)
			}
			if !it.loginOK(t, user, itNewPw, mode) {
				t.Fatal("新密碼登入失敗")
			}
		})
	}
}

// SQL Server：座標未提供時 skip（REQUIRE_INTEGRATION=1 時為失敗，故只在 mssql-test 啟動時列入）。
func TestIntegrationMSSQLRotate(t *testing.T) {
	it := itTargetOf(t, dbconsole.ProtocolMSSQL, testgate.EnvDBRotateMSSQL)
	var b [4]byte
	_, _ = rand.Read(b[:])
	user := "rot_" + hex.EncodeToString(b[:])
	it.adminExec(t, fmt.Sprintf("CREATE LOGIN %s WITH PASSWORD = '%s', CHECK_POLICY = OFF", user, itOldPw))
	t.Cleanup(func() { it.adminExec(t, "DROP LOGIN "+user) })
	if err := Rotate(context.Background(), dbconsole.OpenControl, it.target(user, ""),
		[]byte(itOldPw), []byte(itNewPw)); err != nil {
		t.Fatalf("Rotate 失敗: %v", err)
	}
	if !it.loginOK(t, user, itNewPw, "") {
		t.Fatal("新密碼登入失敗")
	}
}
