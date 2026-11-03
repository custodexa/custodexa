package dbrotate

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/custodexa/backend/internal/dbconsole"
	"github.com/custodexa/backend/internal/model"
)

const (
	flowOld = "Old'Pw\\1"
	flowNew = "NewSecret-Flow-42"
)

// fakeConn 替身控制連線：記下送出的語句與參數。
type fakeConn struct {
	row     []string
	rowErr  error
	execErr []error // 依序對應第 1、2 次 Exec
	execs   []string
	closed  bool
}

func (c *fakeConn) QueryRow(context.Context, string, ...any) ([]string, error) {
	return c.row, c.rowErr
}

func (c *fakeConn) Exec(_ context.Context, q string, args ...any) error {
	rec := q
	for _, a := range args {
		if na, ok := a.(sql.NamedArg); ok {
			rec += fmt.Sprintf(" @%s=%v", na.Name, na.Value)
		}
	}
	c.execs = append(c.execs, rec)
	i := len(c.execs) - 1
	if i < len(c.execErr) {
		return c.execErr[i]
	}
	return nil
}

func (c *fakeConn) Close() error { c.closed = true; return nil }

// fakeOpener 替身連線層：比照 OpenControl 的所有權規則清零收到的密碼。
type fakeOpener struct {
	conn     *fakeConn
	openErrs []error // 依序對應第 1（舊密碼）、2（新密碼）次連線
	received []string
}

func (o *fakeOpener) open(_ context.Context, cfg dbconsole.Config) (dbconsole.ControlConn, error) {
	o.received = append(o.received, string(cfg.Password))
	clear(cfg.Password)
	i := len(o.received) - 1
	if i < len(o.openErrs) && o.openErrs[i] != nil {
		return nil, o.openErrs[i]
	}
	if i == 0 {
		return o.conn, nil
	}
	return &fakeConn{row: []string{"1"}}, nil
}

func mysqlRow() []string { return []string{"8.4.13", "app@%", "STRICT_TRANS_TABLES", "utf8mb4"} }

func mysqlAuthErr() error {
	return &mysqldriver.MySQLError{Number: 1045, Message: "Access denied for user 'app' using password " + flowNew}
}

func netErrWithSecret() error {
	return &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("refused host=db password=" + flowNew)}
}

// bareTimeoutErr 實作 net.Error 的讀取逾時，但沒有包成 *net.OpError（不會被認成斷線）。
type bareTimeoutErr struct{}

func (bareTimeoutErr) Error() string   { return "i/o timeout password=" + flowNew }
func (bareTimeoutErr) Timeout() bool   { return true }
func (bareTimeoutErr) Temporary() bool { return true }

func TestDBRotateFlow(t *testing.T) {
	type tc struct {
		name       string
		proto      dbconsole.Protocol
		user, old  string
		row        []string
		rowErr     error
		openErrs   []error
		execErr    []error
		wantKind   Kind
		wantReason string
		wantOK     bool
		wantExecs  int
		check      func(t *testing.T, o *fakeOpener, err error)
	}
	cases := []tc{
		{name: "本地_帳號名不合", proto: dbconsole.ProtocolMySQL, user: "", wantKind: KindLocalPrecondition,
			wantReason: model.ChangeSecretReasonInvalidAccountName},
		{name: "本地_新密碼不合", proto: dbconsole.ProtocolMySQL, user: "app", wantKind: KindLocalPrecondition,
			wantReason: model.ChangeSecretReasonInvalidNewSecret},
		{name: "本地_舊密碼不合", proto: dbconsole.ProtocolPostgres, user: "app", old: "舊", wantKind: KindLocalPrecondition,
			wantReason: model.ChangeSecretReasonInvalidOldSecret},
		{name: "連線A_認證被拒", proto: dbconsole.ProtocolMySQL, user: "app", openErrs: []error{mysqlAuthErr()},
			wantKind: KindRemoteRejected, wantReason: model.ChangeSecretReasonOldCredentialLoginFailed},
		{name: "連線A_網路失敗", proto: dbconsole.ProtocolMySQL, user: "app", openErrs: []error{netErrWithSecret()},
			wantKind: KindRemoteRejected, wantReason: model.ChangeSecretReasonRemoteUnreachable,
			check: func(t *testing.T, _ *fakeOpener, err error) {
				f := err.(*Failure)
				if f.Cause.Code != "" || f.Cause.Class != "network" {
					t.Fatalf("無錯誤碼的網路錯誤應只帶 class=network，得 %+v", f.Cause)
				}
				if strings.Contains(err.Error(), "refused") || strings.Contains(err.Error(), "host=db") {
					t.Fatalf("錯誤帶出 driver 原文：%s", err)
				}
			}},
		{name: "探測_版本不支援", proto: dbconsole.ProtocolMySQL, user: "app",
			row:      []string{"10.11.6-MariaDB", "app@%", "", "utf8mb4"},
			wantKind: KindRemoteRejected, wantReason: model.ChangeSecretReasonTargetVersionUnsupported},
		{name: "探測_字元集不支援", proto: dbconsole.ProtocolMySQL, user: "app",
			row:      []string{"8.4.13", "app@%", "", "gbk"},
			wantKind: KindRemoteRejected, wantReason: model.ChangeSecretReasonRemoteRejected},
		{name: "探測_身分不符", proto: dbconsole.ProtocolMySQL, user: "app",
			row:      []string{"8.4.13", "other@%", "", "utf8mb4"},
			wantKind: KindRemoteRejected, wantReason: model.ChangeSecretReasonRemoteRejected},
		{name: "探測_查詢失敗", proto: dbconsole.ProtocolMySQL, user: "app", rowErr: &mysqldriver.MySQLError{Number: 1227},
			wantKind: KindRemoteRejected, wantReason: model.ChangeSecretReasonRemoteRejected},
		{name: "改密_伺服器回錯", proto: dbconsole.ProtocolMySQL, user: "app",
			execErr: []error{&mysqldriver.MySQLError{Number: 1064,
				Message: "You have an error near '" + flowNew + "' REPLACE"}},
			wantKind: KindRemoteRejected, wantReason: model.ChangeSecretReasonRemoteRejected, wantExecs: 1,
			check: func(t *testing.T, _ *fakeOpener, err error) {
				if err.(*Failure).Cause.Code != "1064" {
					t.Fatalf("應保留錯誤碼 1064，得 %+v", err.(*Failure).Cause)
				}
			}},
		{name: "改密_無錯誤碼的網路逾時", proto: dbconsole.ProtocolMySQL, user: "app", execErr: []error{bareTimeoutErr{}},
			wantKind: KindIndeterminate, wantExecs: 1,
			check: func(t *testing.T, _ *fakeOpener, err error) {
				c := err.(*Failure).Cause
				if c.Code != "" || c.Class != string(dbconsole.ClassNetwork) {
					t.Fatalf("前提：應分到無錯誤碼的 network 類（不是 lost），得 %+v", c)
				}
			}},
		{name: "改密_無錯誤碼的協定錯誤", proto: dbconsole.ProtocolMySQL, user: "app", execErr: []error{mysqldriver.ErrPktSync},
			wantKind: KindIndeterminate, wantExecs: 1,
			check: func(t *testing.T, _ *fakeOpener, err error) {
				c := err.(*Failure).Cause
				if c.Code != "" || c.Class == ClassLost {
					t.Fatalf("前提：應為無錯誤碼、非 lost 的分類，得 %+v", c)
				}
			}},
		{name: "改密_送出後連線中斷", proto: dbconsole.ProtocolMySQL, user: "app", execErr: []error{driver.ErrBadConn},
			wantKind: KindIndeterminate, wantExecs: 1},
		{name: "自驗_成功", proto: dbconsole.ProtocolMySQL, user: "app", wantOK: true, wantExecs: 1},
		{name: "自驗_認證被拒且回滾成功", proto: dbconsole.ProtocolMySQL, user: "app",
			openErrs: []error{nil, mysqlAuthErr()},
			wantKind: KindRemoteRejected, wantReason: model.ChangeSecretReasonRemoteSelfVerifyFailed, wantExecs: 2,
			check: func(t *testing.T, o *fakeOpener, _ error) {
				want := `ALTER USER USER() IDENTIFIED BY 'Old''Pw\\1' REPLACE '` + flowNew + `'`
				if o.conn.execs[1] != want {
					t.Fatalf("回滾語句應以原舊密碼組成：\n got %s\nwant %s", o.conn.execs[1], want)
				}
			}},
		{name: "自驗_認證被拒且回滾失敗", proto: dbconsole.ProtocolMySQL, user: "app",
			openErrs: []error{nil, mysqlAuthErr()}, execErr: []error{nil, driver.ErrBadConn},
			wantKind: KindRemoteStateUnknown, wantReason: model.ChangeSecretReasonRemoteSelfVerifyRollbackFailed, wantExecs: 2},
		{name: "自驗_網路中斷不改回", proto: dbconsole.ProtocolMySQL, user: "app",
			openErrs: []error{nil, netErrWithSecret()}, wantKind: KindIndeterminate, wantExecs: 1},
		{name: "PostgreSQL_成功", proto: dbconsole.ProtocolPostgres, user: "app",
			row: []string{"160015", "app"}, wantOK: true, wantExecs: 1,
			check: func(t *testing.T, o *fakeOpener, _ error) {
				if strings.Contains(o.conn.execs[0], flowNew) || !strings.Contains(o.conn.execs[0], "SCRAM-SHA-256$") {
					t.Fatalf("PostgreSQL 改密語句：%s", o.conn.execs[0])
				}
			}},
		{name: "PostgreSQL_自驗認證被拒回滾", proto: dbconsole.ProtocolPostgres, user: "app",
			row: []string{"160015", "app"}, openErrs: []error{nil, &pgconn.PgError{Code: "28P01"}},
			wantKind: KindRemoteRejected, wantReason: model.ChangeSecretReasonRemoteSelfVerifyFailed, wantExecs: 2},
		{name: "SQLServer_成功", proto: dbconsole.ProtocolMSSQL, user: "app",
			row: []string{"16", "app"}, wantOK: true, wantExecs: 1,
			check: func(t *testing.T, o *fakeOpener, _ error) {
				if !strings.Contains(o.conn.execs[0], "@p_new="+flowNew) || !strings.Contains(o.conn.execs[0], "@p_old="+flowOld) {
					t.Fatalf("SQL Server 參數：%s", o.conn.execs[0])
				}
			}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			oldPw, newPw := flowOld, flowNew
			if c.old != "" {
				oldPw = c.old
			}
			if c.name == "本地_新密碼不合" {
				newPw = "bad'pw"
			}
			oldSecret, newSecret := []byte(oldPw), []byte(newPw)
			oldBefore, newBefore := bytes.Clone(oldSecret), bytes.Clone(newSecret)
			row := c.row
			if row == nil {
				row = mysqlRow()
			}
			o := &fakeOpener{conn: &fakeConn{row: row, rowErr: c.rowErr, execErr: c.execErr}, openErrs: c.openErrs}
			tgt := Target{Protocol: c.proto, Host: "db", Port: 1, Username: c.user}

			err := Rotate(context.Background(), o.open, tgt, oldSecret, newSecret)

			if !bytes.Equal(oldSecret, oldBefore) || !bytes.Equal(newSecret, newBefore) {
				t.Fatal("Rotate 改動了呼叫端的新舊密碼切片")
			}
			if len(o.received) > 0 && o.received[0] != oldPw {
				t.Fatal("第一條連線收到的不是舊密碼")
			}
			if len(o.received) > 1 && o.received[1] != newPw {
				t.Fatal("第二條連線收到的不是新密碼")
			}
			if len(o.conn.execs) != c.wantExecs {
				t.Fatalf("送出語句 %d 句，應為 %d：%v", len(o.conn.execs), c.wantExecs, o.conn.execs)
			}
			if c.wantOK {
				if err != nil {
					t.Fatalf("預期成功，得 %v", err)
				}
			} else {
				var f *Failure
				if !errors.As(err, &f) || f == nil {
					t.Fatalf("預期 *Failure，得 %T %v", err, err)
				}
				if f.Kind != c.wantKind || f.Reason != c.wantReason {
					t.Fatalf("kind=%d reason=%q，應為 kind=%d reason=%q", f.Kind, f.Reason, c.wantKind, c.wantReason)
				}
				for _, s := range []string{err.Error(), fmt.Sprintf("%+v", err), fmt.Sprintf("%v", f.Cause)} {
					if strings.Contains(s, flowNew) || strings.Contains(s, oldPw) {
						t.Fatalf("錯誤含密碼：%s", s)
					}
				}
				if f.Cause.Dialect != string(c.proto) || f.Cause.Step == "" || f.Cause.Class == "" {
					t.Fatalf("成因欄位不全：%+v", f.Cause)
				}
			}
			firstOpened := len(o.received) > 0 && (len(c.openErrs) == 0 || c.openErrs[0] == nil)
			if firstOpened && !o.conn.closed {
				t.Fatal("第一條連線未關閉")
			}
			if c.check != nil {
				c.check(t, o, err)
			}
		})
	}
}

func TestDBRotateVerify(t *testing.T) {
	noSleep := func(context.Context, time.Duration) error { return nil }
	delays := []time.Duration{0, time.Second, time.Second}
	tgt := Target{Protocol: dbconsole.ProtocolMySQL, Host: "db", Port: 1, Username: "app"}

	t.Run("第一次成功", func(t *testing.T) {
		o := &fakeOpener{conn: &fakeConn{row: []string{"1"}}}
		secret := []byte(flowNew)
		if err := Verify(context.Background(), o.open, tgt, secret, delays, noSleep); err != nil {
			t.Fatal(err)
		}
		if len(o.received) != 1 || string(secret) != flowNew {
			t.Fatalf("嘗試 %d 次；呼叫端切片 %q", len(o.received), secret)
		}
	})
	t.Run("第二次成功", func(t *testing.T) {
		o := &fakeOpener{conn: &fakeConn{row: []string{"1"}}, openErrs: []error{mysqlAuthErr()}}
		if err := Verify(context.Background(), o.open, tgt, []byte(flowNew), delays, noSleep); err != nil {
			t.Fatal(err)
		}
		if len(o.received) != 2 {
			t.Fatalf("嘗試 %d 次，應為 2", len(o.received))
		}
	})
	t.Run("全失敗", func(t *testing.T) {
		o := &fakeOpener{conn: &fakeConn{}, openErrs: []error{mysqlAuthErr(), netErrWithSecret(), mysqlAuthErr()}}
		err := Verify(context.Background(), o.open, tgt, []byte(flowNew), delays, noSleep)
		var f *Failure
		if !errors.As(err, &f) || f == nil {
			t.Fatalf("預期 *Failure，得 %v", err)
		}
		if len(o.received) != 3 {
			t.Fatalf("嘗試 %d 次，應為 3", len(o.received))
		}
		if strings.Contains(err.Error(), flowNew) || strings.Contains(fmt.Sprintf("%+v", err), flowNew) {
			t.Fatalf("錯誤含密碼：%v", err)
		}
		if f.Cause.Step != StepVerify || f.Cause.Code != "1045" {
			t.Fatalf("成因 %+v", f.Cause)
		}
	})
}
