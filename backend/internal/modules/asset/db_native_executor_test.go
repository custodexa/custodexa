package asset

import (
	"context"
	"database/sql/driver"
	"errors"
	"strings"
	"testing"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"

	"github.com/custodexa/backend/internal/dbconsole"
	"github.com/custodexa/backend/internal/model"
)

// dbExecStubConn 替身控制連線。
type dbExecStubConn struct {
	row     []string
	execErr error
}

func (c *dbExecStubConn) QueryRow(context.Context, string, ...any) ([]string, error) {
	return c.row, nil
}
func (c *dbExecStubConn) Exec(context.Context, string, ...any) error { return c.execErr }
func (c *dbExecStubConn) Close() error                               { return nil }

// dbExecStub 依序回應連線：第 1 次舊密碼、第 2 次新密碼。
func dbExecStub(conn *dbExecStubConn, errs ...error) func(context.Context, dbconsole.Config) (dbconsole.ControlConn, error) {
	n := 0
	return func(_ context.Context, cfg dbconsole.Config) (dbconsole.ControlConn, error) {
		clear(cfg.Password)
		i := n
		n++
		if i < len(errs) && errs[i] != nil {
			return nil, errs[i]
		}
		return conn, nil
	}
}

func dbNativeTestTarget() rotationTarget {
	return rotationTarget{
		asset: &model.Asset{Protocol: model.ProtocolMySQL, Host: "db", Port: 3306,
			RotationChannel: model.RotationChannelDBNative},
		channel: model.RotationChannelDBNative, username: "app", secretType: model.ChangeSecretTypePassword,
	}
}

func TestDBNativeExecutorFactory(t *testing.T) {
	if _, ok := rotationExecutorFor(model.RotationChannelDBNative).(notWiredExecutor); ok {
		t.Fatal("db_native 不得落到未接線執行器")
	}
	if _, ok := rotationExecutorFor(model.RotationChannelDBNative).(dbNativeExecutor); !ok {
		t.Fatal("db_native 應取 dbNativeExecutor")
	}
	a := &model.Asset{Protocol: model.ProtocolMySQL, Host: "db", Port: 3307}
	if got := rotationAddr(a, model.RotationChannelDBNative); got != "db:3307" {
		t.Fatalf("rotationAddr = %s", got)
	}
}

func TestDBNativeExecutorMapping(t *testing.T) {
	okRow := []string{"8.4.13", "app@%", "", "utf8mb4"}
	authErr := &mysqldriver.MySQLError{Number: 1045, Message: "denied"}
	cases := []struct {
		name       string
		newPw      string
		conn       *dbExecStubConn
		errs       []error
		wantType   string
		wantReason string
	}{
		{"本地前置", "bad'pw", &dbExecStubConn{row: okRow}, nil, "local", model.ChangeSecretReasonInvalidNewSecret},
		{"舊密碼被拒", "NewPw-1", &dbExecStubConn{row: okRow}, []error{authErr}, "rejected",
			model.ChangeSecretReasonOldCredentialLoginFailed},
		{"版本不支援", "NewPw-1", &dbExecStubConn{row: []string{"8.0.12", "app@%", "", "utf8mb4"}}, nil, "rejected",
			model.ChangeSecretReasonTargetVersionUnsupported},
		{"自驗被拒回滾失敗", "NewPw-1", &dbExecStubConn{row: okRow}, []error{nil, authErr}, "unknown_known", ""},
		{"送出後中斷", "NewPw-1", &dbExecStubConn{row: okRow, execErr: driver.ErrBadConn}, nil, "plain", ""},
		{"成功", "NewPw-1", &dbExecStubConn{row: okRow}, nil, "nil", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			conn := c.conn
			if c.name == "自驗被拒回滾失敗" {
				// 第一句改密成功，回滾那句失敗
				conn = &dbExecStubConn{row: okRow}
			}
			e := dbNativeExecutor{open: dbExecStub(conn, c.errs...)}
			if c.name == "自驗被拒回滾失敗" {
				calls := 0
				inner := dbExecStub(conn, c.errs...)
				e.open = func(ctx context.Context, cfg dbconsole.Config) (dbconsole.ControlConn, error) {
					calls++
					cc, err := inner(ctx, cfg)
					if calls == 2 {
						conn.execErr = driver.ErrBadConn
					}
					return cc, err
				}
			}
			err := e.Rotate(context.Background(), dbNativeTestTarget(), []byte("OldPw-1"), []byte(c.newPw))
			var (
				local   *localPreconditionError
				reject  *remoteRejectedError
				unknown *remoteStateUnknownError
			)
			switch c.wantType {
			case "nil":
				if err != nil {
					t.Fatalf("預期成功：%v", err)
				}
				return
			case "local":
				if !errors.As(err, &local) || local.reason != c.wantReason {
					t.Fatalf("預期本地前置 %s，得 %T %v", c.wantReason, err, err)
				}
			case "rejected":
				if !errors.As(err, &reject) || reject.reason != c.wantReason {
					t.Fatalf("預期遠端拒絕 %s，得 %T %v", c.wantReason, err, err)
				}
			case "unknown_known":
				if !errors.As(err, &unknown) || unknown.reason != model.ChangeSecretReasonRemoteSelfVerifyRollbackFailed {
					t.Fatalf("預期回滾失敗的不可知，得 %T %v", err, err)
				}
			case "plain":
				if err == nil || errors.As(err, &local) || errors.As(err, &reject) || errors.As(err, &unknown) {
					t.Fatalf("預期一般錯誤（預設不可知），得 %T %v", err, err)
				}
			}
			if strings.Contains(err.Error(), "NewPw-1") || strings.Contains(err.Error(), "OldPw-1") {
				t.Fatalf("錯誤含密碼：%v", err)
			}
		})
	}
}

func TestDBNativeExecutorVerify(t *testing.T) {
	noSleep := func(context.Context, time.Duration) error { return nil }
	authErr := &mysqldriver.MySQLError{Number: 1045, Message: "denied NewPw-1"}
	e := dbNativeExecutor{open: dbExecStub(&dbExecStubConn{row: []string{"1"}}, authErr, authErr),
		verifyDelays: []time.Duration{0, time.Second}, sleep: noSleep}
	err := e.Verify(context.Background(), dbNativeTestTarget(), []byte("NewPw-1"))
	if err == nil || strings.Contains(err.Error(), "NewPw-1") {
		t.Fatalf("驗證全失敗應回不含密碼的錯誤，得 %v", err)
	}
	e.open = dbExecStub(&dbExecStubConn{row: []string{"1"}}, authErr)
	if err := e.Verify(context.Background(), dbNativeTestTarget(), []byte("NewPw-1")); err != nil {
		t.Fatalf("第二次成功應回 nil：%v", err)
	}
}
