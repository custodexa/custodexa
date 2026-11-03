package dbrotate

import (
	"bytes"
	"context"
	"time"

	"github.com/custodexa/backend/internal/dbconsole"
	"github.com/custodexa/backend/internal/model"
)

// Opener 建立控制連線（正式為 dbconsole.OpenControl；測試注入替身）。
// 依 OpenControl 的所有權規則，返回時 cfg.Password 已被清零。
type Opener func(ctx context.Context, cfg dbconsole.Config) (dbconsole.ControlConn, error)

// Target 改密目標（不含密碼）。
type Target struct {
	Protocol dbconsole.Protocol
	Host     string
	Port     int
	Database string
	TLSMode  string
	CACert   string
	Username string
}

// config 以 secret 的副本組出連線設定：連線層會清零它收到的切片，呼叫端的原值不受影響。
func (t Target) config(secret []byte) dbconsole.Config {
	return dbconsole.Config{
		Protocol: t.Protocol, Host: t.Host, Port: t.Port, Username: t.Username,
		Password: bytes.Clone(secret), Database: t.Database, TLSMode: t.TLSMode, CACert: t.CACert,
	}
}

// Rotate 五步改密。回 nil＝新密碼已生效且以新密碼連得上；否則回 *Failure。
// 不改動 oldSecret、newSecret。
func Rotate(ctx context.Context, open Opener, t Target, oldSecret, newSecret []byte) error {
	p := t.Protocol
	// 第 1 步：本地前置
	if reason := CheckPreconditions(p, t.Username, oldSecret, newSecret); reason != "" {
		return &Failure{Kind: KindLocalPrecondition, Reason: reason,
			Cause: Error{Dialect: string(p), Step: StepPrecondition, Class: "local"}}
	}
	var newVerifier, oldVerifier string
	if p == dbconsole.ProtocolPostgres {
		var err error
		if newVerifier, err = SCRAMVerifier(newSecret); err != nil {
			return &Failure{Kind: KindLocalPrecondition, Reason: model.ChangeSecretReasonInvalidNewSecret,
				Cause: Error{Dialect: string(p), Step: StepPrecondition, Class: "local"}}
		}
		if oldVerifier, err = SCRAMVerifier(oldSecret); err != nil {
			return &Failure{Kind: KindLocalPrecondition, Reason: model.ChangeSecretReasonInvalidOldSecret,
				Cause: Error{Dialect: string(p), Step: StepPrecondition, Class: "local"}}
		}
	}

	// 第 2 步：舊密碼連線、探測
	connA, err := open(ctx, t.config(oldSecret))
	if err != nil {
		cause := connectError(p, StepLoginOld, err)
		reason := model.ChangeSecretReasonRemoteUnreachable
		if cause.Class == string(dbconsole.ClassAuth) {
			reason = model.ChangeSecretReasonOldCredentialLoginFailed
		}
		return &Failure{Kind: KindRemoteRejected, Reason: reason, Cause: cause}
	}
	defer func() { _ = connA.Close() }()

	row, err := connA.QueryRow(ctx, probeQuery(p))
	if err != nil {
		return &Failure{Kind: KindRemoteRejected, Reason: model.ChangeSecretReasonRemoteRejected,
			Cause: statementError(ctx, p, StepProbe, err)}
	}
	probe, reason := checkProbe(p, t.Username, row)
	if reason != "" {
		return &Failure{Kind: KindRemoteRejected, Reason: reason,
			Cause: Error{Dialect: string(p), Step: StepProbe, Class: "rejected"}}
	}

	// 第 3 步：單句改密（autocommit、不包交易）
	alter := buildAlter(p, probe, oldSecret, newSecret, newVerifier)
	if err := connA.Exec(ctx, alter.query, alter.args...); err != nil {
		cause := statementError(ctx, p, StepAlter, err)
		// 只有目標端回了錯誤碼才能說「沒套用」（單句原子）。斷線、逾時、沒有錯誤碼的
		// 網路或驅動協定錯誤都不能排除語句已在目標端生效：一律交不可知、保留候選
		if cause.Class == ClassLost || cause.Code == "" {
			return &Failure{Kind: KindIndeterminate, Cause: cause}
		}
		return &Failure{Kind: KindRemoteRejected, Reason: model.ChangeSecretReasonRemoteRejected, Cause: cause}
	}

	// 第 4 步：另開連線以新密碼自驗
	connB, err := open(ctx, t.config(newSecret))
	if err == nil {
		_ = connB.Close()
		return nil
	}
	cause := connectError(p, StepLoginNew, err)
	if cause.Class != string(dbconsole.ClassAuth) {
		// 網路或未知原因不能證明新密碼無效：改密語句已成功，此時改回等於把一個可能
		// 正確的狀態改掉。保留給重試
		return &Failure{Kind: KindIndeterminate, Cause: cause}
	}

	// 第 5 步：新密碼被拒，在第一條連線改回舊密碼（改密不中斷已登入的會話）
	back := buildAlter(p, probe, newSecret, oldSecret, oldVerifier)
	if rerr := connA.Exec(ctx, back.query, back.args...); rerr != nil {
		return &Failure{Kind: KindRemoteStateUnknown,
			Reason: model.ChangeSecretReasonRemoteSelfVerifyRollbackFailed,
			Cause:  statementError(ctx, p, StepRollback, rerr)}
	}
	return &Failure{Kind: KindRemoteRejected, Reason: model.ChangeSecretReasonRemoteSelfVerifyFailed, Cause: cause}
}

// Verify 以新密碼建立連線並執行 SELECT 1；delays 為每次嘗試前的等待（第一個通常為 0）。
// 全部失敗回最後一次的 *Failure（不含密碼與 driver 原文）。不改動 secret。
func Verify(ctx context.Context, open Opener, t Target, secret []byte, delays []time.Duration,
	sleep func(context.Context, time.Duration) error) error {
	if len(delays) == 0 {
		delays = []time.Duration{0}
	}
	var last Error
	for _, d := range delays {
		if d > 0 {
			if err := sleep(ctx, d); err != nil {
				return &Failure{Kind: KindIndeterminate,
					Cause: Error{Dialect: string(t.Protocol), Step: StepVerify, Class: ClassLost}}
			}
		}
		conn, err := open(ctx, t.config(secret))
		if err != nil {
			last = connectError(t.Protocol, StepVerify, err)
			continue
		}
		_, qerr := conn.QueryRow(ctx, "SELECT 1")
		_ = conn.Close()
		if qerr == nil {
			return nil
		}
		last = statementError(ctx, t.Protocol, StepVerify, qerr)
	}
	return &Failure{Kind: KindIndeterminate, Cause: last}
}
