package dbrotate

import (
	"context"
	"errors"
	"fmt"

	"github.com/custodexa/backend/internal/dbconsole"
)

// 流程步驟（Error.Step 的值域）。
const (
	StepPrecondition = "precondition"
	StepLoginOld     = "login_old"
	StepProbe        = "probe"
	StepAlter        = "alter"
	StepLoginNew     = "login_new"
	StepRollback     = "rollback"
	StepVerify       = "verify"
)

// ClassLost 語句送出後連線中斷或逾時（Error.Class 在 dbconsole 分類之外多出的值）。
const ClassLost = "lost"

// Error 回給呼叫端的錯誤：只帶方言、步驟、目標端錯誤碼與錯誤類別。
//
// 原始 driver 錯誤在分類完成後即丟棄，不以 %w 包住：訊息原文可能含語句片段（MySQL
// 1064 會回顯 near '<片段>'），也可能含主機與帳號。
type Error struct {
	Dialect string
	Step    string
	Code    string
	Class   string
}

func (e Error) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("dbrotate: dialect=%s step=%s code=%s class=%s", e.Dialect, e.Step, e.Code, e.Class)
	}
	return fmt.Sprintf("dbrotate: dialect=%s step=%s class=%s", e.Dialect, e.Step, e.Class)
}

// Kind 失敗的分流（對應改密執行器的錯誤契約）。
type Kind int

const (
	// KindLocalPrecondition 本地前置失敗，完全未觸碰遠端
	KindLocalPrecondition Kind = iota + 1
	// KindRemoteRejected 遠端確定未變更
	KindRemoteRejected
	// KindRemoteStateUnknown 遠端狀態不可知且成因已知（帶專屬原因碼）
	KindRemoteStateUnknown
	// KindIndeterminate 遠端狀態不可知（送出後中斷、逾時、新密碼連線因網路失敗）
	KindIndeterminate
)

// Failure 一次改密或驗證的失敗：分流、原因碼與不含原文的成因。
type Failure struct {
	Kind   Kind
	Reason string
	Cause  Error
}

func (f *Failure) Error() string {
	if f.Reason == "" {
		return f.Cause.Error()
	}
	return f.Reason + ": " + f.Cause.Error()
}

// connectError 連線階段的錯誤分類（先對原始錯誤做完，再丟棄原文）。
func connectError(p dbconsole.Protocol, step string, err error) Error {
	e := Error{Dialect: string(p), Step: step, Class: string(dbconsole.ClassifyConnect(p, err))}
	if d := dbconsole.DBErrorOf(p, err, false); d != nil {
		e.Code = d.Code
	}
	return e
}

// statementError 已建連線上的語句錯誤分類：斷線與逾時先判，其餘依錯誤碼。
func statementError(ctx context.Context, p dbconsole.Protocol, step string, err error) Error {
	e := Error{Dialect: string(p), Step: step}
	if d := dbconsole.DBErrorOf(p, err, false); d != nil {
		e.Code = d.Code
	}
	switch {
	case dbconsole.IsConnectionLost(err), ctx.Err() != nil, errors.Is(err, context.DeadlineExceeded),
		errors.Is(err, context.Canceled):
		e.Class = ClassLost
	default:
		e.Class = string(dbconsole.ClassifyConnect(p, err))
	}
	return e
}
