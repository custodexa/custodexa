package asset

import (
	"context"
	"errors"
	"time"

	"github.com/custodexa/backend/internal/dbconsole"
	"github.com/custodexa/backend/internal/dbrotate"
	"github.com/custodexa/backend/internal/model"
)

// dbNativeExecutor 資料庫帳號自改密碼（db_native 通道）。
//
// 五步流程與失敗分流在 dbrotate；本執行器只把資產欄位轉成連線目標，並把結果映射到
// 執行器的錯誤分流契約。cause 一律是 dbrotate 的錯誤（方言、步驟、錯誤碼或類別），
// 不含 driver 原文。不改動呼叫端的新舊密碼切片：連線層收到的是副本。
type dbNativeExecutor struct {
	open         dbrotate.Opener
	verifyDelays []time.Duration
	sleep        func(context.Context, time.Duration) error
}

// newDBNativeExecutor 正式組態：真實控制連線、與 Windows 通道相同的驗證重試序列。
func newDBNativeExecutor() dbNativeExecutor {
	return dbNativeExecutor{open: dbconsole.OpenControl, verifyDelays: windowsVerifyDelays(), sleep: sleepContext}
}

// dbRotateTarget 資產欄位轉為改密目標（不含密碼）。
func dbRotateTarget(t rotationTarget) dbrotate.Target {
	a := t.asset
	return dbrotate.Target{
		Protocol: dbconsole.Protocol(a.Protocol), Host: a.Host, Port: a.Port, Database: a.DBName,
		TLSMode: a.DBTLSMode, CACert: a.DBCACert, Username: t.username,
	}
}

func (e dbNativeExecutor) Rotate(ctx context.Context, t rotationTarget, oldSecret, newSecret []byte) error {
	return mapDBRotateError(dbrotate.Rotate(ctx, e.open, dbRotateTarget(t), oldSecret, newSecret))
}

func (e dbNativeExecutor) Verify(ctx context.Context, t rotationTarget, newSecret []byte) error {
	err := dbrotate.Verify(ctx, e.open, dbRotateTarget(t), newSecret, e.verifyDelays, e.sleep)
	if err == nil {
		return nil
	}
	// 驗證失敗的處置由呼叫端決定（記 VERIFY_FAILED）；這裡只交出不含原文的成因
	var f *dbrotate.Failure
	if errors.As(err, &f) {
		return f.Cause
	}
	return err
}

// mapDBRotateError dbrotate 的分流映射成執行器的錯誤契約。
func mapDBRotateError(err error) error {
	if err == nil {
		return nil
	}
	var f *dbrotate.Failure
	if !errors.As(err, &f) {
		return err
	}
	switch f.Kind {
	case dbrotate.KindLocalPrecondition:
		return &localPreconditionError{reason: f.Reason, cause: f.Cause}
	case dbrotate.KindRemoteRejected:
		return &remoteRejectedError{reason: f.Reason, cause: f.Cause}
	case dbrotate.KindRemoteStateUnknown:
		return &remoteStateUnknownError{reason: f.Reason, cause: f.Cause}
	default:
		// 遠端狀態不可知：交一般錯誤，呼叫端記 unverified 並保留候選
		return f.Cause
	}
}

// transportRiskIfContacted 改密紀錄的傳輸風險欄。
//
// 只有這筆處理以任何秘密對目標建立過連線（呼叫了 Rotate 且不是本地前置失敗，或呼叫了
// Verify）才填值，判定依連線當下的資產快照；跳過、本地前置失敗、撥號前被停下的紀錄為空。
func transportRiskIfContacted(asset *model.Asset, contacted bool) string {
	if !contacted || asset == nil {
		return ""
	}
	return model.DBRotationTransportRisk(string(asset.Protocol), asset.EffectiveRotationChannel(), asset.DBTLSMode)
}
