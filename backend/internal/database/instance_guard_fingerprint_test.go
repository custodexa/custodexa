package database

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// 純函式的表格測試：指紋、ack 判定、錯誤分類、攔下訊息。

func TestFingerprintOf(t *testing.T) {
	app := "custodexa-instance-guard"
	pid := int64(12345)
	start := time.Date(2026, 8, 25, 7, 12, 3, 123456000, time.UTC)

	t.Run("NULL 欄以 - 代入", func(t *testing.T) {
		fp := fingerprintOf(nil, nil, nil)
		if fp.ApplicationName != "-" || fp.BackendStart != "-" || fp.PID != 0 {
			t.Fatalf("NULL 欄未以占位符代入: %+v", fp)
		}
		if fp.Code != fingerprintCode("-|-|-") {
			t.Fatalf("NULL 三欄的碼 = %s，want sha256('-|-|-') 前 12 碼 %s", fp.Code, fingerprintCode("-|-|-"))
		}
		if len(fp.Code) != 12 {
			t.Fatalf("碼長 %d，want 12", len(fp.Code))
		}
		if fp.Source != FingerprintSourcePGStatActivity {
			t.Fatalf("Source = %q", fp.Source)
		}
	})

	t.Run("同輸入同碼", func(t *testing.T) {
		a := fingerprintOf(&app, &pid, &start)
		b := fingerprintOf(&app, &pid, &start)
		if a.Code != b.Code {
			t.Fatalf("同輸入不同碼：%s vs %s", a.Code, b.Code)
		}
		want := fingerprintCode(app + "|12345|" + start.Format(time.RFC3339Nano))
		if a.Code != want {
			t.Fatalf("碼 = %s，want %s（正規化字串 application_name|pid|backend_start）", a.Code, want)
		}
	})

	t.Run("backend_start 以 UTC 正規化：不同時區同一瞬間同碼", func(t *testing.T) {
		taipei := start.In(time.FixedZone("Asia/Taipei", 8*3600))
		a := fingerprintOf(&app, &pid, &start)
		b := fingerprintOf(&app, &pid, &taipei)
		if a.Code != b.Code {
			t.Fatalf("同一瞬間不同時區算出不同碼：%s vs %s", a.Code, b.Code)
		}
		if !strings.HasSuffix(b.BackendStart, "Z") {
			t.Fatalf("可讀形式應為 UTC（Z 結尾），實得 %s", b.BackendStart)
		}
	})

	t.Run("任一欄變即碼變", func(t *testing.T) {
		base := fingerprintOf(&app, &pid, &start).Code
		app2 := app + "x"
		pid2 := pid + 1
		start2 := start.Add(time.Nanosecond)
		for name, got := range map[string]string{
			"application_name":      fingerprintOf(&app2, &pid, &start).Code,
			"pid":                   fingerprintOf(&app, &pid2, &start).Code,
			"backend_start":         fingerprintOf(&app, &pid, &start2).Code,
			"application_name NULL": fingerprintOf(nil, &pid, &start).Code,
		} {
			if got == base {
				t.Errorf("改 %s 後碼未變（%s）", name, got)
			}
		}
	})

	t.Run("降級形式", func(t *testing.T) {
		fp := degradedFingerprint("retryable")
		if fp.Source != FingerprintSourceUnavailable {
			t.Fatalf("Source = %q，want unavailable", fp.Source)
		}
		if fp.Code != fingerprintCode("unavailable|retryable") {
			t.Fatalf("降級碼 = %s，want sha256('unavailable|retryable') 前 12 碼", fp.Code)
		}
		if fp.Code == degradedFingerprint("permanent").Code {
			t.Fatal("不同錯誤類別的降級碼不應相同")
		}
		r := fp.readable()
		if !strings.Contains(r, "不可得") || !strings.Contains(r, "code="+fp.Code) {
			t.Fatalf("降級指紋的可讀形式應明說細節不可得並附 code：%s", r)
		}
	})

	t.Run("sqlite 固定形式", func(t *testing.T) {
		fp := sqliteFingerprint(4242, start)
		if fp.ApplicationName != "sqlite" || fp.PID != 4242 || fp.Source != FingerprintSourceSQLite {
			t.Fatalf("sqlite 指紋形式錯誤: %+v", fp)
		}
		if fp.Code != fingerprintCode("sqlite|4242|"+start.Format(time.RFC3339Nano)) {
			t.Fatalf("sqlite 碼不符正規化字串")
		}
	})

	t.Run("可讀形式含 code=", func(t *testing.T) {
		r := fingerprintOf(&app, &pid, &start).readable()
		for _, want := range []string{"application_name=" + app, "pid=12345", "backend_start=2026-08-25T07:12:03.123456Z", "code="} {
			if !strings.Contains(r, want) {
				t.Errorf("可讀形式缺 %q：%s", want, r)
			}
		}
	})
}

func TestEvaluateAck(t *testing.T) {
	cases := []struct {
		name     string
		ack      string
		code     string
		conflict bool
		want     ackVerdict
	}{
		{"有衝突、未設定 → 攔下", "", "ab12cd34ef56", true, ackNotSet},
		{"有衝突、相符 → 允許", "ab12cd34ef56", "ab12cd34ef56", true, ackMatch},
		{"有衝突、大小寫不同 → 不符（不做寬鬆比對）", "AB12CD34EF56", "ab12cd34ef56", true, ackMismatch},
		{"有衝突、前綴相同 → 不符", "ab12cd34ef5", "ab12cd34ef56", true, ackMismatch},
		{"有衝突、尾端空白 → 不符（純函式不修剪）", "ab12cd34ef56 ", "ab12cd34ef56", true, ackMismatch},
		{"有衝突、舊碼 → 不符（持鎖者已變更）", "000000000000", "ab12cd34ef56", true, ackMismatch},
		{"有衝突、碼為空 → 永不相符", "", "", true, ackNotSet},
		{"有衝突、碼為空但 ack 非空 → 不符", "x", "", true, ackMismatch},
		{"無衝突、有設定 → 未使用", "ab12cd34ef56", "", false, ackUnused},
		{"無衝突、未設定 → 未設", "", "", false, ackNotSet},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := evaluateAck(c.ack, c.code, c.conflict); got != c.want {
				t.Fatalf("evaluateAck(%q,%q,%v) = %v，want %v", c.ack, c.code, c.conflict, got, c.want)
			}
		})
	}
}

func TestClassifyGuardError(t *testing.T) {
	pg := func(code string) error { return &pgconn.PgError{Severity: "ERROR", Code: code, Message: "x"} }
	cases := []struct {
		name string
		err  error
		want guardErrorClass
	}{
		{"SQLSTATE 08006 連線失敗", pg("08006"), guardErrRetryable},
		{"SQLSTATE 08001 無法連線", pg("08001"), guardErrRetryable},
		{"SQLSTATE 57P01 admin_shutdown（pg_terminate_backend）", pg("57P01"), guardErrRetryable},
		{"SQLSTATE 57P02 crash_shutdown", pg("57P02"), guardErrRetryable},
		{"SQLSTATE 57P03 cannot_connect_now", pg("57P03"), guardErrRetryable},
		{"SQLSTATE 53300 too_many_connections", pg("53300"), guardErrRetryable},
		{"SQLSTATE 42501 insufficient_privilege", pg("42501"), guardErrPermanent},
		{"SQLSTATE 28P01 invalid_password", pg("28P01"), guardErrPermanent},
		{"SQLSTATE 28000 invalid_authorization", pg("28000"), guardErrPermanent},
		{"SQLSTATE 42P01 undefined_table", pg("42P01"), guardErrPermanent},
		{"SQLSTATE 42601 syntax_error", pg("42601"), guardErrPermanent},
		{"SQLSTATE 3D000 invalid_catalog_name", pg("3D000"), guardErrPermanent},
		{"SQLSTATE 22P02 其他資料錯誤 → 未知", pg("22P02"), guardErrUnknown},
		{"SQLSTATE 57014 query_canceled（非清單）→ 未知", pg("57014"), guardErrUnknown},
		{"包裝過的 PgError 仍取得 SQLSTATE", fmt.Errorf("查詢失敗: %w", pg("42501")), guardErrPermanent},
		{"字串回退：訊息含 (SQLSTATE 42501)", errors.New("ERROR: permission denied for view pg_stat_activity (SQLSTATE 42501)"), guardErrPermanent},
		{"字串回退：訊息含 (SQLSTATE 08006)", errors.New("failed: unexpected EOF (SQLSTATE 08006)"), guardErrRetryable},
		{"net.OpError", &net.OpError{Op: "read", Net: "tcp", Err: errors.New("connection reset by peer")}, guardErrRetryable},
		{"包裝過的 net.OpError", fmt.Errorf("write: %w", &net.OpError{Op: "write", Net: "tcp", Err: errors.New("broken pipe")}), guardErrRetryable},
		{"io.EOF", io.EOF, guardErrRetryable},
		{"io.ErrUnexpectedEOF", io.ErrUnexpectedEOF, guardErrRetryable},
		{"driver.ErrBadConn", driver.ErrBadConn, guardErrRetryable},
		{"context.DeadlineExceeded（查詢逾時）", context.DeadlineExceeded, guardErrRetryable},
		{"包裝過的 DeadlineExceeded", fmt.Errorf("q: %w", context.DeadlineExceeded), guardErrRetryable},
		{"context.Canceled", context.Canceled, guardErrRetryable},
		{"釘選連線不存在", errGuardNotConnected, guardErrRetryable},
		{"errors.New(x) → 未知", errors.New("x"), guardErrUnknown},
		{"sql: database is closed → 未知", errors.New("sql: database is closed"), guardErrUnknown},
		{"nil → 未知（不應被呼叫，仍有定義）", nil, guardErrUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := classifyGuardError(c.err); got != c.want {
				t.Fatalf("classifyGuardError(%v) = %s，want %s", c.err, got, c.want)
			}
		})
	}

	t.Run("類別對應 reason", func(t *testing.T) {
		if guardErrRetryable.reason() != GuardReasonDBUnreachable ||
			guardErrPermanent.reason() != GuardReasonPermanent ||
			guardErrUnknown.reason() != GuardReasonUnknown {
			t.Fatal("類別→reason 對應錯誤")
		}
	})
}

// TestInstanceGuardBlockedMessage 攔下訊息的五要素與不洩露邊界。
func TestInstanceGuardBlockedMessage(t *testing.T) {
	app := "custodexa-instance-guard"
	pid := int64(777)
	start := time.Date(2026, 8, 25, 1, 2, 3, 0, time.UTC)
	fp := fingerprintOf(&app, &pid, &start)

	t.Run("未設 ack", func(t *testing.T) {
		msg := blockedMessage(fp, ackNotSet)
		for _, want := range []string{
			"本版不支援多實例",
			"另一個資料庫工作階段持有",
			"application_name=" + app, "pid=777", "backend_start=2026-08-25T01:02:03Z", "code=" + fp.Code,
			"金鑰快取、匯出工作、錄影落地與封印期留痕",
			"先停止它，再重啟本實例",
			"INSTANCE_GUARD_ACK=" + fp.Code,
			"寫入審計事件並在管理介面顯示橫幅",
			"這不是資料庫損毀",
			"未由本實例執行 migration 或任何資料寫入",
			"持鎖者變更後失效",
			"由確認者承擔",
		} {
			if !strings.Contains(msg, want) {
				t.Errorf("訊息缺要素 %q\n%s", want, msg)
			}
		}
		if strings.Contains(msg, "持鎖者已變更") {
			t.Error("未設 ack 時不應加註「持鎖者已變更」")
		}
		for _, banned := range []string{"password=", "host=", "dbname=", "client_addr", "user="} {
			if strings.Contains(msg, banned) {
				t.Errorf("訊息不得含 %q", banned)
			}
		}
	})

	t.Run("ack 不符加註", func(t *testing.T) {
		msg := blockedMessage(fp, ackMismatch)
		if !strings.Contains(msg, "持鎖者已變更") || !strings.Contains(msg, "重新確認") {
			t.Fatalf("不符時應加註持鎖者已變更並要求重新確認\n%s", msg)
		}
	})

	t.Run("降級指紋仍給救援路徑", func(t *testing.T) {
		d := degradedFingerprint("permanent")
		msg := blockedMessage(d, ackNotSet)
		if !strings.Contains(msg, "無法取得持鎖者細節") || !strings.Contains(msg, "降級確認碼") {
			t.Fatalf("降級時應明說細節不可得\n%s", msg)
		}
		if !strings.Contains(msg, "INSTANCE_GUARD_ACK="+d.Code) {
			t.Fatalf("降級時仍須給出以降級碼重啟的救援指令\n%s", msg)
		}
	})
}
