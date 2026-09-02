package dbconsole

import (
	"bytes"
	"context"
	"database/sql/driver"
	"errors"
	"testing"
)

// 一次性 connector 的兩條不變式：撥號成功後我方持有的明文清零、第二次撥號被拒。
//
// 兩條缺一都不足以支撐對外的說法。只驗清零：連線一斷 database/sql 就用原
// connector 重撥，而重撥要的材料在 driver 內部，我方的清零攔不住它。
// 只驗拒絕：密碼仍在我方的設定物件裡躺到會話結束。

// probeRowValues 探詢語句的回應（當前庫、交易態、影響列數）
func probeRowValues(db, tx string, affected int64) []driver.Value {
	return []driver.Value{[]byte(db), []byte(tx), affected}
}

func TestOneShotConnectorContract(t *testing.T) {
	ourCopy := []byte("s3cret-password")
	cfg := &stubConfig{Password: string(ourCopy)}
	connector := &stubConnector{
		cfg:      cfg,
		probeRow: probeRowValues("app", "unknown", 0),
	}

	_, oneShot := newStubDialect(t, ProtocolMySQL, connector, ourCopy)

	// ── 撥號確實發生過，且發生的當下 driver 拿得到密碼 ──
	//
	// 沒有這一格，「連的時候就是空的」（driver 根本沒收到密碼）與
	// 「連完才清零」無法分辨——而前者代表清零的時機早到會讓握手失敗
	if connector.connected != 1 {
		t.Fatalf("撥號次數 = %d, want 1", connector.connected)
	}
	if connector.passwordAtConnect != "s3cret-password" {
		t.Fatalf("撥號當下 driver 取得的密碼 = %q，期望為原始密碼——"+
			"清零若發生在撥號之前，握手根本拿不到認證材料", connector.passwordAtConnect)
	}

	// ── 撥號返回之後：我方副本與設定物件的密碼欄皆已清零 ──
	if cfg.Password != "" {
		t.Errorf("設定物件的密碼欄 = %q, want 空字串", cfg.Password)
	}
	if !bytes.Equal(ourCopy, make([]byte, len(ourCopy))) {
		t.Errorf("我方的密碼副本未被就地覆寫為零: %q", ourCopy)
	}

	// ── 第二次撥號一律失敗 ──
	//
	// 這是「無可重撥材料」的可執行證據：database/sql 只有在想重撥時才會再呼叫
	// Connect，而重撥正是本套件禁止的事
	if _, err := oneShot.Connect(context.Background()); !errors.Is(err, ErrConnectorSpent) {
		t.Errorf("第二次 Connect 的錯誤 = %v, want ErrConnectorSpent", err)
	}
	if got := oneShot.ConnectAttempts(); got != 2 {
		t.Errorf("撥號嘗試次數 = %d, want 2（一次成功、一次被拒）", got)
	}
	if connector.connected != 1 {
		t.Errorf("內層 connector 被撥了 %d 次, want 1——被拒的那次不得抵達 driver", connector.connected)
	}
}

// TestOneShotConnectorFailureIsNotSpent 撥號失敗不算用畢。
//
// 反向對照：把失敗也算成用畢，會讓「要不要重試」這個由呼叫端決定的事在這一層
// 被偷偷否決，而呼叫端拿到的錯誤會是「connector 已用畢」而非真正的失敗原因。
func TestOneShotConnectorFailureIsNotSpent(t *testing.T) {
	want := errors.New("撥號失敗")
	inner := &failingConnector{err: want}
	zeroed := false
	oneShot := newOneShotConnector(inner, func() { zeroed = true })

	if _, err := oneShot.Connect(context.Background()); !errors.Is(err, want) {
		t.Fatalf("第一次 Connect 的錯誤 = %v, want %v", err, want)
	}
	if zeroed {
		t.Error("撥號失敗時不得清零：呼叫端可能還要以同一份設定重試")
	}

	inner.err = nil
	if _, err := oneShot.Connect(context.Background()); err != nil {
		t.Errorf("失敗之後的第二次 Connect 應可成功，卻回 %v", err)
	}
	if !zeroed {
		t.Error("成功撥號後未清零")
	}
	if _, err := oneShot.Connect(context.Background()); !errors.Is(err, ErrConnectorSpent) {
		t.Errorf("成功之後的再一次 Connect = %v, want ErrConnectorSpent", err)
	}
}

type failingConnector struct{ err error }

func (c *failingConnector) Connect(context.Context) (driver.Conn, error) {
	if c.err != nil {
		return nil, c.err
	}
	return &stubConn{owner: &stubConnector{cfg: &stubConfig{}}}, nil
}
func (c *failingConnector) Driver() driver.Driver { return stubDriver{} }
