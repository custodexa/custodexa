package dbconsole

import (
	"context"
	"database/sql/driver"
	"errors"
	"sync/atomic"
)

// ErrConnectorSpent 一次性 connector 的第二次撥號。
//
// 這個錯誤**永遠不該出現在正常路徑上**：`database/sql` 只有在想重撥時才會再呼叫
// `Connect`，而重撥正是本套件禁止的事。它出現＝有人把單連線的釘選拿掉了
var ErrConnectorSpent = errors.New("dbconsole: 一次性 connector 已用畢，本套件不重撥目標連線")

// oneShotConnector 只能成功撥號一次的 connector。
//
// # 它解決什麼
//
// `database/sql` 的預設行為是：連線壞掉就拿原本的 connector 重撥一條新的。
// 那意味著池會**長期持有可重撥的材料**——對 driver 而言就是一份完整的認證設定。
// 會話開了八小時，密碼材料就在堆上待了八小時，而我們對外的說法是「明文只存活於
// 握手期間」。
//
// 本型別把那條路封死：第一次 `Connect` 成功後立刻呼叫 zero（由各方言實作，
// 覆寫自己設定物件裡的密碼欄），丟棄對內層 connector 的引用，其後的 `Connect`
// 一律回 ErrConnectorSpent。於是 `*sql.DB` 手上**沒有可再撥號的材料**——
// 不是「我們約定不重撥」，是重撥這件事在結構上做不到。
//
// # 為什麼不是「用完就 Close 掉 sql.DB」
//
// 那是會話結束時的事。問題出在會話**進行中**：一條目標連線在任何時刻都可能被
// 目標端踢掉，而 `database/sql` 的重撥發生在下一次取連線時，不需要任何人同意。
type oneShotConnector struct {
	inner driver.Connector
	// zero 首次撥號成功後清除我方持有的明文（覆寫設定物件的密碼欄與副本）。
	// **在 Connect 返回之後、把連線交給 database/sql 之前**呼叫——
	// 更早會讓握手拿不到密碼，更晚就會有一段沒有理由存在的存活期
	zero func()
	// spent 以 CAS 保證 zero 恰好跑一次：database/sql 可能自多個 goroutine
	// 呼叫 Connect（即使我們釘成單連線，關閉與取用仍可能並行）
	spent atomic.Bool
	// connects 撥號次數（含被拒的那些）。測試以它斷言「目標連線關閉後零重撥」——
	// 只斷言「沒有錯誤」的話，重撥成功與根本沒重撥是同一個結果
	connects atomic.Int64
}

func newOneShotConnector(inner driver.Connector, zero func()) *oneShotConnector {
	return &oneShotConnector{inner: inner, zero: zero}
}

// Connect 撥號。第一次成功後清零設定並使後續呼叫一律失敗。
func (c *oneShotConnector) Connect(ctx context.Context) (driver.Conn, error) {
	c.connects.Add(1)
	if c.spent.Load() {
		return nil, ErrConnectorSpent
	}
	conn, err := c.inner.Connect(ctx)
	if err != nil {
		// **失敗不算用畢**：握手失敗時 database/sql 沒有拿到任何連線，
		// 而呼叫端會把整個 Open 判為失敗並清零設定。把失敗也算成用畢，
		// 會讓「重試一次」這個由呼叫端決定的事在這一層被偷偷否決
		return nil, err
	}
	if c.spent.CompareAndSwap(false, true) {
		if c.zero != nil {
			c.zero()
		}
		c.inner = nil
	}
	return conn, nil
}

// Driver 回傳內層 driver。用畢後內層引用已丟棄，此時回 nil——
// `database/sql` 只在 `DB.Driver()` 這個內省路徑上用它，產品路徑不呼叫
func (c *oneShotConnector) Driver() driver.Driver {
	if c.inner == nil {
		return nil
	}
	return c.inner.Driver()
}

// ConnectAttempts 撥號次數（測試與診斷用）
func (c *oneShotConnector) ConnectAttempts() int64 { return c.connects.Load() }

// zeroBytes 就地覆寫位元組切片。
//
// 對 `[]byte` 有效是因為它可變；字串則無法就地清除，這正是 Config.Password
// 取 []byte 的理由
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
