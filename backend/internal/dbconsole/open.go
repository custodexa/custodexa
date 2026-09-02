package dbconsole

import (
	"context"
	"errors"
	"fmt"
)

// ErrUnsupportedProtocol 非本套件支援的方言
var ErrUnsupportedProtocol = errors.New("dbconsole: 不支援的協議")

// Open 對目標資料庫建立一條連線。
//
// # 密碼的所有權
//
// `cfg.Password` 在本函式返回時**已被覆寫為零**，無論成功或失敗。呼叫端不得在
// 呼叫後再次使用該切片，也不該自己保留副本——解封點的紀律是「明文只存活到握手
// 結束」，多留一份就是多一段沒有理由的存活期。
//
// # 失敗時回什麼
//
// 原始的 driver 錯誤原樣回傳，**不包裝、不泛化**：分類與泛化是呼叫端的事
// （它才知道這是起始連線還是切庫、才決定回哪一支機器碼）。在這一層先泛化，
// 審計就再也拿不到 class。
func Open(ctx context.Context, cfg Config) (Dialect, error) {
	if !cfg.Protocol.Supported() {
		zeroBytes(cfg.Password)
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedProtocol, cfg.Protocol)
	}
	switch cfg.Protocol {
	case ProtocolMySQL:
		return openMySQL(ctx, cfg)
	case ProtocolMSSQL:
		return openMSSQL(ctx, cfg)
	default:
		return openPostgres(ctx, cfg)
	}
}
