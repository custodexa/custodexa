package api

import (
	"context"

	"gorm.io/gorm"
)

// 不測帳號寫入範圍的夾具所注入的帳號寫入範圍判定替身（產品碼缺注入即拒絕，夾具須明示注入）。

// allowAllAccountWriteScope 帳號寫入範圍判定替身：全放行。
type allowAllAccountWriteScope struct{}

func (allowAllAccountWriteScope) AuthorizeAccountWrite(context.Context, *gorm.DB, uint, uint) error {
	return nil
}
