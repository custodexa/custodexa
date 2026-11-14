package asset

import (
	"context"

	"github.com/custodexa/backend/internal/model"
)

// contextWithInitiator 測試用：以背景發起者脈絡模擬工作發起者（與正式背景入口同一個標示）。
func contextWithInitiator(ctx context.Context, userID uint, username string) context.Context {
	return model.WithBackgroundInitiator(ctx, userID, username)
}
