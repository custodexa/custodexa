package main

import (
	"context"
	"log"

	"github.com/custodexa/backend/internal/modules/identity"
	"gorm.io/gorm"
)

// runScopedTemplateSeed 啟動資料步驟：先試跑記錄報告，再正式種入（重入零寫入）。
// 必須在權限附證來源注入之後、對外服務之前呼叫。衝突只記日誌、照常啟動；資料庫或事件寫入失敗回錯。
func runScopedTemplateSeed(ctx context.Context, db *gorm.DB) (identity.ScopedTemplateSeedReport, error) {
	dry, err := identity.SeedScopedTemplates(ctx, db, true)
	if err != nil {
		return dry, err
	}
	log.Print(dry.Line() + " mode=dry-run")
	rep, err := identity.SeedScopedTemplates(ctx, db, false)
	if err != nil {
		return rep, err
	}
	log.Printf("%s mode=apply applied=%t version_after=%d", rep.Line(), rep.Applied, rep.VersionAfter)
	if len(rep.Conflicts) > 0 {
		log.Printf("[ScopedTemplateSeed] 範本未套用（名稱或識別已被占用或內容不同）: %v；改名後下一次啟動補做", rep.Conflicts)
	}
	return rep, nil
}
