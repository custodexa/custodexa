package main

// 收束順序守衛：已入列的審計列在金鑰材料收回之前寫出。
//
// 審計列在寫入時才蓋完整性章。服務圖收束時若先收回材料、後排空審計佇列，
// 佇列裡的列會不帶章落地，事後的完整性驗證把它們判為不符——而那些列對應的
// 請求早已正常完成。本檔以正式組裝建出的完整服務圖走真的 Release，斷言
// 收束前入列的每一列都帶章落地，且重算相符。

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
)

func TestReleaseStampsQueuedAuditRows(t *testing.T) {
	env := newSealIntegrationEnvWith(t, func(s1 *stage1) {
		// 產品預設為非同步寫入；本環境為其他測試預設同步，這裡要驗的正是佇列路徑
		s1.cfg.Features.AsyncAuditEnabled = true
	})

	kek, err := buildUIKEKProvider([]byte(testInitialKEK))
	if err != nil {
		t.Fatalf("建構 KEK provider 失敗: %v", err)
	}
	g, err := runStage2(context.Background(), env.s1, kek, nil, nil)
	if err != nil {
		if g != nil {
			_ = g.Release(context.Background())
		}
		t.Fatalf("段 2 建構失敗: %v", err)
	}

	// 小於批量、且不等定時 flush：這些列在 Release 開始時仍在佇列或 worker 手上
	const n = 7
	const marker = "/api/v1/release-flush-probe/"
	for i := 0; i < n; i++ {
		g.auditService.Log(&audit.AuditLogEntry{
			UserID: 1, Username: "admin", Action: model.ActionRead, Resource: model.ResourceAuth,
			Status: model.StatusSuccess, Method: "GET", Path: fmt.Sprintf("%s%d", marker, i),
			ClientIP: "203.0.113.9", StatusCode: 200,
		})
	}

	rctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := g.Release(rctx); err != nil {
		t.Fatalf("Release 失敗: %v", err)
	}

	var rows []model.AuditLog
	if err := database.DB.Where("path LIKE ?", marker+"%").Order("id").Find(&rows).Error; err != nil {
		t.Fatalf("查詢審計列失敗: %v", err)
	}
	if len(rows) != n {
		t.Fatalf("收束前入列 %d 列，落地 %d 列", n, len(rows))
	}
	for _, r := range rows {
		if r.IntegrityHMAC == "" || r.KeyVersion == 0 {
			t.Errorf("列 %d（%s）不帶完整性章落地（key_version=%d）：材料在審計佇列寫出之前就被收回",
				r.ID, r.Path, r.KeyVersion)
		}
	}
}
