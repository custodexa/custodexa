package asset

import (
	"context"
	"testing"

	"github.com/custodexa/backend/internal/model"
)

// 依交易 context 歸因：服務層把交易綁上只帶歸因標示的 context，交易內寫入面的節點留痕列由入庫匯流點帶上 token 標示。

func assetTokenCtx(id uint, name string) context.Context {
	ctx := model.WithRequestCredential(context.Background(), model.RequestCredentialAPIToken)
	return model.WithAPITokenRef(ctx, model.APITokenRef{ID: id, Name: name})
}

// TestAPITokenAssetNodeRowsAttributedByTxContext 以 token 請求的 context 建立、改名、刪除節點：每一筆節點留痕列帶標示；
// 人類工作階段的 context 兩欄為空。
func TestAPITokenAssetNodeRowsAttributedByTxContext(t *testing.T) {
	svc, db := setupGroupDB(t)
	ctx := assetTokenCtx(31, "inventory-sync")
	g, err := svc.Create(ctx, &AssetGroupRequest{Name: "prod"}, 1, "admin", "192.0.2.4")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Update(ctx, g.ID, &AssetGroupRequest{Name: "prod-2"}, 1, "admin", "192.0.2.4"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Delete(ctx, g.ID, 1, "admin", "192.0.2.4"); err != nil {
		t.Fatal(err)
	}
	var rows []model.AuditLog
	if err := db.Order("id").Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if len(rows) < 3 {
		t.Fatalf("節點留痕列 %d 筆, want >= 3", len(rows))
	}
	for _, r := range rows {
		if r.APITokenID == nil || *r.APITokenID != 31 || r.APITokenName == nil || *r.APITokenName != "inventory-sync" {
			t.Fatalf("列 %d（%s）應帶標示：%v %v", r.ID, r.Action, r.APITokenID, r.APITokenName)
		}
	}
	human := model.WithRequestCredential(context.Background(), model.RequestCredentialHumanSession)
	before := rows[len(rows)-1].ID
	if _, err := svc.Create(human, &AssetGroupRequest{Name: "dev"}, 1, "admin", "192.0.2.4"); err != nil {
		t.Fatal(err)
	}
	var after []model.AuditLog
	if err := db.Where("id > ?", before).Find(&after).Error; err != nil {
		t.Fatal(err)
	}
	if len(after) == 0 {
		t.Fatal("人類工作階段同樣留痕")
	}
	for _, r := range after {
		if r.APITokenID != nil || r.APITokenName != nil {
			t.Fatalf("親自操作的列 %d 不帶標示", r.ID)
		}
	}
}
