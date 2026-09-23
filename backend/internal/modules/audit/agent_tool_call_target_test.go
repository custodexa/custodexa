package audit

import (
	"context"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// The ledger stores only session_id. Without the target projection an auditor reading the
// ledger cannot tell which asset and which account a call actually touched.
func TestQueryProjectsSessionTarget(t *testing.T) {
	db := newVersionedDB(t)
	if err := db.AutoMigrate(&model.AgentToolCall{}, &model.Session{}, &model.Asset{}); err != nil {
		t.Fatal(err)
	}
	integrity, _ := newVersionedIntegrity(t, db)
	asset := model.Asset{Name: "prod-db-01", Host: "10.0.0.9", Port: 22, CreatedBy: 1, Protocol: model.ProtocolSSH}
	if err := db.Create(&asset).Error; err != nil {
		t.Fatal(err)
	}
	live := model.Session{SessionID: "s-live", UserID: 1, AssetID: &asset.ID, AccountUsername: "app", StartTime: time.Now(), Status: model.SessionStatusClosed, Protocol: model.ProtocolSSH}
	bare := model.Session{SessionID: "s-bare", UserID: 1, StartTime: time.Now(), Status: model.SessionStatusClosed, Protocol: model.ProtocolSSH}
	for _, row := range []*model.Session{&live, &bare} {
		if err := db.Create(row).Error; err != nil {
			t.Fatal(err)
		}
	}
	for i, id := range []*uint{&live.ID, &bare.ID, nil} {
		row := model.AgentToolCall{Seq: uint(i + 1), UserID: 1, AgentTokenID: 2, OwnerUserID: 3, Tool: "list_assets", ArgsRedacted: "{}", Decision: model.ToolCallPending, SessionID: id}
		if err := db.Session(&gorm.Session{SkipHooks: true}).Create(&row).Error; err != nil {
			t.Fatal(err)
		}
	}
	rows, total, err := NewAgentToolCallLedger(db, integrity).Query(context.Background(), AgentToolCallFilter{})
	if err != nil || total != 3 || len(rows) != 3 {
		t.Fatal(rows, total, err)
	}
	// Ordered id DESC: no session, bare session, live session.
	if rows[0].AssetName != "" || rows[0].AccountUsername != "" {
		t.Fatal("a call outside a session must not borrow a target", rows[0])
	}
	if rows[1].AssetName != "" || rows[1].AccountUsername != "" {
		t.Fatal("a session without an asset must stay empty", rows[1])
	}
	if rows[2].AssetName != "prod-db-01" || rows[2].AccountUsername != "app" {
		t.Fatal("session target not projected", rows[2])
	}
}
