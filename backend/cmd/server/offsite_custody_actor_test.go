package main

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/offsite"
)

// TestOffsiteCustodyJournalActor 擋：生產保管鏈 adapter 帶操作者的事件仍記成系統、丟掉既有
// details 或關聯識別、沒操作者的 worker 路徑誤記成人，以及呼叫端交易回滾後審計列仍留下。
func TestOffsiteCustodyJournalActor(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "custody.db")), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&model.AuditLog{}); err != nil {
		t.Fatal(err)
	}
	j := offsiteCustodyJournal{tx: audit.NewTxSink(), db: db}
	actor := &offsite.OffsiteActor{ID: 301, Name: "sec-admin", IP: "198.51.100.30"}
	ev := func(a *offsite.OffsiteActor, cid string) offsite.CustodyEvent {
		return offsite.CustodyEvent{
			Action: offsite.CustodyActionProfile, Resource: string(model.ResourceSession), Status: string(model.StatusSuccess),
			Details: map[string]any{"old_generation_id": 1, "result": "disabled"}, Actor: a, CorrelationID: cid,
		}
	}
	last := func() model.AuditLog {
		var row model.AuditLog
		if err := db.Order("id desc").First(&row).Error; err != nil {
			t.Fatal(err)
		}
		return row
	}

	t.Run("帶操作者：列記真實操作者、來源位址，details 保留並帶 correlation_id", func(t *testing.T) {
		if err := db.Transaction(func(tx *gorm.DB) error { return j.RecordInTx(tx, ev(actor, "ofs-test-1")) }); err != nil {
			t.Fatal(err)
		}
		row := last()
		if row.UserID != 301 || row.Username != "sec-admin" || row.ClientIP != "198.51.100.30" {
			t.Fatalf("審計主體不符: user=%d name=%s ip=%s", row.UserID, row.Username, row.ClientIP)
		}
		d := map[string]any{}
		if err := json.Unmarshal([]byte(row.Details), &d); err != nil {
			t.Fatal(err)
		}
		if d["result"] != "disabled" || d["old_generation_id"] == nil || d["correlation_id"] != "ofs-test-1" {
			t.Fatalf("details 不符: %v", d)
		}
	})

	t.Run("不帶操作者的 RecordInTx 與 worker 路徑的 Record 仍記系統", func(t *testing.T) {
		if err := db.Transaction(func(tx *gorm.DB) error { return j.RecordInTx(tx, ev(nil, "")) }); err != nil {
			t.Fatal(err)
		}
		if row := last(); row.UserID != 0 || row.Username != "system" {
			t.Fatalf("無操作者應記系統: %d %s", row.UserID, row.Username)
		}
		if err := j.Record(ev(nil, "")); err != nil {
			t.Fatal(err)
		}
		if row := last(); row.UserID != 0 || row.Username != "system" {
			t.Fatalf("worker 路徑應記系統: %d %s", row.UserID, row.Username)
		}
		if err := db.Transaction(func(tx *gorm.DB) error {
			return j.RecordInTx(tx, ev(&offsite.OffsiteActor{ID: 0, Name: "x"}, ""))
		}); err != nil {
			t.Fatal(err)
		}
		if row := last(); row.UserID != 0 || row.Username != "system" {
			t.Fatalf("操作者 ID 為 0 應記系統: %d %s", row.UserID, row.Username)
		}
	})

	t.Run("呼叫端交易回滾時該列不存在", func(t *testing.T) {
		var before int64
		db.Model(&model.AuditLog{}).Count(&before)
		_ = db.Transaction(func(tx *gorm.DB) error {
			if err := j.RecordInTx(tx, ev(actor, "ofs-rollback")); err != nil {
				return err
			}
			return errors.New("呼叫端回滾")
		})
		var after int64
		db.Model(&model.AuditLog{}).Count(&after)
		if after != before {
			t.Fatalf("回滾後多了 %d 列", after-before)
		}
	})
}
