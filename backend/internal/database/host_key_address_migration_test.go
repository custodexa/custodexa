package database

import (
	"fmt"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/testgate"
	"gorm.io/gorm"
)

// TestHostKeyAddressMigration 主機指紋位址增量：回填對各類擁有者資產（含已軟刪）正確、推不出者留空計入報告、
// 回填與 RunMigrations 第二次不改內容。
//
// sqlite 子測試驗回填語義（欄位由模型建出）；postgres 子測試（PG-gated）走真 DDL 與 RunMigrations。
func TestHostKeyAddressMigration(t *testing.T) {
	type hk struct {
		AssetID uint
		Host    string
		Port    int
	}
	read := func(t *testing.T, db *gorm.DB) map[uint]hk {
		t.Helper()
		var rows []hk
		if err := db.Raw(`SELECT asset_id, host, port FROM asset_host_keys ORDER BY asset_id`).Scan(&rows).Error; err != nil {
			t.Fatal(err)
		}
		out := map[uint]hk{}
		for _, r := range rows {
			out[r.AssetID] = r
		}
		return out
	}
	// seed 建立六種擁有者資產的指紋列（asset_id → 預期位址；預期 host 為空＝推不出）
	type want struct {
		host string
		port int
	}
	seed := func(t *testing.T, db *gorm.DB, insertKey func(assetID uint)) map[uint]want {
		t.Helper()
		mk := func(a *model.Asset) uint {
			t.Helper()
			a.CreatedBy = 1
			if err := db.Create(a).Error; err != nil {
				t.Fatal(err)
			}
			return a.ID
		}
		wants := map[uint]want{}
		id := mk(&model.Asset{Name: "ssh-a", Protocol: model.ProtocolSSH, Host: " Host-A.Example ", Port: 2222})
		wants[id] = want{"host-a.example", 2222}
		id = mk(&model.Asset{Name: "rdp-default", Protocol: model.ProtocolRDP, Host: "10.0.0.5", Port: 3389, RotationChannel: model.RotationChannelWindowsSSH})
		wants[id] = want{"10.0.0.5", 22}
		id = mk(&model.Asset{Name: "rdp-custom", Protocol: model.ProtocolRDP, Host: "[::1]", Port: 3389, RotationChannel: model.RotationChannelWindowsSSH, RotationSSHPort: 2200})
		wants[id] = want{"::1", 2200}
		deleted := &model.Asset{Name: "ssh-deleted", Protocol: model.ProtocolSSH, Host: "10.0.0.9", Port: 22}
		id = mk(deleted)
		if err := db.Delete(deleted).Error; err != nil {
			t.Fatal(err)
		}
		wants[id] = want{"10.0.0.9", 22}
		id = mk(&model.Asset{Name: "vnc", Protocol: model.ProtocolVNC, Host: "10.0.0.7", Port: 5900})
		wants[id] = want{}
		wants[9999] = want{} // 擁有者資產不存在
		for assetID := range wants {
			insertKey(assetID)
		}
		return wants
	}
	check := func(t *testing.T, got map[uint]hk, wants map[uint]want) {
		t.Helper()
		for id, w := range wants {
			g, ok := got[id]
			if !ok {
				t.Fatalf("資產 %d 的指紋列消失", id)
			}
			if g.Host != w.host || g.Port != w.port {
				t.Errorf("資產 %d 位址 (%q,%d)，應為 (%q,%d)", id, g.Host, g.Port, w.host, w.port)
			}
		}
	}

	t.Run("sqlite：各類擁有者回填正確、重跑不改內容", func(t *testing.T) {
		db := newAuthzSQLite(t)
		if err := db.AutoMigrate(&model.Asset{}, &model.AssetHostKey{}, &model.AuditLog{}); err != nil {
			t.Fatal(err)
		}
		wants := seed(t, db, func(assetID uint) {
			if err := db.Exec(`INSERT INTO asset_host_keys(asset_id, algorithm, fingerprint, public_key, created_at, updated_at) VALUES(?, 'ssh-ed25519', ?, 'pk', ?, ?)`,
				assetID, fmt.Sprintf("SHA256:fp%d", assetID), time.Now(), time.Now()).Error; err != nil {
				t.Fatal(err)
			}
		})
		plan, err := PlanHostKeyAddressReport(db)
		if err != nil {
			t.Fatal(err)
		}
		rep, err := BackfillHostKeyAddress(db)
		if err != nil {
			t.Fatal(err)
		}
		if rep != plan {
			t.Errorf("dry-run 與正式報告不一致: %+v vs %+v", plan, rep)
		}
		wantRep := HostKeyAddressReport{Total: 6, SSH: 2, RDPWindowsSSHDefaultPort: 1, RDPWindowsSSHCustomPort: 1, SoftDeleted: 1, Unresolved: 2}
		if rep != wantRep {
			t.Errorf("報告 %+v，應為 %+v", rep, wantRep)
		}
		check(t, read(t, db), wants)
		before := dumpTables(t, db, "asset_host_keys")
		rep2, err := BackfillHostKeyAddress(db)
		if err != nil {
			t.Fatal(err)
		}
		if after := dumpTables(t, db, "asset_host_keys"); after != before {
			t.Fatalf("第二次回填改動了內容\nbefore=%s\nafter=%s", before, after)
		}
		// 第二次只重新判定仍為空的兩列，其餘不處理
		if rep2.Total != 2 || rep2.Unresolved != 2 {
			t.Errorf("第二次回填報告 %+v，應只含推不出位址的兩列", rep2)
		}
	})

	t.Run("postgres：真 DDL 升級與 RunMigrations 第二次不改內容", func(t *testing.T) {
		dsn := testgate.Value(t, testgate.EnvPGDSN)
		db := freshSchema(t, dsn, fmt.Sprintf("hk_addr_%d", time.Now().UnixNano()))
		last := -1
		for i, m := range migrations {
			if m.Version == "20261019_asset_host_key_address" {
				last = i
			}
		}
		if last < 0 {
			t.Fatal("找不到本增量")
		}
		for _, m := range migrations[:last] {
			if err := m.Up(db); err != nil {
				t.Fatal(m.Version, err)
			}
		}
		wants := seed(t, db, func(assetID uint) {
			if err := db.Exec(`INSERT INTO asset_host_keys(asset_id, algorithm, fingerprint, public_key, created_at, updated_at) VALUES(?, 'ssh-ed25519', ?, 'pk', now(), now())`,
				assetID, fmt.Sprintf("SHA256:fp%d", assetID)).Error; err != nil {
				t.Fatal(err)
			}
		})
		plan, err := PlanHostKeyAddressReport(db)
		if err != nil {
			t.Fatal(err)
		}
		if err := migrations[last].Up(db); err != nil {
			t.Fatal(err)
		}
		check(t, read(t, db), wants)
		var idx int64
		if err := db.Raw(`SELECT count(*) FROM pg_indexes WHERE tablename = 'asset_host_keys' AND indexname = 'idx_asset_host_keys_address'`).Scan(&idx).Error; err != nil || idx != 1 {
			t.Fatalf("缺少 (host, port) 索引: n=%d err=%v", idx, err)
		}
		if plan.Total != 6 || plan.Unresolved != 2 {
			t.Errorf("dry-run 報告 %+v", plan)
		}
		t.Logf("dry-run 報告: %+v", plan)
		if err := rollbackHostKeyAddress(db); err != nil {
			t.Fatalf("開發用回滾: %v", err)
		}

		run := freshSchema(t, dsn, fmt.Sprintf("hk_addr_run_%d", time.Now().UnixNano()))
		prev := DB
		DB = run
		t.Cleanup(func() { DB = prev })
		if err := RunMigrations(); err != nil {
			t.Fatalf("第一次 RunMigrations: %v", err)
		}
		first := dumpTables(t, run, "schema_migrations", "asset_host_keys")
		if err := RunMigrations(); err != nil {
			t.Fatalf("第二次 RunMigrations: %v", err)
		}
		if second := dumpTables(t, run, "schema_migrations", "asset_host_keys"); second != first {
			t.Fatalf("第二次 RunMigrations 改動了內容")
		}
	})
}
