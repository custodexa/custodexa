package asset

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/glebarez/sqlite"
	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 測試用的連線使用者／操作者
const (
	hostKeyTestUserID   = uint(42)
	hostKeyTestUsername = "hk-tester"
)

func setupHostKeyDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&model.AssetHostKey{}, &model.AssetHostKeyMismatch{}, &model.AuditLog{}, &model.User{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

// newHostKeyTestService 帶真審計落地面（寫 audit_logs）與記錄型告警落地面的服務
func newHostKeyTestService(db *gorm.DB) (*HostKeyService, *recordingAlertSink) {
	svc := NewHostKeyService(db)
	alerts := &recordingAlertSink{}
	svc.SetAuditTxSink(audit.NewTxSink())
	svc.SetSystemAlertSink(alerts)
	return svc, alerts
}

// failingTxSink 注入固定錯誤的審計落地面
type failingTxSink struct{ err error }

func (f failingTxSink) WriteInTx(*gorm.DB, port.AuditEvent) error { return f.err }

func genHostKey(t *testing.T) ssh.PublicKey {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh pub: %v", err)
	}
	return sshPub
}

func hostKeyDial(svc *HostKeyService, assetID uint, path HostKeyPath, addr string, key ssh.PublicKey) (error, *HostKeyDialResult) {
	cb, res := svc.CallbackFor(HostKeyDialContext{
		AssetID: assetID, Path: path, UserID: hostKeyTestUserID, Username: hostKeyTestUsername,
		AccountID: 3, ClientIP: "203.0.113.9", ConnectionRef: "sess_test",
	})
	return cb(addr, nil, key), res
}

func hostKeyActorForTest() HostKeyActor {
	return HostKeyActor{UserID: hostKeyTestUserID, Username: hostKeyTestUsername, ClientIP: "203.0.113.9"}
}

func countAudit(t *testing.T, db *gorm.DB, action model.AuditAction) int64 {
	t.Helper()
	var n int64
	if err := db.Model(&model.AuditLog{}).Where("action = ?", string(action)).Count(&n).Error; err != nil {
		t.Fatal(err)
	}
	return n
}

func countObservations(t *testing.T, db *gorm.DB, assetID uint) int64 {
	t.Helper()
	var n int64
	if err := db.Model(&model.AssetHostKeyMismatch{}).Where("asset_id = ?", assetID).Count(&n).Error; err != nil {
		t.Fatal(err)
	}
	return n
}

func TestHostKeyTOFUAndMatch(t *testing.T) {
	svc, _ := newHostKeyTestService(setupHostKeyDB(t))
	key := genHostKey(t)

	// 首連：TOFU 記錄
	if err, _ := hostKeyDial(svc, 7, HostKeyPathTerminal, "host:22", key); err != nil {
		t.Fatalf("first use should pass: %v", err)
	}
	rec, err := svc.Get(7)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if rec.Fingerprint != ssh.FingerprintSHA256(key) {
		t.Errorf("fingerprint mismatch: %s", rec.Fingerprint)
	}

	// 重連同金鑰：放行且結果不是不符
	err, res := hostKeyDial(svc, 7, HostKeyPathTerminal, "host:22", key)
	if err != nil || res.Mismatch() {
		t.Errorf("same key should pass without mismatch: %v %v", err, res.Mismatch())
	}
}

func TestHostKeyReset(t *testing.T) {
	db := setupHostKeyDB(t)
	svc, alerts := newHostKeyTestService(db)
	if err, _ := hostKeyDial(svc, 7, HostKeyPathTerminal, "host:22", genHostKey(t)); err != nil {
		t.Fatal(err)
	}

	existed, err := svc.Reset(7, hostKeyActorForTest())
	if err != nil || !existed {
		t.Fatalf("Reset = %v, %v", existed, err)
	}
	if len(alerts.events) != 1 || alerts.events[0].Type != port.SystemAlertHostKeyRecordChanged || alerts.events[0].Params["change"] != "reset" {
		t.Fatalf("重置應產生一則 host_key_record_changed（reset）告警，實得 %+v", alerts.events)
	}

	// 重置後新金鑰重新 TOFU
	newKey := genHostKey(t)
	if err, _ := hostKeyDial(svc, 7, HostKeyPathTerminal, "host:22", newKey); err != nil {
		t.Errorf("re-TOFU after reset should pass: %v", err)
	}

	existed, _ = svc.Reset(999, hostKeyActorForTest())
	if existed {
		t.Error("reset unknown asset should report false")
	}
	if len(alerts.events) != 1 {
		t.Errorf("無可重置的請求不得發告警，實有 %d 則", len(alerts.events))
	}
}

// noopRevoker 測試用 authz 級聯撤銷面：資產刪除不涉授權時不做事。
type noopRevoker struct{}

func (noopRevoker) RevokeByAsset(*gorm.DB, uint) (int64, int64, error) { return 0, 0, nil }

// TestHostKeyAddressContinuity 指紋沿用撥號位址：刪除重建不歸零、改址不能繞過、重置只影響本資產。
// 不符時依路徑處置：互動路徑放行並留痕、背景路徑拒絕並留痕，兩者都不為資產記錄新指紋。
func TestHostKeyAddressContinuity(t *testing.T) {
	setup := func(t *testing.T) (*gorm.DB, *AssetService, *HostKeyService, *recordingAlertSink) {
		t.Helper()
		db := setupAccountDB(t)
		if err := db.AutoMigrate(&model.AssetHostKey{}, &model.AssetHostKeyMismatch{}, &model.User{}); err != nil {
			t.Fatal(err)
		}
		assets, _ := newAccountServices(t)
		assets.SetAuthorizationRevoker(noopRevoker{})
		svc, alerts := newHostKeyTestService(db)
		return db, assets, svc, alerts
	}
	mk := func(t *testing.T, assets *AssetService, name, host string, port int) *model.Asset {
		t.Helper()
		a, err := assets.Create(WithSystemCaller(context.Background()), &CreateAssetRequest{
			Name: name, Protocol: model.ProtocolSSH, Host: host, Port: port,
			Username: "root", Password: "s3cret", CreatedBy: 1,
		})
		if err != nil {
			t.Fatalf("建立資產 %s: %v", name, err)
		}
		return a
	}
	dial := func(svc *HostKeyService, a *model.Asset, path HostKeyPath, key ssh.PublicKey) (error, *HostKeyDialResult) {
		return hostKeyDial(svc, a.ID, path, fmt.Sprintf("%s:%d", a.Host, a.Port), key)
	}
	rowCount := func(t *testing.T, db *gorm.DB, assetID uint) int64 {
		t.Helper()
		var n int64
		db.Model(&model.AssetHostKey{}).Where("asset_id = ?", assetID).Count(&n)
		return n
	}

	t.Run("刪除後同位址重建：金鑰不符時互動放行並留痕、背景拒絕並留痕，皆不建自身列；金鑰相符沿用並得到自身列", func(t *testing.T) {
		db, assets, svc, alerts := setup(t)
		k1, k2 := genHostKey(t), genHostKey(t)
		a1 := mk(t, assets, "old", "10.0.0.1", 22)
		if err, _ := dial(svc, a1, HostKeyPathTerminal, k1); err != nil {
			t.Fatalf("首連: %v", err)
		}
		if err := assets.Delete(WithSystemCaller(context.Background()), a1.ID); err != nil {
			t.Fatalf("刪除資產: %v", err)
		}
		if got := rowCount(t, db, a1.ID); got != 1 {
			t.Fatalf("刪除資產後指紋列應保留，實有 %d 筆", got)
		}
		a2 := mk(t, assets, "new", "10.0.0.1", 22)
		err, res := dial(svc, a2, HostKeyPathTerminal, k2)
		if err != nil || !res.Mismatch() || res.Decision().Source != HostKeyRecordAddress {
			t.Fatalf("刪除重建後同位址不同金鑰：互動路徑應放行並標不符（同位址記錄），實得 %v %+v", err, res.Decision())
		}
		if err, _ := dial(svc, a2, HostKeyPathCredentialChange, k2); !errors.Is(err, ErrHostKeyChanged) {
			t.Fatalf("背景路徑遇不符必須拒絕，實得 %v", err)
		}
		if got := rowCount(t, db, a2.ID); got != 0 {
			t.Fatalf("不符時不得為新資產建立自身列，實有 %d 筆", got)
		}
		if n := countAudit(t, db, model.ActionHostKeyMismatch); n != 2 {
			t.Fatalf("兩次不符應各留一筆審計，實有 %d", n)
		}
		if len(alerts.events) != 1 {
			t.Fatalf("同一指紋只告警一次，實有 %d", len(alerts.events))
		}
		if err, _ := dial(svc, a2, HostKeyPathTerminal, k1); err != nil {
			t.Fatalf("相符沿用應放行: %v", err)
		}
		if got := rowCount(t, db, a2.ID); got != 1 {
			t.Fatalf("相符沿用後新資產應得到自身列，實有 %d 筆", got)
		}
	})

	t.Run("改址到已有記錄的位址：自身列為準（有自身列）、同位址記錄為準（無自身列）皆判不符並留痕", func(t *testing.T) {
		db, assets, svc, _ := setup(t)
		kA, kB, kC := genHostKey(t), genHostKey(t), genHostKey(t)
		a := mk(t, assets, "a", "10.0.1.1", 22)
		b := mk(t, assets, "b", "10.0.1.2", 22)
		if err, _ := dial(svc, a, HostKeyPathTerminal, kA); err != nil {
			t.Fatal(err)
		}
		if err, _ := dial(svc, b, HostKeyPathTerminal, kB); err != nil {
			t.Fatal(err)
		}
		// 有自身列：a 改址到 b 的位址，連到的是 b 的金鑰 → 與 a 自身記錄不符（互動放行、背景拒絕）
		a.Host = "10.0.1.2"
		if err, res := dial(svc, a, HostKeyPathFileTransfer, kB); err != nil || !res.Mismatch() || res.Decision().Source != HostKeyRecordOwn {
			t.Fatalf("有自身列的資產改址後連到別台金鑰必須判不符（自身記錄）並放行，實得 %v %+v", err, res.Decision())
		}
		if err, _ := dial(svc, a, HostKeyPathCredentialRotation, kB); !errors.Is(err, ErrHostKeyChanged) {
			t.Fatalf("背景路徑必須拒絕，實得 %v", err)
		}
		rec, _ := svc.Get(a.ID)
		if rec.Fingerprint != ssh.FingerprintSHA256(kA) {
			t.Fatalf("記錄不得被改寫，實為 %s", rec.Fingerprint)
		}
		// 無自身列：c 從未連過，位址上已有 b 的記錄，連到別的金鑰 → 不符
		c := mk(t, assets, "c", "10.0.1.2", 22)
		if err, res := dial(svc, c, HostKeyPathConnectionTest, kC); err != nil || !res.Mismatch() {
			t.Fatalf("無自身列的資產連到與位址記錄不同的金鑰必須判不符並放行，實得 %v", err)
		}
		if n := countAudit(t, db, model.ActionHostKeyMismatch); n != 3 {
			t.Fatalf("三次不符應各留一筆審計，實有 %d", n)
		}
	})

	t.Run("超管重置後接受新指紋（正）；從未見過的位址首次信任（正）", func(t *testing.T) {
		db, assets, svc, _ := setup(t)
		a := mk(t, assets, "r", "10.0.2.1", 22)
		if err, _ := dial(svc, a, HostKeyPathTerminal, genHostKey(t)); err != nil {
			t.Fatal(err)
		}
		if ok, err := svc.Reset(a.ID, hostKeyActorForTest()); err != nil || !ok {
			t.Fatalf("Reset = %v, %v", ok, err)
		}
		fresh := genHostKey(t)
		if err, _ := dial(svc, a, HostKeyPathTerminal, fresh); err != nil {
			t.Fatalf("重置後接受新指紋: %v", err)
		}
		rec, err := svc.Get(a.ID)
		if err != nil || rec.Fingerprint != ssh.FingerprintSHA256(fresh) {
			t.Fatalf("重置後應記錄新指紋: %v %+v", err, rec)
		}
		n := mk(t, assets, "never", "10.0.2.99", 22)
		if err, _ := dial(svc, n, HostKeyPathTerminal, genHostKey(t)); err != nil {
			t.Fatalf("從未見過的位址首次信任: %v", err)
		}
		if got := rowCount(t, db, n.ID); got != 1 {
			t.Fatalf("首次信任應建立自身列，實有 %d 筆", got)
		}
	})

	t.Run("查詢失敗回查核失敗", func(t *testing.T) {
		db, assets, svc, _ := setup(t)
		a := mk(t, assets, "f", "10.0.3.1", 22)
		if err := db.Migrator().DropTable(&model.AssetHostKey{}); err != nil {
			t.Fatal(err)
		}
		err, _ := dial(svc, a, HostKeyPathTerminal, genHostKey(t))
		if !errors.Is(err, ErrHostKeyCheckFailed) {
			t.Fatalf("查詢失敗必須回 ErrHostKeyCheckFailed，實得 %v", err)
		}
	})

	t.Run("重置：只有位址記錄的資產可重置、原列保留、皆無回無可重置", func(t *testing.T) {
		db, assets, svc, _ := setup(t)
		k1 := genHostKey(t)
		old := mk(t, assets, "old", "10.0.4.1", 22)
		if err, _ := dial(svc, old, HostKeyPathTerminal, k1); err != nil {
			t.Fatal(err)
		}
		if err := assets.Delete(WithSystemCaller(context.Background()), old.ID); err != nil {
			t.Fatal(err)
		}
		fresh := mk(t, assets, "fresh", "10.0.4.1", 22)
		if ok, err := svc.Reset(fresh.ID, hostKeyActorForTest()); err != nil || !ok {
			t.Fatalf("只有位址記錄時重置應成功: %v %v", ok, err)
		}
		if got := rowCount(t, db, old.ID); got != 1 {
			t.Fatalf("已刪除資產的原列必須保留，實有 %d 筆", got)
		}
		newKey := genHostKey(t)
		if err, _ := dial(svc, fresh, HostKeyPathTerminal, newKey); err != nil {
			t.Fatalf("重置後下次連線應記錄新指紋: %v", err)
		}
		rec, err := svc.Get(fresh.ID)
		if err != nil || rec.Fingerprint != ssh.FingerprintSHA256(newKey) || rec.Inherited {
			t.Fatalf("重置後應有自身的新指紋: %v %+v", err, rec)
		}
		// 皆無
		none := mk(t, assets, "none", "10.0.4.77", 22)
		if ok, err := svc.Reset(none.ID, hostKeyActorForTest()); err != nil || ok {
			t.Fatalf("皆無記錄時應回無可重置: %v %v", ok, err)
		}
	})

	t.Run("檢視：無自身列時沿用位址記錄並標 inherited、不帶來源識別", func(t *testing.T) {
		_, assets, svc, _ := setup(t)
		k := genHostKey(t)
		old := mk(t, assets, "old", "10.0.5.1", 22)
		if err, _ := dial(svc, old, HostKeyPathTerminal, k); err != nil {
			t.Fatal(err)
		}
		if err := assets.Delete(WithSystemCaller(context.Background()), old.ID); err != nil {
			t.Fatal(err)
		}
		fresh := mk(t, assets, "fresh", "10.0.5.1", 22)
		rec, err := svc.Get(fresh.ID)
		if err != nil {
			t.Fatal(err)
		}
		if !rec.Inherited || rec.AssetID != fresh.ID || rec.ID != 0 || rec.Fingerprint != ssh.FingerprintSHA256(k) {
			t.Fatalf("沿用記錄不符預期: %+v", rec)
		}
		other := mk(t, assets, "other", "10.0.5.2", 22)
		if _, err := svc.Get(other.ID); !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("皆無記錄應回查無: %v", err)
		}
	})

	t.Run("撥號位址輔助函式與六個使用點的實際撥號目標一致", func(t *testing.T) {
		ssh1 := &model.Asset{Protocol: model.ProtocolSSH, Host: " Host-A.Example ", Port: 2222}
		winDefault := &model.Asset{Protocol: model.ProtocolRDP, Host: "10.0.0.5", Port: 3389, RotationChannel: model.RotationChannelWindowsSSH}
		winCustom := &model.Asset{Protocol: model.ProtocolRDP, Host: "[::1]", Port: 3389, RotationChannel: model.RotationChannelWindowsSSH, RotationSSHPort: 2200}
		deleted := &model.Asset{Protocol: model.ProtocolSSH, Host: "10.0.0.9", Port: 22}
		for name, c := range map[string]struct {
			asset   *model.Asset
			dialled string // 使用點實際傳給 ssh 的撥號目標
			wantH   string
			wantP   int
		}{
			// 使用點 1、2、3（終端、檔案傳輸、連線測試）：fmt.Sprintf("%s:%d", Host, Port)
			"ssh 直連":     {ssh1, fmt.Sprintf("%s:%d", ssh1.Host, ssh1.Port), "host-a.example", 2222},
			"ssh 已軟刪擁有者": {deleted, fmt.Sprintf("%s:%d", deleted.Host, deleted.Port), "10.0.0.9", 22},
			// 使用點 4、5、6（改密、改密重試、憑證輪替）：rotationAddr
			"rdp windows_ssh 預設埠": {winDefault, rotationAddr(winDefault, model.RotationChannelWindowsSSH), "10.0.0.5", 22},
			"rdp windows_ssh 自訂埠": {winCustom, rotationAddr(winCustom, model.RotationChannelWindowsSSH), "::1", 2200},
		} {
			h, p, ok := c.asset.HostKeyAddress()
			if !ok || h != c.wantH || p != c.wantP {
				t.Errorf("%s：輔助函式 (%q,%d,%v)，應為 (%q,%d)", name, h, p, ok, c.wantH, c.wantP)
			}
			dh, dp, dok := dialAddress(c.dialled)
			if !dok || dh != h || dp != p {
				t.Errorf("%s：撥號目標 %q 解出 (%q,%d,%v)，與輔助函式 (%q,%d) 不一致", name, c.dialled, dh, dp, dok, h, p)
			}
		}
		// 沒有 SSH 撥號的資產不推位址
		if _, _, ok := (&model.Asset{Protocol: model.ProtocolVNC, Host: "h", Port: 5900}).HostKeyAddress(); ok {
			t.Error("vnc 資產不應有 SSH 撥號位址")
		}
	})
}

// TestHostKeyMismatchTrace 指紋不符的留痕與處置：互動路徑放行、背景路徑拒絕；審計逐次、告警依指紋去重
// （背景拒絕後第一次放行再告警一次）；留痕任一步失敗即查核失敗且三者皆不寫；重置後重新記錄清空觀察。
func TestHostKeyMismatchTrace(t *testing.T) {
	const assetID = uint(11)
	seed := func(t *testing.T) (*gorm.DB, *HostKeyService, *recordingAlertSink, ssh.PublicKey) {
		t.Helper()
		db := setupHostKeyDB(t)
		svc, alerts := newHostKeyTestService(db)
		recorded := genHostKey(t)
		if err, _ := hostKeyDial(svc, assetID, HostKeyPathTerminal, "10.0.9.1:22", recorded); err != nil {
			t.Fatal(err)
		}
		return db, svc, alerts, recorded
	}
	lastAuditDetails := func(t *testing.T, db *gorm.DB) map[string]any {
		t.Helper()
		var row model.AuditLog
		if err := db.Where("action = ?", string(model.ActionHostKeyMismatch)).Order("id DESC").First(&row).Error; err != nil {
			t.Fatal(err)
		}
		var details map[string]any
		if err := json.Unmarshal([]byte(row.Details), &details); err != nil {
			t.Fatalf("details 非 JSON: %v (%s)", err, row.Details)
		}
		if row.AssetID == nil || *row.AssetID != assetID || row.UserID != hostKeyTestUserID || row.Username != hostKeyTestUsername {
			t.Fatalf("審計列的資產或使用者不符: %+v", row)
		}
		return details
	}
	observation := func(t *testing.T, db *gorm.DB, key ssh.PublicKey) model.AssetHostKeyMismatch {
		t.Helper()
		var o model.AssetHostKeyMismatch
		if err := db.Where("asset_id = ? AND observed_fingerprint = ?", assetID, ssh.FingerprintSHA256(key)).First(&o).Error; err != nil {
			t.Fatal(err)
		}
		return o
	}

	t.Run("互動路徑：自身記錄不符放行並留痕，記錄指紋不變", func(t *testing.T) {
		db, svc, alerts, recorded := seed(t)
		other := genHostKey(t)
		err, res := hostKeyDial(svc, assetID, HostKeyPathTerminal, "10.0.9.1:22", other)
		if err != nil || !res.Mismatch() {
			t.Fatalf("互動路徑不符應放行並標不符，實得 %v %v", err, res.Mismatch())
		}
		rec, _ := svc.Get(assetID)
		if rec.Fingerprint != ssh.FingerprintSHA256(recorded) {
			t.Fatalf("記錄指紋不得改寫: %s", rec.Fingerprint)
		}
		if n := countAudit(t, db, model.ActionHostKeyMismatch); n != 1 {
			t.Fatalf("審計應 1 筆，實有 %d", n)
		}
		d := lastAuditDetails(t, db)
		if d["recorded_fingerprint"] != ssh.FingerprintSHA256(recorded) || d["observed_fingerprint"] != ssh.FingerprintSHA256(other) ||
			d["record_source"] != "own" || d["outcome"] != "allowed" || d["path"] != "terminal" || d["connection_ref"] != "sess_test" {
			t.Fatalf("審計 details 不符: %v", d)
		}
		if len(alerts.events) != 1 {
			t.Fatalf("告警應 1 則，實有 %d", len(alerts.events))
		}
		ev := alerts.events[0]
		if ev.Type != port.SystemAlertHostKeyMismatch || ev.Params["outcome"] != "allowed" || ev.Params["path"] != "terminal" ||
			ev.Params["record_source"] != "own" || ev.Params["observed_fingerprint"] != ssh.FingerprintSHA256(other) ||
			ev.Params["recorded_fingerprint"] != ssh.FingerprintSHA256(recorded) || ev.Params["observed_algorithm"] != other.Type() ||
			ev.Params["connection_ref"] != "sess_test" || ev.CorrelationID == "" || ev.CorrelationID != d["correlation_id"] ||
			ev.Actor.UserID != hostKeyTestUserID || ev.Actor.Username != hostKeyTestUsername || ev.AssetID == nil || *ev.AssetID != assetID {
			t.Fatalf("告警事件不符: %+v", ev)
		}
		o := observation(t, db, other)
		if o.SeenCount != 1 || o.FirstAllowedAt == nil || o.RecordedFingerprint != ssh.FingerprintSHA256(recorded) || o.ObservedPublicKey == "" || o.Host != "10.0.9.1" || o.Port != 22 {
			t.Fatalf("觀察紀錄不符: %+v", o)
		}
	})

	t.Run("互動路徑同指紋再三次：審計 4、告警 1、次數 4；換指紋再告警", func(t *testing.T) {
		db, svc, alerts, _ := seed(t)
		other := genHostKey(t)
		for i := 0; i < 4; i++ {
			if err, _ := hostKeyDial(svc, assetID, HostKeyPathFileTransfer, "10.0.9.1:22", other); err != nil {
				t.Fatal(err)
			}
		}
		if n := countAudit(t, db, model.ActionHostKeyMismatch); n != 4 {
			t.Fatalf("審計應 4 筆，實有 %d", n)
		}
		if len(alerts.events) != 1 {
			t.Fatalf("同一指紋只告警一次，實有 %d", len(alerts.events))
		}
		if o := observation(t, db, other); o.SeenCount != 4 {
			t.Fatalf("次數應為 4，實為 %d", o.SeenCount)
		}
		third := genHostKey(t)
		if err, _ := hostKeyDial(svc, assetID, HostKeyPathConnectionTest, "10.0.9.1:22", third); err != nil {
			t.Fatal(err)
		}
		if len(alerts.events) != 2 {
			t.Fatalf("出示另一個指紋應再告警，實有 %d", len(alerts.events))
		}
		if n := countObservations(t, db, assetID); n != 2 {
			t.Fatalf("觀察紀錄應列出兩個指紋，實有 %d", n)
		}
	})

	t.Run("agent 終端屬背景路徑：拒絕並留痕（agent_terminal／refused／not_sent）", func(t *testing.T) {
		db, svc, alerts, _ := seed(t)
		if HostKeyPathAgentTerminal.Interactive() {
			t.Fatal("agent_terminal 不得是互動路徑")
		}
		err, res := hostKeyDial(svc, assetID, HostKeyPathAgentTerminal, "10.0.9.1:22", genHostKey(t))
		if !errors.Is(err, ErrHostKeyChanged) || !res.Mismatch() {
			t.Fatalf("agent 終端遇不符必須拒絕並標不符，實得 %v", err)
		}
		d := lastAuditDetails(t, db)
		if d["path"] != "agent_terminal" || d["outcome"] != "refused" || d["credentials"] != "not_sent" {
			t.Fatalf("審計 details 不符: %v", d)
		}
		if len(alerts.events) != 1 || alerts.events[0].Params["path"] != "agent_terminal" || alerts.events[0].Params["outcome"] != "refused" {
			t.Fatalf("告警不符: %+v", alerts.events)
		}
	})

	t.Run("背景路徑：拒絕並留痕（處置 refused）；先背景拒絕再互動放行會再告警一次，之後不再", func(t *testing.T) {
		db, svc, alerts, _ := seed(t)
		other := genHostKey(t)
		err, _ := hostKeyDial(svc, assetID, HostKeyPathCredentialChange, "10.0.9.1:22", other)
		if !errors.Is(err, ErrHostKeyChanged) {
			t.Fatalf("背景路徑不符必須回 ErrHostKeyChanged，實得 %v", err)
		}
		if d := lastAuditDetails(t, db); d["outcome"] != "refused" || d["path"] != "credential_change" {
			t.Fatalf("背景路徑審計處置應為 refused: %v", d)
		}
		if len(alerts.events) != 1 || alerts.events[0].Params["outcome"] != "refused" {
			t.Fatalf("首次出現應告警一則（refused），實得 %+v", alerts.events)
		}
		if o := observation(t, db, other); o.FirstAllowedAt != nil {
			t.Fatalf("只被背景拒絕過的指紋 first_allowed_at 應為空: %+v", o)
		}
		if err, _ := hostKeyDial(svc, assetID, HostKeyPathCredentialRotation, "10.0.9.1:22", other); !errors.Is(err, ErrHostKeyChanged) {
			t.Fatalf("輪替路徑不符必須拒絕，實得 %v", err)
		}
		if len(alerts.events) != 1 {
			t.Fatalf("背景再拒絕不再告警，實有 %d", len(alerts.events))
		}
		if err, _ := hostKeyDial(svc, assetID, HostKeyPathTerminal, "10.0.9.1:22", other); err != nil {
			t.Fatalf("互動路徑應放行: %v", err)
		}
		if len(alerts.events) != 2 || alerts.events[1].Params["outcome"] != "allowed" {
			t.Fatalf("背景拒絕後第一次放行應再告警一則（allowed），實得 %d 則 %+v", len(alerts.events), alerts.events)
		}
		if err, _ := hostKeyDial(svc, assetID, HostKeyPathTerminal, "10.0.9.1:22", other); err != nil {
			t.Fatal(err)
		}
		if len(alerts.events) != 2 {
			t.Fatalf("之後再放行不得再告警，實有 %d", len(alerts.events))
		}
		if n := countAudit(t, db, model.ActionHostKeyMismatch); n != 4 {
			t.Fatalf("四次撥號應各留一筆審計，實有 %d", n)
		}
		if o := observation(t, db, other); o.SeenCount != 4 || o.FirstAllowedAt == nil {
			t.Fatalf("觀察紀錄次數與首次放行時刻不符: %+v", o)
		}
	})

	t.Run("留痕任一步失敗：回查核失敗且審計、告警、觀察皆 0 列", func(t *testing.T) {
		for name, arrange := range map[string]func(db *gorm.DB, svc *HostKeyService, alerts *recordingAlertSink){
			"審計落地面回錯": func(_ *gorm.DB, svc *HostKeyService, _ *recordingAlertSink) {
				svc.SetAuditTxSink(failingTxSink{err: errors.New("audit down")})
			},
			"審計落地面未注入": func(_ *gorm.DB, svc *HostKeyService, _ *recordingAlertSink) { svc.SetAuditTxSink(nil) },
			"告警落地面回錯": func(_ *gorm.DB, _ *HostKeyService, alerts *recordingAlertSink) {
				alerts.err = errors.New("alert down")
			},
			"告警落地面未注入": func(_ *gorm.DB, svc *HostKeyService, _ *recordingAlertSink) { svc.SetSystemAlertSink(nil) },
			"觀察紀錄寫入失敗": func(db *gorm.DB, _ *HostKeyService, _ *recordingAlertSink) {
				if err := db.Migrator().DropTable(&model.AssetHostKeyMismatch{}); err != nil {
					t.Fatal(err)
				}
			},
		} {
			t.Run(name, func(t *testing.T) {
				db, svc, alerts, _ := seed(t)
				arrange(db, svc, alerts)
				for _, path := range []HostKeyPath{HostKeyPathTerminal, HostKeyPathCredentialChange} {
					err, res := hostKeyDial(svc, assetID, path, "10.0.9.1:22", genHostKey(t))
					if !errors.Is(err, ErrHostKeyCheckFailed) || res.Mismatch() {
						t.Fatalf("%s：留痕失敗必須回 ErrHostKeyCheckFailed 且不標不符，實得 %v", path, err)
					}
				}
				if n := countAudit(t, db, model.ActionHostKeyMismatch); n != 0 {
					t.Fatalf("審計應回滾為 0，實有 %d", n)
				}
				if len(alerts.events) != 0 {
					t.Fatalf("告警應為 0，實有 %d", len(alerts.events))
				}
				if db.Migrator().HasTable(&model.AssetHostKeyMismatch{}) {
					if n := countObservations(t, db, assetID); n != 0 {
						t.Fatalf("觀察紀錄應回滾為 0，實有 %d", n)
					}
				}
			})
		}
	})

	t.Run("記錄讀取失敗回查核失敗", func(t *testing.T) {
		db, svc, _, _ := seed(t)
		if err := db.Migrator().DropTable(&model.AssetHostKey{}); err != nil {
			t.Fatal(err)
		}
		if err, _ := hostKeyDial(svc, assetID, HostKeyPathTerminal, "10.0.9.1:22", genHostKey(t)); !errors.Is(err, ErrHostKeyCheckFailed) {
			t.Fatalf("讀取失敗應回 ErrHostKeyCheckFailed，實得 %v", err)
		}
	})

	t.Run("重置後下一次連線寫新記錄並清空觀察紀錄", func(t *testing.T) {
		db, svc, alerts, _ := seed(t)
		other := genHostKey(t)
		if err, _ := hostKeyDial(svc, assetID, HostKeyPathTerminal, "10.0.9.1:22", other); err != nil {
			t.Fatal(err)
		}
		if ok, err := svc.Reset(assetID, hostKeyActorForTest()); err != nil || !ok {
			t.Fatalf("Reset: %v %v", ok, err)
		}
		fresh := genHostKey(t)
		if err, res := hostKeyDial(svc, assetID, HostKeyPathTerminal, "10.0.9.1:22", fresh); err != nil || res.Mismatch() {
			t.Fatalf("重置後應重新記錄: %v", err)
		}
		rec, _ := svc.Get(assetID)
		if rec.Fingerprint != ssh.FingerprintSHA256(fresh) {
			t.Fatalf("重置後應記錄新指紋: %s", rec.Fingerprint)
		}
		if n := countObservations(t, db, assetID); n != 0 {
			t.Fatalf("重新記錄應清空觀察紀錄，實有 %d", n)
		}
		// 之後與新記錄不符的連線重新開始告警
		before := len(alerts.events)
		if err, _ := hostKeyDial(svc, assetID, HostKeyPathTerminal, "10.0.9.1:22", other); err != nil {
			t.Fatal(err)
		}
		if len(alerts.events) != before+1 {
			t.Fatalf("重置後再不符應重新告警，實有 %d（前 %d）", len(alerts.events), before)
		}
	})

}

// TestHostKeyAdoptInterleave 採用在交易內讀取並原子消耗觀察列：在途請求在另一次採用提交之後才進入交易時，
// 其指紋已失效，必須回 ErrHostKeyObservationNotFound 且不得把舊指紋寫回信任；採用與重置對同一資產序列化。
func TestHostKeyAdoptInterleave(t *testing.T) {
	const assetID = uint(21)
	db := setupHostKeyDB(t)
	svc, alerts := newHostKeyTestService(db)
	recorded, x, y := genHostKey(t), genHostKey(t), genHostKey(t)
	if err, _ := hostKeyDial(svc, assetID, HostKeyPathTerminal, "10.0.9.1:22", recorded); err != nil {
		t.Fatal(err)
	}
	for _, k := range []ssh.PublicKey{x, y} {
		if err, _ := hostKeyDial(svc, assetID, HostKeyPathTerminal, "10.0.9.1:22", k); err != nil {
			t.Fatal(err)
		}
	}
	alerts.events = nil
	actor := hostKeyActorForTest()

	t.Run("R1 採用 X 在途時 R2 採用 Y 先提交：R1 回查無、信任維持 Y", func(t *testing.T) {
		fired := false
		svc.adoptTxBarrier = func() {
			if fired {
				return
			}
			fired = true
			svc.adoptTxBarrier = nil
			if _, err := svc.Adopt(assetID, ssh.FingerprintSHA256(y), actor); err != nil {
				t.Fatalf("R2 採用 Y: %v", err)
			}
		}
		_, err := svc.Adopt(assetID, ssh.FingerprintSHA256(x), actor)
		if !errors.Is(err, ErrHostKeyObservationNotFound) {
			t.Fatalf("在途的 R1 應因 X 已失效而回 ErrHostKeyObservationNotFound，實得 %v", err)
		}
		rec, _ := svc.Get(assetID)
		if rec.Fingerprint != ssh.FingerprintSHA256(y) {
			t.Fatalf("信任應維持 R2 採用的 Y，實為 %s", rec.Fingerprint)
		}
		if n := countObservations(t, db, assetID); n != 0 {
			t.Fatalf("觀察紀錄應已清空，實有 %d", n)
		}
		if n := countAudit(t, db, model.ActionHostKeyAdopt); n != 1 {
			t.Fatalf("採用審計應只有 R2 的 1 筆，實有 %d", n)
		}
		if len(alerts.events) != 1 {
			t.Fatalf("採用告警應只有 1 則，實有 %d", len(alerts.events))
		}
	})

	t.Run("採用在途時重置先提交：採用仍只消耗交易內仍存在的觀察；重置後首連重新記錄並清空", func(t *testing.T) {
		z := genHostKey(t)
		if err, _ := hostKeyDial(svc, assetID, HostKeyPathTerminal, "10.0.9.1:22", z); err != nil {
			t.Fatal(err)
		}
		fired := false
		svc.adoptTxBarrier = func() {
			if fired {
				return
			}
			fired = true
			svc.adoptTxBarrier = nil
			if ok, err := svc.Reset(assetID, actor); err != nil || !ok {
				t.Fatalf("Reset: %v %v", ok, err)
			}
			// 重置後首連：重新記錄並清空觀察（含 Z）
			if err, _ := hostKeyDial(svc, assetID, HostKeyPathTerminal, "10.0.9.1:22", recorded); err != nil {
				t.Fatal(err)
			}
		}
		_, err := svc.Adopt(assetID, ssh.FingerprintSHA256(z), actor)
		if !errors.Is(err, ErrHostKeyObservationNotFound) {
			t.Fatalf("重置與首連提交後，在途採用 Z 應回查無，實得 %v", err)
		}
		rec, _ := svc.Get(assetID)
		if rec.Fingerprint != ssh.FingerprintSHA256(recorded) || rec.ResetPending {
			t.Fatalf("信任應為重置後首連記錄的指紋: %+v", rec)
		}
	})
}
