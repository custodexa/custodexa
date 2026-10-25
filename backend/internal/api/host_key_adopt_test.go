package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/authz"
)

// hkAlertSink 記錄型系統告警落地面（可注入錯誤）
type hkAlertSink struct {
	events []port.SystemAlertEvent
	err    error
}

func (s *hkAlertSink) RaiseInTx(_ *gorm.DB, ev port.SystemAlertEvent) (port.SystemAlertReceipt, error) {
	if s.err != nil {
		return port.SystemAlertReceipt{}, s.err
	}
	s.events = append(s.events, ev)
	return port.SystemAlertReceipt{Severity: "medium"}, nil
}

type hkFailingTxSink struct{ err error }

func (f hkFailingTxSink) WriteInTx(*gorm.DB, port.AuditEvent) error { return f.err }

// hostKeyAPIEnv 真 sqlite、真 HostKeyService、真 handler；身分以中介層注入（與 RegisterRoutes 同一條守衛鏈）。
type hostKeyAPIEnv struct {
	db       *gorm.DB
	hostKeys *asset.HostKeyService
	alerts   *hkAlertSink
	assets   *asset.AssetService
}

func newHostKeyAPIEnv(t *testing.T) *hostKeyAPIEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	if err := migrateWithAuthz(db, &model.Asset{}, &model.AssetGroup{}, &model.AssetNode{}, &model.AssetAccount{},
		&model.Credential{}, &model.CredentialSecretVersion{}, &model.AssetHostKey{}, &model.AssetHostKeyMismatch{},
		&model.AuditLog{}, &model.User{}, &model.Role{}, &model.UserRole{}, &model.UserGroup{}, &model.UserGroupMember{},
		&model.UserGroupRole{}, &model.RoleBindingNode{}); err != nil {
		t.Fatal(err)
	}
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })
	assets, err := asset.NewAssetService(aesColumnCodec(t, make([]byte, 32)), "localhost", 4822, audit.NewTxSink())
	assets.SetTopologyPermissionPort(noopTopologyPort{})
	if err != nil {
		t.Fatal(err)
	}
	hostKeys := asset.NewHostKeyService(db)
	alerts := &hkAlertSink{}
	hostKeys.SetAuditTxSink(audit.NewTxSink())
	hostKeys.SetSystemAlertSink(alerts)
	return &hostKeyAPIEnv{db: db, hostKeys: hostKeys, alerts: alerts, assets: assets}
}

func (e *hostKeyAPIEnv) asset(t *testing.T, name, host string) *model.Asset {
	t.Helper()
	a, err := e.assets.Create(asset.WithSystemCaller(context.Background()), &asset.CreateAssetRequest{
		Name: name, Protocol: model.ProtocolSSH, Host: host, Port: 22, Username: "root", Password: "pw", CreatedBy: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func hkKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// dial 以終端路徑撥號（放行並留痕）
func (e *hostKeyAPIEnv) dial(t *testing.T, a *model.Asset, key ssh.PublicKey) error {
	t.Helper()
	cb, _ := e.hostKeys.CallbackFor(asset.HostKeyDialContext{AssetID: a.ID, Path: asset.HostKeyPathTerminal, UserID: 9, Username: "dialer"})
	return cb(fmt.Sprintf("%s:%d", a.Host, a.Port), nil, key)
}

// do 以指定主體呼叫端點；守門鏈與 RegisterRoutes 相同（可視守門以 allow 替身）
func (e *hostKeyAPIEnv) do(p *authz.Principal, method, path, body string) (int, map[string]any) {
	hh := NewHostKeyHandler(e.hostKeys, &allowAssetVisibility{})
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("userID", uint(1))
		c.Set("username", "super")
		middleware.SetPrincipal(c, p)
	})
	r.GET("/assets/:id/host-key", middleware.RequireAssetVisible(hh.authz), hh.Get)
	r.DELETE("/assets/:id/host-key", RequireHostKeyResetSuperAdmin, hh.Reset)
	r.POST("/assets/:id/host-key/adopt", RequireHostKeyResetSuperAdmin, hh.Adopt)
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	var parsed map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &parsed)
	return w.Code, parsed
}

// allowAssetVisibility 可視守門替身：一律放行（守門本體另有測試）
type allowAssetVisibility struct{}

func (allowAssetVisibility) CheckPermission(context.Context, uint, uint, model.PermissionType) (bool, error) {
	return true, nil
}

func hkSortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (e *hostKeyAPIEnv) count(t *testing.T, model any, where string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := e.db.Model(model).Where(where, args...).Count(&n).Error; err != nil {
		t.Fatal(err)
	}
	return n
}

// TestHostKeyViewMismatches 檢視在有觀察紀錄時回 mismatches（最多 5 筆、最近者在前、不含公鑰），無時回應不變。
func TestHostKeyViewMismatches(t *testing.T) {
	super := legacyPrincipal(model.RoleAdmin)
	t.Run("無觀察紀錄：回應鍵集合與改前相同", func(t *testing.T) {
		e := newHostKeyAPIEnv(t)
		a := e.asset(t, "a", "10.0.0.1")
		if err := e.dial(t, a, hkKey(t)); err != nil {
			t.Fatal(err)
		}
		code, body := e.do(super, "GET", fmt.Sprintf("/assets/%d/host-key", a.ID), "")
		if code != http.StatusOK {
			t.Fatalf("GET: %d %v", code, body)
		}
		if got := hkSortedKeys(body); fmt.Sprint(got) != fmt.Sprint([]string{"algorithm", "asset_id", "created_at", "fingerprint", "id", "updated_at"}) {
			t.Fatalf("無觀察紀錄時鍵集合應與改前相同，實為 %v", got)
		}
	})
	t.Run("6 筆觀察只回 5 筆、最近者在前、欄位固定且不含公鑰", func(t *testing.T) {
		e := newHostKeyAPIEnv(t)
		a := e.asset(t, "a", "10.0.0.1")
		if err := e.dial(t, a, hkKey(t)); err != nil {
			t.Fatal(err)
		}
		var keys []ssh.PublicKey
		for i := 0; i < 6; i++ {
			k := hkKey(t)
			keys = append(keys, k)
			if err := e.dial(t, a, k); err != nil {
				t.Fatal(err)
			}
			// 讓 last_seen_at 單調遞增（sqlite 時間精度）
			e.db.Model(&model.AssetHostKeyMismatch{}).Where("observed_fingerprint = ?", ssh.FingerprintSHA256(k)).
				Update("last_seen_at", gorm.Expr("datetime('now', ?)", fmt.Sprintf("+%d seconds", i+1)))
		}
		code, body := e.do(super, "GET", fmt.Sprintf("/assets/%d/host-key", a.ID), "")
		if code != http.StatusOK {
			t.Fatalf("GET: %d %v", code, body)
		}
		list, _ := body["mismatches"].([]any)
		if len(list) != 5 {
			t.Fatalf("應回 5 筆，實回 %d: %v", len(list), body)
		}
		first := list[0].(map[string]any)
		if got := hkSortedKeys(first); fmt.Sprint(got) != fmt.Sprint([]string{"algorithm", "fingerprint", "first_seen_at", "last_seen_at", "seen_count"}) {
			t.Fatalf("觀察欄位應為 algorithm、fingerprint、first_seen_at、last_seen_at、seen_count，實為 %v", got)
		}
		if first["fingerprint"] != ssh.FingerprintSHA256(keys[5]) {
			t.Fatalf("最近出現者應在前: %v", first["fingerprint"])
		}
		raw, _ := json.Marshal(body)
		if bytes.Contains(raw, []byte("public_key")) || bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString(keys[5].Marshal()))) {
			t.Fatal("回應不得含公鑰本體")
		}
	})
	t.Run("未授權者仍 404", func(t *testing.T) {
		e := newHostKeyAPIEnv(t)
		a := e.asset(t, "a", "10.0.0.1")
		hh := NewHostKeyHandler(e.hostKeys, &denyAssetVisibility{})
		r := gin.New()
		r.Use(func(c *gin.Context) {
			c.Set("userID", uint(1))
			middleware.SetPrincipal(c, legacyPrincipal(model.RoleUser))
		})
		r.GET("/assets/:id/host-key", middleware.RequireAssetVisible(hh.authz), hh.Get)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("GET", fmt.Sprintf("/assets/%d/host-key", a.ID), nil))
		if w.Code != http.StatusNotFound {
			t.Fatalf("未授權應 404，實得 %d %s", w.Code, w.Body.String())
		}
	})
}

type denyAssetVisibility struct{}

func (denyAssetVisibility) CheckPermission(context.Context, uint, uint, model.PermissionType) (bool, error) {
	return false, nil
}

// TestHostKeyAdopt 採用觀察中的指紋：記錄改寫、觀察清除、審計與 host_key_record_changed 告警同交易；
// 不在觀察中回 404；非超管被拒；落地面錯誤整筆回滾；重置也發告警。
func TestHostKeyAdopt(t *testing.T) {
	super := legacyPrincipal(model.RoleAdmin)
	seed := func(t *testing.T) (*hostKeyAPIEnv, *model.Asset, ssh.PublicKey, ssh.PublicKey) {
		t.Helper()
		e := newHostKeyAPIEnv(t)
		a := e.asset(t, "a", "10.0.0.1")
		recorded, x := hkKey(t), hkKey(t)
		if err := e.dial(t, a, recorded); err != nil {
			t.Fatal(err)
		}
		if err := e.dial(t, a, x); err != nil {
			t.Fatal(err)
		}
		// 另一台資產與已刪除資產留下的同位址記錄：採用不得改寫
		other := e.asset(t, "other", "10.0.0.1")
		e.db.Create(&model.AssetHostKey{AssetID: other.ID, Algorithm: "ssh-ed25519", Fingerprint: "SHA256:other", PublicKey: "pk", Host: "10.0.0.1", Port: 22})
		e.db.Create(&model.AssetHostKey{AssetID: 9999, Algorithm: "ssh-ed25519", Fingerprint: "SHA256:deleted", PublicKey: "pk", Host: "10.0.0.1", Port: 22})
		e.alerts.events = nil
		return e, a, recorded, x
	}
	adoptBody := func(k ssh.PublicKey) string {
		b, _ := json.Marshal(map[string]string{"fingerprint": ssh.FingerprintSHA256(k)})
		return string(b)
	}
	snapshot := func(t *testing.T, e *hostKeyAPIEnv) string {
		t.Helper()
		var keys []model.AssetHostKey
		var obs []model.AssetHostKeyMismatch
		var audits []model.AuditLog
		e.db.Order("id").Find(&keys)
		e.db.Order("id").Find(&obs)
		e.db.Order("id").Find(&audits)
		b, _ := json.Marshal(map[string]any{"keys": keys, "obs": obs, "audits": len(audits), "alerts": len(e.alerts.events)})
		return string(b)
	}

	t.Run("超管採用 X", func(t *testing.T) {
		e, a, recorded, x := seed(t)
		// 先標為重置待記錄，採用要清掉旗標
		if ok, err := e.hostKeys.Reset(a.ID, asset.HostKeyActor{UserID: 1, Username: "super"}); err != nil || !ok {
			t.Fatal(ok, err)
		}
		e.alerts.events = nil
		code, body := e.do(super, "POST", fmt.Sprintf("/assets/%d/host-key/adopt", a.ID), adoptBody(x))
		if code != http.StatusOK {
			t.Fatalf("採用: %d %v", code, body)
		}
		if body["fingerprint"] != ssh.FingerprintSHA256(x) {
			t.Fatalf("回應應為新檢視: %v", body)
		}
		if _, has := body["mismatches"]; has {
			t.Fatal("採用回應不得帶 mismatches")
		}
		var rec model.AssetHostKey
		if err := e.db.Where("asset_id = ?", a.ID).First(&rec).Error; err != nil {
			t.Fatal(err)
		}
		if rec.Fingerprint != ssh.FingerprintSHA256(x) || rec.Algorithm != x.Type() ||
			rec.PublicKey != base64.StdEncoding.EncodeToString(x.Marshal()) || rec.ResetPending {
			t.Fatalf("記錄應為 X（演算法、公鑰取自觀察，重置旗標清除）: %+v", rec)
		}
		if n := e.count(t, &model.AssetHostKeyMismatch{}, "asset_id = ?", a.ID); n != 0 {
			t.Fatalf("觀察紀錄應清空，實有 %d", n)
		}
		var audits []model.AuditLog
		e.db.Where("action = ?", string(model.ActionHostKeyAdopt)).Find(&audits)
		if len(audits) != 1 {
			t.Fatalf("採用審計應 1 筆，實有 %d", len(audits))
		}
		var details map[string]any
		_ = json.Unmarshal([]byte(audits[0].Details), &details)
		if details["previous_fingerprint"] != "reset_pending" || details["adopted_fingerprint"] != ssh.FingerprintSHA256(x) || details["ever_allowed"] != true {
			t.Fatalf("採用審計 details 不符（原記錄處於重置待記錄應標 reset_pending）: %v", details)
		}
		if details["trust_generation_before"] != float64(2) || details["trust_generation_after"] != float64(3) {
			t.Fatalf("採用審計 details 應帶世代前後值 2／3（重置已推進一次）: %v", details)
		}
		if audits[0].UserID != 1 || audits[0].Username != "super" || audits[0].AssetID == nil || *audits[0].AssetID != a.ID {
			t.Fatalf("採用審計的操作者或資產不符: %+v", audits[0])
		}
		if len(e.alerts.events) != 1 {
			t.Fatalf("告警應恰 1 則（host_key_record_changed），實有 %d", len(e.alerts.events))
		}
		ev := e.alerts.events[0]
		if ev.Type != port.SystemAlertHostKeyRecordChanged || ev.Params["change"] != "adopted" ||
			ev.Params["previous_fingerprint"] != "reset_pending" || ev.Params["adopted_fingerprint"] != ssh.FingerprintSHA256(x) ||
			ev.Actor.UserID != 1 || ev.Actor.Username != "super" || ev.CorrelationID != details["correlation_id"] {
			t.Fatalf("告警事件不符: %+v", ev)
		}
		// 之後以 X 撥號相符、不寫不符審計；以 Y 撥號產生不符審計與 host_key_mismatch 告警
		before := e.count(t, &model.AuditLog{}, "action = ?", string(model.ActionHostKeyMismatch))
		if err := e.dial(t, a, x); err != nil {
			t.Fatal(err)
		}
		if n := e.count(t, &model.AuditLog{}, "action = ?", string(model.ActionHostKeyMismatch)); n != before {
			t.Fatal("採用後以 X 撥號不得寫不符審計")
		}
		if err := e.dial(t, a, hkKey(t)); err != nil {
			t.Fatal(err)
		}
		if n := e.count(t, &model.AuditLog{}, "action = ?", string(model.ActionHostKeyMismatch)); n != before+1 {
			t.Fatal("以 Y 撥號應寫不符審計")
		}
		if last := e.alerts.events[len(e.alerts.events)-1]; last.Type != port.SystemAlertHostKeyMismatch {
			t.Fatalf("以 Y 撥號應產生 host_key_mismatch 告警: %+v", last)
		}
		// 其他資產與已刪除資產留下的同位址記錄不變
		var others []model.AssetHostKey
		e.db.Where("asset_id <> ?", a.ID).Order("asset_id").Find(&others)
		if len(others) != 2 || others[0].Fingerprint != "SHA256:other" || others[1].Fingerprint != "SHA256:deleted" {
			t.Fatalf("其他資產的同位址記錄不得被改寫: %+v", others)
		}
		_ = recorded
	})

	t.Run("採用不在觀察中的指紋回 404 且狀態不變", func(t *testing.T) {
		e, a, _, _ := seed(t)
		before := snapshot(t, e)
		code, body := e.do(super, "POST", fmt.Sprintf("/assets/%d/host-key/adopt", a.ID), `{"fingerprint":"SHA256:never-observed"}`)
		if code != http.StatusNotFound || body["code"] != "NOTFOUND_HOST_KEY_OBSERVATION" {
			t.Fatalf("應 404 NOTFOUND_HOST_KEY_OBSERVATION，實得 %d %v", code, body)
		}
		if after := snapshot(t, e); after != before {
			t.Fatalf("狀態不得改變\n%s\n%s", before, after)
		}
		if code, body := e.do(super, "POST", fmt.Sprintf("/assets/%d/host-key/adopt", a.ID), `{}`); code != http.StatusBadRequest {
			t.Fatalf("缺指紋應 400: %d %v", code, body)
		}
	})

	t.Run("持 asset:update 的非超管被拒且狀態不變", func(t *testing.T) {
		e, a, _, x := seed(t)
		before := snapshot(t, e)
		custom := authz.NewPrincipal(1, authz.TokenFacts{}, []authz.Assignment{{
			RoleName: "asset-editor", Via: authz.ViaDirect, Scope: model.ScopeKindGlobal,
			Permissions: []authz.Permission{authz.PermAssetUpdate, authz.PermAssetView}, Custom: true,
		}})
		code, body := e.do(custom, "POST", fmt.Sprintf("/assets/%d/host-key/adopt", a.ID), adoptBody(x))
		if code != http.StatusForbidden || body["code"] != "AUTH_PERMISSION_DENIED" || len(body) != 2 {
			t.Fatalf("非超管應 403 能力拒絕單一形狀，實得 %d %v", code, body)
		}
		if after := snapshot(t, e); after != before {
			t.Fatal("狀態不得改變")
		}
	})

	t.Run("落地面錯誤：500 且記錄、觀察、審計、告警皆不變", func(t *testing.T) {
		for name, arrange := range map[string]func(e *hostKeyAPIEnv){
			"審計落地面回錯": func(e *hostKeyAPIEnv) { e.hostKeys.SetAuditTxSink(hkFailingTxSink{err: errors.New("audit down")}) },
			"告警落地面回錯": func(e *hostKeyAPIEnv) { e.alerts.err = errors.New("alert down") },
		} {
			t.Run(name, func(t *testing.T) {
				e, a, _, x := seed(t)
				before := snapshot(t, e)
				arrange(e)
				code, body := e.do(super, "POST", fmt.Sprintf("/assets/%d/host-key/adopt", a.ID), adoptBody(x))
				if code != http.StatusInternalServerError || body["code"] != "INTERNAL_HOST_KEY_ADOPT" {
					t.Fatalf("應 500 INTERNAL_HOST_KEY_ADOPT，實得 %d %v", code, body)
				}
				if after := snapshot(t, e); after != before {
					t.Fatalf("整筆應回滾\n%s\n%s", before, after)
				}
			})
		}
	})

	t.Run("重置：有記錄時發 host_key_record_changed（reset）；無可重置回 404 不發告警；告警失敗重置不生效", func(t *testing.T) {
		e, a, recorded, _ := seed(t)
		code, _ := e.do(super, "DELETE", fmt.Sprintf("/assets/%d/host-key", a.ID), "")
		if code != http.StatusOK {
			t.Fatalf("重置: %d", code)
		}
		if len(e.alerts.events) != 1 {
			t.Fatalf("重置應發 1 則告警，實有 %d", len(e.alerts.events))
		}
		ev := e.alerts.events[0]
		if ev.Type != port.SystemAlertHostKeyRecordChanged || ev.Params["change"] != "reset" ||
			ev.Params["previous_fingerprint"] != ssh.FingerprintSHA256(recorded) || ev.Params["adopted_fingerprint"] != "none" ||
			ev.Actor.UserID != 1 || ev.Actor.Username != "super" {
			t.Fatalf("重置告警不符: %+v", ev)
		}
		// 下一次連線仍照原語義重新記錄
		fresh := hkKey(t)
		if err := e.dial(t, a, fresh); err != nil {
			t.Fatal(err)
		}
		var rec model.AssetHostKey
		e.db.Where("asset_id = ?", a.ID).First(&rec)
		if rec.Fingerprint != ssh.FingerprintSHA256(fresh) || rec.ResetPending {
			t.Fatalf("重置後下一次連線應重新記錄: %+v", rec)
		}
		// 無可重置：另一台從未連線且位址無記錄的資產
		none := e.asset(t, "none", "10.9.9.9")
		e.alerts.events = nil
		if code, body := e.do(super, "DELETE", fmt.Sprintf("/assets/%d/host-key", none.ID), ""); code != http.StatusNotFound {
			t.Fatalf("無可重置應 404: %d %v", code, body)
		}
		if len(e.alerts.events) != 0 {
			t.Fatal("無可重置不得發告警")
		}
		// 告警落地面錯誤：重置不生效（旗標未標記）
		e.alerts.err = errors.New("alert down")
		if code, _ := e.do(super, "DELETE", fmt.Sprintf("/assets/%d/host-key", a.ID), ""); code != http.StatusInternalServerError {
			t.Fatalf("告警失敗時重置應回 500: %d", code)
		}
		e.db.Where("asset_id = ?", a.ID).First(&rec)
		if rec.ResetPending {
			t.Fatal("告警寫不進去時重置不得生效")
		}
	})
}
