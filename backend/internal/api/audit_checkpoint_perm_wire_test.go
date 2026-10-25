package api

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
)

// 列表 API 的 `perm` 鍵（wire 契約）：第四版的點一律帶此鍵（有附證者為八鍵物件、無附證者為
// JSON null），第三版以前的點不帶；附證欄組合建不出合法載荷的第四版點不帶（離線驗證者據此報
// 「載荷無法重建」）。快照本體與其他附證欄一律不外送。
//
// 設 CHECKPOINT_VERIFY_FIXTURE_OUT=<目錄> 時，把本測試的實際 API 回應與公鑰寫到該目錄，
// 供離線驗章工具的測試直接餵（工具不得自行補鍵）。
func TestCheckpointListPermWire(t *testing.T) {
	r, mgr, db, seal := setupCheckpointAPIEnv(t)
	if err := db.AutoMigrate(&model.UserGroup{}, &model.UserGroupMember{}, &model.UserGroupRole{}, &model.RoleBindingNode{},
		&model.AuthzState{}, &model.AssetGroup{}, &model.GroupRoleMapping{}, &model.GroupUserGroupMapping{}, &model.ExternalGroup{},
		&model.UserGroupMappingRuleSupport{}, &model.UserChannelObservation{}, &model.PermissionStateEvent{}, &model.RolePermission{},
		&model.AgentToken{}); err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("INSERT INTO authz_state (id, version) VALUES (1, 0)").Error; err != nil {
		t.Fatal(err)
	}
	// 升級前的鏈：把夾具的 genesis 改寫成第三版載荷（同一把鑰重簽）
	var g model.AuditCheckpoint
	if err := db.First(&g, "seq = 1").Error; err != nil {
		t.Fatal(err)
	}
	g.AggScheme = model.AggSchemeV3
	payload, err := audit.CheckpointSignBytes(&g)
	if err != nil {
		t.Fatal(err)
	}
	signer := lastCheckpointTestSigner
	_, g.Signature = signer.Sign(payload)
	if err := db.Exec("UPDATE audit_checkpoints SET agg_scheme = ?, signature = ? WHERE seq = 1", g.AggScheme, g.Signature).Error; err != nil {
		t.Fatal(err)
	}
	// 第四版、來源未接線：實際封出的 perm 為 null 的點
	if _, err := seal.SealNow(); err != nil {
		t.Fatal(err)
	}
	// 接上權限來源：首次啟用（起點）與下一個相符的點
	audit.SetPermissionSources(authz.PermissionStateAuthzPart, identity.PermissionStateIdentityPart)
	t.Cleanup(func() { audit.SetPermissionSources(nil, nil) })
	for i := 0; i < 2; i++ {
		if _, err := seal.SealNow(); err != nil {
			t.Fatal(err)
		}
	}
	admin := tokenFor(t, mgr, 1, "admin", model.RoleAdmin)
	w := cpReq(t, r, http.MethodGet, "/api/v1/audit-checkpoints?page_size=200", admin, "")
	if w.Code != http.StatusOK {
		t.Fatalf("狀態碼 %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Data struct {
			Items []map[string]json.RawMessage `json:"items"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Data.Items) != 4 {
		t.Fatalf("items = %d, want 4", len(resp.Data.Items))
	}
	bySeq := map[float64]map[string]json.RawMessage{}
	for _, it := range resp.Data.Items {
		var seq float64
		_ = json.Unmarshal(it["seq"], &seq)
		bySeq[seq] = it
		for k := range it {
			if strings.HasPrefix(k, "perm_") {
				t.Errorf("seq=%v 外送了附證欄 %s（只能經 perm 物件）", seq, k)
			}
		}
	}
	if _, ok := bySeq[1]["perm"]; ok {
		t.Error("第三版的點不得帶 perm 鍵")
	}
	if raw, ok := bySeq[2]["perm"]; !ok || string(raw) != "null" {
		t.Errorf("第四版無附證的點應明寫 perm:null，got %q（present=%v）", raw, ok)
	}
	for _, seq := range []float64{3, 4} {
		raw, ok := bySeq[seq]["perm"]
		if !ok {
			t.Fatalf("seq=%v 第四版帶附證的點缺 perm 鍵", seq)
		}
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(raw, &obj); err != nil || len(obj) != 8 {
			t.Fatalf("seq=%v perm 應為八鍵物件：%s", seq, raw)
		}
		var cp model.AuditCheckpoint
		if err := db.First(&cp, "seq = ?", seq).Error; err != nil {
			t.Fatal(err)
		}
		signed, err := audit.CheckpointSignBytes(&cp)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(string(signed), `"perm":`+string(raw)+`}`) {
			t.Errorf("seq=%v 外送的 perm 與簽章載荷內的不同\n wire: %s\n signed: %s", seq, raw, signed)
		}
	}
	if !strings.Contains(string(bySeq[3]["perm"]), `"origin":true`) || !strings.Contains(string(bySeq[4]["perm"]), `"reconciled":true`) {
		t.Errorf("起點與相符點的旗標未如實外送：%s / %s", bySeq[3]["perm"], bySeq[4]["perm"])
	}

	if dir := os.Getenv("CHECKPOINT_VERIFY_FIXTURE_OUT"); dir != "" {
		if err := os.WriteFile(dir+"/api-list-v3-v4.json", w.Body.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		pk := cpReq(t, r, http.MethodGet, "/api/v1/audit-checkpoints/public-key", admin, "")
		if err := os.WriteFile(dir+"/api-public-key.json", pk.Body.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// 部分清空的第四版點：不帶 perm 鍵
	if err := db.Exec("UPDATE audit_checkpoints SET perm_origin = NULL WHERE seq = 4").Error; err != nil {
		t.Fatal(err)
	}
	w = cpReq(t, r, http.MethodGet, "/api/v1/audit-checkpoints?page_size=200", admin, "")
	var again struct {
		Data struct {
			Items []map[string]json.RawMessage `json:"items"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &again); err != nil {
		t.Fatal(err)
	}
	for _, it := range again.Data.Items {
		if string(it["seq"]) == "4" {
			if _, ok := it["perm"]; ok {
				t.Error("附證欄建不出合法載荷的第四版點不得帶 perm 鍵")
			}
		}
	}
}
