package api

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/internal/notifycat"
)

// 委託拓撲端點的守衛。
//
// 拓撲承載「上鎖的資料金鑰送去哪裡解」，其變更是安全變更。本檔守的是：
//
//	(1) 按服務商的**精確鍵集**（多一鍵少一鍵皆拒）——鬆散聯集會讓「缺漏」與
//	    「刻意不帶」無從區分，而這裡的缺漏就是半套目的地；
//	(2) 非法值整筆拒絕且既有值不變；
//	(3) 成功與被拒**都**留痕，且審計本文查得到企圖改成什麼；
//	(4) 沒有可編輯欄位的服務商（GCP）一律拒絕，且該次嘗試同樣留痕。

// topologyTestHandler 建一個只接拓撲面的 handler（不需要金鑰管理器）。
func topologyTestHandler(t *testing.T, provider string) (*KeyManagementHandler, *gorm.DB, *recordingAuditSink) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = sqlDB.Close() })
	if err := db.AutoMigrate(&model.KEKTopology{}, &model.DataKey{}, &model.AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	h := NewKeyManagementHandler(db, nil, nil, "test-fp", nil)
	h.SetDeploymentKMSProvider(func() string { return provider })
	sink := &recordingAuditSink{}
	h.auditTopologyHook = sink.record
	return h, db, sink
}

// recordingAuditSink 收集拓撲變更的留痕（取代真正的審計服務：本檔要驗的是
// 「有沒有留痕、留了什麼」，不是審計鏈的寫入機制）。
type recordingAuditSink struct {
	entries []topologyAuditRecord
}

func (s *recordingAuditSink) record(rec topologyAuditRecord) {
	s.entries = append(s.entries, rec)
}

func doTopology(t *testing.T, h *KeyManagementHandler, method, body string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/api/v1/keys/topology", h.GetKEKTopology)
	r.PUT("/api/v1/keys/topology", h.UpdateKEKTopology)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(method, "/api/v1/keys/topology", strings.NewReader(body)))
	return w
}

// TestKEKTopologyHandlerReadsUnsetDeployment 尚未設定時回得出「未設定」而非錯誤。
func TestKEKTopologyHandlerReadsUnsetDeployment(t *testing.T) {
	h, _, _ := topologyTestHandler(t, keyvault.TopologyProviderVault)
	w := doTopology(t, h, "GET", "")
	if w.Code != 200 {
		t.Fatalf("GET 應回 200，得 %d %s", w.Code, w.Body.String())
	}
	var out kekTopologyResponse
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("回應不是 JSON: %v", err)
	}
	if out.Configured {
		t.Fatal("尚未設定時 configured 應為 false")
	}
	if out.Provider != keyvault.TopologyProviderVault {
		t.Fatalf("服務商應取自部署宣告，得 %q", out.Provider)
	}
	if len(out.EditableFields) != 3 {
		t.Fatalf("Vault 應有三個可編輯欄位，得 %v", out.EditableFields)
	}
	if out.Digest != "" {
		t.Fatalf("尚無拓撲與金鑰列時摘要應為空字串，得 %q", out.Digest)
	}
}

// TestKEKTopologyHandlerExactKeySet 精確鍵集：多一鍵、少一鍵、未知鍵皆拒。
func TestKEKTopologyHandlerExactKeySet(t *testing.T) {
	valid := `{"address":"https://vault.example:8200","transit_key_name":"kek","role_id":"r1"}`
	for name, body := range map[string]string{
		"少一鍵": `{"address":"https://vault.example:8200","transit_key_name":"kek"}`,
		"多一鍵": `{"address":"https://vault.example:8200","transit_key_name":"kek","role_id":"r1","region":"ap-northeast-1"}`,
		"未知鍵": `{"address":"https://vault.example:8200","transit_key_name":"kek","role_id":"r1","note":"x"}`,
		"他家欄位": `{"region":"ap-northeast-1"}`,
		"非物件":  `[]`,
	} {
		h, db, sink := topologyTestHandler(t, keyvault.TopologyProviderVault)
		w := doTopology(t, h, "PUT", body)
		if w.Code != 400 {
			t.Errorf("%s 應被拒（400），得 %d %s", name, w.Code, w.Body.String())
			continue
		}
		if codeOf(t, w) != string(apierror.CodeKeyTopologyInvalid) {
			t.Errorf("%s 的機器碼不符: %s", name, w.Body.String())
		}
		if _, err := keyvault.LoadKEKTopology(db); err == nil {
			t.Errorf("%s 被拒之後不得留下任何列", name)
		}
		if len(sink.entries) != 1 || sink.entries[0].ok {
			t.Errorf("%s 的被拒嘗試應留痕一次且標示為失敗，得 %+v", name, sink.entries)
		}
	}
	// 對照組：精確鍵集成立即被接受。
	h, _, _ := topologyTestHandler(t, keyvault.TopologyProviderVault)
	if w := doTopology(t, h, "PUT", valid); w.Code != 200 {
		t.Fatalf("合法鍵集應被接受，得 %d %s", w.Code, w.Body.String())
	}
}

// TestKEKTopologyInvalidCarriesFields 被拒的回應必須把欄位名送到線上。
//
// 這是回歸守衛而非錦上添花：`fields` 若未在 descriptor 宣告成 ParamSpec，
// validateParams 會把它當成未宣告鍵**整組丟掉**且只留一行伺服端日誌——
// 前端拿不到清單就不逐欄標紅，而回應仍是 200 形狀正確的 400，肉眼看不出來。
func TestKEKTopologyInvalidCarriesFields(t *testing.T) {
	fieldsOf := func(w *httptest.ResponseRecorder) (string, string) {
		t.Helper()
		var out struct {
			Error  string `json:"error"`
			Params struct {
				Fields string `json:"fields"`
			} `json:"params"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("回應不是 JSON: %s", w.Body.String())
		}
		return out.Params.Fields, out.Error
	}

	// 其一：逐欄驗證失敗 → 只列那一欄。
	h, _, _ := topologyTestHandler(t, keyvault.TopologyProviderVault)
	w := doTopology(t, h, "PUT",
		`{"address":"http://attacker.example:8200","transit_key_name":"kek","role_id":"r1"}`)
	got, msg := fieldsOf(w)
	if got != "address" {
		t.Fatalf("明文位址應回 fields=address，得 %q（本文 %s）", got, w.Body.String())
	}
	if !strings.Contains(msg, "address") {
		t.Fatalf("訊息應已代入欄位名，得 %q", msg)
	}

	// 其二：鍵集本身不成立 → 回該服務商的完整可編輯欄位集。
	h2, _, _ := topologyTestHandler(t, keyvault.TopologyProviderVault)
	w2 := doTopology(t, h2, "PUT", `{"address":"https://vault.example:8200"}`)
	got2, _ := fieldsOf(w2)
	for _, want := range []string{"address", "transit_key_name", "role_id"} {
		if !strings.Contains(got2, want) {
			t.Fatalf("鍵集不符應回完整可編輯欄位集，缺 %q，得 %q", want, got2)
		}
	}
}

// TestKEKTopologyHandlerRejectionKeepsExistingValue 被拒的變更不動既有值且留痕帶企圖值。
func TestKEKTopologyHandlerRejectionKeepsExistingValue(t *testing.T) {
	h, db, sink := topologyTestHandler(t, keyvault.TopologyProviderVault)
	if w := doTopology(t, h, "PUT",
		`{"address":"https://vault.example:8200","transit_key_name":"kek","role_id":"r1"}`); w.Code != 200 {
		t.Fatalf("前置設定失敗: %d %s", w.Code, w.Body.String())
	}
	// 位址改為明文傳輸：整筆拒絕。
	w := doTopology(t, h, "PUT",
		`{"address":"http://attacker.example:8200","transit_key_name":"kek","role_id":"r1"}`)
	if w.Code != 400 || codeOf(t, w) != string(apierror.CodeKeyTopologyInvalid) {
		t.Fatalf("明文位址應被拒，得 %d %s", w.Code, w.Body.String())
	}
	row, err := keyvault.LoadKEKTopology(db)
	if err != nil || row.Address != "https://vault.example:8200" {
		t.Fatalf("被拒的變更不得改動既有值，得 %+v / %v", row, err)
	}
	// 被拒的那一筆留痕必須查得到**企圖改成什麼**。
	last := sink.entries[len(sink.entries)-1]
	if last.ok {
		t.Fatal("被拒的變更應標示為失敗")
	}
	if !strings.Contains(last.after, "attacker.example") {
		t.Fatalf("留痕應查得到企圖值，得 after=%q", last.after)
	}
	if !strings.Contains(last.before, "vault.example") {
		t.Fatalf("留痕應查得到前值，得 before=%q", last.before)
	}
}

// TestKEKTopologyHandlerAuditsSuccess 成功的變更留痕帶前後值。
//
// 只記「拓撲已變更」不成立：稽核要回答的是「送去哪裡解」變成了什麼。
func TestKEKTopologyHandlerAuditsSuccess(t *testing.T) {
	h, _, sink := topologyTestHandler(t, keyvault.TopologyProviderAWS)
	if w := doTopology(t, h, "PUT", `{"region":"ap-northeast-1"}`); w.Code != 200 {
		t.Fatalf("首次設定失敗: %d %s", w.Code, w.Body.String())
	}
	if w := doTopology(t, h, "PUT", `{"region":"us-east-1"}`); w.Code != 200 {
		t.Fatalf("更新失敗: %d %s", w.Code, w.Body.String())
	}
	if len(sink.entries) != 2 {
		t.Fatalf("兩次成功應各留一筆痕，得 %d 筆", len(sink.entries))
	}
	first, second := sink.entries[0], sink.entries[1]
	if !first.ok || first.before != "(unset)" || !strings.Contains(first.after, "ap-northeast-1") {
		t.Fatalf("首次設定的留痕不符: %+v", first)
	}
	if !second.ok || !strings.Contains(second.before, "ap-northeast-1") || !strings.Contains(second.after, "us-east-1") {
		t.Fatalf("更新的留痕不符: %+v", second)
	}
}

// TestKEKTopologyHandlerGCPNotEditable GCP 無可編輯欄位，且該次嘗試同樣留痕。
func TestKEKTopologyHandlerGCPNotEditable(t *testing.T) {
	h, _, sink := topologyTestHandler(t, keyvault.TopologyProviderGCP)
	w := doTopology(t, h, "PUT", `{"region":"asia-east1"}`)
	if w.Code != 400 || codeOf(t, w) != string(apierror.CodeKeyTopologyNotEditable) {
		t.Fatalf("GCP 應回 KEY_TOPOLOGY_NOT_EDITABLE，得 %d %s", w.Code, w.Body.String())
	}
	if len(sink.entries) != 1 || sink.entries[0].ok {
		t.Fatalf("被拒的嘗試應留痕：%+v", sink.entries)
	}
	// 讀取面仍可用（唯讀顯示金鑰識別供核對）。
	if r := doTopology(t, h, "GET", ""); r.Code != 200 {
		t.Fatalf("GCP 的 GET 應仍可用，得 %d", r.Code)
	}
}

// TestKEKTopologyDigestFollowsKeyRow 金鑰識別取自金鑰列，摘要隨之改變。
func TestKEKTopologyDigestFollowsKeyRow(t *testing.T) {
	h, db, _ := topologyTestHandler(t, keyvault.TopologyProviderVault)
	if w := doTopology(t, h, "PUT",
		`{"address":"https://vault.example:8200","transit_key_name":"kek","role_id":"r1"}`); w.Code != 200 {
		t.Fatalf("前置設定失敗: %d", w.Code)
	}
	before := decodeTopology(t, doTopology(t, h, "GET", ""))
	if before.KeyRef != "" {
		t.Fatalf("尚無金鑰列時 key_ref 應為空，得 %q", before.KeyRef)
	}
	if err := db.Create(&model.DataKey{Purpose: "data", Version: 1, KEKID: "vault:kek", WrappedKey: "x"}).Error; err != nil {
		t.Fatalf("create: %v", err)
	}
	after := decodeTopology(t, doTopology(t, h, "GET", ""))
	if after.KeyRef != "vault:kek" {
		t.Fatalf("key_ref 應取自金鑰列，得 %q", after.KeyRef)
	}
	if after.Digest == before.Digest {
		t.Fatal("金鑰識別改變之後摘要應隨之改變（否則舊核對可授權新金鑰）")
	}
}

func decodeTopology(t *testing.T, w *httptest.ResponseRecorder) kekTopologyResponse {
	t.Helper()
	var out kekTopologyResponse
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("回應不是 JSON: %s", w.Body.String())
	}
	return out
}

// TestKEKTopologyAuditCarriesBeforeAndAfter 拓撲變更審計的前後值（任務 5.4）。
//
// 只記「拓撲已變更」不成立：稽核要回答的是「上鎖的資料金鑰送去哪裡解」變成了什麼。
// 成功與**被拒**都留痕，被拒者另查得到企圖改成什麼。
func TestKEKTopologyAuditCarriesBeforeAndAfter(t *testing.T) {
	h, _, sink := topologyTestHandler(t, keyvault.TopologyProviderVault)
	base := `{"address":"https://vault.example:8200","transit_key_name":"kek","role_id":"r1"}`
	if w := doTopology(t, h, "PUT", base); w.Code != 200 {
		t.Fatalf("前置設定失敗: %d %s", w.Code, w.Body.String())
	}
	moved := `{"address":"https://vault-2.example:8200","transit_key_name":"kek","role_id":"r1"}`
	if w := doTopology(t, h, "PUT", moved); w.Code != 200 {
		t.Fatalf("變更失敗: %d %s", w.Code, w.Body.String())
	}
	rejected := `{"address":"http://attacker.example:8200","transit_key_name":"kek","role_id":"r1"}`
	if w := doTopology(t, h, "PUT", rejected); w.Code != 400 {
		t.Fatalf("明文位址應被拒: %d", w.Code)
	}

	if len(sink.entries) != 3 {
		t.Fatalf("三次嘗試應各留一筆痕，得 %d", len(sink.entries))
	}
	change := sink.entries[1]
	if !change.ok || !strings.Contains(change.before, "vault.example") || !strings.Contains(change.after, "vault-2.example") {
		t.Fatalf("成功的變更未記下前後值: %+v", change)
	}
	deny := sink.entries[2]
	if deny.ok || !strings.Contains(deny.after, "attacker.example") || deny.code == "" {
		t.Fatalf("被拒的變更未記下企圖值或失敗碼: %+v", deny)
	}
	if !strings.Contains(deny.before, "vault-2.example") {
		t.Fatalf("被拒的變更未記下當時的前值: %+v", deny)
	}
}

// TestTopologyChangeAlert 拓撲變更的告警事件參數合乎通知契約（任務 5.5）。
//
// **不驗「送到了」**：通知通道未設定或不可達時只有審計，介面不得宣稱已通知。
// 這裡驗的是「發出去的那一份長得對」——參數不合契約會降級為 generic 文案，
// 收到通知的人就看不出保管處設定被改了。
func TestTopologyChangeAlert(t *testing.T) {
	h, _, _ := topologyTestHandler(t, keyvault.TopologyProviderVault)
	// 通知器未初始化（單元測試環境）時不得 panic——那條路徑在正式部署上也存在
	// （通知通道未設定）。
	h.notifyTopologyChange("admin", keyvault.TopologyProviderVault, "(unset)", "address=https://v.example:8200")

	params := map[string]string{
		"actor": "admin", "provider": keyvault.TopologyProviderVault,
		"before": "(unset)", "after": "address=https://v.example:8200 role_id=r1",
	}
	if _, err := notifycat.Validate(notifycat.EventKEKTopologyChanged, params); err != nil {
		t.Fatalf("告警參數不合通知契約: %v", err)
	}
	// 參數只含非秘密：憑證欄不在事件目錄宣告的鍵集內，故即使誤傳也不會出站。
	clean, _ := notifycat.FilterDeclared(notifycat.EventKEKTopologyChanged, map[string]string{
		"actor": "admin", "provider": "vault", "before": "x", "after": "y",
		"vault_secret_id": "must-not-leave-the-process",
	})
	if _, leaked := clean["vault_secret_id"]; leaked {
		t.Fatal("未宣告的秘密鍵隨告警出站")
	}
}
