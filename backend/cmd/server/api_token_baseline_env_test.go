package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
)

// API token 的端到端夾具：沿用授權基準的完整服務圖（正式的路由註冊、解封後的第二階段服務、檔案型 sqlite、
// 每個情境之後以範本還原），在其上加 token 的所屬帳號、對照帳號與 token，再把加入的列併入範本。
//
// 對照的方法：同一條路由、同一組合法輸入，分別以「只授權部分角色的 token」與「只持有那些角色的人類帳號」
// 呼叫，比對回應狀態、回應本文與資料庫的變更（新增、刪除、修改的列）。兩個呼叫者是不同帳號，比對前把
// 各自的帳號識別、使用者名稱與電子郵件換成同一個佔位值。

// apiTokenBaselineGate 授權基準情境在 CI 的含競態偵測整包步驟延後到專用步驟執行；本檔的情境照同一約定。
func apiTokenBaselineGate(t *testing.T) {
	t.Helper()
	if os.Getenv("AUTHZ_BASELINE") == "deferred" {
		t.Skip("API token 端到端情境隨授權基準延後到專用步驟（AUTHZ_BASELINE=deferred）")
	}
}

// cmpIdentity 一個呼叫者在比對時要換成佔位值的身分。
type cmpIdentity struct {
	userID   uint
	username string
	email    string
}

// apiTokenPair 一組對照：token（所屬帳號持有 granted 與 extra）與只持有 granted 的人類帳號。
type apiTokenPair struct {
	name        string
	token       *baselineSubject
	human       *baselineSubject
	tokenSelf   cmpIdentity
	humanSelf   cmpIdentity
	tokenID     uint
	grantedRole []uint
}

// apiTokenCustomRole 以權限集合建立自訂角色（直接寫表，與正式的角色定義寫入產生的列同形）。
func (e *baselineEnv) apiTokenCustomRole(name string, perms ...authz.Permission) uint {
	r := model.Role{Name: name, DefinitionVersion: 1}
	if err := e.db.Create(&r).Error; err != nil {
		e.t.Fatalf("自訂角色 %s：%v", name, err)
	}
	for _, p := range perms {
		if err := e.db.Create(&model.RolePermission{RoleID: r.ID, PermissionKey: string(p)}).Error; err != nil {
			e.t.Fatalf("自訂角色 %s 權限 %s：%v", name, p, err)
		}
	}
	return r.ID
}

// apiTokenUser 建立本地人類帳號並直接指派角色（以角色識別）。
func (e *baselineEnv) apiTokenUser(username string, roleIDs ...uint) cmpIdentity {
	id := e.createUser(username, nil)
	for _, rid := range roleIDs {
		if err := model.AssignUserRoleWithSource(e.db, id, rid, model.RoleSourceManual, model.RoleOriginSystem); err != nil {
			e.t.Fatalf("指派角色 %d 給 %s：%v", rid, username, err)
		}
	}
	return cmpIdentity{userID: id, username: username, email: username + "@baseline.test"}
}

// apiTokenIssue 以正式的建立流程替 owner 建立只授權 roleIDs 的 token（建立者以人類工作階段的主體操作）。
func (e *baselineEnv) apiTokenIssue(owner cmpIdentity, name string, roleIDs ...uint) (plaintext string, tokenID uint) {
	svc := identity.NewAPITokenService(e.db, apiTokenGateEvents{})
	svc.SetRestoreGenerationSource(authz.RestoreGeneration)
	op := identity.Operator{UserID: owner.userID, Username: owner.username,
		Principal: authz.NewPrincipal(owner.userID, authz.TokenFacts{SubjectKind: model.KindHuman}, nil)}
	created, err := svc.Create(op, identity.CreateAPITokenInput{Name: name, RoleIDs: roleIDs, NeverExpires: true})
	if err != nil {
		e.t.Fatalf("建立 API token %s：%v", name, err)
	}
	return created.Token, created.View.ID
}

// apiTokenPairOf 建立一組對照：owner 持有 granted＋extra、token 只授權 granted；twin 只持有 granted。
func (e *baselineEnv) apiTokenPairOf(name string, granted, extra []uint) *apiTokenPair {
	owner := e.apiTokenUser("cmp-owner-"+name, append(append([]uint{}, granted...), extra...)...)
	twin := e.apiTokenUser("cmp-twin-"+name, granted...)
	plain, tokenID := e.apiTokenIssue(owner, "cmp-"+name, granted...)
	return &apiTokenPair{
		name:        name,
		token:       &baselineSubject{ID: "T-" + name, Username: owner.username, UserID: owner.userID, Token: plain, Kind: "api_token"},
		human:       &baselineSubject{ID: "H-" + name, Username: twin.username, UserID: twin.userID, Token: e.issueSessionToken(twin.userID), Kind: "session"},
		tokenSelf:   owner,
		humanSelf:   twin,
		tokenID:     tokenID,
		grantedRole: granted,
	}
}

// apiTokenRetemplate 把範本建立之後寫入的表併入範本：之後每個情境都從含這些列的狀態開始，並還原回這個狀態。
func (e *baselineEnv) apiTokenRetemplate() {
	if err := e.db.Exec(`UPDATE authz_state SET version = version + 1 WHERE id = 1`).Error; err != nil {
		e.t.Fatalf("推進權限版本：%v", err)
	}
	for _, tbl := range e.touched() {
		e.sqlExec(fmt.Sprintf(`DELETE FROM tpl.%q`, tbl))
		e.sqlExec(fmt.Sprintf(`INSERT INTO tpl.%q SELECT * FROM main.%q`, tbl, tbl))
	}
	if e.hasSequence() {
		e.sqlExec(`DELETE FROM tpl.sqlite_sequence`)
		e.sqlExec(`INSERT INTO tpl.sqlite_sequence SELECT * FROM main.sqlite_sequence`)
	}
	e.sqlExec(`DELETE FROM ` + baselineTouchedTable)
}

// cmpRecord 一次呼叫可比對的結果。
type cmpRecord struct {
	Status int                       `json:"status"`
	Body   any                       `json:"body,omitempty"`
	DB     map[string]map[string]any `json:"db,omitempty"`
	Alerts []map[string]any          `json:"alerts,omitempty"`
	FS     map[string]string         `json:"fs,omitempty"`
	Remote []string                  `json:"remote,omitempty"`
	// Audit 只記筆數：稽核列帶有經由哪把 token 的標示，兩邊本來就不同
	Audit int `json:"audit"`
}

// cmpTelemetryColumns 比對時不看的欄位：token 的最近使用時間與來源只在 token 呼叫時更新（遙測，不是請求的副作用）。
// 只排除這些欄位；同一列其他欄位的變動（例如撤銷狀態）照常比對。
var cmpTelemetryColumns = map[string]map[string]bool{"api_tokens": {"last_used_at": true, "last_used_ip": true}}

// cmpDropTelemetry 從差異中移除遙測欄位的修改；一列只剩遙測欄位變動時整列不算修改，表沒有其他差異時整表移除。
func cmpDropTelemetry(diff map[string]*rowDiff) {
	for tbl, cols := range cmpTelemetryColumns {
		d, ok := diff[tbl]
		if !ok {
			continue
		}
		kept := d.Modified[:0]
		for _, mod := range d.Modified {
			for col := range cols {
				delete(mod, col)
			}
			if _, hasRowID := mod["@rowid"]; len(mod) > 1 || !hasRowID && len(mod) > 0 {
				kept = append(kept, mod)
			}
		}
		d.Modified = kept
		if len(d.Added) == 0 && len(d.Removed) == 0 && len(d.Modified) == 0 {
			delete(diff, tbl)
		}
	}
}

// cmpActorKeys 值為呼叫者帳號識別時換成佔位值的鍵（建立者、操作者、申請者等）。
var cmpActorKeys = map[string]bool{
	"user_id": true, "created_by": true, "updated_by": true, "granted_by": true, "revoked_by": true,
	"actor_id": true, "operator_id": true, "requester_id": true, "creator_id": true, "assigned_by": true,
	"reviewed_by": true, "confirmed_by": true, "initiator_id": true, "actor_user_id": true, "owner_user_id": true,
	"changed_by": true, "decided_by": true, "acknowledged_by": true, "pinned_by": true, "set_by": true,
}

// cmpRun 以 subj 送出一次請求，收集結果並把資料庫、檔案與行程內狀態還原回範本。
//
// peer 是對照的另一方：清單類回應同時列出兩個呼叫者的帳號，各自換成佔位值後會不對稱，
// 故先把提到任一方使用者名稱的清單元素移除，再比對其餘內容。
func (e *baselineEnv) cmpRun(subj *baselineSubject, br baselineRequest, self, peer cmpIdentity) cmpRecord {
	e.recv.take()
	req := httptest.NewRequest(br.Method, br.Path, bytes.NewReader(br.Body))
	if br.ContentType != "" {
		req.Header.Set("Content-Type", br.ContentType)
	}
	if br.WS {
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("Sec-WebSocket-Version", "13")
		req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	}
	for k, v := range br.Headers {
		req.Header.Set(k, v)
	}
	subj.authorize(req)
	w := e.serve(req)
	if br.Settle > 0 {
		time.Sleep(br.Settle)
	}
	awaitBackground(e.t)
	rec := cmpRecord{Status: w.Code}
	var parsed any
	if raw := w.Body.Bytes(); len(raw) > 0 {
		if json.Unmarshal(raw, &parsed) == nil {
			parsed = cmpDropCallers(parsed, self.username, peer.username)
			rec.Body = cmpSelfNormalize("", normalizeValue("", parsed), self)
		} else {
			rec.Body = map[string]any{"non_json": true, "len": len(raw)}
		}
	}
	touched := e.touched()
	diff := e.diffTables(touched)
	cmpDropTelemetry(diff)
	var split baselineRecord
	e.splitDiff(&split, diff)
	rec.Audit = len(split.Audit)
	if split.DB != nil {
		rec.DB = map[string]map[string]any{}
		for tbl, entry := range split.DB {
			rec.DB[tbl] = cmpSelfNormalize("", entry, self).(map[string]any)
		}
	}
	for _, a := range split.Alerts {
		rec.Alerts = append(rec.Alerts, cmpSelfNormalize("", a, self).(map[string]any))
	}
	rec.FS = e.fsDiff()
	rec.Remote = remoteList(e.recv.take())
	e.resetTables(touched)
	if rec.FS != nil {
		e.resetFS()
	}
	e.resetInProcess(touched)
	return rec
}

// cmpDropCallers 移除陣列中任一字串值含有 names 之一的物件元素（遞迴）。
func cmpDropCallers(v any, names ...string) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			out[k] = cmpDropCallers(val, names...)
		}
		return out
	case []any:
		out := make([]any, 0, len(x))
		for _, val := range x {
			if m, ok := val.(map[string]any); ok && cmpMentions(m, names) {
				continue
			}
			out = append(out, cmpDropCallers(val, names...))
		}
		return out
	default:
		return v
	}
}

// cmpMentions 物件（含巢狀）是否有字串值含有 names 之一。
func cmpMentions(v any, names []string) bool {
	switch x := v.(type) {
	case map[string]any:
		for _, val := range x {
			if cmpMentions(val, names) {
				return true
			}
		}
	case []any:
		for _, val := range x {
			if cmpMentions(val, names) {
				return true
			}
		}
	case string:
		for _, n := range names {
			if n != "" && strings.Contains(x, n) {
				return true
			}
		}
	}
	return false
}

// cmpSelfNormalize 把呼叫者的帳號識別、使用者名稱與電子郵件換成佔位值。
func cmpSelfNormalize(key string, v any, self cmpIdentity) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			out[k] = cmpSelfNormalize(k, val, self)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, val := range x {
			out[i] = cmpSelfNormalize(key, val, self)
		}
		return out
	case []map[string]any:
		out := make([]any, len(x))
		for i, val := range x {
			out[i] = cmpSelfNormalize(key, val, self)
		}
		return out
	case float64:
		if cmpActorKeys[strings.ToLower(key)] && uint(x) == self.userID {
			return "@self"
		}
		return x
	case int64:
		if cmpActorKeys[strings.ToLower(key)] && uint(x) == self.userID {
			return "@self"
		}
		return float64(x)
	case string:
		s := x
		if self.email != "" {
			s = strings.ReplaceAll(s, self.email, "@self-email")
		}
		if self.username != "" {
			s = strings.ReplaceAll(s, self.username, "@self-name")
		}
		if cmpActorKeys[strings.ToLower(key)] && s == fmt.Sprint(self.userID) {
			return "@self"
		}
		return s
	default:
		return v
	}
}

// cmpDiff 兩筆結果的差異描述；相同回空字串。
func cmpDiff(a, b cmpRecord) string {
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if bytes.Equal(ja, jb) {
		return ""
	}
	return fmt.Sprintf("\n  token: %s\n  human: %s", clipCmp(string(ja)), clipCmp(string(jb)))
}

func clipCmp(s string) string {
	if len(s) > 1500 {
		return s[:1500] + "…"
	}
	return s
}

// cmpErrorCode 回應本文的錯誤碼（沒有時回空字串）。
func cmpErrorCode(r cmpRecord) string {
	if m, ok := r.Body.(map[string]any); ok {
		if c, ok := m["code"].(string); ok {
			return c
		}
	}
	return ""
}

// apiTokenOpenRouteKeys 登錄為開放的「方法 樣板路徑」（已排序）。
func apiTokenOpenRouteKeys() []string {
	var out []string
	for _, k := range middleware.APITokenRouteRegistryKeys() {
		method, path, _ := strings.Cut(k, " ")
		if allowed, _ := middleware.APITokenRouteDecision(method, path); allowed {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// TestCmpDropTelemetryKeepsOtherTokenChanges 比對只略過 token 的遙測欄位：只有遙測變動的列被移除，
// 同一列另有撤銷狀態等欄位變動時照常留在差異中，新增或刪除的 token 列也照常比對。
func TestCmpDropTelemetryKeepsOtherTokenChanges(t *testing.T) {
	telemetryOnly := map[string]*rowDiff{"api_tokens": {Modified: []map[string][2]any{
		{"@rowid": {1, 1}, "last_used_at": {nil, "t"}, "last_used_ip": {"", "192.0.2.1"}},
	}}}
	cmpDropTelemetry(telemetryOnly)
	if _, ok := telemetryOnly["api_tokens"]; ok {
		t.Errorf("只有遙測欄位變動時不應留下差異：%v", telemetryOnly["api_tokens"])
	}

	revoked := map[string]*rowDiff{"api_tokens": {Modified: []map[string][2]any{
		{"@rowid": {1, 1}, "last_used_at": {nil, "t"}, "revoked_at": {nil, "t"}},
	}}}
	cmpDropTelemetry(revoked)
	d, ok := revoked["api_tokens"]
	if !ok || len(d.Modified) != 1 {
		t.Fatalf("撤銷狀態的變動應保留：%v", revoked)
	}
	if _, has := d.Modified[0]["revoked_at"]; !has {
		t.Errorf("撤銷欄位應保留：%v", d.Modified[0])
	}
	if _, has := d.Modified[0]["last_used_at"]; has {
		t.Errorf("遙測欄位應移除：%v", d.Modified[0])
	}

	added := map[string]*rowDiff{"api_tokens": {Added: []map[string]any{{"name": "x"}}}}
	cmpDropTelemetry(added)
	if _, ok := added["api_tokens"]; !ok {
		t.Error("新增的 token 列應保留")
	}
}
