package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// 主線資源的寫入回應與讀取一致（端到端，正式的路由註冊與完整服務圖）。兩層：
//
//  1. 必要輸出鍵：每一支寫入端點列出回應必須帶的鍵，缺鍵即失敗（含節點的路徑、群組的四個成員欄位、
//     資產的待配憑證欄位）。
//  2. 同名欄位的值：寫入後立即以同一主體讀取對應的讀取端點，兩邊都有的鍵值必須相同；只出現在一方的鍵
//     必須列在該端點的窄清單，指明哪一邊沒有並附理由，否則同樣失敗。窄清單只豁免「指明的那一邊確實
//     沒有這個鍵」：那一邊帶了這個鍵就照常比值，另一邊缺鍵同樣失敗。
//
// 比對規則：空集合的表示法（缺鍵、null、[]）視為相同；空物件 {} 不在其中，與缺鍵、null、[] 都不同；
// null 不等同 false、0 或非空內容。時間戳與其他字串一樣逐字串比對，不先換算到同一刻度。另外兩邊出現的
// 每個時間戳都不得帶微秒以下的位數：正式資料庫只保存到微秒，寫入回應多帶的位數在隨後讀取時必然消失，
// 測試資料庫保存全部位數而看不出這個差異，所以單獨斷言。臨時授權使用固定在遠未來的有效期，兩次請求
// 之間不會跨過到期點。

// wrSide 窄清單項目指明「沒有這個鍵」的那一邊。
type wrSide int

const (
	// wrAbsentInRead 只在寫入回應：讀取回應沒有這個鍵。
	wrAbsentInRead wrSide = iota + 1
	// wrAbsentInWrite 只在讀取回應：寫入回應沒有這個鍵。
	wrAbsentInWrite
)

// wrOmit 一個窄清單項目：哪一邊沒有、為什麼。
type wrOmit struct {
	absent wrSide
	why    string
}

// wrOmission 刻意只出現在寫入回應或讀取回應其中一方的鍵。
type wrOmission map[string]wrOmit

// wrCase 一支寫入端點與它對應的讀取端點。
type wrCase struct {
	name     string
	method   string
	path     func() string
	body     func() any
	readPath func(write map[string]any) string
	required []string
	omit     wrOmission
}

func (e *baselineEnv) wrCall(subj *baselineSubject, method, path string, body any) srResult {
	e.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			e.t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	subj.authorize(req)
	w := e.serve(req)
	awaitBackground(e.t)
	return srResult{code: w.Code, body: w.Body.Bytes()}
}

// wrObject 解析回應本文。本文為 {"data": {...}, ...} 時取內層物件，並把與 data 並列的鍵（詳情端點的
// 附加投影）併入，使它們同樣受第二層比對與窄清單約束。
func wrObject(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("解析回應：%v：%s", err, raw)
	}
	d, ok := m["data"].(map[string]any)
	if !ok {
		return m
	}
	out := map[string]any{}
	for k, v := range d {
		out[k] = v
	}
	for k, v := range m {
		if k == "data" {
			continue
		}
		if _, dup := out[k]; dup {
			t.Fatalf("回應的 data 與並列鍵 %s 重名：%s", k, raw)
		}
		out[k] = v
	}
	return out
}

// wrNormalize 比對用的正規化：物件內值為空集合（null、[]）的鍵移除；陣列與物件遞迴處理。純量不改寫
// （時間戳逐字串比對；null 與 false、0、"" 仍然不同）。
func wrNormalize(v any) any {
	switch x := v.(type) {
	case []any:
		out := make([]any, len(x))
		for i, it := range x {
			out[i] = wrNormalize(it)
		}
		return out
	case map[string]any:
		out := map[string]any{}
		for k, it := range x {
			if wrEmpty(it) {
				continue
			}
			out[k] = wrNormalize(it)
		}
		return out
	default:
		return x
	}
}

// wrEmpty 空集合的三種表示：缺鍵（呼叫端以 nil 傳入）、null、空陣列。空物件不算：它與空陣列是
// 不同型別，把它當空集合會放過型別錯誤。
func wrEmpty(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case []any:
		return len(x) == 0
	}
	return false
}

// wrDiff 第二層比對：回傳不一致的描述（鍵已排序）。
func wrDiff(write, read map[string]any, omit wrOmission) []string {
	keys := map[string]bool{}
	for k := range write {
		keys[k] = true
	}
	for k := range read {
		keys[k] = true
	}
	var out []string
	for k := range keys {
		wv, wok := write[k]
		rv, rok := read[k]
		if o, ok := omit[k]; ok {
			// 只豁免指明的那一邊確實沒有這個鍵；那一邊帶了就照常比對
			if (o.absent == wrAbsentInRead && !rok) || (o.absent == wrAbsentInWrite && !wok) {
				continue
			}
		}
		if wrEmpty(wv) && wrEmpty(rv) {
			continue
		}
		switch {
		case !wok:
			out = append(out, fmt.Sprintf("%s 只在讀取回應（%s）", k, clipCmp(wrJSON(rv))))
		case !rok:
			out = append(out, fmt.Sprintf("%s 只在寫入回應（%s）", k, clipCmp(wrJSON(wv))))
		case !reflect.DeepEqual(wrNormalize(wv), wrNormalize(rv)):
			out = append(out, fmt.Sprintf("%s 值不同：寫入 %s／讀取 %s", k, clipCmp(wrJSON(wv)), clipCmp(wrJSON(rv))))
		}
	}
	sort.Strings(out)
	return out
}

// wrSubMicro 回傳 v 之中帶微秒以下位數的時間戳（路徑：值），鍵已排序。
func wrSubMicro(v any, at string) []string {
	var out []string
	switch x := v.(type) {
	case string:
		if _, err := time.Parse(time.RFC3339Nano, x); err == nil && len(x) >= 20 {
			if i := strings.IndexByte(x, '.'); i >= 0 {
				frac := x[i+1:]
				if j := strings.IndexAny(frac, "Z+-"); j >= 0 {
					frac = frac[:j]
				}
				if len(frac) > 6 {
					out = append(out, at+"："+x)
				}
			}
		}
	case []any:
		for i, it := range x {
			out = append(out, wrSubMicro(it, fmt.Sprintf("%s[%d]", at, i))...)
		}
	case map[string]any:
		for k, it := range x {
			out = append(out, wrSubMicro(it, strings.TrimPrefix(at+"."+k, "."))...)
		}
	}
	sort.Strings(out)
	return out
}

func wrJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// wrCheck 執行一支寫入並與讀取比對；回傳寫入回應（後續案例可用其識別）。
func (e *baselineEnv) wrCheck(t *testing.T, subj *baselineSubject, c wrCase) map[string]any {
	t.Helper()
	path := c.path()
	w := e.wrCall(subj, c.method, path, c.body())
	if w.code < 200 || w.code >= 300 {
		t.Fatalf("[%s] %s %s 回 %d %s", c.name, c.method, path, w.code, clipCmp(string(w.body)))
	}
	write := wrObject(t, w.body)
	for _, k := range c.required {
		if _, ok := write[k]; !ok {
			t.Errorf("[%s] 寫入回應缺必要鍵 %s：%s", c.name, k, clipCmp(string(w.body)))
		}
	}
	readPath := c.readPath(write)
	r := e.srGet(subj, readPath)
	if r.code != http.StatusOK {
		t.Fatalf("[%s] 讀取 %s 回 %d %s", c.name, readPath, r.code, clipCmp(string(r.body)))
	}
	read := wrObject(t, r.body)
	for side, m := range map[string]map[string]any{"寫入回應": write, "讀取回應": read} {
		if bad := wrSubMicro(m, ""); len(bad) > 0 {
			t.Errorf("[%s] %s的時間戳帶微秒以下的位數（正式資料庫存不下，隨後讀取必然不同）：\n  %s", c.name, side, strings.Join(bad, "\n  "))
		}
	}
	if d := wrDiff(write, read, c.omit); len(d) > 0 {
		t.Errorf("[%s] %s %s 的回應與隨後讀取 %s 不一致：\n  %s", c.name, c.method, path, readPath, strings.Join(d, "\n  "))
	}
	return write
}

func wrID(m map[string]any) uint {
	v, _ := m["id"].(float64)
	return uint(v)
}

// 刻意只出現在一方的鍵（窄清單）。
var (
	wrOmitTimestampsWriteOnly = wrOmission{
		"created_at": {wrAbsentInRead, "節點的讀取回應（與列表元素同形）不帶建立與更新時間；寫入回應是寫入後的節點列"},
		"updated_at": {wrAbsentInRead, "同上"},
	}
	wrOmitWinrmCACert = wrOmission{
		"winrm_ca_cert": {wrAbsentInWrite, "寫入回應與列表一樣只帶 has_winrm_ca_cert，不回 CA 憑證本體；單筆讀取回本體供編輯表單回填"},
	}
	wrOmitUserDetailProjections = wrOmission{
		"role_sets":     {wrAbsentInWrite, "使用者詳情的附加投影：有效角色拆成管理者指派集與映射集，只在單筆讀取"},
		"account_ops":   {wrAbsentInWrite, "使用者詳情的附加投影：對目前操作者的保護身分分類，只在單筆讀取"},
		"approver_only": {wrAbsentInWrite, "使用者詳情的附加投影：僅審批者標記，只在單筆讀取"},
	}
	wrOmitCredentialAggregateState = wrOmission{
		"aggregate_state": {wrAbsentInWrite, "憑證詳情在資源物件之外並列的輪替進度補充資訊（執行期狀態，取不到時整個鍵不出現）；寫入回應是憑證物件本身，不帶進度"},
	}
)

// wrTestCAPEM 一張可解析的自簽 CA 憑證（PEM），供 WinRM ca 模式的寫入案例使用。
func wrTestCAPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "write-response-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestWriteResponseMatchesRead(t *testing.T) {
	apiTokenBaselineGate(t)
	e := newBaselineEnv(t)
	admin := e.subjects["S01"]
	ag1 := e.object("assetGroup.1").(uint)
	ag2 := e.object("assetGroup.2").(uint)
	sshAsset := e.object("asset.ssh").(uint)
	ug := e.object("userGroup.1").(uint)
	s02 := e.subjects["S02"].UserID
	s05 := e.subjects["S05"].UserID
	e.apiTokenRuleRestore()

	var nodeID, assetID, winrmID, accountID, userID, groupID, authzID, tempAuthzID, credID uint
	caPEM := wrTestCAPEM(t)
	future := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	cases := []func() wrCase{
		// ── 節點 ──
		func() wrCase {
			return wrCase{name: "node create", method: http.MethodPost, path: func() string { return "/api/v1/asset-groups" },
				body: func() any {
					return map[string]any{"name": "wr-node", "description": "write response", "parent_id": ag1}
				},
				readPath: func(w map[string]any) string { nodeID = wrID(w); return fmt.Sprintf("/api/v1/asset-groups/%d", nodeID) },
				required: []string{"id", "name", "description", "parent_id", "path"}, omit: wrOmitTimestampsWriteOnly}
		},
		func() wrCase {
			return wrCase{name: "node update", method: http.MethodPut, path: func() string { return fmt.Sprintf("/api/v1/asset-groups/%d", nodeID) },
				body:     func() any { return map[string]any{"name": "wr-node-renamed", "description": "renamed"} },
				readPath: func(map[string]any) string { return fmt.Sprintf("/api/v1/asset-groups/%d", nodeID) },
				required: []string{"id", "name", "description", "parent_id", "path"}, omit: wrOmitTimestampsWriteOnly}
		},
		func() wrCase {
			return wrCase{name: "node move", method: http.MethodPut, path: func() string { return fmt.Sprintf("/api/v1/asset-groups/%d/move", nodeID) },
				body:     func() any { return map[string]any{"parent_id": ag2} },
				readPath: func(map[string]any) string { return fmt.Sprintf("/api/v1/asset-groups/%d", nodeID) },
				required: []string{"id", "name", "parent_id", "path"}, omit: wrOmitTimestampsWriteOnly}
		},
		// ── 資產 ──
		func() wrCase {
			return wrCase{name: "asset create", method: http.MethodPost, path: func() string { return "/api/v1/assets" },
				body: func() any {
					return map[string]any{"name": "wr-asset", "protocol": "ssh", "host": "198.51.100.50", "port": 22,
						"username": "wr-root", "password": "Wr-Fixture-Pass-1", "node_ids": []uint{ag1, nodeID}, "tags": "wr-tag"}
				},
				readPath: func(w map[string]any) string { assetID = wrID(w); return fmt.Sprintf("/api/v1/assets/%d", assetID) },
				required: []string{"id", "name", "protocol", "host", "port", "active", "node_ids", "credential_pending"}}
		},
		func() wrCase {
			return wrCase{name: "asset update (clear nodes)", method: http.MethodPut, path: func() string { return fmt.Sprintf("/api/v1/assets/%d", assetID) },
				body:     func() any { return map[string]any{"description": "nodes cleared", "node_ids": []uint{}} },
				readPath: func(map[string]any) string { return fmt.Sprintf("/api/v1/assets/%d", assetID) },
				required: []string{"id", "name", "port", "active", "credential_pending"}}
		},
		func() wrCase {
			return wrCase{name: "asset update (nodes and port)", method: http.MethodPut, path: func() string { return fmt.Sprintf("/api/v1/assets/%d", assetID) },
				body:     func() any { return map[string]any{"node_ids": []uint{ag2}, "port": 2222, "active": false} },
				readPath: func(map[string]any) string { return fmt.Sprintf("/api/v1/assets/%d", assetID) },
				required: []string{"id", "port", "active", "node_ids", "credential_pending"}}
		},
		func() wrCase {
			return wrCase{name: "asset create (WinRM https with CA)", method: http.MethodPost, path: func() string { return "/api/v1/assets" },
				body: func() any {
					return map[string]any{"name": "wr-winrm", "protocol": "rdp", "host": "198.51.100.51", "port": 3389,
						"username": "wr-admin", "password": "Wr-Fixture-Pass-6", "node_ids": []uint{ag1},
						"rotation_channel": "windows_winrm", "winrm_scheme": "https", "winrm_tls_mode": "ca", "winrm_ca_cert": caPEM}
				},
				readPath: func(w map[string]any) string { winrmID = wrID(w); return fmt.Sprintf("/api/v1/assets/%d", winrmID) },
				required: []string{"id", "rotation_channel", "winrm_scheme", "winrm_tls_mode", "has_winrm_ca_cert", "credential_pending"},
				omit:     wrOmitWinrmCACert}
		},
		func() wrCase {
			return wrCase{name: "asset update (WinRM)", method: http.MethodPut, path: func() string { return fmt.Sprintf("/api/v1/assets/%d", winrmID) },
				body:     func() any { return map[string]any{"winrm_port": 5986, "description": "winrm port set"} },
				readPath: func(map[string]any) string { return fmt.Sprintf("/api/v1/assets/%d", winrmID) },
				required: []string{"id", "winrm_port", "has_winrm_ca_cert", "credential_pending"},
				omit:     wrOmitWinrmCACert}
		},
		// ── 資產帳號 ──
		func() wrCase {
			return wrCase{name: "account create", method: http.MethodPost, path: func() string { return fmt.Sprintf("/api/v1/assets/%d/accounts", sshAsset) },
				body: func() any {
					return map[string]any{"username": "wr-account", "password": "Wr-Fixture-Pass-2", "privileged": true, "note": "write response"}
				},
				readPath: func(w map[string]any) string {
					accountID = wrID(w)
					return fmt.Sprintf("/api/v1/assets/%d/accounts/%d", sshAsset, accountID)
				},
				required: []string{"id", "asset_id", "username", "is_default", "privileged"}}
		},
		func() wrCase {
			return wrCase{name: "account update", method: http.MethodPut, path: func() string { return fmt.Sprintf("/api/v1/assets/%d/accounts/%d", sshAsset, accountID) },
				body: func() any {
					return map[string]any{"privileged": false, "note": "updated", "password": "Wr-Fixture-Pass-3"}
				},
				readPath: func(map[string]any) string { return fmt.Sprintf("/api/v1/assets/%d/accounts/%d", sshAsset, accountID) },
				required: []string{"id", "asset_id", "username", "privileged"}}
		},
		// ── 使用者 ──
		func() wrCase {
			return wrCase{name: "user create", method: http.MethodPost, path: func() string { return "/api/v1/users" },
				body: func() any {
					return map[string]any{"username": "wr-user", "password": "Wr-Fixture-Pass-4!", "email": "wr-user@example.test",
						"full_name": "Write Response", "roles": []string{"user"}}
				},
				readPath: func(w map[string]any) string { userID = wrID(w); return fmt.Sprintf("/api/v1/users/%d", userID) },
				required: []string{"id", "username", "email"}, omit: wrOmitUserDetailProjections}
		},
		func() wrCase {
			return wrCase{name: "user update", method: http.MethodPut, path: func() string { return fmt.Sprintf("/api/v1/users/%d", userID) },
				body: func() any {
					return map[string]any{"email": "wr-user2@example.test", "full_name": "Write Response 2", "allowed_cidrs": []string{"203.0.113.0/24"}}
				},
				readPath: func(map[string]any) string { return fmt.Sprintf("/api/v1/users/%d", userID) },
				required: []string{"id", "username", "email"}, omit: wrOmitUserDetailProjections}
		},
		// ── 使用者群組與成員 ──
		func() wrCase {
			return wrCase{name: "user group create", method: http.MethodPost, path: func() string { return "/api/v1/user-groups" },
				body: func() any { return map[string]any{"name": "wr-group", "description": "write response"} },
				readPath: func(w map[string]any) string {
					groupID = wrID(w)
					return fmt.Sprintf("/api/v1/user-groups/%d", groupID)
				},
				required: []string{"id", "name", "user_ids", "manual_user_ids", "mapped_user_ids", "member_sources"}}
		},
		func() wrCase {
			return wrCase{name: "user group members", method: http.MethodPut, path: func() string { return fmt.Sprintf("/api/v1/user-groups/%d/members", groupID) },
				body:     func() any { return map[string]any{"manual_user_ids": []uint{s02, s05}} },
				readPath: func(map[string]any) string { return fmt.Sprintf("/api/v1/user-groups/%d", groupID) },
				required: []string{"id", "user_ids", "manual_user_ids", "mapped_user_ids", "member_sources"}}
		},
		func() wrCase {
			return wrCase{name: "user group update", method: http.MethodPut, path: func() string { return fmt.Sprintf("/api/v1/user-groups/%d", groupID) },
				body:     func() any { return map[string]any{"name": "wr-group-renamed", "description": "renamed"} },
				readPath: func(map[string]any) string { return fmt.Sprintf("/api/v1/user-groups/%d", groupID) },
				required: []string{"id", "name", "user_ids", "manual_user_ids", "mapped_user_ids", "member_sources"}}
		},
		func() wrCase {
			return wrCase{name: "user group members (existing group with mapped members)", method: http.MethodPut,
				path:     func() string { return fmt.Sprintf("/api/v1/user-groups/%d/members", ug) },
				body:     func() any { return map[string]any{"manual_user_ids": []uint{s02}} },
				readPath: func(map[string]any) string { return fmt.Sprintf("/api/v1/user-groups/%d", ug) },
				required: []string{"id", "user_ids", "manual_user_ids", "mapped_user_ids", "member_sources"}}
		},
		// ── 群組角色指派（以角色指派讀取為基準） ──
		func() wrCase {
			return wrCase{name: "user group role bindings", method: http.MethodPut, path: func() string { return fmt.Sprintf("/api/v1/user-groups/%d/role-bindings", groupID) },
				body: func() any {
					return map[string]any{"role_ids": []uint{e.apiTokenCustomRole("wr-group-role", "asset:view")}}
				},
				readPath: func(map[string]any) string { return fmt.Sprintf("/api/v1/user-groups/%d/role-bindings", groupID) }}
		},
		// ── 授權規則 ──
		func() wrCase {
			return wrCase{name: "authorization create", method: http.MethodPost, path: func() string { return "/api/v1/authorizations" },
				body: func() any {
					return map[string]any{"user_group_id": groupID, "asset_id": assetID, "permission": "connect", "accounts": []string{"wr-root"}}
				},
				readPath: func(w map[string]any) string {
					authzID = wrID(w)
					return fmt.Sprintf("/api/v1/authorizations/%d", authzID)
				},
				required: []string{"id", "permission"}}
		},
		func() wrCase {
			return wrCase{name: "authorization accounts", method: http.MethodPut, path: func() string { return fmt.Sprintf("/api/v1/authorizations/%d/accounts", authzID) },
				body:     func() any { return map[string]any{"accounts": []string{"@ALL"}} },
				readPath: func(map[string]any) string { return fmt.Sprintf("/api/v1/authorizations/%d", authzID) },
				required: []string{"id"}}
		},
		func() wrCase {
			return wrCase{name: "authorization create (temporary, fixed future window)", method: http.MethodPost, path: func() string { return "/api/v1/authorizations" },
				body: func() any {
					return map[string]any{"user_id": s05, "asset_id": sshAsset, "permission": "connect",
						"date_start": future.Format(time.RFC3339), "date_expired": future.AddDate(0, 1, 0).Format(time.RFC3339)}
				},
				readPath: func(w map[string]any) string {
					tempAuthzID = wrID(w)
					return fmt.Sprintf("/api/v1/authorizations/%d", tempAuthzID)
				},
				required: []string{"id", "permission"}}
		},
		// ── 共用憑證 ──
		func() wrCase {
			return wrCase{name: "credential create", method: http.MethodPost, path: func() string { return "/api/v1/credentials" },
				body: func() any {
					return map[string]any{"name": "wr-credential", "username": "wr-cred-user", "protocol_family": "ssh",
						"password": "Wr-Fixture-Pass-5", "note": "write response"}
				},
				readPath: func(w map[string]any) string { credID = wrID(w); return fmt.Sprintf("/api/v1/credentials/%d", credID) },
				required: []string{"id", "name", "username"}, omit: wrOmitCredentialAggregateState}
		},
		func() wrCase {
			return wrCase{name: "credential update", method: http.MethodPut, path: func() string { return fmt.Sprintf("/api/v1/credentials/%d", credID) },
				body:     func() any { return map[string]any{"name": "wr-credential-renamed", "note": "renamed"} },
				readPath: func(map[string]any) string { return fmt.Sprintf("/api/v1/credentials/%d", credID) },
				required: []string{"id", "name", "username"}, omit: wrOmitCredentialAggregateState}
		},
	}
	checked := 0
	for _, mk := range cases {
		c := mk()
		e.wrCheck(t, admin, c)
		checked++
	}
	_ = tempAuthzID
	t.Logf("寫入端點對讀取端點 %d 組逐一比對", checked)
}
