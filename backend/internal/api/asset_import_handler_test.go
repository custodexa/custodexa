package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 資產批次新增的接入層測試：一律經 handler 進入（預檢與寫入端點），
// 服務層用真實的 AssetService 與 sqlite，斷言落在回應形狀與資料庫事實上。

// importTestEnv 匯入端點的測試環境：沿用憑證庫 API 的 fixture（兩台各帶專用憑證的
// 資產＋一筆 ssh 族共用憑證），再掛上資產 handler 的兩個匯入端點與列表
type importTestEnv struct {
	f       *credentialAPIFixture
	router  *gin.Engine
	details map[string]string // 最近一次請求 handler 補的 audit_details
}

func setupImportEnv(t *testing.T) *importTestEnv {
	t.Helper()
	f := setupCredentialAPIEnv(t)
	gin.SetMode(gin.TestMode)
	h := NewAssetHandler(f.assetSvc, authz.NewAssetAuthorizationService(f.db), nil)
	env := &importTestEnv{f: f}
	r := gin.New()
	// 以已驗證的 admin 身分進入（認證與權限閘由路由守衛另行釘住）；
	// 請求結束後讀 handler 補的 audit_details（審計中介層據此寫整批請求列）
	r.Use(func(c *gin.Context) {
		c.Set("userID", uint(1))
		c.Set("username", "admin")
		c.Set("role", c.GetHeader("X-Test-Role"))
		c.Next()
		env.details = nil
		if v, ok := c.Get("audit_details"); ok {
			env.details, _ = v.(map[string]string)
		}
	})
	r.POST("/assets/import/preview", h.PreviewImport)
	r.POST("/assets/import", h.Import)
	r.GET("/assets", h.List)
	env.router = r
	return env
}

func (e *importTestEnv) do(t *testing.T, method, path, contentType string, body []byte, role string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if role == "" {
		role = model.RoleAdmin
	}
	req.Header.Set("X-Test-Role", role)
	w := httptest.NewRecorder()
	e.router.ServeHTTP(w, req)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func (e *importTestEnv) assetCount(t *testing.T) int64 {
	t.Helper()
	var n int64
	require.NoError(t, e.f.db.Model(&model.Asset{}).Count(&n).Error)
	return n
}

// errorSet 一列的錯誤集合（field:code，排序後比對）
func errorSet(row map[string]any) []string {
	var out []string
	for _, e := range row["errors"].([]any) {
		m := e.(map[string]any)
		out = append(out, fmt.Sprintf("%s:%s", m["field"], m["code"]))
	}
	sort.Strings(out)
	return out
}

func sorted(v ...string) []string {
	sort.Strings(v)
	if v == nil {
		return []string{}
	}
	return v
}

// TestImportPreviewReportsEveryRowFieldError 擋「錯誤指錯列或漏報，使用者修了一輪還有下一輪」，
// 以及「專用憑證被第二台資產掛上」「windows 族憑證掛到 linux 主機」「使用者以為設了 TLS 實際沒生效」
func TestImportPreviewReportsEveryRowFieldError(t *testing.T) {
	env := setupImportEnv(t)
	db, creds := env.f.db, env.f.creds

	// 憑證：專用（fixture 第一台資產的預設掛載）、windows 族共用、改密中、上一輪未收斂
	var dedicated model.AssetAccount
	require.NoError(t, db.Where("asset_id = ?", env.f.assetIDs[1]).First(&dedicated).Error)
	mkShared := func(name, family string) uint {
		c, err := creds.Create(credAdminCtx(), &asset.CreateCredentialRequest{
			Name: name, Username: "u-" + name, ProtocolFamily: family, Password: "pw-" + name})
		require.NoError(t, err)
		return c.ID
	}
	windowsID := mkShared("win-admin", model.ProtocolFamilyWindows)
	rotatingID := mkShared("rotating", model.ProtocolFamilySSH)
	outOfSyncID := mkShared("out-of-sync", model.ProtocolFamilySSH)
	require.NoError(t, db.Model(&model.Credential{}).Where("id = ?", rotatingID).
		Update("active_rotation_id", 99).Error)
	require.NoError(t, db.Model(&model.Credential{}).Where("id = ?", outOfSyncID).
		Update("pending_version_id", 99).Error)

	// 節點：一條唯一路徑「總部 / 機房A」，一條不唯一路徑「同名」（直接寫庫造兩個同名根節點）
	hq := model.AssetGroup{Name: "總部"}
	require.NoError(t, db.Create(&hq).Error)
	roomA := model.AssetGroup{Name: "機房A", ParentID: &hq.ID}
	require.NoError(t, db.Create(&roomA).Error)
	require.NoError(t, db.Create(&model.AssetGroup{Name: "同名"}).Error)
	require.NoError(t, db.Create(&model.AssetGroup{Name: "同名"}).Error)

	csv := strings.Join([]string{
		"name,protocol,host,port,credential_id,tags,nodes,description,access_policy,db_name,k8s_namespace,rdp_security,db_tls_mode",
		",ssh,10.0.0.2,,,,,,,,,,",                                                 // 第 2 列：必填
		"multi-err,ssh,10.0.0.3,70000,9999,,,,,appdb,,,",                          // 第 3 列：同列三錯
		"dup,ssh,10.0.0.4,,,,,,,,,,",                                              // 第 4 列：同批重名
		"dup,ssh,10.0.0.5,,,,,,,,,,",                                              // 第 5 列：同批重名
		"alpha,ssh,10.0.0.6,,,,,,,,,,",                                            // 第 6 列：與既有資產重名
		"bad-proto,telnet,10.0.0.7,,,,,,,,,,",                                     // 第 7 列：協定
		"bad-cid,ssh,10.0.0.8,,abc,,,,,,,,",                                       // 第 8 列：憑證編號格式
		fmt.Sprintf("dedicated,ssh,10.0.0.9,,%d,,,,,,,,", dedicated.CredentialID), // 第 9 列
		fmt.Sprintf("family,ssh,10.0.0.10,,#%d,,,,,,,,", windowsID),               // 第 10 列
		fmt.Sprintf("rotating,ssh,10.0.0.11,,%d,,,,,,,,", rotatingID),             // 第 11 列
		fmt.Sprintf("out-of-sync,ssh,10.0.0.12,,%d,,,,,,,,", outOfSyncID),         // 第 12 列
		"rdpsec-on-ssh,ssh,10.0.0.13,,,,,,,,,nla,",                                // 第 13 列：不適用
		"tls-upper,mysql,10.0.0.14,,,,,,,,,,VERIFY-CA",                            // 第 14 列：列舉大小寫
		"pg-verify,postgres,10.0.0.15,,,,,,,,,,verify-ca",                         // 第 15 列：通過
		"tags-a,ssh,10.0.0.16,,,Dba,,,,,,,",                                       // 第 16 列：通過
		`tags-b,ssh,10.0.0.17,,,"DBA,web",,,,,,,`,                                 // 第 17 列：通過，歸一
		"path-missing,ssh,10.0.0.18,,,,不存在 / 節點,,,,,,",                            // 第 18 列：路徑查無
		"path-ambiguous,ssh,10.0.0.19,,,,同名,,,,,,",                                // 第 19 列：路徑不唯一
		"path-ok,ssh,10.0.0.20,,,,總部 / 機房A,,,,,,",                                 // 第 20 列：通過
	}, "\r\n") + "\r\n"

	before := env.assetCount(t)
	code, resp := env.do(t, http.MethodPost, "/assets/import/preview", "text/csv", []byte(csv), "")
	require.Equal(t, http.StatusOK, code, "預檢回應：%v", resp)
	require.Equal(t, before, env.assetCount(t), "預檢不得寫入任何資產")

	want := map[int][]string{
		0:  sorted("name:VALIDATION_ASSET_IMPORT_FIELD_REQUIRED"),
		1:  sorted("port:VALIDATION_ASSET_IMPORT_PORT", "credential_id:NOTFOUND_CREDENTIAL", "db_name:VALIDATION_ASSET_IMPORT_FIELD_NOT_APPLICABLE"),
		2:  sorted("name:CONFLICT_ASSET_IMPORT_NAME_IN_BATCH"),
		3:  sorted("name:CONFLICT_ASSET_IMPORT_NAME_IN_BATCH"),
		4:  sorted("name:CONFLICT_ASSET_NAME"),
		5:  sorted("protocol:VALIDATION_ASSET_PROTOCOL"),
		6:  sorted("credential_id:VALIDATION_ASSET_IMPORT_FIELD_FORMAT"),
		7:  sorted("credential_id:RULE_CREDENTIAL_DEDICATED_SINGLE_BINDING"),
		8:  sorted("credential_id:RULE_CREDENTIAL_PROTOCOL_MISMATCH"),
		9:  sorted("credential_id:RULE_CREDENTIAL_ROTATION_ACTIVE"),
		10: sorted("credential_id:RULE_CREDENTIAL_OUT_OF_SYNC"),
		11: sorted("rdp_security:VALIDATION_ASSET_IMPORT_FIELD_NOT_APPLICABLE"),
		12: sorted("db_tls_mode:VALIDATION_ASSET_DB_TLS_MODE"),
		13: sorted(),
		14: sorted(),
		15: sorted(),
		16: sorted("nodes:NOTFOUND_ASSET_IMPORT_NODE_PATH"),
		17: sorted("nodes:NOTFOUND_ASSET_IMPORT_NODE_PATH"),
		18: sorted(),
	}
	rows := resp["rows"].([]any)
	require.Len(t, rows, len(want))
	for i, raw := range rows {
		row := raw.(map[string]any)
		assert.EqualValues(t, i, row["index"], "第 %d 列 index", i)
		assert.EqualValues(t, i+2, row["line"], "第 %d 列的檔案列號須與試算表一致", i)
		got := errorSet(row)
		if got == nil {
			got = []string{}
		}
		assert.Equal(t, want[i], got, "第 %d 列（檔案第 %d 列）的錯誤集合", i, i+2)
	}

	// 同批重名互指列號
	params := func(i, j int) map[string]any {
		return rows[i].(map[string]any)["errors"].([]any)[j].(map[string]any)["params"].(map[string]any)
	}
	assert.EqualValues(t, 5, params(2, 0)["other_line"])
	assert.EqualValues(t, 4, params(3, 0)["other_line"])
	// 無法轉型的格：值為 null、原文放 raw
	badCID := rows[6].(map[string]any)
	assert.Nil(t, badCID["values"].(map[string]any)["credential_id"])
	assert.Equal(t, "abc", badCID["raw"].(map[string]any)["credential_id"])
	// 「Dba／DBA」同批歸一為第一次出現的寫法
	assert.Equal(t, "Dba", rows[14].(map[string]any)["resolved"].(map[string]any)["tags"])
	assert.Equal(t, "Dba,web", rows[15].(map[string]any)["resolved"].(map[string]any)["tags"])
	// 節點路徑解析
	pathOK := rows[18].(map[string]any)
	assert.Equal(t, []any{float64(roomA.ID)}, pathOK["values"].(map[string]any)["node_ids"])
	assert.Equal(t, []any{"總部 / 機房A"}, pathOK["resolved"].(map[string]any)["node_paths"])
	assert.Equal(t, false, resp["ok"])

	// verify-ca 不附 CA 可通過，且落庫值即 verify-ca（不被改寫或降級）
	body, _ := json.Marshal(map[string]any{"source": "form", "rows": []map[string]any{
		{"name": "pg-verify", "protocol": "postgres", "host": "10.0.0.15", "db_tls_mode": "verify-ca"}}})
	code, resp = env.do(t, http.MethodPost, "/assets/import", "application/json", body, "")
	require.Equal(t, http.StatusCreated, code, "匯入回應：%v", resp)
	var stored model.Asset
	require.NoError(t, db.Where("name = ?", "pg-verify").First(&stored).Error)
	assert.Equal(t, "verify-ca", stored.DBTLSMode)
	assert.Equal(t, 5432, stored.Port, "埠留空＝協定預設埠")
}

// TestImportCSVHeaderAndEncoding 擋「Excel 存出的檔被誤判或錯位對欄」
func TestImportCSVHeaderAndEncoding(t *testing.T) {
	env := setupImportEnv(t)
	preview := func(body []byte) (int, map[string]any) {
		return env.do(t, http.MethodPost, "/assets/import/preview", "text/csv; charset=utf-8", body, "")
	}

	// Excel「CSV UTF-8」：檔首 BOM、CRLF、表頭帶必填標記與大小寫、儲存格內換行
	excel := append([]byte("\xEF\xBB\xBF"), []byte("*Name,Protocol,*HOST,description\r\n"+
		"web-1,ssh,10.0.0.1,\"第一行\r\n第二行\"\r\n"+
		",,,\r\n"+
		"web-2,SSH,10.0.0.2,x\r\n"+
		"web-3,ssh,10.0.0.3,y\r\n")...)
	code, resp := preview(excel)
	require.Equal(t, http.StatusOK, code, "%v", resp)
	rows := resp["rows"].([]any)
	require.Len(t, rows, 3, "全空列略過")
	r0, r1, r2 := rows[0].(map[string]any), rows[1].(map[string]any), rows[2].(map[string]any)
	assert.EqualValues(t, 2, r0["line"])
	assert.EqualValues(t, 4, r1["line"], "儲存格換行不另計，全空列仍佔第 3 列")
	assert.EqualValues(t, 5, r2["line"], "儲存格換行後的第三筆資料記錄是 Excel 第 5 列")
	assert.Equal(t, "web-1", r0["values"].(map[string]any)["name"])
	assert.Contains(t, r0["values"].(map[string]any)["description"], "第二行")
	assert.Equal(t, "ssh", r1["values"].(map[string]any)["protocol"], "協定不分大小寫，存小寫")
	assert.Equal(t, true, resp["ok"])

	// 非 UTF-8（Big5 的「資產」）整份拒收
	code, resp = preview([]byte("name,protocol,host\n\xb8\xea\xb2\xa3,ssh,10.0.0.1\n"))
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Equal(t, "VALIDATION_ASSET_IMPORT_ENCODING", resp["code"])

	// 欄序打亂仍依表頭對欄
	code, resp = preview([]byte("host,protocol,name\n10.0.0.9,rdp,shuffled\n"))
	require.Equal(t, http.StatusOK, code, "%v", resp)
	v := resp["rows"].([]any)[0].(map[string]any)["values"].(map[string]any)
	assert.Equal(t, "shuffled", v["name"])
	assert.Equal(t, "rdp", v["protocol"])
	assert.Equal(t, "10.0.0.9", v["host"])

	// 重複欄、未知欄、缺必填欄：表頭錯誤，指出欄名與原因
	for _, tc := range []struct{ header, column, reason string }{
		{"name,protocol,host,Name", "name", "duplicate"},
		{"name,protocol,host,color", "color", "unknown"},
		{"name,protocol", "host", "missing"},
	} {
		code, resp = preview([]byte(tc.header + "\nx,ssh,10.0.0.1,y\n"))
		assert.Equal(t, http.StatusBadRequest, code, tc.header)
		assert.Equal(t, "VALIDATION_ASSET_IMPORT_HEADER", resp["code"], tc.header)
		assert.Equal(t, tc.column, resp["params"].(map[string]any)["column"], tc.header)
		assert.Equal(t, tc.reason, resp["reason"], tc.header)
	}
}

// TestImportRejectsSecretFields 擋「明文秘密經匯入落庫或進日誌」
func TestImportRejectsSecretFields(t *testing.T) {
	env := setupImportEnv(t)
	const secret = "S3cret-Should-Never-Persist-7f2c"
	var logBuf bytes.Buffer
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	before := env.assetCount(t)

	// CSV：表頭含秘密欄（大小寫與必填標記不影響判定）
	csv := "name,protocol,host,*Password\nweb-9,ssh,10.0.0.9," + secret + "\n"
	code, resp := env.do(t, http.MethodPost, "/assets/import/preview", "text/csv", []byte(csv), "")
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Equal(t, "VALIDATION_ASSET_IMPORT_SECRET_FIELD", resp["code"])
	assert.Equal(t, "*Password", resp["params"].(map[string]any)["column"])

	// JSON：列物件夾帶秘密欄，預檢與寫入兩個端點皆整批拒收
	for _, path := range []string{"/assets/import/preview", "/assets/import"} {
		for _, field := range []string{"password", "private_key", "username", "credential"} {
			body := fmt.Sprintf(`{"source":"form","rows":[{"name":"web-9","protocol":"ssh","host":"10.0.0.9","%s":%q}]}`,
				field, secret)
			code, resp = env.do(t, http.MethodPost, path, "application/json", []byte(body), "")
			assert.Equal(t, http.StatusBadRequest, code, "%s %s", path, field)
			assert.Equal(t, "VALIDATION_ASSET_IMPORT_SECRET_FIELD", resp["code"], "%s %s", path, field)
			assert.Equal(t, field, resp["params"].(map[string]any)["column"], "%s %s", path, field)
		}
	}

	assert.Equal(t, before, env.assetCount(t), "被拒的請求不得寫入任何資產")
	var leaked int64
	require.NoError(t, env.f.db.Model(&model.CredentialSecretVersion{}).
		Where("password_enc LIKE ?", "%"+secret+"%").Count(&leaked).Error)
	assert.Zero(t, leaked)
	assert.NotContains(t, logBuf.String(), secret, "伺服端日誌不得含被拒欄位的值")
}

// TestImportCommitIsAllOrNothing 擋「半成功：前幾台建了、後面失敗」
func TestImportCommitIsAllOrNothing(t *testing.T) {
	env := setupImportEnv(t)
	db := env.f.db
	node := model.AssetGroup{Name: "匯入節點"}
	require.NoError(t, db.Create(&node).Error)

	rows := func(prefix string) []map[string]any {
		return []map[string]any{
			{"name": prefix + "-1", "protocol": "ssh", "host": "10.1.0.1"},
			{"name": prefix + "-2", "protocol": "rdp", "host": "10.1.0.2", "node_ids": []uint{node.ID}},
			{"name": prefix + "-3", "protocol": "ssh", "host": "10.1.0.3", "credential_id": env.f.sharedID},
			{"name": prefix + "-4", "protocol": "mysql", "host": "10.1.0.4", "db_tls_mode": "require"},
		}
	}
	type counts struct{ assets, accounts, nodes, audits int64 }
	snapshot := func() counts {
		var c counts
		require.NoError(t, db.Model(&model.Asset{}).Count(&c.assets).Error)
		require.NoError(t, db.Unscoped().Model(&model.AssetAccount{}).Count(&c.accounts).Error)
		require.NoError(t, db.Model(&model.AssetNode{}).Count(&c.nodes).Error)
		require.NoError(t, db.Model(&model.AuditLog{}).Where("resource = ?", model.ResourceAsset).Count(&c.audits).Error)
		return c
	}

	// 預檢通過後、交易前讓第 3 列的共用憑證進入改密
	env.f.assetSvc.SetImportPreTxHookForTest(func() {
		require.NoError(t, db.Model(&model.Credential{}).Where("id = ?", env.f.sharedID).
			Update("active_rotation_id", 77).Error)
	})
	before := snapshot()
	body, _ := json.Marshal(map[string]any{"source": "form", "rows": rows("stale")})
	code, resp := env.do(t, http.MethodPost, "/assets/import", "application/json", body, "")
	require.Equal(t, http.StatusConflict, code, "%v", resp)
	assert.Equal(t, "CONFLICT_ASSET_IMPORT_STATE_CHANGED", resp["code"])
	failed := resp["rows"].([]any)
	require.Len(t, failed, 1)
	assert.EqualValues(t, 2, failed[0].(map[string]any)["index"], "標出第 3 列")
	assert.Equal(t, []string{"credential_id:RULE_CREDENTIAL_ROTATION_ACTIVE"}, errorSet(failed[0].(map[string]any)))
	assert.Equal(t, before, snapshot(), "資產、掛載、節點掛載與逐台稽核列全為零（整筆回滾）")
	assert.Equal(t, "0", env.details["import_count"])

	// 正常匯入：逐台建立稽核列數＝台數、操作者為發起者；請求列帶來源與台數
	env.f.assetSvc.SetImportPreTxHookForTest(nil)
	require.NoError(t, db.Model(&model.Credential{}).Where("id = ?", env.f.sharedID).
		Update("active_rotation_id", nil).Error)
	body, _ = json.Marshal(map[string]any{"source": "csv", "rows": rows("ok")})
	code, resp = env.do(t, http.MethodPost, "/assets/import", "application/json", body, "")
	require.Equal(t, http.StatusCreated, code, "%v", resp)
	assert.EqualValues(t, 4, resp["created"])
	assert.EqualValues(t, 3, resp["credential_pending"])

	var created []model.AuditLog
	require.NoError(t, db.Where("resource = ? AND action = ? AND (details = '' OR details IS NULL) AND asset_id IN (?)",
		model.ResourceAsset, model.ActionCreate,
		db.Model(&model.Asset{}).Select("id").Where("name LIKE ?", "ok-%")).Find(&created).Error)
	require.Len(t, created, 4, "逐台建立稽核列數＝台數")
	for _, a := range created {
		assert.Equal(t, uint(1), a.UserID)
		assert.Equal(t, "admin", a.Username, "建立稽核列的操作者為發起匯入者，而非 system")
	}
	var others []model.AuditLog
	require.NoError(t, db.Where("resource = ? AND details LIKE ?", model.ResourceAsset, "%node_ids%").Find(&others).Error)
	require.NotEmpty(t, others, "有節點的列留下節點掛載稽核")
	for _, a := range others {
		assert.Equal(t, "admin", a.Username)
	}
	assert.Equal(t, map[string]string{"import_source": "csv", "import_count": "4"}, env.details)
}

// TestAssetListCredentialPendingFlag 擋「待配憑證資產在列表上看起來可連」
func TestAssetListCredentialPendingFlag(t *testing.T) {
	env := setupImportEnv(t)
	db, svc := env.f.db, env.f.assetSvc

	pending, err := svc.Create(credAdminCtx(), &asset.CreateAssetRequest{
		Name: "zero-mount", Protocol: model.ProtocolSSH, Host: "10.2.0.1", Port: 22, CreatedBy: 1})
	require.NoError(t, err)
	mounted, err := svc.Create(credAdminCtx(), &asset.CreateAssetRequest{
		Name: "mounted", Protocol: model.ProtocolSSH, Host: "10.2.0.2", Port: 22,
		Username: "ops", Password: "pw", CreatedBy: 1})
	require.NoError(t, err)
	emptied, err := svc.Create(credAdminCtx(), &asset.CreateAssetRequest{
		Name: "emptied", Protocol: model.ProtocolSSH, Host: "10.2.0.3", Port: 22,
		Username: "ops", Password: "pw", CreatedBy: 1})
	require.NoError(t, err)
	// 刪光帳號：軟刪後回到零掛載
	require.NoError(t, db.Where("asset_id = ?", emptied.ID).Delete(&model.AssetAccount{}).Error)

	flags := func(resp map[string]any) map[string]bool {
		out := map[string]bool{}
		for _, r := range resp["data"].([]any) {
			m := r.(map[string]any)
			out[m["name"].(string)] = m["credential_pending"].(bool)
		}
		return out
	}
	code, resp := env.do(t, http.MethodGet, "/assets?page_size=100", "", nil, model.RoleAdmin)
	require.Equal(t, http.StatusOK, code, "%v", resp)
	got := flags(resp)
	assert.True(t, got["zero-mount"])
	assert.False(t, got["mounted"])
	assert.True(t, got["emptied"], "刪光帳號的資產與新建零掛載者一致")

	code, resp = env.do(t, http.MethodGet, "/assets?page_size=100&credential_pending=true", "", nil, model.RoleAdmin)
	require.Equal(t, http.StatusOK, code, "%v", resp)
	assert.Equal(t, map[string]bool{"zero-mount": true, "emptied": true}, flags(resp), "篩選只回待配憑證者")

	// 一般使用者：帶篩選參數拒 400；列表回應同樣帶旗標
	code, resp = env.do(t, http.MethodGet, "/assets?credential_pending=true", "", nil, model.RoleUser)
	assert.Equal(t, http.StatusBadRequest, code, "%v", resp)
	uid := uint(1)
	for _, id := range []uint{pending.ID, mounted.ID} {
		aid := id
		require.NoError(t, db.Create(&model.AssetAuthorization{UserID: &uid, AssetID: &aid,
			Permission: model.PermissionConnect, GrantedBy: 1}).Error)
	}
	code, resp = env.do(t, http.MethodGet, "/assets", "", nil, model.RoleUser)
	require.Equal(t, http.StatusOK, code, "%v", resp)
	assert.Equal(t, map[string]bool{"zero-mount": true, "mounted": false}, flags(resp))
}
