package main

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
)

// TestDenialAuditClassification 的案例型別與共用斷言。

// denialNewKeys 本段新增的拒絕細節鍵。
var denialNewKeys = []string{"denial", "basis", "required", "scope_reason", "count"}

// denialAuditCase 一個請求與其審計列的期望。
type denialAuditCase struct {
	name, method, path, body string
	uid                      uint
	who                      *authz.Principal
	mount                    func(r gin.IRoutes)
	preset                   map[string]string // 請求開始時已在 audit_details 的鍵（模擬既有寫入點）
	wantCode                 int
	wantStatus               model.AuditStatus
	wantNew                  map[string]string // 新增五鍵的精確期望；nil＝五鍵皆不得出現
	wantExisting             map[string]string // 其餘既有鍵的精確期望（＝改動前同一請求的 details）
	wantQuery                []string          // 查詢摘要須原樣含有的片段
	fixtures                 []string          // 新增鍵的值不得含有的 fixture 名稱或識別碼
	collision                bool              // 預置了同名鍵：值不受受控集合約束（保留的是既有值）
}

func denialAuditReached(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"reached": true}) }

// denialHandler 在 path 掛一個呼叫寫出函式的 handler；fn 回 false（放行）時回 200。
func denialHandler(path string, fn func(c *gin.Context) bool) func(r gin.IRoutes) {
	return func(r gin.IRoutes) {
		r.Any(path, func(c *gin.Context) {
			if fn(c) {
				return
			}
			denialAuditReached(c)
		})
	}
}

func capDetails(basis authz.DenialBasis, required ...string) map[string]string {
	return map[string]string{"denial": "capability", "basis": string(basis), "required": strings.Join(required, ",")}
}

func scopeDetails(reason, count string) map[string]string {
	m := map[string]string{"denial": "scope", "scope_reason": reason}
	if count != "" {
		m["count"] = count
	}
	return m
}

// ensureDenialAuditTable 在 fixture 已裝上的 database.DB 補 audit_logs 表；連線池收到 1，
// 使中介層寫入與本測試讀回落在同一個 sqlite :memory: 上。
func ensureDenialAuditTable(t *testing.T, db *gorm.DB) {
	t.Helper()
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&model.AuditLog{}))
}

// runDenialAuditCase 經真的審計中介層送一個請求，讀回新寫入的那一列並逐項斷言。
func runDenialAuditCase(t *testing.T, db *gorm.DB, c denialAuditCase) {
	t.Helper()
	before := countAuditRows(t, db)
	r := gin.New()
	r.Use(middleware.AuditLogMiddleware(newCoverageAuditService()))
	r.Use(func(ctx *gin.Context) {
		ctx.Set("userID", c.uid)
		ctx.Set("username", "denial-audit")
		if c.who != nil {
			middleware.SetPrincipal(ctx, c.who)
		}
		if c.preset != nil {
			pre := make(map[string]string, len(c.preset))
			for k, v := range c.preset {
				pre[k] = v
			}
			ctx.Set("audit_details", pre)
		}
		ctx.Next()
	})
	c.mount(r)
	var req *http.Request
	if c.body != "" {
		req = httptest.NewRequest(c.method, c.path, strings.NewReader(c.body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(c.method, c.path, nil)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	require.Equal(t, c.wantCode, w.Code, "%s：回應 %s", c.name, w.Body.String())
	require.Equal(t, before+1, countAuditRows(t, db), "%s：須恰寫入一列具名審計列", c.name)

	var row model.AuditLog
	require.NoError(t, db.Unscoped().Order("id desc").First(&row).Error)
	assert.Equal(t, c.wantStatus, row.Status, "%s：審計狀態", c.name)
	assert.Equal(t, c.uid, row.UserID, "%s：具名列", c.name)
	assert.Equal(t, "denial-audit", row.Username, c.name)
	assert.Equal(t, c.wantCode, row.StatusCode, c.name)

	gotNew, gotExisting := splitDenialDetails(t, row.Details)
	wantNew := c.wantNew
	if wantNew == nil {
		wantNew = map[string]string{}
	}
	wantExisting := c.wantExisting
	if wantExisting == nil {
		wantExisting = map[string]string{}
	}
	assert.Equal(t, wantNew, gotNew, "%s：新增拒絕細節（details=%s）", c.name, row.Details)
	assert.Equal(t, wantExisting, gotExisting, "%s：既有鍵須逐值等於改動前（details=%s）", c.name, row.Details)
	assertDenialReason(t, c.name, row, gotNew["denial"])
	for _, q := range c.wantQuery {
		assert.Contains(t, gotExisting["query"], q, "%s：查詢摘要須原樣保留", c.name)
	}
	if !c.collision {
		assertDenialValuesControlled(t, c.name, gotNew, c.fixtures)
	}
}

// splitDenialDetails 解析 details，分成新增五鍵與其餘既有鍵；值一律須為字串。
func splitDenialDetails(t *testing.T, details string) (newKeys, existing map[string]string) {
	t.Helper()
	newKeys, existing = map[string]string{}, map[string]string{}
	if details == "" {
		return
	}
	var raw map[string]any
	require.NoError(t, json.Unmarshal([]byte(details), &raw), "details 須為 JSON 物件：%s", details)
	isNew := map[string]bool{}
	for _, k := range denialNewKeys {
		isNew[k] = true
	}
	for k, v := range raw {
		s, ok := v.(string)
		require.True(t, ok, "details 鍵 %s 的值須為字串：%v", k, v)
		if isNew[k] {
			newKeys[k] = s
		} else {
			existing[k] = s
		}
	}
	return
}

// assertDenialValuesControlled 新增五鍵的值只在受控集合內，且不含 fixture 名稱、識別碼或內建角色名。
func assertDenialValuesControlled(t *testing.T, name string, got map[string]string, fixtures []string) {
	t.Helper()
	if len(got) == 0 {
		return
	}
	reserved := map[string]bool{authz.ReservedSuperAdmin: true, authz.ReservedSuperAdminOrAuditor: true,
		authz.ReservedApproverEligibility: true, authz.ReservedRevokeEligibility: true}
	roleNames := map[string]bool{"admin": true, model.BuiltinSuperAdmin: true, model.BuiltinAuditor: true, model.BuiltinUser: true,
		model.BuiltinApprover: true, model.BuiltinIdentityAdmin: true, model.BuiltinSecurityAdmin: true}
	reasons := map[string]bool{string(authz.ScopeReasonOutOfScope): true, string(authz.ScopeReasonResolverMissing): true,
		string(authz.ScopeReasonTopologyUnavailable): true, middleware.ScopeReasonKindUnmapped: true,
		middleware.ScopeReasonBatchItemsUnavailable: true}
	cat := authz.ProductCatalogue()

	switch got["denial"] {
	case "capability":
		assert.ElementsMatch(t, []string{"denial", "basis", "required"}, denialKeysOf(got), "%s：能力拒絕的鍵", name)
		basis := authz.DenialBasis(got["basis"])
		switch basis {
		case authz.DenialUnregistered:
			assert.Empty(t, got["required"], "%s：unregistered 的 required 為空字串", name)
		case authz.DenialReserved, authz.DenialAllOf, authz.DenialAnyOf:
			require.NotEmpty(t, got["required"], name)
			for _, tok := range strings.Split(got["required"], ",") {
				assert.False(t, roleNames[tok], "%s：required 不得含角色名 %q", name, tok)
				if basis == authz.DenialReserved {
					assert.True(t, reserved[tok], "%s：保留條件值 %q 不在受控清單", name, tok)
					continue
				}
				_, ok := cat.Lookup(authz.Permission(tok))
				assert.True(t, ok, "%s：%q 不是權限點鍵", name, tok)
			}
		default:
			t.Errorf("%s：basis %q 不在四值內", name, basis)
		}
	case "scope":
		want := []string{"denial", "scope_reason"}
		if _, ok := got["count"]; ok {
			want = append(want, "count")
			n, err := strconv.Atoi(got["count"])
			assert.NoError(t, err, "%s：count 須為整數", name)
			assert.GreaterOrEqual(t, n, 0, name)
		}
		assert.ElementsMatch(t, want, denialKeysOf(got), "%s：範圍拒絕的鍵", name)
		assert.True(t, reasons[got["scope_reason"]], "%s：scope_reason %q 不在受控集合", name, got["scope_reason"])
	default:
		t.Errorf("%s：denial %q 不在受控集合", name, got["denial"])
	}
	for k, v := range got {
		for _, f := range fixtures {
			assert.NotContains(t, v, f, "%s：%s 不得含 fixture %q", name, k, f)
		}
	}
}

func denialKeysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// assertDenialKeysDisjoint 既有寫入點（非測試原始碼中引用 audit_details 的檔）以 map 字面值或索引賦值寫的鍵，
// 與本段新增五鍵不重疊。拒絕細節的產出點本身（denial_audit.go、scope_denial_outlet.go）除外。
func assertDenialKeysDisjoint(t *testing.T) {
	t.Helper()
	exclude := map[string]bool{"denial_audit.go": true, "scope_denial_outlet.go": true}
	found := map[string][]string{}
	files := 0
	for _, root := range []string{filepath.Join("..", "..", "internal"), "."} {
		require.NoError(t, filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			if filepath.Base(filepath.Dir(path)) == "middleware" && exclude[d.Name()] {
				return nil
			}
			src, err := os.ReadFile(path)
			if err != nil || !strings.Contains(string(src), `"audit_details"`) {
				return err
			}
			files++
			for _, k := range auditDetailKeysIn(t, path, src) {
				found[k] = append(found[k], path)
			}
			return nil
		}))
	}
	require.GreaterOrEqual(t, files, 8, "掃描到的 audit_details 寫入檔數過少，掃描範圍可能失效")
	for _, k := range []string{"deny_reason", "query"} {
		require.NotEmpty(t, found[k], "正向對照：掃描須找到既有鍵 %q", k)
	}
	for _, k := range denialNewKeys {
		assert.Empty(t, found[k], "既有寫入點使用了本段新增鍵 %q：%v", k, found[k])
	}
}

// auditDetailKeysIn 回傳檔內 map 字面值的字串鍵與 `m["鍵"] = …` 的鍵。
func auditDetailKeysIn(t *testing.T, path string, src []byte) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), path, src, 0)
	require.NoError(t, err, path)
	var keys []string
	lit := func(e ast.Expr) {
		if b, ok := e.(*ast.BasicLit); ok && b.Kind == token.STRING {
			if s, err := strconv.Unquote(b.Value); err == nil {
				keys = append(keys, s)
			}
		}
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CompositeLit:
			if _, ok := x.Type.(*ast.MapType); ok {
				for _, el := range x.Elts {
					if kv, ok := el.(*ast.KeyValueExpr); ok {
						lit(kv.Key)
					}
				}
			}
		case *ast.AssignStmt:
			for _, l := range x.Lhs {
				if ix, ok := l.(*ast.IndexExpr); ok {
					lit(ix.Index)
				}
			}
		}
		return true
	})
	return keys
}

// assertDenialReason 審計列經原因分類：有 denial 鍵者得對應碼（kind_unmapped 的 403 仍歸 scope），
// 無 denial 鍵者不得得到這兩個碼。
func assertDenialReason(t *testing.T, name string, row model.AuditLog, denial string) {
	t.Helper()
	code, _ := audit.ClassifyAuditReason(audit.AuditReasonInput{
		Action: string(row.Action), Resource: string(row.Resource), Status: string(row.Status),
		ErrorMsg: row.ErrorMsg, Details: row.Details, Path: row.Path,
	})
	want := map[string]string{"capability": "authz_capability_denied", "scope": "authz_scope_denied"}[denial]
	if want == "" {
		assert.NotContains(t, []string{"authz_capability_denied", "authz_scope_denied"}, code, "%s：無 denial 鍵不得得到拒絕原因碼", name)
		return
	}
	assert.Equal(t, want, code, "%s：原因碼", name)
}
