package moduleboundary

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// 通知內容表只由 audit 模組寫入的守衛。
//
// 產生點（連線申請、破窗、補審逾期、AI agent、改密工作提醒等）一律經 audit 模組對外的排入介面
// （EnqueueInTx／EnqueueStandalone）寫通知內容；它們所在的模組不得直接引用通知內容的模型或表名。
// 資料邊界閘門（TestModuleDataBoundaryRatchet）以「gorm 呼叫所在檔案的模組」歸屬存取：經排入介面的
// 寫入發生在 audit 模組的檔案內，所以不算跨模組；若別的模組自己呼叫 gorm 寫這張表，閘門會以未登記的
// 跨模組寫入擋下。本守衛另外以字面掃描擋住更早的形態：只要 audit 以外的非測試檔出現表名字面或
// 通知內容模型的識別字就紅，連讀取也不放行。

// notificationMessagesAllowedDirs 可以引用通知內容表或模型的目錄（相對 module 根）。
//   - internal/modules/audit：表的所屬模組（排入、分派、清除）。
//   - internal/model：模型宣告本身。
//   - internal/database：建表 migration 與結構對等守衛。
var notificationMessagesAllowedDirs = []string{
	"internal/modules/audit",
	"internal/model",
	"internal/database",
}

// notificationMessagesFinding 一處引用。
type notificationMessagesFinding struct {
	Site string
	What string
}

// scanNotificationMessagesRefs 掃描 root 下非測試的 Go 檔，回傳允許目錄以外對通知內容表的引用。
func scanNotificationMessagesRefs(t *testing.T, root string) ([]notificationMessagesFinding, int) {
	t.Helper()
	var findings []notificationMessagesFinding
	files := 0
	fset := token.NewFileSet()
	for _, top := range []string{"internal", "cmd", "pkg"} {
		base := filepath.Join(root, top)
		if _, err := os.Stat(base); err != nil {
			continue
		}
		err := filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
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
			rel, _ := filepath.Rel(root, path)
			rel = filepath.ToSlash(rel)
			for _, dir := range notificationMessagesAllowedDirs {
				if strings.HasPrefix(rel, dir+"/") {
					return nil
				}
			}
			files++
			f, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				t.Fatalf("解析 %s 失敗: %v", rel, perr)
			}
			ast.Inspect(f, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.BasicLit:
					if x.Kind == token.STRING {
						if v, err := strconv.Unquote(x.Value); err == nil && strings.Contains(v, "notification_messages") {
							findings = append(findings, notificationMessagesFinding{Site: siteOf(fset, root, x.Pos()), What: "表名字面 " + x.Value})
						}
					}
				case *ast.SelectorExpr:
					if id, ok := x.X.(*ast.Ident); ok && id.Name == "model" && strings.HasPrefix(x.Sel.Name, "NotificationMessage") {
						findings = append(findings, notificationMessagesFinding{Site: siteOf(fset, root, x.Pos()), What: "model." + x.Sel.Name})
					}
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatalf("掃描 %s 失敗: %v", base, err)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Site < findings[j].Site })
	return findings, files
}

func siteOf(fset *token.FileSet, root string, pos token.Pos) string {
	p := fset.Position(pos)
	rel, _ := filepath.Rel(root, p.Filename)
	return filepath.ToSlash(rel) + ":" + strconv.Itoa(p.Line)
}

func TestNotificationMessagesOnlyThroughAuditPort(t *testing.T) {
	root := lifecycleModuleRoot(t)
	findings, files := scanNotificationMessagesRefs(t, root)
	// 掃描範圍下限：檔數歸零即掃描失效，「零引用」不成立
	if files < 300 {
		t.Fatalf("掃描到的非測試檔只有 %d 個，掃描範圍失效", files)
	}
	for _, f := range findings {
		t.Errorf("%s：audit 模組以外不得引用通知內容表（%s）；請改經 audit 的 EnqueueInTx／EnqueueStandalone", f.Site, f.What)
	}
}

// TestNotificationMessagesGuardSensitivity 守衛自檢：在 authz 模組的檔案中直接寫通知內容，掃描必須指出位置。
func TestNotificationMessagesGuardSensitivity(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		t.Helper()
		p := filepath.Join(root, rel)
		if err := mkdirAll(filepath.Dir(p)); err != nil {
			t.Fatal(err)
		}
		if err := writeFile(p, body); err != nil {
			t.Fatal(err)
		}
	}
	write("internal/modules/authz/x.go", "package authz\n\nfunc f(tx interface{ Create(any) }) {\n\ttx.Create(&model.NotificationMessage{})\n}\n")
	write("internal/modules/identity/y.go", "package identity\n\nconst q = `INSERT INTO notification_messages (id) VALUES (1)`\n")
	write("internal/modules/audit/ok.go", "package audit\n\nconst q = `notification_messages`\n")
	findings, _ := scanNotificationMessagesRefs(t, root)
	got := map[string]bool{}
	for _, f := range findings {
		got[f.Site] = true
	}
	for _, want := range []string{"internal/modules/authz/x.go:4", "internal/modules/identity/y.go:3"} {
		if !got[want] {
			t.Fatalf("守衛未指出 %s（實得 %v）", want, findings)
		}
	}
	if len(findings) != 2 {
		t.Fatalf("audit 模組內的引用不應被報告，實得 %v", findings)
	}
}

func mkdirAll(dir string) error { return os.MkdirAll(dir, 0o755) }

func writeFile(path, body string) error { return os.WriteFile(path, []byte(body), 0o644) }
