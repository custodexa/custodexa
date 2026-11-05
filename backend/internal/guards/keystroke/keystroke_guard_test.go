// Package keystroke 承載鍵盤紀錄的兩道靜態守衛：
//
//   - 常開：政策鍵、環境變數清單、設定程式碼中沒有可停用鍵盤紀錄的項目
//   - 獨立：錄影服務、錄影刪除、離機模組不引用鍵盤紀錄套件，
//     且鍵盤紀錄根目錄不在錄影根之下
//
// 兩者都讀不到被驗證對象即 Fatal，不 skip：守衛靜默不執行比沒有守衛更糟。
package keystroke

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	kspkg "github.com/custodexa/backend/internal/keystroke"
)

func moduleRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("無法定位守衛檔位置")
	}
	dir := filepath.Dir(file)
	for i := 0; i < 8; i++ {
		raw, err := os.ReadFile(filepath.Join(dir, "go.mod"))
		if err == nil && strings.Contains(string(raw), "module github.com/custodexa/backend") {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("找不到 backend 的 go.mod：守衛的掃描根失真")
	return ""
}

func goFiles(t *testing.T, root string, skipTests bool) []string {
	t.Helper()
	var out []string
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(p, ".go") || (skipTests && strings.HasSuffix(p, "_test.go")) {
			return nil
		}
		out = append(out, p)
		return nil
	})
	if err != nil {
		t.Fatalf("掃描 %s 失敗: %v", root, err)
	}
	return out
}

// 含 keystroke 且帶停用語義的字樣（鍵名、環境變數名、旗標名）。
var disableLike = regexp.MustCompile(`(?i)keystroke[_a-z]*(enabled|disable|disabled|off|optout|opt_out|skip)|(enable|disable|skip|no)[_]?keystroke`)

// 常開：政策鍵、env、設定程式碼中沒有可停用鍵盤紀錄的項目。
func TestKeystrokeAlwaysOn(t *testing.T) {
	root := moduleRoot(t)
	var targets []string
	for _, rel := range []string{"internal/modules/policy", "config"} {
		targets = append(targets, goFiles(t, filepath.Join(root, rel), true)...)
	}
	if len(targets) < 20 {
		t.Fatalf("政策與設定原始碼只掃到 %d 檔：掃描面失真，守衛將在近乎空集合下假綠", len(targets))
	}
	env := filepath.Join(root, "config", "testdata", ".env.example")
	raw, err := os.ReadFile(env)
	if err != nil {
		t.Fatalf("讀不到 .env.example（%v）：env 清單的掃描面失真", err)
	}
	if len(raw) < 1000 {
		t.Fatalf(".env.example 只有 %d bytes：掛載點為空檔，守衛讀不到被驗證對象", len(raw))
	}
	var hits []string
	for _, f := range targets {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, ln := range strings.Split(string(b), "\n") {
			if disableLike.MatchString(ln) {
				hits = append(hits, filepath.Base(f)+":"+itoa(i+1))
			}
		}
	}
	for i, ln := range strings.Split(string(raw), "\n") {
		if disableLike.MatchString(ln) {
			hits = append(hits, ".env.example:"+itoa(i+1))
		}
	}
	if len(hits) > 0 {
		t.Fatalf("發現可停用鍵盤紀錄的項目（鍵盤紀錄常開，不提供任何關閉選項）：%v", hits)
	}
	// 判別式敏感度：確認正規式抓得到典型的關閉鍵，否則空結果沒有意義
	for _, bad := range []string{"keystroke_enabled", "KEYSTROKE_DISABLE", "disable_keystroke", "retention_keystroke_off"} {
		if !disableLike.MatchString(bad) {
			t.Fatalf("判別式對 %q 回 false：守衛已失效", bad)
		}
	}
	if disableLike.MatchString("retention_keystroke_days") {
		t.Fatal("判別式對保留天數鍵誤報")
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

const ksPkgPrefix = "github.com/custodexa/backend/internal/keystroke"

// 獨立：錄影服務、錄影刪除、離機模組不引用鍵盤紀錄套件。
func TestKeystrokeIndependence(t *testing.T) {
	root := moduleRoot(t)
	var files []string
	for _, f := range goFiles(t, filepath.Join(root, "internal", "modules", "session"), true) {
		if strings.HasPrefix(filepath.Base(f), "recording_") {
			files = append(files, f)
		}
	}
	files = append(files, goFiles(t, filepath.Join(root, "internal", "offsite"), true)...)
	files = append(files, goFiles(t, filepath.Join(root, "internal", "recorder"), true)...)
	for _, f := range goFiles(t, filepath.Join(root, "internal", "api"), true) {
		if strings.HasPrefix(filepath.Base(f), "recording_") {
			files = append(files, f)
		}
	}
	if len(files) < 15 {
		t.Fatalf("錄影與離機原始碼只掃到 %d 檔：掃描面失真", len(files))
	}
	fset := token.NewFileSet()
	var bad []string
	for _, f := range files {
		af, err := parser.ParseFile(fset, f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("解析 %s 失敗: %v", f, err)
		}
		for _, imp := range af.Imports {
			if strings.HasPrefix(strings.Trim(imp.Path.Value, `"`), ksPkgPrefix) {
				bad = append(bad, filepath.Base(f))
			}
		}
		b, _ := os.ReadFile(f)
		if strings.Contains(string(b), "KeystrokeService") || strings.Contains(string(b), "KeystrokeRecord") {
			bad = append(bad, filepath.Base(f)+"（引用鍵盤紀錄型別）")
		}
	}
	if len(bad) > 0 {
		t.Fatalf("錄影或離機模組引用了鍵盤紀錄（兩者生命週期必須獨立）：%v", bad)
	}
}

// 鍵盤紀錄根目錄不在錄影根之下（錄影清理會走訪並刪除整個錄影根）。
func TestKeystrokeRootNotUnderRecordingRoot(t *testing.T) {
	for _, tc := range []struct{ audit, recordings string }{
		{"/var/log/custodexa/audit", "/var/lib/custodexa/recordings"},
		{"/data/audit", "/data/recordings"},
		{"logs/audit_fallback", "recordings"},
	} {
		ks := kspkg.RootFromAuditDir(tc.audit)
		rel, err := filepath.Rel(tc.recordings, ks)
		if err == nil && !strings.HasPrefix(rel, "..") {
			t.Fatalf("鍵盤紀錄根 %s 落在錄影根 %s 之下", ks, tc.recordings)
		}
		if filepath.Base(ks) != kspkg.RootDirName {
			t.Fatalf("根目錄名稱 %q 不是 %q", filepath.Base(ks), kspkg.RootDirName)
		}
	}
}
