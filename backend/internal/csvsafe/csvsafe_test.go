package csvsafe

import (
	"bytes"
	"strings"
	"testing"
)

// TestCsvSafeCellEscapesFormulaLeads 六種公式起頭字元逐一驗證。
//
// 逐形態列出而非抽樣：漏掉任何一個，那一種輸入就是一個未轉義的執行入口，
// 而測試會照樣全綠。
func TestCsvSafeCellEscapesFormulaLeads(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"等號", "=1+1", "'=1+1"},
		{"加號", "+SUM(A1)", "'+SUM(A1)"},
		{"減號", "-cmd|'/c calc'", "'-cmd|'/c calc'"},
		{"小老鼠", "@SUM(A1)", "'@SUM(A1)"},
		{"Tab", "\tfoo", "'\tfoo"},
		{"CR", "\rfoo", "'\rfoo"},
		{"一般文字不動", "root", "root"},
		{"空字串不動", "", ""},
		{"中間有等號不動", "a=b", "a=b"},
		{"正整數不動", "42", "42"},
		{"負整數豁免", "-5", "-5"},
		{"負小數豁免", "-5.25", "-5.25"},
		{"科學記號豁免", "-1.5e-3", "-1.5e-3"},
		{"像數字但不是數字", "-5abc", "'-5abc"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Cell(c.in); got != c.want {
				t.Errorf("Cell(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// TestCsvSafeRowDoesNotMutateInput 轉義回傳新切片，呼叫端的資料不被就地改寫。
func TestCsvSafeRowDoesNotMutateInput(t *testing.T) {
	in := []string{"=evil", "ok"}
	out := Row(in)
	if in[0] != "=evil" {
		t.Errorf("輸入被就地修改: %q", in[0])
	}
	if out[0] != "'=evil" {
		t.Errorf("輸出未轉義: %q", out[0])
	}
}

// TestCsvSafeWriterBOMAndCRLF 試算表形態：BOM 在最前、列以 CRLF 結尾、儲存格已轉義。
func TestCsvSafeWriterBOMAndCRLF(t *testing.T) {
	var buf bytes.Buffer
	w, err := NewWriter(&buf, Options{BOM: true, CRLF: true, Escape: true})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if err := w.WriteAll([][]string{{"帳號", "備註"}, {"=root", "-5"}}); err != nil {
		t.Fatalf("WriteAll: %v", err)
	}
	got := buf.String()
	if !strings.HasPrefix(got, utf8BOM) {
		t.Errorf("缺 UTF-8 BOM: %q", got[:min(6, len(got))])
	}
	if !strings.Contains(got, "帳號,備註\r\n") {
		t.Errorf("表頭未以 CRLF 斷行: %q", got)
	}
	if !strings.Contains(got, "'=root,-5\r\n") {
		t.Errorf("儲存格轉義或數值豁免不符: %q", got)
	}
}

// TestCsvSafeWriterDefaultsMatchStdlib 零值 Options 與 encoding/csv 預設逐位元組相同：
// 既有呼叫端改用本套件時行為不變。
func TestCsvSafeWriterDefaultsMatchStdlib(t *testing.T) {
	var buf bytes.Buffer
	w, err := NewWriter(&buf, Options{})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if err := w.WriteAll([][]string{{"=root", "a,b"}}); err != nil {
		t.Fatalf("WriteAll: %v", err)
	}
	if got, want := buf.String(), "=root,\"a,b\"\n"; got != want {
		t.Errorf("預設形態 = %q, want %q", got, want)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
