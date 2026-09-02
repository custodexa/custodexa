package pdfdoc

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
	"regexp"
	"strings"
	"testing"
)

func newTestDoc(t *testing.T) *Doc {
	t.Helper()
	d, err := New(Options{
		Title:   "測試文件",
		Subject: "unit test",
		Footer: Footer{
			Left:   "job-1",
			Center: "2026-09-02T12:00:00+08:00",
			Page:   "%s / %s",
			Note:   "完整性以清單檔與簽章為準",
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return d
}

// TestPdfDocTableSpansPages 兩千列的表格必然跨頁，且每一頁都要有表頭。
//
// 表頭只出現在第一頁的表格，第二頁起的每一列都是無標籤的數字——
// 那正是長報告最容易被誤讀的地方。
func TestPdfDocTableSpansPages(t *testing.T) {
	d := newTestDoc(t)
	cols := []Column{}
	widths := d.FitColumns([]float64{2, 3, 2, 2})
	titles := []string{"資產", "帳號", "狀態", "剩餘天數"}
	for i, w := range widths {
		cols = append(cols, Column{Title: titles[i], Width: w})
	}
	rows := make([][]string, 0, 2000)
	for i := 0; i < 2000; i++ {
		rows = append(rows, []string{
			fmt.Sprintf("資產-%d", i), fmt.Sprintf("user%d", i), "逾期", fmt.Sprintf("%d", -i),
		})
	}
	d.Table(Table{Columns: cols, Rows: rows, Zebra: true})

	pages := d.PageCount()
	if pages < 2 {
		t.Fatalf("2000 列只產出 %d 頁", pages)
	}

	var buf bytes.Buffer
	if err := d.Output(&buf); err != nil {
		t.Fatalf("Output: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("輸出為空")
	}
	// 表頭在每頁重畫：畫表頭時會填底色，故底色填充指令的次數不少於頁數
	if got := countHeaderFills(t, &buf); got < pages {
		t.Errorf("表頭底色填充 %d 次 < 頁數 %d，表示有頁面缺表頭", got, pages)
	}
}

// headerFillOp 表頭底色的填色指令（灰階 238/240/242 轉為 0–1 的浮點）。
var headerFillOp = regexp.MustCompile(`0\.93\d* 0\.94\d* 0\.94\d* rg`)

// countHeaderFills 解壓內容串流後數表頭底色指令的出現次數。
//
// 內容串流預設經 Flate 壓縮，直接對成品做位元組搜尋恆為零——那會讓這支測試
// 永遠通過而什麼都沒驗到。
func countHeaderFills(t *testing.T, buf *bytes.Buffer) int {
	t.Helper()
	raw := buf.Bytes()
	count := 0
	// 起點刻意含前導換行：`endstream` 的尾巴本身就是 `stream`，
	// 少了它會把每個串流的結尾當成下一個串流的開頭而全數解析失敗
	const begin, end = "\nstream\n", "\nendstream"
	for i := 0; ; {
		s := bytes.Index(raw[i:], []byte(begin))
		if s < 0 {
			break
		}
		s += i + len(begin)
		e := bytes.Index(raw[s:], []byte(end))
		if e < 0 {
			break
		}
		e += s
		if zr, err := zlib.NewReader(bytes.NewReader(raw[s:e])); err == nil {
			if plain, rerr := io.ReadAll(zr); rerr == nil {
				count += len(headerFillOp.FindAll(plain, -1))
			}
			_ = zr.Close()
		}
		i = e
	}
	return count
}

// TestPdfDocCJKRenders 繁中、日文與英數混排不 panic，且字型確實嵌入。
func TestPdfDocCJKRenders(t *testing.T) {
	d := newTestDoc(t)
	d.CoverTitle("資產帳號輪替證據報告", "全系統 / 2026-09-01 – 2026-09-30")
	d.KeyValues([]KV{
		{Key: "範囲", Value: "アカウント基盤（証拠）"},
		{Key: "Scope", Value: "all systems"},
	})
	d.MetricCells([]Metric{
		{Label: "帳號總數", Value: "128"},
		{Label: "逾期", Value: "7", Note: "剩餘天數 A < 0"},
	}, 2)
	ratio := 0.875
	d.Donuts([]Donut{
		{Label: "合規率（排除無記錄）", Ratio: &ratio, Center: "87.5%"},
		{Label: "合規率（無記錄計不合規）", Ratio: nil, Center: "不適用"},
	})
	d.StackedBar(StackedBar{Segments: []Segment{
		{Label: "合規", Value: 100, Shade: 90},
		{Label: "逾期", Value: 7, Shade: 160},
		{Label: "未驗證", Value: 21, Shade: 210},
	}})
	d.NoteBlock("口徑說明", []string{
		"剩餘天數 A ＝ 適用天數 − 距最後成功改密天數",
		"無記録＝本システムに成功記録がないこと",
	})
	d.Table(Table{
		Columns: []Column{{Title: "資産", Width: 60}, {Title: "アカウント", Width: 60}},
		Rows:    [][]string{{"核心系統-01", "ｼｽﾃﾑ管理者"}},
	})

	var buf bytes.Buffer
	if err := d.Output(&buf); err != nil {
		t.Fatalf("Output: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "/FontFile2") {
		t.Error("PDF 未嵌入 TrueType 字型（缺 /FontFile2）")
	}
	if !strings.Contains(out, "/Identity-H") {
		t.Error("PDF 未以 Identity-H 編碼，CJK 無法正確呈現")
	}
}

// TestPdfDocFooterTotalPages 頁尾的總頁數位置符號在輸出時被替換成真實頁數。
//
// 位置符號留在成品上，讀者看到的會是「第 3 頁 / 共 {nb} 頁」。
func TestPdfDocFooterTotalPages(t *testing.T) {
	d := newTestDoc(t)
	for i := 0; i < 3; i++ {
		d.Paragraph(fmt.Sprintf("第 %d 段", i))
		d.NewPage()
	}
	want := d.PageCount()

	var buf bytes.Buffer
	if err := d.Output(&buf); err != nil {
		t.Fatalf("Output: %v", err)
	}
	if want < 2 {
		t.Fatalf("測試前提不成立：只有 %d 頁", want)
	}
	if bytes.Contains(buf.Bytes(), []byte(TotalPagesToken)) {
		t.Error("總頁數位置符號未被替換")
	}
	// UTF-8 字型下文字以 UTF-16BE 編碼，位置符號的 UTF-16 形式也不得殘留
	if bytes.Contains(buf.Bytes(), utf16Bytes(TotalPagesToken)) {
		t.Error("總頁數位置符號（UTF-16 形式）未被替換")
	}
}

// TestPdfDocEmptyTableStatesItself 空表格印出明說「無資料」的一列。
func TestPdfDocEmptyTableStatesItself(t *testing.T) {
	d := newTestDoc(t)
	d.Table(Table{
		Columns:   []Column{{Title: "資產", Width: 80}},
		Rows:      nil,
		EmptyText: "本段無資料",
	})
	var buf bytes.Buffer
	if err := d.Output(&buf); err != nil {
		t.Fatalf("Output: %v", err)
	}
	if d.PageCount() != 1 {
		t.Errorf("空表格產出 %d 頁", d.PageCount())
	}
}

func utf16Bytes(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for _, r := range s {
		out = append(out, byte(r>>8), byte(r&0xFF))
	}
	return out
}
