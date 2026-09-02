// Package csvsafe 是本系統所有 CSV 匯出的共用寫入層。
//
// 存在理由：CSV 會被試算表打開，而試算表把以特定字元開頭的儲存格當**公式**執行。
// 匯出的內容多半來自使用者可控的欄位（帳號名、資產名、備註），沒有轉義即等於
// 把一個遠端執行的入口交給讀報告的人。轉義規則只該有一份——同一條規則散落在
// 三個模組裡，第四個匯出點就會漏掉它。
//
// 邊界：本套件只認「一列字串」，不認任何業務語義；欄名、上限、截斷標示都由呼叫端決定。
package csvsafe

import (
	"encoding/csv"
	"io"
	"regexp"
	"strings"
)

// FormulaLead 會被試算表當成公式起頭的字元。
const FormulaLead = "=+-@\t\r"

// utf8BOM UTF-8 位元組順序記號。
//
// Excel 讀無 BOM 的 UTF-8 CSV 時會以系統編碼解讀，繁體中文與日文直接變亂碼。
// 但 BOM 對非試算表的消費端（管線、程式解析）是多出來的三個位元組，
// 故是否輸出由呼叫端依讀者決定，不預設。
const utf8BOM = "\xEF\xBB\xBF"

// numericLiteral 純數值字面。
//
// 它是轉義的**豁免**：負號開頭的數字不是公式，而把 `-5` 寫成 `'-5`
// 會讓數值欄在試算表裡變成文字——那會讓「數值在畫面與檔案中逐字元相同」
// 這條對稽核的承諾在 CSV 這一側失效。
var numericLiteral = regexp.MustCompile(`^-?\d+(\.\d+)?([eE][+-]?\d+)?$`)

// Cell 防公式注入：以 `=`、`+`、`-`、`@`、Tab、CR 開頭的儲存格前置單引號，
// 純數值字面豁免。
func Cell(v string) string {
	if v == "" {
		return v
	}
	if !strings.ContainsRune(FormulaLead, rune(v[0])) {
		return v
	}
	if numericLiteral.MatchString(v) {
		return v
	}
	return "'" + v
}

// Row 對整列套用 Cell（回傳新切片，不就地修改呼叫端的資料）。
func Row(values []string) []string {
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = Cell(v)
	}
	return out
}

// Options 一份 CSV 的形態選擇。零值＝最保守的形態：無 BOM、LF 換行、不轉義，
// 與 encoding/csv 的預設逐位元組相同。
type Options struct {
	// BOM 寫入 UTF-8 BOM。讀者是試算表時開啟。
	BOM bool
	// CRLF 以 CRLF 斷行（RFC 4180 與試算表慣例）。
	CRLF bool
	// Escape 對每個儲存格套用 Cell。
	//
	// **不預設開啟**：轉義會在儲存格前多一個單引號，對「檔案內容即原始事實」
	// 的匯出（例如逐字保留的指令文字）是一次改寫。開啟與否由該份匯出的
	// 讀者與用途決定。
	Escape bool
}

// Writer 依 Options 產出的 CSV 寫入器。
type Writer struct {
	cw     *csv.Writer
	escape bool
}

// NewWriter 建立寫入器；BOM 於此時即寫出（在任何列之前）。
func NewWriter(w io.Writer, opt Options) (*Writer, error) {
	if opt.BOM {
		if _, err := io.WriteString(w, utf8BOM); err != nil {
			return nil, err
		}
	}
	cw := csv.NewWriter(w)
	cw.UseCRLF = opt.CRLF
	return &Writer{cw: cw, escape: opt.Escape}, nil
}

// Write 寫一列。
func (w *Writer) Write(record []string) error {
	if w.escape {
		record = Row(record)
	}
	return w.cw.Write(record)
}

// WriteAll 寫多列並 Flush。
func (w *Writer) WriteAll(records [][]string) error {
	for _, r := range records {
		if err := w.Write(r); err != nil {
			return err
		}
	}
	w.cw.Flush()
	return w.cw.Error()
}

// Flush 沖出緩衝。
func (w *Writer) Flush() { w.cw.Flush() }

// Error 回報累積的寫入錯誤（沖出後檢查）。
func (w *Writer) Error() error { return w.cw.Error() }
