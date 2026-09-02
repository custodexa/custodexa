package dbconsole

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

// 結果讀取與值的文字化。
//
// # 為什麼所有值都是文字
//
// JSON number 走的是 IEEE 754 雙精度：2^53 以上的整數與任何超過 15 位有效數字的
// decimal 在瀏覽器端會**悄悄**變成另一個數。對金額、帳號、識別碼而言那不是顯示
// 問題而是資料錯誤，且沒有任何症狀——畫面上看起來就是一個正常的數字。
// 故一律送 driver 給的十進位文字，畫面與 CSV 逐字元原樣呈現。
//
// # 上限是回傳上限
//
// 目標端仍然算完了整個結果，我們只是不把它全部搬回來。截斷發生時列上有旗標、
// 畫面上有橫幅——使用者要知道他看到的不是全部，否則他會拿一份被截斷的結果去做決定。

// resultBuilder 累積一次送出的全部結果集，並施加三道上限。
//
// 三道上限跨結果集、跨執行單位共用額度（MSSQL 的多批次因此不能靠切批次繞過），
// 這是「一次送出」而不是「一個結果集」為額度單位的理由。
type resultBuilder struct {
	// rowBudget 剩餘可回傳的資料列（跨結果集，單位級）
	rowBudget int
	// byteBudget 剩餘可回傳的序列化位元組（跨單位，送出級）
	byteBudget int
	truncated  bool
	reason     string
}

func newResultBuilder(byteBudget int) *resultBuilder {
	return &resultBuilder{rowBudget: MaxRowsPerUnit, byteBudget: byteBudget}
}

// resetUnit 一個新的執行單位開始：列額度重設，位元組額度延續。
// 列上限的語義是「單位」、位元組上限的語義是「送出」——兩者刻意不同級，
// 因為前者防的是單一查詢拉回整張表，後者防的是整體記憶體佔用
func (b *resultBuilder) resetUnit() { b.rowBudget = MaxRowsPerUnit }

func (b *resultBuilder) markTruncated(reason string) {
	b.truncated = true
	if b.reason == "" {
		b.reason = reason
	}
}

// exhausted 額度是否已用盡（用盡後停止讀取，但已讀的部分照樣回報）
func (b *resultBuilder) exhausted() bool { return b.rowBudget <= 0 || b.byteBudget <= 0 }

// consumeRow 記帳一列。回傳 false 代表這一列不該被加入（額度已盡）。
func (b *resultBuilder) consumeRow(size int) bool {
	if b.rowBudget <= 0 {
		b.markTruncated("row_limit")
		return false
	}
	if b.byteBudget-size <= 0 {
		b.markTruncated("byte_limit")
		return false
	}
	b.rowBudget--
	b.byteBudget -= size
	return true
}

// truncateCell 施加單欄上限。回傳截斷後的值與是否截斷。
//
// 截斷標記進值裡而不只是列上的旗標：只有列旗標的話，使用者看得到「這一列被動過」
// 卻分不出是哪一欄，於是他會以為每一欄都可能不完整。
func truncateCell(s string) (string, bool) {
	if len(s) <= MaxCellBytes {
		return s, false
	}
	// 以 rune 邊界切，避免留下半個字元——半個 UTF-8 序列會讓
	// JSON 編碼把它換成替代字元，那看起來像資料本身有問題
	cut := MaxCellBytes
	for cut > 0 && !utf8Boundary(s[cut]) {
		cut--
	}
	dropped := len(s) - cut
	return s[:cut] + fmt.Sprintf(CellTruncationMarker, dropped), true
}

// utf8Boundary 這個位元組是不是一個 UTF-8 序列的起始位元組
func utf8Boundary(b byte) bool { return b&0xC0 != 0x80 }

// textify 把 driver 回傳的值轉成傳輸用的文字。
//
// nil 回 nil（SQL NULL 與空字串在畫面與 CSV 上是不同的東西，不可合流）。
// 二進位欄只回佔位字串——內容不進畫面也不進匯出：它沒有可讀的呈現，
// 而把它塞進 CSV 只會產生一個沒有人能用的巨大欄位。
func textify(v any, kind Kind) *string {
	if v == nil {
		return nil
	}
	var s string
	switch val := v.(type) {
	case []byte:
		if kind == KindBinary {
			s = fmt.Sprintf("<bytes %d>", len(val))
		} else {
			s = string(val)
		}
	case string:
		s = val
	case bool:
		s = strconv.FormatBool(val)
	case int64:
		s = strconv.FormatInt(val, 10)
	case int32:
		s = strconv.FormatInt(int64(val), 10)
	case int:
		s = strconv.Itoa(val)
	case float64:
		s = formatFloat(val)
	case float32:
		s = formatFloat(float64(val))
	case time.Time:
		// **不換算時區、不截微秒**：時戳的顯示形態由目標端決定，
		// 我方一換算，同一筆資料在主控台與命令列上就會長得不一樣
		s = val.Format("2006-01-02 15:04:05.999999999 -07:00")
	case fmt.Stringer:
		s = val.String()
	default:
		s = fmt.Sprintf("%v", val)
	}
	out, _ := truncateCell(s)
	return &out
}

// textifyCounted 同 textify，另回報是否發生單欄截斷
func textifyCounted(v any, kind Kind) (*string, bool) {
	p := textify(v, kind)
	if p == nil {
		return nil, false
	}
	return p, strings.HasSuffix(*p, "bytes]")
}

// formatFloat 浮點的文字形態。
//
// 特殊值走 `NaN`／`Infinity`／`-Infinity` 字面而非 JSON 的 null——
// 那三個是目標端真實回傳的值，換成 null 就變成「這一格是 NULL」，是另一件事。
func formatFloat(f float64) string {
	switch {
	case math.IsNaN(f):
		return "NaN"
	case math.IsInf(f, 1):
		return "Infinity"
	case math.IsInf(f, -1):
		return "-Infinity"
	}
	return strconv.FormatFloat(f, 'g', -1, 64)
}

// KindOf 由 driver 回報的型別名推粗分類。
//
// **判定用型別名而非 Go 值的型別**：同一個 Go 型別（[]byte）會同時承載文字、
// 二進位與 decimal，靠值分不出來；型別名是目標端自己的說法。
// 判不出來時回 KindOther——那只影響畫面對齊與 CSV 的數值豁免判斷，
// 不影響值本身（值恆為原文）。
func KindOf(typeName string) Kind {
	t := strings.ToUpper(strings.TrimSpace(typeName))
	// 去掉長度／精度括號：`VARCHAR(255)`／`DECIMAL(18,4)` 的分類與括號無關
	if i := strings.IndexByte(t, '('); i >= 0 {
		t = strings.TrimSpace(t[:i])
	}
	switch {
	case t == "":
		return KindOther
	case containsAny(t, "JSONB", "JSON"):
		return KindJSON
	case containsAny(t, "BOOL", "BIT"):
		return KindBool
	// 二進位在文字類之前判：`VARBINARY` 同時含 BINARY 與 VARCHAR 的字首片段
	case containsAny(t, "BLOB", "BYTEA", "BINARY", "IMAGE", "RAW"):
		return KindBinary
	case containsAny(t, "TIMESTAMP", "DATETIME", "SMALLDATETIME", "DATE", "TIME", "INTERVAL"):
		return KindDateTime
	case containsAny(t, "DECIMAL", "NUMERIC", "MONEY", "SMALLMONEY"):
		return KindDecimal
	case containsAny(t, "DOUBLE", "FLOAT", "REAL", "FLOAT4", "FLOAT8"):
		return KindFloat
	case containsAny(t, "INT", "SERIAL", "YEAR"):
		return KindInteger
	case containsAny(t, "CHAR", "TEXT", "CLOB", "ENUM", "SET", "UUID", "XML", "NAME"):
		return KindText
	}
	return KindOther
}

func containsAny(s string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

// approxRowSize 一列序列化後的粗估位元組數（位元組額度的記帳依據）。
//
// **是粗估不是精確值**：精確值要等 JSON 編碼完成才知道，而那時記憶體已經吃下去了。
// 每欄多算的常數是引號、逗號與可能的跳脫；寧可高估——高估的後果是提早截斷並明示，
// 低估的後果是超出額度而沒有人發現。
func approxRowSize(row []*string) int {
	size := 2
	for _, cell := range row {
		if cell == nil {
			size += 6 // "null,"
			continue
		}
		size += len(*cell) + 3
	}
	return size
}

// Submission 一次送出的位元組額度句柄。
//
// 一次送出可以含多個執行單位（MSSQL 以整行 GO 切批次），而序列化位元組上限
// 是**跨單位合計**的——每個單位各給一份完整額度，等於這條上限對多批次送出
// 形同不存在。列數上限則相反，它是逐單位的，故每個單位起手要重設。
//
// 本型別是那份共用額度對套件外的唯一入口：內部的 builder 不出套件，
// 因為它同時承載已讀進來的結果，讓呼叫端拿到它就等於讓它有機會改寫結果
type Submission struct{ builder *resultBuilder }

// NewSubmission 為一次送出建立額度。**一次送出建一個**——
// 跨送出沿用會讓第二次送出從第一次剩下的額度開始，使用者看到的截斷點會漂移
func NewSubmission() *Submission {
	return &Submission{builder: newResultBuilder(MaxBytesPerSubmission)}
}
