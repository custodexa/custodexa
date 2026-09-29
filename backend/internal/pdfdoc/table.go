package pdfdoc

// 表格：自動跨頁、每頁重複表頭。

// 儲存格自動折行時的行距與上下留白（公釐）。單行列的總高與 lineTableRow 相同，
// 折行表格與裁切表格並排時，沒有折行的列看起來一樣高。
const (
	lineTableWrap = 3.6
	padTableWrap  = (lineTableRow - lineTableWrap) / 2
)

// Column 一欄的定義。Width 為公釐；Align 為 "L"／"C"／"R"。
type Column struct {
	Title string
	Width float64
	Align string
}

// Table 一張表。Rows 的每列長度應等於 Columns 長度；不足補空、超出忽略。
type Table struct {
	Columns []Column
	Rows    [][]string
	// Zebra 隔列淺底。長表格中沒有它，讀者的視線會跨列錯位。
	Zebra bool
	// EmptyText Rows 為空時印出的一行字（例如「本段無資料」）。
	//
	// 空表格什麼都不印，讀者無從分辨「這一段沒有問題」與「這一段漏掉了」。
	EmptyText string
	// Wrap 儲存格（含表頭）自動折行、列高隨內容增長；為 false 時每格單行，
	// 放不下的以刪節號裁切。
	//
	// 給稽核逐格核對的表（設定鍵、帶位移的時刻、確認說明）要開：被裁掉的那一截
	// 可能正是要核對的部分，而刪節號不會告訴讀者少了什麼。
	Wrap bool
}

// Table 畫一張表。跨頁時表頭自動於新頁重畫。
func (d *Doc) Table(t Table) {
	if len(t.Columns) == 0 {
		return
	}
	if len(t.Rows) == 0 {
		if t.EmptyText != "" {
			d.ensureSpace(d.tableHeaderHeight(t) + lineTableRow)
			d.drawHeaderFor(t)
			d.setFont(sizeTable)
			d.setInk(colorMuted)
			d.pdf.SetX(marginLeft)
			d.pdf.CellFormat(d.ContentWidth(), lineTableRow, t.EmptyText, "1", 1, "L", false, 0, "")
			d.setInk(colorInk)
			d.pdf.Ln(2)
		}
		return
	}

	d.ensureSpace(d.tableHeaderHeight(t) + lineTableRow*2)
	d.drawHeaderFor(t)
	// 換頁回呼在此期間生效：自動分頁時新頁的頂端先重畫表頭，
	// 讀者翻到任何一頁都知道每一欄是什麼
	d.tableHeader = func() { d.drawHeaderFor(t) }
	defer func() { d.tableHeader = nil }()

	d.setFont(sizeTable)
	for i, row := range t.Rows {
		fill := t.Zebra && i%2 == 1
		if fill {
			d.pdf.SetFillColor(colorZebraBg[0], colorZebraBg[1], colorZebraBg[2])
		}
		if t.Wrap {
			d.drawWrappedRow(t.Columns, row, fill)
			continue
		}
		d.pdf.SetX(marginLeft)
		d.setInk(colorInk)
		for j, col := range t.Columns {
			ln := 0
			if j == len(t.Columns)-1 {
				ln = 1
			}
			d.pdf.CellFormat(col.Width, lineTableRow, d.truncate(cellAt(row, j), col.Width-2),
				"1", ln, alignOf(col), fill, 0, "")
		}
	}
	d.setFont(sizeBody)
	d.pdf.Ln(2)
}

// TableCellWidth 讓每一段文字都能在表格字級下單行放進一格所需的最小欄寬（公釐，
// 含儲存格內距）。呼叫端據此把設定鍵、時刻這類不宜拆行的欄撐開。
func (d *Doc) TableCellWidth(texts ...string) float64 {
	d.setFont(sizeTable)
	defer d.setFont(sizeBody)
	w := 0.0
	for _, s := range texts {
		if sw := d.pdf.GetStringWidth(s); sw > w {
			w = sw
		}
	}
	return w + 2*d.pdf.GetCellMargin() + 0.1
}

// FitColumnsMin 同 FitColumns，但每欄至少 mins[i] 寬（mins 可短於 weights，
// 缺的視為 0）；撐開的寬度由其餘欄依權重分攤。最小寬合計超過版心時照最小寬給，
// 表格會超出版心——那是呼叫端欄位設計的問題，不在這裡靜默裁欄。
func (d *Doc) FitColumnsMin(weights, mins []float64) []float64 {
	out := d.FitColumns(weights)
	fixed := make([]bool, len(out))
	for changed := true; changed; {
		changed = false
		free, freeWeight := d.ContentWidth(), 0.0
		for i := range out {
			if !fixed[i] && i < len(mins) && out[i] < mins[i] {
				fixed[i], changed = true, true
			}
			if fixed[i] {
				free -= mins[i]
			} else {
				freeWeight += weights[i]
			}
		}
		for i := range out {
			switch {
			case fixed[i]:
				out[i] = mins[i]
			case freeWeight > 0:
				out[i] = free * weights[i] / freeWeight
			}
		}
	}
	return out
}

// drawWrappedRow 畫一列自動折行的儲存格。
//
// 整列放得進本頁剩餘高度就整列畫；放不下而本頁已有資料列時先換頁（表頭隨之重畫）；
// 單一列比一整頁還高時才逐頁分段畫，每段各自成框，文字一個不少。
func (d *Doc) drawWrappedRow(cols []Column, row []string, fill bool) {
	lines := make([][]string, len(cols))
	total := 1
	for j, col := range cols {
		lines[j] = d.wrapLines(cellAt(row, j), col.Width-2*d.pdf.GetCellMargin())
		if len(lines[j]) > total {
			total = len(lines[j])
		}
	}
	for from := 0; from < total; {
		fit := int((d.remainingHeight() - 2*padTableWrap + widthEpsilon) / lineTableWrap)
		switch {
		case fit < total-from && !d.atTableTop() && (from == 0 || fit < 1):
			// 整列放不下而本頁已有資料列：換頁後整列重來
			d.nextTablePage(fill)
			continue
		case fit < 1:
			// 表頭之下連一行都放不下（表頭本身幾乎佔滿一頁）：照樣放一行，避免無窮換頁
			fit = 1
		}
		n := total - from
		if fit < n {
			n = fit
		}
		d.drawRowSlice(cols, lines, from, n, fill)
		from += n
		if from < total {
			d.nextTablePage(fill)
		}
	}
}

// nextTablePage 表格中途換頁（表頭由換頁回呼重畫），並恢復資料列的字級與底色。
func (d *Doc) nextTablePage(fill bool) {
	d.addPageLikeCurrent()
	d.setFont(sizeTable)
	if fill {
		d.pdf.SetFillColor(colorZebraBg[0], colorZebraBg[1], colorZebraBg[2])
	}
}

// drawRowSlice 畫一列中第 from 行起的 n 行（各欄同步），畫完 Y 停在該段下緣。
func (d *Doc) drawRowSlice(cols []Column, lines [][]string, from, n int, fill bool) {
	h := float64(n)*lineTableWrap + 2*padTableWrap
	top, x := d.pdf.GetY(), marginLeft
	style := "D"
	if fill {
		style = "FD"
	}
	d.setInk(colorInk)
	for j, col := range cols {
		d.pdf.Rect(x, top, col.Width, h, style)
		for k := from; k < from+n && k < len(lines[j]); k++ {
			d.pdf.SetXY(x, top+padTableWrap+float64(k-from)*lineTableWrap)
			d.pdf.CellFormat(col.Width, lineTableWrap, lines[j][k], "", 0, alignOf(col), false, 0, "")
		}
		x += col.Width
	}
	d.pdf.SetXY(marginLeft, top+h)
}

// atTableTop 目前位置是否緊接在本頁表頭之下（本頁尚未畫任何資料列）。
func (d *Doc) atTableTop() bool {
	return d.pdf.GetY() <= d.tableTop+widthEpsilon
}

// tableHeaderHeight 表頭高度（折行表頭隨最長的欄名增高）。
func (d *Doc) tableHeaderHeight(t Table) float64 {
	if !t.Wrap {
		return lineTableRow
	}
	d.setFont(sizeTable)
	defer d.setFont(sizeBody)
	return float64(d.headerLineCount(t.Columns))*lineTableWrap + 2*padTableWrap
}

func (d *Doc) headerLineCount(cols []Column) int {
	n := 1
	for _, col := range cols {
		if c := len(d.wrapLines(col.Title, col.Width-2*d.pdf.GetCellMargin())); c > n {
			n = c
		}
	}
	return n
}

// drawHeaderFor 依表格的折行設定畫表頭，並記下表頭下緣（判斷本頁是否已有資料列）。
func (d *Doc) drawHeaderFor(t Table) {
	if !t.Wrap {
		d.drawTableHeader(t.Columns)
		d.tableTop = d.pdf.GetY()
		return
	}
	d.setFont(sizeTable)
	d.setInk(colorInk)
	d.pdf.SetFillColor(colorHeaderBg[0], colorHeaderBg[1], colorHeaderBg[2])
	d.pdf.SetDrawColor(colorRule[0], colorRule[1], colorRule[2])
	d.pdf.SetLineWidth(0.2)
	lines := make([][]string, len(t.Columns))
	for j, col := range t.Columns {
		lines[j] = d.wrapLines(col.Title, col.Width-2*d.pdf.GetCellMargin())
	}
	d.pdf.SetX(marginLeft)
	d.drawRowSlice(t.Columns, lines, 0, d.headerLineCount(t.Columns), true)
	d.tableTop = d.pdf.GetY()
}

// drawTableHeader 畫一列表頭（首次與每次換頁各一次）。
func (d *Doc) drawTableHeader(cols []Column) {
	d.setFont(sizeTable)
	d.setInk(colorInk)
	d.pdf.SetFillColor(colorHeaderBg[0], colorHeaderBg[1], colorHeaderBg[2])
	d.pdf.SetDrawColor(colorRule[0], colorRule[1], colorRule[2])
	d.pdf.SetLineWidth(0.2)
	d.pdf.SetX(marginLeft)
	for j, col := range cols {
		ln := 0
		if j == len(cols)-1 {
			ln = 1
		}
		d.pdf.CellFormat(col.Width, lineTableRow, d.truncate(col.Title, col.Width-2),
			"1", ln, alignOf(col), true, 0, "")
	}
}

func cellAt(row []string, j int) string {
	if j < len(row) {
		return row[j]
	}
	return ""
}

func alignOf(col Column) string {
	if col.Align == "" {
		return "L"
	}
	return col.Align
}
