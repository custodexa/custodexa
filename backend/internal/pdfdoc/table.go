package pdfdoc

// 表格：自動跨頁、每頁重複表頭。

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
}

// Table 畫一張表。跨頁時表頭自動於新頁重畫。
func (d *Doc) Table(t Table) {
	if len(t.Columns) == 0 {
		return
	}
	if len(t.Rows) == 0 {
		if t.EmptyText != "" {
			d.drawTableHeader(t.Columns)
			d.setFont(sizeTable)
			d.setInk(colorMuted)
			d.pdf.SetX(marginLeft)
			d.pdf.CellFormat(d.ContentWidth(), lineTableRow, t.EmptyText, "1", 1, "L", false, 0, "")
			d.setInk(colorInk)
			d.pdf.Ln(2)
		}
		return
	}

	d.ensureSpace(lineTableRow * 3)
	d.drawTableHeader(t.Columns)
	// 換頁回呼在此期間生效：自動分頁時新頁的頂端先重畫表頭，
	// 讀者翻到任何一頁都知道每一欄是什麼
	d.tableHeader = func() { d.drawTableHeader(t.Columns) }
	defer func() { d.tableHeader = nil }()

	d.setFont(sizeTable)
	for i, row := range t.Rows {
		fill := t.Zebra && i%2 == 1
		if fill {
			d.pdf.SetFillColor(colorZebraBg[0], colorZebraBg[1], colorZebraBg[2])
		}
		d.pdf.SetX(marginLeft)
		d.setInk(colorInk)
		for j, col := range t.Columns {
			cell := ""
			if j < len(row) {
				cell = row[j]
			}
			align := col.Align
			if align == "" {
				align = "L"
			}
			ln := 0
			if j == len(t.Columns)-1 {
				ln = 1
			}
			d.pdf.CellFormat(col.Width, lineTableRow, d.truncate(cell, col.Width-2),
				"1", ln, align, fill, 0, "")
		}
	}
	d.setFont(sizeBody)
	d.pdf.Ln(2)
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
		align := col.Align
		if align == "" {
			align = "L"
		}
		d.pdf.CellFormat(col.Width, lineTableRow, d.truncate(col.Title, col.Width-2),
			"1", ln, align, true, 0, "")
	}
}
