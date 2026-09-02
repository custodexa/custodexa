package pdfdoc

// 文字類區塊：標題、段落、鍵值、指標格、說明。全部只收已翻譯的字串。

// CoverTitle 封面主標題與副標題。
func (d *Doc) CoverTitle(title, subtitle string) {
	d.setFont(sizeTitle)
	d.setInk(colorInk)
	d.pdf.SetX(marginLeft)
	d.pdf.CellFormat(d.ContentWidth(), 10, title, "", 1, "L", false, 0, "")
	if subtitle != "" {
		d.setFont(sizeBody)
		d.setInk(colorMuted)
		d.pdf.SetX(marginLeft)
		d.pdf.CellFormat(d.ContentWidth(), 5, subtitle, "", 1, "L", false, 0, "")
	}
	d.setInk(colorInk)
	d.pdf.Ln(3)
	d.rule()
	d.pdf.Ln(3)
}

// SectionTitle 段落標題（含上方留白與底線）。
func (d *Doc) SectionTitle(title string) {
	d.ensureSpace(18)
	d.pdf.Ln(2)
	d.setFont(sizeSection)
	d.setInk(colorInk)
	d.pdf.SetX(marginLeft)
	d.pdf.CellFormat(d.ContentWidth(), 7, title, "", 1, "L", false, 0, "")
	d.rule()
	d.pdf.Ln(2)
	d.setFont(sizeBody)
}

// Paragraph 一段說明文字（自動折行）。
func (d *Doc) Paragraph(text string) {
	if text == "" {
		return
	}
	d.setFont(sizeBody)
	d.setInk(colorInk)
	d.pdf.SetX(marginLeft)
	d.pdf.MultiCell(d.ContentWidth(), lineBody, text, "", "L", false)
	d.pdf.Ln(1)
}

// KV 一組鍵值。
type KV struct {
	Key   string
	Value string
}

// KeyValues 鍵值區：左欄鍵、右欄值，逐列排。
func (d *Doc) KeyValues(rows []KV) {
	const keyWidth = 42.0
	d.setFont(sizeBody)
	for _, r := range rows {
		d.ensureSpace(lineBody + 1)
		d.pdf.SetX(marginLeft)
		d.setInk(colorMuted)
		d.pdf.CellFormat(keyWidth, lineBody, d.truncate(r.Key, keyWidth-2), "", 0, "L", false, 0, "")
		d.setInk(colorInk)
		d.pdf.MultiCell(d.ContentWidth()-keyWidth, lineBody, r.Value, "", "L", false)
	}
	d.pdf.Ln(1)
}

// Metric 一格指標。
type Metric struct {
	Label string
	Value string
	// Note 值下方的小字（口徑或補充），可空。
	Note string
}

// MetricCells 指標格：每列 perRow 格，等寬。
func (d *Doc) MetricCells(cells []Metric, perRow int) {
	if len(cells) == 0 {
		return
	}
	if perRow <= 0 {
		perRow = 6
	}
	const cellHeight = 17.0
	w := d.ContentWidth() / float64(perRow)
	for i := 0; i < len(cells); i += perRow {
		end := i + perRow
		if end > len(cells) {
			end = len(cells)
		}
		d.ensureSpace(cellHeight + 2)
		top := d.pdf.GetY()
		for j, c := range cells[i:end] {
			x := marginLeft + float64(j)*w
			d.pdf.SetDrawColor(colorRule[0], colorRule[1], colorRule[2])
			d.pdf.SetLineWidth(0.2)
			d.pdf.Rect(x, top, w, cellHeight, "D")

			d.pdf.SetXY(x+2, top+2)
			d.setFont(sizeSmall)
			d.setInk(colorMuted)
			d.pdf.CellFormat(w-4, 4, d.truncate(c.Label, w-4), "", 0, "L", false, 0, "")

			d.pdf.SetXY(x+2, top+6.5)
			d.setFont(sizeSection + 2)
			d.setInk(colorInk)
			d.pdf.CellFormat(w-4, 7, d.truncate(c.Value, w-4), "", 0, "L", false, 0, "")

			if c.Note != "" {
				d.pdf.SetXY(x+2, top+13)
				d.setFont(sizeFooter)
				d.setInk(colorMuted)
				d.pdf.CellFormat(w-4, 3.5, d.truncate(c.Note, w-4), "", 0, "L", false, 0, "")
			}
		}
		d.pdf.SetXY(marginLeft, top+cellHeight)
	}
	d.setInk(colorInk)
	d.setFont(sizeBody)
	d.pdf.Ln(3)
}

// NoteBlock 口徑說明區塊：淺底框內逐條列出。
//
// 固定印在報告上而非另附文件：讀者手上只會有這一份 PDF，
// 而每個數字的口徑決定它能不能被當成證據使用。
func (d *Doc) NoteBlock(title string, lines []string) {
	if len(lines) == 0 {
		return
	}
	d.setFont(sizeSmall)
	height := 4.0
	if title != "" {
		height += 5
	}
	for _, ln := range lines {
		height += float64(d.lineCount(ln, d.ContentWidth()-8)) * 4.2
	}
	d.ensureSpace(height + 4)

	top := d.pdf.GetY()
	d.pdf.SetFillColor(colorZebraBg[0], colorZebraBg[1], colorZebraBg[2])
	d.pdf.SetDrawColor(colorRule[0], colorRule[1], colorRule[2])
	d.pdf.Rect(marginLeft, top, d.ContentWidth(), height, "FD")

	y := top + 2
	if title != "" {
		d.pdf.SetXY(marginLeft+4, y)
		d.setFont(sizeBody)
		d.setInk(colorInk)
		d.pdf.CellFormat(d.ContentWidth()-8, 5, title, "", 0, "L", false, 0, "")
		y += 5
	}
	d.setFont(sizeSmall)
	d.setInk(colorMuted)
	for _, ln := range lines {
		d.pdf.SetXY(marginLeft+4, y)
		d.pdf.MultiCell(d.ContentWidth()-8, 4.2, "・"+ln, "", "L", false)
		y = d.pdf.GetY()
	}
	d.pdf.SetXY(marginLeft, top+height)
	d.setInk(colorInk)
	d.setFont(sizeBody)
	d.pdf.Ln(2)
}

// lineCount 概估一段文字在給定寬度下佔幾行（區塊預留高度用）。
func (d *Doc) lineCount(s string, width float64) int {
	if s == "" {
		return 1
	}
	n := int(d.pdf.GetStringWidth("・"+s)/width) + 1
	return n
}

// rule 一條版心寬的細線。
func (d *Doc) rule() {
	y := d.pdf.GetY()
	d.pdf.SetDrawColor(colorRule[0], colorRule[1], colorRule[2])
	d.pdf.SetLineWidth(0.2)
	d.pdf.Line(marginLeft, y, marginLeft+d.ContentWidth(), y)
}
