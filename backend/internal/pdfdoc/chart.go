package pdfdoc

import "fmt"

// 圖形區塊：橫向堆疊長條與圓環。
//
// **以繪圖原語畫，不引入圖表函式庫**：這裡要的只有兩種圖，且兩種都是
// 「一組比例」的直接呈現；為此拉進一整個繪圖生態的相依與其攻擊面不划算。

// Segment 堆疊長條的一段。
type Segment struct {
	Label string
	Value int
	// Shade 0–255 的灰階填色；同一份文件內各段應互異，以便黑白列印仍可分辨。
	Shade int
}

// StackedBar 一條橫向堆疊長條與其圖例。
type StackedBar struct {
	Segments []Segment
	// EmptyText 全部為零時印出的字。
	EmptyText string
}

// StackedBar 畫堆疊長條與圖例（每段標籤與數量）。
func (d *Doc) StackedBar(b StackedBar) {
	total := 0
	for _, s := range b.Segments {
		if s.Value > 0 {
			total += s.Value
		}
	}
	const barHeight = 8.0
	d.ensureSpace(barHeight + 14)
	top := d.pdf.GetY()

	if total == 0 {
		d.setFont(sizeSmall)
		d.setInk(colorMuted)
		d.pdf.SetXY(marginLeft, top)
		d.pdf.CellFormat(d.ContentWidth(), barHeight, b.EmptyText, "", 1, "L", false, 0, "")
		d.setInk(colorInk)
		d.setFont(sizeBody)
		d.pdf.Ln(2)
		return
	}

	x := marginLeft
	d.pdf.SetDrawColor(255, 255, 255)
	d.pdf.SetLineWidth(0.3)
	for i, s := range b.Segments {
		if s.Value <= 0 {
			continue
		}
		w := d.ContentWidth() * float64(s.Value) / float64(total)
		if i == len(b.Segments)-1 {
			w = marginLeft + d.ContentWidth() - x
		}
		d.pdf.SetFillColor(s.Shade, s.Shade, s.Shade)
		d.pdf.Rect(x, top, w, barHeight, "F")
		x += w
	}
	d.pdf.SetDrawColor(colorRule[0], colorRule[1], colorRule[2])
	d.pdf.SetLineWidth(0.2)
	d.pdf.Rect(marginLeft, top, d.ContentWidth(), barHeight, "D")

	// 圖例：色塊＋標籤＋數量，四個一列
	d.pdf.SetXY(marginLeft, top+barHeight+2)
	d.setFont(sizeFooter)
	const perRow = 4
	legendW := d.ContentWidth() / perRow
	for i, s := range b.Segments {
		col := i % perRow
		row := i / perRow
		lx := marginLeft + float64(col)*legendW
		ly := top + barHeight + 2 + float64(row)*4.5
		d.pdf.SetFillColor(s.Shade, s.Shade, s.Shade)
		d.pdf.Rect(lx, ly+0.8, 3, 3, "F")
		d.setInk(colorMuted)
		d.pdf.SetXY(lx+4.5, ly)
		d.pdf.CellFormat(legendW-5, 4.5,
			d.truncate(fmt.Sprintf("%s %d", s.Label, s.Value), legendW-5), "", 0, "L", false, 0, "")
	}
	rows := (len(b.Segments) + perRow - 1) / perRow
	d.pdf.SetXY(marginLeft, top+barHeight+2+float64(rows)*4.5)
	d.setInk(colorInk)
	d.setFont(sizeBody)
	d.pdf.Ln(2)
}

// Donut 一個圓環指標。Ratio 為 nil 表示不適用（分母為零），
// 此時只畫空環並印 NotApplicable 文字——印 0% 會被讀成「一個都不合規」。
type Donut struct {
	Label  string
	Ratio  *float64
	Center string
	// Caption 圓環下方的口徑一句話。
	Caption string
}

// Donuts 並排畫多個圓環（等寬分配）。
func (d *Doc) Donuts(items []Donut) {
	if len(items) == 0 {
		return
	}
	const blockHeight = 34.0
	d.ensureSpace(blockHeight + 4)
	top := d.pdf.GetY()
	w := d.ContentWidth() / float64(len(items))
	radius := 11.0

	for i, it := range items {
		cx := marginLeft + float64(i)*w + w/2
		cy := top + radius + 3
		d.drawRing(cx, cy, radius, it.Ratio)

		d.setFont(sizeBody)
		d.setInk(colorInk)
		d.pdf.SetXY(marginLeft+float64(i)*w, cy-2.5)
		d.pdf.CellFormat(w, 5, it.Center, "", 0, "C", false, 0, "")

		d.setFont(sizeSmall)
		d.pdf.SetXY(marginLeft+float64(i)*w, top+2*radius+5)
		d.pdf.CellFormat(w, 4.5, d.truncate(it.Label, w-2), "", 0, "C", false, 0, "")

		if it.Caption != "" {
			d.setFont(sizeFooter)
			d.setInk(colorMuted)
			d.pdf.SetXY(marginLeft+float64(i)*w, top+2*radius+9.5)
			d.pdf.CellFormat(w, 4, d.truncate(it.Caption, w-2), "", 0, "C", false, 0, "")
		}
	}
	d.pdf.SetXY(marginLeft, top+blockHeight)
	d.setInk(colorInk)
	d.setFont(sizeBody)
	d.pdf.Ln(2)
}

// drawRing 以粗線弧畫環：底環為淺灰，已達成的比例以強調色疊上。
func (d *Doc) drawRing(cx, cy, r float64, ratio *float64) {
	const thickness = 4.5
	rr := r - thickness/2
	d.pdf.SetLineWidth(thickness)

	d.pdf.SetDrawColor(colorEmptyPart[0], colorEmptyPart[1], colorEmptyPart[2])
	d.pdf.Arc(cx, cy, rr, rr, 0, 0, 360, "D")

	if ratio == nil {
		d.pdf.SetLineWidth(0.2)
		return
	}
	p := *ratio
	if p < 0 {
		p = 0
	}
	if p > 1 {
		p = 1
	}
	if p > 0 {
		d.pdf.SetDrawColor(colorAccent[0], colorAccent[1], colorAccent[2])
		d.pdf.Arc(cx, cy, rr, rr, 0, 90-360*p, 90, "D")
	}
	d.pdf.SetLineWidth(0.2)
}
