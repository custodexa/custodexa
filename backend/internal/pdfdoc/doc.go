// Package pdfdoc 是本系統產生 PDF 文件的共用版面層。
//
// 職責邊界：**只認文件模型**——標題、鍵值、指標格、表格、堆疊長條、圓環、
// 說明區塊、頁尾——不認任何一種報告的語義。要產出哪些區塊、每個欄位叫什麼、
// 數字怎麼算，全部由呼叫端決定並以已翻譯的字串傳入。
//
// 這條界線的用途：日後新增別種報告時，只需寫一支「資料 → 文件模型」的轉換，
// 不必動這裡的任何一行；而版面的修正也不會意外改到某一種報告的語義。
//
// 字型內嵌於二進位（見 assets 套件），繁體中文與日文共用同一字重。
package pdfdoc

import (
	"fmt"
	"io"

	"github.com/go-pdf/fpdf"

	"github.com/custodexa/backend/assets"
)

// 版面常數（A4 直式，單位公釐）。
const (
	marginLeft   = 14.0
	marginRight  = 14.0
	marginTop    = 14.0
	marginBottom = 18.0

	fontFamily = "NotoCJK"

	sizeTitle   = 17.0
	sizeSection = 12.0
	sizeBody    = 9.0
	sizeSmall   = 8.0
	// sizeTable 表格字級：欄數多的明細表在此字級才不會整欄被裁成刪節號
	sizeTable    = 7.5
	sizeFooter   = 7.0
	lineBody     = 5.0
	lineTableRow = 6.0
)

// TotalPagesToken 頁尾格式字串中代表「總頁數」的位置符號。
//
// 總頁數在最後一頁畫完之前不可知，故先寫入符號、輸出時整份替換。
const TotalPagesToken = "{nb}"

// 灰階與強調色（RGB）。報告以黑白列印為常態，故層次靠灰階而非色相。
var (
	colorInk       = [3]int{33, 37, 41}
	colorMuted     = [3]int{110, 116, 122}
	colorRule      = [3]int{198, 202, 206}
	colorHeaderBg  = [3]int{238, 240, 242}
	colorZebraBg   = [3]int{248, 249, 250}
	colorAccent    = [3]int{35, 87, 145}
	colorEmptyPart = [3]int{224, 227, 230}
)

// Footer 每頁頁尾的四個位置。Page 為含兩個 %s 的格式字串
// （第一個代入目前頁碼，第二個代入總頁數）。
type Footer struct {
	Left   string
	Center string
	Page   string
	// Note 頁尾第二行（完整性依據之類的固定說明）；空字串即不畫。
	Note string
}

// Options 一份文件的固定屬性。
type Options struct {
	// Title 文件屬性中的標題（非版面上的標題，後者由 CoverTitle 畫）。
	Title string
	// Subject 文件屬性中的主旨。
	Subject string
	Footer  Footer
}

// Doc 建構中的文件。非併發安全：一份文件由一個 goroutine 從頭寫到尾。
type Doc struct {
	pdf *fpdf.Fpdf
	// tableHeader 目前正在繪製的表格表頭；非 nil 時換頁會自動重畫。
	tableHeader func()
}

// New 開一份文件並載入字型。回傳後即可開始下區塊（首頁已開好）。
func New(opt Options) (*Doc, error) {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(marginLeft, marginTop, marginRight)
	pdf.SetAutoPageBreak(true, marginBottom)
	pdf.AliasNbPages(TotalPagesToken)
	if opt.Title != "" {
		pdf.SetTitle(opt.Title, true)
	}
	if opt.Subject != "" {
		pdf.SetSubject(opt.Subject, true)
	}

	// 內嵌位元組直接載入：正式版 image 沒有字型檔可讀，寫暫存檔則需要一個
	// 可寫目錄，而那正是正式版刻意不提供的東西
	pdf.AddUTF8FontFromBytes(fontFamily, "", assets.NotoSansCJKTC)
	if err := pdf.Error(); err != nil {
		return nil, fmt.Errorf("載入內嵌字型失敗: %w", err)
	}

	d := &Doc{pdf: pdf}
	pdf.SetHeaderFunc(func() {
		if d.tableHeader != nil {
			d.tableHeader()
		}
	})
	pdf.SetFooterFunc(func() { d.drawFooter(opt.Footer) })
	pdf.AddPage()
	d.setFont(sizeBody)
	return d, nil
}

// NewPage 換到新的一頁（直式）。
func (d *Doc) NewPage() {
	d.pdf.AddPageFormat("P", fpdf.SizeType{Wd: 210, Ht: 297})
}

// NewLandscapePage 換到新的一頁（橫式）。
//
// 欄數多的明細表在直式版心裡每欄不到十公釐，欄名與時刻會整欄被裁成刪節號——
// 那等於把一張表印成看不懂的東西。橫式是為了讓同一組欄位真的讀得出來，
// 不是為了多放內容。自動換頁沿用當前頁向，故表格跨頁後仍是橫式。
func (d *Doc) NewLandscapePage() {
	d.pdf.AddPageFormat("L", fpdf.SizeType{Wd: 210, Ht: 297})
}

// ContentWidth 目前頁向下的版心寬度。
func (d *Doc) ContentWidth() float64 {
	w, _ := d.pdf.GetPageSize()
	return w - marginLeft - marginRight
}

// FitColumns 依權重把版心寬度分給各欄。
func (d *Doc) FitColumns(weights []float64) []float64 {
	var sum float64
	for _, w := range weights {
		sum += w
	}
	out := make([]float64, len(weights))
	if sum <= 0 {
		return out
	}
	cw := d.ContentWidth()
	for i, w := range weights {
		out[i] = cw * w / sum
	}
	return out
}

// Output 收尾並輸出。呼叫後不應再下任何區塊。
func (d *Doc) Output(w io.Writer) error {
	if err := d.pdf.Error(); err != nil {
		return err
	}
	return d.pdf.Output(w)
}

// PageCount 目前頁數（測試與清單檔用）。
func (d *Doc) PageCount() int { return d.pdf.PageCount() }

func (d *Doc) setFont(size float64) {
	d.pdf.SetFont(fontFamily, "", size)
}

func (d *Doc) setInk(c [3]int) {
	d.pdf.SetTextColor(c[0], c[1], c[2])
}

// drawFooter 頁尾兩行：資訊行與說明行。
//
// 總頁數以位置符號寫入，於輸出時整份替換——最後一頁畫完之前它不可知，
// 而每一頁的頁尾都需要它。
func (d *Doc) drawFooter(f Footer) {
	if f.Left == "" && f.Center == "" && f.Page == "" && f.Note == "" {
		return
	}
	pw, h := d.pdf.GetPageSize()
	d.setFont(sizeFooter)
	d.setInk(colorMuted)

	y := h - marginBottom + 4
	d.pdf.SetY(y)
	d.pdf.SetDrawColor(colorRule[0], colorRule[1], colorRule[2])
	d.pdf.SetLineWidth(0.2)
	d.pdf.Line(marginLeft, y-1.5, pw-marginRight, y-1.5)

	page := ""
	if f.Page != "" {
		page = fmt.Sprintf(f.Page, fmt.Sprintf("%d", d.pdf.PageNo()), TotalPagesToken)
	}
	third := (pw - marginLeft - marginRight) / 3
	d.pdf.SetX(marginLeft)
	d.pdf.CellFormat(third, 4, f.Left, "", 0, "L", false, 0, "")
	d.pdf.CellFormat(third, 4, f.Center, "", 0, "C", false, 0, "")
	d.pdf.CellFormat(third, 4, page, "", 1, "R", false, 0, "")
	if f.Note != "" {
		d.pdf.SetX(marginLeft)
		d.pdf.CellFormat(pw-marginLeft-marginRight, 4, f.Note, "", 1, "L", false, 0, "")
	}
	d.setInk(colorInk)
}

// truncate 把字串裁到指定寬度內，裁掉時以刪節號結尾。
//
// 表格欄位收的是使用者資料（資產名、帳號名、備註），長度沒有結構性上界；
// 溢出到隔壁欄會讓整列不可讀，而那一列可能正是稽核要看的那一列。
func (d *Doc) truncate(s string, width float64) string {
	if s == "" || d.pdf.GetStringWidth(s) <= width {
		return s
	}
	const ellipsis = "…"
	limit := width - d.pdf.GetStringWidth(ellipsis)
	if limit <= 0 {
		return ellipsis
	}
	runes := []rune(s)
	for i := len(runes); i > 0; i-- {
		if d.pdf.GetStringWidth(string(runes[:i])) <= limit {
			return string(runes[:i]) + ellipsis
		}
	}
	return ellipsis
}

// ensureSpace 若剩餘高度不足即換頁。
func (d *Doc) ensureSpace(h float64) {
	_, ph := d.pdf.GetPageSize()
	if d.pdf.GetY()+h > ph-marginBottom {
		d.pdf.AddPage()
	}
}
