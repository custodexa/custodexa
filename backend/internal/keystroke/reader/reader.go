// Package reader 讀取鍵盤紀錄檔並給出完整性判定。
//
// 開檔前先限制路徑在根目錄內並以 O_NOFOLLOW 開檔，開檔後核對標頭與紀錄列
// （紀錄 UUID、會話 id、協定）。讀取器不印出任何事件內容；錯誤只描述位置與類別。
package reader

import (
	"bufio"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/custodexa/backend/internal/keystroke/format"
	"github.com/custodexa/backend/internal/keystroke/sealer"
)

// Status 為完整性判定。
type Status string

const (
	StatusComplete       Status = "complete"
	StatusTruncated      Status = "truncated"
	StatusTampered       Status = "tampered"
	StatusFileMissing    Status = "file_missing"
	StatusPathRejected   Status = "path_rejected"
	StatusHeaderMismatch Status = "header_mismatch"
)

// Record 為紀錄列中與讀取有關的欄位。
type Record struct {
	UUID      string
	SessionID uint64
	Protocol  string
	FilePath  string
	// ExpectComplete 為真表示紀錄列已是 complete：寫入端已封出結束段才會走到這個狀態，
	// 檔案若缺結束段或段數少於 SegmentCount，代表已封出的內容事後消失，判 tampered。
	// 紀錄列仍是 recording／incomplete／failed 時為假，缺結束段維持 truncated。
	ExpectComplete bool
	SegmentCount   int64
}

// Options 控制回傳的事件視窗。Limit 為 0 表示不限。
type Options struct {
	FromEvent int
	Limit     int
}

// Result 為讀取結果。Events 只含視窗內的事件；TotalEvents 為所有已驗證事件數。
// 判定為 truncated 或 tampered 時，失敗點之前的段照常交出。
type Result struct {
	Status        Status
	Header        format.Header
	Events        []format.Event
	TotalEvents   int
	SegmentsRead  int
	FailedSegment int // tampered 時為首個失敗段序號；其餘為 -1
	LastDeltaMs   uint64
}

// maxFrame 限制單段密文長度，超過者視為長度欄被竄改。
const maxFrame = sealer.MaxFrame

// ResolveInRoot 將相對路徑解為根目錄內的絕對路徑；越界回錯誤。
func ResolveInRoot(root, rel string) (string, error) {
	if rel == "" || filepath.IsAbs(rel) {
		return "", errors.New("path rejected")
	}
	clean := filepath.Clean(rel)
	r, err := filepath.Rel(".", clean)
	if err != nil || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) {
		return "", errors.New("path rejected")
	}
	full := filepath.Join(root, clean)
	// 上層目錄若為符號連結，其實體位置也必須在根目錄內
	rootReal, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	dirReal, err := filepath.EvalSymlinks(filepath.Dir(full))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return full, nil
		}
		return "", err
	}
	back, err := filepath.Rel(rootReal, dirReal)
	if err != nil || back == ".." || strings.HasPrefix(back, ".."+string(filepath.Separator)) {
		return "", errors.New("path rejected")
	}
	return full, nil
}

func uuidBytes(s string) ([format.UUIDLen]byte, bool) {
	var out [format.UUIDLen]byte
	raw, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	if err != nil || len(raw) != format.UUIDLen {
		return out, false
	}
	copy(out[:], raw)
	return out, true
}

// Read 讀取並驗證紀錄檔。fek 為已解封的 32-byte 檔案金鑰。
func Read(root string, rec Record, fek []byte, opt Options) Result {
	res := Result{FailedSegment: -1}
	full, err := ResolveInRoot(root, rec.FilePath)
	if err != nil {
		res.Status = StatusPathRejected
		return res
	}
	f, err := os.OpenFile(full, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		switch {
		case errors.Is(err, os.ErrNotExist):
			res.Status = StatusFileMissing
		default:
			// 符號連結（ELOOP）與其他無法安全開啟者一律視為路徑被拒
			res.Status = StatusPathRejected
		}
		return res
	}
	defer f.Close()
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		res.Status = StatusPathRejected
		return res
	}
	return readStream(f, rec, fek, opt)
}

func readStream(r io.Reader, rec Record, fek []byte, opt Options) Result {
	res := readFrames(r, rec, fek, opt)
	if rec.ExpectComplete {
		switch {
		case res.Status == StatusTruncated:
			res.Status = StatusTampered
			res.FailedSegment = res.SegmentsRead
		case res.Status == StatusComplete && int64(res.SegmentsRead) < rec.SegmentCount:
			res.Status = StatusTampered
			res.FailedSegment = res.SegmentsRead
		}
	}
	return res
}

// frameSlack 為單段密文長度在 SegmentMax 之上額外容許的量（單筆大事件可使一段超出封段門檻）。
const frameSlack = 4 << 20

// frameLimit 回傳單段密文長度上限。標頭的 SegmentMax 未經驗證前不可全信，
// 自身也封頂，避免標頭被改大後再度開出大配置。
func frameLimit(segMax uint32) uint64 {
	m := uint64(segMax)
	if m > 1<<20 {
		m = 1 << 20
	}
	return m + frameSlack + 16
}

func readFrames(r io.Reader, rec Record, fek []byte, opt Options) Result {
	res := Result{FailedSegment: -1}
	br := bufio.NewReaderSize(r, 64<<10)

	// 標頭：長度不定，先讀足固定部分再依協定長度補足
	head := make([]byte, 0, 96)
	buf := make([]byte, 1)
	var hdr format.Header
	var hdrLen int
	for {
		h, n, err := format.DecodeHeader(head)
		if err == nil {
			hdr, hdrLen = h, n
			break
		}
		if !errors.Is(err, format.ErrShortHeader) {
			res.Status = StatusTampered
			return res
		}
		if _, rerr := io.ReadFull(br, buf); rerr != nil {
			res.Status = StatusTruncated
			return res
		}
		head = append(head, buf[0])
	}
	hdrBytes := head[:hdrLen]
	res.Header = hdr

	wantUUID, ok := uuidBytes(rec.UUID)
	if !ok || wantUUID != hdr.RecordUUID || hdr.SessionID != rec.SessionID || hdr.Protocol != rec.Protocol {
		res.Status = StatusHeaderMismatch
		return res
	}
	suite, err := sealer.NewSuite(fek, hdr, hdrBytes)
	if err != nil {
		res.Status = StatusTampered
		return res
	}

	var seq uint32
	sawFinal := false
	for {
		var lenField [4]byte
		n, err := io.ReadFull(br, lenField[:])
		if err != nil {
			if n == 0 && errors.Is(err, io.EOF) {
				break
			}
			if sawFinal {
				res.Status = StatusTampered
				res.FailedSegment = int(seq)
				return res
			}
			res.Status = StatusTruncated
			return res
		}
		if sawFinal {
			// 結束段之後不應再有資料
			res.Status = StatusTampered
			res.FailedSegment = int(seq)
			return res
		}
		ctLen, final := sealer.ParseLen(lenField)
		if ctLen < 16 || ctLen >= maxFrame || uint64(ctLen) > frameLimit(hdr.SegmentMax) {
			res.Status = StatusTampered
			res.FailedSegment = int(seq)
			return res
		}
		ct := make([]byte, ctLen)
		if _, err := io.ReadFull(br, ct); err != nil {
			res.Status = StatusTruncated
			return res
		}
		plain, err := suite.Open(seq, ct, final)
		if err != nil {
			res.Status = StatusTampered
			res.FailedSegment = int(seq)
			return res
		}
		evs, derr := format.DecodeEvents(plain)
		for i := range evs {
			idx := res.TotalEvents
			if idx >= opt.FromEvent && (opt.Limit <= 0 || len(res.Events) < opt.Limit) {
				res.Events = append(res.Events, evs[i])
			}
			res.TotalEvents++
			res.LastDeltaMs = evs[i].DeltaMs
		}
		if derr != nil {
			// 段通過驗證但內容無法解碼：視為格式損壞
			res.Status = StatusTampered
			res.FailedSegment = int(seq)
			return res
		}
		res.SegmentsRead++
		seq++
		if final {
			sawFinal = true
		}
	}
	if sawFinal {
		res.Status = StatusComplete
	} else {
		res.Status = StatusTruncated
	}
	return res
}
