package localpty

import (
	"bytes"
	"os"
)

// maxSwallowBytes 注入後「吞掉回顯」的位元組上限。
// 正常情況下 client 讀完密碼會立刻輸出換行（實測 psql／mariadb 皆為 "\r\n"），
// 上限只是不讓異常 client 把整個會話吞掉。超限時剩餘位元組一律丟棄而非放行——
// 唯一會落在這段的東西是密碼本身的回顯。
const maxSwallowBytes = 4096

// PasswordAuth 以 PTY 提示注入提供密碼：憑證不進子程序環境、不進 argv，
// 只在 client 實際開口要密碼的那一刻寫進終端。
//
// 為什麼不用環境變數（db-cli-shell-escape-hardening 第二輪的 P0）：
// psql 的 `\lo_import` 是二進位讀取原語，可完整讀出 `/proc/<pid>/environ`，
// 且同一降權身分的會話彼此都讀得到——密碼只要進過子程序環境就等於公開。
type PasswordAuth struct {
	// Password 要注入的明文密碼（不含換行）
	Password string
	// Prompt client 索取密碼時輸出的完整提示字串（含結尾空白）。
	// 比對方式為「輸出區塊的結尾恰為此字串」——提示之後 client 必然停下等輸入，
	// 故真提示永遠落在區塊尾端。
	Prompt string
	// RequireCanonical 是否要求 PTY 處於 ICANON && !ECHO 才注入。
	// psql／mariadb 讀密碼時必為此態，互動 readline 則否，可據以排除
	// 「查詢結果剛好以提示字串結尾」的偽提示；redis-cli --askpass 走遮罩式
	// raw 讀取，無此判準可用（false）。
	RequireCanonical bool
}

// promptAuth 提示注入器：夾在 ptmx 與呼叫端之間過濾輸出。
// 只由 Conn.Read 的單一 goroutine 驅動，內部狀態無須加鎖。
//
// 三個不變式：
//  1. 提示字串本身不會流出（不進錄影、不進監看、不進審計虛擬螢幕）。
//  2. 注入至多一次（injectOnce）：實測同 user/host/port 的 psql `\connect` 會重用
//     已快取的密碼而不再提示，故「第一次成功注入之後又出現同名提示」必然代表
//     client 正連往別的 host/port——那正是不該把密碼送出去的情境。
//  3. 注入後到第一個換行之間的輸出全部丟棄，避免回顯競態把密碼寫進錄影。
type promptAuth struct {
	cfg   PasswordAuth
	ptmx  *os.File
	write func([]byte) (int, error)

	armed     bool
	held      []byte // 尾端疑似被切斷的提示前綴，暫扣不輸出
	out       []byte // 已過濾、待交給呼叫端的位元組
	swallow   bool
	swallowed int
	readErr   error
	buf       []byte
}

func newPromptAuth(cfg PasswordAuth, ptmx *os.File, write func([]byte) (int, error)) *promptAuth {
	return &promptAuth{cfg: cfg, ptmx: ptmx, write: write, armed: true}
}

// Read 供 Conn.Read 使用：回傳過濾後的輸出
func (a *promptAuth) Read(p []byte) (int, error) {
	for {
		if len(a.out) > 0 {
			n := copy(p, a.out)
			a.out = a.out[n:]
			return n, nil
		}
		if a.readErr != nil {
			return 0, a.readErr
		}
		if len(a.buf) < len(p) {
			a.buf = make([]byte, len(p))
		}
		n, err := a.ptmx.Read(a.buf[:len(p)])
		if n > 0 {
			a.process(a.buf[:n])
		}
		if err != nil {
			a.readErr = err
			// 收線時把暫扣的位元組還給呼叫端（它終究不是提示）
			a.out = append(a.out, a.held...)
			a.held = nil
			if len(a.out) == 0 {
				return 0, err
			}
		}
	}
}

// process 過濾一段原始輸出：必要時注入密碼、丟棄提示與回顯
func (a *promptAuth) process(chunk []byte) {
	data := chunk
	if len(a.held) > 0 {
		data = append(append([]byte{}, a.held...), chunk...)
		a.held = nil
	}

	if a.swallow {
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			a.swallow = false
			data = data[i+1:]
		} else {
			a.swallowed += len(data)
			if a.swallowed <= maxSwallowBytes {
				return
			}
			a.swallow = false
			return
		}
	}

	if a.armed {
		prompt := []byte(a.cfg.Prompt)
		if bytes.HasSuffix(data, prompt) && a.atPasswordPrompt() {
			a.out = append(a.out, data[:len(data)-len(prompt)]...)
			a.armed = false
			a.swallow = true
			a.swallowed = 0
			pw := make([]byte, 0, len(a.cfg.Password)+1)
			pw = append(pw, a.cfg.Password...)
			pw = append(pw, '\n')
			_, _ = a.write(pw)
			return
		}
		// 提示可能跨兩次 read 被切斷：尾端若是提示的真前綴就先扣住。
		// 只在武裝期間（認證前）扣，故不影響一般互動輸出。
		if n := promptPrefixLen(data, prompt); n > 0 {
			a.out = append(a.out, data[:len(data)-n]...)
			a.held = append([]byte{}, data[len(data)-n:]...)
			return
		}
		// 沒有提示的影子：client 已進入互動行編輯（或本 client 無此判準），
		// 認證階段結束，此後零介入
		if !a.cfg.RequireCanonical || a.interactiveReached() {
			a.armed = false
		}
	}
	a.out = append(a.out, data...)
}

// atPasswordPrompt client 是否確實停在「讀密碼」的行紀律狀態
func (a *promptAuth) atPasswordPrompt() bool {
	if !a.cfg.RequireCanonical {
		return true
	}
	st, ok := ttyLineState(a.ptmx)
	return ok && st.canonical && !st.echo
}

// interactiveReached client 是否已進入 readline 互動模式（ICANON 關閉）
func (a *promptAuth) interactiveReached() bool {
	st, ok := ttyLineState(a.ptmx)
	return ok && !st.canonical
}

// promptPrefixLen data 尾端與 prompt 開頭重疊的最長長度（不含完整命中）
func promptPrefixLen(data, prompt []byte) int {
	max := len(prompt) - 1
	if len(data) < max {
		max = len(data)
	}
	for l := max; l > 0; l-- {
		if bytes.Equal(data[len(data)-l:], prompt[:l]) {
			return l
		}
	}
	return 0
}
