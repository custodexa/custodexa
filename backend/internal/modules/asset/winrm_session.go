package asset

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/masterzen/winrm"
)

// WinRM 工作階段：一條 WS-Man 序列（Create Shell → Command → Send → Receive… → Signal → Delete），
// 單一 goroutine 依序驅動，逾時由外層計時器以 context 取消收口。
//
// 順序固定是刻意的：標準輸入的 Send 一定先於第一次 Receive。目標的 Receive 會阻塞到有
// 輸出或 OperationTimeout 為止，若讓輪詢先搶到傳輸，腳本在 ReadLine 上等密碼、
// 我方在 Receive 上等輸出，要等到 60 秒的 OperationTimeout 才解開。

const (
	// winrmDialTimeout 建立 shell（含首次 NTLM 交握）的上限；真機首次連線實測 9–14 秒
	winrmDialTimeout = 30 * time.Second
	// winrmCommandTimeout 指令自送出到回報完成的上限，與 SSH 通道共用同一個值
	winrmCommandTimeout = windowsCommandTimeout
	// winrmOperationTimeout WS-Man 標頭的 OperationTimeout（目標對單一請求的回應上限）
	winrmOperationTimeout = "PT60S"
	winrmLocale           = "en-US"
	winrmEnvelopeSize     = 153600
	// winrmStderrLimit 只保留 stderr 的前段供診斷（cause 只進後端 log，仍不留整段原文）
	winrmStderrLimit = 512
	// winrmStdoutLimit 只保留 stdout 的前段：改密腳本的結果標記在此，其餘輸出不需要
	winrmStdoutLimit = 4096
)

// winrmDialError 建立 shell 階段的失敗：指令尚未送出，遠端確定未被觸碰。
//
// 包成專屬型別是為了讓執行器分得出「指令送出前」與「送出後」的失敗——前者可以
// 依成因分流成確定失敗，後者一律狀態不可知。
type winrmDialError struct {
	cause error
}

func (e *winrmDialError) Error() string { return "winrm: create shell: " + e.cause.Error() }
func (e *winrmDialError) Unwrap() error { return e.cause }

// winrmOutcome 一次執行的結果；err 為 nil 時 exitCode、stdout、stderr 才有意義。
type winrmOutcome struct {
	exitCode int
	stdout   string
	stderr   string
	err      error
}

// winrmSession 一次操作（改密或驗證）的工作階段。用完即棄：驗證一律以新密碼另建。
type winrmSession struct {
	tr     *winrmTransport
	params winrm.Parameters
	cancel context.CancelFunc
}

// newWinRMSession 依資產的通道設定建立工作階段。
func newWinRMSession(ctx context.Context, asset *model.Asset, username, password string,
	newSecurity winrmSecurityFactory, dialTimeout time.Duration) (*winrmSession, error) {
	if asset.WinrmScheme != model.WinrmSchemeHTTP && asset.WinrmScheme != model.WinrmSchemeHTTPS {
		return nil, fmt.Errorf("winrm: unknown scheme %q", asset.WinrmScheme)
	}
	tlsCfg, err := winrmTLSConfig(asset)
	if err != nil {
		return nil, err
	}
	opCtx, cancel := context.WithCancel(ctx)
	return &winrmSession{
		tr: &winrmTransport{
			ctx:         opCtx,
			hc:          newWinRMHTTPClient(tlsCfg, dialTimeout),
			url:         winrmEndpointURL(asset),
			username:    username,
			password:    password,
			newSecurity: newSecurity,
		},
		params: winrm.Parameters{Timeout: winrmOperationTimeout, Locale: winrmLocale, EnvelopeSize: winrmEnvelopeSize},
		cancel: cancel,
	}, nil
}

// run 執行一條命令列，stdin 非空時先投遞標準輸入。
//
// 兩段計時：dialTimeout 蓋建立 shell，commandTimeout 蓋其後全部。任一到期即取消 context
// （所有在飛與後續的 HTTP 請求立刻失敗）並回逾時錯誤。兩段逾時的語義不同：建立 shell
// 逾時發生在指令送出前，包成 winrmDialError 讓執行器分成確定失敗；指令逾時發生在送出後，
// 是狀態不可知。計時器到期與 shell 剛建立同時發生時以 dialed 為準——那一刻指令即將送出，
// 只能交給指令計時器，不能再當成「未送出」。
func (s *winrmSession) run(command, stdin string, dialTimeout, commandTimeout time.Duration) winrmOutcome {
	defer s.cancel()
	dialed := make(chan struct{})
	done := make(chan winrmOutcome, 1)
	go func() { done <- s.execute(command, stdin, dialed) }()

	dialTimer := time.NewTimer(dialTimeout)
	defer dialTimer.Stop()
	select {
	case <-dialed:
	case out := <-done:
		return out
	case <-dialTimer.C:
		select {
		case <-dialed:
		default:
			s.cancel()
			return winrmOutcome{err: &winrmDialError{cause: fmt.Errorf("shell creation timed out after %s", dialTimeout)}}
		}
	}

	commandTimer := time.NewTimer(commandTimeout)
	defer commandTimer.Stop()
	select {
	case out := <-done:
		return out
	case <-commandTimer.C:
		s.cancel()
		return winrmOutcome{err: fmt.Errorf("winrm: command timed out after %s", commandTimeout)}
	}
}

// execute WS-Man 序列本體。dialed 在 shell 建立後關閉，供 run 切換計時器。
func (s *winrmSession) execute(command, stdin string, dialed chan<- struct{}) winrmOutcome {
	defer s.tr.hc.CloseIdleConnections()
	p := &s.params
	url := s.tr.url

	resp, err := s.tr.post(winrm.NewOpenShellRequest(url, p))
	if err != nil {
		return winrmOutcome{err: &winrmDialError{cause: err}}
	}
	shellID, err := winrm.ParseOpenShellResponse(resp)
	if err != nil {
		return winrmOutcome{err: &winrmDialError{cause: err}}
	}
	close(dialed)
	defer func() { _, _ = s.tr.post(winrm.NewDeleteShellRequest(url, shellID, p)) }()

	resp, err = s.tr.post(winrm.NewExecuteCommandRequest(url, shellID, command, nil, p))
	if err != nil {
		return winrmOutcome{err: err}
	}
	commandID, err := winrm.ParseExecuteCommandResponse(resp)
	if err != nil {
		return winrmOutcome{err: err}
	}
	defer func() { _, _ = s.tr.post(winrm.NewSignalRequest(url, shellID, commandID, p)) }()

	// 標準輸入：資料一則、EOF 一則（目標以 End 旗標得知輸入結束）
	if stdin != "" {
		if _, err := s.tr.post(winrm.NewSendInputRequest(url, shellID, commandID, []byte(stdin), false, p)); err != nil {
			return winrmOutcome{err: err}
		}
	}
	if _, err := s.tr.post(winrm.NewSendInputRequest(url, shellID, commandID, nil, true, p)); err != nil {
		return winrmOutcome{err: err}
	}

	var stdout, stderr bytes.Buffer
	for {
		resp, err := s.tr.post(winrm.NewGetOutputRequest(url, shellID, commandID, "stdout stderr", p))
		if err != nil {
			return winrmOutcome{err: err}
		}
		if isWSManFault(resp) {
			if isWSManOperationTimeout(resp) {
				// 目標在 OperationTimeout 內沒有輸出：合法，繼續等；外層計時器管總上限
				continue
			}
			return winrmOutcome{err: errors.New("winrm: receive returned a fault")}
		}
		finished, exitCode, err := winrm.ParseSlurpOutputErrResponse(resp,
			limitedWriter{&stdout, winrmStdoutLimit}, limitedWriter{&stderr, winrmStderrLimit})
		if err != nil {
			return winrmOutcome{err: err}
		}
		if finished {
			return winrmOutcome{exitCode: exitCode, stdout: stdout.String(), stderr: stderr.String()}
		}
	}
}

// isWSManFault 回應的 action 是否為 WS-Man fault。
func isWSManFault(resp string) bool {
	return strings.Contains(resp, "http://schemas.dmtf.org/wbem/wsman/1/wsman/fault")
}

// isWSManOperationTimeout fault 是否為 OperationTimeout（subcode TimedOut）。
func isWSManOperationTimeout(resp string) bool {
	return strings.Contains(resp, "TimedOut") || strings.Contains(resp, "OperationTimeout")
}

// limitedWriter 只保留前 n 位元組，其餘丟棄（不回錯，避免中斷輸出解析）。
type limitedWriter struct {
	buf *bytes.Buffer
	n   int
}

func (w limitedWriter) Write(p []byte) (int, error) {
	if room := w.n - w.buf.Len(); room > 0 {
		keep := p
		if len(keep) > room {
			keep = keep[:room]
		}
		w.buf.Write(keep)
	}
	return len(p), nil
}
