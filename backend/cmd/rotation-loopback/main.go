//go:build loopback

// rotation-loopback：Windows 本機帳號改密的真機回歸驅動程式（build tag loopback）。
//
// 由 CI 在 Windows runner 上對 127.0.0.1 呼叫**正式的**改密執行器，每次執行跑一個案例，
// 以 -expect 系列旗標宣告期望的三態／原因碼，不符即非零退出。
//
// 密碼只從環境變數讀（LOOPBACK_PASSWORD、LOOPBACK_NEW_PASSWORD 與 _2 後綴的第二帳號組），
// 不進命令列；所有印出的字串先把已知秘密替換為 [redacted]。
// 正式建置不帶此 tag，本程式不進出貨映像。
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
)

type options struct {
	caseName            string
	channel             string
	host                string
	account             string
	account2            string
	scheme              string
	port                int
	tlsMode             string
	caCertFile          string
	sshPort             int
	commandTimeout      time.Duration
	assertOldRejected   bool
	concurrent          bool
	expectClass         string
	expectReason        string
	expectErrorContains string
}

type secrets struct {
	password     string
	newPassword  string
	password2    string
	newPassword2 string
	extra        []string
}

// line 一行結構化輸出；欄位與 asset.LoopbackOutcome 對齊，另帶案例與步驟名。
type line struct {
	Case      string `json:"case"`
	Step      string `json:"step"`
	Class     string `json:"class"`
	Reason    string `json:"reason,omitempty"`
	Error     string `json:"error,omitempty"`
	ElapsedMS int64  `json:"elapsed_ms"`
	// Observed 步驟自帶期望時的原始結果（class／reason），Class 只表達期望是否達成
	Observed string `json:"observed,omitempty"`
	// Candidate 改密步驟的候選處置，由 Observed 的三態推得（狀態機對三態的處置固定：
	// failed 清除、unverified 保留、success 於重連驗證通過後提交；單元測試以假端點經 runner 證明）
	Candidate string `json:"candidate,omitempty"`
}

func main() {
	opts := parseFlags()
	sec := secrets{
		password:     os.Getenv("LOOPBACK_PASSWORD"),
		newPassword:  os.Getenv("LOOPBACK_NEW_PASSWORD"),
		password2:    os.Getenv("LOOPBACK_PASSWORD_2"),
		newPassword2: os.Getenv("LOOPBACK_NEW_PASSWORD_2"),
	}
	// 執行器的後端 log（結果標記與退出碼不一致、驗證器不可用）是回歸的證據之一：
	// 導到標準輸出讓執行記錄收到，且先抹除已知秘密。
	log.SetOutput(scrubWriter{sec: &sec, w: os.Stdout})
	target, err := buildTarget(opts, opts.account)
	if err != nil {
		fail(opts.caseName, err.Error())
	}
	ctx := context.Background()

	var outcomes []line
	switch opts.caseName {
	case "verify":
		outcomes = runVerify(ctx, opts, target, sec)
	case "rotate":
		outcomes = runRotate(ctx, opts, target, &sec)
	case "rotate-pair":
		outcomes = runRotatePair(ctx, opts, target, sec)
	case "wrong-password":
		outcomes = runWrongPassword(ctx, opts, target, &sec)
	case "stdin-empty":
		outcomes = runStdinEmpty(ctx, opts, target, sec)
	case "disconnect":
		outcomes = runDisconnect(ctx, opts, target, sec)
	case "self-verify-rollback":
		outcomes = runSelfVerifyRollback(ctx, opts, target, sec)
	case "validator-unavailable":
		outcomes = runValidatorUnavailable(ctx, opts, target, sec)
	case "command-hang":
		outcomes = runCommandHang(ctx, opts, target, sec)
	case "handshake-probe":
		requireSecret(opts, sec.password, "LOOPBACK_PASSWORD")
		port := target.Port
		if port == 0 {
			if target.Scheme == model.WinrmSchemeHTTPS {
				port = 5986
			} else {
				port = 5985
			}
		}
		legs, perr := runHandshakeProbe(ctx, fmt.Sprintf("%s://%s:%d/wsman", target.Scheme, target.Host, port),
			target.Username, sec.password, target.TLSMode == model.WinrmTLSModeInsecure)
		printProbe(legs)
		if perr != nil {
			fail(opts.caseName, sec.scrub(perr.Error()))
		}
		fmt.Printf("LOOPBACK_RESULT case=%s verdict=INFO\n", opts.caseName)
		return
	default:
		fail(opts.caseName, "unknown -case "+opts.caseName)
	}

	verdict := "PASS"
	for _, o := range outcomes {
		o.Error = sec.scrub(o.Error)
		b, _ := json.Marshal(o)
		fmt.Println(string(b))
		if !expectationMet(opts, o) {
			verdict = "FAIL"
		}
	}
	fmt.Printf("LOOPBACK_RESULT case=%s verdict=%s\n", opts.caseName, verdict)
	if verdict != "PASS" {
		os.Exit(1)
	}
}

func parseFlags() options {
	var o options
	flag.StringVar(&o.caseName, "case", "", "verify | rotate | rotate-pair | wrong-password | stdin-empty | disconnect | self-verify-rollback | validator-unavailable | command-hang | handshake-probe")
	flag.StringVar(&o.channel, "channel", model.RotationChannelWindowsWinRM, "windows_winrm | windows_ssh")
	flag.StringVar(&o.host, "host", "127.0.0.1", "target host")
	flag.StringVar(&o.account, "account", "", "local account under test")
	flag.StringVar(&o.account2, "account2", "", "second local account (rotate-pair)")
	flag.StringVar(&o.scheme, "scheme", model.WinrmSchemeHTTP, "winrm scheme: http | https")
	flag.IntVar(&o.port, "port", 0, "winrm port (0 = default for scheme)")
	flag.StringVar(&o.tlsMode, "tls-mode", "", "winrm tls mode for https: system | ca | insecure")
	flag.StringVar(&o.caCertFile, "ca-cert-file", "", "PEM file for tls-mode=ca")
	flag.IntVar(&o.sshPort, "ssh-port", 0, "ssh port for windows_ssh (0 = 22)")
	flag.DurationVar(&o.commandTimeout, "command-timeout", 0, "override command timeout for stdin-empty / disconnect / command-hang (0 = product value)")
	flag.BoolVar(&o.assertOldRejected, "assert-old-rejected", false, "rotate: after success, confirm the old password no longer authenticates (winrm only, single attempt)")
	flag.BoolVar(&o.concurrent, "concurrent", false, "rotate-pair: run both accounts in parallel goroutines instead of one after the other")
	flag.StringVar(&o.expectClass, "expect", "success", "expected class of every step: success | failed | unverified")
	flag.StringVar(&o.expectReason, "expect-reason", "", "expected reason code (non-success steps)")
	flag.StringVar(&o.expectErrorContains, "expect-error-contains", "", "substring the error of non-success steps must contain")
	flag.Parse()
	if o.caseName == "" || o.account == "" {
		fail("", "-case and -account are required")
	}
	return o
}

func buildTarget(o options, account string) (asset.LoopbackTarget, error) {
	t := asset.LoopbackTarget{
		Host:     o.host,
		Channel:  o.channel,
		Username: account,
		Scheme:   o.scheme,
		Port:     o.port,
		TLSMode:  o.tlsMode,
		SSHPort:  o.sshPort,
	}
	if o.caCertFile != "" {
		pem, err := os.ReadFile(o.caCertFile)
		if err != nil {
			return t, fmt.Errorf("read ca cert: %w", err)
		}
		t.CACert = string(pem)
	}
	return t, nil
}

// runVerify T1：以現行密碼驗證（WinRM 走加密路徑；SSH 走 PowerShell）。
func runVerify(ctx context.Context, o options, t asset.LoopbackTarget, sec secrets) []line {
	requireSecret(o, sec.password, "LOOPBACK_PASSWORD")
	return []line{toLine(o.caseName, "verify", asset.LoopbackVerify(ctx, t, sec.password))}
}

// runRotate T2：改密後以新密碼驗證；可再確認舊密碼已失效。
func runRotate(ctx context.Context, o options, t asset.LoopbackTarget, sec *secrets) []line {
	requireSecret(o, sec.password, "LOOPBACK_PASSWORD")
	requireSecret(o, sec.newPassword, "LOOPBACK_NEW_PASSWORD")
	out := []line{toLine(o.caseName, "rotate", asset.LoopbackRotate(ctx, t, sec.password, sec.newPassword))}
	if out[0].Class != asset.LoopbackSuccess {
		return out
	}
	out = append(out, toLine(o.caseName, "verify-new", asset.LoopbackVerify(ctx, t, sec.newPassword)))
	if o.assertOldRejected && t.Channel == model.RotationChannelWindowsWinRM {
		// 單次嘗試（不走驗證重試序列），避免累積失敗登入次數
		old := asset.LoopbackWinRMScript(ctx, t, sec.password, "[Environment]::UserName", o.commandTimeout)
		step := line{Case: o.caseName, Step: "old-rejected", ElapsedMS: old.ElapsedMS}
		if old.Class == asset.LoopbackFailed && old.Reason == model.ChangeSecretReasonOldCredentialLoginFailed {
			step.Class = asset.LoopbackSuccess
		} else {
			step.Class = asset.LoopbackFailed
			step.Reason = old.Reason
			step.Error = "old password still authenticates or failed for another reason: " + old.Error
		}
		out = append(out, step)
	}
	return out
}

// runRotatePair T4：兩個帳號各跑改密＋驗證。
//
// 預設一個接一個，與產品的執行模型相同（改密計劃逐目標序列執行，沒有並行）。
// -concurrent 讓兩個帳號在各自的 goroutine 同時跑：這超出產品的執行模型，
// 只用來觀察全行程鎖在跨帳號交錯下的行為，結果供記錄而非驗收。
func runRotatePair(ctx context.Context, o options, t asset.LoopbackTarget, sec secrets) []line {
	if o.account2 == "" {
		fail(o.caseName, "-account2 is required for rotate-pair")
	}
	requireSecret(o, sec.password, "LOOPBACK_PASSWORD")
	requireSecret(o, sec.newPassword, "LOOPBACK_NEW_PASSWORD")
	requireSecret(o, sec.password2, "LOOPBACK_PASSWORD_2")
	requireSecret(o, sec.newPassword2, "LOOPBACK_NEW_PASSWORD_2")
	t2, err := buildTarget(o, o.account2)
	if err != nil {
		fail(o.caseName, err.Error())
	}
	type job struct {
		suffix   string
		target   asset.LoopbackTarget
		old, new string
	}
	jobs := []job{{"a", t, sec.password, sec.newPassword}, {"b", t2, sec.password2, sec.newPassword2}}
	run := func(j job) []line {
		r := []line{toLine(o.caseName, "rotate-"+j.suffix, asset.LoopbackRotate(ctx, j.target, j.old, j.new))}
		if r[0].Class == asset.LoopbackSuccess {
			r = append(r, toLine(o.caseName, "verify-"+j.suffix, asset.LoopbackVerify(ctx, j.target, j.new)))
		}
		return r
	}
	results := make([][]line, len(jobs))
	if o.concurrent {
		var wg sync.WaitGroup
		for i, j := range jobs {
			wg.Add(1)
			go func(i int, j job) {
				defer wg.Done()
				results[i] = run(j)
			}(i, j)
		}
		wg.Wait()
	} else {
		for i, j := range jobs {
			results[i] = run(j)
		}
	}
	var out []line
	for _, r := range results {
		out = append(out, r...)
	}
	return out
}

// runWrongPassword T6：舊密碼錯誤必須是確定失敗（OLD_CREDENTIAL_LOGIN_FAILED），不是 unverified。
func runWrongPassword(ctx context.Context, o options, t asset.LoopbackTarget, sec *secrets) []line {
	wrong := randomSecret()
	proposed := randomSecret()
	sec.extra = append(sec.extra, wrong, proposed)
	return []line{toLine(o.caseName, "rotate-wrong-old", asset.LoopbackRotate(ctx, t, wrong, proposed))}
}

// runStdinEmpty T5：正式改密腳本、標準輸入為空，兩通道皆可。兩步各自帶期望（Class 表達期望是否達成，
// 原始三態放 Observed）：
//  1. rotate-no-stdin：failed／STDIN_NOT_DELIVERED（結局碼 3，帳號未被觸碰，候選清除）
//  2. old-still-valid：現行密碼仍能登入
//
// 沒有新密碼被投遞，故不做新密碼被拒的一步。目標離開本案例時仍是現行密碼。
func runStdinEmpty(ctx context.Context, o options, t asset.LoopbackTarget, sec secrets) []line {
	requireSecret(o, sec.password, "LOOPBACK_PASSWORD")
	out := []line{rotateCheck(o, "rotate-no-stdin",
		asset.LoopbackRotateWithoutStdin(ctx, t, sec.password, o.commandTimeout),
		asset.LoopbackFailed, model.ChangeSecretReasonStdinNotDelivered)}
	return append(out, check(o, "old-still-valid", asset.LoopbackVerify(ctx, t, sec.password), asset.LoopbackSuccess))
}

// check 一步的期望比對：達成即 Class=success，原始三態一律放 Observed。
func check(o options, step string, out asset.LoopbackOutcome, wantClass string, wantReasons ...string) line {
	l := line{Case: o.caseName, Step: step, ElapsedMS: out.ElapsedMS, Observed: out.Class + "/" + out.Reason}
	reasonOK := len(wantReasons) == 0
	for _, r := range wantReasons {
		if out.Reason == r {
			reasonOK = true
		}
	}
	if out.Class == wantClass && reasonOK {
		l.Class = asset.LoopbackSuccess
		return l
	}
	l.Class = asset.LoopbackFailed
	l.Reason = out.Reason
	l.Error = fmt.Sprintf("expected %s/%v: %s", wantClass, wantReasons, out.Error)
	return l
}

// rotateCheck 改密步驟的 check：另標出狀態機對該三態的候選處置。
func rotateCheck(o options, step string, out asset.LoopbackOutcome, wantClass string, wantReasons ...string) line {
	l := check(o, step, out, wantClass, wantReasons...)
	switch out.Class {
	case asset.LoopbackFailed:
		l.Candidate = "discarded"
	case asset.LoopbackUnverified:
		l.Candidate = "kept"
	case asset.LoopbackSuccess:
		l.Candidate = "promoted-after-verify"
	}
	return l
}

// runValidatorUnavailable T8：正式腳本、正式工作階段、兩行標準輸入，只把校準驗證器那一句換成
// 「驗證器不可用」：腳本改密後不自驗、不回滾，以結局碼 6 交我方的重連驗證。三步：
//  1. rotate-validator-unavailable：success（候選於重連驗證通過後提交）
//  2. verify-new：新密碼能登入（走執行器的驗證序列）
//  3. old-rejected：舊密碼單次登入被拒
//
// 兩通道共用；目標離開本案例時已是新密碼，後面的 step 須接手新密碼。
func runValidatorUnavailable(ctx context.Context, o options, t asset.LoopbackTarget, sec secrets) []line {
	requireSecret(o, sec.password, "LOOPBACK_PASSWORD")
	requireSecret(o, sec.newPassword, "LOOPBACK_NEW_PASSWORD")
	out := []line{rotateCheck(o, "rotate-validator-unavailable",
		asset.LoopbackRotateValidatorUnavailable(ctx, t, sec.password, sec.newPassword), asset.LoopbackSuccess)}
	if out[0].Class != asset.LoopbackSuccess {
		return out
	}
	out = append(out, check(o, "verify-new", asset.LoopbackVerify(ctx, t, sec.newPassword), asset.LoopbackSuccess))
	return append(out, check(o, "old-rejected", asset.LoopbackVerifyOnce(ctx, t, sec.password),
		asset.LoopbackFailed, model.ChangeSecretReasonOldCredentialLoginFailed))
}

// runCommandHang T9：正式改密腳本、正式工作階段（或連線）、兩行標準輸入，只把校準驗證器那一句換成
// 長時間停住，逼出「指令已送出、逾時前未回報完成」的路徑；逾時通常以 -command-timeout 縮短。三步：
//  1. rotate-command-hang：unverified／REMOTE_STATE_UNKNOWN（候選保留），且耗時落在逾時附近
//     （早於逾時代表走的不是逾時路徑；遠超逾時代表逾時後仍在等目標）
//  2. old-still-valid：舊密碼仍能登入（走執行器的驗證序列）
//  3. new-rejected：新密碼單次登入被拒
//
// 兩通道共用；目標離開本案例時仍是舊密碼。
func runCommandHang(ctx context.Context, o options, t asset.LoopbackTarget, sec secrets) []line {
	requireSecret(o, sec.password, "LOOPBACK_PASSWORD")
	requireSecret(o, sec.newPassword, "LOOPBACK_NEW_PASSWORD")
	timeout := o.commandTimeout
	if timeout <= 0 {
		timeout = 90 * time.Second
	}
	hang := asset.LoopbackRotateCommandHang(ctx, t, sec.password, sec.newPassword, o.commandTimeout)
	step := rotateCheck(o, "rotate-command-hang", hang, asset.LoopbackUnverified, model.ChangeSecretReasonRemoteStateUnknown)
	if step.Class == asset.LoopbackSuccess {
		elapsed := time.Duration(hang.ElapsedMS) * time.Millisecond
		if elapsed < timeout || elapsed > timeout+30*time.Second {
			step.Class = asset.LoopbackFailed
			step.Error = fmt.Sprintf("elapsed %s is not within [%s, %s]: not the command-timeout path", elapsed, timeout, timeout+30*time.Second)
		}
	}
	out := []line{step}
	out = append(out, check(o, "old-still-valid", asset.LoopbackVerify(ctx, t, sec.password), asset.LoopbackSuccess))
	out = append(out, check(o, "new-rejected", asset.LoopbackVerifyOnce(ctx, t, sec.newPassword),
		asset.LoopbackFailed, model.ChangeSecretReasonOldCredentialLoginFailed))
	return out
}

// runDisconnect T6D：指令執行中重啟 WinRM 服務，期望 unverified（而非成功或確定失敗）。
func runDisconnect(ctx context.Context, o options, t asset.LoopbackTarget, sec secrets) []line {
	requireSecret(o, sec.password, "LOOPBACK_PASSWORD")
	done := make(chan asset.LoopbackOutcome, 1)
	go func() {
		done <- asset.LoopbackWinRMScript(ctx, t, sec.password, "Start-Sleep -Seconds 40; exit 0", o.commandTimeout)
	}()
	time.Sleep(8 * time.Second)
	// 以絕對路徑呼叫，不經 PATH 搜尋（回歸工具只跑在 Windows runner，SystemRoot 必存在）
	ps := filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	restart := exec.Command(ps, "-NoProfile", "-NonInteractive", "-Command", "Restart-Service WinRM -Force")
	if rerr := restart.Run(); rerr != nil {
		fmt.Fprintf(os.Stderr, "restart winrm service: %v\n", rerr)
	}
	return []line{toLine(o.caseName, "script-mid-flight-restart", <-done)}
}

// runSelfVerifyRollback T7：正式腳本、正式工作階段、兩行標準輸入，只把目標端自驗強制為不通過。
//
// 三步各自帶期望，Class 表達「期望是否達成」，原始結果放 Observed：
//  1. rotate-forced-self-verify-fail：failed／REMOTE_SELF_VERIFY_FAILED（結局碼 4，目標已改回舊密碼，候選清除）
//  2. old-still-valid：舊密碼仍能登入（走執行器的驗證序列）
//  3. new-rejected：新密碼單次登入被拒（不走重試序列，只累積一次失敗登入）
//
// 兩通道共用、原因碼一律嚴格：結局以腳本印在標準輸出的結果標記為準，目標預設 shell 對退出碼的改寫
// 不影響分流。目標離開本案例時仍是舊密碼，後面的 step 不必接手新密碼。
func runSelfVerifyRollback(ctx context.Context, o options, t asset.LoopbackTarget, sec secrets) []line {
	requireSecret(o, sec.password, "LOOPBACK_PASSWORD")
	requireSecret(o, sec.newPassword, "LOOPBACK_NEW_PASSWORD")
	out := []line{rotateCheck(o, "rotate-forced-self-verify-fail",
		asset.LoopbackRotateSelfVerifyFailure(ctx, t, sec.password, sec.newPassword),
		asset.LoopbackFailed, model.ChangeSecretReasonRemoteSelfVerifyFailed)}
	out = append(out, check(o, "old-still-valid", asset.LoopbackVerify(ctx, t, sec.password), asset.LoopbackSuccess))
	out = append(out, check(o, "new-rejected", asset.LoopbackVerifyOnce(ctx, t, sec.newPassword),
		asset.LoopbackFailed, model.ChangeSecretReasonOldCredentialLoginFailed))
	return out
}

func expectationMet(o options, l line) bool {
	if l.Class != o.expectClass {
		return false
	}
	if o.expectReason != "" && l.Reason != o.expectReason {
		return false
	}
	if o.expectErrorContains != "" && !strings.Contains(l.Error, o.expectErrorContains) {
		return false
	}
	return true
}

func toLine(caseName, step string, out asset.LoopbackOutcome) line {
	return line{Case: caseName, Step: step, Class: out.Class, Reason: out.Reason, Error: out.Error, ElapsedMS: out.ElapsedMS}
}

func requireSecret(o options, value, name string) {
	if value == "" {
		fail(o.caseName, name+" is not set")
	}
}

func fail(caseName, msg string) {
	fmt.Fprintln(os.Stderr, msg)
	fmt.Printf("LOOPBACK_RESULT case=%s verdict=FAIL\n", caseName)
	os.Exit(2)
}

// scrub 把每個已知秘密自輸出字串中抹除。
func (s secrets) scrub(text string) string {
	for _, v := range append([]string{s.password, s.newPassword, s.password2, s.newPassword2}, s.extra...) {
		if v != "" {
			text = strings.ReplaceAll(text, v, "[redacted]")
		}
	}
	return text
}

// scrubWriter 後端 log 的出口：每次寫出前抹除已知秘密（含案例中途才產生的隨機密碼）。
type scrubWriter struct {
	sec *secrets
	w   io.Writer
}

func (s scrubWriter) Write(p []byte) (int, error) {
	if _, err := io.WriteString(s.w, s.sec.scrub(string(p))); err != nil {
		return 0, err
	}
	return len(p), nil
}

// randomSecret 只在本程式內使用的隨機字串（錯密案例用），符合本地新密碼驗證且不會與真密碼相同。
func randomSecret() string {
	var b [18]byte
	if _, err := rand.Read(b[:]); err != nil {
		fail("", "random: "+err.Error())
	}
	return "Lb1!" + base64.RawURLEncoding.EncodeToString(b[:])
}
