package asset

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/custodexa/backend/internal/model"
	"golang.org/x/crypto/ssh"
)

// Windows 本機帳號改密的 PowerShell 腳本契約，WinRM 與 SSH 兩條通道共用。
//
// 腳本本身走命令列（目標機的程序清單看得見它），且對每個目標都是同一份文字：密碼與帳號名
// 只走標準輸入，第一行新密碼、第二行舊密碼、第三行帳號名，腳本以 UTF-8 逐行讀取。
// 缺任一行即以結局碼 3 結束，在觸碰帳號之前——沒收到密碼就靜默成功、把密碼改成空字串、
// 或沒有舊密碼可回滾，都比明確失敗糟。
//
// 標準輸入的解碼由腳本自己指定為 UTF-8：宿主程序（sshd／WinRM 服務）不保證主控台輸入
// 編碼，帳號名含非 ASCII 字元時靠預設編碼會被讀成別的字串。帳號名以變數交給
// `Set-LocalUser` 與驗證器，不經字串拼接，因此帳號名只要符合 Windows 自己的規則即可。
//
// # 目標端自驗與回滾
//
// `Set-LocalUser` 之後腳本在目標本機驗證新密碼可登入；不通過就當場以舊密碼改回。
// 目標機離開腳本時只有「已驗證的新密碼」或「舊密碼」兩態，責任不落在堡壘機側的猜測。
// 驗證器先以舊密碼校準：此刻確知舊密碼有效（工作階段就是用它建的），連它都驗不過或
// 拋例外代表驗證器在此環境不可信，改密後不自驗、不回滾，交我方的重連驗證判定。
//
// # 結局訊號：標準輸出的結果標記為主、退出碼為輔
//
// 腳本每個結束點都先在標準輸出印一行 `ROTATION_RESULT=<結局碼>` 再 `exit <同一碼>`。
// 只看退出碼不夠：目標的預設 shell 可能把腳本的退出碼改寫（例如把任何非零一律表面成 1），
// 而一個被改寫成 1 的「結局碼 6」若被當成確定失敗處理，候選會被清掉、目標卻已是新密碼。
// 標記只含結局碼，不含任何密碼；它走標準輸出，不受錯誤串流上的宿主格式（CLIXML 等）干擾。
// 標記缺失而退出碼非零，結局分不清，一律記狀態不可知並保留候選。

// windowsResultMarkerPrefix 結果標記的行首；其後緊接結局碼的十進位數字。
const windowsResultMarkerPrefix = "ROTATION_RESULT="

// windowsRotationScript 改密腳本。腳本文字不含帳號名與密碼，兩通道、所有目標共用同一份。
const windowsRotationScript = `$ErrorActionPreference = 'Stop'
function Write-Result([int]$c) { [Console]::Out.WriteLine('` + windowsResultMarkerPrefix + `' + $c); [Console]::Out.Flush() }
$in = [System.IO.StreamReader]::new([Console]::OpenStandardInput(), [System.Text.UTF8Encoding]::new($false))
$p = $in.ReadLine()
$o = $in.ReadLine()
$u = $in.ReadLine()
if ([string]::IsNullOrEmpty($p) -or [string]::IsNullOrEmpty($o) -or [string]::IsNullOrEmpty($u)) { Write-Result 3; exit 3 }
$v = $null
try {
  Add-Type -AssemblyName System.DirectoryServices.AccountManagement
  $v = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Machine)
  ` + windowsCalibrateStatement + `
} catch { $v = $null }
try { Set-LocalUser -Name $u -Password (ConvertTo-SecureString $p -AsPlainText -Force) } catch { [Console]::Error.WriteLine($_.Exception.Message); Write-Result 1; exit 1 }
if ($null -eq $v) { Write-Result 6; exit 6 }
try { ` + windowsSelfVerifyStatement + ` } catch { Write-Result 6; exit 6 }
if ($ok) { Write-Result 0; exit 0 }
try { Set-LocalUser -Name $u -Password (ConvertTo-SecureString $o -AsPlainText -Force) } catch { Write-Result 5; exit 5 }
Write-Result 4; exit 4`

// windowsCalibrateStatement 腳本中以舊密碼校準驗證器的那一句。
// 獨立成常數是為了讓回歸專用建置能精確指認並取代它；正式碼只在腳本裡用它。
const windowsCalibrateStatement = `if (-not $v.ValidateCredentials($u, $o)) { $v = $null }`

// windowsSelfVerifyStatement 腳本中以新密碼自驗的那一句。
// 獨立成常數的理由同上。
const windowsSelfVerifyStatement = `$ok = $v.ValidateCredentials($u, $p)`

// windowsVerifyScript 驗證用的無副作用指令：以新密碼登入後能跑到這一行即為成功。
const windowsVerifyScript = `[Environment]::UserName`

// windowsCommandTimeout 改密與驗證指令自送出到回報完成的上限，WinRM 與 SSH 兩通道同值。
// 正常改密遠低於此；命中多半是標準輸入沒送到而腳本卡在 ReadLine，或目標端的
// Add-Type／Set-LocalUser 掛住。逾時發生在指令送出後，遠端狀態不可知、候選保留。
const windowsCommandTimeout = 90 * time.Second

// 腳本結局碼契約（標記與退出碼同一套值）。0 為成功且自驗通過；其餘見各常數。
// 不在此表內的值不是契約的一部分：分流視為結局分不清。
const (
	// windowsExitSetLocalUserFailed `Set-LocalUser` 失敗，帳號未變更。
	windowsExitSetLocalUserFailed = 1
	// windowsExitStdinNotDelivered 標準輸入缺密碼行，帳號未被觸碰。
	windowsExitStdinNotDelivered = 3
	// windowsExitSelfVerifyRolledBack 新密碼在目標本機驗證不通過，已改回舊密碼。
	windowsExitSelfVerifyRolledBack = 4
	// windowsExitSelfVerifyRollbackFailed 新密碼驗證不通過，改回舊密碼也失敗：目標狀態不可知。
	windowsExitSelfVerifyRollbackFailed = 5
	// windowsExitSelfVerifyUnavailable 目標本機驗證器不可用，新密碼已設定但未自驗。
	windowsExitSelfVerifyUnavailable = 6
)

// windowsPowerShellPrefix 兩通道共用的命令列前綴。
//
// 顯式呼叫 powershell.exe 而非倚賴目標的預設 shell：Windows OpenSSH 預設 shell 是
// cmd.exe，WinRM 的 winrs shell 也是 cmd，兩者的引號規則都與 PowerShell 不同。
// 命令列由 64 位元的宿主程序（sshd／WinRM 服務）解析，PATH 上的 powershell.exe
// 即 System32 下的 64 位元版本；`Microsoft.PowerShell.LocalAccounts` 模組在 32 位元
// 宿主上不可用，故這一點不是可有可無的。
const windowsPowerShellPrefix = "powershell.exe -NoProfile -NonInteractive -EncodedCommand "

// windowsAccountNameMaxLen Windows 本機帳號名的長度上限，以 UTF-16 碼元計（與 Windows 一致）。
const windowsAccountNameMaxLen = 20

// windowsAccountNameForbidden Windows 本機帳號名不得含的字元。
const windowsAccountNameForbidden = "\"/\\[]:;|=,+*?<>"

// windowsRotationStdin 改密腳本的標準輸入：新密碼、舊密碼、帳號名各一行（UTF-8）。
// 兩執行器共用，順序是腳本契約的一部分。
func windowsRotationStdin(newSecret, oldSecret, account string) string {
	return newSecret + "\n" + oldSecret + "\n" + account + "\n"
}

// buildWindowsCommand 把腳本包成 `powershell.exe … -EncodedCommand <base64>`。
//
// -EncodedCommand 收的是 UTF-16LE 再 base64 的腳本文字。base64 不是加密——
// 這正是密碼不得進腳本的理由；腳本文字裡只有固定指令。
func buildWindowsCommand(script string) string {
	return windowsPowerShellPrefix + encodePowerShellScript(script)
}

// encodePowerShellScript UTF-16LE + base64。
func encodePowerShellScript(script string) string {
	units := utf16.Encode([]rune(script))
	buf := make([]byte, 0, len(units)*2)
	for _, u := range units {
		buf = append(buf, byte(u), byte(u>>8))
	}
	return base64.StdEncoding.EncodeToString(buf)
}

// validateWindowsAccountName 帳號名的本地前置驗證，規則與 Windows 本機帳號（SAM）相同：
// 長度 1 至 20（UTF-16 碼元）；不含 `" / \ [ ] : ; | = , + * ? < >` 與控制字元；
// 不可全為點或空白；首尾不得為空白（Windows 會修剪，我方直接拒絕以免歧義）。
// 其餘字元（含非 ASCII、`@`、`$`、`'`、中間的空白）一律允許：帳號名經標準輸入以變數
// 交給腳本，不嵌進腳本文字。反斜線被拒同時排除了域帳號形態。
// 違者是 localPreconditionError，遠端完全未被觸碰。
func validateWindowsAccountName(name string) error {
	invalid := &localPreconditionError{reason: model.ChangeSecretReasonAccountNameInvalid}
	if name == "" || !utf8.ValidString(name) {
		return invalid
	}
	units := 0
	for _, r := range name {
		if unicode.IsControl(r) || strings.ContainsRune(windowsAccountNameForbidden, r) {
			return invalid
		}
		units += len(utf16.Encode([]rune{r}))
	}
	if units > windowsAccountNameMaxLen {
		return invalid
	}
	if strings.HasPrefix(name, " ") || strings.HasSuffix(name, " ") {
		return invalid
	}
	if strings.Trim(name, ". ") == "" {
		return invalid
	}
	return nil
}

// validateWindowsNewSecret 新密碼走「標準輸入第一行」的協定，含換行或 NUL 會截斷
// 或污染那一行；空密碼則會被腳本判為未投遞。都在本地擋下，不送出。
func validateWindowsNewSecret(secret string) error {
	if !windowsSecretLineSafe(secret) {
		return &localPreconditionError{reason: model.ChangeSecretReasonInvalidNewSecret}
	}
	return nil
}

// validateWindowsOldSecret 舊密碼走「標準輸入第二行」，腳本拿它回滾。含換行或 NUL 的
// 舊密碼會被截成錯的值，腳本拿錯的值回滾等於把帳號改到一個誰都不知道的密碼——
// 比不回滾更糟，故在本地擋下，遠端零接觸。
func validateWindowsOldSecret(secret string) error {
	if !windowsSecretLineSafe(secret) {
		return &localPreconditionError{reason: model.ChangeSecretReasonInvalidOldSecret}
	}
	return nil
}

// windowsSecretLineSafe 一個秘密能否完整佔據標準輸入的一行。
func windowsSecretLineSafe(secret string) bool {
	return secret != "" && !strings.ContainsAny(secret, "\r\n\x00")
}

// windowsLogSubject 後端 log 用的目標識別：資產 ID 與帳號名，不含任何秘密。
func windowsLogSubject(t rotationTarget) string {
	var id uint
	if t.asset != nil {
		id = t.asset.ID
	}
	return fmt.Sprintf("asset=%d user=%s", id, t.username)
}

// parseWindowsResultMarker 自標準輸出找結果標記。逐行比對，容忍 CR、前後空白與 BOM；
// 多行命中取最後一行（腳本只印一次，多行代表輸出被目標端污染，最後一行最接近結束點）。
func parseWindowsResultMarker(stdout string) (int, bool) {
	code, found := 0, false
	for _, raw := range strings.Split(stdout, "\n") {
		line := strings.TrimSpace(strings.TrimPrefix(raw, "\uFEFF"))
		if !strings.HasPrefix(line, windowsResultMarkerPrefix) {
			continue
		}
		n, err := strconv.Atoi(strings.TrimPrefix(line, windowsResultMarkerPrefix))
		if err != nil || n < 0 {
			continue
		}
		code, found = n, true
	}
	return code, found
}

// classifyWindowsOutcome 兩通道共用的結局分流：先讀標準輸出的結果標記，再看退出碼。
//
// 走到這裡的前提是「遠端已回報指令跑完」（WinRM：CommandState=Done 且無傳輸錯誤；
// SSH：指令結束，含退出 0）。標記存在即以標記為結局碼（退出碼不一致時只記一行 log）；
// 標記缺失：退出碼 0 交呼叫端的重連驗證，退出碼非零＝結局分不清，記狀態不可知、候選保留。
// 後者不得歸為確定失敗：目標可能已是新密碼，清掉候選就是「堡壘機舊、資產新」。
// subject 只用於 log（資產 ID 與帳號名）。
func classifyWindowsOutcome(subject string, exitCode int, stdout, stderr string) error {
	code, found := parseWindowsResultMarker(stdout)
	if !found {
		if exitCode == 0 {
			log.Printf("[ChangeSecret] Windows 改密腳本退出碼 0 但無結果標記 %s，交重連驗證判定", subject)
			return nil
		}
		return &remoteStateUnknownError{
			reason: model.ChangeSecretReasonRemoteStateUnknown,
			cause:  fmt.Errorf("exit %d without result marker: %s", exitCode, sanitizeRemoteMessage(strings.TrimSpace(stderr))),
		}
	}
	if code != exitCode {
		log.Printf("[ChangeSecret] Windows 改密腳本結果標記 %d 與退出碼 %d 不一致 %s，以標記為準", code, exitCode, subject)
	}
	if code == windowsExitSelfVerifyUnavailable {
		log.Printf("[ChangeSecret] Windows 目標本機驗證器不可用 %s，未做目標端自驗，改以重連驗證判定", subject)
	}
	return classifyWindowsExit(code, stderr)
}

// classifyWindowsExit 結局碼的分流表。
//
// 0 與 6 為新密碼已設定（6 未經目標自驗，交呼叫端的重連驗證）；1、3、4 為遠端確定是舊密碼，
// 候選可清；5 為目標自己也不知道是哪個密碼，帶專屬原因碼記狀態不可知、候選保留。
// 契約表外的值（契約腳本印不出來，代表目標跑的不是本契約腳本）與「無標記且非零」同一條底線：
// 分不清就記狀態不可知、候選保留，不得當成確定失敗。stderr 只進 cause（後端 log），不落記錄。
func classifyWindowsExit(exitCode int, stderr string) error {
	switch exitCode {
	case 0, windowsExitSelfVerifyUnavailable:
		return nil
	case windowsExitSetLocalUserFailed:
		return &remoteRejectedError{
			reason: model.ChangeSecretReasonRemoteRejected,
			cause:  fmt.Errorf("exit %d: %s", exitCode, sanitizeRemoteMessage(strings.TrimSpace(stderr))),
		}
	case windowsExitStdinNotDelivered:
		return &remoteRejectedError{reason: model.ChangeSecretReasonStdinNotDelivered}
	case windowsExitSelfVerifyRolledBack:
		return &remoteRejectedError{reason: model.ChangeSecretReasonRemoteSelfVerifyFailed}
	case windowsExitSelfVerifyRollbackFailed:
		return &remoteStateUnknownError{reason: model.ChangeSecretReasonRemoteSelfVerifyRollbackFailed}
	default:
		return &remoteStateUnknownError{
			reason: model.ChangeSecretReasonRemoteStateUnknown,
			cause:  fmt.Errorf("exit %d outside the script contract: %s", exitCode, sanitizeRemoteMessage(strings.TrimSpace(stderr))),
		}
	}
}

// windowsSSHExitCode SSH 指令是否跑完：跑完（含退出 0）回 (退出碼, true)；連線中斷等回 (0, false)。
func windowsSSHExitCode(err error) (int, bool) {
	if err == nil {
		return 0, true
	}
	var exitErr *ssh.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitStatus(), true
	}
	return 0, false
}

// classifyWindowsSSHRun SSH 通道跑完改密指令後的分流：指令跑完走結局分流；
// 其餘（連線中斷）原錯誤上拋＝遠端狀態不可知。
func classifyWindowsSSHRun(subject, stdout, stderr string, err error) error {
	exitCode, finished := windowsSSHExitCode(err)
	if !finished {
		return err
	}
	return classifyWindowsOutcome(subject, exitCode, stdout, stderr)
}
