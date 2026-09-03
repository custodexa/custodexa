package asset

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

// 腳本契約與帳號名驗證。密碼與帳號名都只走標準輸入，腳本文字對每個目標相同；
// 帳號名的允許集合就是 Windows 本機帳號自己的規則。

// decodeWindowsCommand 自 `powershell.exe … -EncodedCommand <b64>` 還原腳本文字。
func decodeWindowsCommand(t *testing.T, command string) string {
	t.Helper()
	require.True(t, strings.HasPrefix(command, windowsPowerShellPrefix), "命令列須以顯式的 powershell.exe 前綴開頭: %q", command)
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(command, windowsPowerShellPrefix))
	require.NoError(t, err)
	require.Equal(t, 0, len(raw)%2, "UTF-16LE 位元組數須為偶數")
	units := make([]uint16, len(raw)/2)
	for i := range units {
		units[i] = uint16(raw[2*i]) | uint16(raw[2*i+1])<<8
	}
	return string(utf16.Decode(units))
}

// TestWindowsCommandNeverContainsPassword 組裝出的命令列（含 base64 解碼後的腳本）
// 不含新密碼；標準輸入的內容才含。
func TestWindowsCommandNeverContainsPassword(t *testing.T) {
	const account = "svc backup"
	const password = "N3w-P@ssw0rd!xyz"

	command := buildWindowsCommand(windowsRotationScript)
	assert.NotContains(t, command, password, "命令列本體不得含新密碼")
	assert.NotContains(t, command, base64.StdEncoding.EncodeToString([]byte(password)), "命令列不得含 base64 後的新密碼")

	script := decodeWindowsCommand(t, command)
	assert.NotContains(t, script, password, "解碼後的腳本文字不得含新密碼")
	assert.NotContains(t, script, account, "帳號名不進腳本文字")
	assert.Contains(t, script, "Set-LocalUser -Name $u -Password", "帳號名以變數交給 Set-LocalUser，不經字串拼接")
	assert.Contains(t, script, "[System.IO.StreamReader]::new([Console]::OpenStandardInput(), [System.Text.UTF8Encoding]::new($false))", "標準輸入須以 UTF-8 解碼")
	assert.Contains(t, script, "$in.ReadLine()", "密碼與帳號名須自標準輸入讀取")
	assert.Contains(t, script, "exit 3", "標準輸入為空須以退出碼 3 結束")
	assert.Contains(t, script, "ConvertTo-SecureString $p -AsPlainText -Force")

	stdin := windowsRotationStdin(password, "old", account)
	assert.Contains(t, stdin, password, "標準輸入內容含新密碼")
	assert.True(t, strings.HasSuffix(stdin, "\n"+account+"\n"), "帳號名為標準輸入最後一行")

	verify := decodeWindowsCommand(t, buildWindowsCommand(windowsVerifyScript))
	assert.Equal(t, windowsVerifyScript, verify)
	assert.NotContains(t, verify, "Set-LocalUser", "驗證指令不得有副作用")
}

// TestWindowsAccountNameMatrix 帳號名驗證的表驅動：允許集合＝Windows 本機帳號自己的規則。
func TestWindowsAccountNameMatrix(t *testing.T) {
	cases := []struct {
		name  string
		valid bool
	}{
		{"Administrator", true},
		{"svc backup", true},
		{"John Smith", true},
		{"svc.backup-01_x", true},
		{strings.Repeat("a", 20), true},
		{"名稱", true},
		{"測試@svc1", true},
		{"svc@app", true},
		{"a$", true},
		{"o'brien", true},
		{"a`b", true},
		{"a.b", true},
		{strings.Repeat("測", 20), true},
		{strings.Repeat("測", 21), false},
		{strings.Repeat("a", 21), false},
		{"𝔸" + strings.Repeat("a", 19), false}, // 增補平面字元佔兩個 UTF-16 碼元
		{`DOMAIN\u`, false},
		{"a:b", false},
		{"a;b", false},
		{`a"b`, false},
		{"a/b", false},
		{"a[b]", false},
		{"a|b", false},
		{"a=b", false},
		{"a,b", false},
		{"a+b", false},
		{"a*b", false},
		{"a?b", false},
		{"a<b>", false},
		{" lead", false},
		{"trail ", false},
		{"", false},
		{"...", false},
		{". .", false},
		{"a\nb", false},
		{"a\rb", false},
		{"a\tb", false},
		{"a\x00b", false},
		{"a\x7fb", false},
		{"\xff", false}, // 非合法 UTF-8
	}
	for _, c := range cases {
		err := validateWindowsAccountName(c.name)
		if c.valid {
			assert.NoError(t, err, "%q 應合法", c.name)
			continue
		}
		require.Error(t, err, "%q 應被拒", c.name)
		var local *localPreconditionError
		require.True(t, errors.As(err, &local), "%q 的拒絕須為本地前置錯誤（遠端未觸碰）", c.name)
		assert.Equal(t, model.ChangeSecretReasonAccountNameInvalid, local.reason)
	}

	// 新密碼的標準輸入協定：換行與 NUL 會截斷那一行，空值會被腳本判為未投遞
	for _, bad := range []string{"", "a\nb", "a\rb", "a\x00b"} {
		err := validateWindowsNewSecret(bad)
		var local *localPreconditionError
		require.True(t, errors.As(err, &local), "%q 應為本地前置錯誤", bad)
		assert.Equal(t, model.ChangeSecretReasonInvalidNewSecret, local.reason)
	}
	assert.NoError(t, validateWindowsNewSecret("ok'\"$`;pass"))
}

// TestClassifyWindowsExit 退出碼分流：0 成功、3 密碼未投遞、其餘遠端確定拒絕。
func TestClassifyWindowsExit(t *testing.T) {
	assert.NoError(t, classifyWindowsExit(0, ""))

	var rejected *remoteRejectedError
	require.True(t, errors.As(classifyWindowsExit(3, ""), &rejected))
	assert.Equal(t, model.ChangeSecretReasonStdinNotDelivered, rejected.reason)

	err := classifyWindowsExit(1, "Access is denied\nsecond line")
	require.True(t, errors.As(err, &rejected))
	assert.Equal(t, model.ChangeSecretReasonRemoteRejected, rejected.reason)
	assert.Contains(t, err.Error(), "Access is denied")
	assert.NotContains(t, err.Error(), "second line", "stderr 只取首行進 cause")
}
