package asset

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// runTakeoverSites 已驗證結果型別在正式碼中的出現位置（root：TestCredentialRecoveryHostIdentityTakeover，
// 前綴 4.1/逾期/）。能產生此型別值的寫法合計恰一處、位於承接服務驗證成功的分支；
// 其餘出現位置逐列歸類，歸不進去的一律失敗。
func runTakeoverSites(t *testing.T) {
	t.Run("4.1/逾期/結果型別的正式碼出現位置逐列歸類_唯一建構點", func(t *testing.T) {
		files, err := filepath.Glob("*.go")
		require.NoError(t, err)
		require.NotEmpty(t, files)

		produce := []*regexp.Regexp{
			regexp.MustCompile(`verifiedConfirmation\{`),
			regexp.MustCompile(`new\(verifiedConfirmation\)`),
			regexp.MustCompile(`var [A-Za-z_]+ \*?verifiedConfirmation`),
			regexp.MustCompile(`[A-Za-z_]+ :?= .*\*?verifiedConfirmation`),
		}
		classes := map[string]int{}
		produced := 0
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			body, err := os.ReadFile(f)
			require.NoError(t, err)
			for i, line := range strings.Split(string(body), "\n") {
				if !strings.Contains(line, "verifiedConfirmation") {
					continue
				}
				trim := strings.TrimSpace(line)
				for _, re := range produce {
					if re.MatchString(line) {
						produced++
						require.Equal(t, "hostkey_identity_takeover_member.go", f,
							"能產生結果物件的寫法只能在承接服務的驗證成功分支（%s:%d）", f, i+1)
						break
					}
				}
				switch {
				case strings.HasPrefix(trim, "type verifiedConfirmation struct"), strings.HasPrefix(trim, "// verifiedConfirmation"):
					classes["型別定義"]++
				case trim == "Verified *verifiedConfirmation":
					classes["memberTransition 欄位型別"]++
				case strings.Contains(trim, "&verifiedConfirmation{") && f == "hostkey_identity_takeover_member.go":
					classes["唯一建構點"]++
				default:
					t.Errorf("%s:%d 無法歸入任何允許分類: %s", f, i+1, trim)
				}
			}
		}
		require.Equal(t, 1, produced, "能產生結果物件的寫法合計必須恰 1 處")
		require.Equal(t, 1, classes["唯一建構點"])
		require.Equal(t, 1, classes["memberTransition 欄位型別"])
		require.GreaterOrEqual(t, classes["型別定義"], 1)
	})
}
