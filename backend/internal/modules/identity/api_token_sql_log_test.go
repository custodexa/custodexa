package identity

import (
	"bytes"
	"log"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm/logger"
)

// token 雜湊不進 SQL 紀錄：以真的 SQL logger（與正式組裝相同的實作，只把輸出導到緩衝區）擷取輸出，
// 兩種記錄等級（非 release 逐條輸出、release 只輸出錯誤）下，正常建立、正常認證、以不存在的 token 認證、
// 建立時寫入失敗，輸出都不含雜湊值；失敗的語句仍留下診斷訊號；其他語句照常輸出參數。

var sha256HexPattern = regexp.MustCompile(`[0-9a-f]{64}`)

// captureSQLLog 把測試資料庫的 SQL logger 換成輸出到緩衝區的同款 logger；測試結束還原。
func captureSQLLog(t *testing.T, e *tokenEnv, level logger.LogLevel) *bytes.Buffer {
	t.Helper()
	buf := &bytes.Buffer{}
	prev := e.db.Logger
	e.db.Logger = logger.New(log.New(buf, "", 0), logger.Config{
		SlowThreshold: 200 * time.Millisecond, LogLevel: level, Colorful: false,
	})
	t.Cleanup(func() { e.db.Logger = prev })
	return buf
}

func assertNoDigest(t *testing.T, out string, digests ...string) {
	t.Helper()
	for _, d := range digests {
		assert.NotContains(t, out, d, "SQL 紀錄不得含 token 雜湊")
	}
	assert.Empty(t, sha256HexPattern.FindAllString(out, -1), "SQL 紀錄不得含任何形如 SHA-256 的值")
}

// TestAPITokenSQLLogOmitsDigest token 雜湊在任何記錄等級、成功或失敗都不進 SQL 紀錄。
func TestAPITokenSQLLogOmitsDigest(t *testing.T) {
	for _, mode := range []struct {
		name  string
		level logger.LogLevel
	}{{"非 release 逐條輸出", logger.Info}, {"release 只輸出錯誤", logger.Error}} {
		t.Run(mode.name, func(t *testing.T) {
			e := newAuthTokenEnv(t)
			owner := e.mkUser(t, "owner", "identity_admin")
			buf := captureSQLLog(t, e, mode.level)

			got := e.mustCreate(t, owner, "sqllog-tf", e.roles["identity_admin"])
			e.assertAccepted(t, got.Token, owner)
			missing := APITokenPrefix + "no-such-token-sqllog"
			e.assertRejected(t, missing, APITokenReasonNotFound)
			out := buf.String()
			assertNoDigest(t, out, apiTokenDigest(got.Token), apiTokenDigest(missing))
			if mode.level == logger.Info {
				assert.Contains(t, out, "api_tokens", "非 release 應逐條輸出（擷取的是真的 logger）")
				assert.Contains(t, out, "sqllog-tf", "其他語句照常輸出參數")
			}
			assert.Contains(t, out, "record not found", "查無資料仍留下診斷訊號")

			// 建立時寫入失敗：以觸發器讓 token 的 INSERT 失敗
			require.NoError(t, e.db.Exec(`CREATE TRIGGER api_tokens_reject BEFORE INSERT ON api_tokens
				BEGIN SELECT RAISE(ABORT, 'forced insert failure'); END`).Error)
			buf.Reset()
			_, err := e.tokens.Create(e.op(owner), CreateAPITokenInput{Name: "sqllog-fail",
				RoleIDs: []uint{e.roles["identity_admin"]}, NeverExpires: true})
			require.Error(t, err)
			out = buf.String()
			assertNoDigest(t, out)
			assert.Contains(t, out, "forced insert failure", "寫入失敗仍留下錯誤訊號")
			assert.True(t, strings.Contains(out, "INSERT INTO") && strings.Contains(out, "api_tokens"),
				"失敗的語句仍輸出（不帶參數值）：%s", out)
		})
	}
}
