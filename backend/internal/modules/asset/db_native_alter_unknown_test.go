package asset

import (
	"testing"

	mysqldriver "github.com/go-sql-driver/mysql"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

// dbAlterTimeoutErr 讀取逾時的 net.Error，沒有包成 *net.OpError，也沒有目標端錯誤碼。
type dbAlterTimeoutErr struct{}

func (dbAlterTimeoutErr) Error() string   { return "i/o timeout" }
func (dbAlterTimeoutErr) Timeout() bool   { return true }
func (dbAlterTimeoutErr) Temporary() bool { return true }

// 改密語句送出後收到沒有目標端錯誤碼的錯誤：語句可能已在目標端生效，
// 候選必須保留（未下達）、紀錄記 unverified，平台已存的憑證不動。
func TestDBNativeAlterCodelessErrorKeepsCandidate(t *testing.T) {
	cases := []struct {
		name string
		err  error
	}{
		{"網路逾時_無錯誤碼", dbAlterTimeoutErr{}},
		{"驅動協定錯誤_無錯誤碼", mysqldriver.ErrPktSync},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := setupChangeSecretFixture(t, "root", "oldpass123")
			wireStopAudit(f)
			useDBNativeChannel(t, f.db, f.assetID)
			conn := &dbExecStubConn{row: []string{"8.4.13", "root@%", "", "utf8mb4"}, execErr: c.err}
			exec := dbNativeExecutor{open: dbExecStub(conn)}
			f.runner.executors = func(string) rotationExecutor { return exec }

			records := f.runner.RunPlan(f.plan(t, nil))

			require.Len(t, records, 1)
			assert.Equal(t, model.ChangeSecretUnverified, records[0].Status, "錯誤: %s", records[0].Error)
			assert.Equal(t, model.ChangeSecretReasonRemoteStateUnknown, records[0].Error)
			require.EqualValues(t, 1, f.candidateCount(t), "遠端狀態不可知時候選必須保留")
			cand := candidateOfAccount(t, f)
			assert.False(t, cand.Applied, "語句未回報成功，候選不得標為已下達")
			assert.Equal(t, "oldpass123", f.storedPassword(t), "平台已存憑證不得變動")
		})
	}
}
