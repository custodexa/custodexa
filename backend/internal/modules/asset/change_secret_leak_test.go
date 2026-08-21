package asset

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// change-secret-ssh-deepening 安全修補：遠端可控字串零落庫的**寫入端**守衛。
//
// 攻擊路徑（獨立驗收者實證）：目標機在 chpasswd 階段把收到的 stdin 回吐 stderr，
// 該 stdin 含本輪產生的新密碼；修補前 record.error 因而變成
// `改密指令失敗: root:<新密碼> rejected by pam`——未加密落庫、經 API 反射、
// 並隨 alertFailure 送出產品邊界。
//
// 本守衛與 api/change_secret_candidate_leak_test.go 分工：那支守讀取端
// （端點不得反射秘密），本支守寫入端（runner 一開始就不得把遠端原文寫進欄位）。
// 修補回退成「遠端原文照舊併入」時，本檔第一個測試即轉紅。

// newPasswordFromServer 自靶機收到的 chpasswd stdin 取出本輪產生的新密碼。
// 新密碼是隨機的，測試無從預知——只能從遠端實收的位元組回推
func newPasswordFromServer(t *testing.T, srv *testSSHServer) string {
	t.Helper()
	raw, _ := srv.lastChpasswdStdin.Load().(string)
	require.NotEmpty(t, raw, "靶機未收到 chpasswd stdin：受測路徑未被走到")
	entry := lastNonEmptyLine(raw)
	idx := strings.Index(entry, ":")
	require.Greater(t, idx, 0, "chpasswd 條目格式非 user:password，無法取出新密碼")
	pw := entry[idx+1:]
	require.NotEmpty(t, pw)
	return pw
}

// assertReasonsAreCodes 全表掃描：record.error 與 candidate.last_error 只能是
// 封閉集合內的原因碼。任何動態字串被拼進來（無論是否含秘密）都會落在集合外
func assertReasonsAreCodes(t *testing.T, f *csFixture) {
	t.Helper()
	var recs []model.ChangeSecretRecord
	require.NoError(t, f.db.Find(&recs).Error)
	for _, r := range recs {
		assert.True(t, model.IsChangeSecretReason(r.Error),
			"record.error 非封閉集合內的原因碼（有動態字串被拼入）: %q", r.Error)
	}
	var cands []model.ChangeSecretCandidate
	require.NoError(t, f.db.Find(&cands).Error)
	for _, c := range cands {
		assert.True(t, model.IsChangeSecretReason(c.LastError),
			"candidate.last_error 非封閉集合內的原因碼（有動態字串被拼入）: %q", c.LastError)
	}
}

// TestChangeSecretRemoteStderrNeverReachesRecord 遠端 stderr 回吐新密碼時，
// record.error SHALL 只有原因碼——不得含新密碼、不得含任何遠端原文片段
func TestChangeSecretRemoteStderrNeverReachesRecord(t *testing.T) {
	f := setupChangeSecretFixture(t, "root", "oldpass123")
	f.server.mu.Lock()
	f.server.chpasswdEchoStdinToStderr = true
	f.server.chpasswdExitCode = 1 // 非零退出：stderr 必定送達客戶端（不受斷線競態影響）
	f.server.mu.Unlock()

	plan := f.plan(t, nil)
	records := f.runner.RunPlan(plan)
	require.Len(t, records, 1)

	require.Positive(t, f.server.chpasswdEchoFired.Load(), "stderr 回吐注入器未觸發：本測試不成立")
	require.Positive(t, f.server.chpasswdExitFired.Load(), "非零退出注入器未觸發：本測試不成立")

	newPassword := newPasswordFromServer(t, f.server)
	rec := records[0]

	assert.NotContains(t, rec.Error, newPassword,
		"record.error 含本輪新密碼明文：遠端可控字串被寫進未加密欄並會外送告警")
	assert.NotContains(t, rec.Error, "rejected by pam",
		"record.error 含遠端原文：遠端訊息 SHALL NOT 進入記錄欄")
	assert.NotContains(t, rec.Error, "oldpass123", "record.error 含舊密碼明文")
	assert.Equal(t, model.ChangeSecretReasonRemoteRejected, rec.Error,
		"遠端非零退出 SHALL 記為固定原因碼")
	// D3 的可知性語義不得因本修補而破壞
	assert.Equal(t, model.ChangeSecretFailed, rec.Status,
		"指令跑完但非零退出＝遠端確定未變更，SHALL 為 failed 而非 unverified")
	assert.EqualValues(t, 0, f.candidateCount(t), "遠端確定未變更 ⇒ 候選 SHALL 清除")
	assertReasonsAreCodes(t, f)
}

// TestChangeSecretRemoteStderrNeverReachesCandidateLastError 驗證階段失敗時，
// candidate.last_error 同樣只存原因碼（該欄與 record.error 一樣未加密且經 API 反射）
func TestChangeSecretRemoteStderrNeverReachesCandidateLastError(t *testing.T) {
	f := setupChangeSecretFixture(t, "root", "oldpass123")
	f.server.mu.Lock()
	f.server.chpasswdEchoStdinToStderr = true
	f.server.rejectVerifyLogin = true // 改密成功但新密驗證登入被拒 ⇒ 走 RecordFailure
	f.server.mu.Unlock()

	plan := f.plan(t, nil)
	records := f.runner.RunPlan(plan)
	require.Len(t, records, 1)
	require.Positive(t, f.server.verifyRejectFired.Load(), "驗證拒絕注入器未觸發：本測試不成立")

	newPassword := newPasswordFromServer(t, f.server)
	require.EqualValues(t, 1, f.candidateCount(t), "遠端狀態不可知 ⇒ 候選 SHALL 保留")

	var cand model.ChangeSecretCandidate
	require.NoError(t, f.db.First(&cand).Error)
	assert.NotContains(t, cand.LastError, newPassword, "candidate.last_error 含新密碼明文")
	assert.Equal(t, model.ChangeSecretReasonVerifyFailed, cand.LastError,
		"last_error SHALL 只存原因碼")
	assert.Equal(t, model.ChangeSecretUnverified, records[0].Status)
	assert.Equal(t, model.ChangeSecretReasonVerifyFailed, records[0].Error)

	// 重試路徑（另一個 last_error 寫入點）同樣不得帶入庫原文
	f.retry.RetryOne(&cand)
	var after model.ChangeSecretCandidate
	require.NoError(t, f.db.First(&after, cand.ID).Error)
	assert.True(t, model.IsChangeSecretReason(after.LastError),
		"重試失敗寫入的 last_error 非原因碼: %q", after.LastError)
	assertReasonsAreCodes(t, f)
}

// TestChangeSecretAlertPayloadHasNoRemoteText 告警離開產品邊界，內容 SHALL 只有
// 機器碼＋固定文案。
//
// 本測試端到端攔截**產品實際送出**的位元組：真 AlertNotifier ＋ webhook 通道指向
// httptest server，斷言對象是 HTTP request body 原文，而非測試自己拼的字串。
// 因此 alertFailure 改格式或新增動態來源時，本測試會一併守住。
func TestChangeSecretAlertPayloadHasNoRemoteText(t *testing.T) {
	f := setupChangeSecretFixture(t, "root", "oldpass123")
	require.NoError(t, f.db.AutoMigrate(&model.NotificationChannel{}))

	var mu sync.Mutex
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	require.NoError(t, f.db.Create(&model.NotificationChannel{
		Name: "ops", Type: "webhook", URL: srv.URL, Enabled: true, Language: "zh-TW",
	}).Error)

	notifier := audit.NewAlertNotifier(f.db, nil)
	require.NoError(t, notifier.LoadChannels())
	notifier.Start()
	runner := NewChangeSecretRunner(f.db, f.assets, f.candidates, f.hostKeys, notifier)

	f.server.mu.Lock()
	f.server.chpasswdEchoStdinToStderr = true
	f.server.chpasswdExitCode = 1
	f.server.mu.Unlock()

	plan := f.plan(t, nil)
	records := runner.RunPlan(plan)
	require.Len(t, records, 1)
	require.Positive(t, f.server.chpasswdEchoFired.Load(), "stderr 回吐注入器未觸發：本測試不成立")
	newPassword := newPasswordFromServer(t, f.server)

	// 告警由背景 worker 非同步送出，等實際離開產品邊界的位元組落袋
	deadline := time.Now().Add(5 * time.Second)
	var got []string
	for time.Now().Before(deadline) {
		mu.Lock()
		got = append([]string(nil), bodies...)
		mu.Unlock()
		if len(got) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	require.NotEmpty(t, got, "告警未送達 webhook：本測試不成立（未攔到任何實際送出的內容）")

	for _, body := range got {
		t.Logf("實際離開產品邊界的 webhook body: %s", body)
		assert.NotContains(t, body, newPassword, "告警內容含新密碼明文：秘密會離開產品邊界")
		assert.NotContains(t, body, "rejected by pam", "告警內容含遠端原文")
		assert.NotContains(t, body, "oldpass123", "告警內容含舊密碼明文")
		assert.Contains(t, body, model.ChangeSecretReasonRemoteRejected,
			"告警 SHALL 帶原因碼，實得 %s", body)
	}
}

// TestChangeSecretLocalPreconditionIsCleanFailure 本地前置驗證（username 含 `:`）
// 在完全未接觸遠端時失敗 ⇒ SHALL 為乾淨 failed 且不留候選。
// 若誤歸為 unverified，候選會一直卡著並擋住該帳號後續全部改密（D8）
func TestChangeSecretLocalPreconditionIsCleanFailure(t *testing.T) {
	f := setupChangeSecretFixture(t, "ro:ot", "oldpass123")
	plan := f.plan(t, nil)

	records := f.runner.RunPlan(plan)
	require.Len(t, records, 1)
	require.Positive(t, f.server.passwordAuthCalls.Load(),
		"未走到登入：測到的不是本地前置驗證（可能停在更前面的解析階段）")
	require.EqualValues(t, 0, f.server.chpasswdCalls.Load(),
		"遠端已收到 chpasswd：本地前置驗證未在送出前攔下，測試前提不成立")

	assert.Equal(t, model.ChangeSecretFailed, records[0].Status,
		"本地前置驗證失敗＝遠端未被觸及，SHALL NOT 歸為 unverified")
	assert.Equal(t, model.ChangeSecretReasonInvalidAccountName, records[0].Error)
	assert.EqualValues(t, 0, f.candidateCount(t),
		"乾淨失敗 SHALL 清候選，否則該帳號後續改密會被 D8 永久擋下")
}

// TestChangeSecretRemoteStderrNeverReachesUnknownStateRecord 補上「指令送達後斷線」
// 這條路徑的守衛——它正是本缺陷被實證的路徑（回吐 stderr 後斷線 ⇒ 非 ExitError
// ⇒ unverified），而其餘三支守衛走的是非零退出與驗證失敗，皆繞開了它。
//
// **本測試的界定**：它是「該分支的形狀守衛」——保證斷線路徑寫出的 record.error
// 恆為純原因碼；它**不**證明遠端原文確實抵達過客戶端（`chpasswdEchoFired` 只證明
// 靶機寫了 stderr，斷線下是否送達本就是競態）。
//
// **斷言選「恰等於原因碼」而非「不含新密碼」**：實測突變（把 last_error 改回遠端
// 原文）顯示 not-contains 斷言不會響——該路徑的原文是 SSH 交握訊息、根本不含新密碼，
// 只有等值斷言響。故形狀守衛必須用等值：任何動態字串被拼進來就不等於純原因碼。
func TestChangeSecretRemoteStderrNeverReachesUnknownStateRecord(t *testing.T) {
	f := setupChangeSecretFixture(t, "root", "oldpass123")
	f.server.mu.Lock()
	f.server.chpasswdEchoStdinToStderr = true
	f.server.chpasswdDropConn = true // 指令已送達但回應永遠不到：遠端狀態不可知
	f.server.mu.Unlock()

	plan := f.plan(t, nil)
	records := f.runner.RunPlan(plan)
	require.Len(t, records, 1)

	require.Positive(t, f.server.chpasswdEchoFired.Load(), "stderr 回吐注入器未觸發：本測試不成立")
	require.Positive(t, f.server.chpasswdDropFired.Load(), "斷線注入器未觸發：本測試不成立")

	rec := records[0]
	assert.Equal(t, model.ChangeSecretUnverified, rec.Status,
		"指令送達但回應未到＝遠端狀態不可知，SHALL 為 unverified")
	assert.Equal(t, model.ChangeSecretReasonRemoteStateUnknown, rec.Error,
		"狀態不可知分支的 record.error SHALL 只有原因碼（遠端原文不得拼入）")
	require.EqualValues(t, 1, f.candidateCount(t), "遠端狀態不可知 ⇒ 候選 SHALL 保留待重試")
	assertReasonsAreCodes(t, f)
}
