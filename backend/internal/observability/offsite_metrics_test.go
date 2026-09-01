package observability

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// 離機儲存指標的三態曝光（指標清單＋停用態表）。
//
// # 這一組測試在防什麼
//
// 三種狀態在 `/metrics` 上必須**可分辨**，而分辨的方式是序列的有無，不是值：
//
//	設定表零列（從未設定） 全部 custodexa_offsite_ 序列缺席
//	停用態（零現行世代）   上傳車道缺席、存量與失敗面照常
//	有現行世代             全部曝光
//
// 若把上傳車道在停用態下也留著，採集端讀到的是「待上傳恆為 0、最後成功時刻
// 停在某個過去」——那與「一切正常且無事可做」在 PromQL 上無從分辨，而
// `absent()` 對缺席能給出明確答案。這是本組測試唯一要守的東西。

// offsiteUploadLaneSeries 上傳車道的序列名（停用態下 SHALL 全部缺席）。
var offsiteUploadLaneSeries = []string{
	"custodexa_offsite_pending",
	"custodexa_offsite_uploading",
	"custodexa_offsite_oldest_pending_age_seconds",
	"custodexa_offsite_last_success_timestamp_seconds",
	"custodexa_offsite_uploads_total",
	"custodexa_offsite_uploaded_bytes_total",
	"custodexa_offsite_lease_expired_total",
}

// offsiteInventorySeries 存量與失敗面的序列名（停用態下 SHALL 全部存在）。
var offsiteInventorySeries = []string{
	"custodexa_offsite_failed",
	"custodexa_offsite_integrity_mismatch",
	"custodexa_offsite_foreign",
	"custodexa_offsite_generations",
	"custodexa_offsite_spool_bytes",
	"custodexa_offsite_credential_state",
}

// offsiteFullSnapshot 每一條序列都有非零值的快照。
//
// **刻意讓每個標籤組都非零**：Prometheus 的 GaugeVec 在沒有任何標籤組被寫入時
// 本來就不會輸出任何一行，「缺席」的斷言若跑在空快照上就會由假前提成立。
func offsiteFullSnapshot() OffsiteQueueSnapshot {
	return OffsiteQueueSnapshot{
		Pending: map[OffsiteKindOrigin]float64{
			{Kind: "recording", Origin: "live"}:     3,
			{Kind: "recording", Origin: "backfill"}: 7,
		},
		Uploading:               map[string]float64{"recording": 1},
		Failed:                  map[string]float64{"recording": 2},
		IntegrityMismatch:       map[string]float64{"export": 1},
		Foreign:                 map[string]float64{"recording": 5},
		OldestPendingAgeSeconds: map[string]float64{"backfill": 864000},
		Generations:             2,
		SpoolBytes:              4096,
		CredentialState:         "ok",
	}
}

// TestOffsiteSeriesAbsentWhenNeverConfigured 設定表零列＝全部離機序列缺席。
//
// **這一格是「未設定＝行為完全不變」在指標面的機械保證**：兩個註冊函式都沒被
// 呼叫時，即使有人照樣呼叫 SetOffsiteQueue 與 worker 直寫方法（實際不會，
// 但那正是要防的裝配疏漏），曝光內容仍不得多出任何一條 custodexa_offsite_ 序列。
func TestOffsiteSeriesAbsentWhenNeverConfigured(t *testing.T) {
	m := New()
	m.RegisterStage2()

	// 明知未註冊仍照常寫入：曝光與否由註冊決定，不由呼叫端再判一次
	m.SetOffsiteQueue(offsiteFullSnapshot())
	m.ObserveOffsiteUpload("recording", OffsiteUploadResultUploaded, 1024)
	m.ObserveOffsiteLeaseExpired("recording")
	m.SetOffsiteLastSuccess(time.Now())

	body := gatherBody(t, m)
	require.NotContains(t, body, "custodexa_offsite_",
		"設定表零列時竟曝光了離機序列：「未設定＝行為完全不變」在指標面破功，"+
			"採集端會把一個從未啟用的功能讀成「已啟用且一切為零」")
}

// TestOffsiteMetricsDisabledStateKeepsInventorySeries 停用態：上傳車道缺席、存量面照常。
//
// 具名依驗收條款。與零列態各一格，兩者**不得合併**——
// 合併之後「停用時整組消失」與「停用時只少了車道」會用同一個斷言通過。
func TestOffsiteMetricsDisabledStateKeepsInventorySeries(t *testing.T) {
	m := New()
	m.RegisterStage2()
	m.RegisterOffsiteInventory() // 停用態只註冊這一面

	m.SetOffsiteQueue(offsiteFullSnapshot())
	// worker 在停用態不存在，但即使有人誤呼叫，車道序列仍須缺席
	m.ObserveOffsiteUpload("recording", OffsiteUploadResultUploaded, 1024)
	m.SetOffsiteLastSuccess(time.Now())

	body := gatherBody(t, m)
	for _, name := range offsiteInventorySeries {
		require.Contains(t, body, name,
			"停用態下 %s 竟缺席：停用不代表既有物件消失，失敗清單與取回仍在服務——"+
				"把存量面一起藏起來，管理員就看不見「還有幾件從未上傳成功」", name)
	}
	for _, name := range offsiteUploadLaneSeries {
		require.NotContains(t, body, name,
			"停用態下 %s 竟存在：worker 不在跑而序列還在，採集端讀到的「待上傳為 0」"+
				"與「一切正常且無事可做」無從分辨", name)
	}
}

// TestOffsiteMetricsEnabledStateExposesBothFaces 有現行世代：兩面皆曝光。
//
// 正對照。少了它，上面兩格可以由「這些序列永遠不存在」滿足。
func TestOffsiteMetricsEnabledStateExposesBothFaces(t *testing.T) {
	m := New()
	m.RegisterStage2()
	m.RegisterOffsiteInventory()
	m.RegisterOffsiteUploadLane()

	m.SetOffsiteQueue(offsiteFullSnapshot())
	m.ObserveOffsiteUpload("recording", OffsiteUploadResultUploaded, 1024)
	m.ObserveOffsiteUpload("recording", OffsiteUploadResultFailed, 0)
	m.ObserveOffsiteLeaseExpired("recording")
	m.SetOffsiteLastSuccess(time.Unix(1735689600, 0))

	body := gatherBody(t, m)
	for _, name := range append(append([]string{}, offsiteInventorySeries...), offsiteUploadLaneSeries...) {
		require.Contains(t, body, name, "啟用態下 %s 缺席", name)
	}
	// 標籤與值的抽樣（不逐條比對全文——那會讓任何一次 Help 文字調整都轉紅）
	require.Contains(t, body, `custodexa_offsite_pending{kind="recording",origin="backfill"} 7`)
	require.Contains(t, body, `custodexa_offsite_uploads_total{kind="recording",result="uploaded"} 1`)
	require.Contains(t, body, `custodexa_offsite_uploads_total{kind="recording",result="failed"} 1`)
	require.Contains(t, body, `custodexa_offsite_uploaded_bytes_total{kind="recording"} 1024`)
	require.Contains(t, body, `custodexa_offsite_lease_expired_total{kind="recording"} 1`)
	require.Contains(t, body, "custodexa_offsite_last_success_timestamp_seconds 1.7356896e+09")
	require.Contains(t, body, "custodexa_offsite_generations 2")
	require.Contains(t, body, "custodexa_offsite_spool_bytes 4096")
}

// TestOffsiteCredentialStateFailedIsDistinctFromUnconfigured 金鑰事故不得被併吞為未設定。
//
// 紅線：解密失敗是**事故**，不是功能關閉。少了這條序列，
// 「憑證解不開」在指標面只會表現為上傳失敗數上升——而網路抖動也會讓它上升，
// 兩者無從分辨；前者需要立刻有人去看，後者不需要。
func TestOffsiteCredentialStateFailedIsDistinctFromUnconfigured(t *testing.T) {
	cases := []struct{ state, want string }{
		{"unconfigured", `custodexa_offsite_credential_state{state="unconfigured"} 1`},
		{"ok", `custodexa_offsite_credential_state{state="ok"} 1`},
		{"failed", `custodexa_offsite_credential_state{state="failed"} 1`},
	}
	for _, tc := range cases {
		t.Run(tc.state, func(t *testing.T) {
			m := New()
			m.RegisterStage2()
			m.RegisterOffsiteInventory()

			snap := offsiteFullSnapshot()
			snap.CredentialState = tc.state
			m.SetOffsiteQueue(snap)

			body := gatherBody(t, m)
			require.Contains(t, body, tc.want, "當前態未標為 1")
			// 全集皆曝光（enum 慣例）：採集端不必處理缺值
			for _, other := range OffsiteCredentialStates {
				require.Contains(t, body,
					`custodexa_offsite_credential_state{state="`+other+`"}`,
					"態 %q 的序列缺席：enum 曝光必須給全集，否則 PromQL 讀不出「不在該態」", other)
			}
			if tc.state != "failed" {
				require.Contains(t, body, `custodexa_offsite_credential_state{state="failed"} 0`,
					"非事故態下 failed 竟不是 0")
			}
		})
	}
}

// TestOffsiteQueueAbsentLanesDoNotBecomeZero 缺席與 0 是兩件事。
//
// `OldestPendingAges` 對「無待上傳件的車道」是**不回該鍵**（帳冊層的刻意設計）。
// 若指標層把缺席的鍵補成 0，回填車道從「積壓 10 天」變成「0 秒」時，
// 採集端看到的是一個健康值，而不是序列消失——後者才是「該車道現在沒東西」的
// 正確表達。`Reset` 之後只寫有值的鍵即為此。
func TestOffsiteQueueAbsentLanesDoNotBecomeZero(t *testing.T) {
	m := New()
	m.RegisterStage2()
	m.RegisterOffsiteInventory()
	m.RegisterOffsiteUploadLane()

	m.SetOffsiteQueue(offsiteFullSnapshot())
	require.Contains(t, gatherBody(t, m), `custodexa_offsite_oldest_pending_age_seconds{origin="backfill"}`,
		"前置條件不成立：積壓序列一開始就不存在，下面的「消失」斷言將由假前提成立")

	// 積壓清空：該車道的鍵自快照消失
	drained := offsiteFullSnapshot()
	drained.OldestPendingAgeSeconds = map[string]float64{}
	drained.Pending = map[OffsiteKindOrigin]float64{}
	m.SetOffsiteQueue(drained)

	body := gatherBody(t, m)
	require.NotContains(t, body, `custodexa_offsite_oldest_pending_age_seconds{origin="backfill"}`,
		"積壓清空後序列竟仍在：值會停在最後一個非零數，讓「已清空」看起來像「還在積壓」")
	require.NotContains(t, body, `custodexa_offsite_pending{kind="recording"`,
		"待上傳清空後標籤組竟仍在（Reset 未生效）")
	// 計數器不受 Reset 影響（累計語義）
	require.Contains(t, body, "custodexa_offsite_generations 2", "存量面不該被車道的 Reset 波及")
}

// TestOffsiteRegistrationIsIdempotent B 模式重複解封不得重複註冊。
//
// 重複 `MustRegister` 會 panic，而那發生在解封路徑上——一次重新解封就會殺掉行程。
func TestOffsiteRegistrationIsIdempotent(t *testing.T) {
	m := New()
	m.RegisterStage2()
	require.NotPanics(t, func() {
		for i := 0; i < 3; i++ {
			m.RegisterOffsiteInventory()
			m.RegisterOffsiteUploadLane()
		}
	}, "重複註冊 panic：B 模式下每次解封都會走到這裡")

	body := gatherBody(t, m)
	require.Equal(t, 1, strings.Count(body, "# TYPE custodexa_offsite_generations gauge"),
		"同一條序列被註冊了不只一次")
}
