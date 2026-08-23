package audit

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/notifycat"
)

// 鏈驗證告警的**去識別出站守衛**。
//
// **為什麼是紅線**：失效通知走的是使用者自行設定的外部通道（webhook／IM／郵件），
// 那條路徑上的收件端不在本系統的存取控制之內。出站 payload 若帶著「哪幾個檢查點
// 區間對不上」「哪一段紀錄編號被動過」，等於把「去哪裡找最有價值的審計紀錄、
// 以及那裡的防護已經失效」這件事，主動廣播給一個未經授權的通道——對竄改者而言
// 是精準的回饋訊號。碼與計數足以讓收件人知道「要進系統看」，而細節只能在系統內
// 經認證後查閱（cause_params 落 DB、驗證頁揭露）。
//
// **本守衛與既有紀律的關係**：`CauseParamDetail` 絕不進出站 payload 已是既有紀律
// （audit_failure_service.go 的 Report 只把碼放進 outbound）。本 change 新增了
// 兩個會被塞進 params 的識別資訊——`FailureParamChainVerifyLayer`（層別）與失敗
// 區間集合的 seq——故把該紀律從「散文承諾」升級為對**真實出站路徑**的可執行斷言。
//
// **測的是真實路徑，不是替身**：本檔刻意不用 fakeChainAlerter，而是把真的
// `AuditFailureService` 接上 `ChainVerifyService`，只在最末端（notify 出口）攔截。
// 用替身測「出站帶了什麼」等於測自己寫的替身——中間任何一段把 params 原封轉出的
// 寫法都測不出來。

// ── 允許出站的閉集合 ──────────────────────────────────────────────────────

// chainVerifyOutboundAllowedKeys 每個事件允許出現的 params 鍵（**閉集合**）。
//
// 白名單而非黑名單：黑名單要求「想得到所有不該出去的東西」，而識別資訊的形態
// 是開放的（seq、id 區間、層別、檔案路徑、err 原文……）。閉集合使「新增一個看似
// 無害的參數」預設為紅，作者必須回到這裡顯式主張它可出站。
var chainVerifyOutboundAllowedKeys = map[notifycat.Event]map[string]bool{
	notifycat.EventAuditFailure: {
		"mechanism":                       true,
		"started_at":                      true,
		"cause_code":                      true,
		model.FailureParamFailedPoints:    true,
		model.FailureParamFailedIntervals: true,
	},
	notifycat.EventAuditFailureOngoing: {
		"mechanism":                       true,
		"cause_code":                      true,
		"reported_at":                     true,
		model.FailureParamFailedPoints:    true,
		model.FailureParamFailedIntervals: true,
	},
	notifycat.EventAuditFailureResolved: {
		"mechanism":  true,
		"interval":   true,
		"started_at": true,
		"ended_at":   true,
	},
}

// chainVerifyOutboundEnums 只允許取自機器碼閉集合的鍵。
//
// **僅有鍵白名單不夠**：`cause_code` 若被改成「碼＋冒號＋err 原文」（那正是
// `CauseText` 的形態，且它就在同一支服務裡），鍵名不變而識別資訊照樣出站。
// 值域一併釘死之後，自由字串沒有任何合法的落腳點。
var chainVerifyOutboundEnums = map[string]map[string]bool{
	"mechanism": {
		model.MechanismAuditChainStructure: true,
		model.MechanismAuditChainContent:   true,
		model.MechanismAuditChainVerify:    true,
	},
	"cause_code": {
		model.CauseAuditChainStructureInvalid: true,
		model.CauseAuditChainContentMismatch:  true,
		model.CauseAuditChainContentExtraRows: true,
		model.CauseAuditChainVerifyFailed:     true,
	},
	"interval": {
		notifycat.IntervalKnown:   true,
		notifycat.IntervalUnknown: true,
	},
}

var chainVerifyOutboundTimestampKeys = map[string]bool{
	"started_at": true, "ended_at": true, "reported_at": true,
}

var chainVerifyOutboundCountKeys = map[string]bool{
	model.FailureParamFailedPoints: true, model.FailureParamFailedIntervals: true,
}

// ── 夾具 ──────────────────────────────────────────────────────────────────

type outboundCall struct {
	event  notifycat.Event
	params map[string]string
}

// deidentFixture 把**真的** AuditFailureService 接上 ChainVerifyService，
// 只攔截最末端的 notify 出口
type deidentFixture struct {
	*chainVerifyFixture
	failures *AuditFailureService
	sent     []outboundCall
}

func setupDeidentFixture(t *testing.T) *deidentFixture {
	t.Helper()
	base := setupChainVerifyFixture(t)
	if err := base.db.AutoMigrate(&model.AuditFailureEvent{}); err != nil {
		t.Fatalf("migrate failure events: %v", err)
	}
	// **必須把 failure_alert_enabled 打開**：出廠值為 false，sendNotify 會靜默
	// 丟棄全部投遞——那樣本守衛會在「零筆出站」下全綠，而零筆什麼都證明不了。
	// 下方另有出站筆數與事件覆蓋的下限斷言把這個孔堵死
	if err := base.db.Create(&model.SecurityPolicy{
		Key: policy.PolicyFailureAlertEnabled, Value: "true", UpdatedAt: time.Now(),
	}).Error; err != nil {
		t.Fatalf("開啟失效告警政策: %v", err)
	}

	f := &deidentFixture{chainVerifyFixture: base}
	f.failures = &AuditFailureService{
		db:     base.db,
		policy: policy.NewSecurityPolicyService(base.db),
		notify: func(event notifycat.Event, params map[string]string) {
			// 複製一份：呼叫端的 map 之後可能被重用
			cp := make(map[string]string, len(params))
			for k, v := range params {
				cp[k] = v
			}
			f.sent = append(f.sent, outboundCall{event: event, params: cp})
		},
	}
	if !f.failures.AlertEnabled() {
		t.Fatal("測試前提失效：failure_alert_enabled 未生效，出站將被靜默丟棄")
	}
	// 真服務取代替身，成為 ChainVerifyService 的告警出口
	base.svc.alerts = f.failures
	return f
}

// assertClean 逐筆檢查出站 payload；forbidden 為「已知落在 cause_params／狀態表、
// SHALL NOT 出站」的字串（層別、err 原文片段、seq 字面）
func (f *deidentFixture) assertClean(t *testing.T, forbidden []string) {
	t.Helper()
	for i, call := range f.sent {
		allowed, ok := chainVerifyOutboundAllowedKeys[call.event]
		if !ok {
			t.Errorf("出站 #%d：事件 %q 不在受管清單內——新增的通知事件 SHALL 同時登記其"+
				"允許鍵閉集合，否則新事件天生繞過去識別守衛", i, call.event)
			continue
		}
		for key, val := range call.params {
			if !allowed[key] {
				t.Errorf("出站 #%d（event=%s）帶了未經許可的參數 %q=%q：出站只帶碼與受控計數，"+
					"序號、紀錄區間、層別與任何自由字串一律只落 cause_params（DB）與驗證頁",
					i, call.event, key, val)
				continue
			}
			switch {
			case chainVerifyOutboundEnums[key] != nil:
				if !chainVerifyOutboundEnums[key][val] {
					t.Errorf("出站 #%d（event=%s）的 %q=%q 不是機器碼閉集合的成員："+
						"碼欄一旦承載自由字串（例如 CauseText 的「碼：err 原文」形態），"+
						"識別資訊就從鍵名合法的欄位溜出去了", i, call.event, key, val)
				}
			case chainVerifyOutboundTimestampKeys[key]:
				if _, err := time.Parse(time.RFC3339, val); err != nil {
					t.Errorf("出站 #%d（event=%s）的 %q=%q 不是 RFC3339 時間：時間欄是"+
						"自由字串最容易寄生的地方", i, call.event, key, val)
				}
			case chainVerifyOutboundCountKeys[key]:
				n, err := strconv.Atoi(val)
				if err != nil || n < 0 {
					t.Errorf("出站 #%d（event=%s）的 %q=%q 不是非負整數計數：計數欄"+
						"SHALL NOT 承載序號清單", i, call.event, key, val)
				}
			default:
				t.Errorf("出站 #%d（event=%s）的 %q 在允許鍵內但無值域規則——"+
					"允許出站即須釘住值域，否則鍵白名單只擋得住鍵名", i, call.event, key)
			}
		}
		// 內容檢查（與鍵／值域規則獨立）：已知的識別資訊字串一個都不得出現
		for _, bad := range forbidden {
			for key, val := range call.params {
				if strings.Contains(val, bad) {
					t.Errorf("出站 #%d（event=%s）的 %q=%q 含識別資訊 %q",
						i, call.event, key, val, bad)
				}
			}
		}
	}
}

// seenEvents 出站事件覆蓋
func (f *deidentFixture) seenEvents() map[notifycat.Event]int {
	out := map[notifycat.Event]int{}
	for _, c := range f.sent {
		out[c.event]++
	}
	return out
}

func (f *deidentFixture) seenMechanisms() map[string]bool {
	out := map[string]bool{}
	for _, c := range f.sent {
		if m := c.params["mechanism"]; m != "" {
			out[m] = true
		}
	}
	return out
}

// ── 守衛 ──────────────────────────────────────────────────────────────────

// TestChainVerifyOutboundPayloadIsDeidentified 三個機制、三種事件的出站 payload
// 全部只含碼與計數。
//
// **場景刻意走完整條真實路徑**：開立（Report）→ 集合改變後的重發（NotifyOngoing）
// → 結案（Resolve），外加結構層與「驗證本身失敗」兩個機制。三者的 params 在呼叫端
// 各自帶著不該出站的東西（層別、err 原文），而它們都必須在 AuditFailureService
// 的出站邊界被擋下。
func TestChainVerifyOutboundPayloadIsDeidentified(t *testing.T) {
	f := setupDeidentFixture(t)
	seqs := f.sealIntervals(t, 4, 3)
	x := seqs[0]

	// 每輪預算小到滾動窗推不完，使必驗集合與滾動窗的分工真的發生
	f.tuning.rows = 10000
	f.tuning.interval = 3 * time.Second

	st := f.state(t)
	st.ContentCursorSeq = x
	if err := f.svc.saveState(st); err != nil {
		t.Fatalf("save cursor: %v", err)
	}

	// ── 第 1 輪：抽掉 X 的中段列 → 內容層開立（EventAuditFailure）──
	victim := f.rowIn(t, x, 1)
	f.mustExec(t, "DELETE FROM audit_logs WHERE id = ?", victim.ID)
	if err := f.svc.RunFullNow(context.Background()); err != nil {
		t.Fatalf("第 1 輪: %v", err)
	}
	open := decodeSeqSet(f.state(t).OpenFailedSeqs)
	if _, ok := open[x]; !ok {
		t.Fatalf("測試前提失效：第 1 輪未把 seq=%d 收入失敗區間集合（實得 %v）", x, open)
	}

	// ── 第 2 輪：再抽鏈尾一列 → 集合改變 → 重發（EventAuditFailureOngoing）──
	tail := seqs[len(seqs)-1]
	tailVictim := f.rowIn(t, tail, 1)
	f.mustExec(t, "DELETE FROM audit_logs WHERE id = ?", tailVictim.ID)
	if err := f.svc.RunFullNow(context.Background()); err != nil {
		t.Fatalf("第 2 輪: %v", err)
	}

	// ── 第 3 輪：兩列原樣放回 → 集合清空 → 結案（EventAuditFailureResolved）──
	for _, row := range []model.AuditLog{victim, tailVictim} {
		restore := row
		if err := f.db.Create(&restore).Error; err != nil {
			t.Fatalf("還原被抽的列: %v", err)
		}
	}
	if err := f.svc.RunFullNow(context.Background()); err != nil {
		t.Fatalf("第 3 輪: %v", err)
	}

	// ── 第 4 輪：竄改檢查點簽章 → 結構層機制開立 ──
	f.mustExec(t, "UPDATE audit_checkpoints SET signature = ? WHERE seq = ?", "AAAA", seqs[1])
	if err := f.svc.RunFullNow(context.Background()); err != nil {
		t.Fatalf("第 4 輪: %v", err)
	}

	// ── 第 5 輪：簽章服務不可用 → 「驗證本身失敗」機制（params 帶 err 原文）──
	blind := NewChainVerifyService(f.db, f.verifier, f.seal,
		&stubChainSigner{ready: false}, f.pol, f.tuning, f.failures)
	if err := blind.RunFullNow(context.Background()); err == nil {
		t.Fatal("測試前提失效：簽章服務不可用時應回依賴自檢錯誤")
	}

	// ── 覆蓋下限：零筆或缺事件時本守衛什麼都沒證明 ──
	events := f.seenEvents()
	for _, want := range []notifycat.Event{
		notifycat.EventAuditFailure,
		notifycat.EventAuditFailureOngoing,
		notifycat.EventAuditFailureResolved,
	} {
		if events[want] == 0 {
			t.Fatalf("出站事件 %s 零筆——場景未走到該路徑，守衛在空集合下假綠。實得 %v",
				want, events)
		}
	}
	mechs := f.seenMechanisms()
	for _, want := range []string{
		model.MechanismAuditChainStructure,
		model.MechanismAuditChainContent,
		model.MechanismAuditChainVerify,
	} {
		if !mechs[want] {
			t.Fatalf("機制 %s 未曾出站——三個機制碼須各自被檢查過，實得 %v", want, mechs)
		}
	}

	// ── 逐筆去識別斷言 ──
	// **forbidden 只列「合法值域內絕不可能出現」的字串**：層別與 err 原文片段。
	// seq 不以字面比對——單一數字與時間戳、計數天然重疊，比對它只會製造噪音而非訊號；
	// seq 清單的不可出站由上方的值域規則承擔（計數欄須通過 Atoi，"3,4" 這種清單
	// 過不了，任何碼欄須是閉集合成員），那是結構性的保證而非字串黑名單
	f.assertClean(t, []string{
		ChainVerifyLayerRecent, ChainVerifyLayerFull, // 層別只進 cause_params
		"依賴自檢", // 「驗證本身失敗」的 err 原文片段
		"簽章服務", // 同上
		"agg_hash",
	})

	// ── 反向：識別資訊確實有被保存下來（只是不出站）──
	// 沒有這一段，把 cause_params 一起清空也會讓上面全綠——那是「去識別」
	// 過了頭變成「沒有證據」，稽核端反而無從追查
	var evt model.AuditFailureEvent
	if err := f.db.Where("mechanism = ?", model.MechanismAuditChainContent).
		Order("started_at ASC").First(&evt).Error; err != nil {
		t.Fatalf("內容層失效事件應留有 DB 列: %v", err)
	}
	if !strings.Contains(evt.CauseParams, model.FailureParamChainVerifyLayer) {
		t.Errorf("層別 SHALL 落 cause_params 供稽核（實得 %q）——出站不帶不等於不記錄",
			evt.CauseParams)
	}
}

// TestChainVerifyOutboundCountWhitelistDropsUnknownKeys 出站計數白名單是閉集合：
// 不在表內的計數鍵一律丟棄，不隨機制新增而自動放行。
//
// 與上一條分工：上一條驗「現行呼叫端沒有塞髒東西」，本條驗「就算日後有人塞了，
// 出站邊界仍會擋下」。只有前者時，白名單被整個拆掉也不會轉紅——因為現行呼叫端
// 本來就沒有髒東西可漏。
func TestChainVerifyOutboundCountWhitelistDropsUnknownKeys(t *testing.T) {
	f := setupDeidentFixture(t)

	f.failures.ReportWithCounts(model.MechanismAuditChainContent,
		model.CauseAuditChainContentMismatch,
		map[string]string{
			model.FailureParamChainVerifyLayer: ChainVerifyLayerFull,
			model.CauseParamDetail:             "seq 7,8,9 的 agg_hash 不符",
		},
		map[string]int{
			model.FailureParamFailedIntervals: 3,
			"failed_seqs":                     789, // 白名單外：SHALL 被丟棄
		})

	if len(f.sent) != 1 {
		t.Fatalf("應有一筆出站，實得 %d 筆", len(f.sent))
	}
	if _, ok := f.sent[0].params["failed_seqs"]; ok {
		t.Error("白名單外的計數鍵進了出站 payload：閉集合失效，" +
			"「新增一個看似無害的參數」將自動獲得出站許可")
	}
	f.assertClean(t, []string{ChainVerifyLayerFull, "agg_hash", "7,8,9"})
}
