package asset

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 強制審計 fail-close 的 **runtime fault-injection backstop**
// （modular-architecture W4 任務 4.12c；codex W1 外審焦點 C4 的解方）。
//
// # 為什麼這組測試的優先序高於所有 AST 守衛
//
// 現有的兩道機器保護——產生點掃描（`cmd/server/audit_points_manifest_guard_test.go`）
// 與交易歸屬判定（`audit_points_tx_dataflow_test.go`）——**共用同一個 oracle**：
// 都靠語法形態辨識「哪裡在寫審計」。wrapper、原生 SQL、反射、生成碼、介面派發
// 會讓兩者**同時失明**，而且失明時兩邊仍然互相一致、全綠。這是典型的相關性失敗，
// 加再多 AST 規則都發現不了。
//
// 本組測試換一種 oracle：**從執行期觀察**。注入「審計列寫不進去」這個故障，
// 然後斷言業務交易**真的回滾**——業務列不存在、審計列也不存在。它不問審計是
// 怎麼寫的、經過幾層 wrapper、走 TxSink 還是 `model.RecordAsset*Change`；
// 它只問「審計沒寫成的時候，業務操作有沒有成立」。那正是 fail-close 的定義。
//
// # 故障注入點：GORM Create callback，而不是替身 sink
//
// 刻意**不**用「傳一個永遠回錯的 TxSink 替身」——那只證明得了「已經改走 TxSink 的
// 那幾條路徑」，而 T-2 的 11 個點在 W4 尚未收口（走 `model.RecordAsset*Change` 的
// `tx.Create`）。註冊在 `audit_logs` 上的 Create callback 對兩種形態一視同仁，
// 也對未來任何新的寫入形態一視同仁——**這是換 oracle 的關鍵**，不是實作上的方便。
//
// # 🔴 射程與盲區（codex W4 外審焦點 1；**不得再無條件稱「最終權威」**）
//
// 本組是 **GORM Create callback 路徑上的最終權威**，不是所有審計寫入路徑的最終權威。
// 注入器**看得見**的：任何經由本測試持有的 `*gorm.DB` 句柄（含其 `Session`／交易衍生
// 句柄）走 GORM `Create`／`CreateInBatches` 落地的 `audit_logs` 寫入——不論走 TxSink、
// GORM hook、還是 `model.RecordAsset*Change`。
//
// 注入器**看不見**（下方 `TestBackstopBlindSpots*` 逐條實測，使盲區可見而非隱形）：
//
//	B-a 原生 SQL：`db.Exec("INSERT INTO audit_logs …")` 走 Raw callback，不經 Create；
//	B-b Update callback 路徑：對既有列 `Save`／`Updates` 改寫審計列不經 Create；
//	B-c 全新句柄：另行 `gorm.Open` 取得的 `*gorm.DB` 沒有本測試註冊的 callback；
//	B-d 非 GORM 寫入：`database/sql` 直連、外部程序、其他服務寫同一張表。
//
// **批次（`CreateInBatches`）不是盲區**——實測命中（見 `TestBackstopSeesBatchAuditWrites`），
// 且逐列抽出身分。現況生產碼零筆 B-a…B-d 形態的審計寫入；若日後出現（W6-W9 的
// raw SQL 審計寫入是最可能的來源），backlog B-15 的「DB 層 INSERT trigger 注入器」
// 升級為必做。
//
// # 誠實界定：覆蓋哪些點
//
// 本組覆蓋 manifest 中 `fail-close?＝是` 的交易內產生點（16 點，逐格見下方分節）。不覆蓋：
//   - AP-39／AP-41／AP-42（刻意 fail-open，收口時保持現況）；
//   - AP-23…AP-25（GORM hook，`Session(NewDB:true)` 明示脫離呼叫方交易——
//     它們的「fail-close」是 hook 自身回 error 使該次 Create 失敗，語義不同類）；
//   - AP-56／AP-57（封印回灌自開交易）於本檔不覆蓋，因為它們住 audit 包內、
//     取用未匯出的落地入口——對應案例在
//     `internal/modules/audit/seal_replay_sink_test.go` 的
//     `TestSealReplayFailCloseOnAuditWriteFailure`。

// ── 注入器：唯一哨兵＋身分比對＋強制對照組 ────────────────────────────────

// auditHit 一次被觀察到的審計列寫入（供身分比對與失敗訊息用）。
type auditHit struct {
	Table    string
	Action   string
	Resource string
	Details  string
}

func (h auditHit) String() string {
	d := h.Details
	if len(d) > 120 {
		d = d[:120] + "…"
	}
	return fmt.Sprintf("{table=%s action=%s resource=%s details=%s}", h.Table, h.Action, h.Resource, d)
}

// auditHitSpec 本格**預期命中**的審計點身分。
//
// # 為什麼「命中身分」比「命中次數」重要（codex W4 外審焦點 2）
//
// 舊版防呆只累計 `fired`：只要本次執行中有**任何**審計寫入被攔到就算數。這在
// 「一個操作寫多筆審計」的路徑上會**由不相干的那筆取得 credit**——最典型的是
// `AssetService.Create`：`(*Asset).AfterCreate` hook（AP-23）在
// `RecordAssetAccountChange`（AP-38）之前就寫了一筆。舊防呆對兩者一視同仁，
// 於是「AP-38 這格」實際上可能是被 AP-23 撐綠的；AP-38 即使整條被刪掉，
// 該格仍不會轉紅。
//
// 修法有兩半，缺一不可：
//  1. **選擇性注入**——只對命中 spec 的寫入注入失敗，不相干的審計寫入**照樣放行**。
//     於是被攔下的必然是本格要測的那一筆；hook 先寫的那筆不再能代打。
//  2. **唯一哨兵**——注入器回傳的 error 是本格獨有的值，每格斷言
//     `errors.Is(err, inj.sentinel)`。`err != nil` 可能來自任何前置失敗，
//     `errors.Is(sentinel)` 只可能來自「本格指定的審計點寫入被攔下」。
type auditHitSpec struct {
	// AP manifest 的穩定 ID（＋簡述），只用於錯誤訊息與可追溯性。
	AP string
	// Action／Resource 空字串＝不比對該欄。
	Action   model.AuditAction
	Resource model.AuditResource
	// Details 子字串比對（空＝不比對）。多數格靠它把同 action/resource 的
	// hook 事件（Details 恆為空字串）與顯式審計事件分開。
	Details string
}

func (s auditHitSpec) String() string {
	return fmt.Sprintf("{AP=%s action=%q resource=%q details⊇%q}", s.AP, s.Action, s.Resource, s.Details)
}

func (s auditHitSpec) matches(h auditHit) bool {
	if s.Action != "" && h.Action != string(s.Action) {
		return false
	}
	if s.Resource != "" && h.Resource != string(s.Resource) {
		return false
	}
	if s.Details != "" && !strings.Contains(h.Details, s.Details) {
		return false
	}
	return true
}

// auditFaultInjector 「寫指定審計點必失敗」的故障注入器（每格一個）。
//
// # 三道**獨立於被測邏輯**的防呆（全部在 t.Cleanup 強制，不可豁免）
//
//  1. **對照組已跑**（`controlDone`）——每格的斷言形態都是「業務列不存在／審計列
//     不存在／回了 error」，這三條在「查詢條件寫錯」「夾具根本沒建起業務列」
//     「多點共用一格而第一個點先失敗使後續點永不可達」時**也全部成立**。
//     故每格必須先以無故障對照證明：相同輸入確實建立了指定業務列、且確實抵達了
//     本格指定的審計點。沒跑對照＝該格為真空通過，Cleanup 轉紅。
//  2. **注入器命中過本格身分**（`injected > 0`）——證明控制流真的走到了本格指定的
//     審計寫入。前置條件早退（nil 依賴、env 缺項、marker 已寫、表不存在、服務
//     建構失敗……）一律使計數停在 0 而讓該格轉紅。AP-51 那格即因此假綠了一整波。
//  3. **哨兵歸因**（各格顯式呼叫 `assertCausedBy`／`assertRolledBack`）——回傳的
//     error 必須 `errors.Is` 得到本格的唯一哨兵。
//
// # 併發與共享狀態（codex W4 外審焦點 2 之二）
//
// 真正的風險不是 `t.Cleanup` 被跳過（Go 的正常 panic 仍會執行 Cleanup），而是：
//   - **平行子測試共享同一個 DB／callback**——本檔每格自建 DB 句柄（`setupAccountDB`
//     另外還會改寫套件級 `database.DB`），故本檔**禁止 `t.Parallel`**，由
//     `TestBackstopGridsDeclareNoParallel` 以原始碼掃描機器化；
//   - **計數交叉抵帳**——計數與觀察表全部在 `mu` 之下，且每個計數器綁定單一
//     injector 實例（＝單一測試身分），跨格不可能互相抵帳；
//   - **callback 未解除**——`attach` 註冊即成對登記 `t.Cleanup` 移除，
//     且 Cleanup 為 LIFO：先移除 callback、最後才跑防呆斷言。
type auditFaultInjector struct {
	t        *testing.T
	want     auditHitSpec
	sentinel error

	mu          sync.Mutex
	armed       bool
	observed    []auditHit
	matched     int
	injected    int
	controlDone bool
	attached    int
}

// newAuditFaultInjector 建立本格的注入器（尚未 attach 到任何 DB）。
func newAuditFaultInjector(t *testing.T, want auditHitSpec) *auditFaultInjector {
	t.Helper()
	if want.AP == "" {
		t.Fatal("auditHitSpec.AP 不得為空：注入器必須知道本格預期命中哪個審計點，" +
			"否則又退化成「有任何審計寫入被攔到就算數」")
	}
	inj := &auditFaultInjector{
		t:    t,
		want: want,
		// **每次呼叫都產生一個新的 error 值**：errors.Is 比對的是同一性，
		// 故本哨兵不可能被別格的注入器或任何生產碼錯誤滿足。
		sentinel: errors.New(fmt.Sprintf("注入故障[%s]（測試 %s）：審計列寫入失敗", want.AP, t.Name())),
	}
	// 最先登記＝Cleanup LIFO 中最後執行：跑防呆時 callback 已解除。
	t.Cleanup(inj.assertHealthy)
	return inj
}

// attach 把注入器掛到一個 DB 句柄上（可掛多個——對照組與實驗組用不同庫時需要）。
func (inj *auditFaultInjector) attach(db *gorm.DB) {
	t := inj.t
	t.Helper()
	inj.mu.Lock()
	inj.attached++
	name := fmt.Sprintf("w4_backstop:%s:%d", inj.want.AP, inj.attached)
	inj.mu.Unlock()

	err := db.Callback().Create().Before("gorm:create").Register(name, func(tx *gorm.DB) {
		if tx.Statement == nil {
			return
		}
		if !auditWriteTarget(tx) {
			return
		}
		hits := auditHitsOf(tx)
		inj.mu.Lock()
		defer inj.mu.Unlock()
		inj.observed = append(inj.observed, hits...)
		hit := false
		for _, h := range hits {
			if inj.want.matches(h) {
				hit = true
				break
			}
		}
		if !hit {
			// **不相干的審計寫入照樣放行**——否則它會替本格取得 credit，
			// 而本格指定的審計點永遠不可達（codex 焦點 2）。
			return
		}
		inj.matched++
		if !inj.armed {
			return
		}
		inj.injected++
		_ = tx.AddError(inj.sentinel)
	})
	if err != nil {
		t.Fatalf("註冊故障注入 callback 失敗: %v", err)
	}
	t.Cleanup(func() { _ = db.Callback().Create().Remove(name) })
}

func (inj *auditFaultInjector) arm() {
	inj.mu.Lock()
	defer inj.mu.Unlock()
	if !inj.controlDone {
		inj.t.Fatalf("[%s] 尚未跑無故障對照組就開故障：對照組是「業務列不存在」這條斷言"+
			"不是真空通過的唯一證據，順序不可顛倒", inj.want.AP)
	}
	inj.armed = true
}

func (inj *auditFaultInjector) disarm() {
	inj.mu.Lock()
	defer inj.mu.Unlock()
	inj.armed = false
}

func (inj *auditFaultInjector) matchedCount() int {
	inj.mu.Lock()
	defer inj.mu.Unlock()
	return inj.matched
}

func (inj *auditFaultInjector) observedText() string {
	inj.mu.Lock()
	defer inj.mu.Unlock()
	if len(inj.observed) == 0 {
		return "（本次執行完全沒有觀察到任何 audit_logs 寫入）"
	}
	parts := make([]string, 0, len(inj.observed))
	for _, h := range inj.observed {
		parts = append(parts, h.String())
	}
	return strings.Join(parts, "\n    ")
}

// control 無故障對照組（**每格強制**）。
//
//	run     ：與實驗組同一條入口、相同輸入的無故障執行（須成功）
//	bizRows ：回傳「本格指定的業務列」筆數
//	wantBiz ：對照組跑完之後該業務列應有的筆數（建立類為 1、刪除類為 0）
//
// 三條斷言分別排除三種真空：業務入口本來就會失敗／查詢條件指錯列／斷言表指錯審計點。
func (inj *auditFaultInjector) control(name string, run func() error, bizRows func() int64, wantBiz int64) {
	t := inj.t
	t.Helper()
	before := inj.matchedCount()
	if err := run(); err != nil {
		t.Fatalf("[對照組 %s／%s] 無故障時業務操作就失敗了（%v）——"+
			"實驗組的「回了 error／業務列不存在」將無法歸因於審計 fail-close", inj.want.AP, name, err)
	}
	if got := bizRows(); got != wantBiz {
		t.Fatalf("[對照組 %s／%s] 無故障時業務列應為 %d 筆，實得 %d——"+
			"查詢條件或夾具不成立，實驗組的「業務列不存在」本來就會成立（真空通過）",
			inj.want.AP, name, wantBiz, got)
	}
	if inj.matchedCount() == before {
		t.Fatalf("[對照組 %s／%s] 無故障時**未抵達本格指定的審計點** want=%s；"+
			"本次觀察到的審計寫入：\n    %s\n"+
			"斷言表指錯了審計點（或該點在本輸入下根本不執行），實驗組的注入永遠打不到它",
			inj.want.AP, name, inj.want, inj.observedText())
	}
	inj.mu.Lock()
	inj.controlDone = true
	inj.mu.Unlock()
}

// assertCausedBy 斷言 error 可歸因於本格注入的唯一哨兵。
func (inj *auditFaultInjector) assertCausedBy(label string, err error) {
	t := inj.t
	t.Helper()
	if err == nil {
		t.Fatalf("%s：審計寫入失敗時業務操作竟然成功——fail-close 已退化為 fail-open", label)
	}
	if !errors.Is(err, inj.sentinel) {
		t.Fatalf("%s：回傳的 error 無法歸因於本格注入的哨兵（want=%s）——"+
			"這條 error 來自別的失敗（前置檢查、夾具、其他審計點），本格證明不了 fail-close。實得：%v",
			label, inj.want, err)
	}
}

// assertRolledBack 斷言「業務交易真的回滾」的四件事，而不是只斷言呼叫回了 error。
//
//	(1) 呼叫回非 nil error；
//	(2) 該 error 可歸因於**本格**注入的哨兵（codex 焦點 2：err != nil 可能來自別處）；
//	(3) 業務列不存在（bizCount 為 0）；
//	(4) 審計列不存在（回滾後不得留下半筆留痕；已含對照組留痕者傳差值）。
//
// **(3) 是本測試的核心**：只驗 (1) 的測試在「呼叫端把 error 記 log 就吞掉」的
// 退化下仍會綠——那正是 fail-open 的樣子。
func (inj *auditFaultInjector) assertRolledBack(label string, err error, bizCount, auditDelta int64) {
	t := inj.t
	t.Helper()
	inj.assertCausedBy(label, err)
	if bizCount != 0 {
		t.Fatalf("%s：呼叫回了 error（%v），但業務列仍有 %d 筆——交易沒有回滾，"+
			"「回 error」與「真的回滾」是兩回事", label, err, bizCount)
	}
	if auditDelta != 0 {
		t.Fatalf("%s：回滾後仍多留下 %d 筆審計列", label, auditDelta)
	}
}

// assertHealthy 三道防呆的斷言本體（Cleanup 執行，不可豁免）。
//
// **不得**為了讓某格通過而放寬本斷言；正確的修法是讓那格真的走到指定的審計寫入。
// 真正不使用注入器的案例（`TestFailCloseWhenSinkNotInjected`）根本不建立
// injector，也就不會走到這裡——見該測試的說明。
func (inj *auditFaultInjector) assertHealthy() {
	t := inj.t
	inj.mu.Lock()
	controlDone, injected := inj.controlDone, inj.injected
	inj.mu.Unlock()
	if !controlDone {
		t.Errorf("[backstop 防呆] %s 這格沒有跑無故障對照組——"+
			"「業務列不存在／審計列不存在／回了 error」三條在「夾具本來就沒建起業務列」"+
			"或「斷言表指錯審計點」時也全部成立，本格為真空通過。", inj.want.AP)
	}
	if injected == 0 {
		t.Errorf("[backstop 防呆] %s 這格的故障注入器**一次都沒有命中指定的審計點**"+
			"（want=%s）——表示測試沒走到該審計寫入（前置條件早退最常見），"+
			"三條回滾斷言全因『什麼都沒發生』而成立。本格為假綠：即使生產碼的 fail-close "+
			"被完全移除也不會轉紅。本次觀察到的審計寫入：\n    %s",
			inj.want.AP, inj.want, inj.observedText())
	}
}

// ── 目標判定與身分抽取 ────────────────────────────────────────────────────

// auditWriteTarget 這次 Create 是否寫 audit_logs。
//
// 同時看 Table 與 Model／Dest 型別：`tx.Create(&model.AuditLog{})` 走型別、
// `tx.Table("audit_logs").Create(...)` 走表名。兩者都認，故不因寫法改變而失明。
func auditWriteTarget(tx *gorm.DB) bool {
	if tx.Statement.Table == "audit_logs" {
		return true
	}
	if isAuditLogValue(tx.Statement.Model) {
		return true
	}
	return isAuditLogValue(tx.Statement.Dest)
}

func isAuditLogValue(v any) bool {
	switch v.(type) {
	case *model.AuditLog, []*model.AuditLog, *[]model.AuditLog, *[]*model.AuditLog, []model.AuditLog:
		return true
	}
	return false
}

// auditHitsOf 抽出本次寫入的審計列身分（批次逐列抽）。
//
// 抽不出型別時仍回一筆只帶 Table 的 hit——「有寫入但認不出身分」必須是可見的
// 事實，靜默丟掉它會讓身分比對在未知形態上假綠。
func auditHitsOf(tx *gorm.DB) []auditHit {
	table := tx.Statement.Table
	rows := auditRowsOf(tx.Statement.Dest)
	if len(rows) == 0 {
		rows = auditRowsOf(tx.Statement.Model)
	}
	if len(rows) == 0 {
		return []auditHit{{Table: table}}
	}
	hits := make([]auditHit, 0, len(rows))
	for _, r := range rows {
		if r == nil {
			continue
		}
		hits = append(hits, auditHit{
			Table:    table,
			Action:   string(r.Action),
			Resource: string(r.Resource),
			Details:  r.Details,
		})
	}
	if len(hits) == 0 {
		return []auditHit{{Table: table}}
	}
	return hits
}

func auditRowsOf(v any) []*model.AuditLog {
	switch t := v.(type) {
	case *model.AuditLog:
		return []*model.AuditLog{t}
	case []*model.AuditLog:
		return t
	case *[]*model.AuditLog:
		if t == nil {
			return nil
		}
		return *t
	case []model.AuditLog:
		out := make([]*model.AuditLog, 0, len(t))
		for i := range t {
			out = append(out, &t[i])
		}
		return out
	case *[]model.AuditLog:
		if t == nil {
			return nil
		}
		out := make([]*model.AuditLog, 0, len(*t))
		for i := range *t {
			out = append(out, &(*t)[i])
		}
		return out
	}
	return nil
}

func countRows(t *testing.T, db *gorm.DB, dest any) int64 {
	t.Helper()
	var n int64
	if err := db.Model(dest).Count(&n).Error; err != nil {
		t.Fatalf("計數失敗: %v", err)
	}
	return n
}

func countWhere(t *testing.T, db *gorm.DB, dest any, query string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := db.Model(dest).Where(query, args...).Count(&n).Error; err != nil {
		t.Fatalf("計數失敗: %v", err)
	}
	return n
}

func ptrUint(v uint) *uint { return &v }

// 帳號類審計的共同指紋：`model.RecordAssetAccountChange` 的 Details JSON。
// GORM hook（AP-23…25）寫的列 Details 恆為空字串，故此指紋把兩者分得開。
const accountAuditFingerprint = `"resource":"asset_account"`

// ── AP-36：節點樹建立（nodeAudit）────────────────────────────────────────

func TestFailCloseAssetGroupCreateRollsBackOnAuditFailure(t *testing.T) {
	svc, db := setupGroupDB(t)
	inj := newAuditFaultInjector(t, auditHitSpec{
		AP: "AP-36 AssetGroupService.Create", Action: model.ActionCreate,
		Resource: model.ResourceAsset, Details: `"asset_node_name"`,
	})
	inj.attach(db)

	inj.control("建立節點", func() error {
		_, err := svc.Create(&AssetGroupRequest{Name: "ok"}, 1, "admin", "127.0.0.1")
		return err
	}, func() int64 { return countWhere(t, db, &model.AssetGroup{}, "name = ?", "ok") }, 1)
	auditBefore := countRows(t, db, &model.AuditLog{}) // 對照組留下的合法留痕

	inj.arm()
	_, err := svc.Create(&AssetGroupRequest{Name: "boom"}, 1, "admin", "127.0.0.1")
	inj.assertRolledBack("AP-36 AssetGroupService.Create", err,
		countWhere(t, db, &model.AssetGroup{}, "name = ?", "boom"),
		countRows(t, db, &model.AuditLog{})-auditBefore)
}

// ── AP-37：節點刪除（含授權級聯撤銷）────────────────────────────────────

func TestFailCloseAssetGroupDeleteRollsBackOnAuditFailure(t *testing.T) {
	svc, db := setupGroupDB(t)
	inj := newAuditFaultInjector(t, auditHitSpec{
		AP: "AP-37 AssetGroupService.Delete", Action: model.ActionDelete,
		Resource: model.ResourceAsset, Details: `"revoked_authorizations"`,
	})
	inj.attach(db)

	mkGroup := func(name string) uint {
		t.Helper()
		g, err := svc.Create(&AssetGroupRequest{Name: name}, 1, "admin", "127.0.0.1")
		if err != nil {
			t.Fatalf("前置建立 %s: %v", name, err)
		}
		if err := db.Create(&model.AssetAuthorization{AssetGroupID: &g.ID, UserID: ptrUint(7)}).Error; err != nil {
			t.Fatalf("前置授權 %s: %v", name, err)
		}
		return g.ID
	}

	ctrlID := mkGroup("對照")
	inj.control("刪除節點", func() error {
		_, err := svc.Delete(ctrlID, 1, "admin", "127.0.0.1")
		return err
	}, func() int64 { return countWhere(t, db, &model.AssetGroup{}, "id = ?", ctrlID) }, 0)
	if got := countRows(t, db, &model.AssetAuthorization{}); got != 0 {
		t.Fatalf("[對照組] 級聯撤銷未發生（授權剩 %d 筆）——實驗組的「授權仍在」失去對照", got)
	}

	targetID := mkGroup("待刪")
	inj.arm()
	_, err := svc.Delete(targetID, 1, "admin", "127.0.0.1")
	inj.assertCausedBy("AP-37：審計失敗時刪除竟然成功——授權撤銷即將無痕發生", err)

	// **級聯撤銷必須一併回滾**：這正是該點 fail-close 的理由（授權變更不可無痕）
	if groups := countWhere(t, db, &model.AssetGroup{}, "id = ?", targetID); groups != 1 {
		t.Fatalf("AP-37：節點已被刪除但審計未留痕（回滾失敗）")
	}
	if auths := countRows(t, db, &model.AssetAuthorization{}); auths != 1 {
		t.Fatalf("AP-37：級聯撤銷的授權未隨交易回滾（剩 %d 筆，應為 1）——"+
			"授權在沒有任何審計紀錄的情況下消失了", auths)
	}
}

// ── AP-60：使用者群組刪除（含授權級聯撤銷）──────────────────────────────

func TestFailCloseWhenSinkNotInjected(t *testing.T) {
	newDB := func() *gorm.DB {
		db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
		if err != nil {
			t.Fatalf("sqlite: %v", err)
		}
		if err := db.AutoMigrate(&model.AssetGroup{}, &model.AssetNode{}, &model.Asset{},
			&model.AuditLog{}, &model.AssetAuthorization{}, &model.ApproverScope{}); err != nil {
			t.Fatalf("migrate: %v", err)
		}
		return db
	}

	// 對照組：有 sink 時同一輸入成功且確實留痕
	ctrlDB := newDB()
	if _, err := NewAssetGroupService(ctrlDB, audit.NewTxSink(), &cascadingGroupRevoker{}).
		Create(&AssetGroupRequest{Name: "有 sink"}, 1, "admin", "127.0.0.1"); err != nil {
		t.Fatalf("[對照組] 有注入 sink 時建立應成功: %v", err)
	}
	if got := countRows(t, ctrlDB, &model.AssetGroup{}); got != 1 {
		t.Fatalf("[對照組] 節點應留下 1 筆，得 %d", got)
	}
	if got := countRows(t, ctrlDB, &model.AuditLog{}); got != 1 {
		t.Fatalf("[對照組] 審計應留下 1 筆，得 %d——本入口根本沒抵達審計點，實驗組證明不了 fail-close", got)
	}

	db := newDB()
	svc := NewAssetGroupService(db, nil, &cascadingGroupRevoker{}) // 刻意不注入

	_, err := svc.Create(&AssetGroupRequest{Name: "無 sink"}, 1, "admin", "127.0.0.1")
	if err == nil {
		t.Fatal("未注入 sink 時建立竟然成功——nil sink 被當成 no-op，審計靜默消失")
	}
	if !errors.Is(err, port.ErrTxSinkMissing) {
		t.Fatalf("錯誤應可辨識為 port.ErrTxSinkMissing，得 %v", err)
	}
	if got := countRows(t, db, &model.AssetGroup{}); got != 0 {
		t.Fatalf("未注入 sink 時仍留下 %d 筆節點——業務交易未回滾", got)
	}
}

// ── 自檢：故障注入本身必須真的會攔到寫入 ────────────────────────────────

// TestAuditWriteFaultInjectionActuallyFires 證明注入器本身有效、且**只攔指定身分**。
//
// 三件事：(1) 未武裝時審計列寫得進去；(2) 武裝後命中 spec 的寫入被攔下且錯誤是
// 本格哨兵；(3) **不命中 spec 的審計寫入照樣放行**——這是選擇性注入的核心性質，
// 沒有它，「不相干的早期審計寫入替本格取得 credit」的缺陷就修不掉；
// (4) 非審計表不受影響，否則「業務列不存在」可能是被注入器擋掉的。
func TestFailCloseAssetCreateRollsBackOnAuditFailure(t *testing.T) {
	db := setupAccountDB(t)
	assets, _ := newAccountServices(t)
	inj := newAuditFaultInjector(t, auditHitSpec{
		AP: "AP-38 AssetService.Create（預設帳號審計）", Action: model.ActionCreate,
		Resource: model.ResourceAsset,
		Details:  accountAuditFingerprint + `,"account_id"`,
	})
	inj.attach(db)

	inj.control("建立資產（含預設帳號）", func() error {
		_, err := assets.Create(&CreateAssetRequest{
			Name: "srv-ok", Protocol: model.ProtocolSSH, Host: "10.0.0.1", Port: 22,
			Username: "root", Password: "s3cret", CreatedBy: 1,
		})
		return err
	}, func() int64 { return countWhere(t, db, &model.Asset{}, "name = ?", "srv-ok") }, 1)
	if got := countRows(t, db, &model.AssetAccount{}); got != 1 {
		t.Fatalf("[對照組] 預設帳號應建立 1 筆，得 %d", got)
	}

	inj.arm()
	_, err := assets.Create(&CreateAssetRequest{
		Name: "srv-boom", Protocol: model.ProtocolSSH, Host: "10.0.0.2", Port: 22,
		Username: "root", Password: "s3cret", CreatedBy: 1,
	})
	inj.assertCausedBy("AP-38：審計失敗時建立資產竟然成功——預設帳號建立將無痕發生", err)
	if assetsLeft := countWhere(t, db, &model.Asset{}, "name = ?", "srv-boom"); assetsLeft != 0 {
		t.Fatalf("AP-38：資產列仍在（%d 筆）——交易沒有回滾", assetsLeft)
	}
	orphans := countWhere(t, db, &model.AssetAccount{},
		"asset_id NOT IN (SELECT id FROM assets)")
	if orphans != 0 {
		t.Fatalf("AP-38：留下 %d 筆孤兒帳號列", orphans)
	}
}

// AP-30（＋落地側 AP-22）：AssetAccountService.Create
func TestFailCloseAssetAccountCreateRollsBackOnAuditFailure(t *testing.T) {
	db := setupAccountDB(t)
	assets, accounts := newAccountServices(t)
	asset := mustCreateAsset(t, assets, "srv-1", "10.0.0.1")
	inj := newAuditFaultInjector(t, auditHitSpec{
		AP: "AP-30 AssetAccountService.Create", Action: model.ActionCreate,
		Resource: model.ResourceAsset, Details: `"operation":"` + model.AccountOpCreate + `"`,
	})
	inj.attach(db)

	inj.control("新增資產帳號", func() error {
		_, err := accounts.Create(adminCtx(), asset.ID, &CreateAssetAccountRequest{
			Username: "ctrl", Password: "pw",
		})
		return err
	}, func() int64 { return countWhere(t, db, &model.AssetAccount{}, "username = ?", "ctrl") }, 1)
	before := countRows(t, db, &model.AssetAccount{})

	inj.arm()
	_, err := accounts.Create(adminCtx(), asset.ID, &CreateAssetAccountRequest{
		Username: "deploy", Password: "pw",
	})
	inj.assertCausedBy("AP-30：審計失敗時新增資產帳號竟然成功——憑證新增將無痕發生", err)
	if got := countRows(t, db, &model.AssetAccount{}); got != before {
		t.Fatalf("AP-30：帳號列數自 %d 變為 %d——交易沒有回滾", before, got)
	}
}

// AP-31：AssetAccountService.Update（W4 codex 外審後補齊；此前僅以「與 AP-30／32
// 語法同型」代替逐格，那只證明得了當下的人工比對，擋不住其中一路日後獨立漂移）
func TestFailCloseAssetAccountUpdateRollsBackOnAuditFailure(t *testing.T) {
	db := setupAccountDB(t)
	assets, accounts := newAccountServices(t)
	asset := mustCreateAsset(t, assets, "srv-1", "10.0.0.1")
	acct, err := accounts.Create(adminCtx(), asset.ID, &CreateAssetAccountRequest{
		Username: "deploy", Password: "pw",
	})
	if err != nil {
		t.Fatalf("前置帳號: %v", err)
	}
	inj := newAuditFaultInjector(t, auditHitSpec{
		AP: "AP-31 AssetAccountService.Update", Action: model.ActionUpdate,
		Resource: model.ResourceAsset, Details: `"operation":"` + model.AccountOpUpdate + `"`,
	})
	inj.attach(db)

	ctrlNote := "對照備註"
	inj.control("更新資產帳號", func() error {
		_, err := accounts.Update(adminCtx(), asset.ID, acct.ID, &UpdateAssetAccountRequest{Note: &ctrlNote})
		return err
	}, func() int64 { return countWhere(t, db, &model.AssetAccount{}, "note = ?", ctrlNote) }, 1)

	boomNote := "實驗備註"
	inj.arm()
	_, err = accounts.Update(adminCtx(), asset.ID, acct.ID, &UpdateAssetAccountRequest{Note: &boomNote})
	inj.assertCausedBy("AP-31：審計失敗時更新資產帳號竟然成功——憑證／欄位變更將無痕發生", err)
	if got := countWhere(t, db, &model.AssetAccount{}, "note = ?", boomNote); got != 0 {
		t.Fatalf("AP-31：帳號欄位已被改寫（%d 筆帶新備註）——交易沒有回滾", got)
	}
	if got := countWhere(t, db, &model.AssetAccount{}, "note = ?", ctrlNote); got != 1 {
		t.Fatalf("AP-31：回滾後應維持對照組的備註，實得 %d 筆", got)
	}
}

// AP-32：AssetAccountService.Delete
func TestFailCloseAssetAccountDeleteRollsBackOnAuditFailure(t *testing.T) {
	db := setupAccountDB(t)
	assets, accounts := newAccountServices(t)
	asset := mustCreateAsset(t, assets, "srv-1", "10.0.0.1")
	mk := func(name string) uint {
		t.Helper()
		a, err := accounts.Create(adminCtx(), asset.ID, &CreateAssetAccountRequest{Username: name, Password: "pw"})
		if err != nil {
			t.Fatalf("前置帳號 %s: %v", name, err)
		}
		return a.ID
	}
	ctrlID, targetID := mk("ctrl"), mk("deploy")
	inj := newAuditFaultInjector(t, auditHitSpec{
		AP: "AP-32 AssetAccountService.Delete", Action: model.ActionDelete,
		Resource: model.ResourceAsset, Details: `"operation":"` + model.AccountOpDelete + `"`,
	})
	inj.attach(db)

	inj.control("刪除資產帳號", func() error {
		return accounts.Delete(adminCtx(), asset.ID, ctrlID)
	}, func() int64 { return countWhere(t, db, &model.AssetAccount{}, "id = ?", ctrlID) }, 0)
	before := countRows(t, db, &model.AssetAccount{})

	inj.arm()
	err := accounts.Delete(adminCtx(), asset.ID, targetID)
	inj.assertCausedBy("AP-32：審計失敗時刪除資產帳號竟然成功——憑證移除將無痕發生", err)
	if got := countRows(t, db, &model.AssetAccount{}); got != before {
		t.Fatalf("AP-32：帳號列數自 %d 變為 %d——交易沒有回滾", before, got)
	}
	if got := countWhere(t, db, &model.AssetAccount{}, "id = ?", targetID); got != 1 {
		t.Fatalf("AP-32：目標帳號已消失——刪除未隨交易回滾")
	}
}

// AP-33：AssetAccountService.SetDefault（W4 codex 外審後補齊）
func TestFailCloseAssetAccountSetDefaultRollsBackOnAuditFailure(t *testing.T) {
	db := setupAccountDB(t)
	assets, accounts := newAccountServices(t)
	asset := mustCreateAsset(t, assets, "srv-1", "10.0.0.1")
	mk := func(name string) uint {
		t.Helper()
		a, err := accounts.Create(adminCtx(), asset.ID, &CreateAssetAccountRequest{Username: name, Password: "pw"})
		if err != nil {
			t.Fatalf("前置帳號 %s: %v", name, err)
		}
		return a.ID
	}
	ctrlID, targetID := mk("ctrl"), mk("deploy")
	inj := newAuditFaultInjector(t, auditHitSpec{
		AP: "AP-33 AssetAccountService.SetDefault", Action: model.ActionUpdate,
		Resource: model.ResourceAsset, Details: `"operation":"` + model.AccountOpSetDefault + `"`,
	})
	inj.attach(db)

	inj.control("切換預設帳號", func() error {
		_, err := accounts.SetDefault(adminCtx(), asset.ID, ctrlID)
		return err
	}, func() int64 {
		return countWhere(t, db, &model.AssetAccount{}, "id = ? AND is_default = ?", ctrlID, true)
	}, 1)

	inj.arm()
	_, err := accounts.SetDefault(adminCtx(), asset.ID, targetID)
	inj.assertCausedBy("AP-33：審計失敗時切換預設帳號竟然成功——連線身分改指將無痕發生", err)
	if got := countWhere(t, db, &model.AssetAccount{}, "id = ? AND is_default = ?", targetID, true); got != 0 {
		t.Fatalf("AP-33：目標帳號已成為預設但審計未留痕（回滾失敗）")
	}
	if got := countWhere(t, db, &model.AssetAccount{}, "id = ? AND is_default = ?", ctrlID, true); got != 1 {
		t.Fatalf("AP-33：對照組的預設帳號被清掉且未回滾——「哪個身分連得上」在無痕下被改動")
	}
}

// AP-40：AssetService.UpdatePassword（改密 runner 的落點；W4 codex 外審後補齊）
func TestFailCloseAssetUpdatePasswordRollsBackOnAuditFailure(t *testing.T) {
	db := setupAccountDB(t)
	assets, _ := newAccountServices(t)
	asset := mustCreateAsset(t, assets, "srv-1", "10.0.0.1")
	var acct model.AssetAccount
	if err := db.Where("asset_id = ?", asset.ID).First(&acct).Error; err != nil {
		t.Fatalf("取預設帳號: %v", err)
	}
	inj := newAuditFaultInjector(t, auditHitSpec{
		AP: "AP-40 AssetService.UpdatePassword", Action: model.ActionUpdate,
		Resource: model.ResourceAsset, Details: `"fields":["password"]`,
	})
	inj.attach(db)

	encOf := func() string {
		t.Helper()
		var row model.AssetAccount
		if err := db.Where("id = ?", acct.ID).First(&row).Error; err != nil {
			t.Fatalf("讀取帳號: %v", err)
		}
		return row.PasswordEnc
	}
	original := encOf()
	inj.control("改密", func() error {
		return assets.UpdatePassword(asset.ID, acct.ID, acct.Username, "ctrl-new-pw")
	}, func() int64 {
		if encOf() != original {
			return 1
		}
		return 0
	}, 1)
	afterControl := encOf()

	inj.arm()
	err := assets.UpdatePassword(asset.ID, acct.ID, acct.Username, "boom-new-pw")
	inj.assertCausedBy("AP-40：審計失敗時改密竟然成功——密碼已輪替而無任何審計（改密 runner 與真實密碼從此不一致）", err)
	if got := encOf(); got != afterControl {
		t.Fatalf("AP-40：密文已被改寫但審計未留痕（回滾失敗）")
	}
}

// AP-34／AP-35：syncDefaultAccountFromAsset 的建立分支與更新分支
// （唯一呼叫方是 `AssetService.Update`；W4 codex 外審後補齊——舊版把兩點掛在
// `AssetService.Create` 那格底下宣稱涵蓋，但 Create 根本不呼叫 sync，是錯記）。

// AP-35：更新分支（既有 default 帳號 → 隨資產憑證變更同步）
func TestFailCloseSyncDefaultAccountUpdateRollsBackOnAuditFailure(t *testing.T) {
	db := setupAccountDB(t)
	assets, _ := newAccountServices(t)
	asset := mustCreateAsset(t, assets, "srv-1", "10.0.0.1")
	inj := newAuditFaultInjector(t, auditHitSpec{
		AP: "AP-35 syncDefaultAccountFromAsset（更新分支）", Action: model.ActionUpdate,
		Resource: model.ResourceAsset, Details: `"operation":"` + model.AccountOpUpdate + `"`,
	})
	inj.attach(db)

	nameOf := func() string {
		t.Helper()
		var row model.AssetAccount
		if err := db.Where("asset_id = ? AND is_default = ?", asset.ID, true).First(&row).Error; err != nil {
			t.Fatalf("讀取預設帳號: %v", err)
		}
		return row.Username
	}
	ctrlUser := "ctrluser"
	inj.control("經資產更新同步預設帳號", func() error {
		_, err := assets.Update(adminCtx(), asset.ID, &UpdateAssetRequest{Username: &ctrlUser})
		return err
	}, func() int64 {
		if nameOf() == ctrlUser {
			return 1
		}
		return 0
	}, 1)

	boomUser := "boomuser"
	inj.arm()
	_, err := assets.Update(adminCtx(), asset.ID, &UpdateAssetRequest{Username: &boomUser})
	inj.assertCausedBy("AP-35：審計失敗時資產憑證同步竟然成功——default 帳號被改寫而無痕", err)
	if got := nameOf(); got != ctrlUser {
		t.Fatalf("AP-35：預設帳號 username 已變為 %q 但審計未留痕（回滾失敗）", got)
	}
}

// AP-34：建立分支（零帳號資產 → 就地建 default）
func TestFailCloseSyncDefaultAccountCreateRollsBackOnAuditFailure(t *testing.T) {
	db := setupAccountDB(t)
	assets, _ := newAccountServices(t)
	inj := newAuditFaultInjector(t, auditHitSpec{
		AP: "AP-34 syncDefaultAccountFromAsset（建立分支）", Action: model.ActionCreate,
		Resource: model.ResourceAsset, Details: `"operation":"` + model.AccountOpCreate + `"`,
	})
	inj.attach(db)

	// 零帳號資產：三欄全空即不建 default（見 syncDefaultAccountFromAsset 註解）
	mkBare := func(name string) uint {
		t.Helper()
		a := &model.Asset{Name: name, Protocol: model.ProtocolSSH, Host: "10.9.9.9", Port: 22}
		if err := db.Create(a).Error; err != nil {
			t.Fatalf("前置零帳號資產 %s: %v", name, err)
		}
		if got := countWhere(t, db, &model.AssetAccount{}, "asset_id = ?", a.ID); got != 0 {
			t.Fatalf("前置零帳號資產 %s 竟然帶了 %d 筆帳號，本格前提不成立", name, got)
		}
		return a.ID
	}

	ctrlAsset := mkBare("bare-ctrl")
	ctrlUser := "ctrluser"
	inj.control("零帳號資產補建 default", func() error {
		_, err := assets.Update(adminCtx(), ctrlAsset, &UpdateAssetRequest{Username: &ctrlUser})
		return err
	}, func() int64 { return countWhere(t, db, &model.AssetAccount{}, "asset_id = ?", ctrlAsset) }, 1)

	targetAsset := mkBare("bare-boom")
	boomUser := "boomuser"
	inj.arm()
	_, err := assets.Update(adminCtx(), targetAsset, &UpdateAssetRequest{Username: &boomUser})
	inj.assertCausedBy("AP-34：審計失敗時補建 default 帳號竟然成功——新的連線身分被建立而無痕", err)
	if got := countWhere(t, db, &model.AssetAccount{}, "asset_id = ?", targetAsset); got != 0 {
		t.Fatalf("AP-34：留下 %d 筆帳號列——交易沒有回滾", got)
	}
	if got := countWhere(t, db, &model.Asset{}, "id = ? AND username = ?", targetAsset, boomUser); got != 0 {
		t.Fatalf("AP-34：資產 username 已被改寫但帳號與審計都不在——回滾不完整")
	}
}

// ── AP-26／AP-27：落地本體的 fail-close（消費端現況全為 fail-open，故無回滾可觀察）──
//
// # 誠實界定（本節與其他格**不同類**，不可混稱）
//
// manifest 把 `RecordAssetChange`（AP-26）與 `RecordAssetNodeChange`（AP-27）標為
// `fail-close?＝是`，指的是**落地本體不吞 error**；但它們現況的三個消費端
// （AP-39／41／42）一律 `log.Printf` 且不 return，是 fail-**open**。因此這兩點
// **不存在可觀察的業務回滾**——硬寫一格「業務列不存在」的斷言只會永遠是紅的，
// 或者要靠改生產碼才會綠，那是行為變更不是測試。
//
// 本節能證明、也只證明一件事：注入審計寫入故障時，這兩個函式**把 error 原樣回傳**
// （沒有內部吞掉）。W6 6.1 若把任一消費端改成 fail-close，屆時該消費端要另立回滾格；
// 本格則是那之前唯一的 runtime 證據，也擋住「落地本體被改成吞 error」這種退化。
func TestFailCloseAssetChangeRecordersPropagateAuditError(t *testing.T) {
	db := setupAccountDB(t)
	if err := db.AutoMigrate(&model.AssetNode{}, &model.AssetGroup{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	cases := []struct {
		name string
		spec auditHitSpec
		run  func(tx *gorm.DB) error
	}{
		{
			name: "AP-26 writeAssetChangeAudit",
			spec: auditHitSpec{
				AP: "AP-26 asset.writeAssetChangeAudit", Action: model.ActionUpdate,
				Resource: model.ResourceAsset, Details: `"field":"host"`,
			},
			run: func(tx *gorm.DB) error {
				old := &model.Asset{Name: "a", Host: "10.0.0.1", Port: 22, Protocol: model.ProtocolSSH}
				old.ID = 1
				updated := *old
				updated.Host = "10.0.0.2"
				return writeAssetChangeAudit(audit.NewTxSink(), tx, old, &updated, 1, "admin", model.ActionUpdate)
			},
		},
		{
			name: "AP-27 writeAssetNodeChangeAudit",
			spec: auditHitSpec{
				AP: "AP-27 asset.writeAssetNodeChangeAudit", Action: model.ActionUpdate,
				Resource: model.ResourceAsset, Details: `"field":"node_ids"`,
			},
			run: func(tx *gorm.DB) error {
				return writeAssetNodeChangeAudit(audit.NewTxSink(), tx, 1, []uint{1}, []uint{2}, 1, "admin")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// 每個子測試自建注入器（身分不同）；共用 db 但**不平行**（見檔頭）。
			inj := newAuditFaultInjector(t, tc.spec)
			inj.attach(db)
			base := countRows(t, db, &model.AuditLog{})
			inj.control("落地本體寫入審計列", func() error {
				return tc.run(db)
			}, func() int64 { return countRows(t, db, &model.AuditLog{}) - base }, 1)

			inj.arm()
			err := tc.run(db)
			inj.assertCausedBy(tc.name+"：落地本體吞掉了審計寫入的 error——"+
				"消費端從此無從得知留痕失敗（W6 收口為 fail-close 時會靜默失效）", err)
		})
	}
}

// ── 退化可觀察性：把 TxSink 換成 fire-and-forget 會怎樣（4.12 突變的執行期形式）──

// asyncLikeSink 模擬「有人把交易內審計改掛 AsyncSink」之後的語義：
// 寫入非同步／失敗只記 log／**一律回 nil**。
type asyncLikeSink struct {
	dropped int
	lastErr error
}

func (s *asyncLikeSink) WriteInTx(tx *gorm.DB, ev port.AuditEvent) error {
	// fire-and-forget：真的去寫，但不論成敗都回 nil（AsyncSink 的 at-most-once 語義）
	if err := tx.Session(&gorm.Session{NewDB: true}).Create(&model.AuditLog{
		Action: model.AuditAction(ev.Action), Resource: model.AuditResource(ev.Resource),
		Details: ev.Details,
	}).Error; err != nil {
		s.dropped++
		s.lastErr = err
	}
	return nil
}

// TestAsyncSinkSubstitutionMakesFailCloseTestsGreen 證明「退化會被本組測試抓到」。
//
// **這一格取代人工突變的一部分，而且更強**：它不是把生產碼改壞再跑一次，而是
// 直接在測試內示範退化的語義，並斷言**業務列在審計丟失的情況下成立**——
// 亦即上方每一個 fail-close 案例在該退化下都會轉紅（它們斷言的正是「業務列不存在」）。
func TestAsyncSinkSubstitutionMakesFailCloseTestsGreen(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.AssetGroup{}, &model.AssetNode{}, &model.Asset{},
		&model.AuditLog{}, &model.AssetAuthorization{}, &model.ApproverScope{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	degraded := &asyncLikeSink{}
	svc := NewAssetGroupService(db, degraded, &cascadingGroupRevoker{})
	inj := newAuditFaultInjector(t, auditHitSpec{
		AP: "退化語義（asyncLikeSink）", Action: model.ActionCreate,
		Resource: model.ResourceAsset, Details: `"asset_node_name"`,
	})
	inj.attach(db)

	inj.control("退化 sink 的無故障路徑", func() error {
		_, err := svc.Create(&AssetGroupRequest{Name: "對照"}, 1, "admin", "127.0.0.1")
		return err
	}, func() int64 { return countWhere(t, db, &model.AssetGroup{}, "name = ?", "對照") }, 1)

	inj.arm()
	if _, err := svc.Create(&AssetGroupRequest{Name: "退化"}, 1, "admin", "127.0.0.1"); err != nil {
		t.Fatalf("退化語義下建立應成功（這正是問題所在）: %v", err)
	}
	if degraded.dropped == 0 {
		t.Fatal("審計寫入未被注入器攔到，本格證明不了任何事")
	}
	if !errors.Is(degraded.lastErr, inj.sentinel) {
		t.Fatalf("被丟棄的錯誤不是本格注入的哨兵（實得 %v）——丟棄可能來自別的原因", degraded.lastErr)
	}
	groups := countWhere(t, db, &model.AssetGroup{}, "name = ?", "退化")
	logs := countRows(t, db, &model.AuditLog{})
	if groups != 1 || logs != 1 { // 1＝對照組留下的合法留痕
		t.Fatalf("退化語義的預期形態是「業務列在、審計列不在」，實得 groups=%d logs=%d（對照組留痕 1）", groups, logs)
	}
	t.Logf("退化語義已重現：業務列 %d 筆、丟棄 %d 筆——"+
		"上方每個 fail-close 案例在此語義下都會在「業務列仍在」那條斷言轉紅",
		groups, degraded.dropped)
}

func mustCreateAsset(t *testing.T, assets *AssetService, name, host string) *model.Asset {
	t.Helper()
	asset, err := assets.Create(&CreateAssetRequest{
		Name: name, Protocol: model.ProtocolSSH, Host: host, Port: 22,
		Username: "root", Password: "s3cret", CreatedBy: 1,
	})
	if err != nil {
		t.Fatalf("前置資產 %s: %v", name, err)
	}
	return asset
}

var _ = database.DB // 明示本檔依賴套件級 DB（禁平行的理由之一）

func TestBackstopGridsDeclareNoParallel(t *testing.T) {
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("取本檔路徑失敗，禁令無從檢查")
	}
	body, err := os.ReadFile(self)
	if err != nil {
		t.Fatalf("讀取本檔失敗: %v", err)
	}
	src := string(body)
	// 下界：本檔被清空或改名時不得靜默通過
	if n := strings.Count(src, "\nfunc TestFailClose"); n < 12 {
		t.Fatalf("本檔只剩 %d 個 TestFailClose 格（下限 12）：backstop 已縮水，本禁令正在空集合上假綠", n)
	}
	// 針法以串接組出，避免本測試自身的原始碼命中自己（自我命中會讓禁令永遠紅，
	// 進而誘使有人放寬它——那比沒有禁令更糟）。
	needle := "t.Paral" + "lel()"
	if !strings.Contains(src, needle[:6]) {
		t.Fatal("針法組裝失敗，本禁令正在掃描一個不存在的字串")
	}
	found := 0
	for i, line := range strings.Split(src, "\n") {
		code := line
		if idx := strings.Index(code, "//"); idx >= 0 {
			code = code[:idx] // 註解內提及該呼叫是說明文字，不是宣告
		}
		if strings.Contains(code, "\"") {
			continue // 字串字面量（含本測試的針法與訊息）不是宣告
		}
		if strings.Contains(code, needle) {
			found++
			t.Errorf("第 %d 行宣告了平行子測試：本檔各格共享套件級 database.DB 與 t.Setenv，"+
				"平行化會讓「業務列不存在」因為讀錯庫而成立——那是假綠而不是通過。行內容：%s", i+1, line)
		}
	}
	t.Logf("平行禁令：掃描 %d 行、命中 %d 處", strings.Count(src, "\n")+1, found)
}
