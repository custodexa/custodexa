package identity_test

import (
	"context"
	"errors"
	"fmt"
	"github.com/custodexa/backend/internal/modules/identity"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 強制審計 fail-close 的 **runtime fault-injection backstop**。
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
// 那幾條路徑」，而 T-2 的 11 個點當時尚未收口（走 `model.RecordAsset*Change` 的
// `tx.Create`）。註冊在 `audit_logs` 上的 Create callback 對兩種形態一視同仁，
// 也對未來任何新的寫入形態一視同仁——**這是換 oracle 的關鍵**，不是實作上的方便。
//
// # 🔴 射程與盲區（**不得再無條件稱「最終權威」**）
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
// 且逐列抽出身分。現況生產碼零筆 B-a…B-d 形態的審計寫入；若日後出現（後續模組的
// raw SQL 審計寫入是最可能的來源），「DB 層 INSERT trigger 注入器」
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
// # 為什麼「命中身分」比「命中次數」重要
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
// # 併發與共享狀態
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
			// 而本格指定的審計點永遠不可達。
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
//	(2) 該 error 可歸因於**本格**注入的哨兵（err != nil 可能來自別處）；
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

func TestFailCloseUserGroupDeleteRollsBackOnAuditFailure(t *testing.T) {
	svc, db := setupUserGroupDB(t)
	inj := newAuditFaultInjector(t, auditHitSpec{
		AP: "AP-60 UserGroupService.Delete", Action: model.ActionDelete,
		Resource: model.ResourceUserGroup, Details: `"group_name"`,
	})
	inj.attach(db)

	mkGroup := func(name string) uint {
		t.Helper()
		g := model.UserGroup{Name: name}
		if err := db.Create(&g).Error; err != nil {
			t.Fatalf("前置群組 %s: %v", name, err)
		}
		if err := db.Create(&model.AssetAuthorization{UserGroupID: &g.ID, AssetID: ptrUint(3)}).Error; err != nil {
			t.Fatalf("前置授權 %s: %v", name, err)
		}
		return g.ID
	}

	ctrlID := mkGroup("對照組")
	inj.control("刪除使用者群組", func() error {
		_, err := svc.Delete(ctrlID, 1, "admin", "127.0.0.1")
		return err
	}, func() int64 { return countWhere(t, db, &model.UserGroup{}, "id = ?", ctrlID) }, 0)
	if got := countRows(t, db, &model.AssetAuthorization{}); got != 0 {
		t.Fatalf("[對照組] 級聯撤銷未發生（授權剩 %d 筆）", got)
	}

	targetID := mkGroup("組")
	inj.arm()
	_, err := svc.Delete(targetID, 1, "admin", "127.0.0.1")
	inj.assertCausedBy("AP-60：審計失敗時刪除竟然成功——「刪群組即失權」將無痕發生", err)

	groups := countWhere(t, db, &model.UserGroup{}, "id = ?", targetID)
	auths := countRows(t, db, &model.AssetAuthorization{})
	if groups != 1 || auths != 1 {
		t.Fatalf("AP-60：回滾不完整（群組剩 %d、授權剩 %d，皆應為 1）", groups, auths)
	}
}

// ── AP-51：LDAP env seed（插列＋審計＋marker 同事務）────────────────────

func TestFailCloseLDAPSeedRollsBackOnAuditFailure(t *testing.T) {
	inj := newAuditFaultInjector(t, auditHitSpec{
		AP: "AP-51 identity.RunLDAPEnvSeed", Action: model.ActionCreate,
		Resource: model.ResourceAuth, Details: `"transmission_risks"`,
	})

	t.Setenv("LDAP_ENABLED", "true")
	t.Setenv("LDAP_URL", "ldaps://ldap.example.com:636")
	t.Setenv("LDAP_BIND_DN", "cn=admin,dc=example,dc=com")
	t.Setenv("LDAP_BIND_PASSWORD", "secret")
	t.Setenv("LDAP_BASE_DN", "dc=example,dc=com")

	// **對照組必須用另一個庫**：seed 成功後會寫 marker，同一個庫上重跑會早退，
	// 那樣的「對照」證明不了任何事。輸入（env、codec、sink）逐項相同。
	ctrlDB := newLDAPSeedBackstopDB(t)
	inj.attach(ctrlDB)
	inj.control("env seed", func() error {
		return identity.RunLDAPEnvSeed(ctrlDB, aesColumnCodec(t, make([]byte, 32)), audit.NewTxSink())
	}, func() int64 { return countRows(t, ctrlDB, &model.LDAPDirectory{}) }, 1)
	var ctrlMarkers int64
	ctrlDB.Table("schema_migrations").Count(&ctrlMarkers)
	if ctrlMarkers != 1 {
		t.Fatalf("[對照組] 無故障時 marker 應寫入 1 筆，實得 %d——"+
			"實驗組的「marker 未寫」本來就會成立", ctrlMarkers)
	}

	db := newLDAPSeedBackstopDB(t)
	inj.attach(db)
	inj.arm()
	// **codec 必須是真的**：`identity.RunLDAPEnvSeed` 在 bind password 非空時，於**進入交易之前**
	// 就有 `if codec == nil { return err }`（`ldap_seed_migration.go`）。傳 nil 會在那裡早退，
	// 永不觸及插列／審計／marker，使下方四條斷言全因「什麼都沒發生」成立——
	// 這正是對抗驗證揭露的假綠根因。防呆使此前提不可能再靜默退化。
	err := identity.RunLDAPEnvSeed(db, aesColumnCodec(t, make([]byte, 32)), audit.NewTxSink())

	// **落地狀態先斷言、回傳值後斷言**：本檔的突變配方要求「移除 fail-close 後該格在
	// 『業務列仍在』那條轉紅」——那是 fail-close 的定義；「回了 error」只是它的必要條件。
	var dirs, markers, logs int64
	db.Model(&model.LDAPDirectory{}).Count(&dirs)
	db.Table("schema_migrations").Count(&markers)
	db.Model(&model.AuditLog{}).Count(&logs)
	if dirs != 0 {
		t.Fatalf("AP-51：ldap_directories 留下 %d 筆——認證來源已建立而審計缺席（err=%v）", dirs, err)
	}
	if markers != 0 {
		t.Fatalf("AP-51：marker 已寫（%d 筆）——下次啟動不再重試，seed 永久停在半完成狀態（err=%v）", markers, err)
	}
	if logs != 0 {
		t.Fatalf("AP-51：回滾後仍留下 %d 筆審計列", logs)
	}
	inj.assertCausedBy("AP-51：審計失敗時 seed 竟然成功——一個外部認證來源將被永久建立而無任何審計", err)
}

func newLDAPSeedBackstopDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	// 單連線：sqlite :memory: 每條連線是各自獨立的庫（既有 flaky 真因 ff51836）。
	// seed 路徑跨多次查詢（catalog 探測、marker 查詢、鎖內交易），不釘連線會偶發看不到表。
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql.DB: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&model.LDAPDirectory{}, &model.AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := db.Exec("CREATE TABLE schema_migrations (version varchar(50) PRIMARY KEY, applied_at datetime NOT NULL)").Error; err != nil {
		t.Fatalf("schema_migrations: %v", err)
	}
	return db
}

// ── AP-50：LDAP 目錄設定的三條 fail-close 呼叫路徑（各自一格）────────────
//
// `ldapDirectoryAuditLog` 是單一寫入點，但**六條呼叫路徑語義二分**：auditSave／
// auditURLChange／auditDelete 三條在鎖內交易且 `return`（fail-close），auditRejection
// 與 probe 兩處傳根 DB 只記 log（fail-open）。三條 fail-close 路徑各給一格、
// 各自釘住 Details 的 `event` 欄——舊版把 save 與 url_changed 合在一格，
// 先寫的 save 一失敗，url_changed 就永遠不可達（「多點共用一格」的形態）。

func newLDAPDirectoryFixture(t *testing.T) (*identity.LDAPDirectoryService, *gorm.DB, identity.LDAPDirectoryRequest) {
	t.Helper()
	db := newLDAPDirectoryBackstopDB(t)
	svc := identity.NewLDAPDirectoryService(db, nil, audit.NewTxSink())
	svc.SetTransmissionPolicy(ldapAllowAllGate{})
	req := identity.LDAPDirectoryRequest{
		Name: "LDAP", URL: "ldaps://ldap.example.com:636",
		BindDN: "cn=admin,dc=example,dc=com", BindPassword: "pw",
		BaseDN: "dc=example,dc=com", UserFilter: "(uid=%s)",
		AttrEmail: "mail", AttrFullName: "cn", Enabled: true,
		Actor: identity.LDAPDirectoryActor{ID: 1, Name: "admin", IP: "127.0.0.1"},
	}
	return svc, db, req
}

// AP-50a：auditSave（`upsertLocked` 內，事件 ldap_directory_save）
func TestFailCloseLDAPDirectorySaveRollsBackOnAuditFailure(t *testing.T) {
	svc, db, req := newLDAPDirectoryFixture(t)
	inj := newAuditFaultInjector(t, auditHitSpec{
		AP:       "AP-50a identity.LDAPDirectoryService.Upsert／auditSave",
		Resource: model.ResourceAuth, Details: `"event":"` + identity.LDAPAuditEventSave + `"`,
	})
	inj.attach(db)

	inj.control("建立目錄設定", func() error {
		_, err := svc.Upsert(context.Background(), req)
		return err
	}, func() int64 { return countRows(t, db, &model.LDAPDirectory{}) }, 1)
	auditBefore := countRows(t, db, &model.AuditLog{})

	// 實驗組：**只改名不改 URL**，使本格唯一觸及的 fail-close 路徑是 auditSave
	// （改 URL 會另外走 auditURLChange，該路徑由 AP-50b 那格單獨證明）。
	before := currentLDAPName(t, db)
	req.Name = "LDAP-renamed"
	req.BindPassword = "pw2"
	inj.arm()
	_, err := svc.Upsert(context.Background(), req)
	inj.assertCausedBy("AP-50a：審計失敗時設定變更竟然成功——目錄設定可被改動而無痕", err)
	if after := currentLDAPName(t, db); after != before {
		t.Fatalf("AP-50a：名稱已變更為 %q 但審計未留痕（回滾失敗）", after)
	}
	if got := countRows(t, db, &model.AuditLog{}) - auditBefore; got != 0 {
		t.Fatalf("AP-50a：回滾後多出 %d 筆審計列", got)
	}
}

// AP-50b：auditURLChange（端點改向的高權重事件，事件 ldap_directory_url_changed）
func TestFailCloseLDAPDirectoryURLChangeRollsBackOnAuditFailure(t *testing.T) {
	svc, db, req := newLDAPDirectoryFixture(t)
	inj := newAuditFaultInjector(t, auditHitSpec{
		AP: "AP-50b identity.LDAPDirectoryService.Upsert／auditURLChange", Action: model.ActionUpdate,
		Resource: model.ResourceAuth, Details: `"event":"` + identity.LDAPAuditEventURLChanged + `"`,
	})
	inj.attach(db)

	if _, err := svc.Upsert(context.Background(), req); err != nil {
		t.Fatalf("前置建立: %v", err)
	}
	// 對照組：**同樣是一次 URL 變更**（唯一與實驗組不同的是沒有故障）
	req.URL = "ldaps://ctrl.example.com:636"
	req.BindPassword = "pw-ctrl"
	inj.control("變更目錄端點", func() error {
		_, err := svc.Upsert(context.Background(), req)
		return err
	}, func() int64 {
		return countWhere(t, db, &model.LDAPDirectory{}, "url = ?", "ldaps://ctrl.example.com:636")
	}, 1)
	auditBefore := countRows(t, db, &model.AuditLog{})

	before := currentLDAPURL(t, db)
	req.URL = "ldaps://moved.example.com:636"
	req.BindPassword = "pw2"
	inj.arm()
	_, err := svc.Upsert(context.Background(), req)
	inj.assertCausedBy("AP-50b：審計失敗時端點改向竟然成功——目錄可被改指向而無痕", err)
	if after := currentLDAPURL(t, db); after != before {
		t.Fatalf("AP-50b：URL 已變更為 %q 但審計未留痕（回滾失敗）", after)
	}
	if got := countRows(t, db, &model.AuditLog{}) - auditBefore; got != 0 {
		t.Fatalf("AP-50b：回滾後多出 %d 筆審計列", got)
	}
}

// AP-50c：auditDelete（事件 ldap_directory_delete）
func TestFailCloseLDAPDirectoryDeleteRollsBackOnAuditFailure(t *testing.T) {
	svc, db, req := newLDAPDirectoryFixture(t)
	inj := newAuditFaultInjector(t, auditHitSpec{
		AP: "AP-50c identity.LDAPDirectoryService.Delete", Action: model.ActionDelete,
		Resource: model.ResourceAuth, Details: `"event":"` + identity.LDAPAuditEventDelete + `"`,
	})
	inj.attach(db)
	actor := req.Actor

	if _, err := svc.Upsert(context.Background(), req); err != nil {
		t.Fatalf("前置建立（對照組）: %v", err)
	}
	inj.control("刪除目錄設定", func() error {
		return svc.Delete(context.Background(), actor)
	}, func() int64 { return countRows(t, db, &model.LDAPDirectory{}) }, 0)

	if _, err := svc.Upsert(context.Background(), req); err != nil {
		t.Fatalf("前置建立（實驗組）: %v", err)
	}
	auditBefore := countRows(t, db, &model.AuditLog{})

	inj.arm()
	err := svc.Delete(context.Background(), actor)
	inj.assertCausedBy("AP-50c：審計失敗時刪除竟然成功——認證來源可被移除而無痕", err)
	if got := countRows(t, db, &model.LDAPDirectory{}); got != 1 {
		t.Fatalf("AP-50c：設定列已被刪除但審計未留痕（剩 %d 筆，應為 1）", got)
	}
	if got := countRows(t, db, &model.AuditLog{}) - auditBefore; got != 0 {
		t.Fatalf("AP-50c：回滾後多出 %d 筆審計列", got)
	}
}

func currentLDAPURL(t *testing.T, db *gorm.DB) string {
	t.Helper()
	var row model.LDAPDirectory
	if err := db.First(&row).Error; err != nil {
		t.Fatalf("讀取目錄設定: %v", err)
	}
	return row.URL
}

func currentLDAPName(t *testing.T, db *gorm.DB) string {
	t.Helper()
	var row model.LDAPDirectory
	if err := db.First(&row).Error; err != nil {
		t.Fatalf("讀取目錄設定: %v", err)
	}
	return row.Name
}

func newLDAPDirectoryBackstopDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	// 單連線：sqlite :memory: 每條連線是各自獨立的庫（既有 flaky 真因 ff51836）
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql.DB: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&model.LDAPDirectory{}, &model.AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

// ── nil sink 也必須 fail-close（4.7 的呼叫側備援）────────────────────────

// TestFailCloseWhenSinkNotInjected 未注入 sink 時，強制審計點一律回 error 使業務回滾。
//
// **這是啟動自檢之外的第二道**：啟動自檢擋的是「組裝根漏接」，本測試擋的是
// 「有人另開一條建構路徑繞過組裝根」。兩者都不在時，nil sink 若被實作成 no-op，
// 審計會靜默消失、業務照樣成立、而且所有測試更綠。
//
// # 全檔唯一「設計上就不建立注入器」的一格
//
// 本格的故障源是**未注入 sink**，不是「審計列寫不進去」——審計寫入根本走不到
// DB 那一層就被 `port.WriteInTx` 攔下。建立注入器只會得到一個恆為 0 的命中數，
// 證明不了任何事。
//
// 它的兩項等價證明：
//   - **抵達證明**＝`errors.Is(err, port.ErrTxSinkMissing)`：該哨兵**只可能**由
//     `port.WriteInTx` 在 sink 為 nil 時產出（`port/txsink.go`），亦即控制流必然
//     抵達了審計發出點。任何前置早退都會給出別的錯誤而使本格轉紅。
//   - **對照證明**＝同一輸入在**有注入 sink** 時必須成功且留痕（下方前半段），
//     排除「這條入口本來就會失敗」的真空。
func TestAuditWriteFaultInjectionActuallyFires(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.AuditLog{}, &model.AssetGroup{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	inj := newAuditFaultInjector(t, auditHitSpec{
		AP: "自檢（注入器本身）", Action: model.ActionCreate,
		Resource: model.ResourceAsset, Details: "TARGET",
	})
	inj.attach(db)

	target := func() *model.AuditLog {
		return &model.AuditLog{Action: model.ActionCreate, Resource: model.ResourceAsset, Details: "TARGET"}
	}
	inj.control("直寫命中身分的審計列", func() error {
		return db.Create(target()).Error
	}, func() int64 { return countRows(t, db, &model.AuditLog{}) }, 1)

	inj.arm()
	err = db.Create(target()).Error
	inj.assertCausedBy("啟用故障後審計列仍寫得進去——注入器沒有生效，整組 backstop 形同虛設", err)

	// **不命中身分者放行**（選擇性注入）
	if err := db.Create(&model.AuditLog{
		Action: model.ActionCreate, Resource: model.ResourceAsset, Details: "OTHER",
	}).Error; err != nil {
		t.Fatalf("不命中本格身分的審計寫入不得被攔下（否則不相干的寫入會替本格取得 credit）: %v", err)
	}
	// **只攔審計表**
	if err := db.Create(&model.AssetGroup{Name: "不受影響"}).Error; err != nil {
		t.Fatalf("注入器不得影響非審計表的寫入: %v", err)
	}
	inj.disarm()
}

// 突變自檢的可重現配方（每個案例都須有「移除 fail-close 處置後該案例轉紅」的
// 突變證明）：把對應呼叫點的 `return fmt.Errorf("審計留痕失敗: %w", err)`
// 改成 `log.Printf(...)` 後跑本檔，該案例必須從綠轉紅，**且是在「業務列仍在」那條
// 斷言上紅**（不是在「err == nil」那條——那只證明錯誤有回傳，證不到回滾）。
//
// **第二種突變（防呆自身）**：把某格改成不觸及指定審計點（例：AP-51 格把 codec 改回
// `nil`，使 `identity.RunLDAPEnvSeed` 在進交易前早退），該格必須因 `assertHealthy` 的
// 「一次都沒有命中指定的審計點」而紅——**且此時業務斷言全部通過**。
//
// **第三種突變（身分歸屬）**：讓不相干的審計寫入 fire
// （例：AP-38 格的 `(*Asset).AfterCreate` hook 早於 `RecordAssetAccountChange`
// 寫一筆），本格**不得**因此通過——選擇性注入使該筆放行、`errors.Is(sentinel)`
// 使歸因無法混淆。
//
// **第四種突變（對照組）**：拿掉某格的業務列建立（或把查詢條件改成永遠 0 筆），
// 該格必須在 `control` 那三條之一轉紅，而不是靜默通過。
//
// 四種突變均已實跑驗證。

// ── T-2：資產與資產帳號（AP-22／30…35／38／40）────────────────────────────
//
// 這批點**尚未**收口（仍走 `model.RecordAsset*Change` 的 `tx.Create`，
// 收口另行排程）。**但 backstop 現在就必須涵蓋它們**——涵蓋範圍取自
// manifest 的 `fail-close?＝是` 欄，不是「已收口的點」。先立好，收口時這組
// 測試就是現成的等價證據：收口前後同一組斷言必須都綠，任一轉紅即語義漂移。
//
// **注意 setupAccountDB 會改寫套件級 `database.DB`**——本區各格因此絕不可平行，
// 由 `TestBackstopGridsDeclareNoParallel` 機器化。

// AP-38（＋落地側 AP-22）：AssetService.Create 的預設帳號建立審計。
//
// **本格是「多點共用一格」的原始案例**：`(*Asset).AfterCreate`（AP-23）會在
// `RecordAssetAccountChange`（AP-38）**之前**寫一筆 `Details` 為空的審計列。
// 舊版「fired > 0」的防呆會由那一筆取得 credit，AP-38 整條被刪掉也不會轉紅。
// 現在 spec 釘住 `"resource":"asset_account"`，hook 那筆不命中、照樣放行。
// ── 🔴 射程與盲區：注入器**看不見**什麼─────────────
//
// 下面四格刻意斷言「注入器沒有攔到」。它們不是 fail-close 案例，故**不使用**
// `auditFaultInjector`（那個的防呆會要求「至少命中一次」，與本節目的相反），
// 改用純觀察器 `observeAuditWrites`。
//
// 目的不是修好盲區——GORM callback 本來就只看得見 GORM callback 走過的路——
// 而是讓盲區**可見**：任何人日後把審計寫入改走這些形態，本節的 t.Log
// 會直接告訴他「backstop 從此看不到這條路」。

type auditWriteObserver struct {
	mu   sync.Mutex
	hits []auditHit
}

func (o *auditWriteObserver) count() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.hits)
}

// observeAuditWrites 只觀察不注入的輕量版（射程測試專用）。
func observeAuditWrites(t *testing.T, db *gorm.DB) *auditWriteObserver {
	t.Helper()
	obs := &auditWriteObserver{}
	const name = "w4_backstop:observe"
	err := db.Callback().Create().Before("gorm:create").Register(name, func(tx *gorm.DB) {
		if tx.Statement == nil || !auditWriteTarget(tx) {
			return
		}
		obs.mu.Lock()
		obs.hits = append(obs.hits, auditHitsOf(tx)...)
		obs.mu.Unlock()
	})
	if err != nil {
		t.Fatalf("註冊觀察器失敗: %v", err)
	}
	t.Cleanup(func() { _ = db.Callback().Create().Remove(name) })
	return obs
}

func newBlindSpotDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:w4blind?mode=memory&cache=shared"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql.DB: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&model.AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { db.Exec("DELETE FROM audit_logs") })
	return db
}

// B-a：原生 SQL（`Exec`）走 Raw callback，不經 Create callback ⇒ **盲區**
func TestBackstopBlindSpotRawSQLInsert(t *testing.T) {
	db := newBlindSpotDB(t)
	obs := observeAuditWrites(t, db)
	if err := db.Exec(
		"INSERT INTO audit_logs (user_id, username, action, resource, status, details) VALUES (?,?,?,?,?,?)",
		1, "admin", string(model.ActionCreate), string(model.ResourceAsset), string(model.StatusSuccess), "raw",
	).Error; err != nil {
		t.Fatalf("原生 SQL 寫入: %v", err)
	}
	if got := countWhere(t, db, &model.AuditLog{}, "details = ?", "raw"); got != 1 {
		t.Fatalf("前提不成立：原生 SQL 應寫入 1 筆，實得 %d", got)
	}
	if n := obs.count(); n != 0 {
		t.Fatalf("射程宣告與現實不符：原生 SQL 竟被 Create callback 攔到 %d 次——"+
			"本檔的盲區清單須改寫（這是好消息，但宣告必須跟著改）", n)
	}
	t.Log("盲區 B-a 確認：db.Exec 的原生 INSERT 不經 Create callback，backstop 看不見。" +
		"若日後出現原生 SQL 的審計寫入，須升級為 DB 層 INSERT trigger 注入器")
}

// B-b：Update 路徑（`Save`／`Updates`）——**注入器看不見，但該路徑本身被 model 層封死**
//
// 實測結論比原先的推測更強：`(*model.AuditLog).BeforeUpdate` 回 `gorm.ErrInvalidValue`
// （`internal/model/audit_log.go`，「審計日誌創建後不應被修改」），因此經 ORM 改寫
// 既有審計列**根本不會成功**。B-b 於是不是一個可利用的盲區，而是「注入器看不見、
// 但另一道不變式擋住了」。本格同時釘住那道不變式——它一旦被放寬，B-b 立刻變成
// 真盲區（審計列可被就地竄改且 backstop 無感），本格會轉紅。
func TestBackstopBlindSpotUpdatePathWrite(t *testing.T) {
	db := newBlindSpotDB(t)
	row := &model.AuditLog{Action: model.ActionCreate, Resource: model.ResourceAsset, Details: "before-observe"}
	if err := db.Create(row).Error; err != nil {
		t.Fatalf("前置列: %v", err)
	}
	obs := observeAuditWrites(t, db)
	row.Details = "mutated"
	err := db.Save(row).Error
	if !errors.Is(err, gorm.ErrInvalidValue) {
		t.Fatalf("審計列的 ORM Update 路徑應被 BeforeUpdate 封死（gorm.ErrInvalidValue），實得 %v——"+
			"該不變式若被放寬，Update 路徑就成為 backstop 的真盲區：審計列可被就地竄改而注入器無感", err)
	}
	if got := countWhere(t, db, &model.AuditLog{}, "details = ?", "mutated"); got != 0 {
		t.Fatalf("審計列竟被就地改寫 %d 筆——append-only 不變式已破", got)
	}
	if n := obs.count(); n != 0 {
		t.Fatalf("射程宣告與現實不符：Update 路徑竟被 Create callback 攔到 %d 次", n)
	}
	t.Log("B-b 確認：Update 路徑不經 Create callback（注入器看不見），但 " +
		"(*model.AuditLog).BeforeUpdate 直接封死該路徑，故現況不是可利用的盲區")
}

// B-c：另行 gorm.Open 取得的全新句柄沒有本測試註冊的 callback ⇒ **盲區**
func TestBackstopBlindSpotFreshHandle(t *testing.T) {
	db := newBlindSpotDB(t)
	obs := observeAuditWrites(t, db)
	fresh, err := gorm.Open(sqlite.Open("file:w4blind?mode=memory&cache=shared"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("fresh handle: %v", err)
	}
	if err := fresh.Create(&model.AuditLog{
		Action: model.ActionCreate, Resource: model.ResourceAsset, Details: "fresh",
	}).Error; err != nil {
		t.Fatalf("fresh 句柄寫入: %v", err)
	}
	if got := countWhere(t, db, &model.AuditLog{}, "details = ?", "fresh"); got != 1 {
		t.Fatalf("前提不成立：fresh 句柄應寫入同一張表 1 筆，實得 %d", got)
	}
	if n := obs.count(); n != 0 {
		t.Fatalf("射程宣告與現實不符：全新句柄的寫入竟被攔到 %d 次", n)
	}
	t.Log("盲區 B-c 確認：callback 綁在句柄上，另行 gorm.Open 的 handle 不受注入器管轄。" +
		"生產路徑一律經 database.DB／注入的 *gorm.DB，故此盲區僅在有人自建連線時成立")
}

// 批次不是盲區：`CreateInBatches` 走 Create callback，且身分逐列抽得出來
func TestBackstopSeesBatchAuditWrites(t *testing.T) {
	db := newBlindSpotDB(t)
	obs := observeAuditWrites(t, db)
	rows := []model.AuditLog{
		{Action: model.ActionCreate, Resource: model.ResourceAsset, Details: "batch-1"},
		{Action: model.ActionDelete, Resource: model.ResourceAsset, Details: "batch-2"},
	}
	if err := db.CreateInBatches(&rows, 10).Error; err != nil {
		t.Fatalf("CreateInBatches: %v", err)
	}
	if n := obs.count(); n != 2 {
		t.Fatalf("批次寫入應被逐列觀察到 2 筆，實得 %d——"+
			"射程宣告稱「批次不是盲區」，此處即其證據；若 GORM 版本改變此行為，"+
			"本檔的射程宣告必須跟著改", n)
	}
	spec := auditHitSpec{AP: "batch", Action: model.ActionDelete, Details: "batch-2"}
	matched := false
	obs.mu.Lock()
	for _, h := range obs.hits {
		if spec.matches(h) {
			matched = true
		}
	}
	obs.mu.Unlock()
	if !matched {
		t.Fatal("批次寫入的**逐列身分**抽不出來——身分比對在批次形態上會失明")
	}
	t.Log("射程確認：CreateInBatches 命中 Create callback，且逐列身分可抽出")
}

// ── 共享狀態隔離：本檔禁止平行─────────────────

// TestBackstopGridsDeclareNoParallel 以原始碼掃描釘住「本檔不得出現 t.Parallel」。
//
// # 為什麼是硬禁令而不是「小心一點」
//
//   - `setupAccountDB` 會改寫**套件級**變數 `database.DB`（並以 Cleanup 還原）——
//     兩格平行跑時，後啟動的那格會把前一格的 DB 換掉，前一格的服務層寫入從此
//     落在別的庫；`countRows` 讀到 0 筆，而「業務列不存在」正是本組的通過條件。
//     **那是本組最容易發生、也最難察覺的假綠形態。**
//   - 注入器的 callback 綁在 DB 句柄上，但 `database.DB` 這條共享路徑繞過了句柄隔離。
//   - 本檔多格使用 `t.Setenv`（AP-51），Go 本身即禁止與 `t.Parallel` 併用。
//
// 計數與觀察表已在 `auditFaultInjector.mu` 之下且綁定單一測試身分，`-race` 亦零告警；
// 但那只保證「不會資料競賽」，保證不了「不會交叉抵帳」——後者靠本禁令。
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
	// 下界：本檔被清空或改名時不得靜默通過。
	// **下界自 12 調為 5**：backstop 依模組拆成兩份，asset 的 12 格隨檔遷入
	// `internal/modules/asset/audit_failclose_backstop_test.go`（該檔有自己的同名禁令，
	// 下界 12），本檔留下的是 identity 的 5 格（UserGroup 1＋LDAP 4）。
	// **這不是放寬**——兩份下界相加仍為 17，且各自守著自己那半邊。
	if n := strings.Count(src, "\nfunc TestFailClose"); n < 5 {
		t.Fatalf("本檔只剩 %d 個 TestFailClose 格（下限 5）：backstop 已縮水，本禁令正在空集合上假綠", n)
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

// mustCreateAsset 前置：建一台帶 default 帳號的資產

var _ = database.DB // 明示本檔依賴套件級 DB（禁平行的理由之一）
