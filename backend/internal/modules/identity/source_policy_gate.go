package identity

import (
	"errors"
	"log"
	"strconv"
	"sync/atomic"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/sourceip"
)

// 允許來源網段清單在**判定點**的讀取面與政策不可用處置。
//
// # 為何清單一律現讀
//
// 與「即時有效角色」同一條紀律：判定的價值就在於讀到最新狀態。清單若進 JWT
// 或行程快取，多副本部署下把舊 token 導向未更新的副本即可繼續使用，
// 管理者剛剛收窄的網段形同虛設。成本是一次已索引的主鍵讀取。
//
// # 政策不可用不得視為空清單
//
// 兩種不可用：(a) 使用者列讀不到（DB 錯）；(b) 儲存字串解析失敗。兩者若被
// 當成「清單為空＝不限」，後果是**靜默放行**——限制設了等於沒設，而且沒有
// 任何訊號。故一律拒絕，並經既有的審計機制失效通道上報，讓稽核能把「被擋」
// 歸因到「政策壞了」而非「來源不對」。

// ErrSourcePolicyUnavailable 判定點取不到資料來源（組裝未注入且無全域回退）。
//
// **與「清單不允許此來源」分開命名**：前者是系統組裝錯誤（要修部署），
// 後者是政策生效（要找管理員），兩者的處置完全不同。
var ErrSourcePolicyUnavailable = errors.New("來源政策不可讀：資料來源未初始化")

// sourcePolicyDegraded 政策不可用的行程內狀態旗標。
//
// **只為省掉掃描成本而存在**，不是判定依據：判定一律由 sourceip.Evaluate
// 以當次讀到的字串作成。恢復謂詞要掃 users 全表，若每次成功判定都掃一次，
// 登入尖峰會把它變成每秒數十次全表掃描；以本旗標把掃描收斂到「確實失效中」
// 的期間，未失效時的成本是一次 atomic load。
//
// 生命週期：Report 置真、恢復謂詞為零時置假、啟動時由 AdoptOpenEvent 回填。
// 登記於 manifest-lifecycle（包級可變狀態）。
var sourcePolicyDegraded atomic.Bool

// ReadSourcePolicy 現讀某使用者的允許來源網段儲存字串，並維護政策可用性訊號。
//
// 回傳的字串交由 `sourceip.Evaluate` 判定——**本函式不自行決定放行與否**，
// 判定邏輯只有一份。readErr 非 nil 時呼叫端須把它交給 Evaluate（後者對讀取
// 失敗 fail-close），不得忽略。
func (s *AuthService) ReadSourcePolicy(userID uint) (string, error) {
	// 與世代閘共用組裝根注入的同一份句柄：兩者都是「授權關鍵欄位現查」，
	// 資料來源分家會出現「世代讀得到、清單讀不到」這種只有一半生效的狀態
	db := s.epochDB()
	if db == nil {
		s.noteSourcePolicyRead(userID, "", ErrSourcePolicyUnavailable)
		return "", ErrSourcePolicyUnavailable
	}
	var row model.User
	err := db.Select("allowed_cidrs").First(&row, userID).Error
	s.noteSourcePolicyRead(userID, row.AllowedCIDRs, err)
	if err != nil {
		return "", err
	}
	return row.AllowedCIDRs, nil
}

// noteSourcePolicyRead 判定點讀取後的可用性記帳。
//
// 三態：讀取失敗 → read_error 上報；讀到但字串損壞 → parse_error 上報；
// 讀到且可解析 → 只有在**確實失效中**時才付出恢復謂詞的掃描成本。
func (s *AuthService) noteSourcePolicyRead(userID uint, raw string, readErr error) {
	switch {
	case readErr != nil:
		reportSourcePolicyFailure(model.CauseSourcePolicyUnreadable, userID)
	case !SourcePolicyParsable(raw):
		reportSourcePolicyFailure(model.CauseSourcePolicyCorrupt, userID)
	case sourcePolicyDegraded.Load():
		EvaluateSourcePolicyHealth(s.epochDB())
	}
}

// SourcePolicyParsable 儲存字串是否可解析。
//
// **空字串是可解析的**（＝不限），不是不可用：唯一寫入路徑是驗證後寫入，
// 空值就是「這個帳號沒有限制」的正常表達。把空當成損壞會讓全部未設限的帳號
// 在啟動掃描時被判為政策失效。
func SourcePolicyParsable(raw string) bool {
	list := sourceip.SplitStored(raw)
	if len(list) == 0 {
		return true
	}
	_, _, _, valid := sourceip.Inspect(list)
	return valid
}

// reportSourcePolicyFailure 政策不可用的降級上報。
//
// 走既有的審計機制失效通道（去重、結案、面板、通知都已備妥），
// 不新增事件目錄——新事件名只會多一個名字卻少掉狀態語義。
// params 只帶 user_id：損壞的原始字串不出站也不進 params（去識別紅線）。
func reportSourcePolicyFailure(cause string, userID uint) {
	sourcePolicyDegraded.Store(true)
	failure := audit.GetAuditFailure()
	if failure == nil {
		// 單測路徑（未初始化單例）：旗標仍置真，使恢復謂詞的行為與生產一致
		return
	}
	failure.Report(model.MechanismSourcePolicy, cause,
		map[string]string{"user_id": strconv.FormatUint(uint64(userID), 10)})
}

// sourcePolicyScanRow 恢復謂詞的掃描列。
//
// **欄名以 tag 釘死**：GORM 的預設命名策略對 `AllowedCIDRs` 這種連續大寫
// 推導出的欄名不保證是 `allowed_cidrs`，掃出來會全是空字串——而空字串
// 恰好被判為「可解析」，於是損壞列永遠掃不到，謂詞靜默失效。
type sourcePolicyScanRow struct {
	ID           uint   `gorm:"column:id"`
	AllowedCIDRs string `gorm:"column:allowed_cidrs"`
}

// EvaluateSourcePolicyHealth 恢復謂詞：掃描 users.allowed_cidrs，**雙向**調整失效狀態。
//
// 呼叫時機：啟動、使用者清單成功寫入後、判定點成功讀取且目前失效中時。
// 「存在任何一列解析失敗」即維持（或進入）失效；全部可解析即結案。
//
// **雙向**是刻意的：只做 Resolve 會讓「啟動時就已經有損壞列」這個狀態
// 在第一次有人登入之前完全沒有訊號，而那正是最需要被看見的時刻。
func EvaluateSourcePolicyHealth(db *gorm.DB) {
	if db == nil {
		return
	}
	// 認領重啟前遺留的 open 事件（沿 KEK 退場監看的形態）：不認領時，
	// 掃描乾淨後的 Resolve 會因行程內狀態是「非失效中」而 no-op，
	// 那一列 audit_failure_events 就永遠懸掛
	if failure := audit.GetAuditFailure(); failure != nil &&
		failure.AdoptOpenEvent(model.MechanismSourcePolicy) {
		sourcePolicyDegraded.Store(true)
	}

	var rows []sourcePolicyScanRow
	if err := db.Model(&model.User{}).Select("id", "allowed_cidrs").Find(&rows).Error; err != nil {
		// 掃不到就維持現狀：把「查詢失敗」當成「全部乾淨」會在 DB 抖動時
		// 錯誤結案一個仍在進行中的失效
		log.Printf("[SourcePolicy] 恢復謂詞掃描失敗: %v", err)
		return
	}
	for _, r := range rows {
		if !SourcePolicyParsable(r.AllowedCIDRs) {
			reportSourcePolicyFailure(model.CauseSourcePolicyCorrupt, r.ID)
			return
		}
	}
	if !sourcePolicyDegraded.Load() {
		return
	}
	sourcePolicyDegraded.Store(false)
	if failure := audit.GetAuditFailure(); failure != nil {
		failure.Resolve(model.MechanismSourcePolicy)
	}
}
