package api

import (
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
)

// 檢查點驗證端點的角色指派維度。
//
// # 為什麼換算在這一層而不在對帳器
//
// 快照與失效事件一律只帶識別（`user_id`／`role_id`），因為它們會進檢查點簽章
// 與告警外送，而那兩個去處都不該帶個資。但稽核讀「差在 (7, 2)」得不到任何
// 結論——他要的是「帳號 zhang 多了 admin」。換算因此發生在**出站前的最後一站**：
// 端點本身已由 admin／auditor 守門，名字不會離開這條授權過的路徑。
// **查詢本體不在這一層**：換算的時機在出站前，取名字的動作則向擁有
// `users`／`roles`／`audit_failure_events` 的模組要（見 roleStateNameSource）。
//
// # 回應形狀刻意與內部報告不同
//
// 內部 `audit.RoleStateReport` 帶預期／現況雜湊，那是對帳器的工作記錄，
// 對外沒有可操作性，反而是把「怎麼算出來的」講給不需要知道的人聽。出站只留
// 稽核判讀得到的六項：是否已涵蓋、狀態、自哪個檢查點起算、兩個差集、最近事件。

// roleStateView 出站的角色指派對帳結果
type roleStateView struct {
	// Covered 是否已有含快照的檢查點可作為比對基準
	Covered bool `json:"covered"`
	// State match／mismatch／not_covered（值域見 audit.RoleState* 常數）
	State string `json:"state"`
	// SinceSeq 作為基準的檢查點序號；相符時亦即「已涵蓋至此」
	SinceSeq uint `json:"since_seq,omitempty"`
	// Missing 預期有而現況無；Extra 現況有而預期無
	Missing []roleAssignmentView `json:"missing,omitempty"`
	Extra   []roleAssignmentView `json:"extra,omitempty"`
	// LastEvent 最近一筆相關的審計失效事件；僅不符時附帶
	LastEvent *roleStateEventView `json:"last_event,omitempty"`
}

// roleAssignmentView 差集一筆。
//
// 識別與名稱兩者都給：名稱供閱讀，識別供比對——帳號改名或角色被刪之後，
// 只有識別對得回事件與稽核列
type roleAssignmentView struct {
	UserID uint64 `json:"user_id"`
	RoleID uint64 `json:"role_id"`
	// Username／RoleName 查無對應列時為空字串（帳號或角色已被刪除）。
	// **不以識別冒充名稱**：呈現層據空字串顯示「已不存在的帳號 #7」，
	// 那與「帳號名就叫 7」是兩件事
	Username string `json:"username"`
	RoleName string `json:"role_name"`
}

// roleStateEventView 失效事件的連結資訊（不帶 cause_params 的鑑識細節）
type roleStateEventView struct {
	ID        uint       `json:"id"`
	Mechanism string     `json:"mechanism"`
	CauseCode string     `json:"cause_code"`
	StartedAt time.Time  `json:"started_at"`
	EndedAt   *time.Time `json:"ended_at,omitempty"`
}

// checkpointVerifyResponse 結構層報告＋改寫過的角色指派維度。
//
// 內嵌指標＋同名欄位：`json` 以較淺的深度為準，故外層 `role_state` 蓋掉
// `ChainReport` 內的原欄位。這樣做而不是改 `ChainReport` 的型別，是為了讓
// audit 模組的報告維持「只有識別、可安全落 log 與外送」的性質
type checkpointVerifyResponse struct {
	*audit.ChainReport
	RoleState *roleStateView `json:"role_state,omitempty"`
}

// roleStateNameSource 帳號名與角色名的來源（實作＝`identity.UserService`）。
//
// **接入層不自己查表**：`users`／`roles` 屬 identity 域、`audit_failure_events`
// 屬 audit 域，換算與事件查詢皆下沉到擁有那些表的模組，這裡只留窄介面。
// handler 一旦自持 `*gorm.DB` 直查，「帳號叫什麼名字」就會有第二份真相
// （`TestAPILayerHasNoDirectModelQuery`）
type roleStateNameSource interface {
	// RoleAssignmentUsernames／RoleAssignmentRoleNames 依識別批次取名；
	// 查無者不出現在回傳 map 內（含軟刪，刪帳號不得使差集變匿名）
	RoleAssignmentUsernames(ids []uint64) (map[uint64]string, error)
	RoleAssignmentRoleNames(ids []uint64) (map[uint64]string, error)
}

// roleStateEventSource 失效事件的來源（實作＝`*audit.AuditFailureService`）
type roleStateEventSource interface {
	// LatestByMechanism 指定機制最近一筆事件；無則回 (nil, nil)
	LatestByMechanism(mechanism string) (*model.AuditFailureEvent, error)
}

// roleStateNameLookup 出站投影用得到的查詢面（測試以 fake 取代）
type roleStateNameLookup interface {
	Usernames(ids []uint64) (map[uint64]string, error)
	RoleNames(ids []uint64) (map[uint64]string, error)
	LatestRoleStateEvent() (*model.AuditFailureEvent, error)
}

// roleStateLookup 把兩個模組服務併成投影要的形狀。
//
// 兩側各自可為 nil：只接得到名稱時差集有名字但沒有事件連結，
// 反之亦然——**任一側缺席都不隱藏整個區塊**，理由見 projectRoleState
type roleStateLookup struct {
	names  roleStateNameSource
	events roleStateEventSource
}

// Usernames 帳號名（名稱來源未注入時回空 map，不視為錯誤）
func (l *roleStateLookup) Usernames(ids []uint64) (map[uint64]string, error) {
	if l.names == nil {
		return map[uint64]string{}, nil
	}
	return l.names.RoleAssignmentUsernames(ids)
}

// RoleNames 角色名（同上）
func (l *roleStateLookup) RoleNames(ids []uint64) (map[uint64]string, error) {
	if l.names == nil {
		return map[uint64]string{}, nil
	}
	return l.names.RoleAssignmentRoleNames(ids)
}

// LatestRoleStateEvent 最近一筆角色指派失效事件
func (l *roleStateLookup) LatestRoleStateEvent() (*model.AuditFailureEvent, error) {
	if l.events == nil {
		return nil, nil
	}
	return l.events.LatestByMechanism(model.MechanismRoleStateIntegrity)
}

// projectRoleState 把對帳結果投影成出站形狀。
//
// lookup 為 nil（未注入）時仍回傳識別與狀態，只是名稱留空——**不得整段隱藏**：
// 驗證頁看不到這一列會被讀成「沒有這個機制」，而它其實正在運作
func projectRoleState(rep *audit.RoleStateReport, lookup roleStateNameLookup) *roleStateView {
	if rep == nil {
		return nil
	}
	view := &roleStateView{Covered: rep.Covered, State: rep.State, SinceSeq: rep.SinceSeq}
	users, roles := map[uint64]string{}, map[uint64]string{}
	if lookup != nil {
		ids, roleIDs := rolePairIDs(rep.Missing, rep.Extra)
		if m, err := lookup.Usernames(ids); err == nil {
			users = m
		}
		if m, err := lookup.RoleNames(roleIDs); err == nil {
			roles = m
		}
	}
	view.Missing = toAssignmentViews(rep.Missing, users, roles)
	view.Extra = toAssignmentViews(rep.Extra, users, roles)
	if lookup != nil && rep.State == audit.RoleStateMismatch {
		if ev, err := lookup.LatestRoleStateEvent(); err == nil && ev != nil {
			view.LastEvent = &roleStateEventView{ID: ev.ID, Mechanism: ev.Mechanism,
				CauseCode: ev.CauseCode, StartedAt: ev.StartedAt, EndedAt: ev.EndedAt}
		}
	}
	return view
}

// rolePairIDs 兩個差集去重後的帳號與角色識別
func rolePairIDs(sets ...[]audit.RolePair) ([]uint64, []uint64) {
	seenUser, seenRole := map[uint64]bool{}, map[uint64]bool{}
	users, roles := []uint64{}, []uint64{}
	for _, set := range sets {
		for _, p := range set {
			if !seenUser[p.UserID] {
				seenUser[p.UserID] = true
				users = append(users, p.UserID)
			}
			if !seenRole[p.RoleID] {
				seenRole[p.RoleID] = true
				roles = append(roles, p.RoleID)
			}
		}
	}
	return users, roles
}

// toAssignmentViews 差集換算（維持對帳器給的順序，該順序已經是排序過的）
func toAssignmentViews(pairs []audit.RolePair, users, roles map[uint64]string) []roleAssignmentView {
	if len(pairs) == 0 {
		return nil
	}
	out := make([]roleAssignmentView, 0, len(pairs))
	for _, p := range pairs {
		out = append(out, roleAssignmentView{
			UserID: p.UserID, RoleID: p.RoleID,
			Username: users[p.UserID], RoleName: roles[p.RoleID],
		})
	}
	return out
}
