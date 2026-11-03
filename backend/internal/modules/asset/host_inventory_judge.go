package asset

import (
	"sort"
	"strings"

	"github.com/custodexa/backend/internal/model"
)

// 檢查範圍、盤點結果與特權判定（純函式，不接觸資料庫與網路）。

// 檢查項代號。
const (
	invCheckAccounts   = "accounts"
	invCheckGroups     = "groups"
	invCheckSudoMain   = "sudoers_main"
	invCheckSudoDir    = "sudoers_dir"
	invCheckUnresolved = "sudoers_unresolved"
)

// 檢查項原因碼。
const (
	invReasonPermissionDenied   = "permission_denied"
	invReasonNondefaultLocation = "nondefault_location"
	invReasonNotIncluded        = "not_included"
	invReasonInvalidRows        = "invalid_rows"
	invReasonCommandFailed      = "command_failed"
)

// inventoryFixedNotes 本能力不檢查的提權途徑（固定說明，每次回應都附上）。
var inventoryFixedNotes = []string{
	"other_escalation_tools",
	"unenumerated_directory_accounts",
	"replaced_noninteractive_shell",
}

// invCoverageItem 檢查範圍一項。
type invCoverageItem struct {
	Check         string `json:"check"`
	State         string `json:"state"`
	Reason        string `json:"reason,omitempty"`
	Count         int    `json:"count"`
	DuplicateRows int    `json:"duplicate_rows,omitempty"`
}

// invFindingResult 一個帳號的判定。
type invFindingResult struct {
	Username     string
	UID          string
	UIDConflict  bool
	LoginCapable bool
	Privileged   bool
	Incomplete   bool
	Reasons      []string
}

// invScanResult 一次盤點的判定結果。
type invScanResult struct {
	Status   string // succeeded／partial／failed
	Failure  string // failed 時的結束原因碼
	Coverage []invCoverageItem
	Findings []invFindingResult
	// Escalation 專用帳號身分的提權讀取結果（not_needed／used／denied）；其他身分為空。
	Escalation string
}

// nonLoginShells 不可登入殼層（以完整路徑比對）。
var nonLoginShells = map[string]bool{
	"/sbin/nologin": true, "/usr/sbin/nologin": true, "/bin/nologin": true, "/usr/bin/nologin": true,
	"/bin/false": true, "/usr/bin/false": true, "/bin/true": true, "/usr/bin/true": true,
	"/bin/sync": true, "/usr/bin/sync": true, "/sbin/shutdown": true, "/usr/sbin/shutdown": true,
	"/sbin/halt": true, "/usr/sbin/halt": true,
}

func shellLoginCapable(shell string) bool { return !nonLoginShells[shell] }

func listCoverage(check string, exit int, st invListStats) invCoverageItem {
	it := invCoverageItem{Check: check, Count: st.Rows - st.Invalid, DuplicateRows: st.DuplicateRows}
	switch {
	case exit != 0:
		it.State, it.Reason, it.Count = invStateFailed, invReasonCommandFailed, 0
	case st.Invalid > 0:
		it.State, it.Reason, it.Count = invStatePartial, invReasonInvalidRows, st.Invalid
	default:
		it.State = invStateChecked
	}
	return it
}

// evaluateInventory 由解析後的輸出產生檢查範圍、盤點結果與每個帳號的判定。
// privGroups 為盤點開始時的政策快照（已正規化的逗號分隔清單）。
func evaluateInventory(raw *inventoryRawOutput, privGroups string) (*invScanResult, error) {
	res := &invScanResult{}
	accounts, ast, err := parseInventoryAccounts(raw.AccountList)
	if err != nil {
		return nil, err
	}
	groups, gst, err := parseInventoryGroup(raw.Group)
	if err != nil {
		return nil, err
	}
	frames, err := parseInventorySudoFrames(raw.Sudo)
	if err != nil {
		return nil, err
	}
	if raw.Escalation != nil {
		applyEscalation(frames, raw.Escalation)
	}
	res.Escalation = escalationLabel(raw.Executor, raw.Escalation)
	accItem := listCoverage(invCheckAccounts, raw.AccountListExit, ast)
	grpItem := listCoverage(invCheckGroups, raw.GroupExit, gst)

	mainItem := invCoverageItem{Check: invCheckSudoMain}
	switch frames.MainState {
	case "ok":
		mainItem.State = invStateChecked
	case "unreadable":
		mainItem.State, mainItem.Reason = invStateUnreadable, invReasonPermissionDenied
	default:
		if frames.SudoPresent {
			mainItem.State, mainItem.Reason = invStateFailed, invReasonNondefaultLocation
		} else {
			mainItem.State = invStateAbsent
		}
	}
	rules := parseInventorySudoers(frames.Main, frames.MainState == "ok", frames.Files)

	dirItem := invCoverageItem{Check: invCheckSudoDir}
	switch frames.DirState {
	case "ok":
		unreadable := 0
		for _, f := range frames.Files {
			if !f.Readable && !sudoersDirFileSkipped(f.Name) {
				unreadable++
			}
		}
		switch {
		case frames.MainState == "ok" && !rules.IncludesDir:
			dirItem.State, dirItem.Reason, dirItem.Count = invStateChecked, invReasonNotIncluded, len(frames.Files)
		case unreadable > 0:
			dirItem.State, dirItem.Reason, dirItem.Count = invStatePartial, invReasonPermissionDenied, unreadable
		default:
			dirItem.State, dirItem.Count = invStateChecked, len(frames.Files)
		}
	case "unreadable":
		dirItem.State, dirItem.Reason = invStateUnreadable, invReasonPermissionDenied
	default:
		dirItem.State = invStateAbsent
	}
	annotateEscalation(frames, &mainItem, &dirItem)
	// 主規則檔讀不到或讀取失敗時規則沒有讀進來，無法解析的項目無從判斷，不記為已檢查。
	unresItem := invCoverageItem{Check: invCheckUnresolved, State: invStateChecked, Count: rules.Unresolved + frames.Unparsable}
	if mainItem.State == invStateUnreadable || mainItem.State == invStateFailed {
		unresItem.State = invStateUndetermined
	}
	if frames.Escalated && unresItem.State == invStateChecked {
		unresItem.Reason = invReasonViaEscalation
	}
	res.Coverage = []invCoverageItem{accItem, grpItem, mainItem, dirItem, unresItem}

	if accItem.State == invStateFailed || grpItem.State == invStateFailed {
		res.Status, res.Failure = model.HostAccountScanFailed, inventoryReasonCommandFailed
		return res, nil
	}
	res.Status = model.HostAccountScanSucceeded
	for _, it := range res.Coverage {
		if it.State == invStatePartial || it.State == invStateUnreadable || it.State == invStateFailed {
			res.Status = model.HostAccountScanPartial
		}
	}
	incomplete := false
	for _, it := range []invCoverageItem{mainItem, dirItem} {
		if it.State == invStatePartial || it.State == invStateUnreadable || it.State == invStateFailed {
			incomplete = true
		}
	}
	res.Findings = judgePrivileges(accounts, groups, rules, splitPrivGroups(privGroups), incomplete)
	return res, nil
}

func splitPrivGroups(s string) []string {
	var out []string
	for _, g := range strings.Split(s, ",") {
		if g = strings.TrimSpace(g); g != "" {
			out = append(out, g)
		}
	}
	return out
}

// judgePrivileges 逐帳號判定特權理由（全部成立的理由，排序去重）與可登入。
func judgePrivileges(accounts []*invAccountRow, groups map[string]*invGroup, rules *invSudoRules, privGroups []string, incomplete bool) []invFindingResult {
	inGroup := func(a *invAccountRow, g *invGroup) (member, primary bool) {
		if g == nil {
			return false, false
		}
		member = g.Members[a.Name]
		for _, ag := range a.GIDs {
			for _, gg := range g.GIDs {
				if ag == gg {
					primary = true
				}
			}
		}
		return member, primary
	}
	out := make([]invFindingResult, 0, len(accounts))
	for _, a := range accounts {
		set := map[string]bool{}
		if a.UID0 {
			set[model.PrivReasonUID0] = true
		}
		for _, name := range privGroups {
			member, primary := inGroup(a, groups[name])
			if member {
				set[model.PrivReasonGroup+":"+name] = true
			}
			if primary {
				set[model.PrivReasonGroupPrimary+":"+name] = true
			}
		}
		for _, g := range rules.Grants {
			hit := false
			switch g.Kind {
			case invGrantAll:
				if rules.TargetPW {
					set[model.PrivReasonSudoersAllTarget] = true
				} else {
					set[model.PrivReasonSudoersAll] = true
				}
				continue
			case invGrantUser:
				hit = g.Name == a.Name
			case invGrantGroup:
				m, p := inGroup(a, groups[g.Name])
				hit = m || p
			}
			if !hit {
				continue
			}
			switch {
			case g.Alias != "":
				set[model.PrivReasonSudoersAlias+":"+g.Alias] = true
			case g.Kind == invGrantGroup:
				set[model.PrivReasonSudoersGroup+":"+g.Name] = true
			default:
				set[model.PrivReasonSudoersUser] = true
			}
		}
		reasons := make([]string, 0, len(set))
		privileged := false
		for r := range set {
			reasons = append(reasons, r)
			if r != model.PrivReasonSudoersAllTarget {
				privileged = true
			}
		}
		sort.Strings(reasons)
		login := false
		for _, sh := range a.Shells {
			if shellLoginCapable(sh) {
				login = true
			}
		}
		out = append(out, invFindingResult{
			Username: a.Name, UID: a.UID, UIDConflict: a.UIDConflict,
			LoginCapable: login, Privileged: privileged, Incomplete: incomplete, Reasons: reasons,
		})
	}
	return out
}

// annotateEscalation 依提權讀取的結果補上主規則檔與規則目錄的原因：
// 經提權取得者記 via_escalation；原本讀不到、提權也被拒者記 escalation_denied。
func annotateEscalation(fr *invSudoFrames, main, dir *invCoverageItem) {
	switch {
	case fr.Escalated:
		main.Reason = invReasonViaEscalation
		switch {
		case dir.State == invStatePartial || dir.State == invStateUnreadable:
			dir.Reason = invReasonViaEscalation
		case dir.State == invStateChecked && dir.Reason == "":
			dir.Reason = invReasonViaEscalation
		}
		if fr.DirPartialUnknown && dir.Reason != invReasonNotIncluded {
			dir.State, dir.Reason, dir.Count = invStatePartial, invReasonViaEscalation, 0
		}
	case fr.EscDenied:
		if main.State == invStateUnreadable {
			main.Reason = invReasonEscalationDenied
		}
		if dir.State == invStateUnreadable || dir.State == invStatePartial {
			dir.Reason = invReasonEscalationDenied
		}
	}
}
