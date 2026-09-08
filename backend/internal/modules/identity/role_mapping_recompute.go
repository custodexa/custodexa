package identity

import (
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"github.com/go-ldap/ldap/v3"
	"gorm.io/gorm"
)

// 每次登入的角色映射重算。兩條登入途徑共用這一支。
//
// # 為什麼重算掛在登入而不是背景輪詢
//
// 外部來源不會通知本系統「某人被移出群組了」。要嘛定期回頭問（需要一個能列舉
// 全部使用者群組的高權限帳號，且撤權時效等於輪詢週期），要嘛在人出現的時候問
// 一次（他本來就要被認證，群組資料順著同一次搜尋或同一份權杖回來）。
// 後者的撤權時效是「下次登入與會話絕對壽命兩者取小」，寫進規格。
//
// # 失敗方向
//
// 三種缺席各有各的處置，混為一談就會選錯邊：
//
//	來源未設屬性名／宣告名且無啟用規則  完全短路——不開交易、不碰資料庫、不寫審計
//	來源未設但有啟用規則                不動角色列，寫一筆跳過事件（否則零命中無訊號）
//	已設定但讀不到（搜尋失敗、溢出）    保留既有映射列、不推進世代、寫跳過事件
//
// 「讀到了但是空的」不在上表——那是已知的空集合，該收回的角色要收回。
// 判準與各通道的判定形態見各自的觀測產生點。

// GroupObservationState 一次登入對「這個人屬於哪些群組」的觀測結果。
type GroupObservationState string

const (
	// GroupObservationUnconfigured 來源根本沒設定要從哪裡讀群組
	GroupObservationUnconfigured GroupObservationState = "unconfigured"
	// GroupObservationKnown 已取得群組集合（可以是空集合）
	GroupObservationKnown GroupObservationState = "known"
	// GroupObservationUnknown 設定了但這次讀不到（讀取失敗、型別不符、來源自陳不完整）
	GroupObservationUnknown GroupObservationState = "unknown"
)

// 映射事件的機器碼。放審計列的錯誤訊息欄——那個欄位隨外送轉發出門，
// 細節欄不會（轉發載體不含它），故可辨識性必須掛在會出門的那一欄。
const (
	// RoleMappingEventApplied 重算改變了有效角色集
	RoleMappingEventApplied = "role_mapping_applied"
	// RoleMappingSkipSourceAttrUnset 來源未設群組屬性名／宣告名，但有啟用中的規則
	RoleMappingSkipSourceAttrUnset = "role_mapping_source_attr_unset"
	// RoleMappingSkipGroupsUnknown 群組資料這次讀不到，既有映射保留
	RoleMappingSkipGroupsUnknown = "role_mapping_groups_unknown"
)

// GroupObservation 一次登入對某條途徑的群組觀測。
type GroupObservation struct {
	// Kind 途徑種類（model.RoleMappingChannelKind*）
	Kind string
	// SourceID 該途徑的來源列識別（目錄或提供者）
	SourceID uint
	// State 觀測結果三態
	State GroupObservationState
	// Groups 觀測到的群組原始值。**原樣保留**：比對規則各通道不同，
	// 在這裡先正規化等於在兩種比對規則之外再造一套
	Groups []string
	// HasActiveRules 本來源是否有啟用中的映射規則。
	// 只在 State 為 unconfigured 時被讀——用來分辨完全短路與留痕跳過
	HasActiveRules bool
}

// Channel 本次觀測所屬的通道值。
func (o GroupObservation) Channel() string {
	return model.RoleMappingChannel(o.Kind, o.SourceID)
}

// RoleMappingOutcome 一次重算的結果（供呼叫端決定要不要重載角色與記錄）。
type RoleMappingOutcome struct {
	// Skipped 非空時本次未重算，值為跳過的機器碼
	Skipped string
	// Added／Removed 有效角色集這次多了／少了哪些角色（角色名，已排序）
	Added   []string
	Removed []string
	// EpochBumped 是否推進了憑證世代（有列被移除才推進）
	EpochBumped bool
}

// Changed 有效角色集是否真的變動。
func (r RoleMappingOutcome) Changed() bool {
	return len(r.Added) > 0 || len(r.Removed) > 0
}

// roleMappingEligible 這個帳號吃不吃外部群組映射。
//
// **射程比 IsExternal 窄一階**：IsExternal 取三訊號的聯集，其中「供應來源不是
// 本地」單獨成立時代表的是混合帳號——由外部供應但仍保有本地密碼。那種帳號
// 經外部途徑拿到角色之後，改用本地密碼登入即永久保留（本地密碼路徑根本不經
// 外部來源，沒有任何一次重算會發生）。故混合帳號不吃映射，這條線必須自己劃：
// 綁定端點對目標帳號的型別零限制，不劃就會有人把本地帳號綁上外部身分之後，
// 靠一次外部登入取得管理員角色，再改用本地密碼把它留著。
func roleMappingEligible(u *model.User) bool {
	return u != nil && (u.IsLDAP || u.ExternalCredential)
}

// RecomputeMappedRoles 依本次觀測重算某條通道的映射角色。
//
// 寫入對象只有本次通道的映射列——其他通道的認定不動（見映射事實表的通道分域）。
// 重算與世代推進、審計留痕在同一個使用者級憑證鎖的交易內：停在「角色已改、
// 世代未推進」或「角色已改、沒留痕」的中間態，就是這個功能的漏洞原形。
//
// 呼叫端於本函式回傳後**必須重載使用者的角色集**：後續的多因子強制判定與
// 認證脈絡都讀同一個記憶體物件，不重載的話，這次被映射賦予管理員角色的人
// 不會被要求註冊第二因子，而被降權的人反而還會。
func RecomputeMappedRoles(db *gorm.DB, auditSink port.TxSink, user *model.User,
	obs GroupObservation) (RoleMappingOutcome, error) {
	if db == nil || user == nil || user.ID == 0 {
		return RoleMappingOutcome{}, nil
	}
	if _, _, err := model.ParseRoleMappingChannel(obs.Channel()); err != nil {
		return RoleMappingOutcome{}, err
	}
	// 混合帳號不吃映射（見 roleMappingEligible）
	if !roleMappingEligible(user) {
		return RoleMappingOutcome{}, nil
	}
	// 停用帳號不重算：這次登入嘗試終究會被拒，改寫它的角色列只是讓一個
	// 進不來的人的權限隨群組漂移，而管理員看到的是一筆沒有登入的角色變動
	if !user.Active {
		return RoleMappingOutcome{}, nil
	}

	switch obs.State {
	case GroupObservationUnconfigured:
		// 短路：不開交易、不寫審計；此前建快照時至多做過一次規則表計數。
		// 「未啟用映射的部署只多一次索引計數」這句話的實際內容就是這一行
		if !obs.HasActiveRules {
			return RoleMappingOutcome{}, nil
		}
		return skipRoleMapping(db, auditSink, user, obs, RoleMappingSkipSourceAttrUnset)
	case GroupObservationUnknown:
		return skipRoleMapping(db, auditSink, user, obs, RoleMappingSkipGroupsUnknown)
	}

	outcome := RoleMappingOutcome{}
	err := WithUserCredentialLock(db, user.ID, func(tx *gorm.DB) error {
		var lerr error
		outcome, lerr = applyRoleMappingLocked(tx, auditSink, user, obs)
		return lerr
	})
	if err != nil {
		return RoleMappingOutcome{}, err
	}
	return outcome, nil
}

// applyRoleMappingLocked 鎖內三步：比對規則 → 寫映射事實與角色列 → 有列被移除即推進世代。
func applyRoleMappingLocked(tx *gorm.DB, auditSink port.TxSink, user *model.User,
	obs GroupObservation) (RoleMappingOutcome, error) {
	rules, err := activeGroupRoleMappings(tx, obs.Kind, obs.SourceID)
	if err != nil {
		return RoleMappingOutcome{}, err
	}

	if err := storeGroupObservationSnapshot(tx, user.ID, obs); err != nil {
		return RoleMappingOutcome{}, err
	}

	matcher := groupMatcherFor(obs.Kind)
	matchedRoleIDs := make([]uint, 0, len(rules))
	matchedNames := map[uint]string{}
	hitGroups := map[string]struct{}{}
	seen := map[uint]struct{}{}
	var badRules []string
	for _, rule := range rules {
		hits, badRule := matcher(obs.Groups, rule.MatchValue)
		if badRule {
			badRules = append(badRules, rule.MatchValue)
		}
		if len(hits) == 0 {
			continue
		}
		for _, g := range hits {
			hitGroups[g] = struct{}{}
		}
		if _, dup := seen[rule.RoleID]; dup {
			continue
		}
		seen[rule.RoleID] = struct{}{}
		matchedRoleIDs = append(matchedRoleIDs, rule.RoleID)
		if rule.Role != nil {
			matchedNames[rule.RoleID] = rule.Role.Name
		}
	}

	// 壞掉的規則值每次重算留痕一次：它永遠不會命中，而管理者只會看到
	// 「規則列在頁上、狀態是啟用、沒有人拿到角色」
	if len(badRules) > 0 {
		log.Printf("[RoleMapping] 下列映射規則的群組值無法解析為辨識名稱，永遠不會命中: %q", badRules)
	}

	now := time.Now()
	var addedIDs []uint
	for _, roleID := range matchedRoleIDs {
		granted, err := GrantMappedRole(tx, user.ID, roleID, obs.Channel(), now)
		if err != nil {
			return RoleMappingOutcome{}, err
		}
		if granted {
			addedIDs = append(addedIDs, roleID)
		}
	}
	removedIDs, err := RevokeMappedRolesForChannel(tx, user.ID, obs.Channel(), matchedRoleIDs)
	if err != nil {
		return RoleMappingOutcome{}, err
	}

	outcome := RoleMappingOutcome{}
	if outcome.Added, err = roleNamesOf(tx, addedIDs, matchedNames); err != nil {
		return RoleMappingOutcome{}, err
	}
	if outcome.Removed, err = roleNamesOf(tx, removedIDs, matchedNames); err != nil {
		return RoleMappingOutcome{}, err
	}

	// **判準是「有列被移除」而不是「集合變了」**：純追加不撤走任何憑證已賦予的
	// 能力，推進世代只是把人無故踢下線；而角色從一個換成另一個時數量不變、
	// 確有撤除，不推進即漏撤
	if len(removedIDs) > 0 {
		if err := BumpCredentialEpoch(tx, user.ID, "role_mapping_recomputed"); err != nil {
			return RoleMappingOutcome{}, err
		}
		if _, err := RevokeAllRefreshTokens(tx, user.ID, model.RefreshRevokeCredentialEpoch); err != nil {
			return RoleMappingOutcome{}, fmt.Errorf("撤銷刷新憑證失敗: %w", err)
		}
		outcome.EpochBumped = true
	}

	// **無變動不寫列**：目錄使用者每天登入好幾次，每次都留一筆「什麼都沒變」
	// 會把真正的權限變動淹掉，而每日高危計數也會跟著虛高
	if !outcome.Changed() {
		return outcome, nil
	}
	if err := writeRoleMappingAudit(tx, auditSink, user, obs, RoleMappingEventApplied,
		map[string]any{
			"channel":       obs.Channel(),
			"matched_group": sortedGroupValues(hitGroups),
			"roles_added":   outcome.Added,
			"roles_removed": outcome.Removed,
			"epoch_bumped":  outcome.EpochBumped,
		}); err != nil {
		return RoleMappingOutcome{}, err
	}
	return outcome, nil
}

// storeGroupObservationSnapshot 存下本次觀測到的群組原始值與時間。
//
// **只在已知態寫**：未設定與未知都沒有可存的觀測，覆蓋上一次的值等於把
// 「上次成功讀到什麼」這個唯一的診斷線索抹掉，而那正是讀不到群組時最需要的東西。
//
// 快照是外部自報值：只供管理者回答「我在群組裡卻沒拿到角色」，
// 任何授權判定一律走映射事實表，不得讀這三欄。
// 與角色寫入同一交易——診斷資料與它描述的那次重算若能各自成立，
// 快照就會指向一次沒有發生的重算。
func storeGroupObservationSnapshot(tx *gorm.DB, userID uint, obs GroupObservation) error {
	if obs.State != GroupObservationKnown {
		return nil
	}
	groups := obs.Groups
	if groups == nil {
		// 空集合要存成 `[]` 而不是 null：兩者的意思分別是「讀到了，他不屬於
		// 任何群組」與「沒有觀測」，而前者正是撤權那一格要能被指認的證據
		groups = []string{}
	}
	payload, err := json.Marshal(groups)
	if err != nil {
		return fmt.Errorf("序列化群組觀測快照失敗: %w", err)
	}
	if err := tx.Model(&model.User{}).Where("id = ?", userID).Updates(map[string]any{
		"group_snapshot_channel": obs.Channel(),
		"group_snapshot_groups":  string(payload),
		"group_snapshot_at":      time.Now(),
	}).Error; err != nil {
		return fmt.Errorf("寫入群組觀測快照失敗: %w", err)
	}
	return nil
}

// skipRoleMapping 不動任何角色列，只留一筆可辨識的跳過事件。
//
// 沒有這一筆，「規則設好了但屬性名沒設」與「這次讀不到群組」兩種部署都會
// 永遠零命中而沒有任何訊號——管理者看到規則列在頁上、狀態是啟用，
// 卻沒有一個人拿到角色。
func skipRoleMapping(db *gorm.DB, auditSink port.TxSink, user *model.User,
	obs GroupObservation, code string) (RoleMappingOutcome, error) {
	err := db.Transaction(func(tx *gorm.DB) error {
		return writeRoleMappingAudit(tx, auditSink, user, obs, code, map[string]any{
			"channel": obs.Channel(),
		})
	})
	if err != nil {
		return RoleMappingOutcome{}, err
	}
	return RoleMappingOutcome{Skipped: code}, nil
}

// writeRoleMappingAudit 交易內寫一筆映射事件。
//
// **系統動作的既有形態**：來源位址記系統、使用者識別記**目標**而不是登入者
// 本人——真正的行為者是外部來源那一端的群組管理員，本系統看不到他。
// 稽核要追「誰動的」必須去對外部來源的變更記錄，文件寫明這一句。
//
// 機器碼放錯誤訊息欄：轉發載體含該欄、不含細節欄，可辨識性必須掛在會出門的
// 那一欄。審計寫入失敗即整筆回滾（角色變動與它的留痕同生共死）。
func writeRoleMappingAudit(tx *gorm.DB, auditSink port.TxSink, user *model.User,
	obs GroupObservation, code string, details map[string]any) error {
	payload, err := json.Marshal(details)
	if err != nil {
		return fmt.Errorf("序列化角色映射審計內容失敗: %w", err)
	}
	uid := user.ID
	if err := port.WriteInTx(auditSink, tx, port.AuditEvent{
		Action:     string(model.ActionUpdate),
		Resource:   string(model.ResourceUser),
		ResourceID: &uid,
		Status:     string(model.StatusSuccess),
		Actor:      gatewayapi.Actor{UserID: user.ID, Username: user.Username},
		Request:    gatewayapi.RequestMeta{ClientIP: "system", StatusCode: 200},
		ErrorMsg:   code,
		Details:    string(payload),
	}); err != nil {
		return fmt.Errorf("寫入角色映射審計失敗: %w", err)
	}
	return nil
}

// groupMatcherFor 通道種類對應的比對規則。
//
// 回傳命中的**群組原始值**而不是布林：審計要記「命中了哪些群組」，
// 而規則存的比對值與目錄實際回傳的字串可能只是等價、不是逐字相同。
// 第二個回傳值為真時代表這條規則的比對值本身無法解析——那是一條永遠不會
// 命中的規則，靜默忽略會讓管理者以為它在生效。
func groupMatcherFor(kind string) func(groups []string, matchValue string) (hits []string, badRule bool) {
	if kind == model.RoleMappingChannelKindDirectory {
		return matchDirectoryGroups
	}
	return matchLiteralGroups
}

// matchDirectoryGroups 目錄側：兩邊各自解析成辨識名稱結構後比對。
//
// 屬性型別的大小寫不影響、屬性值的大小寫影響、相對名稱前後的空白在解析階段
// 即被去除。**不折疊值的大小寫**：折疊過寬的失敗方向是誤配提權，而目錄伺服器
// 之所以能對值取寬，是因為它有 schema 知道每個屬性的比對規則；我們沒有。
func matchDirectoryGroups(groups []string, matchValue string) ([]string, bool) {
	want, err := ldap.ParseDN(strings.TrimSpace(matchValue))
	if err != nil {
		return nil, true
	}
	var hits []string
	for _, raw := range groups {
		got, perr := ldap.ParseDN(strings.TrimSpace(raw))
		if perr != nil {
			continue
		}
		if got.Equal(want) {
			hits = append(hits, raw)
		}
	}
	return hits, false
}

// matchLiteralGroups 逐字比對（身分提供者側）。
//
// 兩家提供者的官方文件對群組宣告值的比對規則皆查無明文，故取嚴。
// 逐字比對沒有「規則值本身壞掉」這回事，第二個回傳值恆為 false。
func matchLiteralGroups(groups []string, matchValue string) ([]string, bool) {
	var hits []string
	for _, raw := range groups {
		if raw == matchValue {
			hits = append(hits, raw)
		}
	}
	return hits, false
}

// roleNamesOf 取角色名（優先用規則預載的名稱，缺的才回查）。
func roleNamesOf(tx *gorm.DB, ids []uint, known map[uint]string) ([]string, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	names := make([]string, 0, len(ids))
	var missing []uint
	for _, id := range ids {
		if name, ok := known[id]; ok && name != "" {
			names = append(names, name)
			continue
		}
		missing = append(missing, id)
	}
	if len(missing) > 0 {
		var rows []model.Role
		if err := tx.Where("id IN ?", missing).Find(&rows).Error; err != nil {
			return nil, fmt.Errorf("查詢角色名稱失敗: %w", err)
		}
		for _, r := range rows {
			names = append(names, r.Name)
		}
	}
	sort.Strings(names)
	return names, nil
}

// sortedGroupValues 供審計輸出穩定排序。
func sortedGroupValues(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
