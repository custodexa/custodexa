package audit

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 同一件事的第二列（鏡像列）：請求層為每個已認證請求寫一列帶路徑的紀錄，資料層或
// 服務層又為同一件事寫一列不帶路徑的紀錄。兩列都留在操作日誌，高危計數只算一列。
//
// 排除以逐筆配對成立為前提：同一所屬日、時間窗、狀態、形態各自的配對鍵相符，且
// 一對一。配不到（帶路徑列沒有落庫、請求內容被截斷、兩件事在時間上重疊）一律照算：
// 寧可同一件事算兩列，也不讓任何一件操作從清單消失。配對只在所屬日的區間內進行，
// 不讀其他日子的紀錄，所以跨午夜的請求兩天各算一次。
//
// 請求編號無法用來關聯兩列：只有拿得到請求脈絡的寫入點會帶它，鏡像列的寫入點都
// 在服務層或資料層。日後兩列都帶請求編號時，改以編號相等取代時間窗與一對一，並
// 遞增 HighRiskCriteriaVersion。

// mirrorExclusionCap 單日逐筆排除的上限；超過時不排除（寧可多算）。變數而非常數，
// 只為讓測試以小值驗證超限分支
var mirrorExclusionCap = 10000

const (
	// mirrorWindowSlack 時間窗兩端的放寬：耗時以毫秒捨去，組列與取時刻之間也有微秒落差
	mirrorWindowSlack = time.Second
	// mirrorHandlerWindow 外部登入回呼的建帳號紀錄不記耗時，改用固定窗口
	mirrorHandlerWindow = 60 * time.Second
	// mirrorAssetDeleteGap 資產軟刪與刪除留痕在同一交易內先後執行的最大間隔
	mirrorAssetDeleteGap = time.Second
)

// 帶路徑列的路徑樣式（請求路徑，不含查詢字串）
var (
	reAssetPath        = regexp.MustCompile(`^/api/v1/assets/(\d+)$`)
	reUserPath         = regexp.MustCompile(`^/api/v1/users/(\d+)$`)
	reAssetAccountPath = regexp.MustCompile(`^/api/v1/assets/(\d+)/accounts/(\d+)$`)
	reAssetGroupPath   = regexp.MustCompile(`^/api/v1/asset-groups/(\d+)$`)
	reCredentialPath   = regexp.MustCompile(`^/api/v1/credentials/(\d+)$`)
	reUserGroupPath    = regexp.MustCompile(`^/api/v1/user-groups/(\d+)$`)
	reRoleRulePath     = regexp.MustCompile(`^/api/v1/identity-sources/[^/]+/(\d+)/(?:mappings|role-mappings)/(\d+)$`)
	reGroupRulePath    = regexp.MustCompile(`^/api/v1/identity-sources/[^/]+/(\d+)/user-group-mappings/(\d+)$`)
	reExternalIDPath   = regexp.MustCompile(`^/api/v1/users/(\d+)/(?:external-identities(?:/\d+(?:/unbind-and-disable)?)?|external-only)$`)
	reBreakerPath      = regexp.MustCompile(`^/api/v1/users/(\d+)/agent-breaker/release$`)
)

const (
	pathCreateUser    = "/api/v1/users"
	pathCreateMyAgent = "/api/v1/my/agents"
	pathLDAPDirectory = "/api/v1/ldap-directory"
	// eventOIDCProvisioned 外部登入首次建帳號時，回呼處理寫的帶路徑紀錄
	eventOIDCProvisioned = `"event":"oidc_user_provisioned"`
)

// mirrorRow 候選鏡像列
type mirrorRow struct {
	ID         uint
	CreatedAt  time.Time
	UserID     uint
	Action     string
	ResourceID *uint
	Status     string
	Details    string
	Shape      string
}

// pathRow 候選帶路徑列（RequestBody 只對建帳號的兩條路徑取）
type pathRow struct {
	ID              uint
	CreatedAt       time.Time
	Duration        int
	UserID          uint
	Action          string
	ResourceID      *uint
	Status          string
	Path            string
	OIDCProvisioned int `gorm:"column:oidc_provisioned"`
	RequestBody     string
}

// mirrorLookups 配對鍵需要的外部對照（皆含軟刪列）
type mirrorLookups struct {
	assetDeletedAt map[uint]time.Time
	usernames      map[uint]string
}

// mirrorShape 一種鏡像形態：形態辨識（SQL，另含路徑為空）與配對鍵（共同條件之外）
type mirrorShape struct {
	name  string
	where string
	args  []any
	pair  func(m *mirrorRow, p *pathRow, lk *mirrorLookups) bool
}

// likeHas 細節欄「含有」某個片段（不依賴鍵序；萬用字元已跳脫）
func likeHas() string { return "COALESCE(details, '') LIKE ? ESCAPE '!'" }

func likeArg(fragment string) string {
	r := strings.NewReplacer("!", "!!", "%", "!%", "_", "!_")
	return "%" + r.Replace(fragment) + "%"
}

const principalStateFragment = `"state_table":"` + StateTablePrincipals + `"`

// mirrorShapes 已知的鏡像形態。寫入點各自不帶路徑；人為操作的列帶真實帳號與細節，
// 另有路徑為空的條件，請求層的列不可能命中。辨識錯了的結果是配不到、照算
var mirrorShapes = []mirrorShape{
	{name: "asset_delete_hook", // 資產刪除的資料層留痕：交易不帶脈絡，帳號退回系統
		where: "action = ? AND resource = ? AND user_id = 0 AND username = ? AND COALESCE(details, '') = ''",
		args:  []any{model.ActionDelete, model.ResourceAsset, "system"},
		pair: func(m *mirrorRow, p *pathRow, lk *mirrorLookups) bool {
			ids, ok := pathIDs(reAssetPath, p, model.ActionDelete)
			if !ok {
				return false
			}
			// 鏡像列的帳號與對象編號都不可用；以路徑上那台資產的軟刪時刻對上
			deletedAt, found := lk.assetDeletedAt[ids[0]]
			gap := m.CreatedAt.Sub(deletedAt)
			return found && gap >= 0 && gap <= mirrorAssetDeleteGap
		}},
	{name: "principal_state_change", // 帳號狀態投影（修改、刪除）
		where: "resource = ? AND action IN ? AND user_id = 0 AND username = ? AND " + likeHas(),
		args:  []any{model.ResourceUser, []model.AuditAction{model.ActionUpdate, model.ActionDelete}, "system", likeArg(principalStateFragment)},
		pair: func(m *mirrorRow, p *pathRow, _ *mirrorLookups) bool {
			ids, ok := pathIDs(reUserPath, p, model.AuditAction(m.Action))
			return ok && sameID(m.ResourceID, ids[0])
		}},
	{name: "principal_state_create", // 帳號狀態投影（建立）
		where: "action = ? AND resource = ? AND user_id = 0 AND username = ? AND " + likeHas(),
		args:  []any{model.ActionCreate, model.ResourceUser, "system", likeArg(principalStateFragment)},
		pair: func(m *mirrorRow, p *pathRow, lk *mirrorLookups) bool {
			if p.Action != string(model.ActionCreate) {
				return false
			}
			if p.OIDCProvisioned != 0 {
				return m.ResourceID != nil && sameID(p.ResourceID, *m.ResourceID)
			}
			if p.Path != pathCreateUser && p.Path != pathCreateMyAgent {
				return false
			}
			return requestNamesTarget(m, p, lk)
		}},
	{name: "asset_account_delete",
		where: "action = ? AND resource = ? AND " + likeHas() + " AND " + likeHas(),
		args:  []any{model.ActionDelete, model.ResourceAsset, likeArg(`"resource":"asset_account"`), likeArg(`"operation":"delete"`)},
		pair: func(m *mirrorRow, p *pathRow, _ *mirrorLookups) bool {
			ids, ok := pathIDs(reAssetAccountPath, p, model.ActionDelete)
			return ok && sameID(m.ResourceID, ids[0]) && m.UserID == p.UserID && detailUint(m.Details, "account_id") == ids[1]
		}},
	{name: "asset_group_delete",
		where: "action = ? AND resource = ? AND " + likeHas(),
		args:  []any{model.ActionDelete, model.ResourceAsset, likeArg(`"asset_node_name":`)},
		pair:  sameTargetAndActor(reAssetGroupPath),
	},
	{name: "credential_delete",
		where: "action = ? AND resource = ? AND " + likeHas(),
		args:  []any{model.ActionDelete, model.ResourceCredential, likeArg(`"operation":"delete"`)},
		pair:  sameTargetAndActor(reCredentialPath),
	},
	{name: "user_group_delete",
		where: "action = ? AND resource = ? AND " + likeHas(),
		args:  []any{model.ActionDelete, model.ResourceUserGroup, likeArg(`"group_name":`)},
		pair:  sameTargetAndActor(reUserGroupPath),
	},
	{name: "role_mapping_rule_delete",
		where: "action = ? AND resource = ? AND " + likeHas(),
		args:  []any{model.ActionDelete, model.ResourceAuth, likeArg(`"event":"group_role_mapping_delete"`)},
		pair:  sameRuleAndSource(reRoleRulePath),
	},
	{name: "group_mapping_rule_delete",
		where: "action = ? AND resource = ? AND COALESCE(error_msg, '') = ?",
		args:  []any{model.ActionDelete, model.ResourceUserGroup, "group_user_group_mapping_delete"},
		pair:  sameRuleAndSource(reGroupRulePath),
	},
	{name: "ldap_directory_delete", // 單例設定，路徑沒有編號，只靠時間窗與一對一
		where: "action = ? AND resource = ? AND " + likeHas(),
		args:  []any{model.ActionDelete, model.ResourceAuth, likeArg(`"event":"ldap_directory_delete"`)},
		pair: func(m *mirrorRow, p *pathRow, _ *mirrorLookups) bool {
			return p.Path == pathLDAPDirectory && p.Action == string(model.ActionDelete) && m.UserID == p.UserID
		}},
	{name: "external_identity", // 綁定、解綁、改為僅外部登入；兩列的動作可能不同，不比
		where: "resource = ? AND " + likeHas(),
		args:  []any{model.ResourceUser, likeArg(`"target_user_id":`)},
		pair: func(m *mirrorRow, p *pathRow, _ *mirrorLookups) bool {
			ids, ok := pathIDs(reExternalIDPath, p, "")
			return ok && sameID(m.ResourceID, ids[0]) && m.UserID == p.UserID
		}},
	{name: "agent_breaker_release",
		where: "action = ? AND resource = ? AND " + likeHas(),
		args:  []any{model.ActionUpdate, model.ResourceUser, likeArg(`"event":"agent_breaker_released"`)},
		pair: func(m *mirrorRow, p *pathRow, _ *mirrorLookups) bool {
			ids, ok := pathIDs(reBreakerPath, p, "")
			return ok && sameID(m.ResourceID, ids[0]) && m.UserID == p.UserID
		}},
	{name: "agent_self_service",
		where: "action = ? AND resource = ? AND " + likeHas(),
		args:  []any{model.ActionCreate, model.ResourceUser, likeArg(`"self_service":true`)},
		pair: func(m *mirrorRow, p *pathRow, lk *mirrorLookups) bool {
			return p.Path == pathCreateMyAgent && p.Action == string(model.ActionCreate) &&
				m.UserID == p.UserID && requestNamesTarget(m, p, lk)
		}},
}

// sameTargetAndActor 刪除類：路徑上的對象編號等於鏡像列的對象編號，操作者相同
func sameTargetAndActor(re *regexp.Regexp) func(*mirrorRow, *pathRow, *mirrorLookups) bool {
	return func(m *mirrorRow, p *pathRow, _ *mirrorLookups) bool {
		ids, ok := pathIDs(re, p, model.ActionDelete)
		return ok && sameID(m.ResourceID, ids[0]) && m.UserID == p.UserID
	}
}

// sameRuleAndSource 映射規則刪除：路徑的規則編號等於鏡像列的對象編號、來源編號
// 等於細節的 source_id，操作者相同（路由沒有 :id，帶路徑列的對象編號為空）
func sameRuleAndSource(re *regexp.Regexp) func(*mirrorRow, *pathRow, *mirrorLookups) bool {
	return func(m *mirrorRow, p *pathRow, _ *mirrorLookups) bool {
		ids, ok := pathIDs(re, p, model.ActionDelete)
		return ok && sameID(m.ResourceID, ids[1]) && detailUint(m.Details, "source_id") == ids[0] && m.UserID == p.UserID
	}
}

// pathIDs 路徑符合樣式時回傳路徑上的編號；action 非空時另要求動作相同
func pathIDs(re *regexp.Regexp, p *pathRow, action model.AuditAction) ([]uint, bool) {
	if action != "" && p.Action != string(action) {
		return nil, false
	}
	sub := re.FindStringSubmatch(p.Path)
	if sub == nil {
		return nil, false
	}
	ids := make([]uint, 0, len(sub)-1)
	for _, s := range sub[1:] {
		n, err := strconv.ParseUint(s, 10, 64)
		if err != nil || n == 0 {
			return nil, false
		}
		ids = append(ids, uint(n))
	}
	return ids, true
}

func sameID(p *uint, id uint) bool { return p != nil && *p == id && id != 0 }

// detailUint 細節欄中的正整數；取不到回 0（0 不會等於任何路徑編號）
func detailUint(details, key string) uint {
	dec := json.NewDecoder(bytes.NewReader([]byte(details)))
	dec.UseNumber()
	var m map[string]any
	if dec.Decode(&m) != nil {
		return 0
	}
	n, ok := m[key].(json.Number)
	if !ok {
		return 0
	}
	v, err := strconv.ParseUint(n.String(), 10, 64)
	if err != nil {
		return 0
	}
	return uint(v)
}

// requestNamesTarget 建帳號請求內容的帳號名（去除前後空白）等於鏡像列對象的帳號名。
// 內容被截斷或標為讀取失敗時取不到，回 false（照算）
func requestNamesTarget(m *mirrorRow, p *pathRow, lk *mirrorLookups) bool {
	if m.ResourceID == nil {
		return false
	}
	var body struct {
		Username *string `json:"username"`
	}
	if json.Unmarshal([]byte(p.RequestBody), &body) != nil || body.Username == nil {
		return false
	}
	name := strings.TrimSpace(*body.Username)
	stored, ok := lk.usernames[*m.ResourceID]
	return ok && name != "" && name == stored
}

// inMirrorWindow 鏡像列在請求處理期間寫入：落在 [帶路徑列時刻 − 耗時, 帶路徑列時刻]，
// 兩端各放寬 mirrorWindowSlack；回呼處理的建帳號紀錄改用固定窗口
func inMirrorWindow(m *mirrorRow, p *pathRow) bool {
	lo := p.CreatedAt.Add(-time.Duration(p.Duration)*time.Millisecond - mirrorWindowSlack)
	if p.OIDCProvisioned != 0 {
		lo = p.CreatedAt.Add(-mirrorHandlerWindow)
	}
	hi := p.CreatedAt.Add(mirrorWindowSlack)
	return !m.CreatedAt.Before(lo) && !m.CreatedAt.After(hi)
}

// sameOutcome 成功只配成功；失敗或拒絕只配非成功
func sameOutcome(m *mirrorRow, p *pathRow) bool {
	ok := string(model.StatusSuccess)
	return (m.Status == ok) == (p.Status == ok)
}

// mirrorExclusions 當日配對成立、不計入高危的鏡像列編號
func mirrorExclusions(db *gorm.DB, start, end time.Time) ([]uint, error) {
	mirrors, err := loadMirrorRows(db, start, end)
	if err != nil || len(mirrors) == 0 {
		return nil, err
	}
	paths, err := loadPathRows(db, start, end)
	if err != nil || len(paths) == 0 {
		return nil, err
	}
	lk, err := loadMirrorLookups(db, mirrors, paths)
	if err != nil {
		return nil, err
	}
	return pairMirrors(mirrors, paths, lk), nil
}

// pairMirrors 同一形態下一對一：鏡像列恰有一筆候選帶路徑列，那筆帶路徑列也恰有
// 這一筆候選鏡像列，才排除。不同形態可以配到同一筆帶路徑列（一個請求寫多種留痕）
func pairMirrors(mirrors []mirrorRow, paths []pathRow, lk *mirrorLookups) []uint {
	var out []uint
	for _, sh := range mirrorShapes {
		cands := map[uint][]uint{}
		load := map[uint]int{}
		var members []*mirrorRow
		for i := range mirrors {
			m := &mirrors[i]
			if m.Shape != sh.name {
				continue
			}
			members = append(members, m)
			for j := range paths {
				p := &paths[j]
				if !inMirrorWindow(m, p) || !sameOutcome(m, p) || !sh.pair(m, p, lk) {
					continue
				}
				cands[m.ID] = append(cands[m.ID], p.ID)
				load[p.ID]++
			}
		}
		for _, m := range members {
			if c := cands[m.ID]; len(c) == 1 && load[c[0]] == 1 {
				out = append(out, m.ID)
			}
		}
	}
	return out
}
