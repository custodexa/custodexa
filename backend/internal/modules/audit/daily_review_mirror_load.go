package audit

import (
	"strings"
	"time"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 鏡像列配對的三次讀取：當日候選鏡像列、當日候選帶路徑列（建帳號的兩條路徑另取
// 請求內容），以及配對鍵需要的資產軟刪時刻與帳號名（皆含軟刪列）。兩次主查詢都走
// 當日的時間區間，掃描範圍與計數查詢相同。

func loadMirrorRows(db *gorm.DB, start, end time.Time) ([]mirrorRow, error) {
	var cases, ors []string
	var caseArgs, orArgs []any
	for _, sh := range mirrorShapes {
		cases = append(cases, "WHEN ("+sh.where+") THEN '"+sh.name+"'")
		caseArgs = append(caseArgs, sh.args...)
		ors = append(ors, "("+sh.where+")")
		orArgs = append(orArgs, sh.args...)
	}
	var rows []mirrorRow
	err := highRiskBaseScope(db, start, end).
		Where("COALESCE(path, '') = ''").
		Where(strings.Join(ors, " OR "), orArgs...).
		Select("id, created_at, user_id, action, resource_id, status, COALESCE(details, '') AS details, "+
			"CASE "+strings.Join(cases, " ")+" END AS shape", caseArgs...).
		Scan(&rows).Error
	return rows, err
}

func loadPathRows(db *gorm.DB, start, end time.Time) ([]pathRow, error) {
	var rows []pathRow
	if err := highRiskBaseScope(db, start, end).
		Where("COALESCE(path, '') <> ''").
		Select("id, created_at, duration, user_id, action, resource_id, status, path, "+
			"CASE WHEN "+likeHas()+" THEN 1 ELSE 0 END AS oidc_provisioned", likeArg(eventOIDCProvisioned)).
		Scan(&rows).Error; err != nil {
		return nil, err
	}
	var bodyIDs []uint
	for _, p := range rows {
		if p.Action == string(model.ActionCreate) && (p.Path == pathCreateUser || p.Path == pathCreateMyAgent) {
			bodyIDs = append(bodyIDs, p.ID)
		}
	}
	if len(bodyIDs) == 0 {
		return rows, nil
	}
	var bodies []struct {
		ID          uint
		RequestBody string
	}
	if err := db.Model(&model.AuditLog{}).Where("id IN ?", bodyIDs).
		Select("id, COALESCE(request_body, '') AS request_body").Scan(&bodies).Error; err != nil {
		return nil, err
	}
	byID := make(map[uint]string, len(bodies))
	for _, b := range bodies {
		byID[b.ID] = b.RequestBody
	}
	for i := range rows {
		rows[i].RequestBody = byID[rows[i].ID]
	}
	return rows, nil
}

func loadMirrorLookups(db *gorm.DB, mirrors []mirrorRow, paths []pathRow) (*mirrorLookups, error) {
	lk := &mirrorLookups{assetDeletedAt: map[uint]time.Time{}, usernames: map[uint]string{}}
	var assetIDs, userIDs []uint
	shapes := map[string]bool{}
	for _, m := range mirrors {
		shapes[m.Shape] = true
		if (m.Shape == "principal_state_create" || m.Shape == "agent_self_service") && m.ResourceID != nil {
			userIDs = append(userIDs, *m.ResourceID)
		}
	}
	if shapes["asset_delete_hook"] {
		for i := range paths {
			if ids, ok := pathIDs(reAssetPath, &paths[i], model.ActionDelete); ok {
				assetIDs = append(assetIDs, ids[0])
			}
		}
	}
	if len(assetIDs) > 0 {
		var assets []struct {
			ID        uint
			DeletedAt *time.Time
		}
		if err := db.Unscoped().Model(&model.Asset{}).Where("id IN ?", assetIDs).
			Select("id, deleted_at").Scan(&assets).Error; err != nil {
			return nil, err
		}
		for _, a := range assets {
			if a.DeletedAt != nil {
				lk.assetDeletedAt[a.ID] = *a.DeletedAt
			}
		}
	}
	if len(userIDs) > 0 {
		var users []struct {
			ID       uint
			Username string
		}
		if err := db.Unscoped().Model(&model.User{}).Where("id IN ?", userIDs).
			Select("id, username").Scan(&users).Error; err != nil {
			return nil, err
		}
		for _, u := range users {
			lk.usernames[u.ID] = u.Username
		}
	}
	return lk, nil
}
