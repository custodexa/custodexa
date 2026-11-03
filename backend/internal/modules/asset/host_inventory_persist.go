package asset

import (
	"encoding/json"
	"strconv"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
)

// 盤點結束交易：批次 upsert 結果、標示已不存在、自動重開、計數、告警與結束審計，任一失敗整筆回滾。

func reasonsJSON(rs []string) string {
	if len(rs) == 0 {
		return "[]"
	}
	b, _ := json.Marshal(rs)
	return string(b)
}

func parseReasons(s string) []string {
	var rs []string
	_ = json.Unmarshal([]byte(s), &rs)
	return rs
}

// reasonsGained 判定 now 是否含 before 沒有的理由。
func reasonsGained(before, now []string) bool {
	had := make(map[string]bool, len(before))
	for _, r := range before {
		had[r] = true
	}
	for _, r := range now {
		if !had[r] {
			return true
		}
	}
	return false
}

// managedUsernames 該資產當下已納管（有同名資產帳號）的帳號名。
func managedUsernames(tx *gorm.DB, assetID uint) (map[string]bool, error) {
	var names []string
	if err := tx.Model(&model.AssetAccount{}).Where("asset_id = ?", assetID).Pluck("username", &names).Error; err != nil {
		return nil, err
	}
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m, nil
}

// inventoryRoutineReasonSets 系統預設帳號的特權理由組合（與落庫的 JSON 字串逐字相同，已排序）：
// 只有「主要群組為 root」，可另帶不單獨構成特權的要求目標密碼全員規則。
var inventoryRoutineReasonSets = []string{
	reasonsJSON([]string{model.PrivReasonGroupPrimary + ":root"}),
	reasonsJSON([]string{model.PrivReasonGroupPrimary + ":root", model.PrivReasonSudoersAllTarget}),
}

// inventoryRoutineSystemAccount 不可登入、且唯一的特權理由是主要群組為 root 的帳號（發行版預設的
// halt、shutdown、sync 等）：仍列為特權帳號，但不列入待處理、不計入未納管特權數。
func inventoryRoutineSystemAccount(loginCapable bool, reasonsJSONText string) bool {
	if loginCapable {
		return false
	}
	for _, s := range inventoryRoutineReasonSets {
		if reasonsJSONText == s {
			return true
		}
	}
	return false
}

func inventoryAlertEligible(f *model.HostAccountFinding, managed map[string]bool) bool {
	return f.Status == model.HostAccountFindingOpen && f.Privileged && f.Present && f.LoginCapable && !managed[f.Username]
}

// finishSucceeded 寫入一次成功或部分完成的盤點。
func (s *HostAccountInventoryService) finishSucceeded(scan *model.HostAccountScan, res *invScanResult) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		now := time.Now()
		var existing []model.HostAccountFinding
		if err := tx.Where("asset_id = ?", scan.AssetID).Find(&existing).Error; err != nil {
			return err
		}
		byName := make(map[string]*model.HostAccountFinding, len(existing))
		for i := range existing {
			byName[existing[i].Username] = &existing[i]
		}
		managed, err := managedUsernames(tx, scan.AssetID)
		if err != nil {
			return err
		}
		seen := make(map[string]bool, len(res.Findings))
		rows := make([]model.HostAccountFinding, 0, len(res.Findings))
		reopened, privTotal, unmanagedPriv, newAlerts := 0, 0, 0, 0
		for _, f := range res.Findings {
			seen[f.Username] = true
			reasons := reasonsJSON(f.Reasons)
			row := model.HostAccountFinding{
				AssetID: scan.AssetID, Username: f.Username, UID: f.UID, UIDConflict: f.UIDConflict,
				LoginCapable: f.LoginCapable, Privileged: f.Privileged, Incomplete: f.Incomplete, Present: true,
				PrivilegedReasons: reasons, Status: model.HostAccountFindingOpen, IgnoredReasons: "[]",
				FirstSeenScanID: scan.ID, LastSeenScanID: scan.ID, FirstSeenAt: now, LastSeenAt: now,
			}
			if old := byName[f.Username]; old != nil {
				row.FirstSeenScanID, row.FirstSeenAt, row.Alerted = old.FirstSeenScanID, old.FirstSeenAt, old.Alerted
				row.Status, row.IgnoreReason, row.IgnoredBy, row.IgnoredByName = old.Status, old.IgnoreReason, old.IgnoredBy, old.IgnoredByName
				row.IgnoredAt, row.IgnoredReasons = old.IgnoredAt, old.IgnoredReasons
				if old.Status == model.HostAccountFindingIgnored &&
					(!old.Present || reasonsGained(parseReasons(old.IgnoredReasons), f.Reasons)) {
					row.Status = model.HostAccountFindingOpen
					reopened++
				}
			}
			if row.Privileged {
				privTotal++
				if !managed[row.Username] && !inventoryRoutineSystemAccount(row.LoginCapable, row.PrivilegedReasons) {
					unmanagedPriv++
				}
			}
			eligible := inventoryAlertEligible(&row, managed)
			switch {
			case eligible && !row.Alerted:
				row.Alerted = true
				newAlerts++
			case !eligible:
				row.Alerted = false
			}
			rows = append(rows, row)
		}
		if len(rows) > 0 {
			if err := tx.Clauses(clause.OnConflict{
				Columns: []clause.Column{{Name: "asset_id"}, {Name: "username"}},
				DoUpdates: clause.AssignmentColumns([]string{
					"uid", "uid_conflict", "login_capable", "privileged", "incomplete", "present", "privileged_reasons",
					"status", "ignore_reason", "ignored_by", "ignored_by_name", "ignored_at", "ignored_reasons",
					"alerted", "last_seen_scan_id", "last_seen_at",
				}),
			}).CreateInBatches(&rows, inventoryUpsertBatch).Error; err != nil {
				return err
			}
		}
		var gone []uint
		for i := range existing {
			if existing[i].Present && !seen[existing[i].Username] {
				gone = append(gone, existing[i].ID)
			}
		}
		for start := 0; start < len(gone); start += inventoryUpsertBatch {
			end := min(start+inventoryUpsertBatch, len(gone))
			if err := tx.Model(&model.HostAccountFinding{}).Where("id IN ?", gone[start:end]).
				Updates(map[string]any{"present": false, "alerted": false}).Error; err != nil {
				return err
			}
		}
		cov, err := json.Marshal(res.Coverage)
		if err != nil {
			return err
		}
		upd := tx.Model(&model.HostAccountScan{}).Where("id = ? AND status = ?", scan.ID, model.HostAccountScanRunning).
			Updates(map[string]any{
				"status": res.Status, "failure_reason": "", "finished_at": now, "coverage": string(cov),
				"accounts_total": len(rows), "privileged_total": privTotal,
				"unmanaged_privileged_total": unmanagedPriv, "reopened_total": reopened,
			})
		if upd.Error != nil {
			return upd.Error
		}
		if upd.RowsAffected == 0 {
			return errInventoryScanNotRunning
		}
		scan.Status, scan.FinishedAt, scan.Coverage = res.Status, &now, string(cov)
		scan.AccountsTotal, scan.PrivilegedTotal, scan.UnmanagedPrivilegedTotal, scan.ReopenedTotal = len(rows), privTotal, unmanagedPriv, reopened
		if newAlerts > 0 {
			assetID := scan.AssetID
			if _, err := port.RaiseInTx(s.alerts, tx, port.SystemAlertEvent{
				Type:          port.SystemAlertUnmanagedPrivilegedAccount,
				Actor:         port.SystemAlertActor{UserID: scan.InitiatedBy, Username: scan.InitiatedByName},
				OccurredAt:    now,
				Target:        port.SystemAlertTarget{Kind: port.SystemAlertTargetAsset, ID: strconv.FormatUint(uint64(assetID), 10)},
				AssetID:       &assetID,
				CorrelationID: "inventory:" + strconv.FormatUint(uint64(scan.ID), 10),
				Params:        map[string]string{"new_count": strconv.Itoa(newAlerts), "identity_mode": scan.IdentityMode},
			}); err != nil {
				return err
			}
		}
		return s.writeDoneAudit(tx, scan, res.Coverage, res.Escalation)
	})
}
