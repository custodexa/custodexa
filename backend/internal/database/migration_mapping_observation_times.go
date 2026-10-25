package database

import (
	"fmt"
	"time"

	"gorm.io/gorm"
)

// 逐（帳號，通道）最近已知群組觀測時間增量。
//
// 現行快照每個帳號只有一份（users.group_snapshot_channel／group_snapshot_at），
// 有界重新驗證需要「每條通道各自上次讀到群組是何時」，所以另開一張表。
//
// 回填的目的是讓有界重新驗證的時限「從升級起算」，避免升級本身造成意外收回：
// 凡持有映射支持（角色或使用者群組）的（帳號，通道），last_known_at 取「既有快照時間」
// （僅快照記的那個通道有）與「本次執行時刻」較晚者；快照記的通道若沒有映射支持，
// 仍照舊得到一列快照時間。沒有映射支持也沒有快照的（帳號，通道）不補列。
// 不改任何規則、支持或角色列。回填以 ON CONFLICT DO NOTHING 寫入，
// 重跑不會覆蓋已存在（含較新）的觀測。
//
// # Down 契約
//
// 不提供回滾：回退只走升級前備份。
func mappingObservationTimesDDL() []string {
	return []string{
		`CREATE TABLE user_channel_observations (user_id bigint NOT NULL, channel varchar(64) NOT NULL, last_known_at timestamptz NOT NULL, CONSTRAINT user_channel_observations_pkey PRIMARY KEY (user_id,channel))`,
		`ALTER TABLE user_channel_observations ADD CONSTRAINT fk_user_channel_observations_user FOREIGN KEY (user_id) REFERENCES users(id)`,
	}
}

// backfillChannelObservations 回填各（帳號，通道）的最近已知觀測時間；now 為升級時刻。回傳新增列數。
func backfillChannelObservations(db *gorm.DB, now time.Time) (int64, error) {
	// 時間參數在 PostgreSQL 需明確型別才能放進 UNION；SQLite 不可 CAST（會被截成數字）。
	ts := "?"
	if db.Dialector.Name() == "postgres" {
		ts = "CAST(? AS timestamptz)"
	}
	res := db.Exec(`INSERT INTO user_channel_observations (user_id, channel, last_known_at)
 SELECT c.user_id, c.channel, MAX(c.ts) FROM (
  SELECT s.user_id AS user_id, s.channel AS channel, `+ts+` AS ts FROM user_role_mapping_rule_supports s
  UNION ALL
  SELECT g.user_id, g.channel, `+ts+` FROM user_group_mapping_rule_supports g
  UNION ALL
  SELECT id, group_snapshot_channel, group_snapshot_at FROM users
   WHERE group_snapshot_channel IS NOT NULL AND group_snapshot_channel <> '' AND group_snapshot_at IS NOT NULL
 ) c JOIN users u ON u.id = c.user_id
 GROUP BY c.user_id, c.channel
 ON CONFLICT (user_id, channel) DO NOTHING`, now, now)
	if res.Error != nil {
		return 0, fmt.Errorf("回填通道觀測時間失敗: %w", res.Error)
	}
	return res.RowsAffected, nil
}

// BackfillChannelObservations 是回填的對外入口，供跨套件測試以指定的升級時刻重放同一段回填。
func BackfillChannelObservations(db *gorm.DB, now time.Time) (int64, error) {
	return backfillChannelObservations(db, now)
}

func applyMappingObservationTimes(db *gorm.DB) error {
	for _, stmt := range mappingObservationTimesDDL() {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("執行 mapping_observation_times DDL 失敗（%.80s…）: %w", stmt, err)
		}
	}
	_, err := backfillChannelObservations(db, time.Now().UTC())
	return err
}

// rollbackMappingObservationTimes 不提供回滾；見檔頭 Down 契約。
func rollbackMappingObservationTimes(_ *gorm.DB) error {
	return fmt.Errorf("mapping observation times are not rolled back; restore the pre-upgrade backup instead")
}
