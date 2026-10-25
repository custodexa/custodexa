package database

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// 憑證背景工作授權增量。
//
// 結構：
//   - credential_job_authorizations：不可變的工作授權脈絡（發起者、權限世代、還原世代、能力清單、目標上界）。
//   - change_secret_plans／change_secret_batches／credential_rotations／change_secret_candidates
//     加授權引用；計畫另加授權狀態與修訂號；輪替成員加 dispatch claim 欄與逐台補跑的
//     重排紀錄欄（重排者、當時通過的權限世代與時刻；之後每次派送另以重排者重驗）；
//     候選與輪替成員加目標指紋欄（失權後的有限驗證據此確認目標未被改動）。
//
// # 資料步驟（升級前已啟用的排程計畫）
//
// 不全面暫停。對 enabled 且有 cron 的計畫，依序以既有審計列指認可歸屬者：
// 最後一次成功修改（PUT）的操作者，其次是建立時（POST，以請求內的計畫名比對）的操作者。
// 該使用者必須仍存在、啟用且為一般使用者，才回填為發起者（來源 audit_backfill），
// 之後照常以其當下權限重驗。完全查不到可歸屬者的計畫標 needs_reauthorization 而暫停，
// cron 與 enabled 設定保留，待超管明示重新授權。
// 候選、輪替、批次的舊列不動、不補任何主體。
//
// 資料步驟可重入：只處理尚無授權引用且狀態為空的計畫，重跑結果相同。
//
// # Down 契約
//
// 不提供回滾：授權脈絡屬於證據，回退只走升級前備份。
func credentialJobAuthorizationDDL() []string {
	return []string{
		`CREATE TABLE credential_job_authorizations (id bigserial, schema_version bigint DEFAULT 1 NOT NULL, source_kind character varying(16) NOT NULL, source_id bigint NOT NULL, revision bigint DEFAULT 1 NOT NULL, actor_id bigint NOT NULL, actor_kind character varying(16) DEFAULT 'human'::character varying NOT NULL, actor_name character varying(100) DEFAULT ''::character varying NOT NULL, auth_source character varying(24) NOT NULL, authz_version bigint DEFAULT 0 NOT NULL, permission_sources text DEFAULT '[]'::text NOT NULL, capabilities text DEFAULT '[]'::text NOT NULL, target_bound text DEFAULT '[]'::text NOT NULL, restore_generation character varying(64) DEFAULT ''::character varying NOT NULL, confirmed_at timestamp with time zone NOT NULL, created_at timestamp with time zone, CONSTRAINT credential_job_authorizations_pkey PRIMARY KEY (id), CONSTRAINT credential_job_authorizations_source_kind_check CHECK (source_kind IN ('plan','batch','rotation')))`,
		`CREATE INDEX idx_credential_job_authorizations_source ON credential_job_authorizations USING btree (source_kind, source_id)`,
		`ALTER TABLE change_secret_plans ADD COLUMN authorization_id bigint`,
		`ALTER TABLE change_secret_plans ADD COLUMN authorization_state character varying(24) DEFAULT ''::character varying NOT NULL`,
		`ALTER TABLE change_secret_plans ADD COLUMN revision bigint DEFAULT 1 NOT NULL`,
		`ALTER TABLE change_secret_batches ADD COLUMN authorization_id bigint`,
		`ALTER TABLE credential_rotations ADD COLUMN authorization_id bigint`,
		`ALTER TABLE change_secret_candidates ADD COLUMN authorization_id bigint`,
		`ALTER TABLE credential_rotation_members ADD COLUMN dispatch_claimed_at timestamp with time zone`,
		`ALTER TABLE credential_rotation_members ADD COLUMN dispatch_authz_version bigint DEFAULT 0 NOT NULL`,
		`ALTER TABLE credential_rotation_members ADD COLUMN requeued_by bigint DEFAULT 0 NOT NULL`,
		`ALTER TABLE credential_rotation_members ADD COLUMN requeued_by_name character varying(100) DEFAULT ''::character varying NOT NULL`,
		`ALTER TABLE credential_rotation_members ADD COLUMN requeued_authz_version bigint DEFAULT 0 NOT NULL`,
		`ALTER TABLE credential_rotation_members ADD COLUMN requeued_at timestamp with time zone`,
		`ALTER TABLE credential_rotation_members ADD COLUMN target_fingerprint character varying(64) DEFAULT ''::character varying NOT NULL`,
		`ALTER TABLE change_secret_candidates ADD COLUMN target_fingerprint character varying(64) DEFAULT ''::character varying NOT NULL`,
	}
}

// jobAuthSchemaVersion 授權列格式版本；讀到未知版本一律拒絕恢復。
const jobAuthSchemaVersion = 1

func applyCredentialJobAuthorization(db *gorm.DB) error {
	for _, stmt := range credentialJobAuthorizationDDL() {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("執行 credential_job_authorization DDL 失敗（%.80s…）: %w", stmt, err)
		}
	}
	return BackfillPlanInitiators(db)
}

// rollbackCredentialJobAuthorization 不提供回滾；見檔頭 Down 契約。
func rollbackCredentialJobAuthorization(_ *gorm.DB) error {
	return fmt.Errorf("credential job authorizations retain evidence; restore the pre-upgrade backup instead")
}

// PlanBackfillReport 資料步驟的結果摘要（供測試與營運檢查；不含任何秘密）。
type PlanBackfillReport struct {
	Backfilled []uint
	Paused     []uint
}

type backfillPlanRow struct {
	ID   uint
	Name string
}

// BackfillPlanInitiators 對升級前已啟用的排程計畫回填發起者（可重入）。
func BackfillPlanInitiators(db *gorm.DB) error {
	_, err := backfillPlanInitiators(db)
	return err
}

func backfillPlanInitiators(db *gorm.DB) (PlanBackfillReport, error) {
	var report PlanBackfillReport
	var plans []backfillPlanRow
	if err := db.Raw(`SELECT id, name FROM change_secret_plans
		WHERE enabled = true AND cron <> '' AND authorization_id IS NULL AND authorization_state = ''
		ORDER BY id`).Scan(&plans).Error; err != nil {
		return report, fmt.Errorf("讀取待回填計畫失敗: %w", err)
	}
	if len(plans) == 0 {
		return report, nil
	}
	var version int64
	_ = db.Raw(`SELECT COALESCE(MAX(version), 0) FROM authz_state`).Scan(&version).Error
	// 回填列記升級當下的還原世代：升級前已還原過的部署，其既有排程不因世代為空而全部停擺
	var restoreGen string
	_ = db.Raw(`SELECT COALESCE(MAX(restore_generation), '') FROM authz_state`).Scan(&restoreGen).Error
	for _, plan := range plans {
		actorID, actorName := attributablePlanActor(db, plan)
		err := db.Transaction(func(tx *gorm.DB) error {
			if actorID == 0 {
				return tx.Exec(`UPDATE change_secret_plans SET authorization_state = ? WHERE id = ? AND authorization_id IS NULL`,
					model.PlanAuthNeedsReauthorization, plan.ID).Error
			}
			row := model.CredentialJobAuthorization{
				SchemaVersion: jobAuthSchemaVersion, SourceKind: model.JobAuthSourcePlan, SourceID: plan.ID,
				Revision: 1, ActorID: actorID, ActorKind: "human", ActorName: actorName,
				AuthSource: model.JobAuthViaAuditBackfill, AuthzVersion: version,
				Capabilities: "[]", TargetBound: "[]", RestoreGeneration: restoreGen, ConfirmedAt: time.Now(), CreatedAt: time.Now(),
			}
			// 只寫本增量當下存在的欄：後續增量加的欄（計畫掛載上界）此時尚未建立，由其預設值補上
			if err := tx.Omit("TargetMountBound").Create(&row).Error; err != nil {
				return err
			}
			return tx.Exec(`UPDATE change_secret_plans SET authorization_id = ? WHERE id = ? AND authorization_id IS NULL`,
				row.ID, plan.ID).Error
		})
		if err != nil {
			return report, fmt.Errorf("回填計畫 %d 發起者失敗: %w", plan.ID, err)
		}
		if actorID == 0 {
			report.Paused = append(report.Paused, plan.ID)
		} else {
			report.Backfilled = append(report.Backfilled, plan.ID)
		}
	}
	return report, nil
}

// attributablePlanActor 由審計列指認計畫的最後修改者，其次建立者；查不到回 0。
func attributablePlanActor(db *gorm.DB, plan backfillPlanRow) (uint, string) {
	type auditRow struct {
		UserID      uint
		RequestBody string
	}
	// 最後修改者：路徑帶計畫 id 的 PUT，成功者，最新優先
	var puts []auditRow
	_ = db.Raw(`SELECT user_id, request_body FROM audit_logs
		WHERE resource = ? AND resource_id = ? AND method = 'PUT' AND status = ? AND user_id > 0
		  AND path LIKE '/api/v1/change-secret-plans/%'
		ORDER BY id DESC LIMIT 20`, string(model.ResourceChangeSecretPlan), plan.ID, string(model.StatusSuccess)).Scan(&puts).Error
	for _, r := range puts {
		if id, name := eligibleHuman(db, r.UserID); id != 0 {
			return id, name
		}
	}
	// 建立者：POST 無計畫 id，以請求內的計畫名比對
	var posts []auditRow
	_ = db.Raw(`SELECT user_id, request_body FROM audit_logs
		WHERE method = 'POST' AND status = ? AND user_id > 0 AND path = '/api/v1/change-secret-plans'
		ORDER BY id DESC LIMIT 500`, string(model.StatusSuccess)).Scan(&posts).Error
	for _, r := range posts {
		var body struct {
			Name string `json:"name"`
		}
		if json.Unmarshal([]byte(strings.TrimSpace(r.RequestBody)), &body) != nil || body.Name != plan.Name {
			continue
		}
		if id, name := eligibleHuman(db, r.UserID); id != 0 {
			return id, name
		}
	}
	return 0, ""
}

// eligibleHuman 使用者仍存在、啟用且為一般使用者才可作為回填的發起者。
func eligibleHuman(db *gorm.DB, userID uint) (uint, string) {
	var u struct {
		ID       uint
		Username string
		Kind     string
		Active   bool
	}
	if err := db.Raw(`SELECT id, username, kind, active FROM users WHERE id = ? AND deleted_at IS NULL`, userID).
		Scan(&u).Error; err != nil || u.ID == 0 || !u.Active || u.Kind != "human" {
		return 0, ""
	}
	return u.ID, u.Username
}
