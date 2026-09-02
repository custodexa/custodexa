package audit

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 證據包非同步匯出 job 的受理與查詢。
//
// 打包執行在 audit_export_job_worker.go；本檔只管 job 列的生命週期入口：
// 原子受理（額度＋去重＋建立同交易）、申請者本人的清單、下載目標解析。

// 額度與保留期常數。
//
//   - exportJobPerRequesterLimit：每申請者進行中（pending＋running）上限。
//     取 3——匯出是人工發起的調查動作，同一人同時排三個不同範圍已是重度使用；
//     更多通常是誤觸或腳本失控，收斂錯誤請其等待。
//   - exportJobGlobalLimit：全域進行中上限。取 10——單一 worker 序列打包
//     （實際同時打包數恆為 1），本上限管的是佇列深度：錄影本體可達 GB 級，
//     10 個佇列項已代表最壞情況下要序列處理很久，再收等於承諾做不到的交付。
//   - exportJobArtifactRetention：產物保留 24 小時（設計定值，尚未開放為 policy 鍵）。
//   - exportJobRecordRetention：終態（failed／expired）紀錄保留 30 天後清列。
//     取 30 天——job 列只是申請者的追蹤憑據，發起／下載／取消的證據義務由
//     audit_logs 永久承擔；30 天足以覆蓋「上個月那次匯出怎麼失敗的」的追查，
//     再長只是無界增長。
const (
	exportJobPerRequesterLimit = 3
	exportJobGlobalLimit       = 10
	exportJobArtifactRetention = 24 * time.Hour
	exportJobRecordRetention   = 30 * 24 * time.Hour
)

// 哨兵錯誤（handler 據此收斂 HTTP 機器碼）
var (
	// ErrExportJobLimitExceeded 每人或全域進行中上限已滿。兩種上限刻意共用
	// 一個哨兵：對申請者的可行動語義相同（稍後再試），拆開只是多洩系統負載細節
	ErrExportJobLimitExceeded = errors.New("匯出打包佇列已滿")
	// ErrExportJobNotFound job 不存在**或**不屬於該申請者（收斂，不區分——
	// 存在性細節不對外）
	ErrExportJobNotFound = errors.New("匯出 job 不存在或不屬於該申請者")
)

// DefaultExportArtifactDir 匯出產物暫存根的出廠預設（沿錄影目錄同級慣例）。
const DefaultExportArtifactDir = "/var/lib/custodexa/exports"

// ResolveExportArtifactDir 解析產物暫存根：顯式注入優先，其次 EXPORT_ARTIFACT_PATH，
// 最後出廠預設；回傳前 filepath.Clean（沿 recorder.ResolveBasePath 的收口理由——
// 寫入端與清理端必須拿到逐字相同的根）。
func ResolveExportArtifactDir(dir string) string {
	if dir == "" {
		dir = os.Getenv("EXPORT_ARTIFACT_PATH")
	}
	if dir == "" {
		dir = DefaultExportArtifactDir
	}
	return filepath.Clean(dir)
}

// AuditExportJobService job 列的受理與查詢
type AuditExportJobService struct {
	db *gorm.DB
}

// NewAuditExportJobService 建立服務
func NewAuditExportJobService(db *gorm.DB) *AuditExportJobService {
	return &AuditExportJobService{db: db}
}

// exportFilterSnapshot 序列化篩選快照（欄位序固定＝Go struct 宣告序，可作正規化基準）
func exportFilterSnapshot(filter *ExportFilter) (snapshot string, hash string, err error) {
	data, err := json.Marshal(filter)
	if err != nil {
		return "", "", fmt.Errorf("序列化篩選快照失敗: %w", err)
	}
	sum := sha256.Sum256(data)
	return string(data), fmt.Sprintf("%x", sum), nil
}

// ParseExportFilterSnapshot 反序列化篩選快照（worker 重建打包範圍）
func ParseExportFilterSnapshot(snapshot string) (*ExportFilter, error) {
	var f ExportFilter
	if err := json.Unmarshal([]byte(snapshot), &f); err != nil {
		return nil, fmt.Errorf("解析篩選快照失敗: %w", err)
	}
	return &f, nil
}

// CreateJob 原子受理：去重（僅 pending/running）→ 額度檢查 → 建立，全程單一交易。
//
// 回傳 (job, created)：created=false 代表命中去重、回既有 job——重複發起是
// 冪等而非錯誤（同一人同一範圍的第二次點擊要的就是那一個包）。
// failed 與 done 均不參與去重：failed 不得阻擋重新發起，done 舊包不得冒充
// 新申請（錯置時點）。
//
// **上限檢查與建立必須原子**（並行發起不得同時穿透）：postgres 以
// SHARE ROW EXCLUSIVE 表鎖序列化受理交易（自斥、擋並行寫、不擋讀；受理是
// 人工低頻動作，鎖窗極短）；sqlite（單元測試）本身單寫者，交易即序列化。
// 資料庫層另有 pending/running 部分唯一索引兜底（見 migration）。
func (s *AuditExportJobService) CreateJob(requesterID uint, requesterName string,
	filter *ExportFilter) (*model.AuditExportJob, bool, error) {
	snapshot, hash, err := exportFilterSnapshot(filter)
	if err != nil {
		return nil, false, err
	}

	var job *model.AuditExportJob
	created := false
	err = s.db.Transaction(func(tx *gorm.DB) error {
		if tx.Dialector.Name() == "postgres" {
			if err := tx.Exec(`LOCK TABLE audit_export_jobs IN SHARE ROW EXCLUSIVE MODE`).Error; err != nil {
				return fmt.Errorf("受理鎖取得失敗: %w", err)
			}
		}

		// 去重：同申請者、同篩選、pending/running
		var existing model.AuditExportJob
		findErr := tx.Where("kind = ? AND requester_id = ? AND filter_hash = ? AND status IN ?",
			model.ExportJobKindEvidenceBundle, requesterID, hash,
			[]string{model.ExportJobPending, model.ExportJobRunning}).
			First(&existing).Error
		if findErr == nil {
			job = &existing
			return nil
		}
		if !errors.Is(findErr, gorm.ErrRecordNotFound) {
			return fmt.Errorf("去重查詢失敗: %w", findErr)
		}

		// 額度：每申請者與全域的進行中數
		var mine, global int64
		active := []string{model.ExportJobPending, model.ExportJobRunning}
		if err := tx.Model(&model.AuditExportJob{}).
			Where("requester_id = ? AND status IN ?", requesterID, active).Count(&mine).Error; err != nil {
			return fmt.Errorf("進行中計數失敗: %w", err)
		}
		if mine >= exportJobPerRequesterLimit {
			return ErrExportJobLimitExceeded
		}
		if err := tx.Model(&model.AuditExportJob{}).
			Where("status IN ?", active).Count(&global).Error; err != nil {
			return fmt.Errorf("全域計數失敗: %w", err)
		}
		if global >= exportJobGlobalLimit {
			return ErrExportJobLimitExceeded
		}

		now := time.Now()
		j := &model.AuditExportJob{
			RequesterID:   requesterID,
			RequesterName: requesterName,
			Kind:          model.ExportJobKindEvidenceBundle,
			FilterJSON:    snapshot,
			FilterHash:    hash,
			Status:        model.ExportJobPending,
			RequestedAt:   now,
		}
		if err := tx.Create(j).Error; err != nil {
			return fmt.Errorf("建立匯出 job 失敗: %w", err)
		}
		job = j
		created = true
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	return job, created, nil
}

// ReportJobGuard 報告工作單受理時的額外約束，於受理交易內對「同種類進行中的
// 工作單」施加。inflight 為該種類目前 pending＋running 的全部工作單。
//
// **判準留在發起方**：進行中上限對報告是「同一排程至多一張」，而排程的識別在
// 工作單的篩選快照裡，那是發起方的格式。回非 nil 即拒絕受理（錯誤原樣上拋）。
type ReportJobGuard func(inflight []model.AuditExportJob) error

// CreateReportJob 報告類工作單的受理（種類非 evidence_bundle）。
//
// 與 CreateJob 的三處差異，都源於「報告是共用產物、且可能由系統發起」：
//   - 去重鍵＝種類＋篩選快照，**不含申請者**：同一份報告已在排隊時，另一個人
//     再按一次要拿到的就是那一張。
//   - 每申請者上限只對人類申請者施加（RequesterID 非 0）；排程發起沒有配額可扣，
//     它的節流是 guard 給的「同一排程至多一張」。全域上限一律施加。
//   - dedupeKey 為去重用的正規化篩選字串（空＝以 filterJSON 為準）：發起者名稱
//     一類「不影響產物內容」的欄位留在 filterJSON、不進去重鍵，兩個人同時要
//     同一份報告時拿到的才會是同一張工作單。
//   - expiresAt 為**預定**到期時刻（以發起時刻為基準），worker 打包完成時以
//     「預定到期 − 發起時刻」的長度自實際打包時刻重新起算；nil＝沿既有保留期。
func (s *AuditExportJobService) CreateReportJob(kind, filterJSON, dedupeKey, requesterName string,
	requesterID uint, expiresAt *time.Time, guard ReportJobGuard) (*model.AuditExportJob, bool, error) {
	if kind == "" || kind == model.ExportJobKindEvidenceBundle {
		return nil, false, fmt.Errorf("報告工作單的種類不得為 %q", kind)
	}
	if dedupeKey == "" {
		dedupeKey = filterJSON
	}
	sum := sha256.Sum256([]byte(dedupeKey))
	hash := fmt.Sprintf("%x", sum)

	var job *model.AuditExportJob
	created := false
	err := s.db.Transaction(func(tx *gorm.DB) error {
		if tx.Dialector.Name() == "postgres" {
			if err := tx.Exec(`LOCK TABLE audit_export_jobs IN SHARE ROW EXCLUSIVE MODE`).Error; err != nil {
				return fmt.Errorf("受理鎖取得失敗: %w", err)
			}
		}
		active := []string{model.ExportJobPending, model.ExportJobRunning}

		var inflight []model.AuditExportJob
		if err := tx.Where("kind = ? AND status IN ?", kind, active).
			Order("id ASC").Find(&inflight).Error; err != nil {
			return fmt.Errorf("進行中工作單查詢失敗: %w", err)
		}
		for i := range inflight {
			if inflight[i].FilterHash == hash {
				job = &inflight[i]
				return nil
			}
		}
		if guard != nil {
			if err := guard(inflight); err != nil {
				return err
			}
		}

		if requesterID != 0 {
			var mine int64
			if err := tx.Model(&model.AuditExportJob{}).
				Where("requester_id = ? AND status IN ?", requesterID, active).
				Count(&mine).Error; err != nil {
				return fmt.Errorf("進行中計數失敗: %w", err)
			}
			if mine >= exportJobPerRequesterLimit {
				return ErrExportJobLimitExceeded
			}
		}
		var global int64
		if err := tx.Model(&model.AuditExportJob{}).
			Where("status IN ?", active).Count(&global).Error; err != nil {
			return fmt.Errorf("全域計數失敗: %w", err)
		}
		if global >= exportJobGlobalLimit {
			return ErrExportJobLimitExceeded
		}

		now := time.Now()
		j := &model.AuditExportJob{
			RequesterID:   requesterID,
			RequesterName: requesterName,
			Kind:          kind,
			FilterJSON:    filterJSON,
			FilterHash:    hash,
			Status:        model.ExportJobPending,
			RequestedAt:   now,
			ExpiresAt:     expiresAt,
		}
		if err := tx.Create(j).Error; err != nil {
			return fmt.Errorf("建立報告工作單失敗: %w", err)
		}
		job = j
		created = true
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	return job, created, nil
}

// List 下載中心的清單查詢：種類分支決定要不要綁申請者。
//
// `evidence_bundle`（含缺省）維持「只列本人」——證據包含解密後的錄影與剪貼簿
// 明文，清單範圍與下載授權同判準。`rotation_report` 不加申請者條件：報告是共用
// 產物（無秘密材料），排程產出的那些根本沒有人類申請者，綁本人等於誰都看不到。
//
// id 降冪（穩定排序：id 唯一單調）。page 自 1 起；pageSize 收斂於 [1,100]，預設 20。
func (s *AuditExportJobService) List(requesterID uint, kind string, page, pageSize int) ([]model.AuditExportJob, int64, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	if kind == "" {
		kind = model.ExportJobKindEvidenceBundle
	}
	q := s.db.Model(&model.AuditExportJob{}).Where("kind = ?", kind)
	if bindsRequester(kind) {
		q = q.Where("requester_id = ?", requesterID)
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("job 清單計數失敗: %w", err)
	}
	var jobs []model.AuditExportJob
	if err := q.Order("id DESC").Offset((page - 1) * pageSize).Limit(pageSize).Find(&jobs).Error; err != nil {
		return nil, 0, fmt.Errorf("job 清單查詢失敗: %w", err)
	}
	return jobs, total, nil
}

// bindsRequester 該種類的清單與下載是否綁申請者本人。
//
// **白名單反向寫**：只有明列為共用的種類才放寬，其餘（含未知值）一律綁本人。
// 新增一個種類而忘了想清楚授權，落點是「較嚴」那一邊。
func bindsRequester(kind string) bool {
	return kind != model.ExportJobKindRotationReport
}

// GetForDownload 下載目標解析：種類決定是否要求申請者本人。
//
// 證據包：以 (jobID, requesterID) 單一受權查詢，不存在與非申請者收斂為同一個
// ErrExportJobNotFound——存在性細節不對外。
// 輪替報告：只以 jobID 取件（呼叫端的稽核檢視權限閘已是全部的授權判準）。
func (s *AuditExportJobService) GetForDownload(jobID, requesterID uint) (*model.AuditExportJob, error) {
	var job model.AuditExportJob
	if err := s.db.Where("id = ?", jobID).First(&job).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrExportJobNotFound
		}
		return nil, fmt.Errorf("查詢匯出 job 失敗: %w", err)
	}
	if bindsRequester(job.Kind) && job.RequesterID != requesterID {
		return nil, ErrExportJobNotFound
	}
	return &job, nil
}

// DisplayMap 篩選條件的顯示投影（與 manifest 的 filter 段同一字串化規則，
// 下載中心據此呈現範圍摘要——兩處各寫一份遲早漂移）
func (f *ExportFilter) DisplayMap() map[string]string {
	return filterToMap(f)
}
