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
		findErr := tx.Where("requester_id = ? AND filter_hash = ? AND status IN ?",
			requesterID, hash, []string{model.ExportJobPending, model.ExportJobRunning}).
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

// ListByRequester 申請者本人的 job 清單，id 降冪（穩定排序：id 唯一單調）。
// page 自 1 起；pageSize 收斂於 [1,100]，預設 20。
func (s *AuditExportJobService) ListByRequester(requesterID uint, page, pageSize int) ([]model.AuditExportJob, int64, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	q := s.db.Model(&model.AuditExportJob{}).Where("requester_id = ?", requesterID)
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

// GetForRequester 以 (jobID, requesterID) 單一受權查詢取 job：
// 不存在與非申請者收斂為同一個 ErrExportJobNotFound——存在性細節不對外
// （audit-detail-not-outward；與剪貼簿單筆調閱的跨會話約束同形）。
func (s *AuditExportJobService) GetForRequester(jobID, requesterID uint) (*model.AuditExportJob, error) {
	var job model.AuditExportJob
	if err := s.db.Where("id = ? AND requester_id = ?", jobID, requesterID).First(&job).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrExportJobNotFound
		}
		return nil, fmt.Errorf("查詢匯出 job 失敗: %w", err)
	}
	return &job, nil
}

// DisplayMap 篩選條件的顯示投影（與 manifest 的 filter 段同一字串化規則，
// 下載中心據此呈現範圍摘要——兩處各寫一份遲早漂移）
func (f *ExportFilter) DisplayMap() map[string]string {
	return filterToMap(f)
}
