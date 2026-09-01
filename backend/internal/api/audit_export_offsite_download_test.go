package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/offsite"
)

// 證據包下載的離機退路。
//
// 情境是**容器重建**：產物目錄未掛 volume，job 列還在 DB、`expires_at` 尚未到，
// 但 zip 已隨容器消失。修法前這是一個 410——申請者在下載窗口內卻拿不到東西；
// 有離機副本時應取回並驗過後交付。

// jobRetriever 產物取回面的替身。
type jobRetriever struct {
	row       *model.OffsiteObject
	spoolPath string
	calls     int
	err       error
}

func (j *jobRetriever) Object(uint) (*model.OffsiteObject, error) { return j.row, nil }

func (j *jobRetriever) Fetch(context.Context, uint) (*offsite.FetchedObject, error) {
	j.calls++
	if j.err != nil {
		return nil, j.err
	}
	return &offsite.FetchedObject{Path: j.spoolPath, Size: j.row.Size,
		UploadedAt: time.Now(), Kind: offsite.KindExport, OwnerID: j.row.OwnerID}, nil
}

// wireJobOffsite 讓某個 job「已離機」，並可選擇刪掉本機產物。
func wireJobOffsite(t *testing.T, env *exportJobTestEnv, job *model.AuditExportJob,
	payload string, removeLocal bool) *jobRetriever {
	t.Helper()
	objID := uint(909)
	if err := env.db.Model(&model.AuditExportJob{}).Where("id = ?", job.ID).
		Updates(map[string]any{
			"offsite_object_id": objID,
			"offsite_status":    offsite.StateUploaded,
		}).Error; err != nil {
		t.Fatalf("寫入離機快取欄: %v", err)
	}
	spool := filepath.Join(t.TempDir(), "909.zip")
	if err := os.WriteFile(spool, []byte(payload), 0o600); err != nil {
		t.Fatalf("寫暫存檔: %v", err)
	}
	r := &jobRetriever{
		row: &model.OffsiteObject{ID: objID, Kind: offsite.KindExport, OwnerID: job.ID,
			State: offsite.StateUploaded, Size: int64(len(payload))},
		spoolPath: spool,
	}
	env.handler.SetOffsiteRetriever(r)
	if removeLocal {
		var reloaded model.AuditExportJob
		if err := env.db.First(&reloaded, job.ID).Error; err != nil {
			t.Fatalf("讀回 job: %v", err)
		}
		if err := os.Remove(reloaded.ArtifactPath); err != nil {
			t.Fatalf("刪本機產物: %v", err)
		}
	}
	return r
}

// TestDownloadFallsBackToOffsiteWhenArtifactGone 容器重建情境：本機產物不在、
// 窗口未過、帳冊有副本 → 本人下載得到**驗過的**離機副本，位元組一致。
func TestDownloadFallsBackToOffsiteWhenArtifactGone(t *testing.T) {
	env := newExportJobTestEnv(t)
	job := env.seedDoneJob(t, 9, "ZIPBYTES")
	r := wireJobOffsite(t, env, job, "ZIPBYTES", true)

	w := env.do("GET", fmt.Sprintf("/api/v1/audit-export/jobs/%d/download", job.ID), "9", "auditor")
	if w.Code != http.StatusOK {
		t.Fatalf("本機產物消失但仍在下載窗口內時應以離機副本交付，實得 %d %s",
			w.Code, w.Body.String())
	}
	if w.Body.String() != "ZIPBYTES" {
		t.Fatalf("交付內容不符: %q", w.Body.String())
	}
	if r.calls != 1 {
		t.Fatalf("應實際走過離機取回一次，實得 %d", r.calls)
	}

	// 審計列沿現況含 sha256 與 size
	var rows []model.AuditLog
	if err := env.db.Where("resource = ? AND status = ?",
		string(model.ResourceAuditExport), string(model.StatusSuccess)).Find(&rows).Error; err != nil {
		t.Fatalf("查審計: %v", err)
	}
	found := false
	for _, row := range rows {
		if strings.Contains(row.ErrorMsg, "sha256=deadbeef") && strings.Contains(row.ErrorMsg, "size=8") {
			found = true
		}
	}
	if !found {
		t.Fatalf("離機來源的下載審計仍須含 sha256 與 size，實得 %+v", rows)
	}
}

// TestDownloadOtherAuditorStillDeniedWithOffsiteCopy 本人判準**零改動**：
// 離機副本的存在不得讓他帳號拿到任何東西，且回應與「不存在」逐位元組相同。
func TestDownloadOtherAuditorStillDeniedWithOffsiteCopy(t *testing.T) {
	env := newExportJobTestEnv(t)
	job := env.seedDoneJob(t, 9, "ZIPBYTES")
	r := wireJobOffsite(t, env, job, "ZIPBYTES", true)

	other := env.do("GET", fmt.Sprintf("/api/v1/audit-export/jobs/%d/download", job.ID), "8", "auditor")
	if other.Code != http.StatusForbidden {
		t.Fatalf("他帳號應 403，實得 %d %s", other.Code, other.Body.String())
	}
	ghost := env.do("GET", "/api/v1/audit-export/jobs/999999/download", "8", "auditor")
	if ghost.Code != other.Code || ghost.Body.String() != other.Body.String() {
		t.Fatalf("存在性可由回應分辨: exist=(%d,%q) ghost=(%d,%q)",
			other.Code, other.Body.String(), ghost.Code, ghost.Body.String())
	}
	if strings.Contains(other.Body.String(), "ZIPBYTES") {
		t.Fatal("拒絕回應洩出產物位元組")
	}
	if r.calls != 0 {
		t.Fatalf("非申請者不得觸發任何離機取回（那是一次可觀測的副作用），實得 %d 次", r.calls)
	}
}

// TestDownloadExpiredStillGoneWithOffsiteCopy 逾期仍 410——即使遠端物件仍在。
//
// 產品的下載窗口是 24 小時；遠端副本的角色是窗口內的耐久性與組織的證據寄存，
// 不是把窗口悄悄延長。
func TestDownloadExpiredStillGoneWithOffsiteCopy(t *testing.T) {
	env := newExportJobTestEnv(t)
	job := env.seedDoneJob(t, 9, "ZIPBYTES")
	r := wireJobOffsite(t, env, job, "ZIPBYTES", true)
	if err := env.db.Model(&model.AuditExportJob{}).Where("id = ?", job.ID).
		Update("expires_at", time.Now().Add(-time.Minute)).Error; err != nil {
		t.Fatalf("倒填過期: %v", err)
	}

	w := env.do("GET", fmt.Sprintf("/api/v1/audit-export/jobs/%d/download", job.ID), "9", "auditor")
	if w.Code != http.StatusGone || respCode(t, w) != "RULE_EXPORT_ARTIFACT_UNAVAILABLE" {
		t.Fatalf("逾期應維持 410，實得 %d %s", w.Code, w.Body.String())
	}
	if r.calls != 0 {
		t.Fatalf("逾期者不得觸發離機取回，實得 %d 次", r.calls)
	}
}

// TestDownloadRefusesTamperedOffsiteArtifact 取回被判不符：**本人亦被拒**且留痕。
func TestDownloadRefusesTamperedOffsiteArtifact(t *testing.T) {
	env := newExportJobTestEnv(t)
	job := env.seedDoneJob(t, 9, "ZIPBYTES")
	r := wireJobOffsite(t, env, job, "ZIPBYTES", true)
	r.err = offsite.ErrIntegrityMismatch

	w := env.do("GET", fmt.Sprintf("/api/v1/audit-export/jobs/%d/download", job.ID), "9", "auditor")
	if w.Code != http.StatusConflict {
		t.Fatalf("完整性不符應回 409，實得 %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "ZIPBYTES") {
		t.Fatal("拒絕交付時不得夾帶任何產物位元組")
	}
	var failures int64
	if err := env.db.Model(&model.AuditLog{}).
		Where("resource = ? AND status = ?", string(model.ResourceAuditExport),
			string(model.StatusFailure)).Count(&failures).Error; err != nil {
		t.Fatalf("查審計: %v", err)
	}
	if failures == 0 {
		t.Fatal("被拒的下載必須留痕")
	}
}

// TestDownloadUnaffectedWhenOffsiteNotWired 未組裝離機：本機產物在＝原路徑，
// 本機產物不在＝原本的失敗行為（**零改動**）。
func TestDownloadUnaffectedWhenOffsiteNotWired(t *testing.T) {
	env := newExportJobTestEnv(t)
	job := env.seedDoneJob(t, 9, "ZIPBYTES")

	w := env.do("GET", fmt.Sprintf("/api/v1/audit-export/jobs/%d/download", job.ID), "9", "auditor")
	if w.Code != http.StatusOK || w.Body.String() != "ZIPBYTES" {
		t.Fatalf("本機產物在時應原樣交付，實得 %d %q", w.Code, w.Body.String())
	}

	var reloaded model.AuditExportJob
	if err := env.db.First(&reloaded, job.ID).Error; err != nil {
		t.Fatalf("讀回 job: %v", err)
	}
	if err := os.Remove(reloaded.ArtifactPath); err != nil {
		t.Fatalf("刪產物: %v", err)
	}
	w2 := env.do("GET", fmt.Sprintf("/api/v1/audit-export/jobs/%d/download", job.ID), "9", "auditor")
	if w2.Code == http.StatusOK {
		t.Fatalf("未組裝離機且本機產物消失時不得交付任何內容，實得 %d %q",
			w2.Code, w2.Body.String())
	}
}

// listOneJob 取清單第一列的原始 map（DTO 投影本體，不經型別過濾）。
func listOneJob(t *testing.T, env *exportJobTestEnv) map[string]any {
	t.Helper()
	w := env.do("GET", "/api/v1/audit-export/jobs", "9", "auditor")
	if w.Code != http.StatusOK {
		t.Fatalf("清單: %d %s", w.Code, w.Body.String())
	}
	var body struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(body.Data) != 1 {
		t.Fatalf("預期單列，實得 %d", len(body.Data))
	}
	return body.Data[0]
}

// TestListJobsExposesOffsiteSHA256 下載中心的離機行要說得出「遠端那一份是什麼」
// （狀態行第三列「已離機保存 · <sha256 前 12>」）：uploaded 態的列帶帳冊
// 記下的整檔雜湊，且該值取自帳冊而非 job 自己的產物雜湊。
func TestListJobsExposesOffsiteSHA256(t *testing.T) {
	env := newExportJobTestEnv(t)
	job := env.seedDoneJob(t, 9, "ZIPBYTES")
	r := wireJobOffsite(t, env, job, "ZIPBYTES", false)
	ledgerSHA := strings.Repeat("b", 64)
	r.row.SHA256 = ledgerSHA

	row := listOneJob(t, env)
	if row["offsite_sha256"] != ledgerSHA {
		t.Fatalf("uploaded 態應輸出帳冊雜湊，實得 %v", row["offsite_sha256"])
	}
	if row["offsite_sha256"] == row["artifact_sha256"] {
		t.Fatal("離機雜湊被當成產物雜湊輸出：兩者來源不同，不得互相頂替")
	}
}

// TestListJobsOmitsOffsiteSHA256WhenNotUploaded 非 uploaded 態不輸出雜湊欄
// （那一行不帶雜湊，輸出了只會讓前端把舊值貼在別的狀態旁邊）。
func TestListJobsOmitsOffsiteSHA256WhenNotUploaded(t *testing.T) {
	env := newExportJobTestEnv(t)
	job := env.seedDoneJob(t, 9, "ZIPBYTES")
	r := wireJobOffsite(t, env, job, "ZIPBYTES", false)
	r.row.SHA256 = strings.Repeat("b", 64)
	if err := env.db.Model(&model.AuditExportJob{}).Where("id = ?", job.ID).
		Update("offsite_status", offsite.StatePending).Error; err != nil {
		t.Fatalf("改離機狀態: %v", err)
	}

	row := listOneJob(t, env)
	if _, ok := row["offsite_sha256"]; ok {
		t.Fatalf("非 uploaded 態不應輸出離機雜湊，實得 %v", row["offsite_sha256"])
	}
}

// TestListJobsOmitsOffsiteSHA256WhenNotWired 未組裝離機子系統時同樣不輸出
// （欄位缺席，不是空字串）。
func TestListJobsOmitsOffsiteSHA256WhenNotWired(t *testing.T) {
	env := newExportJobTestEnv(t)
	job := env.seedDoneJob(t, 9, "ZIPBYTES")
	if err := env.db.Model(&model.AuditExportJob{}).Where("id = ?", job.ID).
		Updates(map[string]any{"offsite_object_id": uint(909),
			"offsite_status": offsite.StateUploaded}).Error; err != nil {
		t.Fatalf("寫入離機快取欄: %v", err)
	}

	row := listOneJob(t, env)
	if _, ok := row["offsite_sha256"]; ok {
		t.Fatalf("未組裝離機時不應輸出離機雜湊，實得 %v", row["offsite_sha256"])
	}
}
