package asset

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

// 產物包的配置與清單檔。
//
// 兩件事在這裡被釘住：清單檔**最後寫入**（中斷的包沒有清單檔，依既有判準即
// 不完整），以及清單檔記的每檔 SHA-256 真的是那個檔的雜湊——一份對不上的
// 保管鏈比沒有保管鏈更糟，因為它看起來是有的。

// fixtureJobID 打包 fixture 用的工作單識別碼（頁尾與清單檔都應帶著它）。
const fixtureJobID uint = 4242

// stubSigner 簽章替身：回可辨識的固定字串，供「簽章檔存在且對應清單檔」的斷言。
type stubSigner struct{ signed [][]byte }

func (s *stubSigner) Sign(data []byte) string {
	s.signed = append(s.signed, append([]byte(nil), data...))
	return "stub-signature"
}

// packagerFixture 以既有的報告 fixture 產一份六桶俱全的報告，再打包。
func packagerFixture(t *testing.T, signer *stubSigner) ([]byte, ReportJobFilter) {
	t.Helper()
	f := newReportFixture(t)
	f.global = 90
	asOf := mustTime(t, "2026-09-02T00:00:00Z")
	a := f.asset(t, "核心系統-01")
	ok := f.account(t, a.ID, "compliant")
	f.success(t, ok, asOf.Add(-10*24*time.Hour))
	over := f.account(t, a.ID, "overdue")
	f.success(t, over, asOf.Add(-120*24*time.Hour))
	require.NoError(t, f.db.Create(&model.ChangeSecretRecord{
		PlanID: 1, AssetID: a.ID, AccountID: over.ID, AccountUsername: "overdue",
		SecretType: model.ChangeSecretTypePassword, Status: model.ChangeSecretFailed,
		Error: "remote_exit_nonzero", ExecutedAt: asOf.Add(-2 * 24 * time.Hour),
	}).Error)

	filter := ReportJobFilter{
		ScopeKind:    model.RotationScopeAll,
		PeriodStart:  asOf.Add(-30 * 24 * time.Hour),
		PeriodEnd:    asOf,
		Language:     model.NotificationChannelLanguageZhTW,
		ScheduleID:   3,
		ScheduleName: "月報",
		GeneratedBy:  "月報",
	}
	filterJSON, err := filter.Marshal()
	require.NoError(t, err)

	var sig ManifestSignerForTest = signer
	packager := NewRotationReportPackager(f.builder, sig, "9.9.9")
	require.Equal(t, model.ExportJobKindRotationReport, packager.Kind())

	var buf bytes.Buffer
	manifest, err := packager.Package(&buf, filterJSON, asOf.Add(-time.Hour), fixtureJobID)
	require.NoError(t, err)
	require.NotNil(t, manifest)
	return buf.Bytes(), filter
}

func TestRotationReportPackagerZipLayout(t *testing.T) {
	signer := &stubSigner{}
	raw, _ := packagerFixture(t, signer)

	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	require.NoError(t, err)

	names := make([]string, 0, len(zr.File))
	bodies := map[string][]byte{}
	for _, f := range zr.File {
		names = append(names, f.Name)
		rc, err := f.Open()
		require.NoError(t, err)
		body, err := io.ReadAll(rc)
		require.NoError(t, rc.Close())
		require.NoError(t, err)
		bodies[f.Name] = body
	}

	assert.Equal(t, []string{"report.pdf", "accounts.csv", "records.csv",
		"manifest.json", "manifest.sig"}, names,
		"產物須為五個檔，且清單檔最後寫入（簽章檔緊隨其後）")

	var manifest struct {
		Files []struct {
			Name   string `json:"name"`
			Size   int64  `json:"size"`
			SHA256 string `json:"sha256"`
		} `json:"files"`
	}
	require.NoError(t, json.Unmarshal(bodies["manifest.json"], &manifest))
	require.Len(t, manifest.Files, 3)
	for _, entry := range manifest.Files {
		body, ok := bodies[entry.Name]
		require.True(t, ok, "清單檔列了包內不存在的檔 %s", entry.Name)
		assert.Equal(t, int64(len(body)), entry.Size, "%s 的大小對不上", entry.Name)
		assert.Equal(t, fmt.Sprintf("%x", sha256.Sum256(body)), entry.SHA256,
			"%s 的 SHA-256 對不上——保管鏈失效", entry.Name)
	}

	require.Len(t, signer.signed, 1, "清單檔應被簽一次")
	assert.Equal(t, bodies["manifest.json"], signer.signed[0],
		"簽章對象必須逐位元組等於包內的 manifest.json")
	assert.Equal(t, "stub-signature", string(bodies["manifest.sig"]))
	assert.True(t, bytes.HasPrefix(bodies["report.pdf"], []byte("%PDF")))
}

func TestRotationReportPackagerManifestFields(t *testing.T) {
	signer := &stubSigner{}
	raw, filter := packagerFixture(t, signer)

	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	require.NoError(t, err)
	var manifestRaw []byte
	for _, f := range zr.File {
		if f.Name != "manifest.json" {
			continue
		}
		rc, err := f.Open()
		require.NoError(t, err)
		manifestRaw, err = io.ReadAll(rc)
		require.NoError(t, err)
		require.NoError(t, rc.Close())
	}
	require.NotEmpty(t, manifestRaw)

	var m map[string]any
	require.NoError(t, json.Unmarshal(manifestRaw, &m))

	assert.Equal(t, model.ExportJobKindRotationReport, m["kind"], "清單檔須自述工作單種類")
	assert.Equal(t, "月報", m["exported_by"])
	assert.Equal(t, true, m["signed"])
	assert.NotEmpty(t, m["job_requested_at"], "發起時刻與打包時刻須並列")
	assert.NotEmpty(t, m["exported_at"])

	fm, ok := m["filter"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, model.RotationScopeAll, fm["scope_kind"])
	assert.Equal(t, filter.PeriodStart.Format(time.RFC3339), fm["period_start"])
	assert.Equal(t, filter.PeriodEnd.Format(time.RFC3339), fm["period_end"])
	assert.Equal(t, filter.PeriodEnd.Format(time.RFC3339), fm["as_of"],
		"截止時點取區間結尾：同一組參數必須算出同一份報告")
	assert.Equal(t, "月報", fm["schedule_name"])

	counts, ok := m["counts"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, float64(2), counts["accounts"])
	assert.Equal(t, float64(2), counts["records"], "區間內兩筆：成功一筆、失敗一筆")

	trunc, ok := m["truncated"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, false, trunc["accounts"])
	assert.Equal(t, false, trunc["records"])

	// 未截斷即無機器碼鍵：「沒有這個問題」與「有但值為零」不該長得一樣
	if codes, ok := m["note_codes"].(map[string]any); ok {
		assert.Empty(t, codes)
	}

	// 清單檔不得挾帶任何憑證欄位
	for _, forbidden := range []string{"password", "password_enc", "private_key", "credential_group"} {
		assert.NotContains(t, string(manifestRaw), forbidden)
	}
}

// ManifestSignerForTest 與 audit.ManifestSigner 同形；測試以它避免 import 迴圈
// 之外的耦合，實際注入仍是同一個介面值。
type ManifestSignerForTest interface {
	Sign(data []byte) string
}

// TestRotationReportAppendixAOmitsFourColumns 附表 A 是帳號 CSV 的**子集**：
// 少的正好是位址、協定、天數來源、最近記錄狀態四欄，其餘欄位與欄序逐欄相同。
// 反向也釘住——CSV 不得因此少欄（它是超集，稽核要逐欄核對時看的是它）。
func TestRotationReportAppendixAOmitsFourColumns(t *testing.T) {
	require.Len(t, appendixAColumns, len(appendixAWidths), "欄索引與欄寬必須等長")

	kept := map[string]bool{}
	prev := -1
	for _, idx := range appendixAColumns {
		require.Greater(t, idx, prev, "欄索引須遞增，否則附表的欄序與 CSV 不同")
		prev = idx
		kept[accountColumnKeys[idx]] = true
	}
	for _, dropped := range []string{"col_address", "col_protocol", "col_max_age_source", "col_last_status"} {
		assert.False(t, kept[dropped], "附表 A 不應含 %s", dropped)
		assert.Contains(t, accountColumnKeys, dropped, "帳號 CSV 仍須保留 %s（它是超集）", dropped)
	}
	assert.Len(t, accountColumnKeys, len(appendixAColumns)+4,
		"CSV 與附表 A 的欄數差必須恰好是被投影掉的四欄")
}

// TestRotationReportPackagerCarriesJobID 產物本體帶得走工作單識別碼。
//
// 檔名裡的 job id 一解包就消失；頁尾與清單檔是包內僅有的兩個可攜位置。
// 反向也釘住：頁尾不得再印排程名或產出者名——同一排程每期的封面逐字相同，
// 收包方拿到兩份紙本只能靠時刻猜是哪一張工作單。
func TestRotationReportPackagerCarriesJobID(t *testing.T) {
	signer := &stubSigner{}
	raw, filter := packagerFixture(t, signer)

	ref := reportRef(fixtureJobID)
	assert.Equal(t, "job-4242", ref, "頁尾的報告識別須為 job-<id>")
	assert.NotEqual(t, filter.ScheduleName, ref, "排程名不是識別")
	assert.NotEqual(t, filter.GeneratedBy, ref, "產出者名不是識別")

	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	require.NoError(t, err)
	var manifestRaw []byte
	for _, f := range zr.File {
		if f.Name != "manifest.json" {
			continue
		}
		rc, err := f.Open()
		require.NoError(t, err)
		manifestRaw, err = io.ReadAll(rc)
		require.NoError(t, err)
		require.NoError(t, rc.Close())
	}
	require.NotEmpty(t, manifestRaw)

	var m map[string]any
	require.NoError(t, json.Unmarshal(manifestRaw, &m))
	assert.Equal(t, float64(fixtureJobID), m["job_id"], "清單檔須帶工作單識別碼")
}
