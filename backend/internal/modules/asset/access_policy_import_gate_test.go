package asset

import (
	"context"
	"errors"
	"testing"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
)

func apCapCtx(manage bool) context.Context {
	return WithFieldCapability(adminCtx(), func(field string) FieldCapGrant {
		if manage && field == "access_policy" {
			return FieldCapViaPerm
		}
		return FieldCapDenied
	})
}

// TestAccessPolicyImportGate 匯入預檢與正式匯入的存取政策欄位條件：任一列帶非空值而無權限點即整批拒絕。
func TestAccessPolicyImportGate(t *testing.T) {
	batch := func(policies ...string) *ImportBatch {
		rows := make([]ImportRow, len(policies))
		for i, p := range policies {
			rows[i] = ImportRow{Name: "imp-" + string(rune('a'+i)), Protocol: "ssh", Host: "10.8.0." + string(rune('1'+i)), AccessPolicy: p}
		}
		return &ImportBatch{Source: ImportSourceForm, Rows: rows}
	}
	assetCount := func(t *testing.T, env *AssetService) int64 {
		var n int64
		if err := database.DB.Model(&model.Asset{}).Count(&n).Error; err != nil {
			t.Fatal(err)
		}
		return n
	}

	t.Run("無權限點：任一列帶非空值，預檢與正式匯入皆整批拒絕、資產數不變", func(t *testing.T) {
		setupAccountDB(t)
		assets, _ := newAccountServices(t)
		before := assetCount(t, assets)
		for _, b := range []*ImportBatch{batch("", "open"), batch("approval"), batch("  reason  ", "")} {
			if _, err := assets.PreviewImport(apCapCtx(false), b); !errors.Is(err, ErrFieldCapabilityDenied) {
				t.Errorf("預檢應回欄位能力拒絕，實得 %v", err)
			}
			if _, err := assets.ImportAssets(apCapCtx(false), b, 1, "admin"); !errors.Is(err, ErrFieldCapabilityDenied) {
				t.Errorf("正式匯入應回欄位能力拒絕，實得 %v", err)
			}
		}
		if got := assetCount(t, assets); got != before {
			t.Fatalf("資產數應不變：前 %d 後 %d", before, got)
		}
	})

	t.Run("無權限點：全部列該欄皆空（含空白）不受影響", func(t *testing.T) {
		setupAccountDB(t)
		assets, _ := newAccountServices(t)
		b := batch("", "   ")
		if _, err := assets.PreviewImport(apCapCtx(false), b); err != nil {
			t.Fatalf("預檢: %v", err)
		}
		if _, err := assets.ImportAssets(apCapCtx(false), b, 1, "admin"); err != nil {
			t.Fatalf("匯入: %v", err)
		}
		if got := assetCount(t, assets); got != 2 {
			t.Fatalf("應建立 2 台，實得 %d", got)
		}
	})

	t.Run("持權限點：整批成功並寫入覆寫值", func(t *testing.T) {
		db := setupAccountDB(t)
		assets, _ := newAccountServices(t)
		b := batch("open", "approval", "")
		if _, err := assets.PreviewImport(apCapCtx(true), b); err != nil {
			t.Fatalf("預檢: %v", err)
		}
		if _, err := assets.ImportAssets(apCapCtx(true), b, 1, "admin"); err != nil {
			t.Fatalf("匯入: %v", err)
		}
		var rows []model.Asset
		db.Order("id").Find(&rows)
		if len(rows) != 3 || rows[0].AccessPolicy == nil || *rows[0].AccessPolicy != "open" ||
			rows[1].AccessPolicy == nil || *rows[1].AccessPolicy != "approval" || rows[2].AccessPolicy != nil {
			t.Fatalf("覆寫值不符：%+v", rows)
		}
	})
}
