package asset

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/stretchr/testify/require"
)

func fieldCapCreateReq(name string) *CreateAssetRequest {
	return &CreateAssetRequest{
		Name: name, Protocol: model.ProtocolSSH, Host: "10.7.0.1", Port: 22,
		Username: "ops", Password: "pw-1", CreatedBy: 1,
	}
}

// 欄位級能力缺判定即拒絕；內部作業以明確標記通過；綁入判定時照常判定。
func TestFieldCapabilityFailClosed(t *testing.T) {
	t.Run("未綁判定也無內部標記：帶受限欄位的建立被拒且零寫入", func(t *testing.T) {
		db := setupAccountDB(t)
		assets, _ := newAccountServices(t)
		_, err := assets.Create(adminCtx(), fieldCapCreateReq("no-binding"))
		require.True(t, errors.Is(err, ErrFieldCapabilityDenied), "got %v", err)
		var n int64
		require.NoError(t, db.Model(&model.Asset{}).Where("name = ?", "no-binding").Count(&n).Error)
		require.Zero(t, n)
	})

	t.Run("未綁判定：不帶受限欄位的建立不受影響", func(t *testing.T) {
		setupAccountDB(t)
		assets, _ := newAccountServices(t)
		req := fieldCapCreateReq("no-restricted")
		req.Username, req.Password = "", ""
		_, err := assets.Create(adminCtx(), req)
		require.NoError(t, err)
	})

	t.Run("未綁判定：更新受限欄位被拒", func(t *testing.T) {
		setupAccountDB(t)
		assets, _ := newAccountServices(t)
		a := mustCreateAsset(t, assets, "upd-target", "10.7.0.2")
		pw := "new-pw"
		_, err := assets.Update(adminCtx(), a.ID, &UpdateAssetRequest{Password: &pw})
		require.True(t, errors.Is(err, ErrFieldCapabilityDenied), "got %v", err)
	})

	t.Run("帶內部標記：通過", func(t *testing.T) {
		setupAccountDB(t)
		assets, _ := newAccountServices(t)
		_, err := assets.Create(WithSystemCaller(adminCtx()), fieldCapCreateReq("system-caller"))
		require.NoError(t, err)
	})

	t.Run("綁入判定：依判定結果放行或拒絕", func(t *testing.T) {
		setupAccountDB(t)
		assets, _ := newAccountServices(t)
		deny := WithFieldCapability(adminCtx(), func(string) FieldCapGrant { return FieldCapDenied })
		_, err := assets.Create(deny, fieldCapCreateReq("bound-deny"))
		require.True(t, errors.Is(err, ErrFieldCapabilityDenied), "got %v", err)
		allow := WithFieldCapability(adminCtx(), func(string) FieldCapGrant { return FieldCapViaCompat })
		_, err = assets.Create(allow, fieldCapCreateReq("bound-allow"))
		require.NoError(t, err)
	})

	t.Run("綁入判定時內部標記不覆蓋判定", func(t *testing.T) {
		setupAccountDB(t)
		assets, _ := newAccountServices(t)
		ctx := WithSystemCaller(WithFieldCapability(adminCtx(), func(string) FieldCapGrant { return FieldCapDenied }))
		_, err := assets.Create(ctx, fieldCapCreateReq("both"))
		require.True(t, errors.Is(err, ErrFieldCapabilityDenied), "got %v", err)
	})
}

// 內部標記只能由服務端內部設定：HTTP 處理層與請求相關程式碼不得呼叫 WithSystemCaller。
func TestSystemCallerMarkerNotSetByRequestLayer(t *testing.T) {
	root := filepath.Join("..", "..", "..") // backend/
	var offenders []string
	walk := func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		if strings.HasPrefix(rel, filepath.Join("internal", "modules", "asset")+string(filepath.Separator)) {
			return nil
		}
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		if strings.Contains(string(b), "WithSystemCaller(") {
			offenders = append(offenders, rel)
		}
		return nil
	}
	for _, sub := range []string{"internal", "cmd"} {
		require.NoError(t, filepath.WalkDir(filepath.Join(root, sub), walk))
	}
	require.Empty(t, offenders, "WithSystemCaller 只允許在資產模組內部使用；組裝根需要時請明確登記後再放行")
}
