package main

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
)

// K8s 上傳的「本文完成後再裁決一次」（安全審查 B-01）。
//
// 早期裁決在讀本文之前做；本文的送達時間由客戶端控制，撤權、停用資產、核准時窗
// 到期都可能落在這個窗口裡。本檔釘住：本文暫存完成後、解封憑證與遠端寫入之前，
// 完整資料面裁決會重做一次，窗口內失效的授權不得完成 `kubectl cp`。
//
// 突變自檢：把 UploadK8sFile 中 SaveUploadedFile 之後的第二次 requireK8sDataPlane 拿掉，
// 三個失效案例全部轉紅（原請求 200、copies=1）。

// delayedBody 在第一次讀取本文時執行一次 hook：模擬客戶端先送標頭通過早期裁決、
// 延後送本文，而授權事實在這段期間改變。
type delayedBody struct {
	r    io.Reader
	once func()
}

func (d *delayedBody) Read(p []byte) (int, error) {
	if d.once != nil {
		f := d.once
		d.once = nil
		f()
	}
	return d.r.Read(p)
}

func (e *k8sPlaneEnv) uploadDelayed(t *testing.T, userID, assetID uint, during func()) (int, string, bool) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("pod", "web-0")
	_ = mw.WriteField("container", "web")
	f, _ := mw.CreateFormFile("file", "probe.txt")
	_, _ = f.Write([]byte("probe"))
	_ = mw.Close()
	fired := false
	body := &delayedBody{r: &buf, once: func() {
		fired = true
		if during != nil {
			during()
		}
	}}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/assets/"+itoa(assetID)+"/k8s/upload", body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	w := httptest.NewRecorder()
	e.engine(t, userID).ServeHTTP(w, req)
	return w.Code, w.Body.String(), fired
}

func TestK8sUploadReadjudicatedAfterBody(t *testing.T) {
	uid := k8sPlaneUserScoped

	t.Run("本文期間撤銷連線授權：以連線授權碼拒絕且零複製", func(t *testing.T) {
		env := newK8sPlaneEnv(t, false)
		grantID := env.grantConnect(t, uid, k8sPlaneAssetK8s, nil)
		st, body, fired := env.uploadDelayed(t, uid, k8sPlaneAssetK8s, func() {
			if err := env.db.Delete(&model.AssetAuthorization{}, grantID).Error; err != nil {
				t.Fatal(err)
			}
		})
		if !fired {
			t.Fatal("夾具：本文 hook 未觸發，窗口未重現")
		}
		expectCode(t, "revoked during body", st, body, http.StatusForbidden, "AUTH_ASSET_CONNECT_DENIED")
		if env.assets.copies != 0 {
			t.Fatalf("撤權後不得走到複製階段: copies=%d", env.assets.copies)
		}
	})

	t.Run("本文期間停用資產：以停用碼拒絕且零複製", func(t *testing.T) {
		env := newK8sPlaneEnv(t, false)
		env.grantConnect(t, uid, k8sPlaneAssetK8s, nil)
		st, body, fired := env.uploadDelayed(t, uid, k8sPlaneAssetK8s, func() {
			if err := env.db.Model(&model.Asset{}).Where("id = ?", k8sPlaneAssetK8s).Update("active", false).Error; err != nil {
				t.Fatal(err)
			}
		})
		if !fired {
			t.Fatal("夾具：本文 hook 未觸發")
		}
		expectCode(t, "disabled during body", st, body, http.StatusForbidden, "RULE_ASSET_DISABLED")
		if env.assets.copies != 0 {
			t.Fatalf("停用後不得走到複製階段: copies=%d", env.assets.copies)
		}
	})

	t.Run("本文期間核准時窗到期：以存取政策碼拒絕且零複製", func(t *testing.T) {
		env := newK8sPlaneEnv(t, false)
		env.grantConnect(t, uid, k8sPlaneAssetApproval, nil)
		aid := k8sPlaneAssetApproval
		start, end := time.Now().Add(-time.Minute), time.Now().Add(time.Hour)
		ticket := model.AssetAuthorization{UserID: &uid, AssetID: &aid, Permission: model.PermissionConnect,
			GrantedBy: k8sPlaneUserGranter, Source: model.AuthorizationSourceTicket, DateStart: &start, DateExpired: &end}
		if err := env.db.Create(&ticket).Error; err != nil {
			t.Fatal(err)
		}
		st, body, fired := env.uploadDelayed(t, uid, aid, func() {
			past := time.Now().Add(-time.Second)
			if err := env.db.Model(&model.AssetAuthorization{}).Where("id = ?", ticket.ID).Update("date_expired", past).Error; err != nil {
				t.Fatal(err)
			}
		})
		if !fired {
			t.Fatal("夾具：本文 hook 未觸發")
		}
		expectCode(t, "ticket expired during body", st, body, http.StatusForbidden, "RULE_ACCESS_APPROVAL_REQUIRED")
		if env.assets.copies != 0 {
			t.Fatalf("時窗到期後不得走到複製階段: copies=%d", env.assets.copies)
		}
	})

	t.Run("授權事實未變：延後送本文照常通過，複製一次", func(t *testing.T) {
		env := newK8sPlaneEnv(t, false)
		env.grantConnect(t, uid, k8sPlaneAssetK8s, nil)
		st, body, fired := env.uploadDelayed(t, uid, k8sPlaneAssetK8s, nil)
		if !fired || st != http.StatusOK {
			t.Fatalf("對照：未變更時應通過: fired=%v status=%d body=%s", fired, st, body)
		}
		if env.assets.copies != 1 {
			t.Fatalf("對照：應恰走到一次複製: copies=%d", env.assets.copies)
		}
	})
}
