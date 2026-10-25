package asset

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// jsonFieldsOf 取結構全部帶 json 名稱的欄位名（排序）。
func jsonFieldsOf(rt reflect.Type) []string {
	out := []string{}
	for i := 0; i < rt.NumField(); i++ {
		tag := rt.Field(i).Tag.Get("json")
		name := strings.Split(tag, ",")[0]
		if name == "" || name == "-" {
			continue
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// classCoverageGaps 請求結構欄位與歸類表的落差：未歸類的欄位、表中多餘的鍵。
func classCoverageGaps(rt reflect.Type, table map[string]model.AssetDiffClass) (missing, extra []string) {
	fields := map[string]bool{}
	for _, f := range jsonFieldsOf(rt) {
		fields[f] = true
		if _, ok := table[f]; !ok {
			missing = append(missing, f)
		}
	}
	for k := range table {
		if !fields[k] {
			extra = append(extra, k)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	return
}

const diffTestPEM = "-----BEGIN CERTIFICATE-----\nSECRET-PEM-BODY-0123456789\n-----END CERTIFICATE-----"

// 每個值類／摘要類欄位單獨變更所用的突變函式。
var diffFieldMutators = map[string]func(a *model.Asset){
	"name":                  func(a *model.Asset) { a.Name = "renamed" },
	"protocol":              func(a *model.Asset) { a.Protocol = model.ProtocolRDP },
	"host":                  func(a *model.Asset) { a.Host = "10.9.9.9" },
	"port":                  func(a *model.Asset) { a.Port = 2222 },
	"username":              func(a *model.Asset) { a.Username = "other" },
	"description":           func(a *model.Asset) { a.Description = "d2" },
	"tags":                  func(a *model.Asset) { a.Tags = "t1" },
	"active":                func(a *model.Asset) { a.Active = !a.Active },
	"access_policy":         func(a *model.Asset) { v := model.AccessPolicyReason; a.AccessPolicy = &v },
	"rdp_security":          func(a *model.Asset) { a.RDPSecurity = model.RDPSecurityNLA },
	"rdp_verify_cert":       func(a *model.Asset) { a.RDPVerifyCert = !a.RDPVerifyCert },
	"db_name":               func(a *model.Asset) { a.DBName = "appdb" },
	"db_tls_mode":           func(a *model.Asset) { a.DBTLSMode = "require" },
	"allowed_databases":     func(a *model.Asset) { a.AllowedDatabases = model.StringList{"x"} },
	"k8s_namespace":         func(a *model.Asset) { a.K8sNamespace = "ns" },
	"k8s_pod":               func(a *model.Asset) { a.K8sPod = "pod" },
	"k8s_container":         func(a *model.Asset) { a.K8sContainer = "c" },
	"k8s_insecure_skip_tls": func(a *model.Asset) { a.K8sInsecureSkipTLS = !a.K8sInsecureSkipTLS },
	"sftp_enabled":          func(a *model.Asset) { a.SftpEnabled = !a.SftpEnabled },
	"sftp_port":             func(a *model.Asset) { a.SftpPort = 2022 },
	"sftp_username":         func(a *model.Asset) { a.SftpUsername = "sftpu" },
	"rotation_channel":      func(a *model.Asset) { a.RotationChannel = model.RotationChannelWindowsSSH },
	"winrm_scheme":          func(a *model.Asset) { a.WinrmScheme = "https" },
	"winrm_port":            func(a *model.Asset) { a.WinrmPort = 5986 },
	"winrm_tls_mode":        func(a *model.Asset) { a.WinrmTLSMode = "insecure" },
	"rotation_ssh_port":     func(a *model.Asset) { a.RotationSSHPort = 2200 },
	"db_ca_cert":            func(a *model.Asset) { a.DBCACert = diffTestPEM },
	"k8s_ca_cert":           func(a *model.Asset) { a.K8sCACert = diffTestPEM },
	"winrm_ca_cert":         func(a *model.Asset) { a.WinrmCACert = diffTestPEM },
}

func TestAssetAuditDiffCoverage(t *testing.T) {
	t.Run("更新請求欄位與歸類表零落差", func(t *testing.T) {
		missing, extra := classCoverageGaps(reflect.TypeOf(UpdateAssetRequest{}), model.AssetUpdateFieldClasses)
		require.Empty(t, missing, "更新請求有欄位未歸入 AssetUpdateFieldClasses")
		require.Empty(t, extra, "歸類表有請求結構不存在的鍵")
		for f, c := range model.AssetUpdateFieldClasses {
			if c == model.AssetDiffExcluded {
				require.NotEmpty(t, model.AssetDiffExcludedOwner[f], "排除欄位 %s 必須寫明承擔者", f)
			}
		}
	})

	t.Run("在請求結構臨時加一欄未歸類則偵測轉紅", func(t *testing.T) {
		type withExtra struct {
			Name  *string `json:"name"`
			Fresh *string `json:"brand_new_field"`
		}
		missing, _ := classCoverageGaps(reflect.TypeOf(withExtra{}), model.AssetUpdateFieldClasses)
		require.Equal(t, []string{"brand_new_field"}, missing)
	})

	t.Run("每個值類與摘要類欄位單獨變更各產生一筆對應 diff", func(t *testing.T) {
		for field, class := range model.AssetUpdateFieldClasses {
			if class != model.AssetDiffValue && class != model.AssetDiffDigest {
				continue
			}
			mut, ok := diffFieldMutators[field]
			require.True(t, ok, "缺 %s 的突變函式", field)
			old := &model.Asset{Name: "a", Host: "10.0.0.1", Port: 22, Protocol: model.ProtocolSSH, Active: true}
			updated := *old
			mut(&updated)
			changes := model.DiffAsset(old, &updated)
			var got []string
			for _, c := range changes {
				got = append(got, c.Field)
			}
			require.Equal(t, []string{field}, got, "欄位 %s 單獨變更應恰有一筆同名 diff", field)
		}
		for f := range diffFieldMutators {
			c := model.AssetUpdateFieldClasses[f]
			require.True(t, c == model.AssetDiffValue || c == model.AssetDiffDigest, "突變表多出非值類欄位 %s", f)
		}
	})

	t.Run("CA 欄記 SHA-256 摘要且不含 PEM", func(t *testing.T) {
		for _, f := range []string{"db_ca_cert", "k8s_ca_cert", "winrm_ca_cert"} {
			old := &model.Asset{Name: "a"}
			updated := *old
			diffFieldMutators[f](&updated)
			raw, err := json.Marshal(model.AssetChangeDetails{Changes: model.DiffAsset(old, &updated)})
			require.NoError(t, err)
			require.NotContains(t, string(raw), "SECRET-PEM-BODY", f)
			require.NotContains(t, string(raw), "BEGIN CERTIFICATE", f)
			require.Contains(t, string(raw), model.AssetCertDigest(diffTestPEM), f)
			require.Len(t, model.AssetCertDigest(diffTestPEM), 64)
		}
		require.Equal(t, "", model.AssetCertDigest(""), "空＝未設定")
	})

	t.Run("sftp_password 只記已變更", func(t *testing.T) {
		old := &model.Asset{Name: "a", SftpPasswordEnc: "enc-old-ZZZ"}
		updated := *old
		updated.SftpPasswordEnc = "enc-new-YYY"
		changes := model.DiffAsset(old, &updated)
		require.Len(t, changes, 1)
		require.Equal(t, "sftp_password", changes[0].Field)
		require.True(t, changes[0].Changed)
		raw, err := json.Marshal(model.AssetChangeDetails{Changes: changes})
		require.NoError(t, err)
		require.Contains(t, string(raw), `"changed":true`)
		for _, leak := range []string{"enc-old-ZZZ", "enc-new-YYY", `"old"`, `"new"`} {
			require.NotContains(t, string(raw), leak)
		}
	})

	t.Run("全同值不產生 diff", func(t *testing.T) {
		a := &model.Asset{Name: "a", Host: "h", Port: 22, Protocol: model.ProtocolSSH, DBCACert: diffTestPEM, SftpPasswordEnc: "e"}
		b := *a
		require.Empty(t, model.DiffAsset(a, &b))
	})

	t.Run("經 Update 的審計列：sftp 明文密碼不入明細、同值更新不產生變更列", func(t *testing.T) {
		db := setupAccountDB(t)
		assets, _ := newAccountServices(t)
		a := mustCreateAsset(t, assets, "srv-diff", "10.0.0.1")
		const plain = "Sftp-Plain-PW-9f3a"
		pw := plain
		_, err := assets.Update(WithSystemCaller(adminCtx()), a.ID, &UpdateAssetRequest{SftpPassword: &pw})
		require.NoError(t, err)

		var rows []model.AuditLog
		require.NoError(t, db.Where("details LIKE ?", `%"changes"%`).Find(&rows).Error)
		var found bool
		for _, r := range rows {
			require.NotContains(t, r.Details, plain)
			if strings.Contains(r.Details, `"field":"sftp_password"`) {
				require.Contains(t, r.Details, `"changed":true`)
				found = true
			}
		}
		require.True(t, found, "應有 sftp_password 已變更的審計列")

		before := countWhere(t, db, &model.AuditLog{}, "details LIKE ?", `%"changes"%`)
		desc := ""
		same := a.Host
		_, err = assets.Update(WithSystemCaller(adminCtx()), a.ID, &UpdateAssetRequest{Description: &desc, Host: &same})
		require.NoError(t, err)
		require.Equal(t, before, countWhere(t, db, &model.AuditLog{}, "details LIKE ?", `%"changes"%`),
			"全同值更新不得產生資產變更審計列")
	})

	t.Run("協議切換的兩種清空旗標照舊", func(t *testing.T) {
		db := setupAccountDB(t)
		// 先驗清單清空：mysql（支援主控台）改為 ssh
		old := &model.Asset{Name: "a", Host: "h", Port: 3306, Protocol: model.ProtocolMySQL,
			AllowedDatabases: model.StringList{"d1", "d2"}}
		old.ID = 7
		updated := *old
		updated.Protocol = model.ProtocolSSH
		updated.AllowedDatabases = model.StringList{}
		require.NoError(t, db.Transaction(func(tx *gorm.DB) error {
			return writeAssetChangeAudit(audit.NewTxSink(), tx, old, &updated, 1, "admin", model.ActionUpdate, "")
		}))
		var row model.AuditLog
		require.NoError(t, db.Where("details LIKE ?", `%allowed_databases_cleared%`).First(&row).Error)
		require.Contains(t, row.Details, `"previous_count":2`)

		// 再驗通道清空：rdp＋windows_winrm 改為 mysql（通道不相容）
		old2 := &model.Asset{Name: "b", Host: "h", Port: 3389, Protocol: model.ProtocolRDP,
			RotationChannel: model.RotationChannelWindowsWinRM, WinrmScheme: "https"}
		old2.ID = 8
		updated2 := *old2
		updated2.Protocol = model.ProtocolMySQL
		updated2.RotationChannel = ""
		updated2.WinrmScheme = ""
		require.NoError(t, db.Transaction(func(tx *gorm.DB) error {
			return writeAssetChangeAudit(audit.NewTxSink(), tx, old2, &updated2, 1, "admin", model.ActionUpdate, "")
		}))
		var row2 model.AuditLog
		require.NoError(t, db.Where("details LIKE ?", `%rotation_channel_cleared%`).First(&row2).Error)
		require.Contains(t, row2.Details, `"previous_rotation_channel":"windows_winrm"`)
		require.Contains(t, row2.Details, `"field":"winrm_scheme"`)
	})
}
