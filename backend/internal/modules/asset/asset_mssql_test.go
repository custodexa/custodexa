package asset

import (
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/stretchr/testify/assert"
)

// mssql **必須有使用者名稱**：sqlcmd 只在有 -U 而無 -P 時才印 Password: 並停下等
// stdin，沒有 -U 就根本不索取密碼——PTY 注入永不觸發，使用者只看到無原因的斷線。
// 故 mssql 絕不可加進「免使用者名稱」清單（VNC／Redis／K8s）。本測試把這件事釘死：
// 有人日後為了「方便」把 mssql 加進去，這裡必須先紅。
func TestCreateMSSQLRequiresUsername(t *testing.T) {
	_, _, _ = setupAssetMockDB(t)
	key := make([]byte, 32)
	service, err := NewAssetService(aesColumnCodec(t, key), "localhost", 4822, audit.NewTxSink())
	assert.NoError(t, err)

	_, err = service.Create(&CreateAssetRequest{
		Name:      "mssql-no-user",
		Protocol:  model.ProtocolMSSQL,
		Host:      "10.0.0.9",
		Port:      1433,
		Password:  "secret123",
		CreatedBy: 1,
	})
	assert.ErrorIs(t, err, ErrUsernameRequired,
		"mssql 缺 username 必須被擋；放行會造成 sqlcmd 不索取密碼、注入永不觸發")
}

// -S host,port 的逗號是埠分隔語義，host 自帶逗號會被解讀成埠。
// 只擋 mssql——逗號對其餘協議合法，不得誤傷（localpty.SafeArg 的通用語義不動）。
func TestValidateMSSQLHostComma(t *testing.T) {
	cases := []struct {
		name     string
		protocol model.ProtocolType
		host     string
		wantErr  bool
	}{
		{"mssql 含逗號", model.ProtocolMSSQL, "10.0.0.9,1433", true},
		{"mssql 無逗號", model.ProtocolMSSQL, "10.0.0.9", false},
		{"postgres 含逗號不受影響", model.ProtocolPostgres, "10.0.0.9,1433", false},
		{"ssh 含逗號不受影響", model.ProtocolSSH, "a,b", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateMSSQLHost(c.protocol, c.host)
			if c.wantErr {
				assert.ErrorIs(t, err, ErrMSSQLHostComma)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// 認證類型值域（D3）。domain 與值域外**分成兩碼**：前者是「值合法但本版做不到」，
// 靜默降級為 sql 會讓管理員以為域認證已生效；後者只是打錯字。
func TestNormalizeAccountAuthMethod(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr error
	}{
		{"", AuthMethodSQL, nil},
		{"sql", AuthMethodSQL, nil},
		{"domain", "", ErrAssetAccountAuthMethodUnsupported},
		{"kerberos", "", ErrAssetAccountAuthMethodInvalid},
		{"SQL", "", ErrAssetAccountAuthMethodInvalid}, // 大小寫不寬容，與 db_tls_mode 同紀律
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			got, err := normalizeAccountAuthMethod(c.in)
			if c.wantErr != nil {
				assert.ErrorIs(t, err, c.wantErr)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, c.want, got)
		})
	}
}

// mssql 必須被視為資料庫協議與文字終端協議：漏了任一個，會話會被分派去 guacd
// （沒有 MSSQL client library，送過去永不返回），或不掛指令審計。
func TestMSSQLProtocolClassification(t *testing.T) {
	assert.True(t, model.ProtocolMSSQL.IsDatabase())
	assert.True(t, model.ProtocolMSSQL.IsTextTerminal())
	assert.Equal(t, model.ProtocolType("mssql"), model.ProtocolMSSQL,
		"協議值為 mssql（assets.protocol 為 size:10，sqlserver 無餘裕）")
}
