package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/custodexa/backend/internal/seal"
	"github.com/custodexa/backend/pkg/crypto"
)

// /seal/status 的執行期 KEK 識別：只在已解封時回，值取自服務圖實際持有的 provider。
//
// 部署工具在還原後以這個欄位核對主金鑰，所以兩個方向都要守：
// 未解封時多回一個值，工具會把「沒解封」誤判為「已核對」；
// 已解封時少回或回錯值，工具就無從證明解封用的是哪一把。

// statusKEKMaterial 32 位元組測試材料（非出廠預設）。
var statusKEKMaterial = []byte("aZ9bY8cX7dW6eV5fU4gT3hS2iR1jQ0kP")

// kekGraph 持有真的本地 provider 的假服務圖，識別由 provider 導出。
type kekGraph struct{ provider crypto.KEKProvider }

func (g *kekGraph) Release(context.Context) error { return nil }
func (g *kekGraph) RuntimeKEKID() string          { return g.provider.KeyRef().KeyID }

// plainGraph 不提供識別的服務圖（例如段 2 契約漂移）。
type plainGraph struct{}

func (plainGraph) Release(context.Context) error { return nil }

// statusJournal 恆成功的 journal：本檔驗的是狀態回應，不是 journal 語義。
type statusJournal struct{ seq uint64 }

func (j *statusJournal) WriteReceived(context.Context, uint64, string) (uint64, error) {
	j.seq++
	return j.seq, nil
}
func (*statusJournal) WriteOutcome(context.Context, uint64, uint64, string) error { return nil }
func (*statusJournal) WritePublished(context.Context, uint64, uint64) error       { return nil }
func (*statusJournal) RecordRejected(string)                                      {}
func (*statusJournal) Close() error                                               { return nil }

// newKEKStatusMachine 建一台封存中的狀態機，段 2 交給 stage2。
func newKEKStatusMachine(t *testing.T, stage2 seal.Stage2Func) *seal.Machine {
	t.Helper()
	m, err := seal.New(seal.Config{
		Journal: &statusJournal{},
		Verify: func(context.Context, []byte) (seal.VerifiedMaterial, error) {
			return seal.VerifiedMaterial{}, nil
		},
		Stage2: stage2,
	})
	if err != nil {
		t.Fatalf("建立狀態機失敗: %v", err)
	}
	t.Cleanup(m.WaitCleanup)
	return m
}

// localGraphStage2 段 2 以材料建出真的本地 provider。
func localGraphStage2(t *testing.T, mode string) seal.Stage2Func {
	t.Helper()
	return func(context.Context, seal.VerifiedMaterial) (seal.ServiceGraph, error) {
		p, err := crypto.NewLocalAESKEKProvider(statusKEKMaterial, mode)
		if err != nil {
			return nil, err
		}
		return &kekGraph{provider: p}, nil
	}
}

// readStatus 讀一次 /seal/status 的原始欄位。
func readStatus(t *testing.T, h *SealHandler) map[string]any {
	t.Helper()
	w := sealRequest(sourceTestRouter(t, h), http.MethodGet, "/api/v1/seal/status", "10.0.0.7", "")
	if w.Code != http.StatusOK {
		t.Fatalf("/seal/status 回 %d：%s", w.Code, w.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("/seal/status 回應非 JSON: %v", err)
	}
	return body
}

func unsealOnce(t *testing.T, m *seal.Machine, source string) error {
	t.Helper()
	_, err := m.Unseal(context.Background(), seal.UnsealRequest{
		Material: []byte("x"), SourceKey: source, SourceDigest: source,
	})
	return err
}

func TestSealStatusKEKIDOnlyWhenUnsealed(t *testing.T) {
	want := crypto.Fingerprint(statusKEKMaterial)

	t.Run("ui 解封前無欄位、解封後等於 provider 識別", func(t *testing.T) {
		m := newKEKStatusMachine(t, localGraphStage2(t, crypto.KEKModeUI))
		h := NewSealHandler(m, nil)

		before := readStatus(t, h)
		if before["state"] != string(seal.StateSealed) {
			t.Fatalf("前置：狀態為 %v，期望 sealed", before["state"])
		}
		if v, ok := before["kek_id"]; ok {
			t.Fatalf("封存中回了 kek_id=%v——部署工具會把未解封誤判為已核對", v)
		}

		if err := unsealOnce(t, m, "ui"); err != nil {
			t.Fatalf("解封失敗: %v", err)
		}
		after := readStatus(t, h)
		if after["state"] != string(seal.StateUnsealed) {
			t.Fatalf("前置：狀態為 %v，期望 unsealed", after["state"])
		}
		if got := after["kek_id"]; got != want {
			t.Fatalf("解封後 kek_id=%v，期望材料指紋 %s", got, want)
		}
	})

	t.Run("封印且故障時無欄位", func(t *testing.T) {
		m := newKEKStatusMachine(t, func(ctx context.Context, v seal.VerifiedMaterial) (seal.ServiceGraph, error) {
			// 半建構圖照樣帶得出識別：守的是「故障態不回」，不是「圖給不出值」。
			g, err := localGraphStage2(t, crypto.KEKModeUI)(ctx, v)
			if err != nil {
				return nil, err
			}
			return g, errors.New("段 2 初始化失敗")
		})
		h := NewSealHandler(m, nil)
		if err := unsealOnce(t, m, "faulted"); err == nil {
			t.Fatal("前置：段 2 失敗卻解封成功")
		}
		st := readStatus(t, h)
		if st["state"] != string(seal.StateSealedFaulted) {
			t.Fatalf("前置：狀態為 %v，期望 sealed-faulted", st["state"])
		}
		if v, ok := st["kek_id"]; ok {
			t.Fatalf("封印且故障時回了 kek_id=%v", v)
		}
	})

	t.Run("env 啟動後等於材料指紋", func(t *testing.T) {
		// 與組裝根相同：env 模式於啟動時以固定來源鍵走一次解封。
		m := newKEKStatusMachine(t, localGraphStage2(t, crypto.KEKModeEnv))
		h := NewSealHandler(m, nil)
		h.SetAuthorizer(crypto.KEKModeEnv, nil)
		if err := unsealOnce(t, m, "startup"); err != nil {
			t.Fatalf("啟動解封失敗: %v", err)
		}
		if got := readStatus(t, h)["kek_id"]; got != want {
			t.Fatalf("env 啟動後 kek_id=%v，期望材料指紋 %s", got, want)
		}
	})

	t.Run("服務圖不提供識別時不回欄位", func(t *testing.T) {
		// 不以空字串頂替：已解封卻缺欄位，部署工具會當作讀不到而不是已核對。
		h := NewSealHandler(seal.NewUnsealed(plainGraph{}), nil)
		st := readStatus(t, h)
		if st["state"] != string(seal.StateUnsealed) {
			t.Fatalf("前置：狀態為 %v，期望 unsealed", st["state"])
		}
		if v, ok := st["kek_id"]; ok {
			t.Fatalf("服務圖無識別卻回了 kek_id=%v", v)
		}
	})
}
