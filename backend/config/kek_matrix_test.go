package config

import (
	"strings"
	"testing"
)

// KEK_PROVIDER 判定矩陣的**逐格測試**（kek-provider-modularization D2.2；
// legacy 兩格 3b-legacy／6b 隨 release-transitional-cleanup D3 拆除；
// 遮蔽格 12 隨 KEK 材料鍵收斂為單一 `ENCRYPTION_KEY` 消滅——單鍵下不存在
// 可被遮蔽的第二把鑰）。
//
// 全部經可注入的 EnvLookup 判定，**不污染行程 env**——矩陣需要「未設／設為空字串／
// 設為有效值」三值互相區分，用 os.Setenv 無法表達「顯式設為空字串」與「未設」之別。
//
// 命名對應矩陣列號；每格斷言「結果模式或拒絕」與「命中的矩陣列」，
// 使任一格行為漂移即紅。

const validMaterial = "AbCdEfGhIjKlMnOpQrStUvWxYz012345" // 32 字元、字元集合法、非出廠預設

func decide(t *testing.T, env map[string]string, hsmBuild bool) (*KEKDecision, error) {
	t.Helper()
	return DecideKEK(MapEnvLookup(env), hsmBuild)
}

func wantAccept(t *testing.T, env map[string]string, hsmBuild bool, mode, row string) *KEKDecision {
	t.Helper()
	d, err := decide(t, env, hsmBuild)
	if err != nil {
		t.Fatalf("預期接受（模式 %s，列 %s），得錯誤: %v", mode, row, err)
	}
	if d.Mode != mode {
		t.Errorf("模式 = %q, want %q", d.Mode, mode)
	}
	if d.MatrixRow != row {
		t.Errorf("命中矩陣列 = %q, want %q", d.MatrixRow, row)
	}
	return d
}

func wantReject(t *testing.T, env map[string]string, hsmBuild bool, row string) error {
	t.Helper()
	d, err := decide(t, env, hsmBuild)
	if err == nil {
		t.Fatalf("預期拒絕（列 %s），卻接受為模式 %q（列 %s）", row, d.Mode, d.MatrixRow)
	}
	if !strings.Contains(err.Error(), "[列 "+row+"]") {
		t.Errorf("錯誤訊息未標明矩陣列 %s：%v", row, err)
	}
	return err
}

// 列 1：未設 KEK_PROVIDER ＋ 本地鑰有值 → A env（向後相容路徑）
func TestKEKMatrixRow1_UnsetProviderWithLocalKey(t *testing.T) {
	d := wantAccept(t, map[string]string{EnvKeyEncryptionKey: validMaterial}, false, KEKModeEnv, "1")
	if d.Material != validMaterial || d.MaterialSource != EnvKeyEncryptionKey {
		t.Errorf("材料來源 = %q（材料應取自 ENCRYPTION_KEY）", d.MaterialSource)
	}
}

// KEK 材料鍵**唯一**：`ENCRYPTION_KEY` 之外的任何鍵名皆不得被當成 KEK 材料。
// 釘住名稱收斂——若日後有人重新引入第二把材料鍵並讓它參與判定，本測試即紅。
func TestKEKMaterialKeyIsSingleSourceOfTruth(t *testing.T) {
	// 本次收斂所刪除的鍵名以**字串拼接**構造，不寫字面（獨立驗收 2026-08-11 指出的
	// 覆蓋缺口：原清單不含它，重新引入正是該鍵時守衛不會紅）。
	// 拼接的理由是「活躍碼中不得出現該字面」這條驗收條件以機械 grep 執行——
	// 寫字面會讓零殘留檢查誤報。**後人請勿「修正」為字面**。
	retiredMaterialKey := "KEK_" + "ENV_KEY"
	for _, stale := range []string{retiredMaterialKey, "KEK_MATERIAL", "LEGACY_ENCRYPTION_KEY", "AUDIT_INTEGRITY_KEY"} {
		t.Run(stale, func(t *testing.T) {
			// 只設廢棄鍵：等同無材料 → 列 2（不得被當成 KEK 材料而啟動）
			wantReject(t, map[string]string{stale: validMaterial}, false, "2")
			// 廢棄鍵與現行鍵並存：材料一律取自 ENCRYPTION_KEY，廢棄鍵零影響
			d := wantAccept(t, map[string]string{
				stale:               "ZzYyXxWwVvUuTtSsRrQqPpOoNnMmLl99",
				EnvKeyEncryptionKey: validMaterial,
			}, false, KEKModeEnv, "1")
			if d.Material != validMaterial || d.MaterialSource != EnvKeyEncryptionKey {
				t.Errorf("%s 不得參與 KEK 材料判定：source=%q", stale, d.MaterialSource)
			}
			// ui 模式下廢棄鍵有值不構成「本地材料仍有值」（列 6 而非列 5）
			wantAccept(t, map[string]string{
				EnvKeyKEKProvider: KEKModeUI,
				stale:             validMaterial,
			}, false, KEKModeUI, "6")
		})
	}
}

// 列 2：未設 KEK_PROVIDER ＋ 無本地鑰 → 拒啟動（留空不推斷為 ui）
func TestKEKMatrixRow2_UnsetProviderNoLocalKey(t *testing.T) {
	err := wantReject(t, map[string]string{}, false, "2")
	if !strings.Contains(err.Error(), "ui") {
		t.Errorf("錯誤應說明「留空不會被推斷為 ui」：%v", err)
	}
}

// 列 3：KEK_PROVIDER=env ＋ 材料格式合格 → A env
func TestKEKMatrixRow3_EnvWithValidMaterial(t *testing.T) {
	wantAccept(t, map[string]string{
		EnvKeyKEKProvider:   KEKModeEnv,
		EnvKeyEncryptionKey: validMaterial,
	}, false, KEKModeEnv, "3")
}

// 列 3b：KEK_PROVIDER=env ＋ 材料格式不合格（含全空白、出廠預設值）→ 拒啟動
func TestKEKMatrixRow3b_EnvWithInvalidMaterial(t *testing.T) {
	cases := map[string]string{
		"長度不足":             "tooshort",
		"字元集外字元":           "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!",
		"出廠預設值（PCI 2.2.2）": DefaultEncryptionKey,
	}
	for name, material := range cases {
		t.Run(name, func(t *testing.T) {
			wantReject(t, map[string]string{
				EnvKeyKEKProvider:   KEKModeEnv,
				EnvKeyEncryptionKey: material,
			}, false, "3b")
		})
	}
	// 「恰 32 個空白字元」（codex high）：判定順序上先被「trim 後為空＝無值」攔下，
	// 故落**列 4**（宣告 env 卻無材料）而非列 3b。兩者皆 fail-close，此處釘住的是
	// 「不得因位元組長度符合 32 而放行」——若哪天空白被當成合法材料，本測試先紅。
	t.Run("恰 32 個空白字元被拒（落列 4：trim 後為空＝無值）", func(t *testing.T) {
		wantReject(t, map[string]string{
			EnvKeyKEKProvider:   KEKModeEnv,
			EnvKeyEncryptionKey: strings.Repeat(" ", 32),
		}, false, "4")
	})
}

// 「恰 32 個空白字元」另一角度：於**列 4** 判定中亦不得算「有值」——
// trim 後為空即無值，否則空白字串會成為合法長度的 KEK 材料
func TestKEKAllWhitespaceMaterialIsNotAValue(t *testing.T) {
	// 未宣告模式時：全空白＝無值 → 列 2（而非列 1）
	wantReject(t, map[string]string{EnvKeyEncryptionKey: strings.Repeat(" ", 32)}, false, "2")
	// ui 模式下：全空白＝無值 → 合格（列 6），不觸發列 5
	wantAccept(t, map[string]string{
		EnvKeyKEKProvider:   KEKModeUI,
		EnvKeyEncryptionKey: "   ",
	}, false, KEKModeUI, "6")
}

// 「出廠預設值仍算有值」邊界：ui 模式下留著出廠預設值 → 列 5（不得成為隱式豁免）
func TestKEKFactoryDefaultCountsAsValue(t *testing.T) {
	wantReject(t, map[string]string{
		EnvKeyKEKProvider:   KEKModeUI,
		EnvKeyEncryptionKey: DefaultEncryptionKey,
	}, false, "5")
}

// 列 4：KEK_PROVIDER=env ＋ 無材料 → 拒啟動
func TestKEKMatrixRow4_EnvWithoutMaterial(t *testing.T) {
	wantReject(t, map[string]string{EnvKeyKEKProvider: KEKModeEnv}, false, "4")
}

// 列 5：KEK_PROVIDER=ui ＋ 本地鑰有值 → 拒啟動（假 in-memory）
func TestKEKMatrixRow5_UIWithLocalKey(t *testing.T) {
	wantReject(t, map[string]string{
		EnvKeyKEKProvider:   KEKModeUI,
		EnvKeyEncryptionKey: validMaterial,
	}, false, "5")
}

// 列 6：KEK_PROVIDER=ui ＋ 無本地鑰 → B ui
func TestKEKMatrixRow6_UISealed(t *testing.T) {
	d := wantAccept(t, map[string]string{EnvKeyKEKProvider: KEKModeUI}, false, KEKModeUI, "6")
	if d.Material != "" {
		t.Error("ui 模式不得於判定結果攜帶本地材料")
	}
}

// 列 7：委託模式 ＋ 本地鑰有值 → 拒啟動（組態矛盾）
func TestKEKMatrixRow7_DelegatedWithLocalKey(t *testing.T) {
	for _, mode := range []string{KEKModeKMS, KEKModeHSM} {
		t.Run(mode, func(t *testing.T) {
			wantReject(t, map[string]string{
				EnvKeyKEKProvider:   mode,
				EnvKeyEncryptionKey: validMaterial,
			}, true, "7")
		})
	}
}

// 列 8：委託組態不齊／PIN 兩鍵衝突 → 拒啟動，錯誤**逐鍵**列出
func TestKEKMatrixRow8_DelegatedConfigIncomplete(t *testing.T) {
	t.Run("kms 缺兩鍵逐鍵列出", func(t *testing.T) {
		err := wantReject(t, map[string]string{
			EnvKeyKEKProvider: KEKModeKMS,
			EnvKeyKMSProvider: "aws",
		}, false, "8")
		for _, k := range []string{EnvKeyKMSKeyID, EnvKeyKMSRegion} {
			if !strings.Contains(err.Error(), k) {
				t.Errorf("錯誤未逐鍵列出 %s：%v", k, err)
			}
		}
		if strings.Contains(err.Error(), EnvKeyKMSProvider) {
			t.Errorf("已設的鍵不應列為缺項：%v", err)
		}
	})
	t.Run("kms 鍵值為純空白視同缺項", func(t *testing.T) {
		wantReject(t, map[string]string{
			EnvKeyKEKProvider: KEKModeKMS,
			EnvKeyKMSProvider: "aws",
			EnvKeyKMSKeyID:    "   ",
			EnvKeyKMSRegion:   "ap-northeast-1",
		}, false, "8")
	})
	t.Run("hsm PIN 與 PIN_FILE 皆未設", func(t *testing.T) {
		err := wantReject(t, map[string]string{
			EnvKeyKEKProvider:   KEKModeHSM,
			EnvKeyHSMModule:     "/usr/lib/softhsm2.so",
			EnvKeyHSMTokenLabel: "tok",
			EnvKeyHSMKeyLabel:   "kek",
		}, true, "8")
		if !strings.Contains(err.Error(), EnvKeyHSMPin) || !strings.Contains(err.Error(), EnvKeyHSMPinFile) {
			t.Errorf("錯誤未同時點名兩鍵：%v", err)
		}
	})
	t.Run("hsm PIN 與 PIN_FILE 皆有值＝組態矛盾（不做隱式優先序）", func(t *testing.T) {
		err := wantReject(t, map[string]string{
			EnvKeyKEKProvider:   KEKModeHSM,
			EnvKeyHSMModule:     "/usr/lib/softhsm2.so",
			EnvKeyHSMTokenLabel: "tok",
			EnvKeyHSMKeyLabel:   "kek",
			EnvKeyHSMPin:        "1234",
			EnvKeyHSMPinFile:    "/run/secrets/pin",
		}, true, "8")
		if !strings.Contains(err.Error(), "恰一") {
			t.Errorf("錯誤未指出「須恰一有值」：%v", err)
		}
	})
}

// 列 9：委託組態齊備 → C 委託模式
func TestKEKMatrixRow9_DelegatedComplete(t *testing.T) {
	t.Run("kms", func(t *testing.T) {
		d := wantAccept(t, map[string]string{
			EnvKeyKEKProvider: KEKModeKMS,
			EnvKeyKMSProvider: "aws",
			EnvKeyKMSKeyID:    "alias/custodexa-kek",
			EnvKeyKMSRegion:   "ap-northeast-1",
		}, false, KEKModeKMS, "9")
		if d.KMS.KeyID != "alias/custodexa-kek" {
			t.Errorf("KMS 組態未帶回：%+v", d.KMS)
		}
	})
	t.Run("hsm（pkcs11 build）", func(t *testing.T) {
		d := wantAccept(t, map[string]string{
			EnvKeyKEKProvider:   KEKModeHSM,
			EnvKeyHSMModule:     "/usr/lib/softhsm2.so",
			EnvKeyHSMTokenLabel: "tok",
			EnvKeyHSMKeyLabel:   "kek",
			EnvKeyHSMPinFile:    "/run/secrets/pin",
		}, true, KEKModeHSM, "9")
		if d.HSM.Pin != "" || d.HSM.PinFile == "" {
			t.Errorf("PIN 兩鍵僅一有值時應原樣帶回：%+v", d.HSM)
		}
	})
}

// 列 10：白名單外值（含大小寫不符）→ 拒啟動，不猜、不回落
// **雙審點名必測**：大小寫不符（ENV）、白名單外未知值
func TestKEKMatrixRow10_UnknownProviderValue(t *testing.T) {
	for _, v := range []string{"ENV", "Env", "UI", "vault", "aws-kms", "env "} {
		t.Run(v, func(t *testing.T) {
			if v == "env " {
				// trim 後為 env → 合法（正規化先於白名單比對）
				wantAccept(t, map[string]string{
					EnvKeyKEKProvider:   v,
					EnvKeyEncryptionKey: validMaterial,
				}, false, KEKModeEnv, "3")
				return
			}
			wantReject(t, map[string]string{
				EnvKeyKEKProvider:   v,
				EnvKeyEncryptionKey: validMaterial,
			}, false, "10")
		})
	}
}

// **雙審點名必測**：KEK_PROVIDER 空字串／純空白等同未設（走列 1／2），
// MUST NOT 因「已設定但不在白名單」而拒絕，亦 MUST NOT 使白名單檢查被靜默繞過
func TestKEKProviderEmptyAndBlankEqualUnset(t *testing.T) {
	for _, v := range []string{"", "   ", "\t\n"} {
		t.Run("有本地鑰_"+strings.TrimSpace(v)+"|", func(t *testing.T) {
			wantAccept(t, map[string]string{
				EnvKeyKEKProvider:   v,
				EnvKeyEncryptionKey: validMaterial,
			}, false, KEKModeEnv, "1")
		})
		t.Run("無本地鑰_"+strings.TrimSpace(v)+"|", func(t *testing.T) {
			wantReject(t, map[string]string{EnvKeyKEKProvider: v}, false, "2")
		})
	}
}

// 列 11：非 pkcs11 build 宣告 hsm → 拒啟動，明示需 HSM 變體映像
func TestKEKMatrixRow11_HSMWithoutBuildCapability(t *testing.T) {
	err := wantReject(t, map[string]string{
		EnvKeyKEKProvider:   KEKModeHSM,
		EnvKeyHSMModule:     "/usr/lib/softhsm2.so",
		EnvKeyHSMTokenLabel: "tok",
		EnvKeyHSMKeyLabel:   "kek",
		EnvKeyHSMPin:        "1234",
	}, false, "11")
	if !strings.Contains(err.Error(), "HSM") {
		t.Errorf("錯誤應明示需 HSM 變體映像：%v", err)
	}
}

// 顯式空的 KEK 材料鍵＝無材料：ui 模式合格（列 6），不因「已設定」而誤判有值。
// 單鍵收斂後此處不再有「遮蔽第二把鑰」的語義，空值就只是沒有材料。
func TestKEKEmptyMaterialKeyIsNoMaterial(t *testing.T) {
	wantAccept(t, map[string]string{
		EnvKeyKEKProvider:   KEKModeUI,
		EnvKeyEncryptionKey: "",
	}, false, KEKModeUI, "6")
	// 未宣告模式時空值＝無材料 → 列 2（不得推斷為 ui）
	wantReject(t, map[string]string{EnvKeyEncryptionKey: ""}, false, "2")
}

// 未宣告 KEK_PROVIDER 的向後相容路徑（列 1）**不套材料格式驗證**——
// 列 1 的「其他條件」欄為「—」，格式驗證僅適用於顯式宣告 env 的列 3／3b。
// 任意形狀的舊材料（例如 CI 的 `test-encryption-key-32-bytes!!`）仍可啟動。
func TestKEKRow1SkipsMaterialFormatValidation(t *testing.T) {
	legacyShapedMaterials := []string{
		validMaterial,
		"test-encryption-key-32-bytes!!", // 既有 CI 值：含字元集外字元、長度非 32
		DefaultEncryptionKey,             // 既有 dev 值：出廠預設（release 仍由 DefaultSecretViolations 擋）
	}
	for _, material := range legacyShapedMaterials {
		t.Run(material[:8], func(t *testing.T) {
			d := wantAccept(t, map[string]string{EnvKeyEncryptionKey: material}, false, KEKModeEnv, "1")
			if d.Material != material {
				t.Errorf("KEK 材料 = %q, want ENCRYPTION_KEY 原值", d.Material)
			}
			if d.MaterialSource != EnvKeyEncryptionKey {
				t.Errorf("材料來源 = %q, want %q", d.MaterialSource, EnvKeyEncryptionKey)
			}
			if !d.UsesLocalMaterial() {
				t.Error("既有部署應判為持有本地材料的 env 模式")
			}
		})
	}
}

// DefaultSecretViolations 的**模式感知**（D3）：兩模式各有專測
func TestDefaultSecretViolationsModeAware(t *testing.T) {
	cfg := &Config{Security: SecurityConfig{JWTSecret: "a-real-jwt-secret-32-bytes-long!"}}

	t.Run("env 模式仍擋出廠預設值（PCI 2.2.2 紅線不放寬）", func(t *testing.T) {
		d := wantAccept(t, map[string]string{EnvKeyEncryptionKey: DefaultEncryptionKey}, false, KEKModeEnv, "1")
		got := cfg.DefaultSecretViolations(d)
		if len(got) != 1 || got[0] != "ENCRYPTION_KEY" {
			t.Errorf("env 模式出廠預設值應判為違規, got %v", got)
		}
	})
	t.Run("非 env 模式「本地鑰未設」是合法組態", func(t *testing.T) {
		for _, mode := range []string{KEKModeUI, KEKModeKMS, KEKModeHSM} {
			env := map[string]string{EnvKeyKEKProvider: mode}
			switch mode {
			case KEKModeKMS:
				env[EnvKeyKMSProvider], env[EnvKeyKMSKeyID], env[EnvKeyKMSRegion] = "aws", "alias/k", "ap-northeast-1"
			case KEKModeHSM:
				env[EnvKeyHSMModule], env[EnvKeyHSMTokenLabel] = "/m.so", "tok"
				env[EnvKeyHSMKeyLabel], env[EnvKeyHSMPin] = "kek", "1234"
			}
			d, err := decide(t, env, true)
			if err != nil {
				t.Fatalf("%s 模式應可判定: %v", mode, err)
			}
			if got := cfg.DefaultSecretViolations(d); len(got) != 0 {
				t.Errorf("%s 模式「本地 KEK 鑰未設」不應列為違規, got %v", mode, got)
			}
		}
	})
}

// 決議 log 不得洩漏任何金鑰材料
func TestKEKDecisionLogLineHasNoMaterial(t *testing.T) {
	d := wantAccept(t, map[string]string{EnvKeyEncryptionKey: validMaterial}, false, KEKModeEnv, "1")
	line := d.LogLine()
	if strings.Contains(line, validMaterial) {
		t.Errorf("決議 log 洩漏 KEK 材料：%s", line)
	}
	if !strings.Contains(line, "matrix_row=1") {
		t.Errorf("決議 log 應含命中矩陣列：%s", line)
	}
}
