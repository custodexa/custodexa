package policy

import (
	"errors"
	"strconv"
	"testing"
)

// 保留政策跨鍵約束（audit-checkpoint-chain 第 7 組／security-policy spec
//「保留政策的跨鍵約束」）。

// TestPolicySeedCheckpointRetention 7.1：新政策鍵的定義面。
//
// 斷言四件事而非只斷言「鍵存在」：預設值、0 可用（ZeroDisables）、單位鍵
// （前端查譯錨點）、以及**沒有 PCIValue**——掛上 PCIValue 會讓它進「套用
// 本頁建議值」並在偏離摘要與資料保留鍵並列，把跨鍵語義誤導成單鍵語義
func TestPolicySeedCheckpointRetention(t *testing.T) {
	def := findDef(PolicyRetentionCheckpointDays)
	if def == nil {
		t.Fatal("retention_checkpoint_days 未定義於 policyDefs")
	}
	// 出廠 0＝永久（D-5）：四個資料保留鍵出廠 0/0/0/90，出廠 3650 會使
	// 出廠狀態本身違反跨鍵約束（0=無限大），逼跨鍵驗證退讓成只驗觸及關係
	if def.Type != PolicyTypeInt || def.Default != "0" {
		t.Errorf("type=%s default=%s，want int/0（D-5：出廠永久，使五鍵出廠即自洽）", def.Type, def.Default)
	}
	if !def.ZeroDisables {
		t.Error("ZeroDisables 應為 true（0=永久保留）")
	}
	if def.Max != 3650 {
		t.Errorf("Max=%d，want 3650（O5 判定：與資料保留鍵同一天花板）", def.Max)
	}
	if def.PCIValue != "" {
		t.Errorf("PCIValue=%q，want 空（本鍵無獨立 PCI 建議值，合規語義是跨鍵關係）", def.PCIValue)
	}
	if def.UnitKey != "days" {
		t.Errorf("UnitKey=%q，want days", def.UnitKey)
	}

	svc, _ := setupPolicyDB(t)
	if got := svc.GetInt(PolicyRetentionCheckpointDays); got != 0 {
		t.Errorf("GetInt 預設 = %d, want 0（永久）", got)
	}
	// 出現在 List（政策頁讀取面）
	found := false
	for _, v := range svc.List() {
		if v.Key == PolicyRetentionCheckpointDays {
			found = true
			if v.UnitKey != "days" {
				t.Errorf("List 中 unit_key=%q, want days", v.UnitKey)
			}
			if v.Compliant != nil {
				t.Error("無 PCIValue 的鍵不得產生符合性判定")
			}
		}
	}
	if !found {
		t.Error("retention_checkpoint_days 未出現在 List()")
	}
}

// TestRetentionCoversZeroIsInfinity 比較器本身：0 = 無限大。
//
// 單獨測它是因為**方向搞反不會被上層測試抓到**——上層只看「拒絕/通過」，
// 而把 0 當成「最短」會讓「資料永久、檢查點 10 年」通過，那正是本約束
// 要擋的唯一致命組合
func TestRetentionCoversZeroIsInfinity(t *testing.T) {
	cases := []struct {
		cp, data int
		want     bool
		why      string
	}{
		{3650, 365, true, "檢查點久於資料"},
		{365, 365, true, "等長（spec 是 SHALL NOT 低於，等長合規）"},
		{365, 730, false, "檢查點短於資料"},
		{0, 3650, true, "檢查點永久涵蓋一切"},
		{3650, 0, false, "資料永久、檢查點有期＝證明先於資料消失"},
		{0, 0, true, "兩側皆永久"},
	}
	for _, c := range cases {
		if got := RetentionCovers(c.cp, c.data); got != c.want {
			t.Errorf("RetentionCovers(%d,%d) = %v, want %v（%s）", c.cp, c.data, got, c.want, c.why)
		}
	}
}

// TestCrossKeyRetention 7.3：五個 scenario（spec 場景逐條對應）。
//
// 每個 scenario 都同時斷言「回傳的錯誤型別可帶出鍵名」與「DB 無任一鍵被改」
// ——批次原子語義若破了，錯誤訊息正確也沒有意義
func TestCrossKeyRetention(t *testing.T) {
	tests := []struct {
		name    string
		seed    map[string]string // 前置現值（經合法路徑寫入）
		updates map[string]string
		wantErr bool
		wantKey string
	}{
		{
			name:    "低於資料鍵：checkpoint=365 而 audit_logs=730",
			seed:    map[string]string{PolicyRetentionAuditLogDays: "730"},
			updates: map[string]string{PolicyRetentionCheckpointDays: "365"},
			wantErr: true, wantKey: PolicyRetentionAuditLogDays,
		},
		{
			// 種子把另外三個資料鍵設成有期：**觸及即全驗**（D-5）之下，
			// 出廠的 0（永久）會先絆倒判定，那不是本 scenario 要測的關係
			name: "調升資料鍵越界：checkpoint=1000 而錄影調到 2000",
			seed: map[string]string{
				PolicyRetentionCheckpointDays:     "1000",
				PolicyRetentionAuditLogDays:       "365",
				PolicyRetentionSessionCommandDays: "365",
				PolicyRetentionAlertDays:          "365",
			},
			updates: map[string]string{PolicyRetentionRecordingDays: "2000"},
			wantErr: true, wantKey: PolicyRetentionRecordingDays,
		},
		{
			name:    "0 視為無限大：audit_logs=0（永久）時 checkpoint 只能 0",
			seed:    map[string]string{PolicyRetentionAuditLogDays: "0"},
			updates: map[string]string{PolicyRetentionCheckpointDays: "3650"},
			wantErr: true, wantKey: PolicyRetentionAuditLogDays,
		},
		{
			name:    "0 視為無限大：兩側皆 0 合法",
			seed:    map[string]string{PolicyRetentionAuditLogDays: "0"},
			updates: map[string]string{PolicyRetentionCheckpointDays: "0"},
		},
		{
			// 種子把另外三個資料鍵設成有期：出廠它們是 0（永久），而觸及
			// 保留鍵即對四個資料鍵全驗，未帶入批次的 0 會先絆倒判定。
			// 這是語義正確的結果（資料永久則證明必須永久），spec 場景
			//「同批次雙側調整以終值判定」的前提已同步補上此條件
			name: "同批雙側以終值判定（合法）",
			seed: map[string]string{
				PolicyRetentionSessionCommandDays: "365",
				PolicyRetentionAlertDays:          "365",
				PolicyRetentionRecordingDays:      "90",
			},
			updates: map[string]string{
				PolicyRetentionAuditLogDays:   "1000",
				PolicyRetentionCheckpointDays: "2000",
			},
		},
		{
			name: "同批雙側以終值判定（違法）",
			seed: map[string]string{
				PolicyRetentionSessionCommandDays: "365",
				PolicyRetentionAlertDays:          "365",
				PolicyRetentionRecordingDays:      "90",
			},
			updates: map[string]string{
				PolicyRetentionAuditLogDays:   "2000",
				PolicyRetentionCheckpointDays: "1000",
			},
			wantErr: true, wantKey: PolicyRetentionAuditLogDays,
		},
		{
			// 順序不影響結果：同一批次的兩個鍵互換角色仍以終值判定
			name: "同批雙側：資料鍵在前或在後結果相同",
			seed: map[string]string{
				PolicyRetentionAuditLogDays:       "365",
				PolicyRetentionSessionCommandDays: "365",
				PolicyRetentionAlertDays:          "365",
				PolicyRetentionRecordingDays:      "90",
			},
			updates: map[string]string{
				PolicyRetentionCheckpointDays:     "1000",
				PolicyRetentionSessionCommandDays: "2000",
			},
			wantErr: true, wantKey: PolicyRetentionSessionCommandDays,
		},
		{
			name: "合法組合不受影響：資料鍵調整未越界",
			seed: map[string]string{
				PolicyRetentionCheckpointDays:     "3650",
				PolicyRetentionAuditLogDays:       "365",
				PolicyRetentionSessionCommandDays: "365",
			},
			updates: map[string]string{PolicyRetentionAlertDays: "365"},
		},
		{
			name:    "不相干鍵不觸發跨鍵驗證",
			updates: map[string]string{PolicyPasswordMinLength: "16"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, _ := setupPolicyDB(t)
			for k, v := range tt.seed {
				// 種子經 crossKey=false 寫入：本測要造的是「現值」，
				// 不是「這一批是否合法」（出廠 audit_logs=0 使部分種子
				// 本身即違反約束，那正是要測的前置狀態）
				if _, err := svc.updateBatch(map[string]string{k: v}, "seed", false); err != nil {
					t.Fatalf("種子 %s=%s: %v", k, v, err)
				}
			}
			before := map[string]string{}
			for k := range tt.updates {
				before[k] = svc.Get(k)
			}

			_, err := svc.UpdateBatch(tt.updates, "admin")
			if !tt.wantErr {
				if err != nil {
					t.Fatalf("want 通過，got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("want 拒絕，got nil")
			}
			var crossKey *PolicyRetentionCrossKeyError
			if !errors.As(err, &crossKey) {
				t.Fatalf("錯誤型別 = %T (%v), want *PolicyRetentionCrossKeyError", err, err)
			}
			if !errors.Is(err, ErrPolicyRetentionCrossKey) {
				t.Error("errors.Is 無法比對 sentinel")
			}
			if crossKey.Key != tt.wantKey {
				t.Errorf("Key = %s, want %s", crossKey.Key, tt.wantKey)
			}
			if _, ok := policyKeyAllowlistProbe[crossKey.Key]; !ok {
				t.Errorf("錯誤帶出的鍵 %q 不在 apierror 允許清單內（params 會被丟棄）", crossKey.Key)
			}
			// 整批拒絕：DB 無任一鍵被改
			for k, v := range before {
				if now := svc.Get(k); now != v {
					t.Errorf("整批應拒絕，但 %s 由 %s 變成 %s", k, v, now)
				}
			}
		})
	}
}

// TestCrossKeyRetentionDoesNotBlockFactoryState D-5 驗收 (a)：出廠狀態下
// 逐一調整四個資料保留鍵為任意合法值皆須通過（全域驗不產生誤擋）。
//
// **這條與全域驗是同一個裁決的兩半**：全域驗之所以可行，全靠出廠
// `retention_checkpoint_days=0`（永久）使 `RetentionCovers(0, 任意)` 恆真。
// 有人把出廠值改回 3650 時，本測會在四個子案全部轉紅——那正是要擋的回歸
func TestCrossKeyRetentionDoesNotBlockFactoryState(t *testing.T) {
	// 前提自證（否則本測是零觸發的假綠）：出廠五鍵確實自洽
	base, _ := setupPolicyDB(t)
	if got := base.GetInt(PolicyRetentionCheckpointDays); got != 0 {
		t.Fatalf("前提破了：出廠 checkpoint 保留 = %d, want 0（永久）", got)
	}
	for _, key := range dataRetentionKeys {
		if !RetentionCovers(base.GetInt(PolicyRetentionCheckpointDays), base.GetInt(key)) {
			t.Fatalf("前提破了：出廠狀態下 %s 已違反跨鍵約束", key)
		}
	}

	// 四個資料保留鍵逐一設成任意合法值（含 0＝永久與天花板 3650）皆須 200
	for _, key := range dataRetentionKeys {
		for _, value := range []string{"0", "1", "365", "3650"} {
			t.Run(key+"="+value, func(t *testing.T) {
				svc, _ := setupPolicyDB(t)
				if _, err := svc.UpdateBatch(map[string]string{key: value}, "admin"); err != nil {
					t.Fatalf("出廠狀態下把 %s 設為 %s 被誤擋: %v", key, value, err)
				}
				if got := svc.Get(key); got != value {
					t.Errorf("%s = %s, want %s", key, got, value)
				}
			})
		}
	}

	// 四鍵同批一起設也不得被擋
	svc, _ := setupPolicyDB(t)
	all := map[string]string{}
	for _, key := range dataRetentionKeys {
		all[key] = "3650"
	}
	if _, err := svc.UpdateBatch(all, "admin"); err != nil {
		t.Fatalf("出廠狀態下四個資料鍵同批設 3650 被誤擋: %v", err)
	}
}

// TestCrossKeyRetentionGlobalClosesBypass D-5 驗收 (b)：檢查點鍵設有期值後，
// **單獨**（同批不帶檢查點鍵）調升任一資料鍵越過它必被拒。
//
// 逐鍵跑而非只跑一個：只驗一個鍵的話，validator 少列一個鍵不會有任何測試轉紅
func TestCrossKeyRetentionGlobalClosesBypass(t *testing.T) {
	for _, key := range dataRetentionKeys {
		t.Run(key, func(t *testing.T) {
			svc, _ := setupPolicyDB(t)
			// 先把四個資料鍵設成有期（合法，因出廠 checkpoint=0 涵蓋一切）
			base := map[string]string{}
			for _, k := range dataRetentionKeys {
				base[k] = "90"
			}
			if _, err := svc.UpdateBatch(base, "admin"); err != nil {
				t.Fatalf("前置：四個資料鍵設 90: %v", err)
			}
			// 再把檢查點鍵設成有期值（此時合法）
			if _, err := svc.UpdateBatch(
				map[string]string{PolicyRetentionCheckpointDays: "365"}, "admin"); err != nil {
				t.Fatalf("前置：checkpoint=365: %v", err)
			}
			// 單獨調升該資料鍵越過檢查點鍵——舊的「只驗觸及關係」在此仍會擋，
			// 但它擋不住「批次外造成的違規續存」，故本測與下方 Silent 測互補
			_, err := svc.UpdateBatch(map[string]string{key: "3650"}, "admin")
			var crossKey *PolicyRetentionCrossKeyError
			if !errors.As(err, &crossKey) {
				t.Fatalf("%s 單獨調升到 3650（checkpoint=365）應被拒，got %v", key, err)
			}
			if crossKey.Key != key || crossKey.CheckpointDays != 365 {
				t.Errorf("錯誤 = key %s / cp %d, want %s / 365", crossKey.Key, crossKey.CheckpointDays, key)
			}
			if got := svc.Get(key); got != "90" {
				t.Errorf("整批應拒絕，但 %s 變成 %s", key, got)
			}
		})
	}
}

// TestCrossKeyRetentionGlobalSurfacesSilentViolation 全域驗相對「只驗觸及關係」
// 的實質增益：批次外造成的違規在下一次任何保留鍵編輯時即現形。
//
// 違規來源用 SeedFromEnv（跨鍵約束的明文豁免入口），故這不是假想情境
func TestCrossKeyRetentionGlobalSurfacesSilentViolation(t *testing.T) {
	svc, _ := setupPolicyDB(t)
	// 前置：除錄影外的三個資料鍵與檢查點鍵設成合法組合。
	// **刻意不寫錄影的列**——`SeedFromEnv` 只在該鍵尚無列時才播種
	seed := map[string]string{PolicyRetentionCheckpointDays: "365"}
	for _, k := range dataRetentionKeys {
		if k != PolicyRetentionRecordingDays {
			seed[k] = "90"
		}
	}
	if _, err := svc.UpdateBatch(seed, "admin"); err != nil {
		t.Fatalf("前置: %v", err)
	}
	// 豁免入口造出違規：錄影保留永久、檢查點只留 365 天
	t.Setenv("RECORDING_RETENTION_DAYS", "0")
	svc.SeedFromEnv(PolicyRetentionRecordingDays, "RECORDING_RETENTION_DAYS")
	if got := svc.Get(PolicyRetentionRecordingDays); got != "0" {
		t.Fatalf("前提破了：豁免入口未生效，錄影保留 = %s", got)
	}

	// 此後任何保留鍵編輯（此處是與錄影完全無關的告警保留期）都會撞上該違規
	_, err := svc.UpdateBatch(map[string]string{PolicyRetentionAlertDays: "30"}, "admin")
	var crossKey *PolicyRetentionCrossKeyError
	if !errors.As(err, &crossKey) {
		t.Fatalf("批次外造成的違規應在下一次保留鍵編輯時現形，got %v", err)
	}
	if crossKey.Key != PolicyRetentionRecordingDays {
		t.Errorf("現形的鍵 = %s, want %s", crossKey.Key, PolicyRetentionRecordingDays)
	}
	// 修法路徑存在且不被自己擋住：同批把檢查點鍵一併設為 0（永久）即通過
	if _, err := svc.UpdateBatch(map[string]string{
		PolicyRetentionAlertDays:      "30",
		PolicyRetentionCheckpointDays: "0",
	}, "admin"); err != nil {
		t.Fatalf("同批修正（檢查點改永久）應通過: %v", err)
	}
}

// TestCrossKeyRetentionCoversAllDataKeys 四個資料保留鍵逐一都被涵蓋。
//
// 沒有這條時，validator 少列一個鍵（例如漏掉 session_commands）不會有任何
// 測試轉紅——被漏掉的那類資料就能悄悄設定成比檢查點更長的保留期
func TestCrossKeyRetentionCoversAllDataKeys(t *testing.T) {
	// 逐字釘住清單成員（10.1 的「放寬方向」）：只斷言筆數的話，
	// 有人把 audit_logs 換成一個不受鏈保護的鍵仍會全綠
	want := map[string]bool{
		PolicyRetentionAuditLogDays:       true,
		PolicyRetentionSessionCommandDays: true,
		PolicyRetentionAlertDays:          true,
		PolicyRetentionRecordingDays:      true,
	}
	if len(dataRetentionKeys) != len(want) {
		t.Fatalf("dataRetentionKeys 共 %d 鍵，want %d：%v", len(dataRetentionKeys), len(want), dataRetentionKeys)
	}
	for _, key := range dataRetentionKeys {
		if !want[key] {
			t.Errorf("dataRetentionKeys 多出 %q：本清單只放「被檢查點鏈證明的審計資料」", key)
		}
		delete(want, key)
	}
	for key := range want {
		t.Errorf("dataRetentionKeys 缺少 %q：該類資料可設定成比檢查點更長的保留期而無人擋", key)
	}
	for _, key := range dataRetentionKeys {
		t.Run(key, func(t *testing.T) {
			svc, _ := setupPolicyDB(t)
			// 種子：四個資料鍵都設成短於檢查點鍵的有期值，使唯一的違反
			// 來源是待測的那一個鍵（觸及即全驗之下，殘留的 0 會先絆倒判定）
			seed := map[string]string{PolicyRetentionCheckpointDays: "365"}
			for _, k := range dataRetentionKeys {
				seed[k] = "90"
			}
			if _, err := svc.updateBatch(seed, "seed", false); err != nil {
				t.Fatalf("種子: %v", err)
			}
			_, err := svc.UpdateBatch(map[string]string{key: "730"}, "admin")
			var crossKey *PolicyRetentionCrossKeyError
			if !errors.As(err, &crossKey) || crossKey.Key != key {
				t.Fatalf("%s=730 對 checkpoint=365 應被拒，got %v", key, err)
			}
			if crossKey.DataDays != 730 || crossKey.CheckpointDays != 365 {
				t.Errorf("錯誤攜帶的天數 = data %d / cp %d, want 730 / 365",
					crossKey.DataDays, crossKey.CheckpointDays)
			}
		})
	}
}

// TestCrossKeyRetentionSeedFromEnvExempt SeedFromEnv 不受跨鍵約束。
//
// 理由見 SeedFromEnv 註解：`RECORDING_RETENTION_DAYS=0` 的既有部署若被擋，
// 錄影保留會靜默退回出廠 90 天而開始刪本應永久保留的錄影。本測釘住這條
// 例外是**刻意的**，日後有人「順手」把它收進約束時會轉紅並讀到理由
func TestCrossKeyRetentionSeedFromEnvExempt(t *testing.T) {
	svc, _ := setupPolicyDB(t)
	// 出廠 checkpoint=0（永久）涵蓋一切，「錄影永久」本身不違規；先把檢查點鍵
	// 設成有期值，才存在要被豁免的那個衝突。錄影鍵**刻意不寫列**——
	// `SeedFromEnv` 只在該鍵尚無列時播種
	seed := map[string]string{PolicyRetentionCheckpointDays: "3650"}
	for _, k := range dataRetentionKeys {
		if k != PolicyRetentionRecordingDays {
			seed[k] = "90"
		}
	}
	if _, err := svc.UpdateBatch(seed, "admin"); err != nil {
		t.Fatalf("前置: %v", err)
	}
	t.Setenv("RECORDING_RETENTION_DAYS", "0")
	svc.SeedFromEnv(PolicyRetentionRecordingDays, "RECORDING_RETENTION_DAYS")

	if got := svc.Get(PolicyRetentionRecordingDays); got != "0" {
		t.Fatalf("env 種子未生效：錄影保留 = %s, want 0（升級相容優先於跨鍵約束）", got)
	}
	// 但同一組合經 admin API 路徑必被拒
	if _, err := svc.UpdateBatch(map[string]string{PolicyRetentionRecordingDays: "0"}, "admin"); err == nil {
		t.Error("admin 路徑設錄影永久（checkpoint=3650）應被拒")
	}
}

// policyKeyAllowlistProbe 本包對 apierror 允許清單的最小複本（只放本組會用到的鍵）。
// 完整雙向一致性由 TestPolicyKeyAllowlistCoversDefs 承擔，此處只確保
// 跨鍵錯誤帶出的鍵確實可出 wire
var policyKeyAllowlistProbe = map[string]struct{}{
	PolicyRetentionAuditLogDays:       {},
	PolicyRetentionSessionCommandDays: {},
	PolicyRetentionAlertDays:          {},
	PolicyRetentionRecordingDays:      {},
	PolicyRetentionCheckpointDays:     {},
}

// TestCrossKeyRetentionMaxBoundary 7.2（O5）：Max 3650 之下，資料鍵設到天花板
// 時檢查點鍵仍有合法解——這是「維持 3650」這個判定的成立條件。
func TestCrossKeyRetentionMaxBoundary(t *testing.T) {
	svc, _ := setupPolicyDB(t)
	// 出廠三個資料鍵為 0（永久），觸及檢查點鍵時會全驗；先把它們設成有期
	if _, err := svc.UpdateBatch(map[string]string{
		PolicyRetentionSessionCommandDays: "3650",
		PolicyRetentionAlertDays:          "3650",
		PolicyRetentionRecordingDays:      "3650",
	}, "admin"); err != nil {
		t.Fatalf("前置：把三個資料鍵設到天花板: %v", err)
	}
	// 同批把資料鍵推到天花板、檢查點鍵也設天花板
	if _, err := svc.UpdateBatch(map[string]string{
		PolicyRetentionAuditLogDays:   strconv.Itoa(3650),
		PolicyRetentionCheckpointDays: strconv.Itoa(3650),
	}, "admin"); err != nil {
		t.Fatalf("資料鍵與檢查點鍵同為 3650 應通過（等長合規）: %v", err)
	}
	// 另一個合法解：檢查點永久
	if _, err := svc.UpdateBatch(map[string]string{PolicyRetentionCheckpointDays: "0"}, "admin"); err != nil {
		t.Fatalf("資料鍵 3650 時檢查點設永久應通過: %v", err)
	}
	// 超過天花板由單鍵驗證擋下（跨鍵驗證之前）
	_, err := svc.UpdateBatch(map[string]string{PolicyRetentionCheckpointDays: "7300"}, "admin")
	var invalid *PolicyInvalidValueError
	if !errors.As(err, &invalid) {
		t.Fatalf("7300 應由單鍵上界擋下，got %v", err)
	}
}
