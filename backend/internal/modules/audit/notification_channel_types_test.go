package audit

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
)

// TestChannelTypeRegistryCapabilities 三種型別的四個能力值與 design 決策 5 的表格逐格相同；登錄以外的型別被拒。
func TestChannelTypeRegistryCapabilities(t *testing.T) {
	want := map[string]ChannelCapabilities{
		"webhook":   {CanTargetUser: false, SupportsLinks: true, SignsBody: true, RendersText: false},
		"slack":     {CanTargetUser: false, SupportsLinks: true, SignsBody: false, RendersText: true},
		"slack_app": {CanTargetUser: true, SupportsLinks: true, SignsBody: false, RendersText: true},
	}
	if got := ChannelTypeKeys(); strings.Join(got, ",") != "slack,slack_app,webhook" {
		t.Fatalf("登錄的型別 = %v，want slack、slack_app、webhook", got)
	}
	for key, caps := range want {
		d, ok := ChannelType(key)
		if !ok {
			t.Fatalf("型別 %s 不在登錄中", key)
		}
		if d.Caps != caps {
			t.Errorf("型別 %s 的能力 = %+v，want %+v", key, d.Caps, caps)
		}
		if d.Key != key {
			t.Errorf("型別 %s 的描述鍵為 %q", key, d.Key)
		}
		if !model.ValidNotificationChannelType(key) {
			t.Errorf("model.ValidNotificationChannelType(%q) = false", key)
		}
	}
	// 設定欄位：只有 slack_app 需要目標、秘密必填且是 token；webhook 的簽章密鑰選填；slack 沒有秘密
	if d, _ := ChannelType("slack_app"); !d.Fields.NeedsTarget || d.Fields.Secret != ChannelSecretBearerToken || !d.Fields.SecretRequired || d.MaxPerSecond != 1 || d.Fields.DefaultURL == "" {
		t.Errorf("slack_app 設定欄位不符: %+v max=%v", d.Fields, d.MaxPerSecond)
	}
	if d, _ := ChannelType("webhook"); d.Fields.NeedsTarget || d.Fields.Secret != ChannelSecretSigningKey || d.Fields.SecretRequired || d.MaxPerSecond != 0 {
		t.Errorf("webhook 設定欄位不符: %+v", d.Fields)
	}
	if d, _ := ChannelType("slack"); d.Fields.NeedsTarget || d.Fields.Secret != ChannelSecretNone || d.MaxPerSecond != 0 {
		t.Errorf("slack 設定欄位不符: %+v", d.Fields)
	}
	// 登錄以外的型別
	if _, ok := ChannelType("teams"); ok {
		t.Error("teams 不應在登錄中")
	}
	if model.ValidNotificationChannelType("teams") {
		t.Error("model.ValidNotificationChannelType(teams) = true")
	}
	if err := validateChannel(&NotificationChannelRequest{Name: "x", Type: "teams", URL: "https://example.invalid/h"}); err != ErrInvalidChannelTyp {
		t.Errorf("teams 通道的驗證結果 = %v，want ErrInvalidChannelTyp", err)
	}
}

// channelTypeRegistryFile 型別常數唯一允許出現的非測試檔。
const channelTypeRegistryFile = "notification_channel_types.go"

// channelTypeConstRe 通道型別常數的識別字。
var channelTypeConstRe = regexp.MustCompile(`^NotificationChannelType[A-Z]\w*$`)

// TestChannelTypeLiteralsOnlyInRegistry modules/audit 的非測試檔中，通道型別常數只准出現在登錄檔；
// 其他位置一律經型別描述操作。失敗時列出檔名與行號。
func TestChannelTypeLiteralsOnlyInRegistry(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var violations []string
	scanned, registryHits := 0, 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatalf("解析 %s 失敗: %v", f, err)
		}
		scanned++
		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok || !channelTypeConstRe.MatchString(sel.Sel.Name) {
				return true
			}
			if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "model" {
				return true
			}
			if f == channelTypeRegistryFile {
				registryHits++
				return true
			}
			violations = append(violations, fset.Position(sel.Pos()).String()+" 使用 model."+sel.Sel.Name)
			return true
		})
	}
	if scanned < 50 {
		t.Fatalf("只掃到 %d 個非測試檔：掃描範圍已失真", scanned)
	}
	if registryHits < 3 {
		t.Fatalf("登錄檔只出現 %d 次型別常數：登錄檔已改名或守衛的比對失真", registryHits)
	}
	sort.Strings(violations)
	if len(violations) > 0 {
		t.Fatalf("通道型別常數只准出現在 %s（其他位置經型別描述操作）：\n  %s",
			channelTypeRegistryFile, strings.Join(violations, "\n  "))
	}
}

// frontendChannelConstantsMount dev compose 於 backend 容器內的唯讀掛載點（相對本套件目錄）。
const frontendChannelConstantsMount = "../../../testdata/frontend-constants/notification-channels.js"

// frontendChannelConstantsRel host 直跑時相對專案根的路徑。
const frontendChannelConstantsRel = "frontend/src/constants/notification-channels.js"

// frontendChannelTypePending 登錄已有、前端表單尚未提供的型別（燒盡制）：每一列都必須寫明由哪一段補上，
// 補上後移除；殘留的列會讓守衛失敗。
var frontendChannelTypePending = map[string]string{}

var channelTypeValuesRe = regexp.MustCompile(`(?s)export const CHANNEL_TYPE_VALUES\s*=\s*\[([^\]]*)\]`)

// channelTypesTargetUserRe 前端「能以個人為對象的型別」清單（決定表單是否顯示對個人派送開關）。
var channelTypesTargetUserRe = regexp.MustCompile(`(?s)export const CHANNEL_TYPES_TARGET_USER\s*=\s*\[([^\]]*)\]`)

func readFrontendChannelTypes(t *testing.T) []string {
	t.Helper()
	return readFrontendStringArray(t, channelTypeValuesRe, "CHANNEL_TYPE_VALUES")
}

// readFrontendStringArray 從前端通道常數檔讀出一個字串陣列常數；缺檔或找不到常數即失敗（不跳過）。
func readFrontendStringArray(t *testing.T, re *regexp.Regexp, name string) []string {
	t.Helper()
	path := frontendChannelConstantsMount
	if _, err := os.Stat(path); err != nil {
		path = filepath.Join("..", "..", "..", "..", filepath.FromSlash(frontendChannelConstantsRel))
	}
	raw, err := os.ReadFile(path) //nolint:gosec // 測試資料路徑
	if err != nil {
		t.Fatalf("讀取前端通道常數 %s 失敗（守衛不得在缺檔時跳過）: %v", path, err)
	}
	m := re.FindSubmatch(raw)
	if m == nil {
		t.Fatalf("%s 找不到 %s：前端表單的型別來源已改變", path, name)
	}
	var out []string
	for _, part := range strings.Split(string(m[1]), ",") {
		v := strings.Trim(strings.TrimSpace(part), `'"`)
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

// TestChannelTypesTargetUserMatchFrontend 前端 CHANNEL_TYPES_TARGET_USER＝型別描述宣告能以個人為對象、且接上了
// 以電子郵件查詢使用者的型別（通道服務允許開啟對個人派送的同一判準）。兩邊不一致時，表單會對不能開啟的型別
// 顯示開關（儲存必被拒），或對能開啟的型別藏起開關。
func TestChannelTypesTargetUserMatchFrontend(t *testing.T) {
	var backend []string
	for _, k := range ChannelTypeKeys() {
		desc, _ := ChannelType(k)
		if desc.Caps.CanTargetUser && desc.lookupUser != nil {
			backend = append(backend, k)
		}
	}
	if len(backend) == 0 {
		t.Fatal("後端沒有任何能以個人為對象的型別：判準或登錄已改變，守衛的比對失真")
	}
	front := readFrontendStringArray(t, channelTypesTargetUserRe, "CHANNEL_TYPES_TARGET_USER")
	sort.Strings(backend)
	sort.Strings(front)
	if strings.Join(front, ",") != strings.Join(backend, ",") {
		t.Fatalf("前端 CHANNEL_TYPES_TARGET_USER = %v，後端能以個人為對象的型別 = %v", front, backend)
	}
}

// TestChannelTypeRegistryMatchesConstraintsAndForm 登錄的鍵集合＝通道表型別約束的值域＝待投遞表型別約束的值域
// （扣除不帶快照的空字串）＝前端通道表單的選項（扣除燒盡制待補列）。
func TestChannelTypeRegistryMatchesConstraintsAndForm(t *testing.T) {
	registry := ChannelTypeKeys()
	setOf := func(xs []string) string {
		cp := append([]string(nil), xs...)
		sort.Strings(cp)
		return strings.Join(cp, ",")
	}
	want := setOf(registry)

	channelCheck, ok := database.SchemaCheckInValues("notification_channels_type_check")
	if !ok {
		t.Fatal("schema DDL 找不到 notification_channels_type_check")
	}
	if got := setOf(channelCheck); got != want {
		t.Errorf("通道表型別約束值域 = %s，登錄 = %s", got, want)
	}

	outboxCheck, ok := database.SchemaCheckInValues("system_alert_outbox_dest_type_check")
	if !ok {
		t.Fatal("schema DDL 找不到 system_alert_outbox_dest_type_check")
	}
	var outboxTypes []string
	sawEmpty := false
	for _, v := range outboxCheck {
		if v == "" {
			sawEmpty = true
			continue
		}
		outboxTypes = append(outboxTypes, v)
	}
	if !sawEmpty {
		t.Error("待投遞表型別約束缺少空字串（不帶快照的紀錄寫不進去）")
	}
	if got := setOf(outboxTypes); got != want {
		t.Errorf("待投遞表型別約束值域（扣除空字串）= %s，登錄 = %s", got, want)
	}

	front := readFrontendChannelTypes(t)
	usedPending := map[string]bool{}
	frontSet := map[string]bool{}
	for _, v := range front {
		frontSet[v] = true
		if _, pending := frontendChannelTypePending[v]; pending {
			t.Errorf("前端已提供 %s，frontendChannelTypePending 的該列 SHALL 移除", v)
		}
	}
	for _, key := range registry {
		if frontSet[key] {
			continue
		}
		if _, pending := frontendChannelTypePending[key]; pending {
			usedPending[key] = true
			continue
		}
		t.Errorf("登錄的型別 %s 不在前端通道表單的選項中", key)
	}
	for v := range frontSet {
		if _, ok := ChannelType(v); !ok {
			t.Errorf("前端通道表單的選項 %s 不在登錄中", v)
		}
	}
	for key := range frontendChannelTypePending {
		if !usedPending[key] && !frontSet[key] {
			t.Errorf("frontendChannelTypePending 的 %s 已不在登錄中，SHALL 移除", key)
		}
	}
}

// TestDirectMessageCheckMatchesRegistry 「對個人派送只限能以個人為對象的型別」的資料庫約束與型別登錄一致：
// 約束放行的型別集合＝登錄中宣告 CanTargetUser 的型別集合（新增能以個人為對象的型別時兩邊一起改）。
func TestDirectMessageCheckMatchesRegistry(t *testing.T) {
	def, ok := database.SchemaCheckDefinition("notification_channels_direct_message_type_check")
	if !ok {
		t.Fatal("schema DDL 找不到 notification_channels_direct_message_type_check")
	}
	if !strings.HasPrefix(def, "NOT direct_message_enabled OR ") {
		t.Fatalf("約束的形狀不是「未開啟或型別屬於清單」: %s", def)
	}
	var allowed []string
	for _, m := range regexp.MustCompile(`type = '([a-z_]+)'`).FindAllStringSubmatch(def, -1) {
		allowed = append(allowed, m[1])
	}
	var capable []string
	for _, key := range ChannelTypeKeys() {
		if d, _ := ChannelType(key); d.Caps.CanTargetUser {
			capable = append(capable, key)
		}
	}
	sort.Strings(allowed)
	sort.Strings(capable)
	if strings.Join(allowed, ",") != strings.Join(capable, ",") || len(capable) == 0 {
		t.Errorf("約束放行的型別 %v，登錄中能以個人為對象的型別 %v", allowed, capable)
	}
}
