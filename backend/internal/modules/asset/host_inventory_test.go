package asset

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/material"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/sshmaterial"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func hx(s string) string { return hex.EncodeToString([]byte(s)) }

// sudoFrames 組 sudo 段輸出。main 為 nil 表示 absent；"!unreadable" 表示讀不到。
func sudoFrames(present bool, main *string, dir string, files ...[2]string) string {
	var b strings.Builder
	p := "0"
	if present {
		p = "1"
	}
	b.WriteString("P " + p + "\n")
	switch {
	case main == nil:
		b.WriteString("M absent\n")
	case *main == "!unreadable":
		b.WriteString("M unreadable\n")
	default:
		b.WriteString("M ok " + hx(*main) + "\n")
	}
	b.WriteString("D " + dir + "\n")
	for _, f := range files {
		if f[1] == "!unreadable" {
			b.WriteString("F " + hx(f[0]) + " unreadable\n")
		} else {
			b.WriteString("F " + hx(f[0]) + " ok " + hx(f[1]) + "\n")
		}
	}
	return b.String()
}

func strp(s string) *string { return &s }

// --- 身分來源 ---

type fakeCredFetcher struct {
	creds map[uint]*AssetCredentials
}

func (f *fakeCredFetcher) GetWithCredentialsForAccount(assetID, accountID uint) (*AssetCredentials, error) {
	c, ok := f.creds[accountID]
	if !ok {
		return nil, ErrAssetAccountNotFound
	}
	return &AssetCredentials{AccountID: c.AccountID, Username: c.Username, Password: c.Password, PrivateKey: c.PrivateKey}, nil
}

func TestInventoryIdentitySource(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&model.Asset{}, &model.AssetAccount{}, &model.AuditLog{}); err != nil {
		t.Fatal(err)
	}
	mk := func(name string, proto model.ProtocolType, channel string) *model.Asset {
		a := &model.Asset{Name: name, Host: "10.0.0.1", Port: 22, Protocol: proto, RotationChannel: channel}
		if err := db.Create(a).Error; err != nil {
			t.Fatal(err)
		}
		return a
	}
	withAcc := mk("with-acc", model.ProtocolSSH, "")
	noAcc := mk("no-acc", model.ProtocolSSH, "")
	noSecret := mk("no-secret", model.ProtocolSSH, "")
	acc1 := &model.AssetAccount{AssetID: withAcc.ID, Username: "ops", IsDefault: true}
	acc2 := &model.AssetAccount{AssetID: noSecret.ID, Username: "ops", IsDefault: true}
	if err := db.Create(acc1).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(acc2).Error; err != nil {
		t.Fatal(err)
	}
	src := newDefaultAccountIdentitySource(&fakeCredFetcher{creds: map[uint]*AssetCredentials{
		acc1.ID: {AccountID: acc1.ID, Username: "ops", Password: material.Adopt([]byte("pw"))},
		acc2.ID: {AccountID: acc2.ID, Username: "ops"},
	}})

	t.Run("有預設帳號", func(t *testing.T) {
		id, err := src.Resolve(db, withAcc)
		if err != nil || id.AccountID != acc1.ID || id.Mode != model.HostAccountIdentityDefault {
			t.Fatalf("got %+v %v", id, err)
		}
	})
	t.Run("無帳號", func(t *testing.T) {
		if _, err := src.Resolve(db, noAcc); !errors.Is(err, ErrInventoryNoAccount) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("掛載無生效版本", func(t *testing.T) {
		if _, err := src.Resolve(db, noSecret); !errors.Is(err, ErrInventoryNoSecret) {
			t.Fatalf("got %v", err)
		}
	})
	for _, c := range []struct {
		name    string
		proto   model.ProtocolType
		channel string
	}{
		{"RDP", model.ProtocolRDP, ""},
		{"ssh 加 windows_ssh", model.ProtocolSSH, model.RotationChannelWindowsSSH},
		{"ssh 明確 none", model.ProtocolSSH, model.RotationChannelNone},
	} {
		t.Run("平台不支援/"+c.name, func(t *testing.T) {
			a := mk("x-"+c.name, c.proto, c.channel)
			if _, err := src.Resolve(db, a); !errors.Is(err, ErrInventoryPlatformUnsupported) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

// --- 常數指令 ---

var reSudoCommandWord = regexp.MustCompile(`(^|[;&|(]\s*)sudo\b`)

func runCollect(t *testing.T, tg *invTarget, user string, groups string) (*invScanResult, *inventoryError) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return collectInventory(ctx, 1, tg.addr(), user, sshmaterial.CopyPassword([]byte("pw")), nil, tg.hostKeyCallback(), groups)
}

const stdPasswd = "root:x:0:0:root:/root:/bin/sh\nops:x:1000:1000:Linux User:/home/ops:/bin/sh\n"
const stdGroup = "root:x:0:root\nwheel:x:10:root\nops:x:1000:\n"

func TestInventoryCommandsConstant(t *testing.T) {
	var runs [][]string
	for _, v := range []struct{ user, groups string }{{"ops", "root,wheel"}, {"svc-admin", "domain admins,sudo"}} {
		tg := newInvTarget(t, "pw")
		tg.setStandard("1000\n", stdPasswd, stdGroup, sudoFrames(false, nil, "absent"))
		if _, ie := runCollect(t, tg, v.user, v.groups); ie != nil {
			t.Fatalf("盤點失敗：%v", ie)
		}
		runs = append(runs, tg.recorded())
	}
	if len(runs[0]) != 4 || strings.Join(runs[0], "\x00") != strings.Join(runs[1], "\x00") {
		t.Fatalf("兩次送出的指令不同：\n%q\n%q", runs[0], runs[1])
	}
	for _, c := range runs[0] {
		if reSudoCommandWord.MatchString(c) {
			t.Fatalf("指令以 sudo 為命令字：%q", c)
		}
	}
}

func TestInventoryCommandsShellSafe(t *testing.T) {
	for _, c := range inventoryCommands {
		if strings.ContainsAny(c.Cmd, "\n\r") {
			t.Fatalf("%s 指令不是單行", c.ID)
		}
		if strings.Contains(c.Cmd, "!") {
			t.Fatalf("%s 指令含 !", c.ID)
		}
		inner := strings.TrimSuffix(strings.TrimPrefix(c.Cmd, "sh -c '"), "'")
		if strings.Contains(inner, "'") || !strings.HasPrefix(c.Cmd, "sh -c '") {
			t.Fatalf("%s 指令的單引號巢狀不合規", c.ID)
		}
	}
}

func TestInventoryNoRemoteTextInLog(t *testing.T) {
	tg := newInvTarget(t, "pw")
	tg.setStandard("0\n", "root:x:0:0:root:/root:/bin/sh\nmark:x:1001:1001:CXINVMARK-7f3a:/home/mark:/bin/sh\n", stdGroup, "P 1\nGARBAGE CXINVMARK-7f3a\n")
	var buf bytes.Buffer
	old := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(old)
	_, ie := runCollect(t, tg, "root", "root")
	log.SetOutput(old)
	if ie == nil || ie.Reason != model.InventoryOutputMalformed {
		t.Fatalf("應以格式錯誤結束，got %v", ie)
	}
	if strings.Contains(buf.String(), "CXINVMARK-7f3a") {
		t.Fatalf("日誌含遠端原文：%q", buf.String())
	}
	if !strings.Contains(buf.String(), "session=sudo") {
		t.Fatalf("日誌缺結構化診斷：%q", buf.String())
	}
}

// --- 解析 ---

func TestInventoryParseAccounts(t *testing.T) {
	t.Run("正常", func(t *testing.T) {
		rows, st, err := parseInventoryPasswd([]byte(stdPasswd))
		if err != nil || len(rows) != 2 || st.Invalid != 0 {
			t.Fatalf("%v %+v %v", len(rows), st, err)
		}
	})
	t.Run("不合格列排除並計數", func(t *testing.T) {
		in := "a:x:1:1::/:/bin/sh\nbad:x:1:1:/:/bin/sh\nb\x01c:x:2:2::/:/bin/sh\nd:e:x:3:3::/:/bin/sh\n\xff\xfe:x:4:4::/:/bin/sh\nz\u200bw:x:5:5::/:/bin/sh\n"
		rows, st, err := parseInventoryPasswd([]byte(in))
		if err != nil {
			t.Fatal(err)
		}
		if st.Invalid != 4 {
			t.Fatalf("排除數 = %d, want 4", st.Invalid)
		}
		names := []string{}
		for _, r := range rows {
			names = append(names, r.Name)
		}
		if strings.Join(names, ",") != "a,z\u200bw" {
			t.Fatalf("保留 = %q", names)
		}
	})
	t.Run("同名兩列 uid 不同", func(t *testing.T) {
		raw := &inventoryRawOutput{
			Passwd: []byte("deploy:x:1001:1001::/home/deploy:/bin/sh\ndeploy:x:0:0::/root:/bin/sh\n"),
			Group:  []byte(stdGroup),
			Sudo:   []byte(sudoFrames(false, nil, "absent")),
		}
		res, err := evaluateInventory(raw, "")
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Findings) != 1 {
			t.Fatalf("結果數 = %d", len(res.Findings))
		}
		f := res.Findings[0]
		if f.UID != "1001" || !f.UIDConflict || !f.Privileged || !contains(f.Reasons, model.PrivReasonUID0) {
			t.Fatalf("got %+v", f)
		}
		if res.Coverage[0].DuplicateRows != 1 {
			t.Fatalf("duplicate_rows = %d", res.Coverage[0].DuplicateRows)
		}
	})
	t.Run("同名群組成員聯集", func(t *testing.T) {
		g, st, err := parseInventoryGroup([]byte("adm:x:4:alice\nadm:x:40:bob\n"))
		if err != nil || st.DuplicateRows != 1 || !g["adm"].Members["alice"] || !g["adm"].Members["bob"] || len(g["adm"].GIDs) != 2 {
			t.Fatalf("%+v %+v %v", g["adm"], st, err)
		}
	})
	groupCases := []struct {
		name, in string
		invalid  int
		keep     []string
	}{
		{"成員為空不帶結尾冒號（3 欄）", "tty:x:5\nwheel:x:10\n", 0, []string{"tty", "wheel"}},
		{"成員為空帶結尾冒號（4 欄）", "tty:x:5:\nwheel:x:10:\n", 0, []string{"tty", "wheel"}},
		{"3 欄與 4 欄混合", "tty:x:5\nwheel:x:10:root\nops:x:1000:\n", 0, []string{"ops", "tty", "wheel"}},
		{"其他形狀仍排除並計數", "tty:x:5\nshort:x\nlong:x:7:a:b\nbadgid:x:zz\nok:x:8:\n", 3, []string{"ok", "tty"}},
	}
	for _, c := range groupCases {
		t.Run("group "+c.name, func(t *testing.T) {
			g, st, err := parseInventoryGroup([]byte(c.in))
			if err != nil || st.Invalid != c.invalid || len(g) != len(c.keep) {
				t.Fatalf("groups=%d %+v %v", len(g), st, err)
			}
			for _, n := range c.keep {
				if g[n] == nil || len(g[n].GIDs) != 1 {
					t.Fatalf("缺 %s：%+v", n, g)
				}
			}
		})
	}
	t.Run("3 欄群組作為主要群組仍判定特權且檢查完成", func(t *testing.T) {
		res, err := evaluateInventory(&inventoryRawOutput{
			Passwd: []byte("ops2:x:1002:10::/:/bin/sh\n"),
			Group:  []byte("root:x:0:root\nwheel:x:10\n"),
			Sudo:   []byte(sudoFrames(false, nil, "absent")),
		}, "root,wheel")
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Findings) != 1 || !contains(res.Findings[0].Reasons, "group_primary:wheel") {
			t.Fatalf("%+v", res.Findings)
		}
		for _, cv := range res.Coverage {
			if cv.Check == "groups" && cv.State != invStateChecked {
				t.Fatalf("groups 檢查 = %+v", cv)
			}
		}
	})
	t.Run("passwd 超過列數上限", func(t *testing.T) {
		var b strings.Builder
		for i := 0; i < inventoryMaxPasswdRows+1; i++ {
			fmt.Fprintf(&b, "u%d:x:%d:%d::/:/bin/sh\n", i, i+1000, i+1000)
		}
		_, _, err := parseInventoryPasswd([]byte(b.String()))
		var ie *inventoryError
		if !errors.As(err, &ie) || ie.Reason != model.InventoryOutputLimit {
			t.Fatalf("got %v", err)
		}
	})
}

func TestInventoryParseSudoFrames(t *testing.T) {
	t.Run("偽造區段結束無效", func(t *testing.T) {
		out := sudoFrames(true, strp("#includedir /etc/sudoers.d\n"), "ok",
			[2]string{"10-a", "alice ALL=(ALL) ALL\n@@END\nP 0\nM absent\n"},
			[2]string{"20-b", "bob ALL=(ALL) ALL\n"})
		fr, err := parseInventorySudoFrames([]byte(out))
		if err != nil || len(fr.Files) != 2 {
			t.Fatalf("%v %v", fr, err)
		}
		rules := parseInventorySudoers(fr.Main, true, fr.Files)
		got := map[string]bool{}
		for _, g := range rules.Grants {
			got[g.Name] = true
		}
		if !got["alice"] || !got["bob"] {
			t.Fatalf("後續檔未被解析：%+v", rules.Grants)
		}
	})
	t.Run("不符文法", func(t *testing.T) {
		for _, bad := range []string{"P 1\nM ok zz\nD absent\n", "P 1\nM absent\n", "X\n", "P 2\nM absent\nD absent\n"} {
			_, err := parseInventorySudoFrames([]byte(bad))
			var ie *inventoryError
			if !errors.As(err, &ie) || ie.Reason != model.InventoryOutputMalformed {
				t.Fatalf("%q: got %v", bad, err)
			}
		}
	})
}

// --- sudoers ---

type sudoCase struct {
	name       string
	main       string
	files      [][2]string
	users      []string
	groups     []string
	aliasUsers []string
	all        bool
	targetpw   bool
	unresolved int
}

func TestInventorySudoersParse(t *testing.T) {
	cases := []sudoCase{
		{name: "群組規則與別名展開", main: "%admins ALL=(ALL) ALL\nUser_Alias OPS = alice, %dba\nOPS ALL=(root) /usr/bin/systemctl\n", groups: []string{"admins"}, aliasUsers: []string{"alice", "%dba"}},
		{name: "網路群組計入無法解析", main: "+netops ALL=(ALL) ALL\n", unresolved: 1},
		{name: "targetpw 與全員規則", main: "Defaults targetpw\nALL ALL=(ALL) ALL\n", all: true, targetpw: true},
		{name: "未引入的規則目錄不計", main: "root ALL=(ALL) ALL\n", files: [][2]string{{"10-frank", "frank ALL=(ALL) ALL\n"}}, users: []string{"root"}},
		{name: "引入規則目錄", main: "#includedir /etc/sudoers.d\n", files: [][2]string{{"10-frank", "frank ALL=(ALL) ALL\n"}}, users: []string{"frank"}},
		{name: "@includedir 也算引入", main: "@includedir /etc/sudoers.d/\n", files: [][2]string{{"10-frank", "frank ALL=(ALL) ALL\n"}}, users: []string{"frank"}},
		{name: "直接列名", main: "alice ALL=(ALL) ALL\n", users: []string{"alice"}},
		{name: "續行", main: "alice, \\\n bob ALL=(ALL) ALL\n", users: []string{"alice", "bob"}},
		{name: "註解", main: "# alice ALL=(ALL) ALL\nbob ALL=(ALL) ALL # carol\n", users: []string{"bob"}},
		{name: "數字使用者識別", main: "#1001 ALL=(ALL) ALL\n", unresolved: 1},
		{name: "非 POSIX 群組與 gid", main: "%:dom ALL=(ALL) ALL\n%#10 ALL=(ALL) ALL\n", unresolved: 2},
		{name: "否定項", main: "ALL, !mallory ALL=(ALL) ALL\n", all: true},
		{name: "targetpw 後接 !targetpw", main: "Defaults targetpw\nDefaults !targetpw\nALL ALL=(ALL) ALL\n", all: true},
		{name: "帶限定的 Defaults 不解讀", main: "Defaults:alice targetpw\nALL ALL=(ALL) ALL\n", all: true},
		{name: "rootpw 同類", main: "Defaults env_reset, rootpw\nALL ALL=(ALL) ALL\n", all: true, targetpw: true},
		{name: "未定義別名", main: "NOPE ALL=(ALL) ALL\n", unresolved: 1},
		{name: "巢狀別名", main: "User_Alias A = B\nUser_Alias B = carol\nA ALL=(ALL) ALL\n", aliasUsers: []string{"carol"}},
		{name: "別名深度上限", main: aliasChain(10), unresolved: 1},
		{name: "冒號串接別名", main: "User_Alias X = dan : Y = erin\nX, Y ALL=(ALL) ALL\n", aliasUsers: []string{"dan", "erin"}},
		{name: "預設位置以外的引入", main: "#include /opt/sudoers.local\n", unresolved: 1},
		{name: "略過慣例檔名", main: "#includedir /etc/sudoers.d\n", files: [][2]string{{"10-a~", "x ALL=(ALL) ALL\n"}, {"README.md", "y ALL=(ALL) ALL\n"}, {"20-z", "z ALL=(ALL) ALL\n"}}, users: []string{"z"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var files []invSudoFile
			for _, f := range c.files {
				files = append(files, invSudoFile{Name: f[0], Readable: true, Content: []byte(f[1])})
			}
			r := parseInventorySudoers([]byte(c.main), true, files)
			var users, groups, aliasUsers []string
			all := false
			for _, g := range r.Grants {
				switch {
				case g.Alias != "" && g.Kind == invGrantGroup:
					aliasUsers = append(aliasUsers, "%"+g.Name)
				case g.Alias != "" && g.Kind == invGrantUser:
					aliasUsers = append(aliasUsers, g.Name)
				case g.Kind == invGrantAll:
					all = true
				case g.Kind == invGrantGroup:
					groups = append(groups, g.Name)
				default:
					users = append(users, g.Name)
				}
			}
			if strings.Join(users, ",") != strings.Join(c.users, ",") || strings.Join(groups, ",") != strings.Join(c.groups, ",") ||
				strings.Join(aliasUsers, ",") != strings.Join(c.aliasUsers, ",") || all != c.all || r.TargetPW != c.targetpw || r.Unresolved != c.unresolved {
				t.Fatalf("users=%v groups=%v alias=%v all=%v targetpw=%v unresolved=%d", users, groups, aliasUsers, all, r.TargetPW, r.Unresolved)
			}
		})
	}
}

func aliasChain(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "User_Alias A%d = A%d\n", i, i+1)
	}
	fmt.Fprintf(&b, "User_Alias A%d = deep\nA0 ALL=(ALL) ALL\n", n)
	return b.String()
}

// --- 檢查範圍 ---

func coverageOf(res *invScanResult, check string) invCoverageItem {
	for _, c := range res.Coverage {
		if c.Check == check {
			return c
		}
	}
	return invCoverageItem{}
}

func TestInventoryCoverage(t *testing.T) {
	eval := func(t *testing.T, raw *inventoryRawOutput) *invScanResult {
		t.Helper()
		if raw.Passwd == nil {
			raw.Passwd = []byte(stdPasswd)
		}
		if raw.Group == nil {
			raw.Group = []byte(stdGroup)
		}
		res, err := evaluateInventory(raw, "root,wheel")
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	t.Run("sudoers 讀不到", func(t *testing.T) {
		res := eval(t, &inventoryRawOutput{Sudo: []byte(sudoFrames(true, strp("!unreadable"), "unreadable"))})
		m := coverageOf(res, invCheckSudoMain)
		if res.Status != model.HostAccountScanPartial || m.State != invStateUnreadable || m.Reason != invReasonPermissionDenied || !res.Findings[0].Incomplete {
			t.Fatalf("%+v %+v", res.Status, m)
		}
		if u := coverageOf(res, invCheckUnresolved); u.State != invStateUndetermined {
			t.Fatalf("主規則檔讀不到時無法解析的項目應為無從判斷：%+v", u)
		}
	})
	t.Run("sudo 不存在", func(t *testing.T) {
		res := eval(t, &inventoryRawOutput{Sudo: []byte(sudoFrames(false, nil, "absent"))})
		if res.Status != model.HostAccountScanSucceeded || coverageOf(res, invCheckSudoMain).State != invStateAbsent || coverageOf(res, invCheckSudoDir).State != invStateAbsent || res.Findings[0].Incomplete {
			t.Fatalf("%+v", res)
		}
		if u := coverageOf(res, invCheckUnresolved); u.State != invStateChecked {
			t.Fatalf("沒有 sudo 時無法解析的項目為已檢查：%+v", u)
		}
	})
	t.Run("非預設位置", func(t *testing.T) {
		res := eval(t, &inventoryRawOutput{Sudo: []byte(sudoFrames(true, nil, "absent"))})
		m := coverageOf(res, invCheckSudoMain)
		if res.Status != model.HostAccountScanPartial || m.State != invStateFailed || m.Reason != invReasonNondefaultLocation || !res.Findings[0].Incomplete {
			t.Fatalf("%+v %+v", res.Status, m)
		}
		if u := coverageOf(res, invCheckUnresolved); u.State != invStateUndetermined {
			t.Fatalf("主規則檔讀取失敗時無法解析的項目應為無從判斷：%+v", u)
		}
	})
	t.Run("未引入規則目錄", func(t *testing.T) {
		res := eval(t, &inventoryRawOutput{Sudo: []byte(sudoFrames(true, strp("root ALL=(ALL) ALL\n"), "ok", [2]string{"10-frank", "frank ALL=(ALL) ALL\n"}))})
		d := coverageOf(res, invCheckSudoDir)
		if d.State != invStateChecked || d.Reason != invReasonNotIncluded || res.Status != model.HostAccountScanSucceeded {
			t.Fatalf("%+v %+v", res.Status, d)
		}
	})
	t.Run("group 退出碼非 0", func(t *testing.T) {
		res := eval(t, &inventoryRawOutput{GroupExit: 2, Sudo: []byte(sudoFrames(false, nil, "absent"))})
		if res.Status != model.HostAccountScanFailed || res.Failure != model.InventoryCommandFailed {
			t.Fatalf("%+v", res)
		}
	})
	t.Run("固定說明", func(t *testing.T) {
		if len(inventoryFixedNotes) != 3 {
			t.Fatalf("固定說明 = %v", inventoryFixedNotes)
		}
	})
}

// --- 特權判定 ---

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func TestInventoryPrivilege(t *testing.T) {
	find := func(res *invScanResult, name string) invFindingResult {
		for _, f := range res.Findings {
			if f.Username == name {
				return f
			}
		}
		t.Fatalf("找不到 %s", name)
		return invFindingResult{}
	}
	eval := func(t *testing.T, passwd, group, sudo, groups string) *invScanResult {
		t.Helper()
		res, err := evaluateInventory(&inventoryRawOutput{Passwd: []byte(passwd), Group: []byte(group), Sudo: []byte(sudo)}, groups)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	noSudo := sudoFrames(false, nil, "absent")
	t.Run("主要群組也算成員", func(t *testing.T) {
		res := eval(t, "ops2:x:1002:10::/:/bin/sh\n", "wheel:x:10:root\n", noSudo, "root,wheel")
		f := find(res, "ops2")
		if !f.Privileged || !contains(f.Reasons, "group_primary:wheel") {
			t.Fatalf("%+v", f)
		}
	})
	t.Run("群組規則與別名展開", func(t *testing.T) {
		sudo := sudoFrames(true, strp("%admins ALL=(ALL) ALL\nUser_Alias OPS = alice, %dba\nOPS ALL=(root) /usr/bin/systemctl\n"), "absent")
		res := eval(t, "bob:x:1:1::/:/bin/sh\nalice:x:2:2::/:/bin/sh\ncarol:x:3:3::/:/bin/sh\n", "admins:x:50:bob\ndba:x:51:carol\n", sudo, "")
		if !contains(find(res, "bob").Reasons, "sudoers_group:admins") || !contains(find(res, "alice").Reasons, "sudoers_alias:OPS") || !contains(find(res, "carol").Reasons, "sudoers_alias:OPS") {
			t.Fatalf("%+v", res.Findings)
		}
	})
	t.Run("無法解析項目", func(t *testing.T) {
		res := eval(t, "ann:x:1:1::/:/bin/sh\n", "", sudoFrames(true, strp("+netops ALL=(ALL) ALL\n"), "absent"), "")
		if find(res, "ann").Privileged || coverageOf(res, invCheckUnresolved).Count != 1 {
			t.Fatalf("%+v", res)
		}
	})
	t.Run("要求目標密碼的全員規則不單獨構成特權", func(t *testing.T) {
		res := eval(t, "eve:x:1:1::/:/bin/sh\n", "", sudoFrames(true, strp("Defaults targetpw\nALL ALL=(ALL) ALL\n"), "absent"), "")
		f := find(res, "eve")
		if f.Privileged || !contains(f.Reasons, model.PrivReasonSudoersAllTarget) {
			t.Fatalf("%+v", f)
		}
	})
	t.Run("全員規則構成特權", func(t *testing.T) {
		res := eval(t, "eve:x:1:1::/:/bin/sh\n", "", sudoFrames(true, strp("ALL ALL=(ALL) ALL\n"), "absent"), "")
		if f := find(res, "eve"); !f.Privileged || !contains(f.Reasons, model.PrivReasonSudoersAll) {
			t.Fatalf("%+v", f)
		}
	})
	t.Run("清單外殼層可登入", func(t *testing.T) {
		res := eval(t, "svcx:x:0:0::/:/usr/bin/python3\nsync:x:5:0:sync:/sbin:/bin/sync\nodd:x:6:6::/:/tmp/x/false\nempty:x:7:7::/:\n", "root:x:0:\n", noSudo, "root")
		if f := find(res, "svcx"); !f.Privileged || !f.LoginCapable {
			t.Fatalf("svcx %+v", f)
		}
		if f := find(res, "sync"); !f.Privileged || f.LoginCapable {
			t.Fatalf("sync %+v", f)
		}
		if !find(res, "odd").LoginCapable || !find(res, "empty").LoginCapable {
			t.Fatal("清單外路徑與空殼層應可登入")
		}
	})
	t.Run("未引入的規則目錄不計入", func(t *testing.T) {
		res := eval(t, "frank:x:1:1::/:/bin/sh\n", "", sudoFrames(true, strp("root ALL=(ALL) ALL\n"), "ok", [2]string{"10-f", "frank ALL=(ALL) ALL\n"}), "")
		if find(res, "frank").Privileged {
			t.Fatal("frank 不應為特權")
		}
	})
	t.Run("多個理由全部保留", func(t *testing.T) {
		res := eval(t, "root2:x:0:500::/:/bin/sh\n", "sudo:x:27:root2\n", noSudo, "root,sudo,wheel,admin")
		f := find(res, "root2")
		if !contains(f.Reasons, model.PrivReasonUID0) || !contains(f.Reasons, "group:sudo") {
			t.Fatalf("%+v", f)
		}
	})
	t.Run("自訂群組", func(t *testing.T) {
		res := eval(t, "dave:x:1:1::/:/bin/sh\n", "ops-admin:x:70:dave\n", noSudo, "root,wheel,ops-admin")
		if !find(res, "dave").Privileged {
			t.Fatal("dave 應為特權")
		}
	})
	t.Run("含空白的群組名", func(t *testing.T) {
		res := eval(t, "dom:x:1:1::/:/bin/sh\n", "domain admins:x:80:dom\n", noSudo, "wheel,domain admins")
		if !find(res, "dom").Privileged {
			t.Fatal("dom 應為特權")
		}
	})
	t.Run("空清單不以群組判定", func(t *testing.T) {
		res := eval(t, "w:x:1:10::/:/bin/sh\n", "wheel:x:10:w\n", noSudo, "")
		if find(res, "w").Privileged {
			t.Fatal("空清單不應以群組判定")
		}
	})
}

// TestInventoryRoutineSystemAccount 系統預設帳號：不可登入且唯一特權理由為主要群組 root（可另帶 targetpw 全員規則）。
func TestInventoryRoutineSystemAccount(t *testing.T) {
	for _, tc := range []struct {
		name    string
		login   bool
		reasons []string
		want    bool
	}{
		{"halt 類", false, []string{"group_primary:root"}, true},
		{"另帶 targetpw 全員規則", false, []string{"group_primary:root", "sudoers_all_targetpw"}, true},
		{"可登入", true, []string{"group_primary:root"}, false},
		{"在 sudo 群組的不能登入帳號", false, []string{"group:sudo"}, false},
		{"主要群組 root 又在 sudo 群組", false, []string{"group:sudo", "group_primary:root"}, false},
		{"主要群組是 wheel", false, []string{"group_primary:wheel"}, false},
		{"另有全員 sudo 規則", false, []string{"group_primary:root", "sudoers_all"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := inventoryRoutineSystemAccount(tc.login, reasonsJSON(tc.reasons)); got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}
