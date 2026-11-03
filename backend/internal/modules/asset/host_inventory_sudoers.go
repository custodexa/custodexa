package asset

import (
	"regexp"
	"sort"
	"strings"
)

// sudo 規則解析：只判定「可透過 sudo 提權」的對象，不評估允許的指令範圍。
// 無法確定對象的項目（網路群組、非 POSIX 群組、數字識別、未定義或過深的別名、
// 預設位置以外的引入）不猜測，計入無法解析的項目。

// invSudoGrantKind 授權對象種類。
type invSudoGrantKind int

const (
	invGrantUser invSudoGrantKind = iota
	invGrantGroup
	invGrantAll
)

// invSudoGrant 一個成立的授權對象。Alias 非空表示經使用者別名（記頂層別名名稱）。
type invSudoGrant struct {
	Kind  invSudoGrantKind
	Name  string
	Alias string
}

// invSudoRules 解析結果。
type invSudoRules struct {
	Grants []invSudoGrant
	// TargetPW 以最後一次出現的不帶限定 Defaults 判定 targetpw／rootpw／runaspw 任一生效
	TargetPW   bool
	Unresolved int
	// IncludesDir 主規則檔引入了 /etc/sudoers.d
	IncludesDir bool
}

// invSudoParser 跨檔共用的解析狀態（別名與 Defaults 依檔案讀取順序累積）。
type invSudoParser struct {
	aliases map[string][]string
	pwFlags map[string]bool
	specs   [][]string // 每條使用者規格的使用者清單項
	unres   int
	inclDir bool
	isMain  bool
}

var (
	reCommaSpace = regexp.MustCompile(`\s*,\s*`)
	reAliasName  = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
)

const sudoersDir = "/etc/sudoers.d"

// sudoersDirFileSkipped sudo 的慣例：規則目錄中檔名以 ~ 結尾或含 . 者略過。
func sudoersDirFileSkipped(name string) bool {
	return strings.HasSuffix(name, "~") || strings.Contains(name, ".")
}

// parseInventorySudoers 依序解析主規則檔與規則目錄的可讀檔。
// mainReadable 為 true 且主規則檔未引入規則目錄時，目錄中的規則不計（回傳 IncludesDir=false）。
func parseInventorySudoers(main []byte, mainReadable bool, files []invSudoFile) *invSudoRules {
	p := &invSudoParser{aliases: map[string][]string{}, pwFlags: map[string]bool{}}
	if mainReadable {
		p.isMain = true
		p.parse(string(main))
		p.isMain = false
	}
	useDir := !mainReadable || p.inclDir
	if useDir {
		names := make([]invSudoFile, 0, len(files))
		for _, f := range files {
			if f.Readable && !sudoersDirFileSkipped(f.Name) {
				names = append(names, f)
			}
		}
		sort.Slice(names, func(i, j int) bool { return names[i].Name < names[j].Name })
		for _, f := range names {
			p.parse(string(f.Content))
		}
	}
	out := &invSudoRules{Unresolved: p.unres, IncludesDir: p.inclDir}
	out.TargetPW = p.pwFlags["targetpw"] || p.pwFlags["rootpw"] || p.pwFlags["runaspw"]
	for _, items := range p.specs {
		for _, it := range items {
			p.resolveItem(it, "", 0, &out.Grants)
		}
	}
	out.Unresolved = p.unres
	return out
}

// logicalLines 合併續行並去掉註解；保留 #include／#includedir 與 #<數字> 開頭的列。
func logicalLines(content string) []string {
	var out []string
	var cur strings.Builder
	for _, raw := range strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n") {
		line := raw
		if strings.HasSuffix(line, "\\") {
			cur.WriteString(strings.TrimSuffix(line, "\\"))
			cur.WriteString(" ")
			continue
		}
		cur.WriteString(line)
		out = append(out, stripSudoComment(strings.TrimSpace(cur.String())))
		cur.Reset()
	}
	if cur.Len() > 0 {
		out = append(out, stripSudoComment(strings.TrimSpace(cur.String())))
	}
	return out
}

func stripSudoComment(l string) string {
	if strings.HasPrefix(l, "#include") {
		return l
	}
	for i := 0; i < len(l); i++ {
		if l[i] != '#' {
			continue
		}
		if i+1 < len(l) && l[i+1] >= '0' && l[i+1] <= '9' {
			continue // #<uid>
		}
		return strings.TrimSpace(l[:i])
	}
	return l
}

func (p *invSudoParser) parse(content string) {
	for _, l := range logicalLines(content) {
		if l == "" {
			continue
		}
		switch {
		case strings.HasPrefix(l, "#includedir") || strings.HasPrefix(l, "@includedir"):
			path := strings.TrimRight(strings.TrimSpace(l[len("#includedir"):]), "/")
			if path == sudoersDir && p.isMain {
				p.inclDir = true
			} else if path != sudoersDir {
				p.unres++
			}
		case strings.HasPrefix(l, "#include") || strings.HasPrefix(l, "@include"):
			path := strings.TrimSpace(l[len("#include"):])
			if !strings.HasPrefix(path, sudoersDir+"/") {
				p.unres++
			}
		case strings.HasPrefix(l, "Defaults"):
			p.parseDefaults(l[len("Defaults"):])
		case strings.HasPrefix(l, "User_Alias"):
			p.parseUserAlias(strings.TrimSpace(l[len("User_Alias"):]))
		case strings.HasPrefix(l, "Host_Alias"), strings.HasPrefix(l, "Runas_Alias"), strings.HasPrefix(l, "Cmnd_Alias"), strings.HasPrefix(l, "Cmd_Alias"):
			// 只辨識、不展開
		default:
			p.parseUserSpec(l)
		}
	}
}

// parseDefaults 只解讀不帶限定的 Defaults 中的 targetpw／rootpw／runaspw（`!` 為關閉）。
func (p *invSudoParser) parseDefaults(rest string) {
	if rest == "" || strings.ContainsAny(rest[:1], ":>@!") {
		return // Defaults:user／Defaults>runas／Defaults@host／Defaults!cmd 不解讀
	}
	for _, item := range strings.Split(rest, ",") {
		item = strings.TrimSpace(item)
		on := true
		for strings.HasPrefix(item, "!") {
			on = !on
			item = strings.TrimSpace(item[1:])
		}
		switch item {
		case "targetpw", "rootpw", "runaspw":
			p.pwFlags[item] = on
		}
	}
}

// parseUserAlias `NAME = a, b : NAME2 = c`
func (p *invSudoParser) parseUserAlias(rest string) {
	for _, def := range strings.Split(rest, ":") {
		name, val, ok := strings.Cut(def, "=")
		name = strings.TrimSpace(name)
		if !ok || !reAliasName.MatchString(name) {
			p.unres++
			continue
		}
		var items []string
		for _, it := range strings.Split(val, ",") {
			if it = strings.TrimSpace(it); it != "" {
				items = append(items, it)
			}
		}
		p.aliases[name] = items
	}
}

// parseUserSpec 取使用者規格的使用者清單（到主機清單前為止）。
func (p *invSudoParser) parseUserSpec(l string) {
	before, _, ok := strings.Cut(l, "=")
	if !ok {
		p.unres++
		return
	}
	fields := strings.Fields(reCommaSpace.ReplaceAllString(strings.TrimSpace(before), ","))
	if len(fields) < 2 {
		p.unres++
		return
	}
	p.specs = append(p.specs, strings.Split(fields[0], ","))
}

// resolveItem 把一個使用者清單項解析為授權對象；alias 為頂層別名名稱。
func (p *invSudoParser) resolveItem(it, alias string, depth int, out *[]invSudoGrant) {
	it = strings.TrimSpace(it)
	switch {
	case it == "":
		return
	case strings.HasPrefix(it, "!"):
		return // 否定項不使帳號成為特權
	case it == "ALL":
		*out = append(*out, invSudoGrant{Kind: invGrantAll, Alias: alias})
	case strings.HasPrefix(it, "+"), strings.HasPrefix(it, "#"),
		strings.HasPrefix(it, "%:"), strings.HasPrefix(it, "%#"), strings.HasPrefix(it, "%+"),
		strings.ContainsAny(it, `"\`):
		p.unres++
	case strings.HasPrefix(it, "%"):
		*out = append(*out, invSudoGrant{Kind: invGrantGroup, Name: it[1:], Alias: alias})
	case reAliasName.MatchString(it):
		members, ok := p.aliases[it]
		if !ok || depth >= inventoryMaxAliasDepth {
			p.unres++
			return
		}
		top := alias
		if top == "" {
			top = it
		}
		for _, m := range members {
			p.resolveItem(m, top, depth+1, out)
		}
	default:
		*out = append(*out, invSudoGrant{Kind: invGrantUser, Name: it, Alias: alias})
	}
}
