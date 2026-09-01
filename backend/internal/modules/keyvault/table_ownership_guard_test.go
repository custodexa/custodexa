package keyvault

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// keyvault 的**動態表名**與**跨模組寫入例外**守衛。
//
// **為何非補不可（哪個改動會踩到它）**：把 13 檔搬進獨立包後，`moduleguard`
// 的表所有權判定要靠「抽取 SQL 內的表名」。keyvault 的存量掃描與信封重加密路徑
// **不寫死表名**——`db.Table(target.table)`、
// `fmt.Sprintf("UPDATE %s SET %s = ? ...", target.table, target.column)`
// 全部由 `envelopeMigrationTargets` 這張登記表驅動。
// 靜態抽取器看到的是 `%s`，於是：
//
//   - **keyvault 對 7 張他模組表的 UPDATE 完全隱形**——表所有權守衛回零違規而綠；
//   - 反過來，若日後有人在 keyvault 內寫下**不是**取自登記表的動態表名
//     （例如自參數或設定拼出來的表），同一個抽取器同樣看不見。
//
// 故本檔改以「**登記表本身**」為守衛資料來源（2.2 原文），並把「keyvault 得寫
// 哪些他模組的表」化為具名白名單（2.3）。
//
// **與交易級聯類分開登記、不共用解法**：交易級聯類是「A 模組在自己的交易內
// 直接刪 B 模組的表」，出路是 B 提供 tx-taking 匯出方法；本檔管的是
// 「keyvault 依登記表對全庫密文欄做就地重加密」，**沒有 tx-taking 出路**
// ——重加密要橫跨全部模組的表，逐一改呼叫擁有者會製造 keyvault→全模組 的出向
// 依賴，正好摧毀 keyvault「零出向」的前提。兩者的登記結構、理由與驗收方式因此
// 刻意不共用；見 `keyvaultCrossModuleWriteAllowlist` 每列的理由欄。

// ---- 2.3 具名寫入例外白名單 ----

// crossModuleWriteException 一筆具名的跨模組寫入例外。
type crossModuleWriteException struct {
	Table       string
	OwnerModule string // 模組歸屬；"keyvault" 表示自有表（非例外）
	Reason      string
}

// keyvaultCrossModuleWriteAllowlist keyvault 依 `envelopeMigrationTargets` 就地
// 重加密時會 UPDATE 的表，逐張具名登記。
//
// **這份清單不受編譯器保護**（AR-3 的誠實讓步）：它擋的是「悄悄多寫一張
// 別人的表」，不是「不能寫」。新增登記欄位時 SHALL 同步補列，否則本守衛轉紅。
var keyvaultCrossModuleWriteAllowlist = []crossModuleWriteException{
	{Table: "assets", OwnerModule: "asset",
		Reason: "資產密碼／私鑰／SFTP 密碼三欄的信封重加密。DEK 輪替與 AAD 遷移必須橫跨全部密文欄，改呼叫 asset 的方法會產生 keyvault→asset 出向依賴，摧毀 keyvault 零出向前提。"},
	{Table: "asset_accounts", OwnerModule: "asset",
		Reason: "帳號密碼／私鑰兩欄。同 assets。"},
	{Table: "users", OwnerModule: "identity",
		Reason: "MFA TOTP secret 欄。identity 只擁有語義，密文格式與金鑰版本由 keyvault 單方掌握。"},
	{Table: "oidc_providers", OwnerModule: "identity",
		Reason: "OIDC client secret 欄。同 users。"},
	{Table: "ldap_directories", OwnerModule: "identity",
		Reason: "LDAP service bind 密碼欄。同 users。"},
	{Table: "notification_channels", OwnerModule: "audit",
		Reason: "通知通道的 url／secret 兩欄。audit 側只讀寫明文語義，密文由 keyvault 的 codec 產生與重包。"},
	{Table: "change_secret_candidates", OwnerModule: "asset",
		Reason: "改密未驗證候選憑證的 password_enc／private_key_enc 兩欄。同 asset_accounts：asset 擁有語義，密文格式與金鑰版本由 keyvault 單方掌握。"},
	{Table: "export_signing_keys", OwnerModule: "keyvault",
		Reason: "**自有表**（ExportSigningService 的 Ed25519 私鑰），不構成跨模組寫入；列此以維持與登記表的雙向完備性。"},
	{Table: "checkpoint_signing_keys", OwnerModule: "keyvault",
		Reason: "**自有表**（CheckpointSigningService 的 Ed25519 私鑰，audit-checkpoint-chain），不構成跨模組寫入；列此以維持與登記表的雙向完備性。"},
	{Table: "clipboard_events", OwnerModule: "session",
		Reason: "剪貼簿留存內容欄 content_enc。session 擁有語義，密文格式與金鑰版本由 keyvault 單方掌握；DEK 輪替與 AAD 遷移必須涵蓋本欄，否則輪替後剪貼簿審計證據不可解。"},
	{Table: "offsite_profiles", OwnerModule: "offsite",
		Reason: "離機儲存逐世代的物件儲存憑證欄 credentials_enc。internal/offsite 擁有語義（世代生命週期、憑證模式三值），密文格式與金鑰版本由 keyvault 單方掌握；DEK 輪替與退役 DEK 引用掃描必須涵蓋本欄，否則輪替後歷史世代憑證不可解、其遠端物件永不可取回。**沒有 tx-taking 出路**：重加密橫跨全部模組的表，改呼叫擁有者會製造 keyvault→offsite 出向依賴。"},
}

// TestKeyvaultCrossModuleWriteAllowlistMatchesRegistry 白名單與登記表雙向完備。
//
// 少一列：新增的登記欄位所在的表沒有人審過「keyvault 可以寫它」；
// 多一列：白名單放寬了一個現實中不存在的授權（例外清單只會越放越寬的典型形態）。
func TestKeyvaultCrossModuleWriteAllowlistMatchesRegistry(t *testing.T) {
	if len(envelopeMigrationTargets) < 10 {
		t.Fatalf("envelopeMigrationTargets 只有 %d 筆（現況 11）：登記表已被清空或掃描失真，"+
			"本守衛將在近乎空集合下假綠", len(envelopeMigrationTargets))
	}
	inRegistry := map[string]bool{}
	for _, tgt := range envelopeMigrationTargets {
		if tgt.table == "" || tgt.column == "" {
			t.Errorf("登記項 %+v 的 table／column 不得為空", tgt)
		}
		inRegistry[tgt.table] = true
	}
	inAllowlist := map[string]bool{}
	for _, e := range keyvaultCrossModuleWriteAllowlist {
		if e.OwnerModule == "" || strings.TrimSpace(e.Reason) == "" {
			t.Errorf("白名單 %s 缺 OwnerModule 或理由：無理由的例外等於沒有審過", e.Table)
		}
		if inAllowlist[e.Table] {
			t.Errorf("白名單有重複項 %s", e.Table)
		}
		inAllowlist[e.Table] = true
		if !inRegistry[e.Table] {
			t.Errorf("[白名單→登記表] %s 不在 envelopeMigrationTargets 中："+
				"例外清單放寬了現實中不存在的跨模組寫入授權", e.Table)
		}
	}
	for table := range inRegistry {
		if !inAllowlist[table] {
			t.Errorf("[登記表→白名單] %s 有登記欄位卻未登記於跨模組寫入白名單："+
				"keyvault 會就地 UPDATE 該表而無人審過", table)
		}
	}
	// 他模組表的下界：現況 9 張（assets／asset_accounts／change_secret_candidates／
	// users／oidc_providers／ldap_directories／notification_channels／
	// clipboard_events／offsite_profiles），
	// export_signing_keys 與 checkpoint_signing_keys 為自有表。
	foreign := 0
	for _, e := range keyvaultCrossModuleWriteAllowlist {
		if e.OwnerModule != "keyvault" {
			foreign++
		}
	}
	if foreign < 9 {
		t.Fatalf("跨模組寫入例外只剩 %d 張表（下界 7）：白名單被縮減或登記表失真，"+
			"就地重加密的涵蓋面已縮水", foreign)
	}
	t.Logf("跨模組寫入例外 %d 張他模組表＋%d 張自有表（登記欄位 %d 筆）",
		foreign, len(keyvaultCrossModuleWriteAllowlist)-foreign, len(envelopeMigrationTargets))
}

// TestKeyvaultWriteExceptionIsNotTxCascadeClass 兩類跨模組寫入不得合流。
//
// 白名單的每一列都必須是「登記表驅動的就地重加密」，不得混入交易級聯那類
// 「在自己交易內刪別人的表」的授權——後者的正解是對方提供 tx-taking 方法，
// 兩類共用一份清單會讓交易級聯的個案借道本清單繞過應有的介面化。
func TestKeyvaultWriteExceptionIsNotTxCascadeClass(t *testing.T) {
	registryTables := map[string]bool{}
	for _, tgt := range envelopeMigrationTargets {
		registryTables[tgt.table] = true
	}
	for _, e := range keyvaultCrossModuleWriteAllowlist {
		if !registryTables[e.Table] {
			t.Errorf("%s 不是由登記表驅動：本清單只承載登記表驅動的就地重加密，"+
				"交易級聯刪除 SHALL 走擁有者模組的 tx-taking 匯出方法，不得登記於此", e.Table)
		}
	}
}

// ---- 2.2 表名來源守衛 ----
//
// **本守衛的射程＝「字串構造的表名」，逐條列明**。
// 原版只看「非字面量」的表名，並以「字面量表名有靜態抽取器涵蓋」為由明文跳過
// `db.Table("users")`——查證**該靜態抽取器在本 repo 尚不存在**（全庫搜
// `moduleguard`／`TableOwnership` 只命中本檔），那個跳過理由是錯的陳述，已刪除。
// 現在字面量表名改為**納入判定**（必須是登記表或 keyvault 自有表）。
//
// 涵蓋（違反即紅，各有突變自檢）：
//
//	(a) `db.Table("users")`      字面量表名 → 必須 ∈ 登記表 ∪ keyvault 自有表
//	(b) `db.Exec(sql)` 的 sql 非字面（字串串接、變數）→ fail-close 直接紅；
//	    字面 SQL 則抽出 UPDATE/INTO/FROM/JOIN 後的表名同樣比對允許集合
//	(d) `db.Table(x.table)`      只認 `.table` 後綴，並由
//	    TestKeyvaultTableFieldIsUnambiguous 證明本包只有 envelopeMigrationColumn
//	    有這個未匯出欄位（跨包型別的未匯出欄位在 Go 裡本就取不到），故後綴比對是完備的
//	(e) `fmt.Sprintf(constFmt, tbl)` format 非字面 → fail-close 直接紅
//	(c-部分) `tx.Model(&model.X{}).Update…` 型別解析的寫入 → X 必須是
//	    keyvault 自有的 model 型別（見 keyvaultTypedWriteAllowlist）
//
// **不涵蓋（誠實邊界，已列為待辦）**：
//
//   - `db.Create(&row)`／`db.Save(&row)`／`db.First(&row)` 這類表名由**變數型別**
//     決定的形態。要判定它們得做真正的型別推導（go/types 或 packages.Load），
//     本守衛只做語法層比對。keyvault 現況有一處（export_signing_service.go 的
//     `db.Create(&row)`，寫的是自有表 export_signing_keys）。
//   - 跨包函式包裝出來的表名（keyvault 零出向，現況無此形態）。
//
// 換言之：本守衛能保證「**寫在 keyvault 原始碼裡的表名字串**都經過登記」，
// 不能保證「keyvault 只碰登記過的表」。守衛敘述須照此界定。

// dynamicTableSite 一處以字串構造表名的 SQL。
type dynamicTableSite struct {
	File   string
	Line   int
	Kind   string // "Table"／"Sprintf"／"Exec"／"TypedWrite"
	Source string // 表名運算式的原樣文字（字面量為 `literal:"名稱"`）
}

// dynamicTableSourceOK 判定表名運算式是否「取自登記表」。
//
// 合格形態只有一種：對 `envelopeMigrationColumn` 的 `table` 欄位取值
// （`target.table`／`tgt.table`／`c.table`…）。參數、設定值一律不合格
// ——那些是沒有登記表把關的表名。字面量另由 literalTableName＋允許集合判定。
func dynamicTableSourceOK(src string) bool {
	return strings.HasSuffix(src, ".table")
}

// literalTableName 自 `literal:"users"` 形式取出表名（非字面量回 false）
func literalTableName(src string) (string, bool) {
	const prefix = `literal:"`
	if !strings.HasPrefix(src, prefix) || !strings.HasSuffix(src, `"`) {
		return "", false
	}
	return strings.TrimSuffix(strings.TrimPrefix(src, prefix), `"`), true
}

// sqlTableRefs 自字面 SQL 抽出動詞後的表名（UPDATE／INSERT INTO／DELETE FROM／FROM／JOIN）
var sqlTableRefs = regexp.MustCompile(`(?is)\b(?:update|into|from|join|table)\s+([a-zA-Z_][a-zA-Z0-9_]*)`)

// scanDynamicTableSites 掃描本包非測試檔中以字串構造表名的 SQL 構造點。
func scanDynamicTableSites(t *testing.T, dir string) (sites []dynamicTableSite, scanned int) {
	t.Helper()
	fset := token.NewFileSet()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("讀取 %s 失敗（掃描根失真）: %v", dir, err)
	}
	exprText := func(fset *token.FileSet, e ast.Expr) string {
		var b strings.Builder
		switch v := e.(type) {
		case *ast.SelectorExpr:
			if x, ok := v.X.(*ast.Ident); ok {
				b.WriteString(x.Name + "." + v.Sel.Name)
			} else {
				b.WriteString("<expr>." + v.Sel.Name)
			}
		case *ast.Ident:
			b.WriteString(v.Name)
		case *ast.BasicLit:
			b.WriteString("literal:" + v.Value)
		default:
			b.WriteString(fmt.Sprintf("<%T>", e))
		}
		return b.String()
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(dir, name)
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			// 解析失敗的檔＝沒被掃過，而本守衛的失敗形態正是「掃不到＝零違規＝綠」
			t.Fatalf("解析 %s 失敗: %v", path, perr)
		}
		scanned++
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			line := fset.Position(call.Pos()).Line
			switch sel.Sel.Name {
			case "Table":
				// 字面量**不再跳過**：它同樣是一個沒被登記表把關的表名
				sites = append(sites, dynamicTableSite{
					File: name, Line: line,
					Kind: "Table", Source: exprText(fset, call.Args[0])})
			case "Exec", "Raw":
				switch arg := call.Args[0].(type) {
				case *ast.BasicLit:
					if arg.Kind != token.STRING {
						return true
					}
					for _, m := range sqlTableRefs.FindAllStringSubmatch(arg.Value, -1) {
						sites = append(sites, dynamicTableSite{
							File: name, Line: line,
							Kind: "Exec", Source: `literal:"` + m[1] + `"`})
					}
				case *ast.CallExpr:
					// **只有 fmt.Sprintf 可以放行**（它由 ast.Inspect 自行走到，
					// 在 Sprintf 分支判定，不在此重複計數）。其餘任何呼叫——
					// `db.Exec(buildSQL(tbl))`、`db.Exec(q.String())`——的表名
					// 都藏在被呼叫者裡，本守衛看不見：fail-close。
					// （原版對 *ast.CallExpr 一律略過，
					// 是「現有保證可被普通重構繞過」的具體形態，非型別推導缺口）
					if !isFmtSprintfCall(arg) {
						sites = append(sites, dynamicTableSite{
							File: name, Line: line,
							Kind: "Exec", Source: "<非字面 SQL 呼叫：" + callName(arg) + ">"})
					}
				case *ast.FuncLit:
					// database/sql 的 `conn.Raw(func(any) error {...})`，不是 SQL 字串
				default:
					// 字串串接（`"UPDATE " + tbl + " SET…"`）、變數、設定值：
					// 表名無從靜態判讀 → fail-close
					sites = append(sites, dynamicTableSite{
						File: name, Line: line,
						Kind: "Exec", Source: "<非字面 SQL：" + exprText(fset, call.Args[0]) + ">"})
				}
			case "Sprintf":
				lit, ok := call.Args[0].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					// format 是具名常數／變數時無從判讀其中的表名 → fail-close
					// keyvault 現況零命中；真有需要就改寫成字面 format
					sites = append(sites, dynamicTableSite{
						File: name, Line: line,
						Kind: "Sprintf", Source: "<非字面 format：" + exprText(fset, call.Args[0]) + ">"})
					return true
				}
				format := strings.ToUpper(lit.Value)
				verbAfter := []string{"UPDATE %S", "FROM %S", "INTO %S", "JOIN %S", "TABLE %S"}
				hit := false
				for _, v := range verbAfter {
					if strings.Contains(format, v) {
						hit = true
					}
				}
				if !hit || len(call.Args) < 2 {
					return true
				}
				sites = append(sites, dynamicTableSite{
					File: name, Line: line,
					Kind: "Sprintf", Source: exprText(fset, call.Args[1])})
			case "Update", "Updates", "Delete", "Create", "Save", "FirstOrCreate":
				// 型別解析的寫入：往回走鏈找 `Model(&model.X{})`
				if typ, ok := modelTypeOfChain(sel.X); ok {
					sites = append(sites, dynamicTableSite{
						File: name, Line: line,
						Kind: "TypedWrite", Source: "model:" + typ})
				}
			}
			return true
		})
	}
	sort.Slice(sites, func(i, j int) bool {
		if sites[i].File != sites[j].File {
			return sites[i].File < sites[j].File
		}
		return sites[i].Line < sites[j].Line
	})
	return sites, scanned
}

// isFmtSprintfCall 判定呼叫是否為 `fmt.Sprintf(...)`（唯一可放行的內層呼叫）。
func isFmtSprintfCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Sprintf" {
		return false
	}
	x, ok := sel.X.(*ast.Ident)
	return ok && x.Name == "fmt"
}

// callName 取呼叫運算式的可讀名稱（錯誤訊息用）。
func callName(call *ast.CallExpr) string {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name + "(...)"
	case *ast.SelectorExpr:
		if x, ok := fn.X.(*ast.Ident); ok {
			return x.Name + "." + fn.Sel.Name + "(...)"
		}
		return "<expr>." + fn.Sel.Name + "(...)"
	}
	return "<呼叫>"
}

// modelTypeOfChain 自方法鏈往回找 `Model(&model.X{})`，回傳 X（找不到回 false）。
//
// 例：`tx.Model(&model.DataKey{}).Where(...).Update(...)` 的 Update 呼叫，
// 其 sel.X 是 `tx.Model(...).Where(...)`，逐層往下走即可取到 DataKey。
func modelTypeOfChain(e ast.Expr) (string, bool) {
	for {
		call, ok := e.(*ast.CallExpr)
		if !ok {
			return "", false
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return "", false
		}
		if sel.Sel.Name == "Model" && len(call.Args) > 0 {
			arg := call.Args[0]
			if u, ok := arg.(*ast.UnaryExpr); ok {
				arg = u.X
			}
			if cl, ok := arg.(*ast.CompositeLit); ok {
				if s, ok := cl.Type.(*ast.SelectorExpr); ok {
					return s.Sel.Name, true
				}
				if id, ok := cl.Type.(*ast.Ident); ok {
					return id.Name, true
				}
			}
			return "", false
		}
		e = sel.X
	}
}

// modelTableNames 解析 internal/model，取「結構名 → TableName() 回傳值」。
// 掃描根與 envelope_targets_guard_test.go 同以 repoRoot 為錨。
func modelTableNames(t *testing.T) map[string]string {
	t.Helper()
	modelDir := filepath.Join(repoRoot(t), "internal", "model")
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, modelDir, func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("解析 model 套件失敗（%s）: %v", modelDir, err)
	}
	out := map[string]string{}
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			for _, d := range file.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || fd.Name == nil || fd.Name.Name != "TableName" ||
					fd.Recv == nil || len(fd.Recv.List) == 0 {
					continue
				}
				ident, ok := fd.Recv.List[0].Type.(*ast.Ident)
				if !ok {
					continue
				}
				if lit := singleReturnString(fd); lit != "" {
					out[ident.Name] = lit
				}
			}
		}
	}
	if len(out) < 25 {
		t.Fatalf("只解析到 %d 個 model TableName（現況 32，掃描根 %s）：掃描範圍失真",
			len(out), modelDir)
	}
	return out
}

// keyvaultOwnTables keyvault 自有的表（不構成跨模組寫入）。
var keyvaultOwnTables = []string{"data_keys", "export_signing_keys"}

// keyvaultTypedWriteAllowlist 允許以 `Model(&model.X{})` 形態寫入的 model 型別。
// 值為該型別的表名，由 modelTableNames 逐一核對——防止「型別還在清單裡，
// 但它的 TableName 已被改成別人的表」這種靜默漂移。
var keyvaultTypedWriteAllowlist = map[string]string{
	"DataKey":          "data_keys",
	"ExportSigningKey": "export_signing_keys",
}

// allowedKeyvaultTables 登記表 ∪ keyvault 自有表：keyvault 原始碼裡寫得出來的表名全集。
func allowedKeyvaultTables() map[string]bool {
	out := map[string]bool{}
	for _, tgt := range envelopeMigrationTargets {
		out[tgt.table] = true
	}
	for _, tbl := range keyvaultOwnTables {
		out[tbl] = true
	}
	return out
}

// minKeyvaultScannedFiles 本包非測試檔數下限（現況 14：13 檔搬入＋拆出的
// release.go）。取 12 為下界，保留合併檔案的正常重構空間。
const minKeyvaultScannedFiles = 12

// minDynamicTableSites 表名構造點下限。修補後涵蓋面自 4 處擴為 9 處
// （Table 3／Sprintf 1／TypedWrite 5，見測試的 t.Logf）。取 7 為下界——
// 降到 0 代表掃描器失效，而「零構造點」正是本守衛的假綠形態。
const minDynamicTableSites = 7

// TestKeyvaultDynamicTableNamesComeFromRegistry 表名一律取自登記表或自有表。
//
// **這是 2.2 的本體**：靜態 SQL 抽取器對 `%s` 束手無策，故改判「表名運算式的
// 來源」。從參數、設定、字串串接而來，或指向未登記的表名，都會在此轉紅——
// 那正是「keyvault 悄悄動了一張沒人登記的表」的形態。射程與不涵蓋形態見檔頭。
func TestKeyvaultDynamicTableNamesComeFromRegistry(t *testing.T) {
	dir := filepath.Join(repoRoot(t), "internal", "modules", "keyvault")
	sites, scanned := scanDynamicTableSites(t, dir)
	if scanned < minKeyvaultScannedFiles {
		t.Fatalf("只掃到 %d 個非測試 .go（下限 %d，掃描根 %s）：掃描範圍已失真",
			scanned, minKeyvaultScannedFiles, dir)
	}
	if len(sites) < minDynamicTableSites {
		t.Fatalf("只找到 %d 處表名構造（下限 %d）：掃描器已失效，"+
			"本守衛將在空集合下假綠", len(sites), minDynamicTableSites)
	}
	allowed := allowedKeyvaultTables()
	modelTables := modelTableNames(t)
	for typ, wantTable := range keyvaultTypedWriteAllowlist {
		got, ok := modelTables[typ]
		if !ok {
			t.Errorf("型別寫入白名單的 model.%s 沒有 TableName()：無從確認它寫的是哪張表", typ)
			continue
		}
		if got != wantTable {
			t.Errorf("model.%s 的 TableName() 是 %q，白名單登記的是 %q："+
				"型別寫入白名單已與 model 漂移", typ, got, wantTable)
		}
		if !allowed[got] {
			t.Errorf("型別寫入白名單的 %s（表 %s）不在登記表也不是 keyvault 自有表", typ, got)
		}
	}
	for _, s := range sites {
		switch {
		case s.Kind == "TypedWrite":
			typ := strings.TrimPrefix(s.Source, "model:")
			if _, ok := keyvaultTypedWriteAllowlist[typ]; !ok {
				t.Errorf("%s:%d 以 Model(&model.%s{}) 型別寫入他模組的表："+
					"keyvault 的跨模組寫入 SHALL 只走 envelopeMigrationTargets 驅動的就地重加密"+
					"，型別解析的寫入繞過登記表與跨模組寫入白名單", s.File, s.Line, typ)
			}
		case dynamicTableSourceOK(s.Source):
			// 登記表驅動：envelopeMigrationColumn.table
		default:
			name, isLit := literalTableName(s.Source)
			if !isLit {
				t.Errorf("%s:%d（%s）的表名來源 %s 無從靜態判讀："+
					"表名 SHALL 由登記表驅動或寫成字面量，字串串接／具名 format／參數"+
					"一律不得用於構造表名（無法判讀＝無法登記）", s.File, s.Line, s.Kind, s.Source)
				continue
			}
			if !allowed[name] {
				t.Errorf("%s:%d（%s）寫死了表名 %q，它既不在 envelopeMigrationTargets "+
					"也不是 keyvault 自有表：keyvault 動了一張沒人登記、也不在跨模組寫入"+
					"白名單射程內的表", s.File, s.Line, s.Kind, name)
			}
		}
	}
	byKind := map[string]int{}
	for _, s := range sites {
		byKind[s.Kind]++
	}
	t.Logf("表名構造點 %d 處（掃描 %d 檔，允許表 %d 張）：%v", len(sites), scanned, len(allowed), byKind)
}

// TestKeyvaultTableFieldIsUnambiguous `.table` 後綴比對的完備性前提。
//
// `dynamicTableSourceOK` 只做字串後綴比對，故「任何帶小寫 table 欄的型別」
// 都能通過。本格證明那個前提在本包成立：
// 本包只有 envelopeMigrationColumn 宣告了未匯出的 `table` 欄位；而未匯出欄位
// **不可能**來自其他套件的型別（Go 的匯出規則），故後綴比對在本包是完備的。
func TestKeyvaultTableFieldIsUnambiguous(t *testing.T) {
	dir := filepath.Join(repoRoot(t), "internal", "modules", "keyvault")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("讀取 %s 失敗: %v", dir, err)
	}
	fset := token.NewFileSet()
	var owners []string
	scanned := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if perr != nil {
			t.Fatalf("解析 %s 失敗: %v", name, perr)
		}
		scanned++
		ast.Inspect(f, func(n ast.Node) bool {
			ts, ok := n.(*ast.TypeSpec)
			if !ok {
				return true
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok || st.Fields == nil {
				return true
			}
			for _, fld := range st.Fields.List {
				for _, fn := range fld.Names {
					if fn.Name == "table" {
						owners = append(owners, ts.Name.Name)
					}
				}
			}
			return true
		})
	}
	if scanned < minKeyvaultScannedFiles {
		t.Fatalf("只掃到 %d 個非測試 .go（下限 %d）：掃描範圍已失真", scanned, minKeyvaultScannedFiles)
	}
	sort.Strings(owners)
	if len(owners) != 1 || owners[0] != "envelopeMigrationColumn" {
		t.Fatalf("本包宣告未匯出 table 欄位的型別為 %v，預期只有 envelopeMigrationColumn："+
			"多一個型別即代表 dynamicTableSourceOK 的 `.table` 後綴比對可被非登記來源冒充，"+
			"請改為型別層判定或把新型別納入登記表", owners)
	}
}

// ---- K3a：`.table` 的值必須真的來自登記表（構造點收口）----

// envelopeColumnRegistryFile 唯一允許構造 envelopeMigrationColumn 的檔。
const envelopeColumnRegistryFile = "envelope_migration_service.go"

// envelopeColumnRegistryVar 唯一允許構造 envelopeMigrationColumn 的變數宣告。
const envelopeColumnRegistryVar = "envelopeMigrationTargets"

// TestEnvelopeColumnConstructedOnlyInRegistry `envelopeMigrationColumn` 只能在
// 登記表宣告內構造，且其 `table` 欄不得於他處被賦值。
//
// **為何需要這一格**：`dynamicTableSourceOK` 只證
// 「表名運算式是某個型別的 `table` 欄位」，`TestKeyvaultTableFieldIsUnambiguous`
// 再證「本包只有 envelopeMigrationColumn 有這個欄位」。兩者合起來**仍不證明值
// 來自登記表**——一次普通重構就能繞過：
//
//	col := envelopeMigrationColumn{table: "sessions", column: "x"}
//	db.Table(col.table).Where(...)   // 兩道既有守衛皆放行
//
// 本格把構造點收口到登記表宣告本身：型別的複合字面量只能出現在
// `envelope_migration_service.go` 的 `var envelopeMigrationTargets = ...` 內，
// 且不得有 `x.table = ...` 形態的事後賦值。
//
// **指標間接賦值一併封死**：實證
//
//	p := &envelopeMigrationTargets[0].table
//	*p = v   // lhs 是 StarExpr，不是 SelectorExpr——四格守衛全 PASS
//
// 可繞過上面的 AssignStmt 判定。修法是往上游一步擋**取址**本身：
// `&<任意運算式>.table` 一律視為違規。這條之所以成立，前提是
// `envelopeMigrationColumn.table` **未匯出**——包外拿不到它的位址，而包內的
// 每一次取址都在本掃描面內（`TestKeyvaultTableFieldIsUnambiguous` 另證本包
// 只有這一個型別有未匯出的 `table` 欄）。取址被擋死，`*p = v` 就無從取得 p。
//
// 加起來，`.table` 的值就只能來自那張人工審過的登記表。
//
// **過近似的代價（刻意接受）**：對登記表**副本**的取址（`for _, t := range …`
// 的迴圈變數）也會被判違規，即使改它不影響登記表。與既有 AssignStmt 判定同樣
// 是語法層過近似——寧可誤報一個安全寫法，不可放行一個危險寫法；現況生產碼
// 零命中，代價為零。
func TestEnvelopeColumnConstructedOnlyInRegistry(t *testing.T) {
	dir := filepath.Join(repoRoot(t), "internal", "modules", "keyvault")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("讀取 %s 失敗（掃描根失真）: %v", dir, err)
	}
	fset := token.NewFileSet()
	scanned := 0
	insideRegistry := 0
	var offenders []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if perr != nil {
			t.Fatalf("解析 %s 失敗: %v", name, perr)
		}
		scanned++
		// 先蒐集「登記表宣告」子樹內的所有節點位置，其內的字面量才合法
		registrySpan := map[*ast.CompositeLit]bool{}
		if name == envelopeColumnRegistryFile {
			ast.Inspect(f, func(n ast.Node) bool {
				vs, ok := n.(*ast.ValueSpec)
				if !ok {
					return true
				}
				isRegistry := false
				for _, id := range vs.Names {
					if id.Name == envelopeColumnRegistryVar {
						isRegistry = true
					}
				}
				if !isRegistry {
					return true
				}
				ast.Inspect(vs, func(m ast.Node) bool {
					cl, ok := m.(*ast.CompositeLit)
					if !ok {
						return true
					}
					registrySpan[cl] = true
					// 登記筆數＝陣列字面量的元素數（元素多為省略型別的
					// `{table: …, column: …}`，其 Type 為 nil，故由外層計數）
					if isEnvelopeColumnLit(cl) {
						insideRegistry += len(cl.Elts)
					}
					return true
				})
				return true
			})
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.CompositeLit:
				if !isEnvelopeColumnLit(v) {
					return true
				}
				if registrySpan[v] {
					return true
				}
				offenders = append(offenders, fmt.Sprintf("%s:%d 於登記表宣告外構造 envelopeMigrationColumn",
					name, fset.Position(v.Pos()).Line))
			case *ast.AssignStmt:
				for _, lhs := range v.Lhs {
					if sel, ok := lhs.(*ast.SelectorExpr); ok && sel.Sel.Name == "table" {
						offenders = append(offenders, fmt.Sprintf("%s:%d 對 .table 欄位賦值",
							name, fset.Position(v.Pos()).Line))
					}
				}
			case *ast.UnaryExpr:
				// `&x.table` 取址——拿到指標後 `*p = v` 的 lhs 是 StarExpr，
				// 上面的 SelectorExpr 判定看不見它。往上游擋取址即可封死該路徑
				if v.Op != token.AND {
					return true
				}
				if sel, ok := v.X.(*ast.SelectorExpr); ok && sel.Sel.Name == "table" {
					offenders = append(offenders, fmt.Sprintf("%s:%d 取 .table 欄位的位址"+
						"（指標間接賦值可繞過賦值判定）", name, fset.Position(v.Pos()).Line))
				}
			}
			return true
		})
	}
	if scanned < minKeyvaultScannedFiles {
		t.Fatalf("只掃到 %d 個非測試 .go（下限 %d）：掃描範圍已失真", scanned, minKeyvaultScannedFiles)
	}
	// 涵蓋面下界：登記表內的元素字面量數量必須與登記筆數相符，否則本格在
	// 「一個字面量都沒找到」的狀態下也會綠
	if insideRegistry < len(envelopeMigrationTargets) {
		t.Fatalf("登記表宣告內只認出 %d 個 envelopeMigrationColumn 字面量（登記 %d 筆）："+
			"字面量辨識已失效，本守衛的零違規不成立", insideRegistry, len(envelopeMigrationTargets))
	}
	if len(offenders) > 0 {
		sort.Strings(offenders)
		t.Fatalf("envelopeMigrationColumn SHALL 只在 %s 的 %s 宣告內構造，"+
			"且 .table 不得事後賦值、不得被取址（否則 db.Table(x.table) 的「來自登記表」保證是假的）:\n%s",
			envelopeColumnRegistryFile, envelopeColumnRegistryVar, strings.Join(offenders, "\n"))
	}
	t.Logf("envelopeMigrationColumn 構造點：登記表內 %d 個、他處 0 個（掃描 %d 檔）", insideRegistry, scanned)
}

// isEnvelopeColumnLit 判定複合字面量是否為 envelopeMigrationColumn（含省略元素型別
// 的 `[]envelopeMigrationColumn{{...}}` 形態——那類元素的 Type 為 nil，由外層
// 陣列型別涵蓋，故此處只認顯式具名者，元素則由登記表 span 收下）。
func isEnvelopeColumnLit(cl *ast.CompositeLit) bool {
	switch v := cl.Type.(type) {
	case *ast.Ident:
		return v.Name == "envelopeMigrationColumn"
	case *ast.ArrayType:
		if id, ok := v.Elt.(*ast.Ident); ok {
			return id.Name == "envelopeMigrationColumn"
		}
	}
	return false
}

// TestDynamicTableSourceDetectorMutation 偵測器自證（純函式突變自檢）。
//
// 不動真實程式碼即可證明「判準真的會抓」：合格形態放行、不合格形態全紅。
func TestDynamicTableSourceDetectorMutation(t *testing.T) {
	for _, ok := range []string{"target.table", "tgt.table", "c.table"} {
		if !dynamicTableSourceOK(ok) {
			t.Errorf("合格來源 %q 被誤判為登記表驅動之外", ok)
		}
	}
	for _, bad := range []string{
		`literal:"users"`,       // 字面量：改由允許集合判定，不得走登記表驅動的綠燈
		"tableName",             // 自參數而來
		"cfg.TableName",         // 自設定而來
		"<expr>.Table",          // 大寫欄位（非 envelopeMigrationColumn.table）
		"<非字面 SQL：tbl>",         // 字串串接
		"<非字面 format：constFmt>", // 具名常數 format
	} {
		if dynamicTableSourceOK(bad) {
			t.Errorf("不合格來源 %q 未被判為違規：偵測器已失效", bad)
		}
	}
	// 字面量抽取：允許集合判定的前提
	if name, ok := literalTableName(`literal:"users"`); !ok || name != "users" {
		t.Errorf("literalTableName 取不出字面表名（得 %q, %v）", name, ok)
	}
	if _, ok := literalTableName("target.table"); ok {
		t.Error("literalTableName 把非字面來源誤判為字面量")
	}
	// 字面 SQL 的表名抽取
	got := sqlTableRefs.FindAllStringSubmatch(`"UPDATE users SET x = ? FROM roles"`, -1)
	if len(got) != 2 || got[0][1] != "users" || got[1][1] != "roles" {
		t.Errorf("字面 SQL 表名抽取失效，得 %v", got)
	}
}
