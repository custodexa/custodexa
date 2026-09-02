package main

// 路由審計分類完備性守衛。
//
// # 為什麼需要這個守衛
//
// `extractResource`（`internal/middleware/audit_log.go`）是**手寫白名單 × 路徑段
// first-match**，而且是**加法制**：新增一條端點不需要碰它就能上線、既有測試全綠、
// 路由 golden 也全綠（golden 記的是 method/path/handler/中間件鏈，不記分類）。
// 於是「漏分類」是預設值而不是意外——現況 47 條路由從未有人決定過它們該歸哪一類，
// 它們只是靜靜落進 default 分支。而 default 分支回的是 `asset`，一個**有真實查詢面**
// 的類別：`audit_log.go:86-90` 無條件由 `resource==asset && resource_id!=nil` 推導
// `asset_id`，於是 17 條帶 `:id` 的兜底路由把告警規則 id／群組 id／OIDC provider id
// 寫進 `asset_id`——不是遺漏，是**假事件**。
//
// # 為什麼不能用「把現況寫成清單」的守衛
//
// 一份 `expectedClassification = map[path]resource{...}` 的斷言在新增端點時
// **不會有任何一條斷言失敗**：新端點不在 map 裡，迴圈根本不迭代到它。這正是現況——
// 193 條路由都被 `TestRoutesMatchGolden` 逐條比對過，47 條分類缺陷從中安然穿過。
//
// 故本守衛的**列舉來源是實際註冊的路由集**（`buildRouter` 的 `r.Routes()`），
// `auditRouteRegistry` 只是「決定的紀錄」，不是事實來源。新端點必然缺登記 ⇒ 必然紅，
// 作者被迫做出分類決定（可以決定「不入審計」，但必須寫下來並具名）。
//
// # 五個核對方向
//
//	方向 1（路由 → 登記）：每條註冊路由都必須有一筆登記。新增端點必然轉紅。
//	方向 2（登記 → 路由）：登記表不得有孤兒列（端點刪了登記留著＝過期的決定）。
//	方向 3（登記 → 實碼實算值）：登記宣告的分類必須等於分類器**實際算出**的值。
//	  登記表因此無法用來作弊——在表裡寫個好看的分類卻沒改分類器，方向 3 就紅。
//	方向 4（哨兵上限）：落兜底者總數 ≤ `maxUnclassifiedRoutes`。**要多一條就必須在
//	  同一份 diff 把這個數字調高**，不能靠加豁免繞過。
//	方向 5（`classNoIdentity` 雙向核對）：宣告「中介層永不為其寫列」者，其中間件鏈
//	  須不含認證中介層；反向亦釘住——鏈中無認證中介層者必須登記為 `classNoIdentity`。
//
// 另加**防假綠下界**：路由總數 < `minAuditRoutesScanned` 即 `Fatal`（不是 skip），
// 避免 `buildRouter` 失效時迴圈零迭代而全綠。
//
// # 方向 3 為什麼用 AST 模擬而不是直接呼叫 extractResource
//
// `extractResource` 是 `internal/middleware` 的未匯出函式，本包（組裝根）呼叫不到，
// 且不得為了測試而把它匯出（那會讓分類器的內部形狀變成公開契約）。故沿用
// `internal/guards/` 已驗證的形態：**直讀後端原始碼**。
//
// 但「讀原始碼再自己算一次」有個必須堵住的洞：如果分類器的**演算法結構**變了
// （例如多一層前置迴圈、改成最長前綴匹配），模擬會安靜地與實碼分歧。故
// `loadResourceClassifier` 對函式體施加**嚴格文法**：只接受
// 「`parts := strings.Split(path, "/")` ＋ N 個 `for range parts` 迴圈（每個迴圈體
// 恰一個 `if part == "字面量"` 或一個 `switch part`）＋ 一個兜底 `return`」這一種形狀。
// 任何偏離即 `Fatal` 並要求同步更新守衛——結構漂移從此是紅色，不是假綠。
//
// # 明載的邊界（不假裝涵蓋）
//
//   - 本守衛驗「有沒有做出分類決定」與「決定與實碼是否一致」，**不驗決定得對不對**。
//     把新端點登記成 `classNoIdentity` 是合法的，但它是白紙黑字、要具名的決定。
//   - 射程是**已註冊路由的路由層分類**。`parseRoute` 對 `/login`／`/logout` 的覆寫、
//     handler 以 `c.Set("audit_resource")` 的覆寫（全庫 3 處）、以及 handler 自寫的
//     審計列（SFTP／K8s 的 `resource=file`、`/recordings/stream` 的 AP-68）都不在
//     射程內；那條路徑由中介層側的實列守衛與 `audit_points_asset_pivot_guard_test.go`
//     承擔。
//   - `classNoIdentity` 的語義是「**審計中介層**必然早退」，不是「這條路由完全無留痕」：
//     其中數條（登入、refresh、改密、MFA、rtoken 取流）另有 handler 自寫的產生點。
//   - 分類「對不對」是語義判斷，機器判不出來。本守衛給的是**機械壓力**（必須做決定、
//     決定必須與實碼一致、未分類者受上限節制），不是完備證明。

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/custodexa/backend/internal/model"
)

// ── 分類詞彙（閉集合）────────────────────────────────────────────────────

type routeAuditClass string

const (
	// classResource 已做出分類決定：分類器命中具名段，回傳 `Resource` 欄宣告的值。
	classResource routeAuditClass = "已分類"
	// classNoIdentity 中間件鏈**不含認證中介層** ⇒ 無 `userID` ⇒ 審計中介層在
	// `audit_log.go:52-56` 早退，整筆不寫列。路由層分類對這些端點是空操作。
	// **不等於無留痕**：其中數條另有 handler 自寫的產生點（見檔頭邊界）。
	classNoIdentity routeAuditClass = "鏈中無認證中介層"
	// classUnclassified 已註冊、有身分、分類器**落兜底**。這是本 change 要消滅的
	// 缺陷本體，受 `maxUnclassifiedRoutes` 節制、逐步下修。
	classUnclassified routeAuditClass = "落兜底（未分類）"
)

var routeAuditClasses = map[routeAuditClass]bool{
	classResource: true, classNoIdentity: true, classUnclassified: true,
}

// routeAuditEntry 一條註冊路由的審計分類登記。
type routeAuditEntry struct {
	Class routeAuditClass
	// Resource 只對 classResource 有意義且**必須**等於分類器實算值（方向 3）。
	// 其餘兩類必須留空——留了值就是在登記表裡宣告一個實碼不承認的分類。
	Resource model.AuditResource
	// Why 分類理由。空字串不合法——沒有理由的分類等於沒有分類。
	//
	// **本欄僅供閱讀，不作為任何判準。** 守衛只機械核對 `Class` 與 `Resource`
	// （方向 1-5）；`Why` 的內容無論寫什麼、寫錯什麼，都不會使任何斷言轉紅。
	// 這不是疏漏而是刻意記載的邊界：**自由文字欄無機械核對，正是同型
	// 缺口得以長期潛伏的成因**（`audit-coverage` spec 亦明訂守衛 SHALL NOT
	// 以自由文字欄位作為判準）。
	// 故本欄的價值只在「下一個讀這張表的人不必重新盤查一次」，
	// 讀者不得反過來把它當成「這條路由確實有留痕」的證據——那要回去看
	// 產生點登記表（`manifest-audit-points.md`）與該產生點的行為測試。
	Why string
}

// maxUnclassifiedRoutes 落兜底路由的條數上限。
//
// **這不是「把現況寫成期望值」，而是單調下降的驗收儀表。** 起始值 47 是
// 2026-08-13 的實測數，分兩步收斂到 0。
//   - 第一步（2026-08-14）47 → 33：access-reviews 4／user-groups 6／transmission 3／
//     connect-tokens 1，四族的常數本就存在、只是未接上分類器。
//   - 第二步（2026-08-14）33 → **0**：alert-rules 4／asset-groups 6／audit-checkpoints 3／
//     audit-failures 1／audit-integrity 1／ldap-directory 4／notification-channels 5／
//     oidc-providers 4／roles 1／snippets 4，十族各新增一個常數，
//     且 `extractResource` 的兜底一併換成 `model.ResourceUnclassified` 哨兵。
//
// **上限為 0 之後這道守衛才真正閉合**：任何新端點若沒被分類器命中，方向 1（缺登記）
// 與方向 4（0 > 上限）會同時轉紅——漏分類從「靜默寫出假事件」變成「不改這一行就不能合併」。
//
// 契約兩條，缺一則儀表失效：
//  1. **要多一條未分類路由，就必須在同一份 diff 裡把這個數字調高**——沒有豁免清單、
//     沒有 skip 標記可以繞過它，唯一的放寬途徑是明確改這一行常數。
//     上限已為 0，故「調高」是一個必須有人簽字、且在 code review 中無所遁形的動作。
//  2. **下修只准伴隨真的分類修正**：方向 3 保證登記表改不動實碼，故想讓數字變小
//     只能真的去改 `extractResource`。
const maxUnclassifiedRoutes = 0

// minAuditRoutesScanned 防假綠下界：`buildRouter` 若失效（回空 map／註冊中斷），
// 逐路由迴圈會零迭代而全綠。低於此數即 `Fatal` 而非 skip——掃不到東西的守衛
// 不是「沒發現問題」，是「沒在看」。現況 194 條。
const minAuditRoutesScanned = 150

// minAuthenticatedRoutes 方向 5 的防假綠下界：認證中介層若改名，
// `authMiddlewareMarker` 會一條都認不出來，於是**全部**路由看起來都「無認證」，
// 方向 5 反而要求把它們全登記成 classNoIdentity——那是最糟的假綠。
// 現況 171 條（194 − 23）。
const minAuthenticatedRoutes = 150

// authMiddlewareMarker 認證中介層在鏈指紋中的識別片段。
// 鏈上的兩種形態皆含此片段：`main.AuthMiddleware`（全域掛載）與
// `...(*XxxHandler).RegisterRoutes.AuthMiddleware.funcN`（群組掛載）。
// 刻意**不**用 "AuthMiddleware" 裸字串：`(*AuthorizationHandler)`／`(*AuthHandler)`
// 等 receiver 名也含 "Auth"，前置的點使比對錨在函式名邊界上。
const authMiddlewareMarker = ".AuthMiddleware"

// ── 分類器原始碼的定位錨點 ────────────────────────────────────────────────

const (
	// classifierFileRel 分類器所在檔（相對 module 根）。
	classifierFileRel = "internal/middleware/audit_log.go"
	// classifierFuncName 分類器函式名。
	classifierFuncName = "extractResource"
	// resourceConstFileRel 審計資源常數所在檔（相對 module 根）。
	resourceConstFileRel = "internal/model/audit_log.go"
	// resourceConstTypeName 審計資源常數的型別名。
	resourceConstTypeName = "AuditResource"
	// authIdentityFileRel 唯一允許寫入 `userID` 語義鍵的檔（方向 5 的前提錨點）。
	authIdentityFileRel = "internal/middleware/auth.go"
	// authIdentityKey 審計中介層據以判定「有身分」的 context 鍵。
	authIdentityKey = "userID"
)

// minResourceConsts／minClassifierCases 兩個下界：常數表或 case 表被清空時，
// 模擬器會退化成「一律兜底」而所有 classResource 登記同時轉紅——那反而是好的。
// 但若清空發生在**登記表也被一起改掉**的 diff 裡，下界是最後一道攔截。
const (
	minResourceConsts   = 20
	minClassifierCases  = 15
	minClassifierValues = 20
)

// ── 登記表 ────────────────────────────────────────────────────────────────
//
// 鍵＝`{method, path}`（與路由 golden 同鍵），**不是 file:line**——路由搬家、
// handler 改名都不製造假紅，而真正的變動（新增／刪除端點）必然改變鍵集合。
//
// 再強調一次：**本表不是列舉來源**。列舉來源是 `buildRouter` 的 `r.Routes()`；
// 本表只是「每條路由的分類決定」的紀錄，且該紀錄必須通得過方向 3 的實碼對照。
var auditRouteRegistry = map[[2]string]routeAuditEntry{

	// ── classResource：分類器命中具名段（171 條）──
	{"POST", "/api/v1/access-requests"}:                                              {classResource, model.ResourceAccessRequest, "命中分類器段 `access-requests`"},
	{"POST", "/api/v1/access-requests/:id/approve"}:                                  {classResource, model.ResourceAccessRequest, "命中分類器段 `access-requests`"},
	{"POST", "/api/v1/access-requests/:id/cancel"}:                                   {classResource, model.ResourceAccessRequest, "命中分類器段 `access-requests`"},
	{"POST", "/api/v1/access-requests/:id/reject"}:                                   {classResource, model.ResourceAccessRequest, "命中分類器段 `access-requests`"},
	{"POST", "/api/v1/access-requests/:id/review"}:                                   {classResource, model.ResourceAccessRequest, "命中分類器段 `access-requests`"},
	{"POST", "/api/v1/access-requests/:id/revoke"}:                                   {classResource, model.ResourceAccessRequest, "命中分類器段 `access-requests`"},
	{"POST", "/api/v1/access-requests/break-glass"}:                                  {classResource, model.ResourceAccessRequest, "命中分類器段 `access-requests`"},
	{"GET", "/api/v1/access-requests/history"}:                                       {classResource, model.ResourceAccessRequest, "命中分類器段 `access-requests`"},
	{"GET", "/api/v1/access-requests/mine"}:                                          {classResource, model.ResourceAccessRequest, "命中分類器段 `access-requests`"},
	{"GET", "/api/v1/access-requests/mine/tickets"}:                                  {classResource, model.ResourceAccessRequest, "命中分類器段 `access-requests`"},
	{"GET", "/api/v1/access-requests/pending"}:                                       {classResource, model.ResourceAccessRequest, "命中分類器段 `access-requests`"},
	{"GET", "/api/v1/access-requests/pending/count"}:                                 {classResource, model.ResourceAccessRequest, "命中分類器段 `access-requests`"},
	{"GET", "/api/v1/access-requests/reviews/pending"}:                               {classResource, model.ResourceAccessRequest, "命中分類器段 `access-requests`"},
	{"GET", "/api/v1/access-requests/tickets"}:                                       {classResource, model.ResourceAccessRequest, "命中分類器段 `access-requests`"},
	{"GET", "/api/v1/access-reviews"}:                                                {classResource, model.ResourceAccessReview, "命中分類器段 `access-reviews`（既有常數接線）"},
	{"POST", "/api/v1/access-reviews"}:                                               {classResource, model.ResourceAccessReview, "命中分類器段 `access-reviews`（既有常數接線）"},
	{"GET", "/api/v1/access-reviews/:id"}:                                            {classResource, model.ResourceAccessReview, "命中分類器段 `access-reviews`（既有常數接線）；`:id` 指向複審單，離開 asset 後不再灌進 asset_id"},
	{"GET", "/api/v1/access-reviews/matrix"}:                                         {classResource, model.ResourceAccessReview, "命中分類器段 `access-reviews`（既有常數接線）"},
	{"GET", "/api/v1/alert-rules"}:                                                   {classResource, model.ResourceAlertRule, "命中分類器段 `alert-rules`（新增常數接線）；設定變更（非審計資料讀取），不入 auditSensitiveResources；`:id` 指向規則列"},
	{"POST", "/api/v1/alert-rules"}:                                                  {classResource, model.ResourceAlertRule, "命中分類器段 `alert-rules`（新增常數接線）；設定變更（非審計資料讀取），不入 auditSensitiveResources；`:id` 指向規則列"},
	{"DELETE", "/api/v1/alert-rules/:id"}:                                            {classResource, model.ResourceAlertRule, "命中分類器段 `alert-rules`（新增常數接線）；設定變更（非審計資料讀取），不入 auditSensitiveResources；`:id` 指向規則列"},
	{"PUT", "/api/v1/alert-rules/:id"}:                                               {classResource, model.ResourceAlertRule, "命中分類器段 `alert-rules`（新增常數接線）；設定變更（非審計資料讀取），不入 auditSensitiveResources；`:id` 指向規則列"},
	{"GET", "/api/v1/approver-scopes"}:                                               {classResource, model.ResourceApproverScope, "命中分類器段 `approver-scopes`"},
	{"POST", "/api/v1/approver-scopes"}:                                              {classResource, model.ResourceApproverScope, "命中分類器段 `approver-scopes`"},
	{"DELETE", "/api/v1/approver-scopes/:id"}:                                        {classResource, model.ResourceApproverScope, "命中分類器段 `approver-scopes`"},
	{"GET", "/api/v1/asset-groups"}:                                                  {classResource, model.ResourceAssetGroup, "命中分類器段 `asset-groups`（新增常數接線）；設定變更（非審計資料讀取），不入 auditSensitiveResources；`:id` 指向分組列，非資產 id"},
	{"POST", "/api/v1/asset-groups"}:                                                 {classResource, model.ResourceAssetGroup, "命中分類器段 `asset-groups`（新增常數接線）；設定變更（非審計資料讀取），不入 auditSensitiveResources；`:id` 指向分組列，非資產 id"},
	{"DELETE", "/api/v1/asset-groups/:id"}:                                           {classResource, model.ResourceAssetGroup, "命中分類器段 `asset-groups`（新增常數接線）；設定變更（非審計資料讀取），不入 auditSensitiveResources；`:id` 指向分組列，非資產 id"},
	{"PUT", "/api/v1/asset-groups/:id"}:                                              {classResource, model.ResourceAssetGroup, "命中分類器段 `asset-groups`（新增常數接線）；設定變更（非審計資料讀取），不入 auditSensitiveResources；`:id` 指向分組列，非資產 id"},
	{"PUT", "/api/v1/asset-groups/:id/move"}:                                         {classResource, model.ResourceAssetGroup, "命中分類器段 `asset-groups`（新增常數接線）；設定變更（非審計資料讀取），不入 auditSensitiveResources；`:id` 指向分組列，非資產 id"},
	{"GET", "/api/v1/asset-groups/tree"}:                                             {classResource, model.ResourceAssetGroup, "命中分類器段 `asset-groups`（新增常數接線）；設定變更（非審計資料讀取），不入 auditSensitiveResources；`:id` 指向分組列，非資產 id"},
	{"GET", "/api/v1/assets"}:                                                        {classResource, model.ResourceAsset, "命中分類器段 `assets`"},
	{"POST", "/api/v1/assets"}:                                                       {classResource, model.ResourceAsset, "命中分類器段 `assets`"},
	{"DELETE", "/api/v1/assets/:id"}:                                                 {classResource, model.ResourceAsset, "命中分類器段 `assets`"},
	{"GET", "/api/v1/assets/:id"}:                                                    {classResource, model.ResourceAsset, "命中分類器段 `assets`"},
	{"PUT", "/api/v1/assets/:id"}:                                                    {classResource, model.ResourceAsset, "命中分類器段 `assets`"},
	{"GET", "/api/v1/assets/:id/accounts"}:                                           {classResource, model.ResourceAsset, "命中分類器段 `assets`"},
	{"POST", "/api/v1/assets/:id/accounts"}:                                          {classResource, model.ResourceAsset, "命中分類器段 `assets`"},
	{"DELETE", "/api/v1/assets/:id/accounts/:accountId"}:                             {classResource, model.ResourceAsset, "命中分類器段 `assets`"},
	{"PUT", "/api/v1/assets/:id/accounts/:accountId"}:                                {classResource, model.ResourceAsset, "命中分類器段 `assets`"},
	{"POST", "/api/v1/assets/:id/accounts/:accountId/set-default"}:                   {classResource, model.ResourceAsset, "命中分類器段 `assets`"},
	{"DELETE", "/api/v1/assets/:id/files"}:                                           {classResource, model.ResourceAsset, "命中分類器段 `assets`"},
	{"GET", "/api/v1/assets/:id/files"}:                                              {classResource, model.ResourceAsset, "命中分類器段 `assets`"},
	{"GET", "/api/v1/assets/:id/files/download"}:                                     {classResource, model.ResourceAsset, "命中分類器段 `assets`"},
	{"POST", "/api/v1/assets/:id/files/mkdir"}:                                       {classResource, model.ResourceAsset, "命中分類器段 `assets`"},
	{"POST", "/api/v1/assets/:id/files/upload"}:                                      {classResource, model.ResourceAsset, "命中分類器段 `assets`"},
	{"DELETE", "/api/v1/assets/:id/host-key"}:                                        {classResource, model.ResourceAsset, "命中分類器段 `assets`"},
	{"GET", "/api/v1/assets/:id/host-key"}:                                           {classResource, model.ResourceAsset, "命中分類器段 `assets`"},
	{"GET", "/api/v1/assets/:id/k8s/download"}:                                       {classResource, model.ResourceAsset, "命中分類器段 `assets`"},
	{"GET", "/api/v1/assets/:id/k8s/pods"}:                                           {classResource, model.ResourceAsset, "命中分類器段 `assets`"},
	{"POST", "/api/v1/assets/:id/k8s/upload"}:                                        {classResource, model.ResourceAsset, "命中分類器段 `assets`"},
	{"POST", "/api/v1/assets/:id/test-connection"}:                                   {classResource, model.ResourceAsset, "命中分類器段 `assets`"},
	{"GET", "/api/v1/assets/:id/transfer-capabilities"}:                              {classResource, model.ResourceAsset, "命中分類器段 `assets`"},
	{"GET", "/api/v1/assets/tags"}:                                                   {classResource, model.ResourceAsset, "命中分類器段 `assets`"},
	{"POST", "/api/v1/assets/tags/delete"}:                                           {classResource, model.ResourceAsset, "命中分類器段 `assets`"},
	{"POST", "/api/v1/assets/tags/rename"}:                                           {classResource, model.ResourceAsset, "命中分類器段 `assets`"},
	{"GET", "/api/v1/audit-checkpoints"}:                                             {classResource, model.ResourceAuditCheckpoint, "命中分類器段 `audit-checkpoints`（新增常數接線）；審計資料讀取，**入 auditSensitiveResources**（PCI 10.2.1.3；/verify 帶 seq_from／seq_to）"},
	{"GET", "/api/v1/audit-checkpoints/public-key"}:                                  {classResource, model.ResourceAuditCheckpoint, "命中分類器段 `audit-checkpoints`（新增常數接線）；審計資料讀取，**入 auditSensitiveResources**（PCI 10.2.1.3；/verify 帶 seq_from／seq_to）"},
	{"GET", "/api/v1/audit-checkpoints/verify"}:                                      {classResource, model.ResourceAuditCheckpoint, "命中分類器段 `audit-checkpoints`（新增常數接線）；審計資料讀取，**入 auditSensitiveResources**（PCI 10.2.1.3；/verify 帶 seq_from／seq_to）"},
	{"GET", "/api/v1/audit-export"}:                                                  {classResource, model.ResourceAuditExport, "命中分類器段 `audit-export`"},
	{"POST", "/api/v1/audit-export/jobs"}:                                            {classResource, model.ResourceAuditExport, "命中分類器段 `audit-export`；證據包 job 發起，另有 handler 側審計（AP-75）含完整篩選快照，中介層本列為請求層留痕、兩者並存"},
	{"GET", "/api/v1/audit-export/jobs"}:                                             {classResource, model.ResourceAuditExport, "命中分類器段 `audit-export`；申請者本人 job 清單（敏感資源 GET 記查詢摘要）"},
	{"GET", "/api/v1/audit-export/jobs/:id/download"}:                                {classResource, model.ResourceAuditExport, "命中分類器段 `audit-export`；產物下載＝取走證物整包，另有 handler 側逐次下載審計（AP-75），拒絕同樣入審計"},
	{"GET", "/api/v1/audit-export/public-key"}:                                       {classResource, model.ResourceAuditExport, "命中分類器段 `audit-export`"},
	{"GET", "/api/v1/rotation-report"}:                                               {classResource, model.ResourceRotationReport, "命中分類器段 `rotation-report`（新增常數接線）；輪替證據報告的資料集讀取（audit:view）"},
	{"GET", "/api/v1/rotation-report/records"}:                                       {classResource, model.ResourceRotationReport, "命中分類器段 `rotation-report`；區間內改密記錄明細的分頁讀取"},
	{"POST", "/api/v1/rotation-report/jobs"}:                                         {classResource, model.ResourceRotationReport, "命中分類器段 `rotation-report`；手動產出，另有 handler 側審計（AP-83）含範圍與區間，中介層本列為請求層留痕、兩者並存"},
	{"GET", "/api/v1/rotation-report/schedules"}:                                     {classResource, model.ResourceRotationReport, "命中分類器段 `rotation-report`；排程列表（admin）"},
	{"POST", "/api/v1/rotation-report/schedules"}:                                    {classResource, model.ResourceRotationReport, "命中分類器段 `rotation-report`；建立排程，resource_id 為排程列 id（AP-83）"},
	{"PUT", "/api/v1/rotation-report/schedules/:id"}:                                 {classResource, model.ResourceRotationReport, "命中分類器段 `rotation-report`；修改排程，`:id` 指向排程列而非資產"},
	{"DELETE", "/api/v1/rotation-report/schedules/:id"}:                              {classResource, model.ResourceRotationReport, "命中分類器段 `rotation-report`；刪除排程"},
	{"POST", "/api/v1/rotation-report/schedules/:id/run"}:                            {classResource, model.ResourceRotationReport, "命中分類器段 `rotation-report`；立即依排程規則產一份（提前的一期，同樣推進區間錨點）"},
	{"GET", "/api/v1/audit-failures"}:                                                {classResource, model.ResourceAuditFailure, "命中分類器段 `audit-failures`（新增常數接線）；審計資料讀取，**入 auditSensitiveResources**（PCI 10.2.1.3）"},
	{"GET", "/api/v1/audit-integrity/verify"}:                                        {classResource, model.ResourceAuditIntegrity, "命中分類器段 `audit-integrity`（新增常數接線）；審計資料讀取，**入 auditSensitiveResources**（PCI 10.2.1.3；驗證帶時間範圍）"},
	{"GET", "/api/v1/audit-logs"}:                                                    {classResource, model.ResourceAuditLog, "命中分類器段 `audit-logs`"},
	{"GET", "/api/v1/audit-logs/:id"}:                                                {classResource, model.ResourceAuditLog, "命中分類器段 `audit-logs`"},
	{"GET", "/api/v1/audit-logs/resource/:resource/:id"}:                             {classResource, model.ResourceAuditLog, "命中分類器段 `audit-logs`"},
	{"GET", "/api/v1/audit/subjects"}:                                                {classResource, model.ResourceAuditTimeline, "命中分類器段 `subjects`；稽核工作台聚合讀取"},
	{"GET", "/api/v1/audit/timeline"}:                                                {classResource, model.ResourceAuditTimeline, "命中分類器段 `timeline`；稽核工作台聚合讀取"},
	{"POST", "/api/v1/auth/logout"}:                                                  {classResource, model.ResourceAuth, "命中分類器段 `auth`"},
	{"GET", "/api/v1/auth/me"}:                                                       {classResource, model.ResourceAuth, "命中分類器段 `auth`"},
	{"PATCH", "/api/v1/auth/me"}:                                                     {classResource, model.ResourceAuth, "命中分類器段 `auth`"},
	{"POST", "/api/v1/auth/mfa/disable"}:                                             {classResource, model.ResourceAuth, "命中分類器段 `auth`"},
	{"POST", "/api/v1/auth/mfa/enable"}:                                              {classResource, model.ResourceAuth, "命中分類器段 `auth`"},
	{"POST", "/api/v1/auth/mfa/setup"}:                                               {classResource, model.ResourceAuth, "命中分類器段 `auth`"},
	{"GET", "/api/v1/authorizations"}:                                                {classResource, model.ResourceAuthorization, "命中分類器段 `authorizations`"},
	{"POST", "/api/v1/authorizations"}:                                               {classResource, model.ResourceAuthorization, "命中分類器段 `authorizations`"},
	{"DELETE", "/api/v1/authorizations/:id"}:                                         {classResource, model.ResourceAuthorization, "命中分類器段 `authorizations`"},
	{"PUT", "/api/v1/authorizations/:id/accounts"}:                                   {classResource, model.ResourceAuthorization, "命中分類器段 `authorizations`"},
	{"POST", "/api/v1/authorizations/batch"}:                                         {classResource, model.ResourceAuthorization, "命中分類器段 `authorizations`"},
	{"GET", "/api/v1/authorizations/effective-assets"}:                               {classResource, model.ResourceAuthorization, "命中分類器段 `authorizations`"},
	{"GET", "/api/v1/authorizations/effective-users"}:                                {classResource, model.ResourceAuthorization, "命中分類器段 `authorizations`"},
	{"GET", "/api/v1/change-secret-candidates"}:                                      {classResource, model.ResourceChangeSecretPlan, "命中分類器段 `change-secret-candidates`；併入改密計畫分類（varchar(20) 放不下獨立常數）"},
	{"DELETE", "/api/v1/change-secret-candidates/:id"}:                               {classResource, model.ResourceChangeSecretPlan, "命中分類器段 `change-secret-candidates`；併入改密計畫分類（varchar(20) 放不下獨立常數）"},
	{"POST", "/api/v1/change-secret-candidates/:id/retry"}:                           {classResource, model.ResourceChangeSecretPlan, "命中分類器段 `change-secret-candidates`；併入改密計畫分類（varchar(20) 放不下獨立常數）"},
	{"GET", "/api/v1/change-secret-plans"}:                                           {classResource, model.ResourceChangeSecretPlan, "命中分類器段 `change-secret-plans`"},
	{"POST", "/api/v1/change-secret-plans"}:                                          {classResource, model.ResourceChangeSecretPlan, "命中分類器段 `change-secret-plans`"},
	{"DELETE", "/api/v1/change-secret-plans/:id"}:                                    {classResource, model.ResourceChangeSecretPlan, "命中分類器段 `change-secret-plans`"},
	{"PUT", "/api/v1/change-secret-plans/:id"}:                                       {classResource, model.ResourceChangeSecretPlan, "命中分類器段 `change-secret-plans`"},
	{"GET", "/api/v1/change-secret-plans/:id/records"}:                               {classResource, model.ResourceChangeSecretPlan, "命中分類器段 `change-secret-plans`"},
	{"POST", "/api/v1/change-secret-plans/:id/run"}:                                  {classResource, model.ResourceChangeSecretPlan, "命中分類器段 `change-secret-plans`"},
	{"GET", "/api/v1/command-alerts"}:                                                {classResource, model.ResourceCommandAlert, "命中分類器段 `command-alerts`"},
	{"POST", "/api/v1/command-alerts/:id/review"}:                                    {classResource, model.ResourceCommandAlert, "命中分類器段 `command-alerts`"},
	{"GET", "/api/v1/commands"}:                                                      {classResource, model.ResourceCommand, "命中分類器段 `commands`"},
	{"POST", "/api/v1/connect-tokens"}:                                               {classResource, model.ResourceSession, "命中分類器段 `connect-tokens`（既有常數接線）；票證簽發是「開一場連線」的前置動作，歸 session 而非另立常數"},
	{"GET", "/api/v1/daily-reviews"}:                                                 {classResource, model.ResourceDailyReview, "命中分類器段 `daily-reviews`"},
	{"POST", "/api/v1/daily-reviews"}:                                                {classResource, model.ResourceDailyReview, "命中分類器段 `daily-reviews`"},
	{"GET", "/api/v1/daily-reviews/status"}:                                          {classResource, model.ResourceDailyReview, "命中分類器段 `daily-reviews`"},
	{"GET", "/api/v1/keys"}:                                                          {classResource, model.ResourceKeyManagement, "命中分類器段 `keys`"},
	{"DELETE", "/api/v1/keys/retired-material"}:                                      {classResource, model.ResourceKeyManagement, "命中分類器段 `keys`"},
	{"DELETE", "/api/v1/keys/rewrap"}:                                                {classResource, model.ResourceKeyManagement, "命中分類器段 `keys`"},
	{"POST", "/api/v1/keys/rewrap"}:                                                  {classResource, model.ResourceKeyManagement, "命中分類器段 `keys`"},
	{"POST", "/api/v1/keys/rotate"}:                                                  {classResource, model.ResourceKeyManagement, "命中分類器段 `keys`"},
	{"GET", "/api/v1/offsite-storage/status"}:                                        {classResource, model.ResourceOffsiteStorage, "命中分類器段 `offsite-storage`（新增常數接線）；設定變更與運維動作（非審計資料讀取），不入 auditSensitiveResources；`:id` 分別指向帳冊列與世代列，**都不是資產或會話 id**"},
	{"GET", "/api/v1/offsite-storage/failures"}:                                      {classResource, model.ResourceOffsiteStorage, "命中分類器段 `offsite-storage`（新增常數接線）；設定變更與運維動作（非審計資料讀取），不入 auditSensitiveResources；`:id` 分別指向帳冊列與世代列，**都不是資產或會話 id**"},
	{"POST", "/api/v1/offsite-storage/test"}:                                         {classResource, model.ResourceOffsiteStorage, "命中分類器段 `offsite-storage`（新增常數接線）；設定變更與運維動作（非審計資料讀取），不入 auditSensitiveResources；`:id` 分別指向帳冊列與世代列，**都不是資產或會話 id**"},
	{"POST", "/api/v1/offsite-storage/retry-failed"}:                                 {classResource, model.ResourceOffsiteStorage, "命中分類器段 `offsite-storage`（新增常數接線）；設定變更與運維動作（非審計資料讀取），不入 auditSensitiveResources；`:id` 分別指向帳冊列與世代列，**都不是資產或會話 id**"},
	{"POST", "/api/v1/offsite-storage/objects/:id/retry"}:                            {classResource, model.ResourceOffsiteStorage, "命中分類器段 `offsite-storage`（新增常數接線）；設定變更與運維動作（非審計資料讀取），不入 auditSensitiveResources；`:id` 分別指向帳冊列與世代列，**都不是資產或會話 id**"},
	{"GET", "/api/v1/offsite-storage/settings"}:                                      {classResource, model.ResourceOffsiteStorage, "命中分類器段 `offsite-storage`（新增常數接線）；設定變更與運維動作（非審計資料讀取），不入 auditSensitiveResources；`:id` 分別指向帳冊列與世代列，**都不是資產或會話 id**"},
	{"PUT", "/api/v1/offsite-storage/settings"}:                                      {classResource, model.ResourceOffsiteStorage, "命中分類器段 `offsite-storage`（新增常數接線）；設定變更與運維動作（非審計資料讀取），不入 auditSensitiveResources；`:id` 分別指向帳冊列與世代列，**都不是資產或會話 id**"},
	{"POST", "/api/v1/offsite-storage/settings/confirm"}:                             {classResource, model.ResourceOffsiteStorage, "命中分類器段 `offsite-storage`（新增常數接線）；設定變更與運維動作（非審計資料讀取），不入 auditSensitiveResources；`:id` 分別指向帳冊列與世代列，**都不是資產或會話 id**"},
	{"POST", "/api/v1/offsite-storage/settings/disable"}:                             {classResource, model.ResourceOffsiteStorage, "命中分類器段 `offsite-storage`（新增常數接線）；設定變更與運維動作（非審計資料讀取），不入 auditSensitiveResources；`:id` 分別指向帳冊列與世代列，**都不是資產或會話 id**"},
	{"GET", "/api/v1/offsite-storage/profiles"}:                                      {classResource, model.ResourceOffsiteStorage, "命中分類器段 `offsite-storage`（新增常數接線）；設定變更與運維動作（非審計資料讀取），不入 auditSensitiveResources；`:id` 分別指向帳冊列與世代列，**都不是資產或會話 id**"},
	{"POST", "/api/v1/offsite-storage/profiles/:id/revoke-credentials"}:              {classResource, model.ResourceOffsiteStorage, "命中分類器段 `offsite-storage`（新增常數接線）；設定變更與運維動作（非審計資料讀取），不入 auditSensitiveResources；`:id` 分別指向帳冊列與世代列，**都不是資產或會話 id**"},
	{"DELETE", "/api/v1/ldap-directory"}:                                             {classResource, model.ResourceLDAPDirectory, "命中分類器段 `ldap-directory`（新增常數接線）；設定變更（非審計資料讀取），不入 auditSensitiveResources；單例，無 `:id`"},
	{"GET", "/api/v1/ldap-directory"}:                                                {classResource, model.ResourceLDAPDirectory, "命中分類器段 `ldap-directory`（新增常數接線）；設定變更（非審計資料讀取），不入 auditSensitiveResources；單例，無 `:id`"},
	{"PUT", "/api/v1/ldap-directory"}:                                                {classResource, model.ResourceLDAPDirectory, "命中分類器段 `ldap-directory`（新增常數接線）；設定變更（非審計資料讀取），不入 auditSensitiveResources；單例，無 `:id`"},
	{"POST", "/api/v1/ldap-directory/test"}:                                          {classResource, model.ResourceLDAPDirectory, "命中分類器段 `ldap-directory`（新增常數接線）；設定變更（非審計資料讀取），不入 auditSensitiveResources；單例，無 `:id`"},
	{"GET", "/api/v1/instance-guard"}:                                                {classResource, model.ResourceInstanceGuard, "命中分類器段 `instance-guard`（新增常數接線）；管理者限定的守衛快照（含持鎖者指紋與確認碼），每次呼叫一列讀取留痕——「哪個管理者何時看了衝突細節」本身是有價值的留痕；介面不輪詢（粗狀態輪詢走 /seal/status，classNoIdentity）；唯讀、無 `:id`，不入 auditSensitiveResources"},
	{"GET", "/api/v1/my/connections"}:                                                {classResource, model.ResourceSession, "命中分類器段 `connections`；/my/connections* 操作的是 session"},
	{"POST", "/api/v1/my/connections/:id/terminate"}:                                 {classResource, model.ResourceSession, "命中分類器段 `connections`；/my/connections* 操作的是 session"},
	{"GET", "/api/v1/notification-channels"}:                                         {classResource, model.ResourceNotifyChannel, "命中分類器段 `notification-channels`（新增常數接線）；設定變更（非審計資料讀取），不入 auditSensitiveResources；`:id` 指向通道列"},
	{"POST", "/api/v1/notification-channels"}:                                        {classResource, model.ResourceNotifyChannel, "命中分類器段 `notification-channels`（新增常數接線）；設定變更（非審計資料讀取），不入 auditSensitiveResources；`:id` 指向通道列"},
	{"DELETE", "/api/v1/notification-channels/:id"}:                                  {classResource, model.ResourceNotifyChannel, "命中分類器段 `notification-channels`（新增常數接線）；設定變更（非審計資料讀取），不入 auditSensitiveResources；`:id` 指向通道列"},
	{"PUT", "/api/v1/notification-channels/:id"}:                                     {classResource, model.ResourceNotifyChannel, "命中分類器段 `notification-channels`（新增常數接線）；設定變更（非審計資料讀取），不入 auditSensitiveResources；`:id` 指向通道列"},
	{"POST", "/api/v1/notification-channels/:id/test"}:                               {classResource, model.ResourceNotifyChannel, "命中分類器段 `notification-channels`（新增常數接線）；設定變更（非審計資料讀取），不入 auditSensitiveResources；`:id` 指向通道列"},
	{"GET", "/api/v1/oidc-providers"}:                                                {classResource, model.ResourceOIDCProvider, "命中分類器段 `oidc-providers`（新增常數接線）；設定變更（非審計資料讀取），不入 auditSensitiveResources；`:id` 指向提供者列"},
	{"POST", "/api/v1/oidc-providers"}:                                               {classResource, model.ResourceOIDCProvider, "命中分類器段 `oidc-providers`（新增常數接線）；設定變更（非審計資料讀取），不入 auditSensitiveResources；`:id` 指向提供者列"},
	{"DELETE", "/api/v1/oidc-providers/:id"}:                                         {classResource, model.ResourceOIDCProvider, "命中分類器段 `oidc-providers`（新增常數接線）；設定變更（非審計資料讀取），不入 auditSensitiveResources；`:id` 指向提供者列"},
	{"PUT", "/api/v1/oidc-providers/:id"}:                                            {classResource, model.ResourceOIDCProvider, "命中分類器段 `oidc-providers`（新增常數接線）；設定變更（非審計資料讀取），不入 auditSensitiveResources；`:id` 指向提供者列"},
	{"GET", "/api/v1/recordings/stats"}:                                              {classResource, model.ResourceRecording, "命中分類器段 `recordings`"},
	{"GET", "/api/v1/roles"}:                                                         {classResource, model.ResourceRole, "命中分類器段 `roles`（新增常數接線）；設定面讀取（非審計資料讀取），不入 auditSensitiveResources；無 `:id`"},
	{"GET", "/api/v1/security-policies"}:                                             {classResource, model.ResourceSecurityPolicy, "命中分類器段 `security-policies`"},
	{"PUT", "/api/v1/security-policies"}:                                             {classResource, model.ResourceSecurityPolicy, "命中分類器段 `security-policies`"},
	{"GET", "/api/v1/sessions"}:                                                      {classResource, model.ResourceSession, "命中分類器段 `sessions`"},
	{"GET", "/api/v1/sessions/:id"}:                                                  {classResource, model.ResourceSession, "命中分類器段 `sessions`"},
	{"GET", "/api/v1/sessions/:id/clipboard-events"}:                                 {classResource, model.ResourceClipboardEvent, "命中分類器段 `clipboard-events`；子資源前置特判先於容器段 sessions"},
	{"GET", "/api/v1/sessions/:id/clipboard-events/:eventID/content"}:                {classResource, model.ResourceClipboardEvent, "命中分類器段 `clipboard-events`；單筆內容調閱＝取走證物本體，另有 handler 側逐筆 fail-close 留痕（AP-74），中介層本列為請求層留痕、兩者語義並存"},
	{"GET", "/api/v1/sessions/:id/commands"}:                                         {classResource, model.ResourceCommand, "命中前置特判段 `commands`；取走指令原文＝取證，與容器段 sessions 分開"},
	{"DELETE", "/api/v1/sessions/:id/recording"}:                                     {classResource, model.ResourceRecording, "命中前置特判段 `recording`；刪除錄影證物須與一般連線操作分得開"},
	{"GET", "/api/v1/sessions/:id/recording"}:                                        {classResource, model.ResourceRecording, "命中前置特判段 `recording`；錄影中繼資料讀取與取流同族"},
	{"GET", "/api/v1/sessions/:id/recording/download"}:                               {classResource, model.ResourceRecording, "命中前置特判段 `recording`；取走終端畫面錄影本體＝取證"},
	{"GET", "/api/v1/sessions/:id/recording/stream"}:                                 {classResource, model.ResourceRecording, "命中前置特判段 `recording`；取走終端畫面錄影本體＝取證"},
	{"POST", "/api/v1/sessions/:id/recording/token"}:                                 {classResource, model.ResourceRecording, "命中前置特判段 `recording`；簽發取流票證是取證動作的起點"},
	{"DELETE", "/api/v1/sessions/:id/share"}:                                         {classResource, model.ResourceSession, "命中分類器段 `sessions`"},
	{"POST", "/api/v1/sessions/:id/share"}:                                           {classResource, model.ResourceSession, "命中分類器段 `sessions`"},
	{"POST", "/api/v1/sessions/:id/terminate"}:                                       {classResource, model.ResourceSession, "命中分類器段 `sessions`"},
	{"GET", "/api/v1/sessions/active"}:                                               {classResource, model.ResourceSession, "命中分類器段 `sessions`"},
	{"GET", "/api/v1/sessions/statistics"}:                                           {classResource, model.ResourceSession, "命中分類器段 `sessions`"},
	{"GET", "/api/v1/snippets"}:                                                      {classResource, model.ResourceSnippet, "命中分類器段 `snippets`（新增常數接線）；設定變更（非審計資料讀取），不入 auditSensitiveResources；`:id` 指向片段列"},
	{"POST", "/api/v1/snippets"}:                                                     {classResource, model.ResourceSnippet, "命中分類器段 `snippets`（新增常數接線）；設定變更（非審計資料讀取），不入 auditSensitiveResources；`:id` 指向片段列"},
	{"DELETE", "/api/v1/snippets/:id"}:                                               {classResource, model.ResourceSnippet, "命中分類器段 `snippets`（新增常數接線）；設定變更（非審計資料讀取），不入 auditSensitiveResources；`:id` 指向片段列"},
	{"PUT", "/api/v1/snippets/:id"}:                                                  {classResource, model.ResourceSnippet, "命中分類器段 `snippets`（新增常數接線）；設定變更（非審計資料讀取），不入 auditSensitiveResources；`:id` 指向片段列"},
	{"GET", "/api/v1/ssh/sessions/:id/stats"}:                                        {classResource, model.ResourceSession, "命中分類器段 `sessions`"},
	{"GET", "/api/v1/syslog-settings"}:                                               {classResource, model.ResourceSyslogSetting, "命中分類器段 `syslog-settings`"},
	{"PUT", "/api/v1/syslog-settings"}:                                               {classResource, model.ResourceSyslogSetting, "命中分類器段 `syslog-settings`"},
	{"POST", "/api/v1/syslog-settings/test"}:                                         {classResource, model.ResourceSyslogSetting, "命中分類器段 `syslog-settings`"},
	{"POST", "/api/v1/transmission-consents"}:                                        {classResource, model.ResourceTransmission, "命中分類器段 `transmission-consents`（既有常數接線）；與清冊同歸 transmission——同一份政策的兩面"},
	{"GET", "/api/v1/transmission-inventory"}:                                        {classResource, model.ResourceTransmission, "命中分類器段 `transmission-inventory`（既有常數接線）"},
	{"POST", "/api/v1/transmission-inventory/export"}:                                {classResource, model.ResourceTransmission, "命中分類器段 `transmission-inventory`（既有常數接線）"},
	{"GET", "/api/v1/user-groups"}:                                                   {classResource, model.ResourceUserGroup, "命中分類器段 `user-groups`（既有常數接線）"},
	{"POST", "/api/v1/user-groups"}:                                                  {classResource, model.ResourceUserGroup, "命中分類器段 `user-groups`（既有常數接線）"},
	{"DELETE", "/api/v1/user-groups/:id"}:                                            {classResource, model.ResourceUserGroup, "命中分類器段 `user-groups`（既有常數接線）；`:id` 指向群組，離開 asset 後不再灌進 asset_id"},
	{"PUT", "/api/v1/user-groups/:id"}:                                               {classResource, model.ResourceUserGroup, "命中分類器段 `user-groups`（既有常數接線）；`:id` 指向群組，離開 asset 後不再灌進 asset_id"},
	{"GET", "/api/v1/user-groups/:id/authorization-count"}:                           {classResource, model.ResourceUserGroup, "命中分類器段 `user-groups`（既有常數接線）；`authorization-count` 非 `authorizations` 段，不被授權分類吃掉"},
	{"PUT", "/api/v1/user-groups/:id/members"}:                                       {classResource, model.ResourceUserGroup, "命中分類器段 `user-groups`（既有常數接線）；`:id` 指向群組，離開 asset 後不再灌進 asset_id"},
	{"GET", "/api/v1/users"}:                                                         {classResource, model.ResourceUser, "命中分類器段 `users`"},
	{"POST", "/api/v1/users"}:                                                        {classResource, model.ResourceUser, "命中分類器段 `users`"},
	{"DELETE", "/api/v1/users/:id"}:                                                  {classResource, model.ResourceUser, "命中分類器段 `users`"},
	{"GET", "/api/v1/users/:id"}:                                                     {classResource, model.ResourceUser, "命中分類器段 `users`"},
	{"PUT", "/api/v1/users/:id"}:                                                     {classResource, model.ResourceUser, "命中分類器段 `users`"},
	{"GET", "/api/v1/users/:id/external-identities"}:                                 {classResource, model.ResourceUser, "命中分類器段 `users`"},
	{"POST", "/api/v1/users/:id/external-identities"}:                                {classResource, model.ResourceUser, "命中分類器段 `users`"},
	{"DELETE", "/api/v1/users/:id/external-identities/:identityId"}:                  {classResource, model.ResourceUser, "命中分類器段 `users`"},
	{"POST", "/api/v1/users/:id/external-identities/:identityId/unbind-and-disable"}: {classResource, model.ResourceUser, "命中分類器段 `users`"},
	{"POST", "/api/v1/users/:id/external-only"}:                                      {classResource, model.ResourceUser, "命中分類器段 `users`"},
	{"PUT", "/api/v1/users/:id/inactivity-exempt"}:                                   {classResource, model.ResourceUser, "命中分類器段 `users`"},
	{"POST", "/api/v1/users/:id/mfa/disable"}:                                        {classResource, model.ResourceUser, "命中分類器段 `users`"},
	{"PUT", "/api/v1/users/:id/password"}:                                            {classResource, model.ResourceUser, "命中分類器段 `users`"},
	{"PUT", "/api/v1/users/:id/roles"}:                                               {classResource, model.ResourceUser, "命中分類器段 `users`"},
	{"POST", "/api/v1/users/:id/roles/:role"}:                                        {classResource, model.ResourceUser, "命中分類器段 `users`"},
	{"PUT", "/api/v1/users/:id/status"}:                                              {classResource, model.ResourceUser, "命中分類器段 `users`"},
	{"POST", "/api/v1/users/:id/unlock"}:                                             {classResource, model.ResourceUser, "命中分類器段 `users`"},
	{"GET", "/api/v1/users/local-admin-count"}:                                       {classResource, model.ResourceUser, "命中分類器段 `users`"},
	{"POST", "/api/v1/users/source-policy/check"}:                                    {classResource, model.ResourceUser, "命中分類器段 `users`（允許來源網段的純判定端點，靜態段與 `:id` 並存）"},

	// ── classNoIdentity：鏈中無認證中介層 ⇒ 審計中介層必然早退（23 條）──
	//
	// **理由欄的「[歸屬：…]」前綴＝留痕歸屬**。
	// 加註的動機：`classNoIdentity` 只說「審計**中介層**不為它寫列」，讀者極易把它
	// 誤讀成「這條路由無留痕」，而該誤讀正是這些留痕缺口
	// 能長期潛伏的原因之一——沒有人回答過「那誰來留痕」。
	//
	// 四種歸屬（散文詞彙，**不是閉集合、不受任何斷言檢查**）：
	//
	//	handler 自寫  該路由的留痕由 handler 內的產生點承擔，AP 編號指向
	//	              `openspec/changes/archive/2026-08-11-modular-architecture/research/manifest-audit-points.md`
	//	              （隨公開快照出門），該表才是產生點的權威登記。
	//	他體系        留痕不在 `audit_logs`，而在 sessions 表或 seal journal。
	//	              此二者由 `audit-coverage` spec 的「他體系留痕的明載定調」承擔，
	//	              **SHALL NOT 被視為審計缺口**。
	//	無留痕        該端點無稽核語義（探針、指標、登入前的唯讀探詢）。
	//	              與豁免表 `coverageExemptRoutes` 的 `exemptProbe`／`exemptPreAuth` 對應。
	//
	// **再次強調：本欄不作為判準**（見 `routeAuditEntry.Why` 的說明）。歸屬寫錯不會
	// 有任何測試轉紅；真正擋住「產生點消失」的是各 AP 的行為測試與
	// `audit_rejection_coverage_guard_test.go` 的拒絕留痕守衛。
	{"POST", "/api/v1/auth/change-password"}: {classNoIdentity, "",
		"[歸屬：handler 自寫] password_change scoped token 自解析，被 AuthMiddleware deny-by-default 擋下故不可掛；" +
			"留痕＝AP-09 `auth_handler.go` `auditPasswordChange`（來源位址取自連線對端）"},
	{"POST", "/api/v1/auth/login"}: {classNoIdentity, "",
		"[歸屬：handler 自寫] 登入時尚無身分；留痕＝AP-07 `auditLogin`（來源位址取自連線對端，" +
			"修前可由 `X-Forwarded-For` 指定）"},
	{"GET", "/api/v1/auth/banner"}: {classNoIdentity, "",
		"[歸屬：無留痕] 登入前告示讀取（`security_policy_handler.go` `LoginBanner`），" +
			"登入前可達的唯讀查詢，無身分亦無變更語義，故不產生審計列"},
	{"GET", "/api/v1/auth/methods"}: {classNoIdentity, "",
		"[歸屬：無留痕] 登入方式探詢（`oidc_handler.go` `LoginMethods`），登入前可達的唯讀查詢，" +
			"無身分亦無變更語義，故不產生審計列"},
	{"POST", "/api/v1/auth/mfa/enroll/confirm"}: {classNoIdentity, "",
		"[歸屬：handler 自寫] MFA 強制註冊，enrollment scoped token 自解析；" +
			"留痕＝AP-10 `auth_mfa_handler.go` `auditAuthEventFull`（成功走 `auditMFALoginSuccess`，" +
			"並帶 provider Details）"},
	{"POST", "/api/v1/auth/mfa/enroll/setup"}: {classNoIdentity, "",
		"[歸屬：handler 自寫] MFA 強制註冊，enrollment scoped token 自解析；" +
			"留痕＝AP-10（本端點只有失敗分支寫列——setup 本身不改變任何狀態）"},
	{"POST", "/api/v1/auth/mfa/verify"}: {classNoIdentity, "",
		"[歸屬：handler 自寫] MFA 第二階段，pending token 自 body 帶入並專用解析；" +
			"留痕＝AP-10（正式會話成功列由本點寫，OIDC 交換端只寫 `mfa_pending`，兩者不重複計登入成功）"},
	{"GET", "/api/v1/auth/oidc/:id/begin"}: {classNoIdentity, "",
		"[歸屬：無留痕] OIDC 授權起始，登入前可達；本端點僅重導至 IdP，錯誤走 `respondLoginError` 不寫列。" +
			"逾界的洪水面由 AP-53 的 `oidc_abuse_aggregate` 聚合列承擔，流程結果由 callback／exchange 的 AP-72 承擔"},
	{"GET", "/api/v1/auth/oidc/callback"}: {classNoIdentity, "",
		"[歸屬：handler 自寫] OIDC 回呼，登入前可達；留痕＝AP-72 `oidc_handler.go` `writeOIDCAudit`" +
			"（涵蓋 JIT 建帳號列、流程失敗列、准入拒絕列）"},
	{"POST", "/api/v1/auth/oidc/exchange"}: {classNoIdentity, "",
		"[歸屬：handler 自寫] OIDC 碼交換，登入前可達；留痕＝AP-72（涵蓋成功登入列與 MFA `mfa_pending` 列）"},
	{"POST", "/api/v1/auth/refresh"}: {classNoIdentity, "",
		"[歸屬：handler 自寫] refresh 憑證自 body 帶入，access 可能已過期故為公開路由；" +
			"留痕＝AP-08 `auditRefreshEvent`（同時承接**成功輪替**，修前只有失敗留痕）"},
	{"GET", "/api/v1/connect"}: {classNoIdentity, "",
		"[歸屬：handler 自寫＋他體系] WebSocket 連線閘，token 於 handler 內自解析。" +
			"兌換**拒絕**＝AP-69 `proxy/connect_gates.go` `AuditConnectDenied`" +
			"（與 `/ssh` 共用同一個寫入點，本側 `details.via=connect`）；" +
			"**成功建線**由 sessions 表承擔（spec「他體系留痕的明載定調」）"},
	{"GET", "/metrics"}: {classNoIdentity, "",
		"[歸屬：無留痕] 營運指標曝光端點，不掛認證、無稽核語義" +
			"（豁免表 `exemptProbe`）。**前身 `/api/v1/internal/metrics` 已移除**：" +
			"該路徑落在 edge 整段代理的 `/api` 之下，「內部使用」的前提在正式部署下不成立"},
	{"GET", "/api/v1/ping"}: {classNoIdentity, "",
		"[歸屬：無留痕] 連通性探針，不掛認證，無稽核語義（豁免表 `exemptProbe`）"},
	{"GET", "/api/v1/recordings/stream"}: {classNoIdentity, "",
		"[歸屬：handler 自寫] rtoken 取流（刻意不掛 JWT）；" +
			"留痕＝AP-68 `recording_handler.go` `auditRecordingRetrieval`"},
	{"GET", "/api/v1/seal/status"}: {classNoIdentity, "",
		"[歸屬：他體系] 封印期端點，須早於認證系統可用；留痕由 seal journal 承擔" +
			"（spec「他體系留痕的明載定調」），`audit_logs` 無列不計為缺口"},
	{"POST", "/api/v1/seal/unseal"}: {classNoIdentity, "",
		"[歸屬：他體系] 封印期解封端點，須早於認證系統可用；留痕由 seal journal 承擔" +
			"（spec「他體系留痕的明載定調」），`audit_logs` 無列不計為缺口"},
	{"GET", "/api/v1/sessions/:id/monitor"}: {classNoIdentity, "",
		"[歸屬：handler 自寫] 監控 WebSocket，token 於 handler 內自解析；" +
			"留痕＝AP-70 `sshproxy/handler.go` `auditObserverJoin`（**本 change 新增**，" +
			"修前管理員即時監看他人會話零留痕）"},
	{"GET", "/api/v1/sessions/share/:code/ws"}: {classNoIdentity, "",
		"[歸屬：handler 自寫] 分享連線 WebSocket；handler 只寫 authContext，中介層整筆跳過。" +
			"留痕＝AP-70（**本 change 新增**，`via=share`，含無效分享碼的 `status=denied` 拒絕列）"},
	{"GET", "/api/v1/ssh"}: {classNoIdentity, "",
		"[歸屬：handler 自寫＋他體系] SSH WebSocket 閘，connect token 於 handler 內自解析。" +
			"兌換**拒絕**＝AP-69 `proxy.AuditConnectDenied`（與 `/connect` 共用" +
			"同一個寫入點，`details.via=ssh`；缺票／偽票／過期票／閘序拒絕四路皆留痕）；" +
			"**成功建線**由 sessions 表承擔（`sshproxy/handler.go` 的 `createSession`，涵蓋" +
			"使用者／資產／來源位址／登入帳號；spec「他體系留痕的明載定調」）"},
	{"GET", "/api/v1/db-console/sessions/:id/results/:event_id/export"}: {classResource, model.ResourceSession,
		"命中分類器段 `sessions`（`db-console` 段在其前，分類器逐段掃描故不影響）；" +
			"中介層本列為請求層留痕，handler 另寫 `file_download`／`file` 的成敗與中止列" +
			"（含 event_id、set_index、size、sha256；中止列另記 bytes_sent 與 sha256_sent），兩者並存"},
	{"GET", "/api/v1/db-console"}: {classNoIdentity, "",
		"[歸屬：handler 自寫＋他體系] 查詢主控台 WebSocket 閘，connect token 於 handler 內自解析。" +
			"兌換**拒絕**＝AP-69 `proxy.AuditConnectDenied`（與 `/ssh` 共用同一個寫入點）；" +
			"**成功建線**由 sessions 表承擔（`sshproxy/dbconsole_handler.go` 的 `createSession`，" +
			"`db_console=true`）；會話期間的操作事件另以 `audit_logs` 結構化留痕" +
			"（`RequestBody.kind` 區分連線失敗、admission、樹瀏覽、切庫、目標受限、取消、" +
			"連線關閉、重連自報、結束時交易未提交）"},
	{"GET", "/health"}: {classNoIdentity, "",
		"[歸屬：無留痕] 存活探針，不掛認證，無稽核語義（豁免表 `exemptProbe`）"},
	{"POST", "/health"}: {classNoIdentity, "",
		"[歸屬：無留痕] 存活探針，不掛認證，無稽核語義（豁免表 `exemptProbe`）"},
	{"GET", "/healthz"}: {classNoIdentity, "",
		"[歸屬：無留痕] 存活探針，不掛認證，無稽核語義（豁免表 `exemptProbe`）"},
}

// minIdentityScanFiles 方向 5 前提錨點的掃描下界（現況 361 個非測試 .go）。
const minIdentityScanFiles = 250

// ── 分類器的原始碼模擬（方向 3 的事實來源）────────────────────────────────

// classifierRule 一條「路徑段字面量集合 → 資源值」規則。
type classifierRule struct {
	keys  []string
	value string
}

// classifierLoop 一個 `for _, part := range parts` 迴圈。**順序即語義**：
// 前面的迴圈整輪走完才輪到後面的，這正是子資源前置特判能勝過容器段的原因。
type classifierLoop struct {
	rules []classifierRule
}

type resourceClassifier struct {
	loops []classifierLoop
	// def 兜底分支回傳的值。
	def string
	// caseCount／valueCount 供下界檢查（規則表被清空時不得假綠）。
	caseCount, valueCount int
}

// classify 以與 `extractResource` 逐字相同的順序語義算出分類。
// 第二個回傳值標示是否**落到兜底分支**——這是方向 4 的判準本體，
// 不是「值等於 asset」的代理判準，故兜底常數換成真哨兵時本守衛零改動。
func (rc resourceClassifier) classify(path string) (string, bool) {
	parts := strings.Split(path, "/")
	for _, lp := range rc.loops {
		for _, p := range parts {
			for _, r := range lp.rules {
				for _, k := range r.keys {
					if p == k {
						return r.value, false
					}
				}
			}
		}
	}
	return rc.def, true
}

// loadAuditResourceConsts 讀出 `model.Resource*` 常數名 → 字面值。
func loadAuditResourceConsts(t *testing.T, root string) map[string]string {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(resourceConstFileRel))
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("解析 %s 失敗（守衛不在殘缺 AST 上作判定）：%v", resourceConstFileRel, err)
	}
	out := map[string]string{}
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, s := range gd.Specs {
			vs, ok := s.(*ast.ValueSpec)
			if !ok || len(vs.Names) != 1 || len(vs.Values) != 1 {
				continue
			}
			id, ok := vs.Type.(*ast.Ident)
			if !ok || id.Name != resourceConstTypeName {
				continue
			}
			lit, ok := vs.Values[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				continue
			}
			v, uerr := strconv.Unquote(lit.Value)
			if uerr != nil {
				continue
			}
			out[vs.Names[0].Name] = v
		}
	}
	if len(out) < minResourceConsts {
		t.Fatalf("自 %s 只讀到 %d 個 %s 常數（下界 %d）：常數表讀不全時，"+
			"方向 3 會把每一筆登記都判成「常數不存在」而全紅，或更糟——被人以放寬解讀掩蓋",
			resourceConstFileRel, len(out), resourceConstTypeName, minResourceConsts)
	}
	return out
}

// loadResourceClassifier 直讀分類器原始碼，並以**嚴格文法**確保演算法結構未漂移。
func loadResourceClassifier(t *testing.T) resourceClassifier {
	t.Helper()
	root := guardModuleRoot(t)
	consts := loadAuditResourceConsts(t, root)

	path := filepath.Join(root, filepath.FromSlash(classifierFileRel))
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("解析 %s 失敗（守衛不在殘缺 AST 上作判定）：%v", classifierFileRel, err)
	}

	var fn *ast.FuncDecl
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if ok && fd.Recv == nil && fd.Name.Name == classifierFuncName && fd.Body != nil {
			fn = fd
			break
		}
	}
	if fn == nil {
		t.Fatalf("%s 內找不到函式 %s：分類器若搬遷，SHALL 同步更新 classifierFileRel／classifierFuncName，"+
			"而不是讓守衛靜默失去被驗證對象", classifierFileRel, classifierFuncName)
	}

	bail := func(format string, args ...any) {
		t.Helper()
		t.Fatalf("%s 的結構不符本守衛的文法："+format+"。\n"+
			"分類器演算法一旦改形（多一層迴圈、改成前綴或最長匹配、兜底移位…），"+
			"原始碼模擬會與實碼無聲分歧，方向 3 從此驗的是假東西。故此處 Fatal 而非放行——"+
			"改了分類器結構 SHALL 同步更新 loadResourceClassifier 的文法",
			append([]any{classifierFuncName}, args...)...)
	}

	resolve := func(e ast.Expr) string {
		sel, ok := e.(*ast.SelectorExpr)
		if !ok {
			bail("%s", "回傳值不是 model.Resource* 形式的選擇器")
			return ""
		}
		x, ok := sel.X.(*ast.Ident)
		if !ok || x.Name != "model" {
			bail("回傳值的套件限定不是 model（得到 %s）", classifierExprName(sel.X))
			return ""
		}
		v, ok := consts[sel.Sel.Name]
		if !ok {
			bail("回傳 model.%s，但 %s 內找不到同名的 %s 常數",
				sel.Sel.Name, resourceConstFileRel, resourceConstTypeName)
			return ""
		}
		return v
	}

	stringLit := func(e ast.Expr) string {
		lit, ok := e.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			bail("%s", "路徑段比對的右運算元不是字串字面量")
			return ""
		}
		v, uerr := strconv.Unquote(lit.Value)
		if uerr != nil {
			bail("字串字面量 %s 無法解析", lit.Value)
			return ""
		}
		return v
	}

	singleReturn := func(b *ast.BlockStmt) string {
		if b == nil || len(b.List) != 1 {
			bail("%s", "分支主體必須恰好是一個 return（多一個語句就代表有守衛看不見的副作用或條件）")
			return ""
		}
		ret, ok := b.List[0].(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			bail("%s", "分支主體的唯一語句必須是單值 return")
			return ""
		}
		return resolve(ret.Results[0])
	}

	stmts := fn.Body.List
	if len(stmts) < 3 {
		bail("函式體只有 %d 個語句，最少需要「split ＋ 至少一個迴圈 ＋ 兜底 return」", len(stmts))
	}

	// ── 語句 0：parts := strings.Split(path, "/") ──
	assign, ok := stmts[0].(*ast.AssignStmt)
	if !ok || assign.Tok != token.DEFINE || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
		bail("%s", "第一個語句不是單一 := 賦值")
	}
	partsIdent, ok := assign.Lhs[0].(*ast.Ident)
	if !ok {
		bail("%s", "第一個語句的左值不是識別字")
	}
	call, ok := assign.Rhs[0].(*ast.CallExpr)
	if !ok || len(call.Args) != 2 {
		bail("%s", "第一個語句的右值不是雙引數呼叫")
	}
	if sel, ok := call.Fun.(*ast.SelectorExpr); !ok || sel.Sel.Name != "Split" {
		bail("%s", "第一個語句不是 strings.Split")
	}
	if sep := stringLit(call.Args[1]); sep != "/" {
		bail("切分符是 %q 而非 \"/\"", sep)
	}

	// ── 末語句：兜底 return ──
	last, ok := stmts[len(stmts)-1].(*ast.ReturnStmt)
	if !ok || len(last.Results) != 1 {
		bail("%s", "最後一個語句不是單值 return（兜底分支）")
	}
	rc := resourceClassifier{def: resolve(last.Results[0])}
	if rc.def == "" {
		bail("%s", "兜底分支回傳空值")
	}

	// ── 中段：一連串 for _, part := range parts ──
	for _, st := range stmts[1 : len(stmts)-1] {
		rng, ok := st.(*ast.RangeStmt)
		if !ok {
			bail("%s", "split 與兜底 return 之間出現非 for-range 的語句")
			continue
		}
		if src, ok := rng.X.(*ast.Ident); !ok || src.Name != partsIdent.Name {
			bail("for-range 走訪的不是 %s", partsIdent.Name)
		}
		val, ok := rng.Value.(*ast.Ident)
		if !ok {
			bail("%s", "for-range 未取值變數（無值變數的迴圈不可能做路徑段比對）")
			continue
		}
		if rng.Body == nil || len(rng.Body.List) != 1 {
			bail("%s", "for-range 主體必須恰好是一個語句（if 或 switch）")
			continue
		}

		var lp classifierLoop
		switch inner := rng.Body.List[0].(type) {
		case *ast.IfStmt:
			if inner.Init != nil || inner.Else != nil {
				bail("%s", "前置特判的 if 不得帶 init 或 else")
			}
			bin, ok := inner.Cond.(*ast.BinaryExpr)
			if !ok || bin.Op != token.EQL {
				bail("%s", "前置特判的條件不是 == 比較")
				continue
			}
			if id, ok := bin.X.(*ast.Ident); !ok || id.Name != val.Name {
				bail("前置特判比較的左運算元不是迴圈值變數 %s", val.Name)
			}
			lp.rules = append(lp.rules, classifierRule{
				keys: []string{stringLit(bin.Y)}, value: singleReturn(inner.Body)})
		case *ast.SwitchStmt:
			if inner.Init != nil {
				bail("%s", "switch 不得帶 init")
			}
			if id, ok := inner.Tag.(*ast.Ident); !ok || id.Name != val.Name {
				bail("switch 的判別式不是迴圈值變數 %s", val.Name)
			}
			for _, cs := range inner.Body.List {
				cc, ok := cs.(*ast.CaseClause)
				if !ok || len(cc.List) == 0 {
					bail("%s", "switch 內出現 default 或非 case 子句（default 會把兜底語義搬進迴圈，模擬看不見）")
					continue
				}
				keys := make([]string, 0, len(cc.List))
				for _, e := range cc.List {
					keys = append(keys, stringLit(e))
				}
				lp.rules = append(lp.rules, classifierRule{
					keys: keys, value: singleReturn(&ast.BlockStmt{List: cc.Body})})
				rc.caseCount++
				rc.valueCount += len(keys)
			}
		default:
			bail("%s", "for-range 主體既不是 if 也不是 switch")
		}
		rc.loops = append(rc.loops, lp)
	}

	if rc.caseCount < minClassifierCases || rc.valueCount < minClassifierValues {
		t.Fatalf("自 %s 只解析出 %d 個 case／%d 個路徑段字面量（下界 %d／%d）："+
			"規則表被清空時模擬會一律回兜底，方向 3 反而變成「大家都未分類」而不是紅——下界即為此而設",
			classifierFileRel, rc.caseCount, rc.valueCount, minClassifierCases, minClassifierValues)
	}
	return rc
}

// classifierExprName 供錯誤訊息印出運算式型別，不參與判定。
func classifierExprName(e ast.Expr) string {
	if id, ok := e.(*ast.Ident); ok {
		return id.Name
	}
	return "非識別字"
}

// ── 路由全集（列舉來源）──────────────────────────────────────────────────

// auditRouteUniverse 取**最大路由面**（release ＋ 審計開）作為列舉來源，
// 並斷言其餘組態的路由集皆為其子集——否則某條路由可能只存在於未被掃描的組態裡，
// 永遠不需要登記，而那正是本守衛要消滅的靜默豁免。
func auditRouteUniverse(t *testing.T) (map[[2]string]string, map[[2]string][]string) {
	t.Helper()
	routes, chains := buildRouter(t, gin.ReleaseMode, true)
	if len(routes) < minAuditRoutesScanned {
		t.Fatalf("buildRouter 只回了 %d 條路由（下界 %d）：列舉來源若失效，"+
			"逐路由迴圈零迭代即全綠——掃不到東西不是「沒問題」，是「沒在看」",
			len(routes), minAuditRoutesScanned)
	}

	others := []struct {
		mode  string
		audit bool
	}{
		{gin.ReleaseMode, false},
		{gin.DebugMode, true},
		{gin.DebugMode, false},
	}
	for _, o := range others {
		r2, _ := buildRouter(t, o.mode, o.audit)
		for k := range r2 {
			if _, ok := routes[k]; !ok {
				t.Fatalf("組態 mode=%s audit=%v 註冊了 %s %s，但它不在列舉來源"+
					"（release/audit=on）裡：該路由將永遠不需要登記",
					o.mode, o.audit, k[0], k[1])
			}
		}
	}
	return routes, chains
}

func chainHasAuthMiddleware(chain []string) bool {
	for _, n := range chain {
		if strings.Contains(n, authMiddlewareMarker) {
			return true
		}
	}
	return false
}

func routeKeyString(k [2]string) string { return k[0] + " " + k[1] }

// ── 登記表自身的形態 ──────────────────────────────────────────────────────

// TestAuditRouteRegistryEntriesAreWellFormed 分類詞彙是閉集合、理由不得為空、
// 資源欄只在 classResource 時有值。
func TestAuditRouteRegistryEntriesAreWellFormed(t *testing.T) {
	if len(auditRouteRegistry) < minAuditRoutesScanned {
		t.Fatalf("登記表只有 %d 筆（下界 %d）：表被清空時方向 1 會整批紅，"+
			"但若清空與路由集失效同時發生就會雙雙假綠", len(auditRouteRegistry), minAuditRoutesScanned)
	}
	var bad []string
	for k, e := range auditRouteRegistry {
		switch {
		case !routeAuditClasses[e.Class]:
			bad = append(bad, routeKeyString(k)+"：分類 "+string(e.Class)+" 不在閉集合內")
		case strings.TrimSpace(e.Why) == "":
			bad = append(bad, routeKeyString(k)+"：理由為空——沒有理由的分類等於沒有分類")
		case e.Class == classResource && e.Resource == "":
			bad = append(bad, routeKeyString(k)+"：classResource 未宣告 Resource")
		case e.Class != classResource && e.Resource != "":
			bad = append(bad, routeKeyString(k)+"：非 classResource 卻宣告了 Resource="+
				string(e.Resource)+"（登記表不得宣告實碼不承認的分類）")
		}
	}
	sort.Strings(bad)
	if len(bad) > 0 {
		t.Errorf("登記表有 %d 筆形態不合法：\n  %s", len(bad), strings.Join(bad, "\n  "))
	}
}

// ── 方向 1／2：路由 ↔ 登記雙向對齊 ────────────────────────────────────────

// TestAuditRouteRegistryCoversEveryRegisteredRoute 列舉來源是**路由集**，登記表只是
// 決定的紀錄。新增任何端點（含既有前綴下的新子路徑）必然缺登記而轉紅，作者被迫做出
// 分類決定；反向釘住孤兒登記，避免刪了端點卻留著一筆過期的決定。
func TestAuditRouteRegistryCoversEveryRegisteredRoute(t *testing.T) {
	routes, _ := auditRouteUniverse(t)

	var missing []string
	for k := range routes {
		if _, ok := auditRouteRegistry[k]; !ok {
			missing = append(missing, routeKeyString(k))
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("有 %d 條已註冊路由沒有審計分類登記：\n  %s\n\n"+
			"新端點若不做分類決定，`extractResource` 會靜默把它兜底成一個**有真實查詢面**的"+
			"類別（現況 asset），帶 `:id` 時更會由 audit_log.go:86-90 推導出假的 asset_id。"+
			"請在 auditRouteRegistry 補一筆並寫下理由——可以決定「不入審計」，但那必須是具名的決定",
			len(missing), strings.Join(missing, "\n  "))
	}

	var orphans []string
	for k := range auditRouteRegistry {
		if _, ok := routes[k]; !ok {
			orphans = append(orphans, routeKeyString(k))
		}
	}
	sort.Strings(orphans)
	if len(orphans) > 0 {
		t.Errorf("登記表有 %d 筆孤兒列（登記了但路由不存在）：\n  %s\n\n"+
			"端點刪除時登記須一併刪除，否則登記表會逐漸變成一份沒人維護的歷史檔案",
			len(orphans), strings.Join(orphans, "\n  "))
	}
}

// ── 方向 3：登記 ↔ 實碼實算值 ─────────────────────────────────────────────

// TestAuditRouteRegistryMatchesClassifierOutput 登記表**不是**事實來源：事實是
// `extractResource` 對該路徑實際算出的值。在登記表裡寫個好看的分類卻沒改分類器，
// 這條就紅。
func TestAuditRouteRegistryMatchesClassifierOutput(t *testing.T) {
	routes, _ := auditRouteUniverse(t)
	rc := loadResourceClassifier(t)

	var mismatch []string
	for k := range routes {
		e, ok := auditRouteRegistry[k]
		if !ok {
			continue // 由方向 1 報告
		}
		got, fellToDefault := rc.classify(k[1])
		switch e.Class {
		case classResource:
			if fellToDefault {
				mismatch = append(mismatch, routeKeyString(k)+
					"：登記為已分類（"+string(e.Resource)+"），但分類器實際落**兜底分支**——"+
					"該登記應為 classUnclassified，否則缺口會從 maxUnclassifiedRoutes 的計數裡消失")
				continue
			}
			if got != string(e.Resource) {
				mismatch = append(mismatch, routeKeyString(k)+
					"：登記 "+string(e.Resource)+"，分類器實算 "+got)
			}
		case classUnclassified:
			if !fellToDefault {
				mismatch = append(mismatch, routeKeyString(k)+
					"：登記為落兜底，但分類器實際命中具名段並回 "+got+
					"——分類已補上就 SHALL 把登記改為 classResource 並下修 maxUnclassifiedRoutes")
			}
		case classNoIdentity:
			// 分類器對它是空操作（中介層早退），故不比對實算值；
			// 該類的正確性由方向 5 的中間件鏈雙向核對承擔。
		}
	}
	sort.Strings(mismatch)
	if len(mismatch) > 0 {
		t.Errorf("有 %d 筆登記與分類器實算值不符：\n  %s\n\n"+
			"登記表是「決定的紀錄」，不是斷言的事實來源；事實來源是 %s 的實算值",
			len(mismatch), strings.Join(mismatch, "\n  "), classifierFuncName)
	}
}

// TestClassifierSimulatorAgreesWithKnownTruth 模擬器自身的健全性：三則已定案、
// 不因後續改動而改變的對照。模擬器若因文法解析失誤而退化（例如規則全丟失、
// 迴圈順序顛倒），方向 3 會整批紅——但也可能整批「剛好」對，故此處另立正向對照。
func TestClassifierSimulatorAgreesWithKnownTruth(t *testing.T) {
	rc := loadResourceClassifier(t)

	cases := []struct {
		path string
		want string
	}{
		{"/api/v1/assets/:id", string(model.ResourceAsset)},
		{"/api/v1/users/:id/roles", string(model.ResourceUser)},
		// 子資源前置特判須勝過容器段 sessions
		{"/api/v1/sessions/:id/clipboard-events", string(model.ResourceClipboardEvent)},
		// /my/connections* 操作的是 session（不得落兜底）
		{"/api/v1/my/connections", string(model.ResourceSession)},
	}
	for _, tc := range cases {
		got, fell := rc.classify(tc.path)
		if fell {
			t.Errorf("模擬器把 %s 判成落兜底：模擬與實碼已分歧", tc.path)
			continue
		}
		if got != tc.want {
			t.Errorf("模擬器 classify(%s) = %s，want %s", tc.path, got, tc.want)
		}
	}

	// 反向對照：一條不存在於任何規則的路徑必須落兜底。若它也「命中」了什麼，
	// 代表文法解析把某條規則的鍵讀成了空字串之類的萬用值。
	if _, fell := rc.classify("/api/v1/no-such-segment-anywhere/:id"); !fell {
		t.Error("模擬器對未知路徑未落兜底：規則鍵可能被解析成萬用值，方向 3 從此不可信")
	}
}

// ── 方向 4：哨兵上限 ──────────────────────────────────────────────────────

// TestUnclassifiedRoutesStayUnderCeiling 未分類路由受上限節制。
//
// **上限是驗收儀表，不是現況的橡皮圖章**：要多一條未分類路由，就必須在同一份 diff 裡
// 把 maxUnclassifiedRoutes 調高——沒有豁免清單、沒有 skip 可以繞過。
func TestUnclassifiedRoutesStayUnderCeiling(t *testing.T) {
	routes, chains := auditRouteUniverse(t)
	rc := loadResourceClassifier(t)

	// **判準取自實碼，不取自登記表的 Class 欄**。
	// 上限降到 0 之後，若仍只數 `Class == classUnclassified` 的登記筆數，
	// 這條斷言會退化成恆真——沒有那種登記存在，迴圈零迭代。改成
	// 「分類器實算落兜底 **且** 中間件鏈含認證中介層」之後，把新端點登記成
	// classResource 卻沒改分類器時，本條與方向 3 會**各自獨立**轉紅（不互相掩蓋）。
	//
	// 為什麼要加「鏈含認證中介層」這一半：鏈中無認證中介層者（/health、/ping、
	// /seal/*、/connect、/ssh、/metrics…共 9 條落兜底）根本走不到寫列那一步
	// （`audit_log.go` 無 userID 即早退），分類器對它們是空操作。把它們計進儀表
	// 等於要求為永遠不會被使用的分類簽字，而儀表要量的是「會寫出列、卻寫不出分類」。
	// 這一半的正確性由方向 5 獨立雙向核對（宣告與實際鏈必須相符）。
	var unclassified []string
	for k := range routes {
		if !chainHasAuthMiddleware(chains[k]) {
			continue
		}
		if _, fellToDefault := rc.classify(k[1]); fellToDefault {
			unclassified = append(unclassified, routeKeyString(k))
		}
	}
	sort.Strings(unclassified)

	if len(unclassified) > maxUnclassifiedRoutes {
		t.Errorf("落兜底的路由有 %d 條，超過上限 %d：\n  %s\n\n"+
			"新增未分類路由 SHALL 在同一份 diff 明確調高 maxUnclassifiedRoutes——"+
			"那是一個要有人簽字的動作，不是安靜多一列登記",
			len(unclassified), maxUnclassifiedRoutes, strings.Join(unclassified, "\n  "))
	}
	t.Logf("落兜底路由 %d 條 / 上限 %d（驗收儀表：起始 47，現為 0）",
		len(unclassified), maxUnclassifiedRoutes)
}

// TestClassifierFallbackIsDedicatedSentinel 兜底**必須**是專屬哨兵，
// 不得是任何有真實查詢面的類別。
//
// **為什麼另立一條而不併進上面**：上限為 0 時，`maxUnclassifiedRoutes` 只證明
// 「沒有已註冊路由落兜底」，對**兜底本身回什麼**一無所知。而缺陷本體正是後者——
// 兜底回 `asset` 時，`audit_log.go` 由 `resource == ResourceAsset && resource_id != nil`
// 無條件推導 asset_id，於是任何未來漏分類的帶 `:id` 端點都會立刻在同號**資產**的
// 時間軸上長出假事件。哨兵使那條推導對漏分類列自然失效。
//
// 換句話說：上面那條管「有沒有人落進兜底」，這條管「落進去會被寫成什麼」。
// 兜底值單獨退化（改回 asset 而路由分類一條沒動）在上面那條是完全綠的，
// 必須有一條專門的紅燈指名它。
func TestClassifierFallbackIsDedicatedSentinel(t *testing.T) {
	rc := loadResourceClassifier(t)

	if rc.def != string(model.ResourceUnclassified) {
		t.Errorf("%s 的兜底分支回 %q，SHALL 為專屬哨兵 %q。\n\n"+
			"兜底 SHALL NOT 落在任何有真實查詢面的類別上：那不只是丟失資訊，"+
			"而是把假列注入一個真實的查詢結果集，並經 asset_id 推導把「遺漏」升級為「假事件」",
			classifierFuncName, rc.def, model.ResourceUnclassified)
	}

	// 反向：哨兵 SHALL NOT 同時是任何具名段的分類結果——它一旦被某條 case 回傳，
	// 「這條列是漏分類來的」就不再等價於「resource == unclassified」，
	// 而那個等價正是哨兵全部的價值（可計數、可篩選、可告警）
	for i, lp := range rc.loops {
		for _, r := range lp.rules {
			if r.value == string(model.ResourceUnclassified) {
				t.Errorf("第 %d 個迴圈有規則以具名段回傳哨兵 %q（鍵：%v）："+
					"哨兵只能來自兜底，否則「未分類」的計數會被真實決定污染",
					i+1, r.value, r.keys)
			}
		}
	}
}

// ── 方向 5：classNoIdentity ↔ 中間件鏈雙向核對 ────────────────────────────

// TestNoIdentityRoutesMatchMiddlewareChain 「不入審計」的宣告必須與中間件鏈相符，
// 且**雙向**：宣告無身分而鏈中有認證 → 紅（那條其實會寫列，分類決定是必要的）；
// 鏈中無認證卻登記成有分類 → 也紅（那個分類決定是死的，實際永遠不生效）。
func TestNoIdentityRoutesMatchMiddlewareChain(t *testing.T) {
	routes, chains := auditRouteUniverse(t)

	authed := 0
	var falseNoIdentity, missingNoIdentity []string
	for k := range routes {
		chain, ok := chains[k]
		if !ok {
			t.Fatalf("%s 沒有中間件鏈指紋：鏈探針失效時方向 5 會把全部路由誤判為無認證", routeKeyString(k))
		}
		hasAuth := chainHasAuthMiddleware(chain)
		if hasAuth {
			authed++
		}
		e, ok := auditRouteRegistry[k]
		if !ok {
			continue // 由方向 1 報告
		}
		switch {
		case e.Class == classNoIdentity && hasAuth:
			falseNoIdentity = append(falseNoIdentity, routeKeyString(k))
		case e.Class != classNoIdentity && !hasAuth:
			missingNoIdentity = append(missingNoIdentity, routeKeyString(k))
		}
	}

	if authed < minAuthenticatedRoutes {
		t.Fatalf("只有 %d 條路由的鏈被認出含認證中介層（下界 %d）：認證中介層若改名，"+
			"authMiddlewareMarker 會一條都認不出來，於是全部路由看起來都「無身分」——"+
			"那是本守衛最糟的假綠形態。改了認證中介層名稱 SHALL 同步更新 authMiddlewareMarker",
			authed, minAuthenticatedRoutes)
	}

	sort.Strings(falseNoIdentity)
	if len(falseNoIdentity) > 0 {
		t.Errorf("有 %d 條登記為 classNoIdentity 的路由，其中間件鏈**含**認證中介層：\n  %s\n\n"+
			"這些路由實際會寫出審計列，故必須做出真正的分類決定（classResource 或 classUnclassified）",
			len(falseNoIdentity), strings.Join(falseNoIdentity, "\n  "))
	}

	sort.Strings(missingNoIdentity)
	if len(missingNoIdentity) > 0 {
		t.Errorf("有 %d 條中間件鏈**不含**認證中介層的路由，卻登記成有分類：\n  %s\n\n"+
			"審計中介層在 audit_log.go:52-56 因無 userID 而整筆早退，故該分類決定永遠不生效——"+
			"登記為 classNoIdentity 並寫下理由，讓「這條路由的留痕另有安排（或根本沒有）」是白紙黑字",
			len(missingNoIdentity), strings.Join(missingNoIdentity, "\n  "))
	}
}

// TestAuditIdentityKeySetOnlyByAuthMiddleware 方向 5 的**前提錨點**。
//
// 方向 5 的推論鏈是：鏈中無 AuthMiddleware ⇒ context 無 `userID` ⇒ 審計中介層早退。
// 中間那一步靠的是「`userID` 這個語義鍵只有 AuthMiddleware 會寫」。若哪天有 handler
// 為了留痕而自行 `c.Set("userID", ...)`（設計上明確否決過的做法），推論鏈就斷了：
// 那條路由會開始寫列，而方向 5 仍然說它「不入審計」——守衛全綠、事實相反。
func TestAuditIdentityKeySetOnlyByAuthMiddleware(t *testing.T) {
	root := guardModuleRoot(t)

	scanned := 0
	anchorSeen := false
	var offenders []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			switch d.Name() {
			case "vendor", "testdata", ".git", "node_modules", "tmp":
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		scanned++
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, p, nil, 0)
		if perr != nil {
			return perr
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) != 2 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Set" {
				return true
			}
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			v, uerr := strconv.Unquote(lit.Value)
			if uerr != nil || v != authIdentityKey {
				return true
			}
			if rel == authIdentityFileRel {
				anchorSeen = true
				return true
			}
			offenders = append(offenders, rel+":"+strconv.Itoa(fset.Position(lit.Pos()).Line))
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("走訪 module 樹失敗（守衛不在殘缺視野下宣稱通過）：%v", err)
	}
	if scanned < minIdentityScanFiles {
		t.Fatalf("只掃到 %d 個非測試 .go（下界 %d）：視野若塌陷，零命中會被誤讀為「沒人違規」",
			scanned, minIdentityScanFiles)
	}
	if !anchorSeen {
		t.Fatalf("在 %s 內找不到 Set(%q, …)：正向錨點消失代表認證中介層改了身分鍵或搬了家，"+
			"方向 5 的推論鏈失去起點，SHALL 同步更新 authIdentityFileRel／authIdentityKey",
			authIdentityFileRel, authIdentityKey)
	}
	sort.Strings(offenders)
	if len(offenders) > 0 {
		t.Errorf("%s 之外有 %d 處寫入 %q 語義鍵：\n  %s\n\n"+
			"`userID` 是全系統「已通過認證」的語義鍵。為了留痕而在 handler 內寫入它，"+
			"會讓一條刻意不做 JWT 認證的路徑在下游看起來像認證過（設計上已否決此做法），"+
			"同時使方向 5 的「鏈中無認證 ⇒ 不寫列」推論失效",
			authIdentityFileRel, len(offenders), authIdentityKey, strings.Join(offenders, "\n  "))
	}
}
