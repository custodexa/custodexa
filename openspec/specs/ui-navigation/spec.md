# ui-navigation

## Purpose

管理介面的導覽結構與選單組織：側邊欄採分組資訊架構、可收合並標示目前位置，各頁採一致的頁面骨架；導覽依角色（persona）調整可見項與儀表板卡片；總覽群組含工作區入口（工作區維持純連線介面），審計群組含檢查點驗證與稽核工作台入口。

## Requirements

### Requirement: Grouped sidebar information architecture

The main layout sidebar SHALL organize navigation into labeled groups: 總覽 (Dashboard, Workspace entry), 資產 (Assets — shown as「我的資產」when the server-provided global asset presentation capability is absent, Credentials「帳號憑證庫」, Authorizations, Change Secret Plans, Change Secret Batches「批次改密」), 連線 (Sessions, My Connections, My Requests), 審核 (Approvals), 審計 (Audit Logs, Commands, Alerts, Access Reviews), 身分與權限 (Users, Roles, User Groups, Approver Scopes「審核範圍」, Identity Sources「身分來源」), 系統設定 (Security Policies, Access Control, Key Management, Transmission Security, Offsite Storage「離機儲存」). The former single 系統管理 group SHALL be split into 身分與權限 and 系統設定 with all route paths unchanged; the former 會話 group label SHALL be renamed 連線. Test-only pages (RDP recording test, connection test) MUST NOT appear in the production navigation.

身分來源 SHALL 為單一入口，涵蓋目錄型與身分提供者型兩種來源——兩者是同層的身分來源，分列兩個入口會使設定者以為那是兩件互不相干的事，而其設定欄位、測試方式與群組映射的維護動線相同。外部群組對角色的映射規則 SHALL 於各來源的詳情頁內成為一個區段，SHALL NOT 另立獨立的映射頁。

合併前的兩個路由（身分提供者、目錄設定）SHALL 繼續解析到合併後的頁面，SHALL NOT 回 404——書籤與既有文件都指向舊路徑。身分來源的路由段 SHALL 登記於登入後重導向的路由白名單；合併前的兩個路由段於其重導向仍存在期間 SHALL 一併保留於該白名單。

Entries SHALL be filtered by the shared capability-based entry rules before grouping. Group membership SHALL NOT grant access to another entry. Group labels MAY be omitted when a single visible group is flattened as specified by the sidebar presentation requirement. Existing role-based scenarios in this requirement describe the preserved behavior of the built-in subjects; they SHALL NOT require client-side role comparisons.

**Notification-channel navigation extension**

In addition to the system-settings entries listed above, the 系統設定 group SHALL include Notification Channels「通知通道」 as an independently routed entry. Its visibility and direct navigation SHALL use the same capability requirement as the notification-channel management endpoint, without additionally requiring alert-record read access. The alert page entry in 審計 SHALL remain reachable by holders of any capability required by one of its remaining tabs, and SHALL NOT be reachable through the notification-channel management capability alone once that tab has moved. The existing capability-filtered collapsible groups, favorites and single-group flattening SHALL continue to apply to the new entry.

#### Scenario: Grouped navigation rendered
- **WHEN** an admin user logs in and the main layout renders
- **THEN** the sidebar shows 身分與權限 (使用者管理/角色管理/使用者群組/審核範圍/身分來源) and 系統設定 (安全政策/存取管控/金鑰管理/傳輸安全/離機儲存) as separate labeled groups, the 總覽 group contains the 工作區 entry, and no test pages are listed

#### Scenario: Permission-aware visibility
- **WHEN** a non-admin user logs in
- **THEN** admin-only entries (including the entire 身分與權限 and 系統設定 groups, hence the 審核範圍 page) are hidden from the sidebar while remaining routes guard against direct URL access as before, where the hidden set follows the capability-based entry rules: for a user holding no identity-group or settings-group capability (as with the built-in user and auditor profiles) it covers both entire groups, whereas a non-admin user who holds the settings-group read capability (for example a system security administrator) sees the 系統設定 group containing exactly the entries whose capability rules that user satisfies, including 安全政策 and 存取管控, while every other entry stays hidden and route-guarded

#### Scenario: Auditor sees access reviews entry
- **WHEN** an auditor logs in and the main layout renders
- **THEN** the 審計 group shows the「存取複審」entry and navigating to it succeeds

#### Scenario: Renamed entry keeps deep links working
- **WHEN** a user opens a bookmarked URL of any regrouped page (e.g. the former 通道加密清冊 path or any 系統管理 page)
- **THEN** the original route resolves to the same page without redirect or 404

#### Scenario: 合併前的兩個來源路由仍可用

- **WHEN** 使用者開啟合併前的身分提供者或目錄設定書籤網址
- **THEN** 該網址解析到身分來源頁的對應內容，SHALL NOT 回 404

#### Scenario: 身分來源的路由段登記於重導向白名單

- **WHEN** 使用者經身分提供者登入並指定身分來源頁為登入後的重導向目標
- **THEN** 該目標通過白名單比對而未被退回預設路徑；合併前的兩個路由段同樣通過比對

### Requirement: Sidebar collapse
The sidebar SHALL support collapsing to an icon-only rail and persist the collapsed state across page reloads (localStorage).

The collapse control SHALL be discoverable without scrolling: it SHALL remain visible within the initial viewport (900px height baseline) regardless of how many menu items the sidebar contains, and SHALL NOT be positioned below the sidebar's overflow fold.

#### Scenario: Collapse persists
- **WHEN** the user collapses the sidebar and reloads the page
- **THEN** the sidebar renders collapsed with icon-only items and tooltips on hover

#### Scenario: Collapse control visible without scrolling
- **WHEN** the sidebar's menu content exceeds the viewport height
- **THEN** the collapse control remains visible and operable within the initial viewport without scrolling the sidebar

### Requirement: Current location indication
The layout SHALL clearly indicate the active page in the sidebar and show the current page title in the content header area.

#### Scenario: Active item highlighted
- **WHEN** the user navigates to any page from the sidebar
- **THEN** the corresponding sidebar item is visually highlighted using the primary token color and the content header shows the page title

### Requirement: Consistent page scaffold
Every management page SHALL follow a consistent scaffold: page header (title + primary action), filter/toolbar row, content area (table/cards), and pagination, with uniform spacing driven by design tokens.

#### Scenario: Scaffold uniformity
- **WHEN** the user switches between Assets, Sessions, Users, and Audit Logs pages
- **THEN** the header, toolbar, table, and pagination occupy consistent positions and spacing across all pages

### Requirement: Persona-aware navigation and dashboard

Sidebar composition, landing content, and existing dashboard cards SHALL use server-provided capabilities while preserving the built-in subjects' current content: general users see 我的資產 and connection-oriented cards; subjects with effective approval eligibility additionally see 審核中心 and the pending-count card; auditors see audit-oriented entries and backlog cards (unreviewed alerts, active connections, recording-failure sessions, pending review sign-offs); admins see management entries, system overview and aggregated backlog cards. 我的連線 and 我的申請 SHALL be visible to every signed-in subject. Combined subjects SHALL keep their existing eligible entries and cards without duplication. Card counts SHALL use the existing list/count endpoints; this change SHALL NOT introduce new cards or let client-side role names determine permission.

審核相關的入口、badge 與卡片 SHALL 以「後端有效審核者」的衍生呈現點為唯一述詞（具 approver 角色 OR 屬任一審核方群組），
與該端點的守衛判準逐字相同；admin 角色 SHALL NOT 作為該述詞的兜底。述詞不成立時，前端 SHALL NOT 呼叫僅審核者可用的端點，
且 SHALL NOT 渲染依賴該端點的卡片或 badge——取不到數而顯示 0 會讓使用者把「無資格」讀成「無待辦」。

**Dashboard data-access extension**

The preceding restriction on new cards describes the capability-only navigation transition. The release-guidance card SHALL be a separate nonblocking explanation above the existing dashboard cards. For the per-card authorization extension, additional card-data endpoints MAY be introduced; they SHALL preserve the existing list/count endpoint contracts and delegate to the same authorized query providers. This extension SHALL NOT replace effective reviewer eligibility with a client-side role check or alter the built-in subjects' preserved navigation.

Each existing dashboard card, panel and quick action SHALL require its own registered read capability, authenticated-self predicate or actual approval eligibility, independently of other cards. A presentation-only capability that selects card wording SHALL NOT make other cards visible or fetchable. Existing built-in compatibility profiles SHALL retain their self-service, connection, audit and management content where their card predicates hold. Combined capabilities SHALL produce the union of eligible cards and panels without duplication, and holding one group of capabilities SHALL NOT hide the self-service cards or panels of a subject who is also eligible for them. Client-side role names SHALL NOT determine authorization. 我的連線 and 我的申請 SHALL remain visible to every signed-in user; their visibility SHALL NOT grant new connection or request-submission rights.

Item-count cards SHALL use their corresponding authorized lists' full filtered totals, before pagination. Pending-approval cards and badges SHALL share the effective reviewer predicate and actual review-scope query; administrator status SHALL NOT provide fallback eligibility. A missing predicate SHALL cause both absence of the card and rejection by its data endpoint, rather than a false zero, and a failed request SHALL be shown as unavailable rather than zero. Existing non-count metrics and the daily security-review component SHALL retain their source units and authorization.

#### Scenario: General user persona
- **WHEN** a user with only the user role logs in
- **THEN** the sidebar shows 我的資產 (not 資產管理), self-service entries, and the workspace entry, and the dashboard shows connection-oriented cards with no management wording

#### Scenario: Auditor persona dashboard
- **WHEN** an auditor logs in and opens the dashboard
- **THEN** audit-backlog cards (unreviewed alerts, recording-failure sessions, pending sign-offs) are displayed with counts, each navigating to its corresponding page

#### Scenario: Approver overlay
- **WHEN** a user holding both user and approver roles logs in
- **THEN** the sidebar additionally shows 審核中心 with the pending badge and the dashboard additionally shows the pending-approvals card

#### Scenario: admin 無審核資格時不出現待審入口
- **WHEN** 僅具 admin 角色（未持 approver 角色、不屬任何審核方群組）的使用者開啟儀表板
- **THEN** 待審申請卡不渲染，且該頁不對僅審核者可用的待審件數端點發出請求（主控台無該端點的 403）

#### Scenario: 群組審核方看得到待審入口
- **WHEN** 未持 approver 角色但屬於某審核方群組的使用者開啟儀表板
- **THEN** 待審申請卡渲染並顯示件數，與側邊欄 badge 的數字一致

### Requirement: Workspace entry in sidebar
The sidebar 總覽 group SHALL contain a 工作區 entry that navigates to the workspace in the same tab; the workspace itself SHALL remain a pure connection surface with no additional navigation, badges, or self-service features.

The workspace asset list SHALL contain only assets that are visible to the user through connection visibility: authorization rules and approval visibility, each row carrying its authorization level and connection entry state. Assets that are visible only through management scope SHALL NOT appear in the workspace, because managing a node does not grant connection through the platform. Subjects holding the global asset presentation capability keep their existing workspace list. When a connection ticket is refused because the asset does not exist or is not connectable for the user, the workspace SHALL say that the asset cannot be found or the user has no connection permission for it, without distinguishing the two cases, and SHALL NOT state only that the asset does not exist.

#### Scenario: Workspace round trip
- **WHEN** a user clicks the 工作區 sidebar entry and then the workspace back control
- **THEN** the user lands in the workspace and returns to the management console, with the workspace UI unchanged apart from pre-existing behavior

#### Scenario: Management-only assets are not listed
- **WHEN** a subject manages node A through a node-scoped assignment, has an authorization rule for asset X outside A and no rule for asset Y inside A, and opens the workspace
- **THEN** the workspace lists X with its connection entry state and does not list Y, while the asset page still lists both X and Y

#### Scenario: Refused ticket does not claim the asset is gone
- **WHEN** a user opens a workspace session for an asset that the user can no longer connect to and ticket issuance returns not found
- **THEN** the session shows that the asset cannot be found or the user has no connection permission for it

### Requirement: Checkpoint verification entry in audit group

The sidebar 審計 group SHALL contain a checkpoint verification entry that navigates to the standalone checkpoint verification page. The entry SHALL require the server-provided capability for checkpoint verification. The sidebar and route guard SHALL apply the same requirement; the existing admin and auditor subjects retain access and general users retain their rejection.

The entry label SHALL be localized in zh-TW, en-US and ja-JP (no hardcoded prose). Adding this entry SHALL NOT change any existing route path or group membership.

#### Scenario: Auditor sees checkpoint verification entry

- **WHEN** an auditor logs in and the main layout renders
- **THEN** the 審計 group shows the checkpoint verification entry and navigating to it succeeds

#### Scenario: General user cannot reach the page

- **WHEN** a user with only the user role logs in and attempts to open the checkpoint verification URL directly
- **THEN** the entry is absent from the sidebar and the route guard rejects the navigation

#### Scenario: Existing navigation unchanged

- **WHEN** an admin reviews the sidebar against the Grouped sidebar information architecture requirement
- **THEN** all pre-existing entries keep their group, label and path; only the checkpoint verification entry is added

### Requirement: Auditor workbench navigation entry

The sidebar 審計 group SHALL contain an auditor workbench entry that navigates to the standalone investigation workbench page. The entry SHALL be the first item of the 審計 group (investigation is the highest-frequency audit entry point) and SHALL require the server-provided capability for investigation workbench access. The route guard SHALL use that same capability; existing admin and auditor subjects retain access and general users retain their rejection.

The entry label SHALL be localized in zh-TW, en-US and ja-JP (no hardcoded prose), and the breadcrumb mapping table SHALL be updated for the new path. Adding this entry SHALL NOT change any existing route path, label or group membership.

The workbench route SHALL accept its full investigation state (pivot, subject, time window, categories, focused event) as query parameters, so that a shared or bookmarked workbench URL resolves directly to the intended investigation scope.

#### Scenario: Auditor sees workbench entry

- **WHEN** an auditor logs in and the main layout renders
- **THEN** the 審計 group lists the workbench entry first and navigating to it succeeds

#### Scenario: General user cannot reach the page

- **WHEN** a user with only the user role attempts to open the workbench URL directly
- **THEN** the entry is absent from the sidebar and the route guard rejects the navigation

#### Scenario: Deep link resolves to scope

- **WHEN** a user opens a workbench URL carrying pivot, subject id and time window parameters
- **THEN** the page renders that exact investigation scope without further input

#### Scenario: Existing navigation unchanged

- **WHEN** an admin reviews the sidebar against the Grouped sidebar information architecture requirement
- **THEN** all pre-existing entries keep their group, label and path; only the workbench entry is added

### Requirement: Rotation evidence navigation entry

The sidebar 審計 group SHALL contain a rotation evidence entry that navigates to the rotation evidence page. The entry SHALL be reachable by holders of either the server-provided rotation evidence read capability or the report schedule management capability, with the same rule shared by the sidebar and route guard. Existing admin and auditor subjects retain access and general users retain their rejection. Schedule management SHALL remain inside that page and require its own management capability, which preserves the existing admin-only behavior; it SHALL NOT become a separate sidebar entry.

A holder of the schedule management capability without the rotation evidence read capability SHALL see the page with only the schedule section, expanded, and a note that report content and downloads require audit read permission. The page SHALL NOT request the report dataset, record or recent-report endpoints for such a holder at any point, including on load, on refresh, on record paging and after the holder runs or edits a schedule, and SHALL NOT show report refresh or generation actions. Running a schedule SHALL keep its own permission and SHALL still reload the schedule list. Granting this entry SHALL NOT add audit read capability to any built-in template.

The entry label SHALL be localized in zh-TW, en-US and ja-JP, and the breadcrumb mapping table SHALL be updated for the new path. Adding this entry SHALL NOT change any existing route path, label or group membership; the download center entry keeps its path and label while gaining a second tab.

#### Scenario: Auditor sees rotation evidence entry

- **WHEN** an auditor logs in and the main layout renders
- **THEN** the 審計 group lists the rotation evidence entry and navigating to it succeeds

#### Scenario: General user cannot reach the page

- **WHEN** a user with only the user role attempts to open the rotation evidence URL directly
- **THEN** the entry is absent from the sidebar and the route guard rejects the navigation

#### Scenario: Existing navigation unchanged

- **WHEN** an admin reviews the sidebar against the Grouped sidebar information architecture requirement
- **THEN** all pre-existing entries keep their group, label and path; only the rotation evidence entry is added

#### Scenario: Schedule manager without audit read
- **WHEN** a system security administrator, whose template holds schedule management but not audit read, opens the rotation evidence entry
- **THEN** the entry is visible and the guard allows it; the page shows the expanded schedule section and the audit-permission note, and no request is sent to the report dataset, record or recent-report endpoints

#### Scenario: Running a schedule does not reload reports without audit read
- **WHEN** the same administrator runs a schedule immediately from the schedule section
- **THEN** the run request and a schedule list reload are sent, and no request is sent to the report dataset, record or recent-report endpoints; a holder of audit read still sees the recent reports refresh after the run

### Requirement: Credential library navigation entry

The sidebar 資產 group SHALL contain a credential library entry (「帳號憑證庫」) that navigates to the credential
library page. The entry and route guard SHALL require the server-provided credential management capability.
The existing admin subject retains access; other built-in subjects, including the auditor whose access to credential
names is confined to the rotation evidence report, retain their rejection. Credential rotation SHALL live inside that page as an action on a credential rather than as a separate
sidebar entry.

The entry label SHALL be localized in zh-TW, en-US and ja-JP, and the breadcrumb mapping table SHALL be updated
for the new path. Adding this entry SHALL NOT change any existing route path, label or group membership; the
change secret plans entry keeps its path and label.

#### Scenario: Admin sees credential library entry

- **WHEN** an admin logs in and the main layout renders
- **THEN** the 資產 group lists the credential library entry and navigating to it succeeds

#### Scenario: Auditor cannot reach the page

- **WHEN** an auditor attempts to open the credential library URL directly
- **THEN** the entry is absent from the sidebar and the route guard rejects the navigation

#### Scenario: General user cannot reach the page

- **WHEN** a user with only the user role attempts to open the credential library URL directly
- **THEN** the entry is absent from the sidebar and the route guard rejects the navigation

#### Scenario: Existing navigation unchanged

- **WHEN** an admin reviews the sidebar against the Grouped sidebar information architecture requirement
- **THEN** all pre-existing entries keep their group, label and path; only the credential library entry is added

### Requirement: 側欄底部顯示產品版本

登入後的介面 SHALL 在側欄最下方、選單捲動區之外，以一行小字顯示「Custodexa <版本>」，所有角色都看得到。選單內容再長，這一行也 SHALL 留在視窗內。版本值 SHALL 取自目前使用者資訊端點回應的 `product_version`，並 SHALL 重用側欄原本就會發出的那一次請求；前端 SHALL NOT 寫死版本字串。只有發布版號形狀的值（X.Y.Z，可帶預發版後綴）SHALL 顯示；開發建置的 `dev`、空值、缺欄或請求失敗時，該行 SHALL 不渲染，也 SHALL NOT 顯示錯誤。側欄收合時 SHALL 只顯示版號，滑過時以提示呈現完整字樣。這一行 SHALL 為純文字，不可點。

#### Scenario: 有版本時顯示
- **WHEN** 已登入使用者開啟任一頁面，且目前使用者資訊回應的 `product_version` 為 `1.13.0`
- **THEN** 側欄底部顯示「Custodexa 1.13.0」，而且不在選單的捲動區內

#### Scenario: 開發建置不顯示
- **WHEN** `product_version` 為 `dev`，或回應缺少此欄
- **THEN** 側欄底部不出現版本行，也不留空白列

#### Scenario: 請求失敗不報錯
- **WHEN** 目前使用者資訊請求失敗
- **THEN** 側欄照常顯示選單，但不出現版本行，也沒有錯誤提示

#### Scenario: 收合態
- **WHEN** 使用者收合側欄，且版本為 `1.13.0`
- **THEN** 底部只顯示 `1.13.0`，滑過時提示「Custodexa 1.13.0」

### Requirement: 能力入口可見性與路由放行同源

側邊欄每個入口的資格與直接輸入網址的放行 SHALL 由同一份規則、同一個 `canEnter` 函式決定。受限入口 SHALL 以後端下發權限點經 `can(perm)` 判定，SHALL NOT 讀角色陣列。沒有資格的入口 SHALL 不出現，直接輸入網址 SHALL 導回儀表板；未登入者仍依會話守衛導往登入。分組收合只改呈現，不改入口資格。

- 管理與稽核類入口 SHALL 分別要求對應資源的能力，不因同組而補上其他能力。
- 審核中心 SHALL 要求由有效審核資格產生的呈現點；管理能力 SHALL NOT 作為兜底。
- 我的連線、我的申請 SHALL 對所有已登入者可見，且可直接以網址進入。入口可見 SHALL NOT 新增申請或連線資格；原不能送件者 SHALL 看見既有拒絕原因或明確不適用說明。
- 我的 agent SHALL 要求由「名下至少一個 agent 或政策允許自建」產生的呈現點；SHALL NOT 由角色或其他管理能力推導。
- 原登入即可的儀表板、工作區、個人資料與資產入口 SHALL 維持其資格，包含沒有一般路由層能力的主體。

詳情頁 SHALL 沿用列表頁規則，query 別名 SHALL 沿用所屬入口規則。未登記入口 SHALL 不顯示也不放行。能力資料 SHALL 取自目前使用者資訊端點，守衛與側欄共用同一載入與快照；尚未載入或缺欄時 SHALL NOT 回退到角色陣列。角色清單及既有資格欄位可繼續顯示，但入口裁決 SHALL 使用後端同次產生的能力投影。

「我的 agent」入口的圖示 SHALL 與該頁空白狀態的機器人圖示相同，SHALL NOT 與「我的申請」共用圖示。

以此角色預覽期間，前述「能力資料 SHALL 取自目前使用者資訊端點」只適用於操作者本人的能力資料：本人的能力仍只取自目前使用者資訊端點並照常整批替換；`can(perm)`、`canEnter`、入口守衛與側欄過濾改以伺服器的角色預覽權限集合為準（見「以此角色預覽模式」），兩者仍共用同一個判斷函式，入口資格在預覽中同樣同源。預覽權限集合 SHALL NOT 寫入本人的能力資料，本人能力也 SHALL NOT 併入預覽集合；離開預覽後守衛與側欄 SHALL 立即回到本人的能力快照。預覽中依個人資格產生的呈現點（審核中心、我的 agent）SHALL NOT 出現。

#### Scenario: 系統管理者負責 agent 時看得到我的 agent

- **WHEN** 名下有一個 agent 主體的系統管理者登入或重新整理頁面
- **THEN** 側邊欄連線群組出現「我的 agent」，點入或直接輸入其網址皆可進入並看到該 agent

#### Scenario: 沒有 agent 且不允許自建時看不到也進不去

- **WHEN** 名下沒有 agent 主體、且自行建立 agent 的政策為關閉的使用者（不論是一般使用者、系統管理者或稽核人員）開啟任一頁面，並直接輸入「我的 agent」的網址
- **THEN** 側邊欄沒有「我的 agent」，直接輸入網址被導回儀表板

#### Scenario: 允許自建時不論角色都看得到我的 agent

- **WHEN** 自行建立 agent 的政策為開啟，名下沒有 agent 主體的一般使用者、系統管理者或稽核人員重新整理頁面
- **THEN** 側邊欄出現「我的 agent」，直接輸入其網址可進入

#### Scenario: 系統管理者與稽核人員可進入自助頁

- **WHEN** 系統管理者或稽核人員直接輸入「我的連線」或「我的申請」的網址
- **THEN** 守衛放行且側邊欄可見這兩項；送件或連線資格仍由既有後端判準決定

#### Scenario: 每個身分的選單與放行逐項一致

- **WHEN** 對每一種身分組合（一般使用者、系統管理者、稽核人員，各自疊加審核資格、審核群組成員、多角色，以及負責 agent 與否、自建政策開關）逐一比對所有側邊欄選單項目
- **THEN** 每一項的「選單是否具可達資格」與「路由是否放行」結論相同；收合組內的入口可經展開到達

#### Scenario: 入口可見但不具送件資格

- **WHEN** 原本不能送出申請的已登入使用者開啟「我的申請」
- **THEN** 頁面呈現本人資料及既有拒絕或不適用說明，不把入口可見轉為申請授權

### Requirement: 能力過濾後的分組收合與常用釘選

側欄 SHALL 先按共用入口規則過濾項目、移除空組，再決定呈現方式。來源組多於一組時 SHALL 支援各組獨立收合；預設展開，導覽至某項時其來源組 SHALL 可展開以定位。目前只有一個可見來源組時 SHALL 自動攤平成單層，不顯示該組標題或收合控制。來源組數 SHALL 在釘選移出原組之前計算，不把常用區當作來源組。

使用者 SHALL 能將有資格的入口釘選到頂部常用區，依釘選順序顯示；同一 item SHALL 不在原組重複顯示。取消釘選 SHALL 回到原位置。釘選識別 SHALL 使用宣告的穩定 ID，保留 query 別名的區別；收藏 SHALL NOT 授權未知或已失去資格的入口。常用為空時 SHALL 不留空區。

分組收合與釘選偏好 SHALL 以使用者 ID 及格式版本隔離於同源本地儲存；壞資料 SHALL 回預設。既有路徑、標題、圖示、badge 來源、整條側欄的圖示收合、目前位置與版本行 SHALL 保持；收合與釘選控制 SHALL 可用鍵盤操作並有三語標籤。

#### Scenario: 多組與單組呈現
- **WHEN** 能力過濾後有多組入口，或只剩一個來源組
- **THEN** 前者可分別收合，後者直接呈現單層項目；兩者的入口資格均與路由守衛一致

#### Scenario: 釘選與取消
- **WHEN** 使用者釘選有資格的入口後取消釘選
- **THEN** 該項先出現在頂部常用而不在原組重複，取消後回原位置

#### Scenario: 釘選不能繞過權限
- **WHEN** 某釘選項已失去資格或其識別不在宣告中
- **THEN** 側欄不顯示該項，收藏不改變其網址守衛結果

#### Scenario: 使用者偏好隔離
- **WHEN** 同一瀏覽器切換使用者
- **THEN** 各自套用自己的釘選與收合設定，不讀取前一位使用者的偏好

### Requirement: Notification channels have an independent settings entry

The system-settings group SHALL contain an independently routed notification-channel entry at `/notification-channels`. Its label SHALL use the existing localized notification-channel terminology. Sidebar visibility, direct navigation, breadcrumbs and post-login redirects SHALL use the same channel-management capability rule. Access SHALL NOT additionally require alert-record read permission.

The alert page SHALL remove its notification-channel tab and channel-data loading, and SHALL retain its alert-record, rule-management and system-alert catalog tabs, each under its own capability rule. When opened, it SHALL select the first tab the user is eligible for. The new page SHALL reuse the existing channel-management component and preserve its controls, transport warnings, destination masking, language settings, test delivery and change/delete confirmation semantics. When the page is opened, including through its direct URL, it SHALL load and display the existing channels without relying on the alert page. Moving the component SHALL NOT change channel API authorization, transactional auditing, delivery snapshots or notification delivery behavior.

After the move, the alert page entry SHALL be granted by any capability required by one of its remaining tabs, and SHALL NOT be granted by the channel-management capability alone. A user whose only alert-related capability is channel management SHALL reach channels through the new entry; the alert page entry SHALL be absent for that user and its direct URL SHALL be handled like any other ineligible entry. Sidebar visibility and direct navigation for the alert page SHALL continue to use one shared rule.

Other existing sidebar entries SHALL retain their route paths and reachability predicates. The new entry SHALL participate in the existing filtered groups, favorites and single-group presentation. A saved favorite SHALL NOT bypass a removed capability.

#### Scenario: Channel manager without audit access
- **WHEN** a user has channel-management capability but lacks alert-record read capability
- **THEN** the user can enter notification channels through system settings and its direct URL without acquiring access to alert records

#### Scenario: Channel-only user does not see an empty alert page
- **WHEN** a user holds channel-management capability but none of the capabilities required by the remaining alert-page tabs
- **THEN** the sidebar shows the notification-channel entry but not the alert page entry, and opening the alert page URL directly is rejected in the same way as the sidebar decision

#### Scenario: No channel-management capability
- **WHEN** a user without channel-management capability attempts to open the new entry or direct URL
- **THEN** the entry is absent, the route is rejected and the channel endpoint independently rejects the request

#### Scenario: Alert page after relocation
- **WHEN** an authorized user opens the alert page
- **THEN** the alert-record, rule-management and system-alert catalog tabs the user is eligible for remain, the first eligible tab is selected, and no channel tab or channel-data request appears

#### Scenario: Rule-management-only user reaches the alert page
- **WHEN** a user holds the alert-rule management capability but neither alert-record read capability nor the system-alert catalog capability
- **THEN** the alert page entry is visible, direct navigation is allowed, and the rule-management tab is shown and selected

#### Scenario: System-alert catalog remains reachable
- **WHEN** a user who holds the system-alert catalog capability but not alert-record read capability opens the alert page
- **THEN** the alert page entry is visible and the system-alert catalog tab is shown and selected

#### Scenario: Preserved channel-management behavior
- **WHEN** a channel manager uses the independent settings page
- **THEN** the existing management component and notification confirmations remain available with unchanged server-side delivery contracts

#### Scenario: Favorites and grouped presentation
- **WHEN** a user pins the channel entry or later loses its required capability
- **THEN** the existing favorite and group presentation rules apply, and losing the capability removes the entry without changing other entries' eligibility

### Requirement: Release guidance can be reopened from the user menu

Every signed-in user SHALL have a localized「新版說明」action in the user menu. Selecting it SHALL navigate to the dashboard and reopen the current release-guidance card using current capabilities, even if that user previously dismissed it. This action SHALL NOT reset the server-persisted dismissal or grant access to any management entry. The card SHALL remain nonblocking and support keyboard closing and reopening.

#### Scenario: Reopen from another page
- **WHEN** a signed-in user selects「新版說明」while viewing another page
- **THEN** the dashboard opens with the guidance expanded and its heading focused, while the stored dismissal remains unchanged

#### Scenario: General user's menu
- **WHEN** a general user opens the user menu and reopens guidance
- **THEN** the action is available and the guidance includes no management sections or unauthorized links

### Requirement: 無資產檢視權限者的資產與工作區畫面

資產頁與工作區的入口 SHALL 維持登入即可。主體不持資產檢視權限點時，兩頁 SHALL NOT 呼叫資產列表端點，SHALL 改顯示說明：角色沒有資產檢視權限、因此不會列出資產，需要經平台連線時聯絡管理員加上一般使用者角色。兩頁 SHALL NOT 把這種情況呈現為「沒有可用的主機」的空態或「列表更新失敗」。資產頁在此狀態下 SHALL NOT 顯示描述可用資產的頁首副標與重新整理動作。儀表板的「開啟工作區」與資產快速操作 SHALL 只在主體持有資產檢視權限點時呈現。

#### Scenario: 授權管理員開啟我的資產

- **WHEN** 只持授權管理員範本、沒有資產檢視權限點的使用者開啟我的資產頁
- **THEN** 頁面顯示角色沒有資產檢視權限的說明，主控台與網路紀錄沒有資產列表請求與 403

#### Scenario: 授權管理員開啟工作區

- **WHEN** 同一位使用者開啟工作區
- **THEN** 側欄顯示同一則說明，不出現列表更新失敗或權限不足的提示

#### Scenario: 儀表板快速操作依能力呈現

- **WHEN** 同一位使用者開啟儀表板
- **THEN** 快速操作沒有「開啟工作區」與「我的資產」；持資產檢視權限點的使用者兩張都看得到

### Requirement: 政策組唯讀入口

政策組頁的入口 SHALL 要求政策組檢視權限點，側欄與路由守衛共用同一規則。頁面讀取政策組與條文 SHALL 只依賴政策組檢視權限點可讀的資料來源，SHALL NOT 要求合規檢視或其他權限點；只為寫入表單服務的輔助資料（例如設定清單）SHALL 只在主體持有其所需權限點時讀取，未持有時不發請求，頁面照常呈現政策組與條文。持檢視、不持政策組管理權限點者 SHALL 能進入並檢視政策組與條文，頁面 SHALL 以一行說明標示唯讀，SHALL NOT 呈現新增、更名、生效切換、刪除、條文編輯、備註與確認等寫入動作；頁面 SHALL 以唯讀標示呈現每個政策組是否生效，頁面說明 SHALL NOT 提及唯讀者無法執行的動作。寫入端點的權限不變。只持政策組管理、不持檢視者 SHALL 被擋在入口外，角色編輯 SHALL 以既有缺依賴提示指出缺少檢視權限點。

#### Scenario: 稽核員檢視政策組

- **WHEN** 稽核員開啟政策組頁
- **THEN** 頁面列出政策組與條文並標示唯讀，沒有任何寫入按鈕；每個組顯示生效中或未生效的唯讀標示，內建組的說明不提加備註或人工確認

#### Scenario: 只持政策組檢視的自訂角色看得到內容

- **WHEN** 只持政策組檢視權限點、沒有合規檢視與安全政策管理權限點的自訂角色使用者開啟政策組頁
- **THEN** 頁面列出政策組與條文並標示唯讀；網路紀錄沒有合規判定結果與安全設定清單的請求，也沒有權限不足的提示

#### Scenario: 沒有合規檢視的管理者讀得到政策組

- **WHEN** 持政策組檢視與管理、沒有合規檢視權限點的系統安全管理員開啟政策組頁
- **THEN** 頁面列出政策組與條文，寫入動作齊全，沒有合規判定結果的請求

#### Scenario: 管理者照常寫入

- **WHEN** 持政策組檢視與管理權限點的使用者開啟政策組頁
- **THEN** 寫入動作與修改前相同

#### Scenario: 只持管理權限點者進不去

- **WHEN** 只持政策組管理權限點的使用者直接輸入政策組頁網址
- **THEN** 路由守衛導回儀表板，側欄沒有此入口

### Requirement: 以此角色預覽模式

管理介面 SHALL 提供以此角色預覽模式，讓操作者看到持有某個角色者的側欄、入口與頁內動作。進入時前端 SHALL 取得伺服器的角色預覽權限集合；伺服器回報不可預覽時 SHALL NOT 進入。進入後 SHALL 導到登入即可見的儀表板。每次發出的預覽權限集合請求 SHALL 綁定發出當下的會話世代與預覽請求序號；登出、切換帳號、離開預覽、離開發出請求的角色編輯畫面或再次發出預覽請求之後，先前請求的回應 SHALL 丟棄，SHALL NOT 設定預覽集合、導航或顯示任何說明，只有最後一次發出且仍有效的請求可以進入預覽。預覽中角色編輯與檢視畫面的「以此角色預覽」入口 SHALL 呈現但停用，並說明預覽中不能再預覽其他角色、請先離開預覽，SHALL NOT 讀取預覽權限集合；離開預覽 SHALL 一律回到最初進入預覽的角色編輯畫面。預覽 SHALL NOT 切換身分、簽發 token 或票證、建立 session，SHALL NOT 在請求中加入任何標頭或參數來表示預覽。操作者本人既有會話的正常續期與登出不屬預覽發出的請求，SHALL 照常進行；續期依既有規則換發與輪替本人的憑證，不計為預覽的簽發，預覽也 SHALL NOT 因此取得連線、錄影、監看或分享的票證。

預覽期間，前端的能力判斷、入口守衛與側欄過濾 SHALL 改以預覽權限集合為準，各頁依能力決定的呈現（含只決定文案的呈現點）一併跟隨預覽集合；操作者本人的能力狀態 SHALL 保持不變，本人能力的更新 SHALL NOT 寫入預覽集合，預覽集合也 SHALL NOT 併入本人能力。依個人資格出現的入口 SHALL NOT 因預覽而出現。預覽中經頁內連結進到預覽集合外的頁面，SHALL 照一般入口守衛導回儀表板、不另行提示，並仍在預覽中。使用者選單與右上身分 SHALL 仍為操作者本人。

預覽期間的資料讀取 SHALL 以操作者本人的身分送出，由伺服器依本人權限裁決；畫面資料 SHALL 以操作者本人可視為上限。每個送出的讀取，伺服器回應 SHALL 與操作者本人在非預覽時送出同一請求的回應相同；因呈現跟隨預覽集合，預覽中送出的讀取請求集合可以與非預覽時不同。預覽集合含資產檢視而操作者本人不含時，資產頁與工作區 SHALL 說明這裡的資料操作者本人看不到、持有者登入後會看到自己範圍內的資產，SHALL NOT 呼叫資產列表端點，SHALL NOT 呈現為列表更新失敗或權限不足的錯誤；其他頁的讀取被伺服器以本人權限拒絕時，SHALL 使用該頁既有的無權限或不可用呈現。預覽集合不含資產檢視時，資產頁與工作區 SHALL 照持有者會看到的說明呈現。

預覽期間，方法不是 GET、HEAD、OPTIONS 的請求 SHALL 不送出，並 SHALL 說明預覽中不能修改、持有這個角色的人可以使用；唯一例外是經盤點列明、伺服器端不寫入任何資料的讀取類請求，且 SHALL NOT 包含任何簽發 token 或票證、或對遠端主機執行動作的請求；本人會話的續期與登出依第一段照常進行，不屬此例外清單。需要簽發票證才能進行的動作（播放錄影、監看、從工作區連線、分享）SHALL 在預覽中於觸發元素上直接停用，並說明預覽中不能連線或播放錄影、持有這個角色的人可以使用，SHALL NOT 以按下後被攔截的「不能修改」說明代替；請求層的攔截仍保留為最後一道。角色具管理權的頁面，寫入類操作 SHALL 呈現但停用，並說明預覽中不能操作、持有這個角色的人可以使用；以手勢觸發的寫入（例如拖曳搬移節點）SHALL 在預覽中停用手勢本身（節點列不出現拖曳把手），並在游標停留的該列下方說明預覽中不能搬移節點、持有這個角色的人可以使用，SHALL NOT 讓手勢完成後才被拒絕；批次選取等只為寫入服務的控制 SHALL 停用。角色不具該動作能力時，該操作 SHALL 依能力判斷隱藏。列級操作 SHALL 只依預覽集合決定是否呈現，且 SHALL 一律停用。目前頁面在伺服器回應的頁面狀態為唯讀時，標題旁 SHALL 標示唯讀並以固定句說明這個角色只能檢視、看不到新增、編輯與刪除，新增與編輯類按鈕 SHALL NOT 出現，既有頁面說明 SHALL 保留；頁面已有自己的唯讀說明時 SHALL 沿用該說明，SHALL NOT 另加通用說明；頁面狀態為管理或可用時 SHALL NOT 標示唯讀。

屬於操作者本人的連線呈現（資產列表的授權狀態與連線入口）SHALL NOT 在預覽中顯示，並 SHALL 說明連線按鈕因人而異、預覽中不顯示。描述操作者本人管理範圍的頁首範圍行 SHALL NOT 在預覽中顯示，不論該頁的範圍資料取自何處；離開預覽後 SHALL 依原資料恢復。

預覽期間畫面頂部 SHALL 常駐橫幅，位於其他全域橫幅之上，顯示被預覽的角色名稱、只能看不能修改、畫面上的資料以操作者自己看得到的為上限，離開預覽按鈕在橫幅右側；橫幅內 SHALL NOT 放預覽範圍選擇器。預覽範圍選擇器 SHALL 位於資產管理頁節點樹正上方的狀態列，讓選取範圍與看到篩選結果發生在同一處。預覽範圍的選項 SHALL 只取自操作者本人可視的節點，預設為不篩選；選定後 SHALL 只作用於既有的節點篩選，送出的請求與操作者自己選取該節點時相同，SHALL NOT 將範圍送給伺服器作為裁決依據，也 SHALL NOT 改變預覽權限集合。範圍控制旁 SHALL 說明此範圍只篩選畫面、不改變角色。

離開預覽時，前端 SHALL 立即恢復以操作者本人的能力判斷，並回到進入預覽的角色編輯畫面（顯示已儲存的內容），且 SHALL 在右上「以此角色預覽」按鈕下方短暫顯示已離開預覽並帶出角色名稱，約 3 秒後消失。預覽狀態 SHALL 只存在該分頁的記憶體：重新整理與在網址列輸入網址（整頁重新載入）SHALL 結束預覽、不另提示，並留在同一頁以操作者本人的權限顯示；開新分頁 SHALL NOT 帶預覽，原分頁仍在預覽中；登出或切換帳號 SHALL NOT 保留預覽。

#### Scenario: 進入預覽後側欄只剩角色的入口

- **WHEN** 超級管理者以一個權限集合恰為 `asset:view`、`asset:create`、`asset:update`、`asset:delete`、`asset:test`、`assetgroup:manage`、`session:view` 的自訂角色進入預覽
- **THEN** 側欄只剩該角色對應的入口與登入即可見的入口，沒有審核中心與我的 agent，右上仍是超級管理者本人，畫面落在儀表板，橫幅顯示角色名稱、只能看不能修改、資料以自己看得到的為上限與離開預覽

#### Scenario: 管理頁的寫入呈現但停用

- **WHEN** 以權限集合恰為 `asset:view`、`asset:create`、`asset:update`、`asset:delete`、`asset:test`、`assetgroup:manage`、`session:view` 的角色預覽，進入資產管理頁（頁面狀態為管理）
- **THEN** 頁首沒有唯讀標示，新增等寫入按鈕與列級操作呈現但停用，並說明預覽中不能新增、持有這個角色的人可以使用；授權狀態與連線入口不顯示，列表底部說明連線按鈕因人而異、預覽中不顯示

#### Scenario: 預覽中不能拖曳搬移節點

- **WHEN** 預覽中在該角色有節點管理權的資產頁節點樹上按住節點拖動
- **THEN** 節點列沒有拖曳把手、無法被拖起，游標停留的該列下方顯示「這個節點不能搬」與預覽中不能搬移節點、持有這個角色的人可以使用的說明，沒有任何搬移請求送出

#### Scenario: 部分管理的頁面不標唯讀

- **WHEN** 以權限集合恰為 `asset:view`、`asset:update` 的角色預覽並進入資產管理頁（頁面狀態為管理）
- **THEN** 頁首沒有唯讀標示與唯讀說明，列級編輯呈現但停用，新增與刪除依能力判斷不出現

#### Scenario: 唯讀頁看不到寫入並說明

- **WHEN** 以權限集合恰為 `asset:view`、`credential:view` 的角色預覽並進入帳號憑證庫頁（頁面狀態為唯讀）
- **THEN** 新增與編輯類按鈕不出現，標題旁標示唯讀並顯示「這個角色只能檢視，看不到新增、編輯與刪除。」，既有頁面說明仍在

#### Scenario: 可以進入但沒有授予的頁面不標唯讀

- **WHEN** 以權限集合恰為 `credential:view` 的角色預覽並進入帳號憑證庫頁（入口規則放行、摘要判定沒有授予，頁面狀態為可用）
- **THEN** 頁首沒有唯讀標示與唯讀說明，新增與編輯類按鈕依能力判斷不出現

#### Scenario: 頁面自有唯讀說明時不重複

- **WHEN** 以權限集合恰為 `policygroup:view` 的角色預覽並進入政策組頁（頁面狀態為唯讀）
- **THEN** 頁首標示唯讀，沿用該頁自己的唯讀說明，沒有另加通用的唯讀說明

#### Scenario: 需簽發票證的動作直接停用

- **WHEN** 預覽中在會話頁或工作區看到播放錄影、監看、連線或分享的操作
- **THEN** 這些操作在按下前就是停用狀態，並說明預覽中不能連線或播放錄影、持有這個角色的人可以使用；沒有任何簽發票證的請求送出，也不出現「預覽中不能修改」的說明

#### Scenario: 寫入請求不送出

- **WHEN** 預覽中任何程式路徑發出非讀取方法的請求
- **THEN** 請求未送到伺服器，畫面說明預覽中不能修改，伺服器端沒有任何寫入或簽發

#### Scenario: 高於本人權限的角色看不到本人看不到的資料

- **WHEN** 具角色檢視能力但不具資產檢視能力的操作者預覽一個具資產管理權的角色並開啟資產管理頁
- **THEN** 頁面說明這裡的資料本人看不到、持有者登入後會看到自己範圍內的資產，沒有資產列表請求、403 或列表更新失敗的提示；其他頁送出的每個讀取，回應本文與操作者以同一 token 在非預覽時送出同一請求的回應相同

#### Scenario: 繞過前端直接呼叫仍依本人裁決

- **WHEN** 不具資產新增能力的操作者正在預覽一個具資產新增能力的角色，並繞過前端的請求攔截，以本人的 token 直接呼叫資產新增端點
- **THEN** 伺服器以本人權限拒絕，回應與非預覽時同一呼叫相同，資產資料不變

#### Scenario: 預覽範圍只篩選本人可視的資料

- **WHEN** 預覽中在預覽範圍選擇一個節點後開啟資產管理頁與資產授權管理頁
- **THEN** 範圍選擇器位於資產管理頁節點樹正上方的狀態列（不在橫幅），選項只含操作者本人可視的節點，兩頁送出的請求與操作者自己選取該節點時相同，其他頁不受影響，預覽權限集合不變

#### Scenario: 預覽橫幅與其他全域橫幅並存

- **WHEN** 預覽中系統同時顯示單實例守衛橫幅
- **THEN** 預覽橫幅在最上方，守衛橫幅照常在其下方，守衛橫幅的細節展開依預覽集合決定是否呈現

#### Scenario: 預覽中不能再預覽其他角色

- **WHEN** 以含角色檢視能力的角色 A 預覽時，從角色頁開啟另一個角色 B 的編輯畫面，游標停在「以此角色預覽」上，然後按下離開預覽
- **THEN** 按鈕為停用，說明卡顯示「預覽中不能再預覽其他角色。請先離開預覽。」，沒有讀取預覽權限集合的請求；離開預覽後回到角色 A 的編輯畫面，提示帶出角色 A 的名稱

#### Scenario: 遲到的預覽回應不生效

- **WHEN** 按下以此角色預覽後、伺服器回應前，操作者登出、切換帳號，或離開該角色編輯畫面
- **THEN** 回應抵達時被丟棄：沒有進入預覽、沒有導到儀表板、沒有出現說明彈出框，畫面停在操作者當下所在的頁面

#### Scenario: 逆序完成只採用最後一次

- **WHEN** 操作者在角色 A 的編輯畫面按下以此角色預覽，回應前改開角色 B 的編輯畫面並按下以此角色預覽，B 的回應先抵達、A 的回應後抵達
- **THEN** 進入的是角色 B 的預覽，A 的回應被丟棄、不覆蓋預覽集合也不再導航；離開預覽回到角色 B 的編輯畫面

#### Scenario: 離開預覽恢復本人

- **WHEN** 操作者按下離開預覽
- **THEN** 側欄、入口與頁內動作立即依操作者本人的能力呈現，畫面回到進入預覽的角色編輯畫面（已儲存內容），右上「以此角色預覽」按鈕下方顯示「已離開預覽，回到「角色名」」約 3 秒後消失

#### Scenario: 進出預覽不簽發也不建立 session

- **WHEN** 操作者進入預覽、瀏覽數頁、再離開預覽
- **THEN** 期間除操作者本人既有會話的續期外，沒有任何簽發 token 或票證的請求送出；伺服器端的連線、錄影、監看與分享票證及 session 數量與進入前相同，本人的更新憑證只因續期依既有規則輪替

#### Scenario: 重新整理或輸入網址後預覽結束

- **WHEN** 預覽中在資產管理頁重新整理，或在網址列輸入網址
- **THEN** 預覽結束且不另提示，留在同一頁以操作者本人的權限顯示，沒有預覽橫幅

#### Scenario: 新分頁不帶預覽

- **WHEN** 預覽中開新分頁（含從頁面另開的視窗）
- **THEN** 新分頁以操作者本人的權限顯示、沒有預覽橫幅，原分頁仍在預覽中

#### Scenario: 預覽中經連結進到持有者看不到的頁

- **WHEN** 預覽中經頁內連結進到預覽集合外的頁面
- **THEN** 照一般入口守衛導回儀表板，不另提示，預覽橫幅仍在、仍在預覽中
