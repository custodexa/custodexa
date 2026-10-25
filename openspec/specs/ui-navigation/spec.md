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
