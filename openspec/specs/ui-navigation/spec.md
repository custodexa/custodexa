# ui-navigation

## Purpose

管理介面的導覽結構與選單組織：側邊欄採分組資訊架構、可收合並標示目前位置，各頁採一致的頁面骨架；導覽依角色（persona）調整可見項與儀表板卡片；總覽群組含工作區入口（工作區維持純連線介面），審計群組含檢查點驗證與稽核工作台入口。
## Requirements
### Requirement: Grouped sidebar information architecture

The main layout sidebar SHALL organize navigation into labeled groups: 總覽 (Dashboard, Workspace entry), 資產 (Assets — shown as「我的資產」to non-admin/auditor roles, Credentials「帳號憑證庫」, Authorizations, Change Secret Plans, Change Secret Batches「批次改密」), 連線 (Sessions, My Connections, My Requests), 審核 (Approvals), 審計 (Audit Logs, Commands, Alerts, Access Reviews), 身分與權限 (Users, Roles, User Groups, Approver Scopes「審核範圍」, Identity Sources「身分來源」), 系統設定 (Security Policies, Access Control, Key Management, Transmission Security, Offsite Storage「離機儲存」). The former single 系統管理 group SHALL be split into 身分與權限 and 系統設定 with all route paths unchanged; the former 會話 group label SHALL be renamed 連線. Test-only pages (RDP recording test, connection test) MUST NOT appear in the production navigation.

身分來源 SHALL 為單一入口，涵蓋目錄型與身分提供者型兩種來源——兩者是同層的身分來源，分列兩個入口會使設定者以為那是兩件互不相干的事，而其設定欄位、測試方式與群組映射的維護動線相同。外部群組對角色的映射規則 SHALL 於各來源的詳情頁內成為一個區段，SHALL NOT 另立獨立的映射頁。

合併前的兩個路由（身分提供者、目錄設定）SHALL 繼續解析到合併後的頁面，SHALL NOT 回 404——書籤與既有文件都指向舊路徑。身分來源的路由段 SHALL 登記於登入後重導向的路由白名單；合併前的兩個路由段於其重導向仍存在期間 SHALL 一併保留於該白名單。

#### Scenario: Grouped navigation rendered
- **WHEN** an admin user logs in and the main layout renders
- **THEN** the sidebar shows 身分與權限 (使用者管理/角色管理/使用者群組/審核範圍/身分來源) and 系統設定 (安全政策/存取管控/金鑰管理/傳輸安全/離機儲存) as separate labeled groups, the 總覽 group contains the 工作區 entry, and no test pages are listed

#### Scenario: Permission-aware visibility
- **WHEN** a non-admin user logs in
- **THEN** admin-only entries (including the entire 身分與權限 and 系統設定 groups, hence the 審核範圍 page) are hidden from the sidebar while remaining routes guard against direct URL access as before

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

Sidebar composition, landing content, and dashboard cards SHALL follow the persona matrix: general users see self-service entries (我的資產/我的連線/我的申請) with connection-oriented dashboard cards; approver-overlaid users additionally see 審核中心 with a pending-count card; auditors see audit-oriented entries with an audit-backlog card group (unreviewed alerts, active connections, recording-failure sessions, pending review sign-offs); admins see the full navigation with system overview plus aggregated backlog cards. Multi-role users SHALL see the union of their personas' entries and cards without duplication. Card counts SHALL be sourced from existing list/count endpoints.

審核相關的入口、badge 與卡片 SHALL 以「後端有效審核者」為唯一述詞（具 approver 角色 OR 屬任一審核方群組），
與該端點的守衛判準逐字相同；admin 角色 SHALL NOT 作為該述詞的兜底。述詞不成立時，前端 SHALL NOT 呼叫僅審核者可用的端點，
且 SHALL NOT 渲染依賴該端點的卡片或 badge——取不到數而顯示 0 會讓使用者把「無資格」讀成「無待辦」。

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

#### Scenario: Workspace round trip
- **WHEN** a user clicks the 工作區 sidebar entry and then the workspace back control
- **THEN** the user lands in the workspace and returns to the management console, with the workspace UI unchanged apart from pre-existing behavior

### Requirement: Checkpoint verification entry in audit group

The sidebar 審計 group SHALL contain a checkpoint verification entry that navigates to the standalone checkpoint verification page. The entry SHALL be visible to admin and auditor roles only (`roles: ['admin','auditor']`, consistent with the existing audit entries), and SHALL be hidden from general users while the route guard rejects direct URL access.

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

The sidebar 審計 group SHALL contain an auditor workbench entry that navigates to the standalone investigation workbench page. The entry SHALL be the first item of the 審計 group (investigation is the highest-frequency audit entry point) and SHALL be visible to admin and auditor roles only (`roles: ['admin','auditor']`, consistent with the existing audit entries), while the route guard rejects direct URL access for other roles.

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

The sidebar 審計 group SHALL contain a rotation evidence entry that navigates to the rotation evidence page. The entry SHALL be visible to admin and auditor roles only (`roles: ['admin','auditor']`), and the route guard SHALL reject direct URL access for other roles. Schedule management SHALL live inside that page as an admin-only region rather than as a separate sidebar entry.

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

### Requirement: Credential library navigation entry

The sidebar 資產 group SHALL contain a credential library entry (「帳號憑證庫」) that navigates to the credential
library page. The entry SHALL be visible to admin only, and the route guard SHALL reject direct URL access for
every other role — including auditor, whose read access to credential names is confined to the rotation evidence
report. Credential rotation SHALL live inside that page as an action on a credential rather than as a separate
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

