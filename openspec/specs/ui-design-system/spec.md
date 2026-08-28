# ui-design-system

## Purpose

前端 UI 設計語言的一致性規範：以暗色優先的設計 token 定義色彩與間距、整合 Element Plus 暗色模式、統一非同步狀態呈現、終端與回放的視覺一致、可讀性與對比要求、Custodexa 品牌識別，並訂定 zh-TW 文案的用語標準與互動慣例、角色顯示的單一來源與列舉顯示完整性。
## Requirements
### Requirement: Dark-first design tokens
The frontend SHALL define a single source of design tokens (CSS custom properties) covering color, spacing, radius, shadow, and typography scale, with dark theme as the default. All view pages and shared components MUST consume these tokens instead of hard-coded color or spacing values.

#### Scenario: Tokens applied globally
- **WHEN** the application loads in the browser via docker-compose frontend service
- **THEN** the `<html>` element carries the `dark` class and root CSS variables (e.g. `--ot-bg-page`, `--ot-bg-surface`, `--ot-text-primary`, `--ot-border`) are defined and consumed by the layout

#### Scenario: No hard-coded light backgrounds remain
- **WHEN** any of the 13 view pages is rendered
- **THEN** page background, card surfaces, and table areas use token-driven dark colors with no residual white/light-gray hard-coded styles

### Requirement: Element Plus dark mode integration
The frontend SHALL enable Element Plus dark mode via its official dark CSS variables and override brand variables (`--el-color-primary` series, fill, border, background colors) to match the project tokens, so that all Element Plus components (tables, dialogs, forms, dropdowns, messages, pagination) render consistently in dark theme without per-component patching. The overridden `--el-color-primary-light-N` ramp SHALL follow the dark-theme mixing direction (each step mixes the brand primary toward the dark background — light-5 through light-9 monotonically darker), matching Element Plus native dark semantics; a light-theme direction value (lighter than primary) SHALL NOT be used for light-5..9. Disabled primary buttons (white text on `--el-color-primary-light-5`) SHALL meet WCAG AA contrast (≥4.5:1).

#### Scenario: Element components follow dark theme
- **WHEN** a dialog, message box, dropdown, or date picker is opened on any page
- **THEN** it renders with dark surfaces and accessible text contrast (no white popup on dark page)

#### Scenario: Disabled primary button legible
- **WHEN** any form's primary submit button is in disabled state (e.g. required fields incomplete) on the dark theme
- **THEN** the button label remains legible with white-on-background contrast ≥4.5:1 (light-5 is a dark mix of primary and page background, not a light tint)

### Requirement: Unified async state presentation
The frontend SHALL provide a consistent presentation for loading, empty, and error states across list pages, using shared patterns or components (skeleton/spinner for loading, descriptive empty state with action hint, error state with retry affordance). Callers of the shared empty-state component SHALL use its declared props (title/hint) so guidance text is actually rendered; passing undeclared props that silently drop copy is a defect.

#### Scenario: Empty list state
- **WHEN** a list API returns zero items (e.g. no assets yet)
- **THEN** the page shows the shared empty-state presentation with guidance text instead of a bare empty table

#### Scenario: Loading state
- **WHEN** a list API request is in flight
- **THEN** the page shows the shared loading presentation and disables duplicate submissions

#### Scenario: Empty-state guidance text renders
- **WHEN** a page supplies custom empty-state copy (status statement and/or next-step guidance)
- **THEN** that copy is visibly rendered by the shared component (not silently dropped), verified by regression tests on the calling pages

### Requirement: Terminal and playback visual coherence
The xterm.js terminal theme and the recording playback containers SHALL use colors aligned with the design tokens, so that entering a terminal session or playback page does not produce a jarring contrast switch from the management UI.

#### Scenario: Terminal page coherence
- **WHEN** a user opens an SSH terminal session
- **THEN** the terminal background, toolbar, and surrounding chrome all derive from the same dark token palette

### Requirement: Readability and contrast
Text and interactive elements on dark surfaces MUST maintain sufficient contrast: primary text and primary actions SHALL meet WCAG AA contrast ratio (4.5:1 for normal text) against their background tokens.

#### Scenario: Primary text contrast
- **WHEN** body text renders on the page background or surface tokens
- **THEN** the measured contrast ratio is at least 4.5:1

### Requirement: Custodexa brand identity
The frontend SHALL present the product as "Custodexa" across all user-visible surfaces (sidebar, login, workspace top bar, terminal top bar, browser title, favicon), sourcing the display name and tagline from a single brand module (`frontend/src/brand.js`) and the brand mark from the fixed asset path `/brand/icon.png`; the descriptive subtitle SHALL resolve from the i18n locale resources (key `brand.subtitle`, translated per language) rather than the brand module, while name/tagline/icon remain fixed brand identity not subject to translation. The design tokens SHALL anchor brand colors to the Custodexa palette v2 (Primary Blue `#2563EB` as the interactive brand color — applied on dark surfaces via a lighter ramp with `#2563EB` as the pressed state; Primary Navy `#0D1B2A` surface hierarchy; Slate Gray `#334155` borders; Accent Teal `#14B8A6` as info/highlight) while preserving the dark-first theme and existing semantic colors. Rebranding SHALL require only: replacing the assets under `docs/assets/brand/` and `frontend/public/brand/`, updating token values from the palette card, editing the brand module, and updating the `brand.subtitle` values in the locale files — no per-page code changes. Technical identifiers (module paths, recording paths, audit-integrity HKDF info strings, seed account emails) MUST NOT be renamed.

#### Scenario: Brand name and mark displayed
- **WHEN** a user opens the login page or any management page
- **THEN** the brand icon (fixed path) and name (from the brand module) are displayed with no residual hard-coded brand names in page components

#### Scenario: Brand palette anchored in tokens
- **WHEN** the application renders in the browser
- **THEN** `--ot-primary` resolves to the dark-surface blue ramp anchored to Primary Blue and surface tokens resolve to the Navy v2 hierarchy, consumed globally without per-page hard-coded brand colors

#### Scenario: Contrast preserved after remapping
- **WHEN** primary actions and body text render on the v2 navy surfaces
- **THEN** WCAG AA contrast (4.5:1) is maintained per the existing readability requirement

#### Scenario: Rebrand via template only
- **WHEN** a future rebrand supplies a new palette card, icon, and logo
- **THEN** swapping the fixed-path assets, token values, brand module, and locale `brand.subtitle` values completes the rebrand with zero page-level code edits

#### Scenario: Subtitle follows active language
- **WHEN** the active language is en-US or ja-JP
- **THEN** the browser title and any subtitle surface render the translated subtitle while the name "Custodexa" and the English tagline remain unchanged

#### Scenario: Audit integrity chain unaffected
- **WHEN** the rebrand is deployed on an existing installation
- **THEN** historical audit-log HMAC verification still passes (integrity HKDF info string unchanged) and existing TOTP enrollments still verify

### Requirement: Terminology standard
The frontend SHALL follow a single terminology standard for zh-TW user-facing copy: 使用者 (not 用戶), 連線 for session entities in interface copy (technical fields like Session ID keep their original form), connection states 進行中/已結束/異常中斷, creation verb 新增 on buttons, success messages phrased 已○○, reload action 重新整理, and 停用 (not 禁用). Under i18n this standard defines the content rules for the zh-TW locale resources (the authoring source); en-US and ja-JP translations SHALL follow their own language norms and are not bound by these Chinese term choices. New and modified pages MUST use the standard for zh-TW strings; existing pages conform to it as recorded in the Terminology sweep completed requirement.

#### Scenario: Renamed menu labels
- **WHEN** an admin views the sidebar in zh-TW
- **THEN** the entry formerly named 用戶管理 reads 使用者管理 and the group formerly labeled 會話 reads 連線

#### Scenario: New pages follow the standard
- **WHEN** a newly added or modified page renders zh-TW user-facing copy
- **THEN** the copy conforms to the terminology standard (使用者/連線/進行中/新增/已○○/重新整理/停用)

#### Scenario: zh-TW standard scoped to zh-TW locale
- **WHEN** the en-US or ja-JP locale renders the same surfaces
- **THEN** translations follow natural English/Japanese phrasing without being constrained by the Chinese term mapping

### Requirement: Interaction convention standard
The frontend SHALL follow a single interaction convention set, recorded in docs/DESIGN_SPEC.md and applied across all management pages: select/date/switch filters apply on change while text inputs apply on enter or an explicit 搜尋 button (with a 重設 affordance); in-row table actions use link-style buttons with semantic types; destructive confirmations use the unified title 確認刪除, consequence copy 此操作無法復原, and a danger-styled 確定刪除 button; every list/overview page offers a 重新整理 action in its page header; dialogs use one of three width tiers (480/560/680); submit forms validate via rules with inline error messages; tabs sit at page level and refetch on switch; empty states use the shared EmptyState component; global errors surface only via the interceptor toast; pagination uses the full layout with the shared container class.

#### Scenario: Filter behavior uniform
- **WHEN** a user changes a dropdown filter on any list page
- **THEN** the list refreshes immediately without pressing a separate query button, and text search still applies via enter or the 搜尋 button

#### Scenario: Destructive confirmation uniform
- **WHEN** a user triggers any delete/dangerous action
- **THEN** the confirmation presents the unified title, consequence copy, and danger-styled confirm button

#### Scenario: Refresh affordance present
- **WHEN** a user opens any list or overview page
- **THEN** a 重新整理 action is available in the page header area

#### Scenario: Shared utilities consumed
- **WHEN** a page renders dates, durations, protocol tags, or role-gated content
- **THEN** it consumes the shared format/protocol utilities and role composable rather than local reimplementations

### Requirement: Terminology sweep completed
All user-facing copy across management pages SHALL conform to the terminology standard (使用者/連線/進行中/新增/已○○/重新整理/停用) with no residual 用戶/會話/刷新/創建/禁用 outside technical identifiers, verified by repository-wide search. The following boundary terms SHALL likewise follow Taiwan-standard usage: 檢視（非查看）、目前（非當前）、字元/字串（非字符/字符串）、唯讀（非只讀）、存取（非訪問）、連線（非連接，連接埠除外）、設定（非設置）、支援（非支持）、批次（非批量）、IP 位址（非 IP 地址）、一般（人稱，非普通）。

#### Scenario: No simplified-flavored residuals
- **WHEN** the frontend source is searched for the deprecated terms in user-facing strings
- **THEN** no occurrences remain except technical identifiers and historical archives

#### Scenario: Boundary terms cleared
- **WHEN** frontend and backend Chinese strings are searched for the boundary terms
- **THEN** no user-facing occurrences remain, with 連接埠 preserved as the correct Taiwan term for port

### Requirement: Role display metadata single source
The frontend SHALL source role display metadata from a single module (`constants/roles.js`) consumed by the roles page (table tags and the per-role permission description card, rendered by iterating the backend role list), the users page (role tags), and the profile page. The module SHALL remain the single source for the role value domain and non-translatable metadata (tag color, ordering); role labels and detailed descriptions SHALL resolve from the i18n locale resources (keyed per role) so they follow the active language. The assignable-roles list in the user role-assignment dialog SHALL be fetched from the backend roles API rather than hard-coded, so backend-added roles appear automatically. zh-TW role labels SHALL follow the terminology standard: 管理員/稽核人員/審核人員/一般使用者. Unknown role names SHALL degrade gracefully: raw name, info tag, and the backend-provided description when present (empty otherwise) — roles are an open set, exempt from the closed-domain trip-the-suite rule. A completeness test SHALL pin that every seeded backend role (admin/auditor/approver/user) has metadata and a non-empty label/description key in every supported locale.

#### Scenario: Backend-added role is assignable and described
- **WHEN** a role exists in the backend roles table (e.g. approver)
- **THEN** the role-assignment dialog offers it (from the API), the roles page shows its localized tag and description entry, and no page displays a bare English role name for seeded roles

#### Scenario: Metadata completeness pinned across locales
- **WHEN** the frontend test suite runs
- **THEN** a completeness test fails if any seeded role (admin/auditor/approver/user) lacks tag metadata or lacks a non-empty label/description translation in any supported locale (zh-TW/en-US/ja-JP)

#### Scenario: Graceful fallback for unknown roles
- **WHEN** the backend returns a role name without frontend metadata
- **THEN** the UI renders the raw name with a neutral tag and the backend-provided description, without crashing or hiding the role

#### Scenario: Role labels follow active language
- **WHEN** the active language is switched to en-US
- **THEN** role tags and description cards render the en-US translations while API payloads keep the original role values

### Requirement: Enumeration display completeness
Frontend enumeration display metadata (audit actions, audit resources, failure mechanisms, session end reasons, protocols, roles) SHALL live in single-source modules whose value domains are hard-copied from the backend definitions; display labels for these values SHALL resolve from the i18n locale resources and be pinned by completeness tests asserting that every backend value has a non-empty key in every supported locale. For the closed domains (audit actions, audit resources, failure mechanisms, session end reasons) a backend-added value SHALL fail the frontend suite (in all languages at once) until metadata is supplied; roles are an open set pinned only for seeded roles with graceful fallback for unknown names, and protocol tags are technical identifiers not subject to translation. Filter dropdowns for these enumerations SHALL be generated from the same source as the display translations (no separate hand-written option lists), and zombie options for values the backend does not produce MUST NOT exist.

#### Scenario: Backend-added enum value trips the suite
- **WHEN** the backend adds a new audit action, resource, mechanism, or end reason
- **THEN** the corresponding completeness test fails for every supported locale until the value-domain module and all locale files are updated, after which dropdowns and table translations update together

#### Scenario: No zombie filter options
- **WHEN** a user opens the audit log resource filter
- **THEN** every option corresponds to a value the backend can produce (the former value="alert" dead option is absent)

#### Scenario: Approver scope manageable from UI
- **WHEN** an admin opens the 審核範圍 dialog for an approver-role user
- **THEN** existing scopes are listed (asset or asset-group), new scopes can be assigned via the asset XOR group selector, and removal requires an explicit confirmation

### Requirement: Form controls carry a programmatic label association
Every form control that a user is expected to operate SHALL be programmatically associated with its visible label, so that assistive technology can report which control the text describes. A label that merely sits next to a control SHALL NOT be treated as satisfying this requirement.

The association SHALL be verified against the rendered DOM, not against the props a component declares. A component library may declare an attribute as a prop, consume it, and never place it on the underlying native element; a test that only checks the prop was accepted passes while the association does not exist.

Where the control is a native element under the project's own control, `for` paired with `id` SHALL be preferred, because it also makes the label activate the control. Where the control is rendered by a component library that does not forward an identifier to its native element, the association SHALL be made with `aria-labelledby` pointing at the label's `id`. This form carries the semantic association without the click-to-focus behaviour, which is an accepted limitation of the component boundary rather than an omission.

Identifier values SHALL be unique within the rendered page and stable across renders. Index-derived identifiers SHALL NOT be used where the same form can appear more than once (dialogs, repeated panels, branches that are currently mutually exclusive): a collision resolves to the wrong label, which reports incorrect information rather than none, and mutual exclusivity in today's implementation is not a structural guarantee.

Controls that exist only as a programmatic trigger and are never presented to the user (for example a hidden file input activated by a button) SHALL be exempt, because they have no position in the visual layout where a label could belong. The visible control that activates them carries the accessible name instead.

#### Scenario: Native control under project control
- **WHEN** the control is a native form element the project renders directly
- **THEN** the label carries `for` and the control carries the matching `id`, and activating the label moves focus to the control

#### Scenario: Component library control
- **WHEN** the control is rendered by a component library that does not forward an identifier to its native element
- **THEN** the label carries an `id` and the control carries `aria-labelledby` with that value, verified on the rendered node rather than on the wrapper component

#### Scenario: Repeated or branched instances of the same form
- **WHEN** the same field appears in more than one place, including branches that are mutually exclusive today
- **THEN** their identifiers differ, so that a later change allowing both to render at once cannot silently collide

#### Scenario: Hidden trigger control
- **WHEN** a control is hidden from the layout and exists only to be activated programmatically
- **THEN** it is exempt from the label association requirement, and the visible activating control carries the accessible name

### Requirement: Buttons declare their type
Every `button` element SHALL declare an explicit `type`. HTML defaults an undeclared button to `submit`, so a button that is later moved inside a form changes behaviour without any edit to the button itself. Buttons that perform an action other than form submission SHALL declare `type="button"`.

#### Scenario: Action button outside a form
- **WHEN** a button triggers an action that is not a form submission
- **THEN** it declares `type="button"` regardless of whether a form element currently encloses it

