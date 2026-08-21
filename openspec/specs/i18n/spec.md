# i18n

## Purpose

前端國際化基礎能力：三語支援（zh-TW 事實源／en-US／ja-JP）、語言切換與偏好、Element Plus 連動、日期時長本地化、locale 完備性防護與技術識別字紅線。後端錯誤訊息的 error code 體系屬另一規格範圍。
## Requirements
### Requirement: Supported languages with zh-TW as source of truth
The frontend SHALL support three display languages — zh-TW (source of truth), en-US, and ja-JP — via vue-i18n in Composition API mode, with locale resources stored as one JSON file per language under a single frontend i18n module. The zh-TW resource SHALL be the authoring source; en-US and ja-JP SHALL maintain an identical key set. Missing translations SHALL resolve through the fallback chain (ja-JP → en-US → zh-TW; en-US → zh-TW) and MUST NOT render bare key paths or break layout.

#### Scenario: ja-JP falls back to en-US
- **WHEN** a key has zh-TW and en-US translations but its ja-JP translation is missing
- **THEN** the ja-JP UI renders the en-US text, never the raw key path

#### Scenario: Chain falls through to zh-TW
- **WHEN** a key exists only in zh-TW (missing in both ja-JP and en-US)
- **THEN** the ja-JP and en-US UIs render the zh-TW text, never the raw key path

#### Scenario: Locale key sets aligned
- **WHEN** the frontend test suite runs
- **THEN** a structural test fails if the zh-TW, en-US, and ja-JP locale files do not have exactly the same key set

### Requirement: Language switching and preference persistence

The frontend SHALL offer a language switcher in the MainLayout header, on the login page (language must be selectable before authentication), in the workspace top bar (connection surfaces live outside the MainLayout shell, so the long-lived workspace needs its own switcher), and **on the unseal page**. The unseal page is not an optional surface for this: while a deployment is sealed it is the **only reachable page** (every other route is redirected to it and the login endpoint itself returns 503), so an operator who cannot read the active language is stranded on a page that blocks the entire service with no way out. The switcher SHALL remain operable while sealed — language selection SHALL NOT depend on any backend endpoint. The selected language SHALL be persisted in localStorage under the device-global key `ot-lang` (not role-scoped, since it takes effect pre-login), and resolved on startup in the order: valid `ot-lang` value > browser language prefix match (zh→zh-TW, ja→ja-JP, otherwise en-US) > zh-TW default. A stored value outside the supported locale set MUST be treated as unset (falling through to browser detection), never applied. Switching SHALL take effect immediately without a full page reload; Element Plus component locale SHALL follow the active language reactively including imperative APIs (ElMessageBox/ElMessage rendered outside the provider tree); and `document.title` and the `<html lang>` attribute SHALL update on every language change (watch-driven, not assigned once at module load).

#### Scenario: Switch without reload
- **WHEN** a user changes the language from the workspace top bar while a connection is active (or from the MainLayout header on any management page)
- **THEN** menus, enumeration labels, Element Plus component texts, and date formats re-render in the new language without a page reload and the active connection stays alive (shell state preserved, WebSocket not rebuilt)

#### Scenario: Pre-login language selection
- **WHEN** a visitor on the login page selects en-US
- **THEN** the login page renders in English immediately and the choice persists in `ot-lang` across sessions

#### Scenario: Language selectable while sealed
- **WHEN** the deployment is sealed and the operator lands on the unseal page (the only reachable page, reached from any URL via the seal redirect)
- **THEN** a language switcher offering every supported locale MUST be present on that page, and selecting one MUST re-render the unseal page in that language immediately, without a reload and without any successful backend call

#### Scenario: First-visit browser detection
- **WHEN** a first-time visitor with browser language ja-JP and no `ot-lang` stored opens the app
- **THEN** the UI renders in ja-JP; a stored `ot-lang` value on a later visit takes precedence over browser language

#### Scenario: Invalid stored value ignored
- **WHEN** localStorage contains `ot-lang=fr-FR` (or an empty/legacy value) and the browser language is en
- **THEN** the app starts in en-US via browser detection, without applying the unsupported value to i18n or the Element Plus locale mapping

#### Scenario: Imperative dialogs follow language
- **WHEN** the user switches to en-US and then triggers a confirmation via ElMessageBox without custom button text
- **THEN** the dialog's default confirm/cancel/close texts render in English

#### Scenario: Document metadata follows language
- **WHEN** the user switches the language at runtime
- **THEN** `document.title` re-renders with the translated subtitle and `document.documentElement.lang` reflects the active locale

### Requirement: Localized date, duration, and relative time
Date and time rendering SHALL derive its locale from the active i18n language (via the shared format utilities — no per-page reimplementation), using Intl APIs for date order and month representation and Intl.RelativeTimeFormat for relative time. The hour representation SHALL remain fixed at 24-hour across all languages (audit precision decision, not a localization preference). Duration texts SHALL use count-aware plural messages (English singular/plural distinguished, Japanese/Chinese spacing natural) — never unit-string interpolation joined by spaces. Values displayed on a loaded page SHALL be re-derived at render time so a language switch re-renders them; storing pre-formatted strings in component state is a defect for the surfaces this capability covers.

#### Scenario: Date format follows language
- **WHEN** the active language changes from zh-TW to en-US
- **THEN** timestamps rendered by the shared format utilities switch to the en-US date order while remaining 24-hour

#### Scenario: Relative time localized
- **WHEN** a list shows an event from three minutes ago in ja-JP
- **THEN** the relative label renders in Japanese (not 「3 分鐘前」), produced by Intl.RelativeTimeFormat or locale resources

#### Scenario: Duration plurals correct in English
- **WHEN** durations of 1 hour and 2 hours render in en-US
- **THEN** the texts distinguish singular and plural (1 hour / 2 hours), never `1 hours`

#### Scenario: Loaded page re-renders on switch
- **WHEN** a list page with timestamps is already rendered and the user switches the language
- **THEN** the visible timestamps re-render in the new locale without a manual refresh

### Requirement: Technical identifiers excluded from translation
Technical identifiers MUST NOT be translated or altered by i18n: enumeration values themselves (audit action/resource keys, end reasons, role names as stored), protocol tags (SSH/RDP/VNC/K8s/DB), session IDs, recording paths, audit-integrity HKDF info strings, seed account emails, and debug/console messages. Translation applies only to user-facing display strings.

#### Scenario: Enum values stay stable across languages
- **WHEN** the UI language is en-US or ja-JP
- **THEN** filter requests and API payloads still use the original enumeration values (e.g. `create`, `asset`) and protocol tags still render as SSH/RDP/VNC

#### Scenario: Audit records unaffected
- **WHEN** a user operates the UI in any language
- **THEN** audit log entries are written with the same language-neutral action/resource keys and JSON details as before i18n

### Requirement: Full management-surface string coverage
All user-facing strings in frontend view pages and shared components — template copy, table column labels, form labels and placeholders, buttons, dialog titles and bodies, and imperative feedback (ElMessage/ElMessageBox) — SHALL resolve from the i18n locale resources; hard-coded display strings in any supported language MUST NOT remain in views or components. Keys SHALL be organized as one top-level namespace per view/component file, with strings shared by two or more files promoted to the `common.*` namespace instead of duplicated. Enumeration display SHALL keep resolving through the single-source constants/utils getters — views MUST NOT introduce local enum-to-text maps. The zh-TW locale SHALL remain the authoring source and its rendered output SHALL be textually identical before and after extraction (wording fixes are a separate adjudication, not part of the sweep). Backend-supplied display strings (security-policy `label`/`unit` fields, transmission risk labels, and transmission-inventory notes/preflight/unset markers) SHALL be localized via enumerable machine codes per the `Backend-supplied display labels localized` requirement; code comments and technical identifiers (including inventory detail composite keys such as `security=nla,verify_cert=true`) remain outside translation scope.

#### Scenario: Management pages fully render in active language
- **WHEN** the user switches to en-US or ja-JP and visits any management page (e.g. Assets, AuditLogs, Users, Alerts) including its dialogs, dropdown placeholders, and action feedback messages
- **THEN** every user-facing string renders in the active language with no residual zh-TW hard-coded copy, and backend-supplied labels resolve through their machine-code getters

#### Scenario: zh-TW rendering unchanged by extraction
- **WHEN** the UI renders in zh-TW after the sweep
- **THEN** all user-facing copy is textually identical to the pre-sweep zh-TW UI, and existing tests asserting zh-TW strings pass without weakening

#### Scenario: Mixed-language handover items closed
- **WHEN** the UI renders in en-US or ja-JP
- **THEN** the Dashboard subtitle suffix, the AuditLogs status filter labels and status column translation, and the 「全部」 filter placeholders on Sessions/Authorizations/Alerts/Users/AuditLogs/Assets all follow the active language

#### Scenario: New keys guarded by existing structural tests
- **WHEN** the sweep adds keys to the locale files
- **THEN** the three-locale key-set alignment test and per-key placeholder consistency check cover the new keys without modification, and a key added to fewer than all three locales fails the suite

#### Scenario: No local enum maps reintroduced
- **WHEN** a view needs to display an enumeration value (e.g. audit log status)
- **THEN** it resolves through the single-source constants/utils getters (or `enum.*` locale keys), and any pre-existing local map (e.g. the former AuditLogs translateStatus) is removed

#### Scenario: Roles list description column localized
- **WHEN** the user switches to en-US or ja-JP and opens the roles page
- **THEN** the role list's description column resolves seeded roles through the shared `roleDescription` getter in the active language (never rendering the backend zh `description` field directly for a seeded role), and an unknown (non-seeded) role degrades gracefully to the backend-supplied description string

### Requirement: Backend-supplied display labels localized
Backend-supplied display strings that surface in the UI SHALL be resolved for display via a stable machine code rather than rendered directly from the backend zh text (the backend zh string is retained only as a graceful-degradation fallback and audit/export snapshot). This covers three surfaces: security-policy field labels (anchored on the policy `key`) and value units (anchored on a semantic `unit_key`, with a definition-time invariant that a non-empty unit has a valid `unit_key`); transmission risk labels (anchored on the risk `key`); and transmission-inventory channel notes and strict-mode preflight messages (anchored on a `note_code`/`preflight_code`, count parameters carried as integers) plus the unset-value marker (carried in a complete machine-keyed `detail_codes` map — technical composite keys unchanged, the sole Chinese `(未設定)` key re-keyed to `unset` — which the new frontend adopts wholesale in place of the legacy `detail` map, with `detail` retained unchanged only as an old-frontend/export fallback, so no merge or dedup against the Chinese `detail` is ever required). The frontend SHALL resolve each through a shared getter — never per-page maps — that returns the translation for the active language and, being reactive to the locale, re-renders on language switch.

Resolution SHALL degrade precisely, not through vue-i18n's automatic fallback chain: the getter SHALL use the translation only when it exists for the exact active locale (existence-checked) AND all required parameters are supplied; otherwise it SHALL return the backend-supplied zh string, and only the raw code as a last resort. A missing translation or absent required parameter SHALL NOT render a bare `{slot}` or code path, and SHALL emit a dev-only console warning (silent in production). The zh-TW locale text for these codes SHALL be the source of truth and MUST equal the backend zh template so the wire fallback and the rendered translation never diverge.

Each family of codes SHALL be enumerable from a backend registry (a policy-definition table, a risk-descriptor registry with `AllRiskDescriptors()`, and an inventory note/preflight descriptor registry), and each registry SHALL validate at registration time that a descriptor's `{placeholder}` set exactly equals its declared required parameters (no missing, extra, duplicate, or empty parameter names). Risk labels and inventory notes/preflight SHALL be produced only through a registry-backed constructor; a static-analysis test SHALL scan all backend production files (recognizing the public struct and its aliases, allowlisting the key-only fingerprint helper) and fail if any bare risk composite literal or bare inventory note/preflight assignment bypasses the registry. Backend completeness tests (reusing the shared locale-directory mount) SHALL fail if any registered code lacks a non-empty translation in all three languages, if any locale carries an orphan key outside the registries, if a parametrized code's `{placeholder}` set differs across the three languages, if the zh-TW translation drifts from the backend zh template (template compared to template, not to an interpolated instance), or if an en-US/ja-JP value is byte-identical to zh-TW outside an explicit allowlist (untranslated-copy heuristic). Parameter-integrity unit tests SHALL confirm each parametrized constructor emits exactly its declared parameters — including that each inventory preflight carries the correct count source — and fails fast on a missing one.

Localizing these display strings SHALL NOT change any persistence or audit JSON shape: consent records and gate/transmission audit details continue to serialize their existing `{key, label}` risk snapshots unchanged, and inventory audit continues to record only its event code. Parameters needed only for display (e.g. a risk's `{protocol}`) SHALL be supplied by the frontend caller from its own context or carried on non-persisted wire responses, never added to a persisted struct.

#### Scenario: Policy pages fully localized including inventory
- **WHEN** the user switches to en-US and opens any of the four policy pages, including the transmission-inventory page's channel notes and strict-mode preflight lines
- **THEN** every policy field label, value unit, risk label, channel note, and preflight message renders in English (e.g. "Max failed login attempts", "minutes", "Switching to strict will reject 3 RDP assets"), with no residual zh-TW from the backend

#### Scenario: Count-parametrized preflight pluralized
- **WHEN** a strict-mode preflight for 1 asset and for 3 assets renders in en-US
- **THEN** the messages distinguish singular and plural via count-aware plural messages (never "1 assets"), and all three languages declare the same `{count}` slot

#### Scenario: Missing parameter degrades to backend zh, never a bare slot
- **WHEN** a new frontend runs against an older backend, or a caller omits a required display parameter for `syslog_non_tls`
- **THEN** the getter returns the backend-supplied zh label (already interpolated), never a literal `{protocol}`, and a dev console warning is emitted

#### Scenario: Persistence and audit shape unchanged
- **WHEN** a user consents to transmission risks in ja-JP and the consent and audit records are written
- **THEN** the dialog shows Japanese risk labels while the persisted consent `risk_items` and the audit `details` serialize the same `{key, label}` snapshot, byte-shape unchanged

#### Scenario: New backend code without translation fails CI
- **WHEN** a ninth transmission risk (or a new policy key / inventory code) is added without a translation, or a bare risk literal bypasses the registry
- **THEN** the backend completeness test and the risk static-analysis test fail, and the UI meanwhile degrades to the backend zh fallback rather than a bare code

### Requirement: 伺服端出站通知翻譯目錄
後端 SHALL 具備一個伺服端翻譯目錄套件 `internal/notifycat`，以 `embed` 內建 zh-TW/en-US/ja-JP 三語資源，並提供 `Render(lang, event, params)` 組出出站文案。此目錄的服務範圍 SHALL 僅限**出站 Slack 文案**（含系統訊息、測試通知、告警標示與 audit-failure 通知）——HTTP 錯誤與 WebSocket/串流一律走「送碼、前端查譯」，SHALL NOT 由伺服端渲染。

事件識別字 SHALL 為具名型別 `notifycat.Event`，其常數與對應 `EventSpec` SHALL 同檔宣告，成為目錄的單一真實來源。目錄 SHALL 具備**雙向完備性守衛**：三語鍵集與 registry 鍵集完全相等（缺鍵、孤兒鍵皆紅）、同一鍵的 `{placeholder}` 集合三語一致、registry 非空。呼叫端 SHALL 以 notifycat 匯出常數指名事件；**字面量守衛** SHALL 掃描「`Event` 型別的參數位置或賦值目標出現字串字面量」（`NotifyEvent` 呼叫的第一實參、`Event` 變數宣告/賦值右值為 BasicLit 即紅）——因 Go 未定型字串常數可隱式轉換為具名型別，僅掃顯式轉換節點不足以攔截最自然的錯誤寫法。

#### Scenario: 三語渲染由目錄產出
- **WHEN** 一個系統事件送往語系為 en-US 的 Slack 通道
- **THEN** 文案由 notifycat 以 en-US 資源渲染為英文，params 插值到對應佔位符，後端程式碼中不存在對應的散文組字

#### Scenario: 缺鍵與孤兒鍵皆守衛失敗
- **WHEN** 新增一個 `notifycat.Event` 常數但未補齊三語文案，或某語系殘留 registry 以外的鍵
- **THEN** 雙向完備性測試失敗並指出事件與語言，未完備的目錄無法進入主線

#### Scenario: 佔位符三語一致
- **WHEN** 某事件的 en-US 文案漏掉 zh-TW 已宣告的 `{count}` 佔位符
- **THEN** 佔位符一致性測試失敗，避免渲染出缺參數的文案

#### Scenario: 字面量事件識別字被攔截
- **WHEN** 開發者寫 `NotifyEvent("access_request_approved", params)`（字串字面量隱式轉為 `Event`）
- **THEN** 字面量守衛測試失敗，迫使改用 notifycat 匯出常數，typo 於守衛期即被攔截

### Requirement: opaque 參數淨化契約
出站與串流的參數值分為三種 kind：`enum`（允許清單）、`int`、`opaque`（自由字串）。`opaque` 值 SHALL 原樣傳遞**不翻譯**（username、asset_name、request_id、rule name 等屬此類）。所有 `opaque` 值 SHALL 經**單一共用淨化函式** `sanitizeOpaque` 處理，該函式同時服務 notifycat 出站組字與 WebSocket 幀 params：限長 **128 rune**（非 byte，使中日文合法名不受傷；asset name 上限 100、username 50，合法值永不觸限）、strip 換行／ANSI ESC／控制字元；超限 SHALL **可見截斷**（尾附省略記號），SHALL NOT 拒發或靜默丟棄——合規通知不因單一長值消失。

值層 SHALL NOT 宣稱能機器判定「是不是散文」；防線為宣告審查＋限長去格式＋收端自行呈現，此限制 SHALL 誠實記載。去識別紅線不變：事由全文等敏感長文 SHALL NOT 進入 params。

#### Scenario: 超長值可見截斷不拒發
- **WHEN** 某 opaque 參數值超過 128 rune
- **THEN** 值被截斷至上限並附可見省略記號後照常送出，通知不因此消失

#### Scenario: 控制字元被移除
- **WHEN** 某 opaque 值（如告警規則名稱）含 ANSI ESC 或換行字元
- **THEN** 這些字元在送出前被 strip，出站 payload 與 WebSocket 幀皆不含終端控制序列

#### Scenario: opaque 值不被翻譯
- **WHEN** 通道語系為 ja-JP 且事件 params 含 username 與 asset_name
- **THEN** 模板文字以日文渲染，而這些 opaque 值原樣呈現，不被查譯或改寫

#### Scenario: 敏感長文不入 params
- **WHEN** 一筆存取申請的事由全文很長
- **THEN** 事由全文不作為 params 送出，出站 payload 僅含受控的結構化欄位

### Requirement: 「送碼、前端查譯」延伸至 WebSocket 幀
「後端送機器碼、前端查譯顯示」的架構 SHALL 自 HTTP 錯誤延伸至 WebSocket 幀：終端錯誤幀（`type:"error"`）SHALL 帶必填 `code`，控制通知幀（`type:"notice"`）SHALL 帶 `code`（並得帶 `params`），前端 SHALL 依當前語言查譯後呈現，後端 SHALL NOT 對串流內容做伺服端語言渲染。既有 `data` 欄 SHALL 保留 zh fallback，使譯文漏鍵時仍有可見訊息。

因採前端查譯，WebSocket 連線 SHALL NOT 需要語系參數；監看類廣播 SHALL 對全房觀察者送出同一份碼化 bytes，由各前端各自查譯，天然達成 per-observer 正確語言，SHALL NOT 為此改動 observers 資料結構。

#### Scenario: WS 錯誤幀依前端語言顯示
- **WHEN** 使用者以 en-US 介面連線失敗並收到帶 `code` 的錯誤幀
- **THEN** 終端錯誤畫面顯示該 code 的英文譯文；譯文缺失時退回幀內 `data` 的 zh fallback，不顯示裸 key

#### Scenario: 多觀察者各自語言
- **WHEN** 同一監看房間有 zh-TW 與 ja-JP 兩位觀察者，房間關閉廣播送出
- **THEN** 兩人各自看到自己語言的訊息，後端只送出一份相同的碼化 bytes

#### Scenario: 連線不攜帶語系參數
- **WHEN** 前端建立終端 WebSocket
- **THEN** 連線 URL 與握手訊息不含語系參數，語言切換不需重建 WebSocket

### Requirement: 前端錯誤文字解析單一入口全面落實
前端所有呈現 API 錯誤文字的站點 SHALL 經共用純函式 `resolveApiError(data, status)` 解析，SHALL NOT 直讀 `data.error` 自行呈現——直讀會繞過 code 三層降級，使後端已 code 化的錯誤在 en-US/ja-JP 介面仍顯示繁中。既知繞過站點（SSH 終端錯誤呈現、syslog 轉發設定卡、告警頁）SHALL 收斂至同一函式。

#### Scenario: 既知繞過站點收斂
- **WHEN** 使用者以 en-US 介面在 SSH 終端、syslog 轉發設定卡或告警頁觸發 API 錯誤
- **THEN** 錯誤文字經 `resolveApiError` 以 code 查譯顯示英文，而非後端繁中 `error` 原文

#### Scenario: 降級鏈不被繞過破壞
- **WHEN** 某錯誤的 code 在前端無譯文
- **THEN** 站點仍經同一函式退回後端 `error` 繁中文案，再退回通用狀態訊息，永不顯示空白或裸 key

### Requirement: 對外文案的稽核可讀性與其守衛

面向**稽核與合規人員**的對外文案（檢查點驗證頁、稽核調查工作台、安全政策的風險說明）SHALL 以該讀者可理解的語言撰寫。判準為讀者能回答兩個問題：**我在看什麼**、**我該做什麼判斷**。

四條規範：

1. **保護範圍在先**：凡陳述控制邊界之處，SHALL 先呈現該控制保護什麼，再列邊界。只列「防不了什麼」SHALL NOT 單獨成立。
2. **每條邊界兩部分**：SHALL 同時載明「情境」與「此風險由什麼承擔」，缺一不成立。
3. **不得裸露實作術語**：對外文案 SHALL NOT 包含內部函式名、狀態機器碼或工程術語。
4. **三語各自為該語言合規人員的用語**：en-US 與 ja-JP SHALL NOT 為 zh-TW 的逐字直譯，SHALL NOT 使用音譯型工程詞（如以片假名音譯 query、workbench），SHALL NOT 出現不完整句。

上述規範 SHALL NOT 被用來刪除或弱化任何事實：改寫前後的事實條數 SHALL NOT 減少，任何「防不了 X」SHALL NOT 被改寫為「防得了 X」，補償控制的描述 SHALL NOT 超過實際實作。

**機械守衛**（規範 1、2、3 可機器驗證的部分）SHALL 存在，且其掃描對象為**三份 locale 檔的對外 namespace**，SHALL NOT 為原始碼——原始碼識別字本應為英文技術詞，掃原始碼只會製造誤報並逼人擴大豁免。守衛 SHALL 涵蓋：

- **術語黑名單**：對外 namespace 的任一值含黑名單詞即失敗。豁免 SHALL 逐鍵附理由，且豁免總數 SHALL 有釘定上限，新增豁免使其超限即失敗（防「只驗刪除、不驗放寬」）。
- **邊界結構**：邊界聲明每一條須具備「情境」與「由什麼承擔」兩部分，缺一即失敗。
- **順序**：保護範圍段的位置須早於第一條邊界。

守衛 SHALL 在選取集合為空時失敗（namespace 更名或結構調整導致掃空時 SHALL NOT 靜默通過），且每支守衛 SHALL 以突變自證其會轉紅。

**跨頁用語一致性**：同一概念在不同頁面 SHALL 使用同一用語（封存單位的稱呼、驗證頁自身的稱呼、清除水位的稱呼、連線的稱呼）。同一概念出現兩種說法 SHALL 視為缺陷。

#### Scenario: 對外文案不含實作術語

- **WHEN** 掃描三份 locale 的對外 namespace
- **THEN** 無任一值含內部函式名、狀態機器碼或黑名單工程術語，豁免鍵各自附有理由且未超過釘定上限

#### Scenario: 邊界缺承擔即失敗

- **WHEN** 任一條邊界聲明只有情境而無「由什麼承擔」
- **THEN** 結構守衛失敗

#### Scenario: 保護範圍被移到邊界之後即失敗

- **WHEN** 保護範圍段與邊界段的順序被對調
- **THEN** 順序守衛失敗

#### Scenario: 掃空不得靜默通過

- **WHEN** 對外 namespace 更名或被移除，使守衛的選取集合為空
- **THEN** 守衛失敗，SHALL NOT 因無項目可檢而通過

#### Scenario: 三語各自可讀

- **WHEN** 以 en-US 與 ja-JP 檢視對外文案
- **THEN** 各語言為該語言合規人員的用語，無音譯型工程詞、無不完整句、非 zh-TW 逐字直譯

#### Scenario: 同一概念跨頁同名

- **WHEN** 比對檢查點驗證頁與稽核調查工作台對同一概念的用語
- **THEN** 兩頁使用同一詞，SHALL NOT 各自命名

### Requirement: 解封頁文案的操作者可讀性與其守衛

解封頁的對外文案（`unseal.*` 與同頁渲染的 `apiError.SEAL_*`）SHALL 以**疲勞狀態下的維運
人員**為讀者撰寫。該讀者具備維運領域知識（環境變數、重啟服務、十六進位、base64），
但工作記憶已耗盡且會跳著看畫面——解封頁被讀到的時點，正是服務中斷處理中。
判準為讀者能回答一個問題：**我下一步要做什麼**。

五條規範：

1. **動作在前**：凡述及需要人為處置之處，SHALL 先呈現要做的事，理由 SHALL 置後或省略。
2. **一句一事**：單句 SHALL NOT 串接三個以上子句。多重處置 SHALL 拆為編號步驟或並列
   選項，SHALL NOT 寫成散文。
3. **不得陳述內部設計理由**：對外文案 SHALL NOT 說明後端為何如此設計（失敗回應為何
   不可區分、某驗證走哪條路徑、某頁為何不需登入、狀態回應含哪些欄位）。
   對應之安全行為本身不因此改變。
4. **不得裸露實作術語**：SHALL NOT 包含內部函式名、狀態機器碼，或未經替換的工程行話
   （信封密文、解包／unwrap、收束、留痕、材料、fail-close 一類）。技術識別字
   （環境變數名、檔名、`base64`、路徑）SHALL NOT 視為行話，SHALL 原樣保留。
5. **三語同標準**：en-US 與 ja-JP SHALL 各自符合上列四條，SHALL NOT 因翻譯而回復長句
   或補回被刪除的設計理由。否定句與警告之強度 SHALL 三語一致——弱化即為缺陷。

上述規範 SHALL NOT 被用來刪除或弱化任何事實：改寫前後**操作者做決定所需的事實條數
SHALL NOT 減少**（含「一般解封不需要帳號密碼」「主金鑰的三種輸入寫法」「冷卻會自動
恢復、不需重啟」一類），任何「會發生 X」SHALL NOT 被改寫為「不會發生 X」。

**遺失警語之版面優先度**：`key-management` 已要求「KEK 遺失導致全部資料永久不可解、
系統不提供任何救援」以不可略過的措辭陳述於解封介面。解封頁 SHALL 進一步使該陳述在
**版面上優先於同頁其他說明**——SHALL 具獨立標題、SHALL 位於任何解封表單之前、
其正文 SHALL NOT 以次要文字樣式呈現。該區塊 SHALL 於系統**未解封時**恆常顯示，
SHALL NOT 僅於初始化解封路徑顯示（一般解封的操作者同樣可能是該金鑰的唯一持有者）；
已解封時 SHALL NOT 顯示——該狀態下此陳述不可行動，恆常出現只會訓練使用者忽略它。

**跨頁用語一致性**（既有規範之延伸）：解封頁承載之錯誤訊息與該頁自身文案 SHALL 使用
同一用語。同一概念出現兩種說法 SHALL 視為缺陷。

**機械守衛**（規範 3、4 可機器驗證的部分）SHALL 存在，其掃描對象為**三份 locale 檔的
`unseal.*` 全部葉鍵**，SHALL NOT 為原始碼。守衛 SHALL 涵蓋行話黑名單與狀態機器碼形態，
且 SHALL 在選取集合為空或顯著縮小時失敗（鍵改名或 namespace 調整導致掃空時
SHALL NOT 靜默通過）。

**機械守衛之誠實界線**：守衛擋得住行話回流與鍵消失，**擋不住「這句話人看不看得懂」**。
後者 SHALL 以人工驗收承擔，且該驗收 SHALL 由未參與該文案撰寫者執行——
系統 SHALL NOT 宣稱文案可讀性已被自動化驗證。

#### Scenario: 解封頁文案不含內部設計理由與行話

- **WHEN** 掃描三份 locale 的 `unseal.*` 全部葉鍵
- **THEN** 無任一值含狀態機器碼、內部函式名或行話黑名單詞，且葉鍵數未低於釘定下限

#### Scenario: 遺失警語先於解封表單且非次要樣式

- **WHEN** 系統未解封，解封頁渲染完成
- **THEN** 遺失警語區塊 MUST 出現於任何解封表單之前，MUST 具獨立標題，
  其正文 MUST NOT 套用次要文字樣式

#### Scenario: 已解封時不再顯示遺失警語

- **WHEN** 系統已解封，解封頁渲染完成
- **THEN** 遺失警語區塊 MUST NOT 出現

#### Scenario: 一般解封路徑同樣顯示遺失警語

- **WHEN** 系統未解封且狀態為既有部署（非初始化解封）
- **THEN** 遺失警語區塊 MUST 出現

#### Scenario: 操作者所需事實未因改寫而減少

- **WHEN** 檢視一般解封與初始化解封兩條路徑的文案
- **THEN** 「一般解封不需要帳號密碼」「主金鑰的三種輸入寫法」「初始管理員帳密的來源」
  MUST 各自仍可自畫面讀到

#### Scenario: 三語警告強度一致

- **WHEN** 以三語檢視遺失警語與保存確認勾選項
- **THEN** 各語言 MUST 同為無條件、無例外、涵蓋全部資料的措辭，
  MUST NOT 出現「可能」「大部分」一類在其他語言不存在的弱化限定

