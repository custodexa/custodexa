# permission-dashboard-guidance Specification

## Purpose
儀表板依有效權限點呈現：升級後的非阻擋新版說明（依能力組成段落與連結、關閉狀態存伺服器、可由使用者選單重看）、升級時被調整的保留項目告知，以及各卡逐一宣告授權、計數與列表共用授權與篩選來源、待審計數依實際審核資格計算。

## Requirements

### Requirement: Nonblocking capability-aware release guidance

The dashboard SHALL display release guidance above its existing cards when a signed-in user has not dismissed that guidance version. The guidance SHALL be an inline card without a blocking overlay or focus trap; all other dashboard functions SHALL remain usable. The release guidance version SHALL remain stable across patch releases of the same guidance content.

Guidance sections and links SHALL reflect the user's effective server-provided capabilities and available entry rules. Section applicability and link availability SHALL be decided separately. Each link SHALL be shown only when the shared entry rule of its destination, the same rule used by the sidebar and route guard, admits the user; the guidance SHALL NOT define a separate or broader capability check for a link. A section SHALL apply when the shared entry rule of its destination admits the user, except that a management section whose destination entry is open to every signed-in user SHALL apply only when the user holds the server-provided presentation capability for that management view. Such an exception SHALL NOT change the destination entry's reachability. A section that applies without an admissible destination SHALL show its text without the link. General users SHALL NOT receive management sections; holding an entry that is open to every signed-in user SHALL NOT by itself make a management section applicable. The guidance SHALL NOT query or contain asset, credential, node, group or user records, names or counts. It MAY display authorized policy adjustment records as specified separately. Existing dashboard cards and panels SHALL remain available under their respective authorization rules.

#### Scenario: First visit after upgrade
- **WHEN** a user signs in after upgrading and opens the dashboard without a dismissal for the current guidance version
- **THEN** the guidance appears above the existing cards and the rest of the page remains operable

#### Scenario: Guidance follows effective capabilities
- **WHEN** a general user and a user with management capabilities open the guidance
- **THEN** each sees only sections and available links applicable to their capabilities, and neither receives resource records or resource counts in the guidance

#### Scenario: Links use the destination entry rule
- **WHEN** a user can enter a destination through any one of several capabilities accepted by its entry rule, or holds none of them
- **THEN** the guidance shows that destination's link exactly when the sidebar shows the entry, and a section whose applicability is that entry rule appears under the same condition, without requiring a single broader management capability

#### Scenario: An open entry does not imply a management section
- **WHEN** a signed-in user who lacks the global asset presentation capability and every credential capability opens the guidance
- **THEN** the user can still enter the asset page, but neither the asset-management section nor the credential section appears

#### Scenario: Asset-management and credential sections are independent
- **WHEN** one user holds only the global asset presentation capability and another holds only one of the capabilities accepted by the credential entry rule
- **THEN** the first sees the asset-management section without the credential section, the second sees the credential section without the asset-management section, and each link follows its destination entry rule

#### Scenario: Guidance loading fails independently
- **WHEN** guidance or dismissal loading fails
- **THEN** a retryable state is shown without blocking the dashboard or granting access through fallback role checks

### Requirement: Server-persisted self-owned guidance dismissal

Guidance dismissal SHALL be stored on the server per authenticated user and guidance version. The read and write endpoints SHALL be registered as owner/self operations and SHALL derive the owner solely from the authenticated principal. They SHALL reject attempts to specify another owner, unknown input fields or unsupported guidance versions. Repeated dismissal SHALL be idempotent. The status and its audit record SHALL commit together; a failed save SHALL NOT be represented as a successful dismissal.

Missing state SHALL mean not dismissed. After successful dismissal, subsequent visits, sign-ins and browsers SHALL NOT automatically display that guidance version. Manually reopening the guidance SHALL NOT clear its stored dismissal. Session changes SHALL discard the preceding user's cached state and in-flight results.

#### Scenario: Dismissal survives a different browser
- **WHEN** a user dismisses guidance and later signs in through another browser
- **THEN** the same version stays automatically hidden while another user's undismissed guidance remains visible

#### Scenario: Caller cannot read or change another user's state
- **WHEN** an unauthenticated caller or a caller specifying another user attempts to access dismissal state
- **THEN** the request is rejected and the other user's state is unchanged

#### Scenario: Idempotent dismissal and failed save
- **WHEN** a dismissal is repeated or its transactional audit fails
- **THEN** repetition does not create duplicate state or audit entries, and failure leaves the prior state unchanged with retry available

#### Scenario: Manual reopening is temporary
- **WHEN** a user reopens previously dismissed guidance and subsequently signs in again
- **THEN** the manual view uses current capabilities and the stored dismissal still prevents automatic display

### Requirement: Durable retention-adjustment notice

Users with the security-policy read capability SHALL see every retention adjustment recorded during upgrade. The four data retention categories (audit logs, command streams, alert records and recordings) are raised when their value was between 1 and 6 days; checkpoint retention is adjusted only when needed to keep covering a data category it covered before the upgrade. The card SHALL show each recorded category with its recorded previous value, recorded new value and adjustment time, and SHALL NOT assume a fixed new value for checkpoint retention. The notice SHALL identify these as historical upgrade adjustments, not the current configuration or a statutory minimum.

Coverage SHALL follow the cross-policy retention rule: checkpoint retention covers a data category when it is permanent or not shorter than that category, and a value of 0 means permanent retention. Values that remained 0 or at least 7 days SHALL NOT be listed as raised. The notice SHALL separately list data categories that checkpoint retention currently does not cover, computed from current effective values, labeled as current settings to be adjusted on the security policy page; the upgrade does not modify these values. Because an uncovered relation may predate the upgrade or arise later through configuration seeding or direct changes, the notice SHALL NOT state when or why a relation became uncovered. A link to the security policy page SHALL follow that page's shared entry rule.

The notice SHALL use durable policy-adjustment records, independent of audit-log retention and guidance dismissal. A later configuration change or a different product patch version SHALL NOT erase an applicable adjustment. Repeated adjustments of the same category SHALL be represented by its latest recorded adjustment. When there are neither recorded adjustments nor uncovered categories, the retention section SHALL NOT be shown.

The adjustment endpoint SHALL require the applicable policy read capability independently of the self-owned dismissal endpoint. Unauthorized users SHALL receive neither the records nor the section. The projection SHALL contain policy identifiers, reason indicators, day values and timestamps only; it SHALL NOT contain resource identities, names or counts. When the adjustment source cannot be read, the endpoint SHALL return an existing error response and SHALL NOT return an empty, partial or previously read projection as success. A missing adjustment source SHALL prevent the endpoint from being assembled rather than produce empty results; an empty successful projection SHALL mean that there are neither recorded adjustments nor uncovered categories.

#### Scenario: All affected categories are listed
- **WHEN** four data retention categories were raised and checkpoint retention was adjusted to keep covering them
- **THEN** the authorized user's card lists all five recorded categories with their recorded old and new day values and timestamps, and marks the checkpoint entry as adjusted to preserve coverage

#### Scenario: Permanent and already compliant values are unchanged
- **WHEN** some policies were 0 or at least 7 days and others were raised
- **THEN** only the raised policies appear in the adjustment list and the explanation preserves 0 as permanent retention

#### Scenario: Uncovered categories are current, not historical
- **WHEN** a data category is permanent or longer than checkpoint retention, whether that relation existed before the upgrade or arose afterwards
- **THEN** the card lists it separately as a current uncovered setting with the security policy link allowed by its entry rule, without presenting it as an upgrade adjustment or stating when it became uncovered

#### Scenario: Notice remains available after audit expiry
- **WHEN** a user first opens or manually reopens guidance after the corresponding audit rows expired or current policy values changed
- **THEN** the recorded upgrade adjustments remain available and are labeled as historical adjustments

#### Scenario: Nothing to report
- **WHEN** no category was adjusted and checkpoint retention currently covers every data category
- **THEN** the retention section is not shown

#### Scenario: Unauthorized or failed adjustment loading
- **WHEN** a caller lacks policy read access or an authorized request fails
- **THEN** the former is rejected without records, while the latter produces a retryable error rather than a false empty list

#### Scenario: Adjustment source failure is not reported as empty
- **WHEN** the adjustment source returns an error, including after yielding some records, or is not provided when the service is assembled
- **THEN** the request fails with an existing error code and no records, or the service is not assembled, and in neither case does an empty successful projection appear

### Requirement: Per-card authorization registry

Each dashboard card SHALL declare a stable identifier, necessary read capabilities or authenticated-self predicate or effective approval eligibility, data provider, unit, filters and destination where one exists. The frontend SHALL use server-provided capabilities for visibility and SHALL NOT fetch data for a card whose necessary predicate is absent. The backend SHALL independently enforce that card's predicate on every request and reject unknown card identifiers by default.

One management capability SHALL NOT imply access to other cards. The server's presentation-only capability for approval eligibility SHALL NOT be accepted as an assignable backend permission. Effective permissions SHALL be resolved from the current principal, not client-supplied role names or presentation flags. Self-service cards SHALL be limited to the caller's own data.

The registry SHALL cover asset totals, own connections, own pending requests, active sessions, today's sessions, total sessions, today's alerts, recording storage, pending approvals, unreviewed alerts, active recording-failure sessions and time since the last access review. The existing daily security-review component, activity panels and quick actions SHALL each retain their own read or action predicates.

#### Scenario: Missing predicate for each card
- **WHEN** a subject lacks a registered card's necessary capability or eligibility
- **THEN** that card is absent, no frontend request is made for it and a direct data request is rejected

#### Scenario: Combined capabilities and custom roles
- **WHEN** a subject has multiple or custom combinations of effective capabilities
- **THEN** applicable cards appear once each and no unrelated card data is returned

#### Scenario: Revoked or stale card data
- **WHEN** a capability is removed or the signed-in account changes
- **THEN** the corresponding data is cleared and responses from the preceding session cannot repopulate it

### Requirement: Filtered counts share list authorization and query sources

Every item-count card SHALL use the same authorized query source and filters as its destination list, counting after visibility filtering and deduplication and before pagination or display limits. For the same subject, data and time window, the card value SHALL equal the destination list's full filtered total. A page length or truncated set SHALL NOT substitute for that total. Existing API response contracts SHALL remain unchanged; new card data SHALL be provided through additional endpoints.

Card navigation SHALL apply its filters to the destination view. Today's session and alert cards SHALL use the same captured day interval and the same interval-boundary interpretation as their destination views; a record at the boundary between two days SHALL be counted in only one day. Unreviewed alerts SHALL include all eligible alert sources, including system-security alerts, under the same unreviewed predicate as the alert list. Recording-failure counts SHALL cover the complete authorized active-session set, not a recent-activity preview.

Recording-storage bytes, elapsed access-review days and daily-review status SHALL retain their original units and authoritative providers; they SHALL NOT be treated as item counts or given fictitious destination pages. Failed loading SHALL NOT be displayed as a successful zero. No card SHALL reveal names or counts outside the caller's permitted data set.

#### Scenario: Full total beyond a page limit
- **WHEN** an authorized list has more matching records than its display limit
- **THEN** its card and full-total indicator use the complete filtered count while the loaded-row count is distinguished

#### Scenario: Same filters and day interval
- **WHEN** a user opens a count card's destination
- **THEN** the destination applies the same status and time filters, and fixed-data counts agree with its full filtered total

#### Scenario: System and other alert sources
- **WHEN** unreviewed records include both system-security alerts and other alert kinds
- **THEN** the unreviewed-alert card and list count all eligible unreviewed records using the same query

#### Scenario: Units and unavailable data
- **WHEN** recording storage or access-review age is rendered, or a data request fails
- **THEN** successful values preserve their source units and failed values remain unavailable rather than appearing as zero

### Requirement: Pending approvals reflect actual review eligibility

The pending-approvals card SHALL require the same effective reviewer predicate as the approval-center entry and endpoints. A super-administrator or management role SHALL NOT substitute for that predicate. Its value SHALL use the complete pending and pending-review counts used by the corresponding views and navigation badge, under the same ApproverScope and actual decision-eligibility rules.

A request SHALL contribute to the count only when the corresponding single-request decision would let the actor act on it. For pending approvals this means at least one item is still pending, that item is within the actor's review scope, and the request is not barred by the self-decision rule applied to that decision, which excludes the requester, the designated executor and, when the requester is an agent, its current owner. For pending reviews the count SHALL apply exactly the exclusions and scope rule used by the single review decision. A pending approval whose pending expiry time has passed SHALL NOT be counted, consistently with the single decision rejecting it. This expiry exclusion SHALL apply only to pending approvals: a break-glass request awaiting review SHALL remain counted while its review is pending, regardless of whether its connection window has ended or its review deadline has passed, and the single review decision SHALL continue to accept an eligible actor for it. The list, count, badge and card SHALL share one predicate with the single decision; a divergent copy of these rules SHALL NOT be introduced for the card. Multiple eligible items of the same request SHALL NOT multiply the request count. A qualified reviewer with no matching requests SHALL receive zero; a caller without reviewer eligibility SHALL be rejected.

#### Scenario: Scope and self-review exclusions
- **WHEN** a reviewer has eligible requests alongside out-of-scope, self-requested, owned-agent or otherwise non-actionable requests
- **THEN** only requests the shared review service permits the actor to review contribute to the count

#### Scenario: Executor and completed items are not counted
- **WHEN** the actor is the designated executor of an in-scope request, or a request's in-scope items are already decided while only out-of-scope items remain pending
- **THEN** that request is not counted, consistently with the single-request decision rejecting the actor

#### Scenario: Expiry affects pending approvals only
- **WHEN** an eligible reviewer has an ordinary pending request past its pending expiry time, a break-glass request whose connection window has ended and a break-glass request past its review deadline, both still awaiting review
- **THEN** the expired pending request is not counted and cannot be decided, while both break-glass requests are counted as pending reviews and the reviewer can still review them

#### Scenario: No administrator fallback
- **WHEN** an administrator without effective reviewer eligibility requests pending-approval data
- **THEN** the endpoint rejects the request and the card is absent

#### Scenario: Group reviewer and empty scope result
- **WHEN** a group-derived reviewer has matching requests or has no matches
- **THEN** the count equals the full eligible pending and pending-review totals, or zero respectively, consistently with the badge
