# frontend-testing

## Purpose

前端測試基礎建設與關鍵元件、流程的測試覆蓋規範。

## Requirements

### Requirement: Test infrastructure runs inside docker-compose
The frontend SHALL provide `npm run test` (single run) and `npm run test:coverage` scripts executable inside the docker-compose frontend container, using Vitest with a DOM environment, requiring no network access beyond the local node_modules.

#### Scenario: Tests run in container
- **WHEN** `docker compose exec -T frontend npm run test` is executed
- **THEN** the suite runs to completion and exits non-zero on any failure

#### Scenario: Coverage report
- **WHEN** `docker compose exec -T frontend npm run test:coverage` is executed
- **THEN** a coverage summary is produced for the tested modules

### Requirement: HTTP interceptor behavior is tested
The request interceptor module SHALL have tests covering: Authorization header injection when the in-memory session holds a token, no header when it is empty, 401 response clearing the in-memory token and the stored user entry and redirecting to login, and error message mapping for 400/403/404/500 responses.

#### Scenario: Token injection
- **WHEN** the in-memory session holds a token and a request is dispatched
- **THEN** the request config carries `Authorization: Bearer <token>`

#### Scenario: 401 handling
- **WHEN** a response returns status 401 and the refresh attempt fails
- **THEN** the in-memory token is cleared, the user entry is removed from localStorage, and the browser is directed to /login

### Requirement: Session module and storage guard are tested
The in-memory session module SHALL have tests covering: page-load restore performing no network call without a login hint, restore succeeding via the refresh endpoint and storing the token in memory only, restore failure clearing the login hint, concurrent restore calls sharing one refresh request, and cross-tab signals carrying no credential while a logout signal clears the in-memory token. A source-level guard test SHALL scan all frontend sources (tests excluded) and fail on any read or write of an access token in localStorage or sessionStorage, and SHALL fail if the application entry point stops clearing the legacy stored token.

#### Scenario: Restore without hint
- **WHEN** the session module restores on page load and no login hint exists
- **THEN** no refresh request is issued and the caller is told the session is absent

#### Scenario: Restore success
- **WHEN** a login hint exists and the refresh endpoint returns a token
- **THEN** the token is held in memory, localStorage and sessionStorage contain no token, and concurrent restore calls observe a single refresh request

#### Scenario: Storage guard turns red
- **WHEN** any source file gains `localStorage.setItem('token', …)` or the entry point loses the legacy cleanup
- **THEN** the guard test fails and names the offending file

### Requirement: Router guards are tested
The router navigation guards SHALL have tests covering: unauthenticated access to a protected route redirects to /login, authenticated access to /login redirects to /dashboard, and role-restricted routes redirect non-matching users to /dashboard.

#### Scenario: Unauthenticated redirect
- **WHEN** no token exists and navigation targets a route with requiresAuth
- **THEN** navigation resolves to /login

#### Scenario: Role restriction
- **WHEN** a non-admin user navigates to an admin-only route
- **THEN** navigation resolves to /dashboard

### Requirement: Permission-aware layout rendering is tested
MainLayout SHALL have tests verifying: all five nav groups render for admin users, admin-only groups and items are absent for non-admin users, and the sidebar collapse state persists to localStorage under `ot-sidebar-collapsed`.

#### Scenario: Non-admin visibility
- **WHEN** MainLayout mounts with a non-admin user in localStorage
- **THEN** 系統管理 group and 資產授權 item are not rendered

#### Scenario: Collapse persistence
- **WHEN** the collapse toggle is clicked
- **THEN** `ot-sidebar-collapsed` in localStorage reflects the new state

### Requirement: Shared components are tested
PageHeader and EmptyState SHALL have tests covering prop rendering and slot projection.

#### Scenario: PageHeader slots
- **WHEN** PageHeader mounts with title, description, and an actions slot
- **THEN** all three render in their designated regions

### Requirement: CI runs frontend tests
The CI workflow SHALL execute the frontend test suite and fail the pipeline on test failure.

#### Scenario: CI gate
- **WHEN** a commit triggers the CI workflow
- **THEN** the frontend job runs `npm run test` and the pipeline fails if any test fails
