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
The request interceptor module SHALL have tests covering: Authorization header injection when a token exists, no header when absent, 401 response clearing stored credentials and redirecting to login, and error message mapping for 400/403/404/500 responses.

#### Scenario: Token injection
- **WHEN** a token exists in localStorage and a request is dispatched
- **THEN** the request config carries `Authorization: Bearer <token>`

#### Scenario: 401 handling
- **WHEN** a response returns status 401
- **THEN** token and user entries are removed from localStorage and the browser is directed to /login

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
