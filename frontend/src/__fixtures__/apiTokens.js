// API token 清單投影的測試替身：欄位與值依後端回應契約（TokenView、eligibility、restore）。
const DAY = 24 * 60 * 60 * 1000

const isoIn = (days) => new Date(Date.now() + days * DAY).toISOString()

export const roleAsset = (extra = {}) => ({
  role_id: 5,
  name: '資產管理員',
  builtin_key: 'asset_admin',
  effective: true,
  scope: { kind: 'nodes', nodes: [{ id: 31, name: '研發三處' }, { id: 41, name: '研發四處' }] },
  ...extra,
})

export const roleAuthz = (extra = {}) => ({
  role_id: 9,
  name: '授權管理員',
  builtin_key: 'authz_admin',
  effective: true,
  scope: { kind: 'global' },
  ...extra,
})

export const roleAdmin = (extra = {}) => ({
  role_id: 1,
  name: 'admin',
  builtin_key: 'super_admin',
  effective: true,
  scope: { kind: 'global' },
  ...extra,
})

export const roleSecurity = (extra = {}) => ({
  role_id: 2,
  name: '系統安全管理員',
  builtin_key: 'security_admin',
  effective: true,
  scope: { kind: 'global' },
  ...extra,
})

const base = (extra) => ({
  privileged: false,
  created_at: '2026-08-15T02:12:40Z',
  expires_at: null,
  last_used_at: null,
  last_used_ip: '',
  revoked_at: null,
  revoked_by: null,
  revoke_note: '',
  ...extra,
})

export const tokenPlanCi = (extra = {}) =>
  base({
    id: 1,
    name: 'terraform-plan-ci',
    status: 'expiring_soon',
    granted_roles: [roleAsset()],
    created_at: '2026-08-18T07:20:33Z',
    expires_at: isoIn(3),
    last_used_at: '2026-11-12T18:00:09Z',
    last_used_ip: '10.20.30.21',
    ...extra,
  })

export const tokenProdApply = (extra = {}) =>
  base({
    id: 2,
    name: 'terraform-prod-apply',
    status: 'active',
    granted_roles: [roleAsset(), roleAuthz()],
    expires_at: isoIn(90),
    last_used_at: '2026-11-13T05:58:02Z',
    last_used_ip: '10.20.30.15',
    ...extra,
  })

export const tokenDrift = (extra = {}) =>
  base({
    id: 3,
    name: 'drift-check',
    status: 'active',
    granted_roles: [roleAsset()],
    created_at: '2026-11-12T08:40:03Z',
    ...extra,
  })

export const tokenExpired = (extra = {}) =>
  base({
    id: 4,
    name: 'terraform-2025',
    status: 'expired',
    granted_roles: [roleAsset({ effective: false, scope: null })],
    created_at: '2025-08-15T02:05:12Z',
    expires_at: '2026-08-15T15:59:59Z',
    last_used_at: '2026-08-15T13:40:02Z',
    last_used_ip: '10.20.30.15',
    ...extra,
  })

export const tokenRevoked = (extra = {}) =>
  base({
    id: 5,
    name: 'jenkins-legacy',
    status: 'revoked',
    granted_roles: [roleAuthz()],
    created_at: '2025-03-02T03:00:45Z',
    expires_at: '2026-03-02T15:59:59Z',
    last_used_at: '2025-09-29T00:12:19Z',
    last_used_ip: '10.20.40.9',
    revoked_at: '2025-09-30T09:02:44Z',
    revoked_by: { user_id: 57, username: 'ops-chen' },
    ...extra,
  })

export const standardTokens = () => [tokenProdApply(), tokenDrift(), tokenExpired(), tokenRevoked(), tokenPlanCi()]

export const eligibility = (extra = {}) => ({
  can_create: true,
  reason: '',
  grantable_roles: [roleAsset(), roleAuthz()],
  non_grantable_roles: [{ role_id: 4, name: '一般使用者', builtin_key: 'user' }],
  allowed_cidrs: ['10.20.0.0/16', '10.30.5.0/24'],
  ...extra,
})

export const listResponse = (tokens = standardTokens(), elig = eligibility(), restore = { invalidated_count: 0, restored_at: null }) => ({
  data: tokens,
  eligibility: elig,
  restore,
})

// 明顯的假值：只用來確認一次性明文的流向
export const FAKE_PLAINTEXT = 'cxp_reveal_once_fixture_for_tests_only'
