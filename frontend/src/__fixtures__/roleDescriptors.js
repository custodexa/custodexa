// 角色編輯描述的測試 fixture：取後端入口表中三種態數的代表入口與全部三個獨立能力、固定入口。
const st = (name, ...keys) => ({ name, keys })
const hidden = { name: 'hidden', keys: [] }

export const descriptorsFixture = {
  entries: [
    {
      id: 'assets',
      group: 'asset',
      states: [
        hidden,
        st('read', 'asset:view'),
        st('manage', 'asset:view', 'asset:create', 'asset:update', 'asset:delete', 'asset:test', 'asset:group-manage'),
      ],
      details: [
        { id: 'asset.view', key: 'asset:view' },
        { id: 'asset.create', key: 'asset:create' },
        { id: 'asset.update', key: 'asset:update' },
        { id: 'asset.delete', key: 'asset:delete' },
        { id: 'asset.test', key: 'asset:test' },
        { id: 'asset_account.view', key: 'asset:view' },
        { id: 'asset_account.update', key: 'asset:update' },
        { id: 'node.manage', key: 'asset:group-manage' },
      ],
      write_keys: ['asset:create', 'asset:delete', 'asset:group-manage', 'asset:test', 'asset:update'],
    },
    {
      id: 'credentials',
      group: 'asset',
      states: [
        hidden,
        st('read', 'credential:view', 'asset:view'),
        st('manage', 'credential:manage', 'credential:view', 'credential:create', 'credential:update', 'asset:view'),
      ],
      details: [],
      write_keys: ['credential:create', 'credential:manage', 'credential:update'],
    },
    {
      id: 'authorizations',
      group: 'authorization',
      states: [hidden, st('manage', 'authorization:manage')],
      details: [],
      write_keys: ['authorization:manage'],
    },
    {
      id: 'approver_scopes',
      group: 'authorization',
      states: [hidden, st('manage', 'approverscope:manage', 'approverscope:manage_applicant')],
      details: [],
      write_keys: ['approverscope:manage', 'approverscope:manage_applicant'],
    },
    {
      id: 'users',
      group: 'identity',
      states: [hidden, st('manage', 'user:manage')],
      details: [],
      write_keys: ['user:manage'],
    },
    {
      id: 'roles',
      group: 'identity',
      states: [hidden, st('available', 'role:view')],
      details: [],
    },
    {
      id: 'sessions',
      group: 'audit',
      states: [hidden, st('read', 'session:view'), st('manage', 'session:view', 'session:terminate')],
      details: [],
      write_keys: ['session:terminate'],
    },
    {
      id: 'audit_logs',
      group: 'audit',
      states: [hidden, st('available', 'audit:view')],
      details: [],
    },
    {
      id: 'alerts',
      group: 'audit',
      states: [hidden, st('read', 'alert:view', 'audit:view'), st('manage', 'alert:view', 'alert:manage', 'audit:view')],
      details: [],
      write_keys: ['alert:manage'],
    },
    {
      id: 'access_reviews',
      group: 'audit',
      states: [hidden, st('manage', 'accessreview:manage', 'audit:view')],
      details: [],
      write_keys: ['accessreview:manage'],
    },
  ],
  capabilities: [
    { id: 'role_assign', key: 'role:assign', trust_hint: true, requires_entry: false },
    { id: 'access_policy_override', key: 'access_policy:manage', trust_hint: false, requires_entry: false },
    { id: 'recording_delete', key: 'recording:delete', trust_hint: false, requires_entry: false },
  ],
  fixed_entries: ['dashboard', 'workspace', 'profile', 'my_connections', 'my_requests', 'my_agents', 'approvals'],
}

export const emptySummary = {
  summary: { manage: [], read: [], available: [], hidden: [] },
  missing_dependencies: [],
  blocked_screens: [],
}
