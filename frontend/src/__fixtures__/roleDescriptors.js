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
    },
    {
      id: 'users',
      group: 'identity',
      states: [hidden, st('manage', 'user:manage')],
      details: [],
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
