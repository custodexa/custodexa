import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import RoleEditor from '../RoleEditor.vue'
import { ElDialogStub } from '@/__fixtures__/dialogStub'
import { descriptorsFixture } from '@/__fixtures__/roleDescriptors'
import { previewDisabledMapping } from '@/__fixtures__/rolePreviews'
import i18n from '@/i18n'

enableAutoUnmount(afterEach)

const h = vi.hoisted(() => ({
  request: vi.fn(),
  route: { params: {}, query: {} },
  push: vi.fn(),
  replace: vi.fn(),
}))

// 直接攔在 HTTP 層：驗證實際送出的路徑與本文鍵集合
vi.mock('@/api/request', () => ({ default: (...a) => h.request(...a) }))
vi.mock('vue-router', () => ({
  useRoute: () => h.route,
  useRouter: () => ({ push: h.push, replace: h.replace }),
}))

const t = (k, p) => i18n.global.t(k, p)
const noRefs = { direct: 0, group_bindings: 0, mapping_rules: 0 }
const emptyOp = { marks: [], self_direction: '', routes_gained: [], routes_lost: [], evaluated: 0 }
const noHit = { total: 0, matched: 0, truncated: false, subjects: [], operation: emptyOp }

const detail = (over = {}) => ({
  id: 10,
  name: 'ops-custom',
  description: 'desc',
  builtin_key: null,
  locked: false,
  definition_version: 5,
  template_role_id: 4,
  permissions: ['user:manage'],
  summary: { manage: ['users'], read: [], available: [], hidden: ['assets'] },
  missing_dependencies: [],
  blocked_screens: [],
  ...over,
})
const listRow = (over = {}) => ({
  id: 10,
  name: 'ops-custom',
  builtin_key: null,
  locked: false,
  definition_version: 5,
  user_count: 0,
  references: { ...noRefs, mapping_rules: 1 },
  ...over,
})

let cfg
const setup = (over = {}) => {
  cfg = {
    canDefine: true,
    detail: detail(),
    rows: [
      { id: 4, name: 'identity_admin', builtin_key: 'identity_admin', locked: true, user_count: 0, references: noRefs },
      listRow(),
    ],
    summary: { summary: { manage: ['users'], read: [], available: [], hidden: [] }, missing_dependencies: [], blocked_screens: [] },
    preview: noHit,
    previewError: null,
    putError: null,
    ...over,
  }
  h.request.mockImplementation(async (c) => {
    const key = `${c.method.toUpperCase()} ${c.url}`
    if (key === 'GET /role-definitions/descriptors') return descriptorsFixture
    if (key === 'GET /role-definitions') return { data: cfg.rows, total: cfg.rows.length, can_define: cfg.canDefine }
    if (key.startsWith('GET /role-definitions/')) {
      const id = Number(c.url.split('/').pop())
      return id === 4 ? detail({ id: 4, name: 'identity_admin', builtin_key: 'identity_admin', locked: true, permissions: ['user:manage', 'role:view'] }) : cfg.detail
    }
    if (key === 'POST /role-definitions/summary') return cfg.summary
    if (key === 'POST /role-assignment-previews') {
      if (cfg.previewError) throw cfg.previewError
      return cfg.preview
    }
    if (key === 'PUT /role-definitions/10') {
      if (cfg.putError) throw cfg.putError
      return detail()
    }
    if (key === 'POST /role-definitions') return { id: 77 }
    throw new Error(`unexpected request ${key}`)
  })
}
const calls = (method, url) => h.request.mock.calls.map((c) => c[0]).filter((c) => c.method.toUpperCase() === method && c.url === url)

const mountEditor = async (params = { id: '10' }, query = {}) => {
  h.route.params = params
  h.route.query = query
  const w = mount(RoleEditor, {
    global: { plugins: [ElementPlus], stubs: { ElDialog: ElDialogStub, RouterLink: { template: '<a><slot /></a>' } } },
  })
  await flushPromises()
  return w
}

describe('RoleEditor', () => {
  beforeEach(() => {
    h.request.mockReset()
    h.push.mockReset()
    h.replace.mockReset()
    setup()
  })

  it('各入口的選項數與名稱與描述一致，沒有描述以外的唯讀選項', async () => {
    const w = await mountEditor()
    const names = (id) => w.findAll(`[data-test^="entry-${id}-"]`).map((b) => b.attributes('data-test').slice(`entry-${id}-`.length))
    expect(names('assets')).toEqual(['hidden', 'read', 'manage'])
    expect(names('users')).toEqual(['hidden', 'manage'])
    expect(names('roles')).toEqual(['hidden', 'available'])
    expect(w.get('[data-test="entry-users-manage"]').text()).toBe(t('roles.state.manage'))
    expect(w.find('[data-test="entry-users-read"]').exists()).toBe(false)
    expect(w.find('[data-test="entry-roles-read"]').exists()).toBe(false)
    expect(w.get('[data-test="entry-users-manage"]').attributes('aria-pressed')).toBe('true')
  })

  it('固定入口不可操作並顯示可見條件', async () => {
    const w = await mountEditor()
    const fixed = w.get('[data-test="fixed-entries"]')
    expect(fixed.findAll('button, input')).toHaveLength(0)
    expect(w.get('[data-test="fixed-my_agents"]').text()).toContain(t('roles.editor.fixedVisible.agentOwner'))
    expect(w.get('[data-test="fixed-approvals"]').text()).toContain(t('roles.editor.fixedVisible.approver'))
    expect(w.get('[data-test="fixed-dashboard"]').text()).toContain(t('roles.editor.fixedVisible.everyone'))
  })

  it('資產可展開細分動作並顯示「n／m」', async () => {
    const w = await mountEditor()
    expect(w.get('[data-test="detail-toggle-assets"]').text()).toBe(t('roles.editor.detailCount', { n: 0, m: 8 }))
    expect(w.find('[data-test="detail-asset.view"]').exists()).toBe(false)
    await w.get('[data-test="detail-toggle-assets"]').trigger('click')
    await w.get('[data-test="detail-asset.create"]').setValue(true)
    expect(w.get('[data-test="detail-toggle-assets"]').text()).toBe(t('roles.editor.detailCount', { n: 1, m: 8 }))
  })

  it('三個獨立能力各一個勾選；只有 trust_hint 為真者出現人選信任提示', async () => {
    const w = await mountEditor()
    for (const c of descriptorsFixture.capabilities) {
      expect(w.findAll(`[data-test="capability-${c.id}"]`)).toHaveLength(1)
      expect(w.get('[data-test="capability-section"]').text()).toContain(t(`roles.editor.capability.${c.id}`))
    }
    expect(w.findAll('[data-test="trust-hint"]')).toHaveLength(1)
    expect(w.findAll('[data-test="no-partial-delegation"]')).toHaveLength(1)
    expect(w.get('[data-test="trust-hint"]').text()).toBe(t('roles.editor.trustHint'))
  })

  it('只勾 access_policy_override 儲存：permissions 只多 access_policy:manage', async () => {
    const w = await mountEditor()
    await w.get('[data-test="capability-access_policy_override"]').setValue(true)
    await w.get('[data-test="editor-save"]').trigger('click')
    await flushPromises()
    const put = calls('PUT', '/role-definitions/10')
    expect(put).toHaveLength(1)
    expect(put[0].data.permissions).toEqual(['access_policy:manage', 'user:manage'])
    expect(put[0].data.permissions).not.toContain('asset:update')
  })

  it('勾 recording_delete 後畫面沒有任何刪除錄影的按鈕或連結', async () => {
    const w = await mountEditor()
    await w.get('[data-test="capability-recording_delete"]').setValue(true)
    expect(w.findAll('[data-test*="delete-recording"], [data-test*="recording-delete-btn"]')).toHaveLength(0)
    const label = t('roles.editor.capability.recording_delete')
    const actions = w.findAll('button, a').filter((el) => el.text().includes(label))
    expect(actions).toHaveLength(0)
  })

  it('缺依賴：入口出現缺少項目與打不開的頁面，儲存鈕可按、儲存成功、勾選不變', async () => {
    setup({
      detail: detail({ permissions: ['user:manage', 'role:assign'] }),
      summary: {
        summary: { manage: ['users'], read: [], available: [], hidden: [] },
        missing_dependencies: [{ permission: 'role:assign', missing: ['role:view'] }],
        blocked_screens: [{ id: 'role_assign', missing: ['role:view'] }],
      },
    })
    const w = await mountEditor()
    const miss = w.get('[data-test="missing-role_assign"]')
    expect(miss.text()).toContain(t('roles.editor.entry.roles'))
    expect(w.get('[data-test="summary-missing"]').text()).toContain(t('roles.editor.summary.missingTitle'))
    const save = w.get('[data-test="editor-save"]')
    expect(save.attributes('disabled')).toBeUndefined()
    await save.trigger('click')
    await flushPromises()
    expect(calls('PUT', '/role-definitions/10')[0].data.permissions).toEqual(['role:assign', 'user:manage'])
    expect(w.get('[data-test="capability-role_assign"]').element.checked).toBe(true)
  })

  it('右欄摘要有「看不到」一段列出隱藏入口', async () => {
    setup({ summary: { summary: { manage: ['users'], read: [], available: [], hidden: ['alerts'] }, missing_dependencies: [], blocked_screens: [] } })
    const w = await mountEditor()
    const body = w.get('[data-test="summary-body"]').text()
    expect(body).toContain(`${t('roles.editor.summary.hiddenTitle')}：`)
    expect(body).toContain(t('roles.editor.entry.alerts'))
  })

  it('右欄摘要在勾了獨立能力後出現「其他能力」一段', async () => {
    const w = await mountEditor()
    expect(w.get('[data-test="summary-body"]').text()).not.toContain(`${t('roles.editor.capabilityTitle')}：`)
    await w.get('[data-test="capability-recording_delete"]').setValue(true)
    const body = w.get('[data-test="summary-body"]').text()
    expect(body).toContain(`${t('roles.editor.capabilityTitle')}：`)
    expect(body).toContain(t('roles.editor.capability.recording_delete'))
  })

  it('摘要文字來自 POST /role-definitions/summary', async () => {
    setup({ summary: { summary: { manage: ['alerts'], read: [], available: [], hidden: [] }, missing_dependencies: [], blocked_screens: [] } })
    const w = await mountEditor()
    expect(calls('POST', '/role-definitions/summary').length).toBeGreaterThan(0)
    expect(calls('POST', '/role-definitions/summary')[0].data).toEqual({ permissions: ['user:manage'] })
    expect(w.get('[data-test="summary-body"]').text()).toContain(t('roles.editor.entry.alerts'))
  })

  it('locked 角色全部控制唯讀', async () => {
    setup({ detail: detail({ id: 4, locked: true, builtin_key: 'identity_admin', name: 'identity_admin' }) })
    const w = await mountEditor({ id: '4' })
    expect(w.find('[data-test="editor-save"]').exists()).toBe(false)
    for (const b of w.findAll('.seg-btn')) expect(b.attributes('disabled')).toBeDefined()
    for (const c of w.findAll('input[type="checkbox"]')) expect(c.attributes('disabled')).toBeDefined()
    expect(w.get('input[data-test="editor-name"]').attributes('disabled')).toBeDefined()
    expect(w.get('[data-test="editor-badge-locked"]').exists()).toBe(true)
  })

  it('版本衝突：提示重新載入、草稿保留且不再送出', async () => {
    setup({ putError: { response: { status: 409, data: { error: { code: 'ROLE_DEFINITION_CONFLICT' } } } } })
    const w = await mountEditor()
    await w.get('[data-test="capability-role_assign"]').setValue(true)
    await w.get('[data-test="editor-save"]').trigger('click')
    await flushPromises()
    expect(w.get('[data-test="editor-conflict"]').text()).toContain(t('roles.editor.conflict.title'))
    expect(w.get('[data-test="capability-role_assign"]').element.checked).toBe(true)
    expect(calls('PUT', '/role-definitions/10')).toHaveLength(1)
    expect(w.get('[data-test="editor-save"]').attributes('disabled')).toBeDefined()
    await w.get('[data-test="editor-save"]').trigger('click')
    await flushPromises()
    expect(calls('PUT', '/role-definitions/10')).toHaveLength(1)
  })

  it('修改既有自訂角色：不論人數與引用都先預覽一次，確認框出現會通知安全人員', async () => {
    setup({ preview: previewDisabledMapping })
    const w = await mountEditor()
    await w.get('[data-test="entry-users-hidden"]').trigger('click')
    await w.get('[data-test="entry-assets-manage"]').trigger('click')
    await w.get('[data-test="editor-save"]').trigger('click')
    await flushPromises()
    const previews = calls('POST', '/role-assignment-previews')
    expect(previews).toHaveLength(1)
    expect(Object.keys(previews[0].data).sort()).toEqual(['kind', 'permissions', 'role_id'])
    expect(previews[0].data.kind).toBe('role_definition')
    expect(w.get('[data-test="danger-notify"]').text()).toContain(t('dangerConfirm.notify.title'))
    expect(calls('PUT', '/role-definitions/10')).toHaveLength(0)

    await w.get('[data-test="danger-back"]').trigger('click')
    await flushPromises()
    expect(calls('PUT', '/role-definitions/10')).toHaveLength(0)

    await w.get('[data-test="editor-save"]').trigger('click')
    await flushPromises()
    await w.get('[data-test="danger-proceed"]').trigger('click')
    await flushPromises()
    expect(calls('PUT', '/role-definitions/10')).toHaveLength(1)
  })

  it('預覽回 403 或失敗：提示暫時無法取得，仍可送出 PUT', async () => {
    setup({ previewError: { response: { status: 403 } } })
    const w = await mountEditor()
    await w.get('[data-test="capability-role_assign"]').setValue(true)
    await w.get('[data-test="editor-save"]').trigger('click')
    await flushPromises()
    expect(w.text()).toContain(t('dangerConfirm.previewFailed.title'))
    expect(calls('PUT', '/role-definitions/10')).toHaveLength(0)
    await w.get('[data-test="danger-proceed"]').trigger('click')
    await flushPromises()
    expect(calls('PUT', '/role-definitions/10')).toHaveLength(1)
  })

  it('沒有組合也沒有標記時直接儲存，請求本文鍵集合等於修改列', async () => {
    const w = await mountEditor()
    await w.get('[data-test="capability-role_assign"]').setValue(true)
    await w.get('[data-test="editor-save"]').trigger('click')
    await flushPromises()
    const put = calls('PUT', '/role-definitions/10')[0]
    expect(Object.keys(put.data).sort()).toEqual(['description', 'expected_version', 'name', 'permissions'])
    expect(put.data.expected_version).toBe(5)
  })

  it('新增不送預覽：無範本不送 template_role_id，帶範本則送', async () => {
    setup()
    let w = await mountEditor({}, { name: 'brand-new', description: 'x' })
    await w.get('[data-test="entry-users-manage"]').trigger('click')
    await w.get('[data-test="editor-save"]').trigger('click')
    await flushPromises()
    let post = calls('POST', '/role-definitions')
    expect(post).toHaveLength(1)
    expect(Object.keys(post[0].data).sort()).toEqual(['description', 'name', 'permissions'])
    expect(calls('POST', '/role-assignment-previews')).toHaveLength(0)
    expect(h.replace).toHaveBeenCalledWith('/roles/77')
    w.unmount()

    h.request.mockClear()
    setup()
    w = await mountEditor({}, { name: 'from-tpl', template: '4' })
    expect(w.get('[data-test="entry-roles-available"]').attributes('aria-pressed')).toBe('true')
    await w.get('[data-test="editor-save"]').trigger('click')
    await flushPromises()
    post = calls('POST', '/role-definitions')
    expect(Object.keys(post[0].data).sort()).toEqual(['description', 'name', 'permissions', 'template_role_id'])
    expect(post[0].data.template_role_id).toBe(4)
    expect(calls('POST', '/role-assignment-previews')).toHaveLength(0)
  })

  it('畫面上沒有節點選擇或「以此角色預覽」', async () => {
    const w = await mountEditor()
    expect(w.findAll('[data-test*="node"], [data-test*="preview-as"], [data-test*="permission-overview"]')).toHaveLength(0)
    expect(w.text()).not.toContain('以此角色預覽')
  })

  describe('可限範圍標示與節點範圍指派提示', () => {
    const scopedDescriptors = () => {
      const d = JSON.parse(JSON.stringify(descriptorsFixture))
      d.entries[0].scopable = true // assets
      d.entries[0].details[0].scopable = true // asset.view
      d.entries[0].details[1].scopable = false
      d.entries[1].scopable = false // users
      d.capabilities[1].scopable = true // access_policy_override
      return d
    }
    const withDescriptors = (d) => {
      const base = h.request.getMockImplementation()
      h.request.mockImplementation(async (c) => {
        if (`${c.method.toUpperCase()} ${c.url}` === 'GET /role-definitions/descriptors') return d
        return base(c)
      })
    }
    const sum = (over = {}) => ({
      summary: { manage: ['users'], read: [], available: [], hidden: [] },
      missing_dependencies: [],
      blocked_screens: [],
      ...over,
    })

    it('入口、細項、獨立能力依伺服器 scopable 帶標示，false 或缺欄位的不帶', async () => {
      withDescriptors(scopedDescriptors())
      const w = await mountEditor()
      const tag = t('roles.editor.scopable')
      expect(w.get('[data-test="scopable-entry-assets"]').text()).toBe(tag)
      expect(w.find('[data-test="scopable-entry-users"]').exists()).toBe(false)
      expect(w.find('[data-test="scopable-entry-roles"]').exists()).toBe(false)
      await w.get('[data-test="detail-toggle-assets"]').trigger('click')
      expect(w.find('[data-test="scopable-detail-asset.view"]').exists()).toBe(true)
      expect(w.find('[data-test="scopable-detail-asset.create"]').exists()).toBe(false)
      expect(w.get('[data-test="scopable-capability-access_policy_override"]').text()).toBe(tag)
      expect(w.find('[data-test="scopable-capability-role_assign"]').exists()).toBe(false)
    })

    it('入口的權限鍵全是可範圍化的鍵、但描述 scopable 為 false 時仍不帶標示', async () => {
      const d = scopedDescriptors()
      d.entries[1].states = [d.entries[1].states[0], { name: 'manage', keys: ['asset:view', 'asset:update'] }]
      withDescriptors(d)
      const w = await mountEditor()
      expect(w.find('[data-test="scopable-entry-users"]').exists()).toBe(false)
    })

    it('摘要的管理範圍段依伺服器兩個布林呈現三種文字', async () => {
      const cases = [
        [{}, t('roles.editor.summary.scopeAll')],
        [{ scope_node_selectable: true }, t('roles.editor.summary.scopeNodeSelectable')],
        [{ scope_mixed_global_only: true }, t('roles.editor.summary.scopeMixedGlobalOnly')],
      ]
      for (const [flags, text] of cases) {
        setup({ summary: sum({ summary: { manage: ['users'], read: [], available: [], hidden: [], scope_global_only: !Object.keys(flags).length, ...flags } }) })
        const w = await mountEditor()
        expect(w.get('[data-test="summary-scope"]').text()).toBe(text)
        w.unmount()
      }
    })

    it('有 2 筆節點範圍指派且草稿不可限定：提示含 2，儲存鈕可用並送出', async () => {
      setup({ detail: detail({ scopable: false, node_range_no_effect: false, node_scoped_binding_count: 2 }), summary: sum({ scopable: false, node_range_no_effect: false }) })
      const w = await mountEditor()
      const notice = w.get('[data-test="scope-notice-reject"]')
      expect(notice.text()).toContain(t('roles.editor.nodeScopedNotice', { n: 2 }))
      expect(w.find('[data-test="scope-notice-no-effect"]').exists()).toBe(false)
      const save = w.get('[data-test="editor-save"]')
      expect(save.attributes('disabled')).toBeUndefined()
      await save.trigger('click')
      await flushPromises()
      expect(calls('PUT', '/role-definitions/10')).toHaveLength(1)
    })

    it('草稿變成範圍不會生效：改顯示含 2 的另一句提示，不顯示前一句，仍可儲存', async () => {
      setup({ detail: detail({ scopable: true, node_range_no_effect: false, node_scoped_binding_count: 2 }), summary: sum({ scopable: true, node_range_no_effect: false }) })
      const w = await mountEditor()
      expect(w.find('[data-test="scope-notice-reject"]').exists()).toBe(false)
      expect(w.find('[data-test="scope-notice-no-effect"]').exists()).toBe(false)
      setup({ detail: detail({ scopable: true, node_range_no_effect: false, node_scoped_binding_count: 2 }), summary: sum({ scopable: true, node_range_no_effect: true }) })
      w.unmount()
      const w2 = await mountEditor()
      await w2.get('[data-test="entry-users-hidden"]').trigger('click')
      await new Promise((r) => setTimeout(r, 350))
      await flushPromises()
      expect(w2.get('[data-test="scope-notice-no-effect"]').text()).toContain(t('roles.editor.nodeScopedNoEffectNotice', { n: 2 }))
      expect(w2.find('[data-test="scope-notice-reject"]').exists()).toBe(false)
      const save = w2.get('[data-test="editor-save"]')
      expect(save.attributes('disabled')).toBeUndefined()
      await save.trigger('click')
      await flushPromises()
      expect(calls('PUT', '/role-definitions/10')).toHaveLength(1)
    })

    it('沒有節點範圍指派時不顯示任何提示；畫面沒有節點選擇與預覽入口', async () => {
      setup({ detail: detail({ scopable: false, node_scoped_binding_count: 0 }), summary: sum({ scopable: false, node_range_no_effect: false }) })
      const w = await mountEditor()
      expect(w.find('[data-test="scope-notice-reject"]').exists()).toBe(false)
      expect(w.find('[data-test="scope-notice-no-effect"]').exists()).toBe(false)
      expect(w.findAll('[data-test*="node"], [data-test*="preview-as"]')).toHaveLength(0)
    })

    it('人選信任提示與摘要發權句三語都寫明含高風險權限點的自訂角色只限超級管理者指派', async () => {
      const marks = { 'zh-TW': ['高風險', '超級管理者'], 'en-US': ['high-risk', 'super administrator'], 'ja-JP': ['高リスク', 'スーパー管理者'] }
      for (const [loc, words] of Object.entries(marks)) {
        const d = (await import(`@/i18n/locales/${loc}.json`)).default
        for (const text of [d.roles.editor.trustHint, d.roles.summary.assignmentTrust]) {
          for (const word of words) expect(text).toContain(word)
        }
      }
    })
  })
})
