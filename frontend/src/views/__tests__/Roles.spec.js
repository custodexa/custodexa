import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import Roles from '../Roles.vue'
import { ElDialogStub } from '@/__fixtures__/dialogStub'
import i18n from '@/i18n'

enableAutoUnmount(afterEach)

// happy-dom 的 MutationObserver 與 el-table key-render-helper 不相容
class MutationObserverStub {
  observe() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', MutationObserverStub)

const api = vi.hoisted(() => ({
  listRoleDefinitions: vi.fn(),
  copyRoleDefinition: vi.fn(),
  deleteRoleDefinition: vi.fn(),
  confirmDestructive: vi.fn(),
  push: vi.fn(),
}))

vi.mock('@/api/roleDefinitions', async (orig) => ({
  ...(await orig()),
  listRoleDefinitions: (...a) => api.listRoleDefinitions(...a),
  copyRoleDefinition: (...a) => api.copyRoleDefinition(...a),
  deleteRoleDefinition: (...a) => api.deleteRoleDefinition(...a),
}))
vi.mock('@/utils/confirm', () => ({ confirmDestructive: (...a) => api.confirmDestructive(...a) }))
vi.mock('vue-router', () => ({ useRouter: () => ({ push: api.push }) }))

const t = (k, p) => i18n.global.t(k, p)
const noRefs = { direct: 0, group_bindings: 0, mapping_rules: 0 }
const row = (over) => ({
  id: 1,
  name: 'x',
  description: '',
  builtin_key: null,
  locked: false,
  definition_version: 3,
  template_role_id: null,
  summary: { manage: [], read: [], available: [], hidden: ['assets'] },
  assignment_state: 'open',
  user_count: 0,
  references: noRefs,
  ...over,
})

const fixture = (canDefine = true, summaryOverride) => ({
  can_define: canDefine,
  total: 7,
  data: [
    row({ id: 1, name: 'admin', builtin_key: 'super_admin', locked: true, user_count: 2, summary: { manage: ['assets', 'users'], read: [], available: [], hidden: [] } }),
    row({ id: 2, name: 'approver', builtin_key: 'approver', locked: true }),
    row({ id: 3, name: 'user', builtin_key: 'user', locked: true }),
    row({ id: 4, name: 'identity_admin', builtin_key: 'identity_admin', locked: true }),
    row({ id: 10, name: 'ops-custom', definition_version: 5, template_role_id: 4, summary: summaryOverride || { manage: ['users'], read: ['assets'], available: [], hidden: [] } }),
    row({ id: 11, name: 'mapped-only', user_count: 0, references: { direct: 0, group_bindings: 0, mapping_rules: 1 } }),
    row({ id: 12, name: 'held', user_count: 2, references: { direct: 2, group_bindings: 1, mapping_rules: 0 } }),
  ],
})

const mountView = () =>
  mount(Roles, { global: { plugins: [ElementPlus], stubs: { ElDialog: ElDialogStub } } })

const load = async (data) => {
  api.listRoleDefinitions.mockResolvedValue(data)
  const w = mountView()
  await flushPromises()
  return w
}

describe('Roles 角色列表', () => {
  beforeEach(() => {
    Object.values(api).forEach((m) => m.mockReset())
  })

  it('內建與自訂兩區依回應分開，數量取自回應', async () => {
    const w = await load(fixture())
    expect(w.get('[data-test="roles-section-builtin"]').text()).toContain(t('roles.list.builtinTitle', { n: 4 }))
    expect(w.get('[data-test="roles-section-custom"]').text()).toContain(t('roles.list.customTitle', { n: 3 }))
    expect(w.get('[data-test="roles-section-custom"]').text()).toContain('ops-custom')
    expect(w.get('[data-test="roles-section-builtin"]').text()).not.toContain('ops-custom')
  })

  it('摘要出現「部分管理：資產管理」，且排在可檢視之前', async () => {
    const w = await load(fixture(true, { manage: [], partial: ['assets'], read: ['sessions'], available: [], hidden: [] }))
    const text = w.get('[data-test="role-summary-10"]').text()
    const partialLine = `${t('roles.summary.partial')}：${t('roles.editor.entry.assets')}`
    expect(text).toContain(partialLine)
    expect(text.indexOf(partialLine)).toBeLessThan(text.indexOf(`${t('roles.summary.read')}：`))
  })

  it('可用的功能欄由 summary 產生：改 summary 即改變顯示，改角色名不改變', async () => {
    const w1 = await load(fixture())
    const base = w1.get('[data-test="role-summary-10"]').text()
    expect(base).toContain(t('roles.editor.entry.users'))

    const renamed = fixture()
    renamed.data[4].name = 'renamed-role'
    const w2 = await load(renamed)
    expect(w2.get('[data-test="role-summary-10"]').text()).toBe(base)

    const w3 = await load(fixture(true, { manage: ['alerts'], read: [], available: [], hidden: [] }))
    const changed = w3.get('[data-test="role-summary-10"]').text()
    expect(changed).not.toBe(base)
    expect(changed).toContain(t('roles.editor.entry.alerts'))
  })

  it('操作：超管列只有檢視、其他內建列可作範本、自訂列有編輯複製刪除', async () => {
    const w = await load(fixture())
    expect(w.find('[data-test="role-view-1"]').exists()).toBe(true)
    expect(w.find('[data-test="role-template-1"]').exists()).toBe(false)
    expect(w.find('[data-test="role-template-2"]').exists()).toBe(true)
    expect(w.find('[data-test="role-edit-10"]').exists()).toBe(true)
    expect(w.find('[data-test="role-copy-10"]').exists()).toBe(true)
    expect(w.find('[data-test="role-delete-10"]').exists()).toBe(true)
    expect(w.find('[data-test="roles-create"]').exists()).toBe(true)
  })

  it('can_define 為假時只剩檢視，沒有新增鈕並說明', async () => {
    const w = await load(fixture(false))
    expect(w.find('[data-test="roles-create"]').exists()).toBe(false)
    expect(w.get('[data-test="roles-view-only"]').text()).toBe(t('roles.list.viewOnlyNote'))
    for (const id of [1, 2, 10]) {
      expect(w.find(`[data-test="role-view-${id}"]`).exists()).toBe(true)
    }
    expect(w.find('[data-test="role-template-2"]').exists()).toBe(false)
    expect(w.find('[data-test="role-edit-10"]').exists()).toBe(false)
    expect(w.find('[data-test="role-copy-10"]').exists()).toBe(false)
    expect(w.find('[data-test="role-delete-10"]').exists()).toBe(false)
  })

  it('審核人員列的「可用的功能」寫出核准連線申請，不顯示未授予', async () => {
    const w = await load(fixture())
    const text = w.get('[data-test="role-summary-2"]').text()
    expect(text).toContain(t('roles.list.approverAbility'))
    expect(text).not.toContain(t('roles.summary.hidden'))
    expect(w.get('[data-test="role-summary-3"]').text()).toContain(t('roles.summary.hidden'))
  })

  it('內建管理類角色列顯示中文名，不露原始鍵', async () => {
    const w = await load(fixture())
    const text = w.text()
    expect(text).toContain('身分管理員')
    expect(text).not.toContain('identity_admin')
  })

  it('範本選項不含超管；管理範圍欄為三值之一', async () => {
    const w = await load(fixture())
    expect(w.vm.templateOptions.map((r) => r.id)).toEqual([2, 3, 4])
    expect(w.get('[data-test="role-scope-1"]').text()).toBe(t('roles.list.scopeGlobal'))
    expect(w.get('[data-test="role-scope-2"]').text()).toBe(t('roles.list.scopeByReviewer'))
    expect(w.get('[data-test="role-scope-3"]').text()).toBe(t('roles.list.scopeNotApplicable'))
    expect(w.get('[data-test="role-users-1"]').text()).toBe('2')
  })

  it('任何引用大於 0 即停用刪除並列出三種引用數；沒有使用者但有映射規則仍停用', async () => {
    const w = await load(fixture())
    for (const id of [11, 12]) {
      expect(w.get(`[data-test="role-delete-${id}"]`).attributes('disabled')).toBeDefined()
    }
    const held = w.get('[data-test="role-in-use-12"]').text()
    expect(held).toContain(t('roles.list.inUse.direct', { n: 2 }))
    expect(held).toContain(t('roles.list.inUse.groups', { n: 1 }))
    expect(held).toContain(t('roles.list.inUse.mappings', { n: 0 }))
    const mapped = w.get('[data-test="role-in-use-11"]').text()
    expect(mapped).toContain(t('roles.list.inUse.mappings', { n: 1 }))
    expect(mapped).toContain(t('roles.list.inUse.hint.mappings'))
    expect(w.get('[data-test="role-delete-10"]').attributes('disabled')).toBeUndefined()
    await w.get('[data-test="role-delete-11"]').trigger('click')
    expect(api.confirmDestructive).not.toHaveBeenCalled()
  })

  it('全為 0 時刪除經 confirmDestructive 並帶期望版本', async () => {
    api.confirmDestructive.mockResolvedValue(undefined)
    api.deleteRoleDefinition.mockResolvedValue({})
    const w = await load(fixture())
    await w.get('[data-test="role-delete-10"]').trigger('click')
    await flushPromises()
    expect(api.confirmDestructive).toHaveBeenCalledTimes(1)
    expect(api.deleteRoleDefinition).toHaveBeenCalledWith(10, 5)
    expect(api.listRoleDefinitions).toHaveBeenCalledTimes(2)
  })

  it('取消破壞性確認時不送出刪除', async () => {
    api.confirmDestructive.mockRejectedValue('cancel')
    const w = await load(fixture())
    await w.get('[data-test="role-delete-10"]').trigger('click')
    await flushPromises()
    expect(api.deleteRoleDefinition).not.toHaveBeenCalled()
  })

  it('伺服器回使用中：顯示引用說明並重新載入', async () => {
    api.confirmDestructive.mockResolvedValue(undefined)
    api.deleteRoleDefinition.mockRejectedValue({ response: { status: 409, data: { error: { code: 'ROLE_DEFINITION_IN_USE' } } } })
    const w = await load(fixture())
    await w.get('[data-test="role-delete-10"]').trigger('click')
    await flushPromises()
    const dlg = w.get('[data-test="role-in-use-conflict"]')
    expect(dlg.text()).toContain(t('roles.list.inUse.conflictTitle', { name: 'ops-custom' }))
    expect(dlg.text()).toContain(t('roles.list.inUse.conflictBody'))
    expect(api.listRoleDefinitions).toHaveBeenCalledTimes(2)
  })

  it('新增對話框以範本起手，下一步導向編輯頁並帶範本 ID', async () => {
    const w = await load(fixture())
    await w.get('[data-test="role-template-2"]').trigger('click')
    await w.get('input[data-test="role-create-name"]').setValue('新角色')
    await w.get('[data-test="role-create-next"]').trigger('click')
    expect(api.push).toHaveBeenCalledWith({ path: '/roles/new', query: { name: '新角色', template: '2' } })
  })

  it('複製送出新名稱並重新載入', async () => {
    api.copyRoleDefinition.mockResolvedValue({})
    const w = await load(fixture())
    await w.get('[data-test="role-copy-10"]').trigger('click')
    await w.get('input[data-test="role-copy-name"]').setValue('ops-copy')
    await w.get('[data-test="role-copy-submit"]').trigger('click')
    await flushPromises()
    expect(api.copyRoleDefinition).toHaveBeenCalledWith(10, 'ops-copy')
    expect(api.listRoleDefinitions).toHaveBeenCalledTimes(2)
  })

  it('說明文案取自巢狀鍵：新文案，三語非空', async () => {
    const zh = (await import('@/i18n/locales/zh-TW.json')).default
    expect(zh.roles.tipBody).toBeTruthy()
    expect(zh.roles.tipBody).not.toContain('固定角色')
    expect(zh.roles.tipBody).not.toContain('不支援新增或刪除')
    expect(zh.roles.headerDesc).toBe('角色決定一個人在後台看得到哪些頁面、能改哪些資料。能連線到哪些主機，由資產授權決定。')
    for (const loc of ['en-US', 'ja-JP']) {
      const d = (await import(`@/i18n/locales/${loc}.json`)).default
      expect(d.roles.tipBody.length).toBeGreaterThan(0)
      expect(d.roles.headerDesc.length).toBeGreaterThan(0)
    }
  })

  describe('管理範圍欄與範本', () => {
    const scopedFixture = () => {
      const base = fixture()
      base.data.push(
        row({ id: 5, name: 'asset_admin', builtin_key: 'asset_admin', locked: true, scopable: true, node_range_no_effect: false }),
        row({ id: 6, name: 'authz_admin', builtin_key: 'authz_admin', locked: true, scopable: true, node_range_no_effect: false }),
        row({ id: 30, name: 'custom-scopable', scopable: true, node_range_no_effect: false }),
        row({ id: 31, name: 'custom-global', scopable: false, node_range_no_effect: false }),
        row({ id: 32, name: 'custom-no-effect', scopable: true, node_range_no_effect: true }),
      )
      // 一般使用者與審核人員：伺服器回可限定但範圍不生效，欄位仍依內建分類
      base.data[1] = { ...base.data[1], scopable: true, node_range_no_effect: true }
      base.data[2] = { ...base.data[2], scopable: true, node_range_no_effect: true }
      return base
    }
    const at = t('roles.list.scopeAtAssignment')

    it('可限定且範圍會生效的內建列與自訂列顯示「指派時選節點」，其餘依伺服器值', async () => {
      const w = await load(scopedFixture())
      expect(w.get('[data-test="role-scope-5"]').text()).toBe(at)
      expect(w.get('[data-test="role-scope-6"]').text()).toBe(at)
      expect(w.get('[data-test="role-scope-30"]').text()).toBe(at)
      expect(w.get('[data-test="role-scope-31"]').text()).toBe(t('roles.list.scopeGlobal'))
      expect(w.get('[data-test="role-scope-32"]').text()).toBe(t('roles.list.scopeGlobal'))
    })

    it('一般使用者與審核人員依內建分類，即使回應可限定也不顯示「指派時選節點」', async () => {
      const w = await load(scopedFixture())
      expect(w.get('[data-test="role-scope-2"]').text()).toBe(t('roles.list.scopeByReviewer'))
      expect(w.get('[data-test="role-scope-3"]').text()).toBe(t('roles.list.scopeNotApplicable'))
      expect(w.get('[data-test="role-scope-1"]').text()).toBe(t('roles.list.scopeGlobal'))
    })

    it('只含可範圍化鍵的自訂角色，回應不可限定時仍顯示全系統（不在前端推算）', async () => {
      const data = scopedFixture()
      data.data.push(row({ id: 33, name: 'only-scopable-keys', scopable: false, node_range_no_effect: false, permissions: ['asset:view', 'asset:update'] }))
      const w = await load(data)
      expect(w.get('[data-test="role-scope-33"]').text()).toBe(t('roles.list.scopeGlobal'))
    })

    it('兩個範本列只有檢視與以此為範本新增，沒有編輯、複製、刪除', async () => {
      const w = await load(scopedFixture())
      for (const id of [5, 6]) {
        expect(w.find(`[data-test="role-view-${id}"]`).exists()).toBe(true)
        expect(w.find(`[data-test="role-template-${id}"]`).exists()).toBe(true)
        for (const k of ['edit', 'copy', 'delete']) expect(w.find(`[data-test="role-${k}-${id}"]`).exists()).toBe(false)
      }
      expect(w.get('[data-test="roles-section-builtin"]').text()).toContain(t('enum.role.asset_admin.label'))
      expect(w.get('[data-test="roles-section-builtin"]').text()).toContain(t('enum.role.authz_admin.label'))
      expect(w.get('[data-test="roles-section-builtin"]').text()).not.toContain('asset_admin')
    })

    it('新增對話框的起手範本含兩個範本、不含超管，且可帶範本進編輯頁', async () => {
      const w = await load(scopedFixture())
      expect(w.vm.templateOptions.map((r) => r.id)).toEqual([2, 3, 4, 5, 6])
      await w.get('[data-test="role-template-5"]').trigger('click')
      await w.get('input[data-test="role-create-name"]').setValue('我的資產管理')
      await w.get('[data-test="role-create-next"]').trigger('click')
      expect(api.push).toHaveBeenCalledWith({ path: '/roles/new', query: { name: '我的資產管理', template: '5' } })
    })
  })
})
