import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import UserRoleScopeTab from '../components/UserRoleScopeTab.vue'
import { ElDialogStub } from '@/__fixtures__/dialogStub'
import i18n from '@/i18n'

enableAutoUnmount(afterEach)

const h = vi.hoisted(() => ({ request: vi.fn() }))

vi.mock('@/api/request', () => ({ default: (...a) => h.request(...a) }))
vi.mock('vue-router', () => ({
  useRoute: () => ({ params: {}, query: {} }),
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
}))

const defs = [
  { id: 1, name: 'user', assignment_state: 'open', management_class: false },
  { id: 5, name: 'asset_admin', assignment_state: 'open', management_class: true },
  { id: 9, name: 'authz_admin', assignment_state: 'open', management_class: true },
  { id: 12, name: 'cred_admin', assignment_state: 'open', management_class: true },
]
const noOp = { marks: [], self_direction: '', routes_gained: [], routes_lost: [], evaluated: 0 }
const roleRef = (id, name, key) => ({ role_id: id, name, builtin_key: key })
const ASSET = roleRef(5, '資產管理員', 'asset_admin')
const AUTHZ = roleRef(9, '授權管理員', 'authz_admin')

let preview
// tokens：這個帳號的 API token 清單（GET /users/:id/api-tokens）；傳 'fail' 模擬讀不到
const setup = (apiTokens, tokens = []) => {
  preview = { total: 0, matched: 0, truncated: false, subjects: [], operation: noOp, ...(apiTokens ? { api_tokens: apiTokens } : {}) }
  h.request.mockImplementation(async (c) => {
    const key = `${c.method.toUpperCase()} ${c.url}`
    if (key === 'GET /role-definitions') return { data: defs, total: defs.length, can_define: false }
    if (key === 'GET /user-groups') return { data: [] }
    if (key === 'GET /users/57/role-bindings') return { data: [] }
    if (key === 'GET /users/57/api-tokens') {
      if (tokens === 'fail') throw new Error('token list down')
      return { data: tokens, can_revoke: true, protected: false, account_active: true }
    }
    if (key === 'POST /role-assignment-previews') return preview
    throw new Error(`unexpected request ${key}`)
  })
}
const tokenRow = (id, name, granted, status = 'active') => ({ id, name, status, granted_roles: granted })
const granted = (ref, effective) => ({ ...ref, scope: { kind: 'all' }, effective })

const mountTab = async (manual = ['user', 'asset_admin', 'authz_admin']) => {
  const w = mount(UserRoleScopeTab, {
    props: { userId: 57, username: 'ops-chen', roleSets: { manual, mapped: [] } },
    global: { plugins: [ElementPlus], stubs: { ElDialog: ElDialogStub } },
  })
  await flushPromises()
  return w
}
const settle = async () => {
  await new Promise((r) => setTimeout(r, 500))
  await flushPromises()
}

beforeEach(() => {
  h.request.mockReset()
  i18n.global.locale.value = 'zh-TW'
})

describe('角色變動對 API token 的影響提示', () => {
  it('取消勾選的角色以「將移除」列出，儲存前不從畫面消失', async () => {
    setup(null)
    const w = await mountTab()
    await w.get('[data-test="remove-asset_admin"]').trigger('click')
    expect(w.find('[data-test="manual-role-asset_admin"]').exists()).toBe(false)
    expect(w.get('[data-test="pending-remove-asset_admin"]').text()).toContain('將移除')
  })

  it('收回一個角色、沒有任何一把暫停：黃框寫出受影響的名稱與剩下的角色，變化列寫幾把失去', async () => {
    setup({
      total_usable: 3,
      affected: [{ id: 2, name: 'terraform-prod-apply', loses_roles: [AUTHZ], remaining_roles: [ASSET], becomes_suspended: false }],
      suspended_count: 0,
      eligible_after: true,
    })
    const w = await mountTab()
    await w.get('[data-test="remove-authz_admin"]').trigger('click')
    await settle()
    const box = w.get('[data-test="api-token-impact-lose"]').text()
    expect(box).toContain('尚未儲存：ops-chen 的 API token 會同步失去「授權管理員」')
    expect(box).toContain('terraform-prod-apply')
    expect(box).toContain('儲存後只剩「資產管理員」')
    expect(w.get('[data-test="change-api-token-value"]').text()).toBe('1 把會失去這個角色，0 把暫停')
    expect(w.find('[data-test="change-view-api-tokens"]').exists()).toBe(true)
  })

  it('收回後有部分暫停：改用含暫停把數的說法', async () => {
    setup({
      total_usable: 3,
      affected: [
        { id: 2, name: 'terraform-prod-apply', loses_roles: [AUTHZ], remaining_roles: [ASSET], becomes_suspended: false },
        { id: 7, name: 'authz-sync', loses_roles: [AUTHZ], remaining_roles: [], becomes_suspended: true },
      ],
      suspended_count: 1,
      eligible_after: true,
    })
    const w = await mountTab()
    await w.get('[data-test="remove-authz_admin"]').trigger('click')
    await settle()
    expect(w.get('[data-test="api-token-impact-lose"]').text()).toContain('儲存後其中 1 把會暫停')
    expect(w.get('[data-test="change-api-token-value"]').text()).toBe('2 把會失去這個角色，1 把暫停')
  })

  it('收回全部管理角色：黃框說明全部暫停，變化列寫幾把將暫停', async () => {
    setup({ total_usable: 3, affected: [], suspended_count: 3, eligible_after: false })
    const w = await mountTab()
    await w.get('[data-test="remove-asset_admin"]').trigger('click')
    await w.get('[data-test="remove-authz_admin"]').trigger('click')
    await settle()
    expect(w.get('[data-test="api-token-impact-all-lost"]').text()).toContain('ops-chen 將沒有任何管理權限，名下 3 把 API token 會全部暫停')
    expect(w.get('[data-test="change-api-token-value"]').text()).toBe('3 把將暫停（角色指派回來即恢復）')
  })

  it('加上新的管理角色：藍框說明現有的不會自動得到，變化列寫不變', async () => {
    setup({ total_usable: 3, affected: [], suspended_count: 0, eligible_after: true })
    const w = await mountTab()
    w.vm.addPicked('cred_admin')
    await settle()
    const box = w.get('[data-test="api-token-impact-no-grow"]')
    const alert = w.findAllComponents({ name: 'ElAlert' }).find((c) => c.attributes('data-test') === 'api-token-impact-no-grow')
    expect(alert.props('type')).toBe('info')
    expect(box.text()).toContain('ops-chen 現有的 API token 不會自動得到')
    expect(w.get('[data-test="change-api-token-value"]').text()).toBe('不變（現有 3 把沒有勾選這個角色）')
  })

  describe('加回 token 授權過的角色', () => {
    it('預覽回報會恢復的 token：黃框點名哪幾把恢復哪個角色，不說「不會得到」，變化列不寫「不變」', async () => {
      setup({
        total_usable: 2,
        affected: [{ id: 2, name: 'tf-apply', loses_roles: [], remaining_roles: [ASSET, AUTHZ], regains_roles: [AUTHZ], becomes_suspended: false, becomes_active: false }],
        suspended_count: 0,
        eligible_after: true,
      })
      const w = await mountTab(['user', 'asset_admin'])
      w.vm.addPicked('authz_admin')
      await settle()
      const box = w.get('[data-test="api-token-impact-regain"]').text()
      expect(box).toContain('尚未儲存：ops-chen 的 API token 會恢復「授權管理員」')
      expect(box).toContain('tf-apply')
      expect(w.find('[data-test="api-token-impact-no-grow"]').exists()).toBe(false)
      expect(w.find('[data-test="api-token-impact-lose"]').exists()).toBe(false)
      const alert = w.findAllComponents({ name: 'ElAlert' }).find((c) => c.attributes('data-test') === 'api-token-impact-regain')
      expect(alert.props('type')).toBe('warning')
      expect(w.get('[data-test="change-api-token-value"]').text()).toBe('1 把會恢復這個角色')
      expect(w.find('[data-test="change-view-api-tokens"]').exists()).toBe(true)
    })

    it('原本暫停、加回後恢復可用（預覽沒有可用的 token）：點名哪幾把恢復可用', async () => {
      setup({
        total_usable: 0,
        affected: [{ id: 3, name: 'tf-plan', loses_roles: [], remaining_roles: [ASSET], regains_roles: [ASSET], becomes_suspended: false, becomes_active: true }],
        suspended_count: 0,
        eligible_after: true,
      })
      const w = await mountTab(['user'])
      w.vm.addPicked('asset_admin')
      await settle()
      const box = w.get('[data-test="api-token-impact-regain"]').text()
      expect(box).toContain('其中 1 把原本暫停，儲存後恢復為可用：tf-plan')
      expect(w.get('[data-test="change-api-token-value"]').text()).toBe('1 把會恢復這個角色，其中 1 把恢復可用')
      expect(w.get('[data-test="change-api-token-value"]').text()).not.toContain('目前沒有')
    })

    it('預覽回應還沒有恢復資訊時：依 token 清單找出授權過、目前不生效的那幾把', async () => {
      setup(
        { total_usable: 2, affected: [], suspended_count: 0, eligible_after: true },
        [tokenRow(2, 'tf-apply', [granted(ASSET, true), granted(AUTHZ, false)]), tokenRow(3, 'drift', [granted(ASSET, true)])]
      )
      const w = await mountTab(['user', 'asset_admin'])
      w.vm.addPicked('authz_admin')
      await settle()
      const box = w.get('[data-test="api-token-impact-regain"]').text()
      expect(box).toContain('tf-apply')
      expect(box).not.toContain('drift')
      expect(w.find('[data-test="api-token-impact-no-grow"]').exists()).toBe(false)
      expect(w.get('[data-test="change-api-token-value"]').text()).toBe('1 把會恢復這個角色')
    })

    it('已失效（撤銷、到期）的 token 不算會恢復', async () => {
      setup(
        { total_usable: 1, affected: [], suspended_count: 0, eligible_after: true },
        [tokenRow(4, 'old', [granted(AUTHZ, false)], 'revoked'), tokenRow(5, 'cur', [granted(ASSET, true)])]
      )
      const w = await mountTab(['user', 'asset_admin'])
      w.vm.addPicked('authz_admin')
      await settle()
      expect(w.find('[data-test="api-token-impact-regain"]').exists()).toBe(false)
      expect(w.find('[data-test="api-token-impact-no-grow"]').exists()).toBe(true)
      expect(w.get('[data-test="change-api-token-value"]').text()).toBe('不變（現有 1 把沒有勾選這個角色）')
    })

    it('token 清單讀不到、預覽也沒有恢復資訊：不斷言「不會得到」或「不變」，請儲存後確認', async () => {
      vi.spyOn(console, 'error').mockImplementation(() => {})
      setup({ total_usable: 2, affected: [], suspended_count: 0, eligible_after: true }, 'fail')
      const w = await mountTab(['user', 'asset_admin'])
      w.vm.addPicked('authz_admin')
      await settle()
      expect(w.find('[data-test="api-token-impact-no-grow"]').exists()).toBe(false)
      expect(w.get('[data-test="api-token-impact-regain-unknown"]').text()).toContain('無法確認 ops-chen 現有的 API token 是否會恢復「授權管理員」')
      expect(w.get('[data-test="change-api-token-value"]').text()).toBe('無法預先確認，儲存後請到「API token」分頁查看')
    })

    it('同時收回一個角色、加回另一個：失去與恢復兩件事都列出', async () => {
      setup({
        total_usable: 2,
        affected: [
          { id: 2, name: 'tf-apply', loses_roles: [ASSET], remaining_roles: [AUTHZ], regains_roles: [AUTHZ], becomes_suspended: false, becomes_active: false },
        ],
        suspended_count: 0,
        eligible_after: true,
      })
      const w = await mountTab(['user', 'asset_admin'])
      await w.get('[data-test="remove-asset_admin"]').trigger('click')
      w.vm.addPicked('authz_admin')
      await settle()
      expect(w.find('[data-test="api-token-impact-lose"]').exists()).toBe(true)
      expect(w.find('[data-test="api-token-impact-regain"]').exists()).toBe(true)
      expect(w.get('[data-test="change-api-token-value"]').text()).toBe('1 把會失去這個角色，0 把暫停；1 把會恢復這個角色')
    })

    it('三語都有恢復角色的文字', () => {
      for (const lang of ['zh-TW', 'en-US', 'ja-JP']) {
        for (const k of ['roles.apiTokenRegainTitle', 'roles.apiTokenRegainBody', 'roles.apiTokenRegainActive', 'roles.apiTokenRegainUnknownTitle', 'roles.apiTokenRegainUnknownBody', 'change.apiTokenRegain', 'change.apiTokenRegainActive', 'change.apiTokenCheckAfterSave', 'change.apiTokenPartsSeparator']) {
          expect(i18n.global.te(`userDetail.${k}`, lang), `${lang} ${k}`).toBe(true)
        }
      }
    })
  })

  it('原本沒有管理權限、加上第一個管理角色（預覽回應沒有 api_tokens 鍵）：不出提示框，變化列說明之後可以自己建立', async () => {
    // 後端只在對象有尚可使用的 token 時帶 api_tokens；沒有任何 token 時這個鍵不存在
    setup(null)
    const w = await mountTab(['user'])
    w.vm.addPicked('asset_admin')
    await settle()
    expect(w.find('[data-test^="api-token-impact-"]').exists()).toBe(false)
    expect(w.get('[data-test="change-api-token-value"]').text()).toBe('目前沒有。儲存後，ops-chen 可以在個人資料頁自己建立')
    expect(w.find('[data-test="change-view-api-tokens"]').exists()).toBe(false)
  })

  it('沒有 api_tokens 鍵、本人經群組已有管理角色：加上管理角色時不說「目前沒有、儲存後可以自己建立」', async () => {
    setup(null)
    const base = h.request.getMockImplementation()
    h.request.mockImplementation(async (c) => {
      const key = `${c.method.toUpperCase()} ${c.url}`
      if (key === 'GET /user-groups') return { data: [{ id: 3, name: 'ops', member_sources: [{ user_id: 57 }] }] }
      if (key === 'GET /user-groups/3/role-bindings') return { data: [{ role_id: 9, role_name: 'authz_admin', scope: 'all' }] }
      return base(c)
    })
    const w = await mountTab(['user'])
    w.vm.addPicked('asset_admin')
    await settle()
    expect(w.find('[data-test="change-api-token"]').exists()).toBe(false)
  })

  it('沒有 api_tokens 鍵且原本已有管理角色：不顯示提示也不顯示變化列', async () => {
    setup(null)
    const w = await mountTab()
    await w.get('[data-test="remove-authz_admin"]').trigger('click')
    await settle()
    expect(w.find('[data-test^="api-token-impact-"]').exists()).toBe(false)
    expect(w.find('[data-test="change-api-token"]').exists()).toBe(false)
  })

  it('沒有 api_tokens 鍵、只加上非管理角色：不顯示變化列', async () => {
    setup(null)
    const w = await mountTab(['user'])
    w.vm.addPicked('approver_like')
    await settle()
    expect(w.find('[data-test="change-api-token"]').exists()).toBe(false)
  })

  it('預覽暫時無法取得：不以猜測顯示 API token 變化列', async () => {
    setup(null)
    h.request.mockImplementation(async (c) => {
      const key = `${c.method.toUpperCase()} ${c.url}`
      if (key === 'GET /role-definitions') return { data: defs, total: defs.length, can_define: false }
      if (key === 'GET /user-groups') return { data: [] }
      if (key === 'GET /users/57/role-bindings') return { data: [] }
      if (key === 'GET /users/57/api-tokens') return { data: [] }
      throw new Error('preview down')
    })
    vi.spyOn(console, 'error').mockImplementation(() => {})
    const w = await mountTab(['user'])
    w.vm.addPicked('asset_admin')
    await settle()
    expect(w.find('[data-test="change-api-token"]').exists()).toBe(false)
  })

  it('按查看 API token：通知上層切換分頁', async () => {
    setup({ total_usable: 3, affected: [], suspended_count: 0, eligible_after: true })
    const w = await mountTab()
    await w.get('[data-test="remove-authz_admin"]').trigger('click')
    await settle()
    await w.get('[data-test="change-view-api-tokens"]').trigger('click')
    expect(w.emitted('view-api-tokens')).toHaveLength(1)
  })
})

describe('「將移除」的角色可以就地取消', () => {
  it('按取消移除：角色回到原位置、不再列為將移除，沒有其他改動時儲存鈕回到不可按', async () => {
    setup(null)
    const w = await mountTab()
    await w.get('[data-test="remove-asset_admin"]').trigger('click')
    expect(w.get('[data-test="roles-save"]').attributes('disabled')).toBeUndefined()
    const undo = w.get('[data-test="undo-remove-asset_admin"]')
    expect(undo.text()).toBe('取消移除')
    await undo.trigger('click')
    expect(w.find('[data-test="pending-remove-asset_admin"]').exists()).toBe(false)
    const order = w.findAll('[data-test^="manual-role-"]').map((n) => n.attributes('data-test'))
    expect(order).toEqual(['manual-role-user', 'manual-role-asset_admin', 'manual-role-authz_admin'])
    expect(w.get('[data-test="roles-save"]').attributes('disabled')).toBeDefined()
    expect(w.find('[data-test="change-panel"]').exists()).toBe(false)
  })

  it('同時新加入角色時取消移除：只放回被移除的那個，新加入的保留並排在後面', async () => {
    setup(null)
    const w = await mountTab()
    w.vm.addPicked('cred_admin')
    await flushPromises()
    await w.get('[data-test="remove-user"]').trigger('click')
    await w.get('[data-test="undo-remove-user"]').trigger('click')
    const order = w.findAll('[data-test^="manual-role-"]').map((n) => n.attributes('data-test'))
    expect(order).toEqual(['manual-role-user', 'manual-role-asset_admin', 'manual-role-authz_admin', 'manual-role-cred_admin'])
    expect(w.find('[data-test^="pending-remove-"]').exists()).toBe(false)
  })

  it('三語都有取消移除的文字', async () => {
    setup(null)
    const w = await mountTab()
    await w.get('[data-test="remove-asset_admin"]').trigger('click')
    for (const [locale, text] of [['en-US', 'Undo removal'], ['ja-JP', '削除を取り消す'], ['zh-TW', '取消移除']]) {
      i18n.global.locale.value = locale
      await flushPromises()
      expect(w.get('[data-test="undo-remove-asset_admin"]').text()).toBe(text)
    }
  })
})
