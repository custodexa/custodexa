import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import DangerComboConfirm from '../DangerComboConfirm.vue'
import { needsDangerConfirm } from '@/utils/dangerCombo'
import { useAssignmentPreview } from '@/composables/useAssignmentPreview'
import { previewDisabledMapping } from '@/__fixtures__/rolePreviews'
import { ElDialogStub } from '@/__fixtures__/dialogStub'
import i18n from '@/i18n'

enableAutoUnmount(afterEach)

const apiMock = vi.hoisted(() => ({ previewRoleAssignment: vi.fn() }))
vi.mock('@/api/roleDefinitions', () => ({
  previewRoleAssignment: (...a) => apiMock.previewRoleAssignment(...a),
}))

const t = (k, p) => i18n.global.t(k, p)

const op = (over = {}) => ({
  marks: [],
  self_direction: '',
  routes_gained: [],
  routes_lost: [],
  evaluated: 2,
  ...over,
})

const comboPreview = () => ({
  total: 2,
  matched: 2,
  truncated: false,
  subjects: [
    { user_id: 7, self: true, new_combos: ['identity_with_security'], combos: ['identity_with_security'] },
    { user_id: 9, self: false, new_combos: ['identity_with_security'], combos: ['identity_with_security'] },
  ],
  operation: op({ marks: ['management_grant'] }),
})

const mountConfirm = (props = {}) =>
  mount(DangerComboConfirm, {
    props: { modelValue: true, ...props },
    global: { plugins: [ElementPlus], stubs: { ElDialog: ElDialogStub } },
  })

describe('DangerComboConfirm', () => {
  beforeEach(() => apiMock.previewRoleAssignment.mockReset())

  it('列出組合碼對應文案與總數，名稱只出現在已載入的主體', () => {
    const w = mountConfirm({
      preview: comboPreview(),
      knownSubjects: [{ user_id: 7, name: 'alice-self' }],
    })
    const text = w.text()
    expect(text).toContain(t('dangerConfirm.title', { n: 1 }))
    expect(text).toContain(t('roles.dangerCombo.identity_with_security'))
    expect(text).toContain(t('dangerConfirm.affectedTotal', { n: 2 }))
    expect(w.get('[data-test="danger-combo-names"]').text()).toBe('alice-self')
    expect(text).not.toContain('user 9')
  })

  it('沒有主體但 operation.marks 含 management_grant：判定需確認並顯示會通知安全人員', () => {
    expect(needsDangerConfirm(previewDisabledMapping)).toBe(true)
    const w = mountConfirm({ preview: previewDisabledMapping })
    expect(w.get('[data-test="danger-notify"]').text()).toContain(t('dangerConfirm.notify.title'))
    expect(w.text()).toContain(t('dangerConfirm.notBlockingZero'))
  })

  it('total 為 0 而 marks 非空時同樣需要確認', () => {
    const p = { total: 0, subjects: [], operation: op({ marks: ['management_grant'], evaluated: 0 }) }
    expect(needsDangerConfirm(p)).toBe(true)
  })

  it('沒有組合且 marks 為空：不需要確認', () => {
    const p = { total: 3, subjects: [{ user_id: 1, new_combos: [] }], operation: op() }
    expect(needsDangerConfirm(p)).toBe(false)
    expect(needsDangerConfirm(null)).toBe(false)
  })

  it('evaluated 小於 total：顯示只求值部分', () => {
    const p = { ...comboPreview(), total: 30, operation: op({ marks: ['management_grant'], evaluated: 5 }) }
    const w = mountConfirm({ preview: p })
    expect(w.get('[data-test="danger-evaluated-partial"]').text()).toBe(
      t('dangerConfirm.evaluatedPartial', { total: 30, evaluated: 5 }),
    )
  })

  it('自我授權分類：增減皆會通知', () => {
    for (const dir of ['increase', 'decrease']) {
      const p = { total: 1, subjects: [], operation: op({ marks: ['self_authorization'], self_direction: dir }) }
      const w = mountConfirm({ preview: p })
      expect(w.get('[data-test="danger-notify"]').text()).toContain(t('dangerConfirm.notify.selfChange'))
    }
  })

  it('「仍要儲存」才觸發寫入回呼，「返回修改」不觸發', async () => {
    const onConfirm = vi.fn()
    const onBack = vi.fn()
    const w = mountConfirm({ preview: comboPreview(), onConfirm, onBack })
    await w.get('[data-test="danger-back"]').trigger('click')
    expect(onBack).toHaveBeenCalledTimes(1)
    expect(onConfirm).not.toHaveBeenCalled()
    await w.get('[data-test="danger-proceed"]').trigger('click')
    expect(onConfirm).toHaveBeenCalledTimes(1)
  })

  it('預覽失敗：顯示暫時無法取得且仍可儲存', async () => {
    const onConfirm = vi.fn()
    const w = mountConfirm({ unavailable: true, onConfirm })
    expect(w.text()).toContain(t('dangerConfirm.previewFailed.title'))
    expect(w.text()).toContain(t('dangerConfirm.previewFailed.hint'))
    await w.get('[data-test="danger-proceed"]').trigger('click')
    expect(onConfirm).toHaveBeenCalledTimes(1)
  })

  it('組合與分類只來自預覽回應：元件不接收角色或權限清單', () => {
    const names = Object.keys(DangerComboConfirm.props)
    expect(names.filter((n) => /role|perm/i.test(n))).toEqual([])
  })
})

describe('useAssignmentPreview latest-request-wins', () => {
  it('舊回應晚到時採較晚請求的結果', async () => {
    let resolveFirst
    apiMock.previewRoleAssignment
      .mockImplementationOnce(() => new Promise((r) => { resolveFirst = r }))
      .mockResolvedValueOnce({ total: 2, subjects: [], operation: op() })
    let api
    const Host = {
      template: '<div />',
      setup() {
        api = useAssignmentPreview({ debounceMs: 0 })
        return {}
      },
    }
    mount(Host)
    const first = api.run({ kind: 'role_definition', role_id: 1, permissions: ['a'] })
    const second = api.run({ kind: 'role_definition', role_id: 1, permissions: ['b'] })
    await second
    resolveFirst({ total: 99, subjects: [], operation: op() })
    await first
    await flushPromises()
    expect(api.result.value.total).toBe(2)
    expect(api.status.value).toBe('ok')
  })

  it('失敗與 403 一律為暫時無法取得且不丟例外', async () => {
    apiMock.previewRoleAssignment.mockRejectedValueOnce({ response: { status: 403 } })
    let api
    mount({ template: '<div />', setup() { api = useAssignmentPreview(); return {} } })
    const out = await api.run({ kind: 'role_definition' })
    expect(out.ok).toBe(false)
    expect(api.status.value).toBe('unavailable')
  })
})
