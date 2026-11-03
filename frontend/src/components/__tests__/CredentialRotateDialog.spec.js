import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import CredentialRotateDialog from '@/components/credential/CredentialRotateDialog.vue'
import CredentialDetailPanel from '@/components/credential/CredentialDetailPanel.vue'
import ExecutorNoticeBox from '@/components/asset/ExecutorNoticeBox.vue'

// 共用憑證的改密對話框。
//
// 斷言重心在兩件事：
//  1. 送出的載荷就是畫面上選的那一組（模式＋密碼策略三欄）——策略靜默走預設，
//     等於管理員以為勾了符號、實際沒有；
//  2. 「每台各自隨機」會解除共用且不可復原，該後果必須在選中時就出現，
//     不是送出後才說。

enableAutoUnmount(afterEach)

class ObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
  takeRecords() { return [] }
}
vi.stubGlobal('MutationObserver', ObserverStub)
vi.stubGlobal('ResizeObserver', ObserverStub)

const startMock = vi.fn()
const impactMock = vi.fn()
vi.mock('@/api/credentials', async (importOriginal) => ({
  ...(await importOriginal()),
  startCredentialRotation: (...a) => startMock(...a),
  confirmCredentialImpact: (...a) => impactMock(...a),
}))

// 對話框預設 teleport 到 body，掛載樹上找不到；以就地渲染的替身取代
const dialogStub = {
  props: ['modelValue'],
  template:
    '<div v-if="modelValue" class="dialog-stub"><slot /><slot name="footer" /></div>',
}

async function mountDialog(props = {}) {
  const wrapper = mount(CredentialRotateDialog, {
    global: { plugins: [ElementPlus], stubs: { 'el-dialog': dialogStub } },
    props: {
      modelValue: true,
      credentialId: 110,
      credentialName: '正式區 root',
      bindingCount: 12,
      ...props,
    },
  })
  await flushPromises()
  return wrapper
}

beforeEach(() => {
  vi.clearAllMocks()
  startMock.mockResolvedValue({ data: { id: 7, status: 'running', members: [] } })
  impactMock.mockResolvedValue({ required: false, in_scope_count: 3 })
})

describe('改密對話框', () => {
  it('預設整組一起換，摘要說明逐台執行與驗證', async () => {
    const wrapper = await mountDialog()

    expect(wrapper.vm.form.mode).toBe('group')
    expect(wrapper.find('[data-test="rotate-summary"]').text()).toContain('12')
    expect(wrapper.find('[data-test="rotate-summary"]').text()).toContain('單台失敗不影響其他台')
    // 整組模式不出現解除共用的警語
    expect(wrapper.find('[data-test="split-warning"]').exists()).toBe(false)
  })

  it('選「每台各自隨機」即出現不可復原的提示', async () => {
    const wrapper = await mountDialog()

    wrapper.vm.form.mode = 'split'
    await flushPromises()

    const warning = wrapper.find('[data-test="split-warning"]')
    expect(warning.exists()).toBe(true)
    expect(warning.text()).toContain('此操作無法復原')
    expect(warning.text()).toContain('正式區 root')
  })

  it('送出載荷帶 mode 與密碼策略三欄', async () => {
    const wrapper = await mountDialog()

    wrapper.vm.form.mode = 'split'
    wrapper.vm.form.password_length = 24
    wrapper.vm.form.include_symbol = false
    await flushPromises()

    await wrapper.vm.submit()
    await flushPromises()

    expect(startMock).toHaveBeenCalledTimes(1)
    const [id, payload] = startMock.mock.calls[0]
    expect(id).toBe(110)
    expect(payload.mode).toBe('split')
    expect(payload.policy).toEqual({
      length: 24,
      include_symbol: false,
      exclude_ambiguous: true,
    })

    // 非同步語義：送出即關閉，進度由詳情面板接手
    expect(wrapper.emitted('update:modelValue').at(-1)).toEqual([false])
    expect(wrapper.emitted('submitted')[0][0].id).toBe(7)
  })

  it('重新開啟時回到整組模式，不停在上一次選的解除共用選項', async () => {
    const wrapper = await mountDialog()

    wrapper.vm.form.mode = 'split'
    await wrapper.setProps({ modelValue: false })
    await wrapper.setProps({ modelValue: true })
    await flushPromises()

    expect(wrapper.vm.form.mode).toBe('group')
  })
})

describe('ExecutorRotateHint', () => {
  it('executorCount=0 時無提示', async () => {
    const wrapper = await mountDialog({ executorCount: 0 })
    expect(wrapper.find('[data-test="rotate-executor-hint"]').exists()).toBe(false)
  })

  it('executorCount=7 時標題與內文含 7 與「送到這 7 台的每一台」', async () => {
    const wrapper = await mountDialog({ executorCount: 7, bindingCount: 5, outOfScopeCount: 2 })
    const hint = wrapper.get('[data-test="rotate-executor-hint"]')
    expect(hint.text()).toContain('7 台主機的堡壘機專用帳號')
    expect(hint.text()).toContain('送到這 7 台的每一台')
  })

  it('專用帳號提示為與設定對話框同型的黃色提示框：小警示圖示、粗體標題、一般內文，不是 el-alert', async () => {
    const wrapper = await mountDialog({ executorCount: 7, bindingCount: 5, outOfScopeCount: 2 })
    const box = wrapper.findAllComponents(ExecutorNoticeBox).find((c) => c.attributes('data-test') === 'rotate-executor-hint')
    expect(box.props('tone')).toBe('warning')
    expect(box.classes()).toEqual(expect.arrayContaining(['notice-box', 'is-warning']))
    expect(box.find('.el-alert').exists()).toBe(false)
    expect(box.find('[data-test="notice-box-icon"]').exists()).toBe(true)
    const title = box.get('[data-test="notice-box-title"]')
    expect(title.element.tagName).toBe('STRONG')
    expect(title.text()).toContain('7 台主機的堡壘機專用帳號')
    expect(box.get('p').text()).toContain('送到這 7 台的每一台')
  })

  it('提示文字不含範圍外資產名稱', async () => {
    const wrapper = await mountDialog({
      executorCount: 7, bindingCount: 5, outOfScopeCount: 2,
      bindings: [{ account_id: 1, asset_id: 1, asset_name: 'web-01', username: 'root' }],
    })
    const text = wrapper.get('[data-test="rotate-executor-hint"]').text()
    expect(text).not.toContain('web-01')
    expect(text).not.toContain('範圍外資產')
  })

  it('詳情面板對範圍內 5 台加範圍外 2 台的專用帳號憑證傳入 7', async () => {
    const bindings = [1, 2, 3, 4, 5].map((n) => ({
      account_id: n, asset_id: n, asset_name: `host-${n}`, username: 'cx-exec', purpose: 'executor',
    }))
    const wrapper = mount(CredentialDetailPanel, {
      global: { plugins: [ElementPlus], stubs: { 'el-dialog': dialogStub } },
      props: {
        credential: {
          id: 40, name: 'fleet-exec', scope: 'shared', purpose: 'executor', secret_type: 'password',
          protocol_family: 'ssh', username: 'cx-exec', bindings, binding_count: 5,
          out_of_scope_asset_count: 2,
        },
      },
    })
    await flushPromises()
    expect(wrapper.getComponent(CredentialRotateDialog).props('executorCount')).toBe(7)
  })

  it('人員連線用途的憑證不傳專用帳號台數', async () => {
    const wrapper = mount(CredentialDetailPanel, {
      global: { plugins: [ElementPlus], stubs: { 'el-dialog': dialogStub } },
      props: {
        credential: {
          id: 41, name: 'ops', scope: 'shared', purpose: 'login', secret_type: 'password',
          protocol_family: 'ssh', username: 'ops', bindings: [], binding_count: 0,
        },
      },
    })
    await flushPromises()
    expect(wrapper.getComponent(CredentialRotateDialog).props('executorCount')).toBe(0)
  })
})
