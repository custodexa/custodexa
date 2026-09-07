import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import CredentialDetachDialog from '@/components/credential/CredentialDetachDialog.vue'

// 單台脫離共用。
//
// 斷言重心在三件事：
//  1. 送出載荷帶 source，隨機來源另帶策略、自訂來源另帶新秘密；
//  2. 自訂來源時新秘密必填——空著送出等同把這台改成一組沒人知道的東西；
//  3. 文案要說清楚「先套用、再以新值驗證登入，通過才脫離」，
//     否則使用者無從判斷失敗時那台機器現在吃哪一組。

enableAutoUnmount(afterEach)

class ObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
  takeRecords() { return [] }
}
vi.stubGlobal('MutationObserver', ObserverStub)
vi.stubGlobal('ResizeObserver', ObserverStub)

const detachMock = vi.fn()
vi.mock('@/api/credentials', () => ({
  detachCredentialBinding: (...a) => detachMock(...a),
}))

const dialogStub = {
  props: ['modelValue'],
  template:
    '<div v-if="modelValue" class="dialog-stub"><slot /><slot name="footer" /></div>',
}

async function mountDialog(props = {}) {
  const wrapper = mount(CredentialDetachDialog, {
    global: { plugins: [ElementPlus], stubs: { 'el-dialog': dialogStub } },
    props: {
      modelValue: true,
      credentialId: 110,
      credentialName: '正式區 root',
      bindingCount: 12,
      accountId: 20113,
      assetName: 'web-01',
      username: 'root',
      ...props,
    },
  })
  await flushPromises()
  return wrapper
}

beforeEach(() => {
  vi.clearAllMocks()
  detachMock.mockResolvedValue({ data: { id: 9, status: 'completed', members: [] } })
})

describe('脫離共用對話框', () => {
  it('說明這台的去向與其餘各台不受影響，且失敗維持共用', async () => {
    const wrapper = await mountDialog()

    expect(wrapper.find('[data-test="detach-from"]').text()).toContain('正式區 root')
    expect(wrapper.find('[data-test="detach-to"]').text()).toContain('web-01')
    const intro = wrapper.find('[data-test="detach-intro"]').text()
    expect(intro).toContain('11')
    expect(intro).toContain('改密失敗時維持共用')
  })

  it('自訂來源顯示驗證步驟的說明', async () => {
    const wrapper = await mountDialog()

    wrapper.vm.form.source = 'custom'
    await flushPromises()

    expect(wrapper.find('[data-test="detach-custom-hint"]').text())
      .toContain('驗證通過才脫離')
  })

  it('隨機來源：載荷帶 source 與密碼策略', async () => {
    const wrapper = await mountDialog()

    wrapper.vm.form.password_length = 20
    wrapper.vm.form.exclude_ambiguous = false
    await wrapper.vm.submit()
    await flushPromises()

    expect(detachMock).toHaveBeenCalledTimes(1)
    const [credentialId, accountId, payload] = detachMock.mock.calls[0]
    expect(credentialId).toBe(110)
    expect(accountId).toBe(20113)
    expect(payload.source).toBe('random')
    expect(payload.policy).toEqual({
      length: 20,
      include_symbol: true,
      exclude_ambiguous: false,
    })
    expect(payload.password).toBeUndefined()
  })

  it('自訂來源時密碼欄必填：空值不送出', async () => {
    const wrapper = await mountDialog()

    wrapper.vm.form.source = 'custom'
    await flushPromises()

    await wrapper.vm.submit()
    await flushPromises()
    expect(detachMock).not.toHaveBeenCalled()
    expect(wrapper.vm.missingSecret).toBe(true)

    wrapper.vm.form.password = 'NewSecret-2026'
    await flushPromises()
    await wrapper.vm.submit()
    await flushPromises()

    expect(detachMock).toHaveBeenCalledTimes(1)
    const payload = detachMock.mock.calls[0][2]
    expect(payload.source).toBe('custom')
    expect(payload.password).toBe('NewSecret-2026')
    expect(payload.policy).toBeUndefined()
    expect(wrapper.emitted('detached')[0][0].id).toBe(9)
  })

  it('金鑰型憑證的自訂來源改為私鑰必填', async () => {
    const wrapper = await mountDialog({ secretType: 'ssh_key' })

    wrapper.vm.form.source = 'custom'
    await flushPromises()
    expect(wrapper.vm.missingSecret).toBe(true)

    wrapper.vm.form.private_key = 'test-private-key-material'
    await flushPromises()
    expect(wrapper.vm.missingSecret).toBe(false)
  })

  it('只剩一台掛載時，說明文案不提「其餘幾台」', async () => {
    const wrapper = await mountDialog({ bindingCount: 1 })

    const intro = wrapper.find('[data-test="detach-intro"]').text()
    expect(intro).toContain('成為專用憑證')
    expect(intro).not.toContain('其餘')
  })

  it('脫離後原憑證只剩一台時，說出它會轉為專用並失去名稱（不是「不受影響」）', async () => {
    const wrapper = await mountDialog({ bindingCount: 2 })

    const intro = wrapper.find('[data-test="detach-intro"]').text()
    expect(intro).toContain('正式區 root')
    expect(intro).toContain('只剩 1 台')
    expect(intro).toContain('轉為那台的專用憑證')
    expect(intro).toContain('名稱')
    // 那台主機的密碼確實沒被動，但整筆憑證會從共用清單消失——不能用「不受影響」概括
    expect(intro).not.toContain('不受影響')

    // 三台以上仍是原本那句
    const many = await mountDialog({ bindingCount: 3 })
    const manyIntro = many.find('[data-test="detach-intro"]').text()
    expect(manyIntro).toContain('其餘 2 台不受影響')
  })

  it('副標寫出正在動哪一台的哪個帳號（標題只說得出動作）', async () => {
    const wrapper = await mountDialog()

    const subject = wrapper.find('[data-test="detach-subject"]')
    expect(subject.exists()).toBe(true)
    expect(subject.text()).toBe('web-01 · root')
  })
})
