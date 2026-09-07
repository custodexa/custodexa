import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import CredentialFormDialog from '@/components/credential/CredentialFormDialog.vue'

// 共用憑證的建立／編輯對話框（憑證庫與資產表單的選擇器都開它）。
//
// 最小覆蓋，三件事：
//  1. 建立需要的必填欄位真的擋得住空值——建出一筆沒有秘密的憑證，
//     它掛上去的每一台都連不上，而畫面上看不出原因；
//  2. 送出的載荷只帶端點收的欄位（多送 auth_method 會讓端點 500）；
//  3. 編輯模式只送可改的那幾欄，且不重送秘密。

enableAutoUnmount(afterEach)

class ObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', ObserverStub)
vi.stubGlobal('ResizeObserver', ObserverStub)

const createMock = vi.fn()
const updateMock = vi.fn()
vi.mock('@/api/credentials', () => ({
  createCredential: (...a) => createMock(...a),
  updateCredential: (...a) => updateMock(...a),
}))

const dialogStub = {
  props: ['modelValue'],
  template: '<div v-if="modelValue" class="dialog-stub"><slot /><slot name="footer" /></div>',
}

// 表單狀態在 modelValue 轉為 true 時才由 credential 回填，故一律關著掛、再打開
async function mountDialog(props = {}) {
  const wrapper = mount(CredentialFormDialog, {
    global: { plugins: [ElementPlus], stubs: { 'el-dialog': dialogStub } },
    props: { modelValue: false, ...props },
  })
  await wrapper.setProps({ modelValue: true })
  await flushPromises()
  return wrapper
}

beforeEach(() => {
  vi.clearAllMocks()
  createMock.mockResolvedValue({ id: 9 })
  updateMock.mockResolvedValue({ id: 9 })
})

describe('新增共用憑證', () => {
  it('名稱、帳號名與秘密缺一即擋在送出之前', async () => {
    const wrapper = await mountDialog()

    await wrapper.vm.submit()
    await flushPromises()
    expect(createMock).not.toHaveBeenCalled()

    wrapper.vm.form.name = '正式區 root'
    await wrapper.vm.submit()
    await flushPromises()
    expect(createMock).not.toHaveBeenCalled()

    wrapper.vm.form.username = 'root'
    await wrapper.vm.submit()
    await flushPromises()
    expect(createMock).not.toHaveBeenCalled()
  })

  it('載荷只帶端點收的欄位，且秘密依型別二擇一', async () => {
    const wrapper = await mountDialog()
    Object.assign(wrapper.vm.form, {
      name: '正式區 root',
      username: 'root',
      protocol_family: 'ssh',
      secret_type: 'password',
      password: 'p@ss',
      private_key: '不該送出去',
      note: '備註',
    })

    await wrapper.vm.submit()
    await flushPromises()

    const payload = createMock.mock.calls[0][0]
    expect(payload).toEqual({
      name: '正式區 root',
      username: 'root',
      secret_type: 'password',
      protocol_family: 'ssh',
      note: '備註',
      password: 'p@ss',
      private_key: '',
    })
    // 端點不收認證類型，帶上去會 500
    expect('auth_method' in payload).toBe(false)
    expect(wrapper.emitted('saved')).toHaveLength(1)
  })
})

describe('編輯憑證', () => {
  it('只送可改的欄位（共用改名、專用改帳號名），不重送秘密', async () => {
    const wrapper = await mountDialog({
      credential: {
        id: 9, name: '正式區 root', scope: 'shared', username: 'root',
        secret_type: 'password', protocol_family: 'ssh', note: '',
      },
    })
    wrapper.vm.form.name = '正式區 root（新）'
    wrapper.vm.form.note = '改過'

    await wrapper.vm.submit()
    await flushPromises()

    expect(updateMock).toHaveBeenCalledWith(9, { note: '改過', name: '正式區 root（新）' })
    expect(createMock).not.toHaveBeenCalled()
  })
})
