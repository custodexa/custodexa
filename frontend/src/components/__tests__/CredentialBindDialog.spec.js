import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import CredentialBindDialog from '@/components/credential/CredentialBindDialog.vue'

// 把共用憑證掛到一台資產上。
//
// 最小覆蓋，三件事：
//  1. 開啟即載入可掛的資產清單；
//  2. 沒選資產擋在送出之前（送出去只會被端點以缺參數拒絕，畫面上像是沒反應）；
//  3. 送出的載荷帶資產識別與兩個旗標——掛載對主機零寫入，故載荷裡不該有任何秘密。

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

const bindMock = vi.fn()
vi.mock('@/api/credentials', () => ({
  bindCredential: (...a) => bindMock(...a),
}))

const getAssetListMock = vi.fn()
vi.mock('@/api/assets', () => ({
  getAssetList: (...a) => getAssetListMock(...a),
}))

const dialogStub = {
  props: ['modelValue'],
  template: '<div v-if="modelValue" class="dialog-stub"><slot /><slot name="footer" /></div>',
}

async function mountDialog(props = {}) {
  const wrapper = mount(CredentialBindDialog, {
    global: { plugins: [ElementPlus], stubs: { 'el-dialog': dialogStub } },
    props: { modelValue: false, credentialId: 110, ...props },
  })
  await wrapper.setProps({ modelValue: true })
  await flushPromises()
  return wrapper
}

beforeEach(() => {
  vi.clearAllMocks()
  getAssetListMock.mockResolvedValue({
    data: [{ id: 2, name: 'ssh-multi-test', protocol: 'ssh' }],
    total: 1,
  })
  bindMock.mockResolvedValue({ id: 21 })
})

describe('掛到資產', () => {
  it('開啟即載入資產清單', async () => {
    const wrapper = await mountDialog()
    expect(getAssetListMock).toHaveBeenCalledWith({ page: 1, page_size: 200 })
    expect(wrapper.vm.assets).toHaveLength(1)
  })

  it('沒選資產擋在送出之前', async () => {
    const wrapper = await mountDialog()
    await wrapper.vm.submit()
    await flushPromises()
    expect(bindMock).not.toHaveBeenCalled()
  })

  it('載荷帶資產與兩個旗標，且不含任何秘密（掛載對主機零寫入）', async () => {
    const wrapper = await mountDialog()
    Object.assign(wrapper.vm.form, {
      asset_id: 2,
      is_default: true,
      privileged: true,
      note: '正式區',
    })

    await wrapper.vm.submit()
    await flushPromises()

    expect(bindMock).toHaveBeenCalledWith(110, {
      asset_id: 2,
      is_default: true,
      privileged: true,
      note: '正式區',
    })
    const payload = bindMock.mock.calls[0][1]
    expect('password' in payload).toBe(false)
    expect('private_key' in payload).toBe(false)
    expect(wrapper.emitted('bound')).toHaveLength(1)
  })
})
