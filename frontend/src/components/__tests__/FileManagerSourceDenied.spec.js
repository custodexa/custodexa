// 檔案面板收到 403 AUTH_SOURCE_NOT_ALLOWED：面板內就地說明（不留白），
// 重新載入成功後說明消失；單項操作被拒同樣標示。
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import FileManager from '../FileManager.vue'
import { listFiles, uploadFile, getTransferCapabilities } from '@/api/files'

enableAutoUnmount(afterEach)

class MutationObserverStub {
  observe() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', MutationObserverStub)

vi.mock('@/api/files', () => ({
  listFiles: vi.fn(),
  uploadFile: vi.fn(),
  downloadFile: vi.fn(),
  mkdir: vi.fn(),
  deleteFile: vi.fn(),
  getTransferCapabilities: vi.fn(),
}))

const drawerStub = {
  props: ['modelValue'],
  template: '<div v-if="modelValue" class="drawer-stub"><slot /></div>',
}

const sourceDenied = () => ({
  response: { status: 403, data: { code: 'AUTH_SOURCE_NOT_ALLOWED' } },
})

const mountManager = () =>
  mount(FileManager, {
    props: { modelValue: true, assetId: 3 },
    global: { plugins: [ElementPlus], stubs: { 'el-drawer': drawerStub } },
  })

describe('FileManager 來源網段拒絕', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    getTransferCapabilities.mockResolvedValue({
      capabilities: {
        clipboard_send: true,
        clipboard_recv: true,
        file_upload: true,
        file_download: true,
        file_delete: true,
      },
    })
  })

  it('開啟面板列目錄被拒：顯示說明，重新載入成功後消失', async () => {
    listFiles.mockRejectedValueOnce(sourceDenied())
    const wrapper = mountManager()
    await wrapper.vm.refresh()
    await flushPromises()
    expect(wrapper.find('[data-test="source-denied"]').exists()).toBe(true)

    listFiles.mockResolvedValueOnce({ entries: [] })
    await wrapper.vm.refresh()
    await flushPromises()
    expect(wrapper.find('[data-test="source-denied"]').exists()).toBe(false)
  })

  it('面板開著時單項操作被拒：標示來源網段說明', async () => {
    listFiles.mockResolvedValue({ entries: [] })
    uploadFile.mockRejectedValue(sourceDenied())
    const wrapper = mountManager()
    await wrapper.vm.refresh()
    await flushPromises()
    expect(wrapper.find('[data-test="source-denied"]').exists()).toBe(false)

    await wrapper.vm.handleUpload({ file: new File(['a'], 'a.txt') })
    await flushPromises()
    expect(wrapper.find('[data-test="source-denied"]').exists()).toBe(true)
  })

  it('其他錯誤碼不標示來源網段說明', async () => {
    listFiles.mockRejectedValueOnce({ response: { status: 500, data: { code: 'INTERNAL_X' } } })
    const wrapper = mountManager()
    await wrapper.vm.refresh()
    await flushPromises()
    expect(wrapper.find('[data-test="source-denied"]').exists()).toBe(false)
  })
})
