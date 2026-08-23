// SFTP 沿用會話帳號：自會話分頁進入檔案管理時，
// 五個檔案端點都必須帶 session_id——後端 `sftp_handler.go` 的帳號解析分支
// 只認 query 的 session_id，漏帶＝終端用 app、檔案面靜默用 root（審計語義斷裂）。
// 獨立入口（無 session）維持不帶＝走預設帳號。
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus, { ElMessage, ElMessageBox } from 'element-plus'
import FileManager from '../FileManager.vue'
import { listFiles, uploadFile, downloadFile, mkdir, deleteFile, getTransferCapabilities } from '@/api/files'

// 逐測卸載：本檔掛載元件後不卸載，殘留元件在 document 上累積使單測耗時隨測試序
// 上升，全量並行時末幾格逼近逾時上限而間歇轉紅。治法同 fca615b（Assets／
// AuditLogs／Users／MainLayout）：enableAutoUnmount(afterEach)。
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

const mountManager = (props = {}) =>
  mount(FileManager, {
    props: { modelValue: true, assetId: 3, ...props },
    global: { plugins: [ElementPlus], stubs: { 'el-drawer': drawerStub } },
  })

describe('FileManager 會話帳號沿用', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    listFiles.mockResolvedValue({ entries: [] })
    uploadFile.mockResolvedValue({})
    downloadFile.mockResolvedValue(new Blob(['x']))
    mkdir.mockResolvedValue({})
    deleteFile.mockResolvedValue({})
    getTransferCapabilities.mockResolvedValue({
      capabilities: {
        clipboard_send: true,
        clipboard_recv: true,
        file_upload: true,
        file_download: true,
        file_delete: true,
      },
      clipboard_enforced_protocols: ['rdp', 'vnc'],
      clipboard_requires_reconnect: true,
    })
  })

  it('自會話分頁進入：五個檔案端點皆帶該 session id', async () => {
    const wrapper = mountManager({ sessionId: 42, accountUsername: 'app' })
    await wrapper.vm.refresh()
    await flushPromises()
    expect(listFiles).toHaveBeenLastCalledWith(3, '/', 42)

    await wrapper.vm.handleUpload({ file: new File(['a'], 'a.txt') })
    expect(uploadFile).toHaveBeenLastCalledWith(3, '/', expect.any(File), 42)

    await wrapper.vm.handleDownload({ name: 'a.txt', is_dir: false })
    expect(downloadFile).toHaveBeenLastCalledWith(3, '/a.txt', 42)

    vi.spyOn(ElMessageBox, 'prompt').mockResolvedValue({ value: 'sub' })
    await wrapper.vm.handleMkdir()
    expect(mkdir).toHaveBeenLastCalledWith(3, '/sub', 42)

    vi.spyOn(ElMessageBox, 'confirm').mockResolvedValue('confirm')
    await wrapper.vm.handleDelete({ name: 'a.txt', is_dir: false })
    expect(deleteFile).toHaveBeenLastCalledWith(3, '/a.txt', 42)
  })

  it('獨立入口（無 session）不帶 session id＝走預設帳號', async () => {
    const wrapper = mountManager()
    await wrapper.vm.refresh()
    await flushPromises()
    expect(listFiles).toHaveBeenLastCalledWith(3, '/', null)
  })

  it('帳號標示隨 prop 切換而變，不是寫死的靜態文案', async () => {
    const wrapper = mountManager()
    await flushPromises()
    expect(wrapper.text()).toContain('檔案操作使用此資產的預設帳號')
    expect(wrapper.text()).not.toContain('檔案操作使用連線帳號')

    await wrapper.setProps({ sessionId: 42, accountUsername: 'app' })
    await flushPromises()
    expect(wrapper.text()).toContain('檔案操作使用連線帳號 app')
    expect(wrapper.text()).not.toContain('檔案操作使用此資產的預設帳號')

    await wrapper.setProps({ accountUsername: 'root' })
    await flushPromises()
    expect(wrapper.text()).toContain('檔案操作使用連線帳號 root')
  })
})

// 連線建立中即可開檔案管理，先以預設帳號載入目錄；
// sessionId 之後才到。若不重載，畫面是帳號 A 的清單、刪除卻打帳號 B 的同路徑
describe('FileManager 清單與操作的身分一致性', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    listFiles.mockResolvedValue({ entries: [{ name: 'a.txt', is_dir: false, size: 1 }] })
    deleteFile.mockResolvedValue({})
    getTransferCapabilities.mockResolvedValue({
      capabilities: {
        clipboard_send: true,
        clipboard_recv: true,
        file_upload: true,
        file_download: true,
        file_delete: true,
      },
      clipboard_enforced_protocols: ['rdp', 'vnc'],
      clipboard_requires_reconnect: true,
    })
    downloadFile.mockResolvedValue(new Blob(['x']))
  })

  it('sessionId 由無到有時重載目錄，且以新身分重新查詢', async () => {
    const wrapper = mountManager()
    await wrapper.vm.refresh()
    await flushPromises()
    expect(listFiles).toHaveBeenLastCalledWith(3, '/', null)

    await wrapper.setProps({ sessionId: 42 })
    await flushPromises()

    expect(listFiles).toHaveBeenLastCalledWith(3, '/', 42)
    expect(listFiles).toHaveBeenCalledTimes(2)
  })

  it('身分變更當下先清空清單，不留舊帳號的檔案給人按', async () => {
    let resolveReload
    const wrapper = mountManager()
    await wrapper.vm.refresh()
    await flushPromises()
    expect(wrapper.vm.entries).toHaveLength(1)

    listFiles.mockImplementationOnce(() => new Promise((r) => { resolveReload = r }))
    await wrapper.setProps({ sessionId: 42 })
    // 重載尚未回來：清單已空
    expect(wrapper.vm.entries).toEqual([])

    resolveReload({ entries: [{ name: 'b.txt', is_dir: false, size: 2 }] })
    await flushPromises()
    expect(wrapper.vm.entries.map((e) => e.name)).toEqual(['b.txt'])
  })

  it('重載完成前不得執行刪除／下載，改為重新載入並告知', async () => {
    let resolveReload
    const confirmSpy = vi.spyOn(ElMessageBox, 'confirm').mockResolvedValue('confirm')
    const warnSpy = vi.spyOn(ElMessage, 'warning').mockImplementation(() => {})
    const wrapper = mountManager()
    await wrapper.vm.refresh()
    await flushPromises()

    listFiles.mockImplementationOnce(() => new Promise((r) => { resolveReload = r }))
    await wrapper.setProps({ sessionId: 42 })

    await wrapper.vm.handleDelete({ name: 'a.txt', is_dir: false })
    await wrapper.vm.handleDownload({ name: 'a.txt', is_dir: false })

    expect(deleteFile).not.toHaveBeenCalled()
    expect(downloadFile).not.toHaveBeenCalled()
    expect(confirmSpy).not.toHaveBeenCalled()
    expect(warnSpy).toHaveBeenCalled()

    // 重載完成後恢復可操作，且打的是新身分
    resolveReload({ entries: [{ name: 'a.txt', is_dir: false, size: 1 }] })
    await flushPromises()
    await wrapper.vm.handleDelete({ name: 'a.txt', is_dir: false })
    expect(deleteFile).toHaveBeenLastCalledWith(3, '/a.txt', 42)

    confirmSpy.mockRestore()
    warnSpy.mockRestore()
  })

  it('載入途中身分改變時丟棄過期回應（不得以舊帳號清單覆蓋）', async () => {
    let resolveStale
    listFiles.mockImplementationOnce(() => new Promise((r) => { resolveStale = r }))
    const wrapper = mountManager()
    const stale = wrapper.vm.refresh()

    // 新身分的回應先備好，確保 watcher 觸發的重載拿到的是「新」清單
    listFiles.mockResolvedValue({ entries: [{ name: 'fresh.txt', is_dir: false, size: 3 }] })
    await wrapper.setProps({ sessionId: 42 })
    await flushPromises()

    resolveStale({ entries: [{ name: 'stale.txt', is_dir: false, size: 9 }] })
    await stale
    await flushPromises()

    expect(wrapper.vm.entries.map((e) => e.name)).toEqual(['fresh.txt'])
  })
})
