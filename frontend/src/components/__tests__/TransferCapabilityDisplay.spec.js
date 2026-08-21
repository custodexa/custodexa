// 資料傳輸能力的呈現（data-transfer-control 6.2／6.3）。
//
// 守衛的不變式：**被政策禁止的動作在點下去之前就必須是不可用的**。
// 只驗「禁止時不可用」不夠——把 `allows()` 寫成恆回 false 也會通過，那會讓
// 五鍵全開的出廠狀態下整個檔案面板變灰。故每項能力都驗雙向：允許＝可用、
// 禁止＝不可用。
//
// 呈現不是強制點：後端 SFTP／K8s 閘與 tunnel 攔截才是。本檔不宣稱驗到控制。
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'

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

vi.hoisted(() => {
  globalThis.window.Guacamole = {
    StringReader: class {},
    StringWriter: class {},
    WebSocketTunnel: function () {},
    Client: function () {},
  }
})

import FileManager from '../FileManager.vue'
import GuacamoleClient from '../GuacamoleClient.vue'
import { listFiles, getTransferCapabilities } from '@/api/files'

const caps = (overrides = {}) => ({
  capabilities: {
    clipboard_send: true,
    clipboard_recv: true,
    file_upload: true,
    file_download: true,
    file_delete: true,
    ...overrides,
  },
  clipboard_enforced_protocols: ['rdp', 'vnc'],
  clipboard_requires_reconnect: true,
})

const drawerStub = {
  props: ['modelValue'],
  template: '<div v-if="modelValue" class="drawer-stub"><slot /></div>',
}

const mountManager = () =>
  mount(FileManager, {
    props: { modelValue: true, assetId: 3 },
    global: { plugins: [ElementPlus], stubs: { 'el-drawer': drawerStub } },
  })

describe('FileManager 依有效能力呈現不可用（6.2）', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    listFiles.mockResolvedValue({ entries: [{ name: 'a.txt', is_dir: false, size: 1 }] })
  })

  it('五鍵全允許（出廠值）時三個動作皆可用，且不顯示被擋提示', async () => {
    getTransferCapabilities.mockResolvedValue(caps())
    const wrapper = mountManager()
    await wrapper.vm.refresh()
    await flushPromises()

    expect(wrapper.vm.canUpload).toBe(true)
    expect(wrapper.vm.canDownload).toBe(true)
    expect(wrapper.vm.canDelete).toBe(true)
    expect(wrapper.vm.deniedFileActions).toEqual([])
    expect(wrapper.find('.file-caps-alert').exists()).toBe(false)
  })

  it('逐項禁止只關掉該項，其餘不受影響（避免整面板誤鎖）', async () => {
    const cases = [
      ['file_upload', 'canUpload'],
      ['file_download', 'canDownload'],
      ['file_delete', 'canDelete'],
    ]
    for (const [action, flag] of cases) {
      getTransferCapabilities.mockResolvedValue(caps({ [action]: false }))
      const wrapper = mountManager()
      await wrapper.vm.refresh()
      await flushPromises()

      expect(wrapper.vm[flag]).toBe(false)
      for (const [, other] of cases.filter(([a]) => a !== action)) {
        expect(wrapper.vm[other]).toBe(true)
      }
      expect(wrapper.vm.deniedFileActions).toEqual([action])
      wrapper.unmount()
    }
  })

  it('禁止上傳時工具列的上傳與新增目錄鈕實際為 disabled（不只是旗標）', async () => {
    getTransferCapabilities.mockResolvedValue(caps({ file_upload: false }))
    const wrapper = mountManager()
    await wrapper.vm.refresh()
    await flushPromises()

    const toolbarButtons = wrapper.findAll('.file-actions button')
    expect(toolbarButtons.length).toBeGreaterThan(0)
    // 上傳與新增目錄兩鈕不可用；重新整理鈕不受傳輸政策影響，仍可用
    expect(toolbarButtons.filter((b) => b.attributes('disabled') !== undefined).length).toBe(2)
    expect(wrapper.find('.file-caps-alert').exists()).toBe(true)
  })

  it('禁止刪除時列上的刪除鈕 disabled、下載鈕仍可用', async () => {
    getTransferCapabilities.mockResolvedValue(caps({ file_delete: false }))
    const wrapper = mountManager()
    await wrapper.vm.refresh()
    await flushPromises()

    expect(wrapper.vm.canDelete).toBe(false)
    expect(wrapper.vm.canDownload).toBe(true)
  })

  it('能力查詢失敗時維持可用（呈現面 fail-open，強制仍在伺服端）', async () => {
    getTransferCapabilities.mockRejectedValue(new Error('network'))
    const wrapper = mountManager()
    await wrapper.vm.refresh()
    await flushPromises()

    expect(wrapper.vm.canUpload).toBe(true)
    expect(wrapper.vm.canDownload).toBe(true)
    expect(wrapper.vm.canDelete).toBe(true)
  })

  it('每次重新整理都重取能力（會話進行中改政策，檔案三鍵即時生效）', async () => {
    getTransferCapabilities.mockResolvedValue(caps())
    const wrapper = mountManager()
    await wrapper.vm.refresh()
    await flushPromises()
    const first = getTransferCapabilities.mock.calls.length

    getTransferCapabilities.mockResolvedValue(caps({ file_download: false }))
    await wrapper.vm.refresh()
    await flushPromises()

    expect(getTransferCapabilities.mock.calls.length).toBeGreaterThan(first)
    expect(wrapper.vm.canDownload).toBe(false)
  })
})

describe('GuacamoleClient 剪貼簿與上傳鈕依能力呈現（6.3）', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.stubGlobal('ResizeObserver', class {
      observe() {}
      disconnect() {}
    })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  const mountClient = () =>
    mount(GuacamoleClient, {
      props: { assetId: 77, protocol: 'rdp', assetName: '測試 RDP' },
      global: { plugins: [ElementPlus] },
    })

  it('剪貼簿雙向與檔案上傳各自對應一個鍵，允許時皆可用', async () => {
    getTransferCapabilities.mockResolvedValue(caps())
    const wrapper = mountClient()
    await wrapper.vm.loadCapabilities(77)
    await flushPromises()

    expect(wrapper.vm.canClipboardSend).toBe(true)
    expect(wrapper.vm.canClipboardRecv).toBe(true)
    expect(wrapper.vm.canFileUpload).toBe(true)
  })

  it('禁止貼入資產只關貼上鈕，取遠端剪貼簿不受影響（方向不得混淆）', async () => {
    getTransferCapabilities.mockResolvedValue(caps({ clipboard_send: false }))
    const wrapper = mountClient()
    await wrapper.vm.loadCapabilities(77)
    await flushPromises()

    expect(wrapper.vm.canClipboardSend).toBe(false)
    expect(wrapper.vm.canClipboardRecv).toBe(true)
  })

  it('禁止自資產抄出只關取遠端剪貼簿鈕，貼上不受影響（反向同驗）', async () => {
    getTransferCapabilities.mockResolvedValue(caps({ clipboard_recv: false }))
    const wrapper = mountClient()
    await wrapper.vm.loadCapabilities(77)
    await flushPromises()

    expect(wrapper.vm.canClipboardRecv).toBe(false)
    expect(wrapper.vm.canClipboardSend).toBe(true)
  })

  it('禁止檔案上傳時圖形通道的上傳鈕不可用', async () => {
    getTransferCapabilities.mockResolvedValue(caps({ file_upload: false }))
    const wrapper = mountClient()
    await wrapper.vm.loadCapabilities(77)
    await flushPromises()

    expect(wrapper.vm.canFileUpload).toBe(false)
    expect(wrapper.vm.canClipboardSend).toBe(true)
  })
})
