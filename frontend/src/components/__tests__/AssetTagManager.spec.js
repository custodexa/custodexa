import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus, { ElMessage, ElMessageBox } from 'element-plus'
import AssetTagManager from '../AssetTagManager.vue'
import { renameAssetTag, deleteAssetTag } from '@/api/assets'

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

vi.mock('@/api/assets', () => ({
  renameAssetTag: vi.fn(),
  deleteAssetTag: vi.fn(),
}))

// el-dialog teleport 到 body，happy-dom 下 wrapper.text() 撈不到——inline stub
const dialogStub = {
  props: ['modelValue'],
  template: '<div v-if="modelValue" class="dialog-stub"><slot /><slot name="footer" /></div>',
}

const sampleTags = [
  { name: 'DBA', count: 3 },
  { name: 'DbA標籤', count: 2 },
  { name: '生產', count: 5 },
]

const mountManager = () =>
  mount(AssetTagManager, {
    props: { modelValue: true, tags: sampleTags },
    global: { plugins: [ElementPlus], stubs: { 'el-dialog': dialogStub } },
  })

describe('AssetTagManager 標籤治理', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('總覽含使用數、搜尋可收窄', async () => {
    const wrapper = mountManager()
    await flushPromises()

    expect(wrapper.text()).toContain('DBA')
    expect(wrapper.text()).toContain('生產')

    wrapper.vm.search = '生'
    await flushPromises()
    expect(wrapper.vm.filteredTags.map((t) => t.name)).toEqual(['生產'])
  })

  it('改名：受影響數前置顯示、成功後發 changed', async () => {
    renameAssetTag.mockResolvedValue({ affected: 2 })
    const successSpy = vi.spyOn(ElMessage, 'success').mockImplementation(() => {})
    const wrapper = mountManager()
    await flushPromises()

    wrapper.vm.openRename(sampleTags[1]) // DbA標籤 count 2
    await flushPromises()
    expect(wrapper.text()).toContain('受影響資產：2 台')

    wrapper.vm.renameTo = '維運'
    await wrapper.vm.confirmRename()

    expect(renameAssetTag).toHaveBeenCalledWith('DbA標籤', '維運')
    expect(successSpy).toHaveBeenCalledWith('已更新 2 台資產')
    expect(wrapper.emitted('changed')).toBeTruthy()
    successSpy.mockRestore()
  })

  it('目標 canonical 相等既有標籤時顯示合併提示', async () => {
    const wrapper = mountManager()
    await flushPromises()

    wrapper.vm.openRename(sampleTags[1]) // from = DbA標籤
    wrapper.vm.renameTo = 'dba' // 與既有 DBA canonical 相等
    await flushPromises()

    expect(wrapper.vm.mergeTarget).toBe('DBA')
    expect(wrapper.text()).toContain('將合併')
  })

  it('改名目標含逗號拒絕、不打 API', async () => {
    const warnSpy = vi.spyOn(ElMessage, 'warning').mockImplementation(() => {})
    const wrapper = mountManager()
    await flushPromises()

    wrapper.vm.openRename(sampleTags[0])
    wrapper.vm.renameTo = 'a,b'
    await wrapper.vm.confirmRename()

    expect(warnSpy).toHaveBeenCalledWith('標籤不得含逗號')
    expect(renameAssetTag).not.toHaveBeenCalled()
    warnSpy.mockRestore()
  })

  it('刪除：二次確認後打 API 並發 changed；取消不打', async () => {
    deleteAssetTag.mockResolvedValue({ affected: 5 })
    const confirmSpy = vi.spyOn(ElMessageBox, 'confirm').mockResolvedValue('confirm')
    const wrapper = mountManager()
    await flushPromises()

    await wrapper.vm.handleDelete(sampleTags[2]) // 生產 count 5
    expect(confirmSpy).toHaveBeenCalled()
    expect(deleteAssetTag).toHaveBeenCalledWith('生產')
    expect(wrapper.emitted('changed')).toBeTruthy()

    // 取消路徑
    deleteAssetTag.mockClear()
    confirmSpy.mockRejectedValue('cancel')
    await wrapper.vm.handleDelete(sampleTags[0])
    expect(deleteAssetTag).not.toHaveBeenCalled()
    confirmSpy.mockRestore()
  })
})
