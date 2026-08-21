import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, enableAutoUnmount } from '@vue/test-utils'

// 逐測卸載：本檔掛載元件後不卸載，殘留元件在 document 上累積使單測耗時隨測試序
// 上升，全量並行時末幾格逼近逾時上限而間歇轉紅。治法同 fca615b（Assets／
// AuditLogs／Users／MainLayout）：enableAutoUnmount(afterEach)。
enableAutoUnmount(afterEach)

const ElDialogStub = {
  name: 'ElDialog',
  props: ['modelValue', 'title'],
  emits: ['update:modelValue'],
  template: '<div class="stub-dialog"><slot /><slot name="footer" /></div>',
}

const { mockCreate, mockRevoke } = vi.hoisted(() => ({
  mockCreate: vi.fn(),
  mockRevoke: vi.fn(),
}))

vi.mock('@/api/sessions', () => ({
  createSessionShare: mockCreate,
  revokeSessionShare: mockRevoke,
  getSessionStats: vi.fn(),
}))

vi.mock('element-plus', async (importOriginal) => {
  const actual = await importOriginal()
  return { ...actual, ElMessage: { success: vi.fn(), error: vi.fn() } }
})

import ShareDialog from '../ShareDialog.vue'

function mountDialog() {
  return mount(ShareDialog, {
    props: { modelValue: true, sessionId: 42 },
    global: { stubs: { 'el-dialog': ElDialogStub } },
  })
}

describe('ShareDialog', () => {
  beforeEach(() => vi.clearAllMocks())

  it('建立分享後組出完整連結', async () => {
    mockCreate.mockResolvedValue({
      code: 'abc123',
      share_path: '/share/abc123',
      expires_at: '2026-06-12T13:00:00Z',
    })
    const wrapper = mountDialog()
    await wrapper.vm.create()

    expect(mockCreate).toHaveBeenCalledWith(42, { ttl_minutes: 10 })
    expect(wrapper.vm.shareUrl).toContain('/share/abc123')
  })

  it('撤銷後清空分享狀態', async () => {
    mockCreate.mockResolvedValue({ code: 'x', share_path: '/share/x', expires_at: '2026-06-12T13:00:00Z' })
    mockRevoke.mockResolvedValue({})
    const wrapper = mountDialog()
    await wrapper.vm.create()
    await wrapper.vm.revoke()

    expect(mockRevoke).toHaveBeenCalledWith(42)
    expect(wrapper.vm.share).toBeNull()
  })
})
