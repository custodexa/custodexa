// 主機金鑰與記錄不符的警示元件（host-key-verification）：終端與檔案管理共用。
// 超管看到直達資產主機金鑰區塊的入口；其他人看到聯絡管理員的提示；可關閉且不落 localStorage；
// 第一層照實寫出「已替你送出登入憑證」（接受風險的留痕），技術細節收進「詳細說明」。
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import HostKeyMismatchNotice from '../HostKeyMismatchNotice.vue'
import FileManager from '../FileManager.vue'
import { listFiles, getTransferCapabilities } from '@/api/files'
import { setLanguage, SUPPORTED_LOCALES, LANG_STORAGE_KEY, t } from '@/i18n'
import { resetCapabilities } from '@/composables/useCapabilities'
import { grantFor } from '@/composables/__tests__/capabilityFixtures'
import { getCurrentUser } from '@/api/auth'
import { ADMIN_PERMISSIONS } from '@/composables/__tests__/capabilityFixtures'

enableAutoUnmount(afterEach)

class MutationObserverStub {
  observe() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', MutationObserverStub)

vi.mock('@/api/auth', () => ({
  getCurrentUser: vi.fn(),
}))

vi.mock('@/api/files', () => ({
  listFiles: vi.fn(),
  uploadFile: vi.fn(),
  downloadFile: vi.fn(),
  mkdir: vi.fn(),
  deleteFile: vi.fn(),
  getTransferCapabilities: vi.fn(),
}))

const mountNotice = (props = {}) =>
  mount(HostKeyMismatchNotice, {
    props: { assetId: 7, ...props },
    global: { plugins: [ElementPlus] },
  })

describe('HostKeyMismatchNotice', () => {
  beforeEach(() => {
    localStorage.clear()
    resetCapabilities()
    setLanguage('zh-TW')
  })

  it('超管：顯示標題、說明（含已替你送出登入憑證）與「前往資產設定採用或重置主機金鑰」入口，點擊開深連結', async () => {
    grantFor(['admin'])
    const openSpy = vi.spyOn(window, 'open').mockImplementation(() => null)
    const w = mountNotice()
    expect(w.find('[data-test="host-key-mismatch-notice"]').exists()).toBe(true)
    expect(w.text()).toContain('主機身分與記錄不符')
    expect(w.text()).toContain('平台已替你送出登入憑證')
    expect(w.text()).toContain('可能有人冒充，請立即中斷連線')
    expect(w.text()).toContain('此事已記錄')
    const go = w.find('[data-test="host-key-mismatch-go"]')
    expect(go.exists()).toBe(true)
    expect(go.text()).toBe('前往資產設定採用或重置主機金鑰')
    expect(w.find('[data-test="host-key-mismatch-contact"]').exists()).toBe(false)
    await go.trigger('click')
    expect(openSpy).toHaveBeenCalledWith('/assets?edit=7', '_blank')
    openSpy.mockRestore()
  })

  it('另開分頁尚未載入能力時，元件自行載入：超管載入後看到入口而非聯絡提示', async () => {
    getCurrentUser.mockResolvedValueOnce({ id: 1, permissions: ADMIN_PERMISSIONS, scope_summary: [] })
    const w = mountNotice()
    await flushPromises()
    expect(getCurrentUser).toHaveBeenCalledTimes(1)
    expect(w.find('[data-test="host-key-mismatch-go"]').exists()).toBe(true)
    expect(w.find('[data-test="host-key-mismatch-contact"]').exists()).toBe(false)
  })

  it('非超管：只看到聯絡管理員採用新指紋或重置的提示，沒有入口', () => {
    grantFor(['user'])
    const w = mountNotice()
    expect(w.find('[data-test="host-key-mismatch-go"]').exists()).toBe(false)
    const contact = w.find('[data-test="host-key-mismatch-contact"]')
    expect(contact.exists()).toBe(true)
    expect(contact.text()).toBe('請聯絡管理員確認後採用新指紋或重置主機金鑰')
  })

  it('詳細說明預設收合，展開後列出主機金鑰、憑證與告警送達三點，再按收起', async () => {
    grantFor(['user'])
    const w = mountNotice()
    const toggle = w.find('[data-test="host-key-mismatch-details-toggle"]')
    expect(toggle.attributes('aria-expanded')).toBe('false')
    expect(toggle.text()).toBe('詳細說明')
    expect(w.find('[data-test="host-key-mismatch-details"]').exists()).toBe(false)
    // 第一層不帶技術細節
    expect(w.text()).not.toContain('私鑰認證')
    await toggle.trigger('click')
    const items = w.findAll('[data-test="host-key-mismatch-details"] li').map((li) => li.text())
    expect(items).toEqual([
      t('hostKeyMismatch.detailHostKey'),
      t('hostKeyMismatch.detailCredential'),
      t('hostKeyMismatch.detailAlert'),
    ])
    expect(items[1]).toContain('不送出私鑰')
    expect(items[2]).toContain('送達與否取決於通知通道的設定與投遞結果')
    expect(toggle.attributes('aria-expanded')).toBe('true')
    expect(toggle.text()).toBe('收起說明')
    await toggle.trigger('click')
    expect(w.find('[data-test="host-key-mismatch-details"]').exists()).toBe(false)
  })

  it('可關閉：關閉後消失、發出 dismiss，且不寫 localStorage', async () => {
    grantFor(['user'])
    const w = mountNotice()
    expect(w.find('.el-alert__close-btn').exists()).toBe(true)
    // el-alert 的 close 事件（關閉鈕點擊）
    w.findComponent({ name: 'ElAlert' }).vm.$emit('close')
    await flushPromises()
    expect(w.find('[data-test="host-key-mismatch-notice"]').exists()).toBe(false)
    expect(w.emitted('dismiss')).toHaveLength(1)
    // 只允許 i18n 的語言鍵；關閉狀態不得落 localStorage
    const keys = Array.from({ length: localStorage.length }, (_, i) => localStorage.key(i)).filter((k) => k !== LANG_STORAGE_KEY)
    expect(keys).toEqual([])
  })

  it('審計摘要與連線測試提示三語都明示登入憑證已（或可能已）送出', () => {
    const want = { 'zh-TW': ['登入憑證', '未核對', '密碼可能已送出'], 'en-US': ['credentials', 'unverified', 'may have been sent'], 'ja-JP': ['認証情報', '未確認', '可能性'] }
    for (const locale of SUPPORTED_LOCALES) {
      setLanguage(locale)
      const [w1, w2, w3] = want[locale]
      expect(t('auditorWorkbench.summary.audit_log.host_key_mismatch'), locale).toContain(w1)
      expect(t('auditorWorkbench.summary.audit_log.host_key_mismatch'), locale).toContain(w2)
      expect(t('auditorWorkbench.summary.audit_log.host_key_cred_sent'), locale).toContain(w1)
      expect(t('assets.testSuccessHostKeyMismatch'), locale).toContain(w1)
      expect(t('assets.testFailedHostKeyMismatch', { reason: 'x' }), locale).toContain(w3)
    }
    setLanguage('zh-TW')
  })

  it('三語各渲染一次無缺鍵（不出現 hostKeyMismatch.* 原鍵）', () => {
    grantFor(['admin'])
    for (const locale of SUPPORTED_LOCALES) {
      setLanguage(locale)
      const w = mountNotice()
      expect(w.text(), locale).not.toContain('hostKeyMismatch.')
      expect(w.text().length, locale).toBeGreaterThan(40)
      w.unmount()
    }
    setLanguage('zh-TW')
  })
})

describe('FileManager 與主機金鑰不符警示', () => {
  const drawerStub = {
    props: ['modelValue'],
    template: '<div v-if="modelValue" class="drawer-stub"><slot /></div>',
  }
  const mountManager = () =>
    mount(FileManager, {
      props: { modelValue: true, assetId: 3 },
      global: { plugins: [ElementPlus], stubs: { 'el-drawer': drawerStub } },
    })

  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
    resetCapabilities()
    grantFor(['user'])
    setLanguage('zh-TW')
    getTransferCapabilities.mockResolvedValue({
      capabilities: { clipboard_send: true, clipboard_recv: true, file_upload: true, file_download: true, file_delete: true },
      clipboard_enforced_protocols: [],
      clipboard_requires_reconnect: false,
    })
  })

  it('列目錄回應帶 host_key_mismatch: true 時顯示同一元件', async () => {
    listFiles.mockResolvedValue({ entries: [], host_key_mismatch: true })
    const w = mountManager()
    await w.vm.refresh()
    await flushPromises()
    expect(w.find('[data-test="host-key-mismatch-notice"]').exists()).toBe(true)
    expect(w.find('[data-test="host-key-mismatch-contact"]').exists()).toBe(true)
  })

  it('旗標為 false 或缺欄時不顯示', async () => {
    for (const res of [{ entries: [], host_key_mismatch: false }, { entries: [] }]) {
      listFiles.mockResolvedValue(res)
      const w = mountManager()
      await w.vm.refresh()
      await flushPromises()
      expect(w.find('[data-test="host-key-mismatch-notice"]').exists()).toBe(false)
      w.unmount()
    }
  })
})
