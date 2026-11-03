import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import HostAccountInventoryDrawer from '../asset/HostAccountInventoryDrawer.vue'
import previewWrite from '@/directives/previewWrite'
import { resetCapabilities, setCapabilitiesForTests } from '@/composables/useCapabilities'
import zh from '@/i18n/locales/zh-TW.json'

// 盤點畫面依身分的呈現：確認氣泡、從未盤點說明卡、狀態卡只給身分類別、專用帳號相關的錯誤與下一步。

const getAssetMock = vi.fn()
const getHostKeyMock = vi.fn()
const listAccountsMock = vi.fn()
const getInvMock = vi.fn()
const startMock = vi.fn()
const getExecutorMock = vi.fn()

vi.mock('@/api/assets', () => ({
  getAsset: (...a) => getAssetMock(...a),
  getAssetHostKey: (...a) => getHostKeyMock(...a),
}))
vi.mock('@/api/assetAccounts', () => ({ listAssetAccounts: (...a) => listAccountsMock(...a) }))
vi.mock('@/api/assetExecutor', () => ({ getAssetExecutor: (...a) => getExecutorMock(...a) }))
vi.mock('@/api/hostInventory', () => ({
  getAssetInventory: (...a) => getInvMock(...a),
  startInventoryScan: (...a) => startMock(...a),
  reopenInventoryFinding: vi.fn(),
  ignoreInventoryFinding: vi.fn(),
}))

class ObserverStub {
  observe() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', ObserverStub)
vi.stubGlobal('ResizeObserver', ObserverStub)
enableAutoUnmount(afterEach)

const stubs = {
  'el-drawer': {
    props: ['modelValue'],
    template: '<div v-if="modelValue" class="drawer-stub"><slot name="header" /><slot /></div>',
  },
  'el-dialog': { props: ['modelValue'], template: '<div v-if="modelValue"><slot /><slot name="footer" /></div>' },
  // 確認框內容永遠渲染，內文、標題與提醒都在 DOM 裡才斷言得到（真元件版見 HostInventoryStartConfirm.spec.js）
  'el-popover': { template: '<span><slot name="reference" /><span class="pop-body"><slot /></span></span>' },
  'el-tooltip': { template: '<span><slot /></span>' },
  'router-link': { template: '<a><slot /></a>' },
  'el-collapse': { template: '<div><slot /></div>', props: ['modelValue'] },
  'el-collapse-item': { template: '<div><slot /></div>', props: ['title', 'name'] },
}

const ASSET = { id: 7, name: 'web-01', host: '10.0.0.7', protocol: 'ssh', effective_rotation_channel: 'posix_ssh' }
const ACCOUNTS = { data: [{ id: 1, username: 'opsadmin', is_default: true }] }
const baseScan = (o = {}) => ({
  id: 5, status: 'succeeded', identity_mode: 'executor', initiated_by_name: 'alice',
  started_at: '2026-11-02T10:00:00Z', finished_at: '2026-11-02T10:00:20Z',
  accounts_total: 12, privileged_total: 3, unmanaged_privileged_total: 2, privileged_groups: 'root,sudo', ...o,
})
const inv = (o = {}) => ({
  scan: null, coverage: [], fixed_notes: [], findings: [], total: 0, page: 1, page_size: 50,
  next_identity: { mode: 'executor', username: '' }, ...o,
})
const apiErr = (status, code) => Object.assign(new Error('x'), { response: { status, data: { code } } })
const PERMS = ['asset:view', 'account:discover', 'asset:update']
const WITH_EXEC = [...PERMS, 'asset:executor-manage']

async function open(perms = WITH_EXEC) {
  setCapabilitiesForTests(perms)
  const w = mount(HostAccountInventoryDrawer, {
    props: { modelValue: true, assetId: 7 },
    global: { plugins: [ElementPlus], stubs, directives: { 'preview-write': previewWrite } },
  })
  await flushPromises()
  return w
}
const title = (w) => w.get('[data-test="inv-confirm-title"]').text()

beforeEach(() => {
  vi.clearAllMocks()
  getAssetMock.mockResolvedValue({ ...ASSET })
  getHostKeyMock.mockResolvedValue({ fingerprint: 'SHA256:x' })
  listAccountsMock.mockResolvedValue(ACCOUNTS)
  getExecutorMock.mockResolvedValue({ configured: true, username: 'cx-exec' })
  getInvMock.mockResolvedValue(inv())
})
afterEach(() => resetCapabilities())

describe('ExecutorIdentity 確認氣泡與說明卡', () => {
  it('next_identity=executor 且持專用帳號管理權：讀專用帳號一次、氣泡寫它的名稱、不含預設帳號名', async () => {
    const w = await open(WITH_EXEC)
    expect(getExecutorMock).toHaveBeenCalledTimes(1)
    expect(getExecutorMock).toHaveBeenCalledWith(7)
    expect(title(w)).toBe('用堡壘機專用帳號 cx-exec 登入盤點？')
    expect(title(w)).not.toContain('opsadmin')
    expect(w.get('[data-test="inv-confirm-body"]').text()).toContain('只讀取帳號與群組清單，不會修改主機。')
    expect(w.find('[data-test="inv-confirm-no-executor"]').exists()).toBe(false)
  })

  it('沒有專用帳號管理權：不呼叫該端點，氣泡用代稱且不含任何帳號名', async () => {
    const w = await open(PERMS)
    expect(getExecutorMock).not.toHaveBeenCalled()
    expect(title(w)).toBe('用這台的堡壘機專用帳號登入盤點？')
    expect(w.text()).not.toContain('cx-exec')
    expect(w.text()).not.toContain('opsadmin')
  })

  it('專用帳號讀取失敗（404）或名稱為空：退回代稱', async () => {
    getExecutorMock.mockRejectedValueOnce(apiErr(404, 'NOTFOUND_ASSET_EXECUTOR'))
    let w = await open(WITH_EXEC)
    expect(title(w)).toBe('用這台的堡壘機專用帳號登入盤點？')
    w.unmount()
    getExecutorMock.mockResolvedValueOnce({ configured: true, username: '  ' })
    w = await open(WITH_EXEC)
    expect(title(w)).toBe('用這台的堡壘機專用帳號登入盤點？')
  })

  it('default_account：氣泡寫預設帳號名，另加「這台沒有設定堡壘機專用帳號」一句，不呼叫專用帳號端點', async () => {
    getInvMock.mockResolvedValue(inv({ next_identity: { mode: 'default_account', username: 'opsadmin' } }))
    const w = await open(WITH_EXEC)
    expect(getExecutorMock).not.toHaveBeenCalled()
    expect(title(w)).toBe('用預設帳號 opsadmin 登入盤點？')
    expect(w.get('[data-test="inv-confirm-no-executor"]').text()).toContain('這台沒有設定堡壘機專用帳號')
  })

  it('default_account 名稱為空：用代稱「這台的預設帳號」', async () => {
    getInvMock.mockResolvedValue(inv({ next_identity: { mode: 'default_account', username: '' } }))
    const w = await open(WITH_EXEC)
    expect(title(w)).toBe('用這台的預設帳號登入盤點？')
  })

  it('從未盤點說明卡依 next_identity 兩種寫法，且只寫身分類別不寫帳號名', async () => {
    let w = await open(WITH_EXEC)
    expect(w.get('[data-test="inv-never-card"]').text()).toContain('堡壘機專用帳號登入')
    expect(w.get('[data-test="inv-never-card"]').text()).not.toContain('cx-exec')
    w.unmount()
    getInvMock.mockResolvedValue(inv({ next_identity: { mode: 'default_account', username: 'opsadmin' } }))
    w = await open(WITH_EXEC)
    expect(w.get('[data-test="inv-never-card"]').text()).toContain('預設帳號登入')
    expect(w.get('[data-test="inv-never-card"]').text()).not.toContain('opsadmin')
  })

  it('兩種身分都沒有（next_identity 為 null）：開始鈕停用；欄位缺席時退回只看預設帳號', async () => {
    getInvMock.mockResolvedValue(inv({ next_identity: null }))
    let w = await open(WITH_EXEC)
    expect(w.get('[data-test="inv-start"]').attributes('disabled')).toBeDefined()
    // 原因與連結在按鈕下方（畫面稿 B3）：黃字一句，有編輯權者帶「前往帳號設定」，點了發出 goto
    expect(w.get('[data-test="inv-start-blocked"]').text()).toContain('這台沒有堡壘機專用帳號，也沒有預設帳號，盤點沒有帳號可以登入。')
    expect(w.get('[data-test="inv-start-blocked"] [data-test="inv-blocked-icon"]').attributes('aria-hidden')).toBe('true')
    expect(w.get('[data-test="inv-blocked-go-accounts"] [data-test="inv-blocked-link-icon"]').attributes('aria-hidden')).toBe('true')
    await w.get('[data-test="inv-blocked-go-accounts"]').trigger('click')
    expect(w.emitted('goto')[0][0]).toEqual({ id: 7, target: 'accounts' })
    w.unmount()
    w = await open(['asset:view', 'account:discover'])
    expect(w.find('[data-test="inv-blocked-go-accounts"]').exists()).toBe(false)
    w.unmount()
    getInvMock.mockResolvedValue(inv({ next_identity: undefined }))
    w = await open(WITH_EXEC)
    expect(w.get('[data-test="inv-start"]').attributes('disabled')).toBeUndefined()
  })
})

describe('ExecutorIdentity 狀態卡', () => {
  it('executor 盤點列：只顯示身分類別，兩種權限下都不含帳號名（含後端誤帶的名稱）', async () => {
    getInvMock.mockResolvedValue(inv({ scan: baseScan({ identity_username: 'cx-exec' }) }))
    for (const perms of [WITH_EXEC, PERMS]) {
      const w = await open(perms)
      const line = w.get('[data-test="inv-lastrun"]').text()
      expect(line).toContain('用堡壘機專用帳號登入')
      expect(line).not.toContain('cx-exec')
      w.unmount()
    }
  })

  it('default_account 盤點列：預設帳號名取盤點當時的身分，並保留「這台沒有設定堡壘機專用帳號」說明', async () => {
    getInvMock.mockResolvedValue(inv({
      scan: baseScan({ identity_mode: 'default_account', identity_username: 'deploy' }),
      next_identity: { mode: 'executor', username: '' },
    }))
    const w = await open(WITH_EXEC)
    const line = w.get('[data-test="inv-lastrun"]').text()
    expect(line).toContain('用預設帳號 deploy 登入')
    expect(line).toContain('沒有設定堡壘機專用帳號')
    expect(line).not.toContain('opsadmin')
  })

  it('default_account 盤點列的帳號名為空：用不帶名稱的句子', async () => {
    getInvMock.mockResolvedValue(inv({ scan: baseScan({ identity_mode: 'default_account', identity_username: '' }) }))
    const w = await open(WITH_EXEC)
    const line = w.get('[data-test="inv-lastrun"]').text()
    expect(line).toContain('用預設帳號登入')
    expect(line).not.toContain('opsadmin')
  })
})

describe('ExecutorIdentity 發起錯誤與結束原因', () => {
  const startErr = async (code, perms) => {
    const w = await open(perms)
    startMock.mockRejectedValueOnce(apiErr(code.startsWith('CONFLICT') ? 409 : code.includes('RATE') ? 429 : 422, code))
    await w.get('[data-test="inv-start"]').trigger('click')
    await w.vm.$.setupState.start()
    await flushPromises()
    return w
  }

  it('RULE_INVENTORY_EXECUTOR_UNAVAILABLE：有專用帳號管理權才有連結，連結導向落點；沒有權限只有文字', async () => {
    let w = await startErr('RULE_INVENTORY_EXECUTOR_UNAVAILABLE', WITH_EXEC)
    expect(w.get('[data-test="inv-start-error"]').text()).toContain('沒有可用的秘密')
    const link = w.get('[data-test="inv-go-executor"]')
    await link.trigger('click')
    expect(w.emitted('goto')[0][0]).toEqual({ id: 7, target: 'executor-test-login' })
    w.unmount()
    w = await startErr('RULE_INVENTORY_EXECUTOR_UNAVAILABLE', PERMS)
    expect(w.get('[data-test="inv-start-error"]').text()).toContain('沒有可用的秘密')
    expect(w.find('[data-test="inv-go-executor"]').exists()).toBe(false)
  })

  it('CONFLICT_INVENTORY_EXECUTOR_BUSY 與 RATE_LIMITED：有專屬文案、沒有連結；限流句不含任何數字', async () => {
    let w = await startErr('CONFLICT_INVENTORY_EXECUTOR_BUSY', WITH_EXEC)
    expect(w.get('[data-test="inv-start-error"]').text()).toContain('正在改密')
    expect(w.find('[data-test="inv-go-executor"]').exists()).toBe(false)
    w.unmount()
    w = await startErr('RULE_INVENTORY_EXECUTOR_RATE_LIMITED', WITH_EXEC)
    const text = w.get('[data-test="inv-start-error"]').text()
    expect(text).toContain('太頻繁')
    expect(text).not.toMatch(/[0-9０-９]/)
    expect(text).not.toBe(zh.hostInventory.err.generic)
  })

  it('三個新結束原因碼都有非通用文案；專用帳號被清除與沒有秘密的下一步，僅持管理權者有鈕', async () => {
    const codes = ['INVENTORY_EXECUTOR_CHANGED', 'INVENTORY_EXECUTOR_BUSY', 'INVENTORY_EXECUTOR_UNAVAILABLE']
    for (const code of codes) {
      getInvMock.mockResolvedValue(inv({ scan: baseScan({ status: 'failed', failure_reason: code }) }))
      const w = await open(WITH_EXEC)
      const banner = w.get('[data-test="inv-banner-failed"]').text()
      expect(banner).toContain('堡壘機專用帳號')
      expect(banner).not.toContain(zh.hostInventory.failure.generic)
      const btn = w.find('[data-test="inv-go-executor-failed"]')
      expect(btn.exists()).toBe(code !== 'INVENTORY_EXECUTOR_BUSY')
      if (btn.exists()) {
        await btn.trigger('click')
        expect(w.emitted('goto')[0][0]).toEqual({ id: 7, target: 'executor-test-login' })
      }
      w.unmount()
      const w2 = await open(PERMS)
      expect(w2.find('[data-test="inv-go-executor-failed"]').exists()).toBe(false)
      w2.unmount()
    }
  })
})

describe('ExecutorIdentity 檢查範圍與補齊說明', () => {
  const cov = (reason) => [{ check: 'sudoers_main', state: 'unreadable', reason, path: '/etc/sudoers' }]

  it('via_escalation 與 escalation_denied 有各自文案；denied 對持管理權者帶「設定方式」連結', async () => {
    getInvMock.mockResolvedValue(inv({ scan: baseScan(), coverage: cov('escalation_denied') }))
    let w = await open(WITH_EXEC)
    expect(w.get('[data-test="inv-coverage"]').text()).toContain('提權讀取也被拒絕')
    const link = w.get('[data-test="cov-setup-link"]')
    await link.trigger('click')
    expect(w.emitted('goto')[0][0]).toEqual({ id: 7, target: 'executor-test-login' })
    w.unmount()
    w = await open(PERMS)
    expect(w.find('[data-test="cov-setup-link"]').exists()).toBe(false)
    w.unmount()
    getInvMock.mockResolvedValue(inv({ scan: baseScan(), coverage: [{ check: 'sudoers_main', state: 'checked', reason: 'via_escalation' }] }))
    w = await open(WITH_EXEC)
    expect(w.get('[data-test="inv-coverage"]').text()).toContain('提權讀取')
  })

  it('提權讀取被拒的缺項句改寫成專用帳號的說法，不重複同一句原因', async () => {
    getInvMock.mockResolvedValue(inv({ scan: baseScan({ status: 'partial' }), coverage: cov('escalation_denied') }))
    const w = await open(WITH_EXEC)
    const text = w.get('[data-test="inv-banner-partial"]').text()
    expect(text).toContain('專用帳號沒有讀取權限，提權讀取也被拒絕')
    expect(text).not.toContain('登入帳號沒有讀取權限')
  })

  it('部分完成的補齊說明：用預設帳號時建議設定專用帳號；已是專用帳號時說讓它能讀（有名稱寫名稱）', async () => {
    const partial = (mode) => inv({
      scan: baseScan({ status: 'partial', identity_mode: mode }),
      coverage: cov('permission_denied'),
    })
    getInvMock.mockResolvedValue(partial('default_account'))
    let w = await open(WITH_EXEC)
    expect(w.get('[data-test="inv-partial-hint-text"]').text()).toContain('設定這台的堡壘機專用帳號')
    w.unmount()
    getInvMock.mockResolvedValue(partial('executor'))
    w = await open(WITH_EXEC)
    expect(w.get('[data-test="inv-partial-hint-text"]').text()).toContain('專用帳號 cx-exec 能讀取 sudo 規則')
    await w.get('[data-test="inv-partial-go-executor"]').trigger('click')
    expect(w.emitted('goto')[0][0]).toEqual({ id: 7, target: 'executor-test-login' })
    w.unmount()
    w = await open(PERMS)
    expect(w.get('[data-test="inv-partial-hint-text"]').text()).not.toContain('cx-exec')
    expect(w.find('[data-test="inv-partial-go-executor"]').exists()).toBe(false)
  })
})

describe('ExecutorIdentity 三語', () => {
  it('hostInventory 與角色說明的三語鍵集相等', async () => {
    const en = (await import('@/i18n/locales/en-US.json')).default
    const ja = (await import('@/i18n/locales/ja-JP.json')).default
    const keys = (o, p = '') => Object.entries(o).flatMap(([k, v]) => (v && typeof v === 'object' ? keys(v, `${p}${k}.`) : [`${p}${k}`]))
    expect(keys(en.hostInventory).sort()).toEqual(keys(zh.hostInventory).sort())
    expect(keys(ja.hostInventory).sort()).toEqual(keys(zh.hostInventory).sort())
    for (const l of [zh, en, ja]) {
      expect(l.roles.editor.entryNote.host_account_inventory.length).toBeGreaterThan(40)
    }
    expect(zh.roles.editor.entryNote.host_account_inventory).toContain('有堡壘機專用帳號時')
  })
})
