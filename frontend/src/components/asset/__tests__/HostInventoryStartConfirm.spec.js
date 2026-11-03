import { describe, it, expect, vi, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import HostInventoryStartConfirm from '../HostInventoryStartConfirm.vue'
import HostInventoryStatusCard from '../HostInventoryStatusCard.vue'
import previewWrite from '@/directives/previewWrite'

// 這份規格用真的 Element Plus 元件（不用替身），確認內文真的渲染在 DOM 裡
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

const mountConfirm = (props = {}) =>
  mount(HostInventoryStartConfirm, {
    props: { title: '用堡壘機專用帳號 cx-exec 登入盤點？', label: '開始盤點', ...props },
    attachTo: document.body,
    global: { plugins: [ElementPlus], directives: { 'preview-write': previewWrite } },
  })

const startBtn = (w) => w.get('[data-test="inv-start"]')
const open = async (w) => {
  await startBtn(w).trigger('click')
  await flushPromises()
  await new Promise((r) => setTimeout(r, 0))
  await flushPromises()
}

describe('HostInventoryStartConfirm（真 Element Plus）', () => {
  it('點按鈕後確認框顯示：標題、內文、取消與確認鈕都在 DOM 裡', async () => {
    const w = mountConfirm()
    await open(w)
    const box = w.get('[data-test="inv-confirm"]')
    expect(box.isVisible()).toBe(true)
    expect(box.get('[data-test="inv-confirm-title"]').text()).toBe('用堡壘機專用帳號 cx-exec 登入盤點？')
    expect(box.get('[data-test="inv-confirm-body"]').text()).toBe('只讀取帳號與群組清單，不會修改主機。')
    expect(box.get('[data-test="inv-confirm-cancel"]').text()).toBe('取消')
    expect(box.get('[data-test="inv-confirm-ok"]').text()).toBe('開始')
    expect(box.attributes('role')).toBe('dialog')
    expect(box.attributes('aria-labelledby')).toBe(box.get('[data-test="inv-confirm-title"]').attributes('id'))
  })

  it('標題前有資訊圖示、沒有專用帳號的提醒前有警示圖示，皆為裝飾性', async () => {
    const w = mountConfirm({ noExecutor: true })
    await open(w)
    const t = w.get('[data-test="inv-confirm-title"] [data-test="inv-confirm-title-icon"]')
    expect(t.attributes('aria-hidden')).toBe('true')
    const a = w.get('[data-test="inv-confirm-no-executor"] [data-test="inv-confirm-warn-icon"]')
    expect(a.attributes('aria-hidden')).toBe('true')
    const w2 = mountConfirm()
    await open(w2)
    expect(w2.find('[data-test="inv-confirm-warn-icon"]').exists()).toBe(false)
  })

  it('沒有專用帳號時多一句提醒；首次登入與讀不到指紋各自一句', async () => {
    const w = mountConfirm({ noExecutor: true, fingerprint: 'none' })
    await open(w)
    expect(w.get('[data-test="inv-confirm-no-executor"]').text()).toBe('這台沒有設定堡壘機專用帳號，部分設定可能讀不到，結果會標示「可能不完整」。')
    expect(w.get('[data-test="inv-fingerprint-line"]').text()).toBe('這台還沒有記錄主機指紋，這次登入會記下目前的指紋。')
    expect(w.find('[data-test="inv-fingerprint-unknown"]').exists()).toBe(false)
    const w2 = mountConfirm({ fingerprint: 'unknown' })
    await open(w2)
    expect(w2.find('[data-test="inv-fingerprint-unknown"]').exists()).toBe(true)
    expect(w2.find('[data-test="inv-confirm-no-executor"]').exists()).toBe(false)
  })

  it('開啟後焦點進確認框；確認後發出 confirm 並收起', async () => {
    const w = mountConfirm()
    await open(w)
    expect(document.activeElement).toBe(w.get('[data-test="inv-confirm"]').element)
    await w.get('[data-test="inv-confirm-ok"]').trigger('click')
    await flushPromises()
    expect(w.emitted('confirm')).toHaveLength(1)
    expect(w.get('[data-test="inv-confirm"]').isVisible()).toBe(false)
  })

  it('取消與 Esc 都不發 confirm，並把焦點還給原按鈕', async () => {
    const w = mountConfirm()
    await open(w)
    await w.get('[data-test="inv-confirm-cancel"]').trigger('click')
    await flushPromises()
    expect(w.emitted('confirm')).toBeUndefined()
    expect(w.get('[data-test="inv-confirm"]').isVisible()).toBe(false)
    expect(document.activeElement).toBe(startBtn(w).element)

    await open(w)
    expect(document.activeElement).toBe(w.get('[data-test="inv-confirm"]').element)
    await w.get('[data-test="inv-confirm"]').trigger('keydown', { key: 'Escape' })
    await flushPromises()
    expect(w.emitted('confirm')).toBeUndefined()
    expect(w.get('[data-test="inv-confirm"]').isVisible()).toBe(false)
    expect(document.activeElement).toBe(startBtn(w).element)
  })

  it('點確認框外面會收起且不發 confirm', async () => {
    const w = mountConfirm()
    await open(w)
    document.body.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }))
    document.body.dispatchEvent(new MouseEvent('mouseup', { bubbles: true }))
    document.body.dispatchEvent(new MouseEvent('click', { bubbles: true }))
    await new Promise((r) => setTimeout(r, 400))
    await flushPromises()
    expect(w.emitted('confirm')).toBeUndefined()
    expect(w.get('[data-test="inv-confirm"]').isVisible()).toBe(false)
  })

  it('停用時按鈕為原生 disabled', async () => {
    const w = mountConfirm({ disabled: true })
    expect(startBtn(w).attributes('disabled')).toBeDefined()
  })
})

describe('HostInventoryStatusCard 發起鈕停用原因（兩種身分都沒有）', () => {
  const card = (props) =>
    mount(HostInventoryStatusCard, { props: { scan: null, ...props }, global: { plugins: [ElementPlus] } })

  it('原因寫在按鈕下方，沒有任何身分時帶「前往帳號設定」連結，點了發出 goto', async () => {
    const w = card({ blockedReason: '這台沒有堡壘機專用帳號，也沒有預設帳號，盤點沒有帳號可以登入。', blockedGoAccounts: true })
    expect(w.get('[data-test="inv-start-blocked"]').text()).toContain('盤點沒有帳號可以登入')
    const link = w.get('[data-test="inv-blocked-go-accounts"]')
    expect(link.text()).toBe('前往帳號設定')
    await link.trigger('click')
    expect(w.emitted('goto')[0]).toEqual(['accounts'])
  })

  it('只支援 Linux／Unix 這類原因沒有連結；沒有原因就不出現', () => {
    const w = card({ blockedReason: '只支援 Linux / Unix 主機，這台無法盤點。' })
    expect(w.find('[data-test="inv-blocked-go-accounts"]').exists()).toBe(false)
    expect(card({}).find('[data-test="inv-start-blocked"]').exists()).toBe(false)
  })
})
