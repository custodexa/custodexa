// 鍵盤紀錄入口與理由對話框：無權限不渲染、無可查看內容不開理由框、理由驗證、錯誤就地呈現、成功交接。
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import { setCapabilitiesForTests, resetCapabilities } from '@/composables/useCapabilities'
import { takeKeystrokeView } from '@/utils/keystrokeView'

enableAutoUnmount(afterEach)
class MutationObserverStub { observe() {} disconnect() {} takeRecords() { return [] } }
vi.stubGlobal('MutationObserver', MutationObserverStub)

const metaMock = vi.fn()
const viewMock = vi.fn()
const push = vi.fn()
vi.mock('@/api/keystrokes', () => ({
  getKeystrokeMeta: (...a) => metaMock(...a),
  viewKeystrokes: (...a) => viewMock(...a),
}))
vi.mock('vue-router', () => ({ useRouter: () => ({ push }), useRoute: () => ({ params: { id: '9' } }) }))

import KeystrokeEntry from '../KeystrokeEntry.vue'

const mountEntry = () => mount(KeystrokeEntry, {
  props: { sessionId: 9 },
  global: { plugins: [ElementPlus] },
  attachTo: document.body,
})
const apiError = (status, code) => Object.assign(new Error('x'), { response: { status, data: { code } } })

beforeEach(() => {
  metaMock.mockReset(); viewMock.mockReset(); push.mockReset()
  setCapabilitiesForTests(['session:view', 'keystroke:view'])
})
afterEach(() => { resetCapabilities() })

describe('KeystrokeEntry', () => {
  it('沒有 keystroke:view 不渲染入口，也不查中繼資料', async () => {
    setCapabilitiesForTests(['session:view'])
    const w = mountEntry()
    await flushPromises()
    expect(w.find('[data-test="keystroke-entry"]').exists()).toBe(false)
    expect(metaMock).not.toHaveBeenCalled()
  })

  it('viewable=false 直接顯示狀態說明，不開理由對話框', async () => {
    metaMock.mockResolvedValue({ data: { state: 'not_covered', coverage_reason: 'db_console', viewable: false } })
    const w = mountEntry()
    await w.find('[data-test="keystroke-entry"]').trigger('click')
    await flushPromises()
    expect(document.body.textContent).toContain('不另外記錄鍵盤輸入')
    expect(document.body.textContent).not.toContain('指令記錄中')
    expect(document.querySelector('[data-test="keystroke-reason-input"]')).toBeNull()
  })

  it('failed 且無檔案（viewable=false）顯示原因，不開理由框', async () => {
    metaMock.mockResolvedValue({ data: { state: 'failed', viewable: false, failure_cause: 'KEYSTROKE_DIR_UNWRITABLE' } })
    const w = mountEntry()
    await w.find('[data-test="keystroke-entry"]').trigger('click')
    await flushPromises()
    expect(document.body.textContent).toContain('紀錄存放位置無法寫入')
    expect(document.querySelector('[data-test="keystroke-reason-input"]')).toBeNull()
  })

  it('viewable=true 開理由框；空白送出顯示錯誤且不發請求', async () => {
    metaMock.mockResolvedValue({ data: { state: 'complete', viewable: true } })
    const w = mountEntry()
    await w.find('[data-test="keystroke-entry"]').trigger('click')
    await flushPromises()
    document.querySelector('[data-test="keystroke-reason-submit"]').click()
    await flushPromises()
    expect(document.querySelector('[data-test="keystroke-reason-error"]').textContent).toContain('請寫下查看理由')
    expect(viewMock).not.toHaveBeenCalled()
  })

  it('超過 1000 字顯示超出字數且不送出', async () => {
    metaMock.mockResolvedValue({ data: { state: 'complete', viewable: true } })
    const w = mountEntry()
    await w.find('[data-test="keystroke-entry"]').trigger('click')
    await flushPromises()
    const ta = document.querySelector('[data-test="keystroke-reason-input"] textarea') || document.querySelector('textarea')
    ta.value = '字'.repeat(1003)
    ta.dispatchEvent(new Event('input'))
    await flushPromises()
    document.querySelector('[data-test="keystroke-reason-submit"]').click()
    await flushPromises()
    expect(document.querySelector('[data-test="keystroke-reason-error"]').textContent).toContain('多了 3 字')
    expect(viewMock).not.toHaveBeenCalled()
  })

  it('成功：理由放本文、經記憶體交接並導向檢視頁', async () => {
    metaMock.mockResolvedValue({ data: { state: 'complete', viewable: true } })
    viewMock.mockResolvedValue({ data: { events: [], integrity: 'complete', record_status: 'complete' } })
    const w = mountEntry()
    await w.find('[data-test="keystroke-entry"]').trigger('click')
    await flushPromises()
    const ta = document.querySelector('textarea')
    ta.value = '  追查事件單  '
    ta.dispatchEvent(new Event('input'))
    await flushPromises()
    document.querySelector('[data-test="keystroke-reason-submit"]').click()
    await flushPromises()
    expect(viewMock).toHaveBeenCalledWith(9, { reason: '追查事件單' })
    expect(push).toHaveBeenCalledWith({ name: 'KeystrokeViewer', params: { id: '9' } })
    const held = takeKeystrokeView(9)
    expect(held.reason).toBe('追查事件單')
    expect(JSON.stringify(window.location)).not.toContain('追查')
  })

  it('金鑰未解封：錯誤留在對話框、保留理由、可再試', async () => {
    metaMock.mockResolvedValue({ data: { state: 'complete', viewable: true } })
    viewMock.mockRejectedValue(apiError(409, 'RULE_KEYSTROKE_VAULT_SEALED'))
    const w = mountEntry()
    await w.find('[data-test="keystroke-entry"]').trigger('click')
    await flushPromises()
    const ta = document.querySelector('textarea')
    ta.value = '調查'
    ta.dispatchEvent(new Event('input'))
    await flushPromises()
    document.querySelector('[data-test="keystroke-reason-submit"]').click()
    await flushPromises()
    expect(document.querySelector('[data-test="keystroke-reason-failure"]').textContent).toContain('尚未解封')
    expect(document.querySelector('textarea').value).toBe('調查')
    expect(push).not.toHaveBeenCalled()
  })

  it('無法驗證：只給關閉、不給再試', async () => {
    metaMock.mockResolvedValue({ data: { state: 'complete', viewable: true } })
    viewMock.mockRejectedValue(apiError(422, 'RULE_KEYSTROKE_RECORD_REJECTED'))
    const w = mountEntry()
    await w.find('[data-test="keystroke-entry"]').trigger('click')
    await flushPromises()
    const ta = document.querySelector('textarea')
    ta.value = '調查'
    ta.dispatchEvent(new Event('input'))
    await flushPromises()
    document.querySelector('[data-test="keystroke-reason-submit"]').click()
    await flushPromises()
    expect(document.querySelector('[data-test="keystroke-reason-failure"]').textContent).toContain('無法通過驗證')
    expect(document.querySelector('[data-test="keystroke-reason-submit"]')).toBeNull()
  })
})
