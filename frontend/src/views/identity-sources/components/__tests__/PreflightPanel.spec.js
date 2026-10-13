import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import i18n from '@/i18n'
import PreflightPanel from '../PreflightPanel.vue'

enableAutoUnmount(afterEach)

const statusMock = vi.fn()
vi.mock('@/api/identitySources', () => ({
  getSourceStatus: (...a) => statusMock(...a),
  isNotImplemented: () => false,
  errorCode: () => '',
  CODE_LDAP_DIRECTORY_NOT_FOUND: 'LDAP_DIRECTORY_NOT_FOUND',
}))

const providersMock = vi.fn()
vi.mock('@/api/oidc', () => ({
  getOIDCProviders: (...a) => providersMock(...a),
}))

const t = (key) => i18n.global.t(key)

const mountPanel = (props = {}) =>
  mount(PreflightPanel, {
    props: {
      type: 'oidc',
      sourceId: null,
      redirectUri: 'https://bastion.example.com/api/v1/auth/oidc/callback',
      redirectUriState: 'ready',
      ...props,
    },
    global: { plugins: [ElementPlus] },
  })

const deferred = () => {
  let resolve
  const promise = new Promise((r) => {
    resolve = r
  })
  return { promise, resolve }
}

beforeEach(() => {
  statusMock.mockReset()
  statusMock.mockResolvedValue({})
  providersMock.mockReset()
  providersMock.mockResolvedValue({ data: [] })
})

describe('PreflightPanel：OIDC 第一塊', () => {
  it('只有可複製的回呼網址與「各欄取值見左側說明」，沒有 Entra 提示', async () => {
    const wrapper = mountPanel()
    await flushPromises()

    expect(wrapper.find('[data-test="preflight-redirect"]').text()).toBe(
      'https://bastion.example.com/api/v1/auth/oidc/callback'
    )
    expect(wrapper.find('[data-test="preflight-redirect-copy"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="preflight-guide-hint"]').text()).toBe(
      t('identitySources.preflight.oidc.guideHint')
    )
    expect(wrapper.findAll('[data-test="preflight-entra-hint"]')).toHaveLength(0)
    expect(wrapper.props()).not.toHaveProperty('entra')
  })

  it('基準網址未設定：顯示未設定狀態且不給複製', async () => {
    const wrapper = mountPanel({ redirectUri: '', redirectUriState: 'base_url_unset' })
    await flushPromises()
    expect(wrapper.find('[data-test="preflight-redirect"]').text()).toBe(
      t('identitySources.preflight.oidc.redirectUnset')
    )
    expect(wrapper.find('[data-test="preflight-redirect-copy"]').exists()).toBe(false)
  })
})

describe('PreflightPanel：新增頁的回呼網址', () => {
  it('還沒有單筆詳情時，取提供者列表頂層的回呼網址並可複製', async () => {
    providersMock.mockResolvedValue({ data: [], redirect_uri: 'https://b.example.com/api/v1/auth/oidc/callback', redirect_uri_state: 'ready' })
    const wrapper = mountPanel({ redirectUri: '', redirectUriState: '' })
    await flushPromises()
    expect(providersMock).toHaveBeenCalledWith({ quiet: true })
    expect(wrapper.find('[data-test="preflight-redirect"]').text()).toBe('https://b.example.com/api/v1/auth/oidc/callback')
    expect(wrapper.find('[data-test="preflight-redirect-copy"]').exists()).toBe(true)
  })

  it('基準網址未設定：顯示未設定說明，不是「後端尚未提供」', async () => {
    providersMock.mockResolvedValue({ data: [], redirect_uri: '', redirect_uri_state: 'base_url_unset' })
    const wrapper = mountPanel({ redirectUri: '', redirectUriState: '' })
    await flushPromises()
    expect(wrapper.find('[data-test="preflight-redirect"]').text()).toBe(t('identitySources.preflight.oidc.redirectUnset'))
  })

  it('已有單筆詳情時不另打列表', async () => {
    mountPanel({ sourceId: 4 })
    await flushPromises()
    expect(providersMock).not.toHaveBeenCalled()
  })
})

describe('PreflightPanel：等待這次登入的結果', () => {
  const T1 = '2026-10-13T12:00:00Z'
  const T2 = '2026-10-13T12:05:00Z'
  const st = (at) => ({
    login_test_state: 'ready',
    login_test_url: 'https://b.example.com/login?source=oidc:4',
    last_attempt: { at, outcome: 'success', reason_code: 'success', window_days: 30 },
  })
  const A = 'identitySources.preflight.attempt.'

  beforeEach(() => {
    vi.useFakeTimers()
    vi.stubGlobal('navigator', { clipboard: { writeText: vi.fn().mockResolvedValue(undefined) } })
    statusMock.mockResolvedValue(st(T1))
  })
  afterEach(() => {
    vi.useRealTimers()
    vi.unstubAllGlobals()
  })

  const armAndReturn = async () => {
    const wrapper = mountPanel({ sourceId: 4 })
    await flushPromises()
    await wrapper.find('[data-test="login-test-copy"]').trigger('click')
    await flushPromises()
    window.dispatchEvent(new Event('focus'))
    await flushPromises()
    return wrapper
  }

  it('切回時仍是上一次嘗試：顯示等待中並每 2 秒重抓，等到新紀錄就顯示它', async () => {
    const wrapper = await armAndReturn()
    const base = statusMock.mock.calls.length
    expect(wrapper.find('[data-test="attempt-waiting"]').text()).toBe(t(`${A}waiting`))
    expect(wrapper.find('[data-test="preflight-summary"]').text()).toContain(t(`${A}waiting`))
    expect(wrapper.find('[data-test="attempt-label"]').exists()).toBe(false)

    vi.advanceTimersByTime(2000)
    await flushPromises()
    expect(statusMock.mock.calls.length).toBe(base + 1)

    statusMock.mockResolvedValue(st(T2))
    vi.advanceTimersByTime(2000)
    await flushPromises()
    expect(wrapper.find('[data-test="attempt-waiting"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="attempt-label"]').exists()).toBe(true)
    const done = statusMock.mock.calls.length
    vi.advanceTimersByTime(30000)
    await flushPromises()
    expect(statusMock.mock.calls.length).toBe(done)
  })

  it('約 15 秒仍沒有新紀錄：改說沒有收到並列三點可能原因，之後不再輪詢', async () => {
    const wrapper = await armAndReturn()
    vi.advanceTimersByTime(16000)
    await flushPromises()
    expect(wrapper.find('[data-test="attempt-timeout"]').text()).toBe(t(`${A}waitTimeout`))
    expect(wrapper.find('[data-test="attempt-missing"]').exists()).toBe(true)
    // 箭頭與自動展開同步：朝下、aria-expanded 為 true，點一下即收合
    const toggle = wrapper.find('[data-test="attempt-missing-toggle"]')
    expect(toggle.attributes('aria-expanded')).toBe('true')
    expect(toggle.find('svg').html()).toContain('chevron-down')
    await toggle.trigger('click')
    expect(toggle.attributes('aria-expanded')).toBe('false')
    expect(toggle.find('svg').html()).toContain('chevron-right')
    expect(wrapper.find('[data-test="attempt-missing"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="attempt-waiting"]').exists()).toBe(false)
    const after = statusMock.mock.calls.length
    expect(after).toBeLessThanOrEqual(10)
    vi.advanceTimersByTime(60000)
    await flushPromises()
    expect(statusMock.mock.calls.length).toBe(after)
  })

  it('沒有複製過測試連結：切回只照一般方式重抓一次，不進入等待', async () => {
    const wrapper = mountPanel({ sourceId: 4 })
    await flushPromises()
    window.dispatchEvent(new Event('focus'))
    await flushPromises()
    expect(wrapper.find('[data-test="attempt-waiting"]').exists()).toBe(false)
    vi.advanceTimersByTime(30000)
    await flushPromises()
    expect(statusMock).toHaveBeenCalledTimes(2)
  })
})

describe('PreflightPanel：刷新', () => {
  afterEach(() => {
    vi.useRealTimers()
  })

  it('按「重新整理」重抓狀態', async () => {
    const wrapper = mountPanel({ sourceId: 4 })
    await flushPromises()
    expect(statusMock).toHaveBeenCalledTimes(1)
    await wrapper.find('[data-test="preflight-refresh"]').trigger('click')
    await flushPromises()
    expect(statusMock).toHaveBeenCalledTimes(2)
  })

  it('window focus 單獨觸發即重抓', async () => {
    mountPanel({ sourceId: 4 })
    await flushPromises()
    window.dispatchEvent(new Event('focus'))
    await flushPromises()
    expect(statusMock).toHaveBeenCalledTimes(2)
  })

  it('10 秒內觸發三次（focus 與轉為可見混合）：立即一次＋期滿補抓一次', async () => {
    vi.useFakeTimers()
    mountPanel({ sourceId: 4 })
    await flushPromises()
    const base = statusMock.mock.calls.length
    Object.defineProperty(document, 'visibilityState', { configurable: true, get: () => 'visible' })

    window.dispatchEvent(new Event('focus'))
    vi.advanceTimersByTime(2000)
    document.dispatchEvent(new Event('visibilitychange'))
    vi.advanceTimersByTime(2000)
    window.dispatchEvent(new Event('focus'))
    await flushPromises()
    expect(statusMock.mock.calls.length - base).toBe(1)

    vi.advanceTimersByTime(6000)
    await flushPromises()
    expect(statusMock.mock.calls.length - base).toBe(2)

    vi.advanceTimersByTime(20000)
    await flushPromises()
    expect(statusMock.mock.calls.length - base).toBe(2)
  })

  it('兩次重抓的回覆逆序到達時畫面為較新者', async () => {
    const wrapper = mountPanel({ sourceId: 4 })
    await flushPromises()
    const older = deferred()
    const newer = deferred()
    statusMock.mockReturnValueOnce(older.promise).mockReturnValueOnce(newer.promise)
    await wrapper.find('[data-test="preflight-refresh"]').trigger('click')
    await wrapper.find('[data-test="preflight-refresh"]').trigger('click')
    newer.resolve({ rule_count: 2, enabled_rule_count: 2, last_recompute_matched_users: 5 })
    await flushPromises()
    older.resolve({ rule_count: 9, enabled_rule_count: 9, last_recompute_matched_users: 1 })
    await flushPromises()
    const rules = wrapper.find('[data-test="preflight-light-rules"]').text()
    expect(rules).toContain(i18n.global.t('identitySources.preflight.light.rulesAll', { count: 2, matched: 5 }))
  })

  it('卸載後事件不再觸發、補抓不執行', async () => {
    vi.useFakeTimers()
    const wrapper = mountPanel({ sourceId: 4 })
    await flushPromises()
    window.dispatchEvent(new Event('focus'))
    window.dispatchEvent(new Event('focus'))
    await flushPromises()
    const before = statusMock.mock.calls.length
    wrapper.unmount()
    window.dispatchEvent(new Event('focus'))
    vi.advanceTimersByTime(20000)
    await flushPromises()
    expect(statusMock.mock.calls.length).toBe(before)
  })
})
