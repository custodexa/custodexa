import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import SecurityPolicies from '../SecurityPolicies.vue'
import { SECURITY_SECTIONS } from '@/constants/policyDomains'

// 逐測卸載：避免殘留元件在 document 上累積
enableAutoUnmount(afterEach)

const getPoliciesMock = vi.fn()
const updatePoliciesMock = vi.fn()
const previewComplianceMock = vi.fn()
const previewApplyMock = vi.fn()

vi.mock('@/api/securityPolicies', () => ({
  getSecurityPolicies: (...args) => getPoliciesMock(...args),
  updateSecurityPolicies: (...args) => updatePoliciesMock(...args),
  previewCompliance: (...args) => previewComplianceMock(...args),
  previewApplyPolicies: (...args) => previewApplyMock(...args),
}))

const getDailyReviewStatusMock = vi.fn(() => Promise.resolve({ data: { enabled: false, timezone_state: null } }))
vi.mock('@/api/dailyReviews', () => ({
  getDailyReviewStatus: (...args) => getDailyReviewStatusMock(...args),
}))

const getSyslogMock = vi.fn()
vi.mock('@/api/syslogSettings', () => ({
  getSyslogSettings: (...args) => getSyslogMock(...args),
  updateSyslogSettings: vi.fn(),
  testSyslogSettings: vi.fn(),
}))

const policy = (key) => ({
  key,
  type: 'int',
  default: '1',
  label: key,
  unit: '',
  value: '1',
  verdicts: [],
})

const allKeys = SECURITY_SECTIONS.flatMap((s) => s.keys)
const response = (keys, extra = []) => ({
  data: [...keys, ...extra].map(policy),
  groups: [],
})

// 可驅動的 IntersectionObserver：測試自行回報哪張卡片進入畫面
let observers = []
class FakeIntersectionObserver {
  constructor(cb) {
    this.cb = cb
    this.targets = []
    observers.push(this)
  }
  observe(el) {
    this.targets.push(el)
  }
  disconnect() {
    this.targets = []
  }
  unobserve() {}
}

const mountPage = async () => {
  const wrapper = mount(SecurityPolicies, {
    attachTo: document.body,
    global: { plugins: [ElementPlus] },
  })
  await flushPromises()
  return wrapper
}

const navIds = (wrapper) =>
  wrapper.findAll('[data-test="policy-section-nav"] button').map((b) => b.attributes('data-nav-id'))
const cardIds = (wrapper) => wrapper.findAll('.policy-card[data-section-id]').map((c) => c.attributes('data-section-id'))

describe('SecurityPolicies 分區導覽', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    observers = []
    vi.stubGlobal('IntersectionObserver', FakeIntersectionObserver)
    Element.prototype.scrollIntoView = vi.fn()
    previewComplianceMock.mockResolvedValue({ data: { draft: true, verdicts: [] } })
    getSyslogMock.mockResolvedValue({
      data: { dropped: 0, setting: { enabled: false, host: '', port: 514, protocol: 'udp', tls_ca: '' } },
    })
    getPoliciesMock.mockResolvedValue(response(allKeys))
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('八區全有時導覽項目與頁面卡片逐項相同，文字等於卡片標題', async () => {
    const wrapper = await mountPage()
    const ids = navIds(wrapper)
    expect(ids).toHaveLength(8)
    expect(ids).toEqual(cardIds(wrapper))
    expect(ids).toEqual(SECURITY_SECTIONS.map((s) => s.id))
    const navTexts = wrapper.findAll('[data-test="policy-section-nav"] button').map((b) => b.text())
    const titles = wrapper.findAll('.policy-card[data-section-id] .card-title').map((c) => c.text())
    expect(navTexts).toEqual(titles)
  })

  it('回應拿掉叢集存取的鍵時頁面與導覽都沒有 cluster，其餘七項不變', async () => {
    getPoliciesMock.mockResolvedValue(response(allKeys.filter((k) => k !== 'k8s_list_timeout_seconds')))
    const wrapper = await mountPage()
    const ids = navIds(wrapper)
    expect(ids).not.toContain('cluster')
    expect(cardIds(wrapper)).not.toContain('cluster')
    expect(ids).toEqual(SECURITY_SECTIONS.map((s) => s.id).filter((id) => id !== 'cluster'))
    expect(ids).toHaveLength(7)
    expect(ids).toEqual(cardIds(wrapper))
  })

  it('多一個未歸任何設定頁的鍵時導覽最後一項為其他', async () => {
    getPoliciesMock.mockResolvedValue(response(allKeys, ['zz_unassigned_probe_key']))
    const wrapper = await mountPage()
    const ids = navIds(wrapper)
    expect(ids.at(-1)).toBe('rest')
    expect(wrapper.findAll('[data-test="policy-section-nav"] button').at(-1).text()).toBe('其他')
    expect(ids).toEqual(cardIds(wrapper))
  })

  it('導覽不發任何請求：點選前後政策、判定與 syslog 的請求數相同', async () => {
    const wrapper = await mountPage()
    const counts = () => [
      getPoliciesMock.mock.calls.length,
      updatePoliciesMock.mock.calls.length,
      previewComplianceMock.mock.calls.length,
      previewApplyMock.mock.calls.length,
      getSyslogMock.mock.calls.length,
    ]
    const before = counts()
    for (const id of navIds(wrapper)) {
      await wrapper.find(`[data-test="section-nav-${id}"]`).trigger('click')
    }
    await flushPromises()
    expect(counts()).toEqual(before)
    expect(updatePoliciesMock).not.toHaveBeenCalled()
  })

  it('點「日誌保留與審閱」時對應卡片捲動一次、該項標示目前位置、其餘項沒有', async () => {
    const wrapper = await mountPage()
    Element.prototype.scrollIntoView.mockClear()
    const target = wrapper.find('[data-test="section-nav-log_retention"]')
    expect(target.text()).toBe('日誌保留與審閱')
    await target.trigger('click')
    expect(Element.prototype.scrollIntoView).toHaveBeenCalledTimes(1)
    const card = wrapper.find('.policy-card[data-section-id="log_retention"]').element
    expect(Element.prototype.scrollIntoView.mock.instances[0]).toBe(card)
    expect(target.attributes('aria-current')).toBe('location')
    const others = wrapper
      .findAll('[data-test="policy-section-nav"] button')
      .filter((b) => b.attributes('data-nav-id') !== 'log_retention')
    others.forEach((b) => expect(b.attributes('aria-current')).toBeUndefined())
  })

  it('IntersectionObserver 回報密碼政策進入畫面時目前位置改為該項', async () => {
    const wrapper = await mountPage()
    const obs = observers.find((o) => o.targets.length > 0)
    expect(obs).toBeTruthy()
    const passwordCard = obs.targets.find((el) => el.getAttribute('data-section-id') === 'password')
    obs.cb([{ target: passwordCard, isIntersecting: true }])
    await flushPromises()
    const current = wrapper
      .findAll('[data-test="policy-section-nav"] button')
      .filter((b) => b.attributes('aria-current') === 'location')
    expect(current).toHaveLength(1)
    expect(current[0].attributes('data-nav-id')).toBe('password')
  })

  it('導覽為具無障礙名稱的 nav，項目為 button，方向鍵移動焦點、Enter 觸發捲動', async () => {
    const wrapper = await mountPage()
    const nav = wrapper.find('nav[data-test="policy-section-nav"]')
    expect(nav.exists()).toBe(true)
    expect(nav.attributes('aria-label')).toBe('安全政策分區')
    const buttons = nav.findAll('button')
    expect(buttons.length).toBe(8)
    buttons[0].element.focus()
    await buttons[0].trigger('keydown', { key: 'ArrowDown' })
    expect(document.activeElement).toBe(buttons[1].element)
    await buttons[1].trigger('keydown', { key: 'ArrowDown' })
    expect(document.activeElement).toBe(buttons[2].element)
    await buttons[2].trigger('keydown', { key: 'ArrowUp' })
    expect(document.activeElement).toBe(buttons[1].element)
    Element.prototype.scrollIntoView.mockClear()
    await buttons[1].trigger('keydown', { key: 'Enter' })
    expect(Element.prototype.scrollIntoView).toHaveBeenCalledTimes(1)
  })
})
