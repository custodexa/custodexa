import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount, DOMWrapper } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import DailyReviewTimezoneField from '../DailyReviewTimezoneField.vue'
import DailyReviewTimezoneConfirm from '../DailyReviewTimezoneConfirm.vue'

enableAutoUnmount(afterEach)
vi.setConfig({ testTimeout: 20_000 })

const getDailyReviewStatusMock = vi.fn()
vi.mock('@/api/dailyReviews', () => ({
  getDailyReviewStatus: (...a) => getDailyReviewStatusMock(...a),
}))

const RouterLinkStub = {
  name: 'RouterLink',
  props: { to: { type: [String, Object], required: true } },
  template: '<a class="router-link-stub"><slot /></a>',
}

// 瀏覽器清單刻意不含 UTC（實際瀏覽器的 supportedValuesOf 也不含）
const BROWSER_ZONES = ['Asia/Taipei', 'Asia/Tokyo', 'Europe/London']

const tzState = (overrides = {}) => ({
  active: 'Asia/Taipei',
  today: { date: '2026-10-11', window_start: '2026-10-10T16:00:00Z', window_end: '2026-10-11T16:00:00Z' },
  pending: null,
  ...overrides,
})

const mountField = (props = {}) =>
  mount(DailyReviewTimezoneField, {
    props: { value: 'Asia/Taipei', enabled: true, label: '業務時區', ...props },
    global: { plugins: [ElementPlus], stubs: { RouterLink: RouterLinkStub } },
  })

// 下拉選項掛在 body
const optionTexts = () =>
  new DOMWrapper(document.body).findAll('.el-select-dropdown__item').map((n) => n.text())

describe('DailyReviewTimezoneField', () => {
  let supported

  beforeEach(() => {
    vi.clearAllMocks()
    supported = vi.spyOn(Intl, 'supportedValuesOf').mockReturnValue(BROWSER_ZONES)
    getDailyReviewStatusMock.mockResolvedValue({ data: { enabled: true, timezone_state: tzState() } })
  })

  afterEach(() => {
    supported.mockRestore()
  })

  // 防：管理員無法選回系統預設 UTC，或目前值顯示成空白
  it('選項含 UTC 與不在瀏覽器清單的目前值', async () => {
    const wrapper = mountField({ value: 'UTC' })
    await flushPromises()
    // 零位移寫成 UTC+0，不寫「UTC（UTC）」
    expect(wrapper.find('.el-select__placeholder').text()).toBe('UTC（UTC+0）')

    wrapper.findComponent({ name: 'ElSelect' }).vm.$emit('visible-change', true)
    await flushPromises()
    const options = optionTexts()
    expect(options).toContain('UTC（UTC+0）')
    expect(options).not.toContain('UTC（UTC）')
    expect(options).toContain('Asia/Taipei（UTC+8）')
    wrapper.unmount()

    // 後端目前值不在瀏覽器清單：照實列為選項並顯示
    const odd = mountField({ value: 'Etc/GMT-14' })
    await flushPromises()
    expect(odd.find('.el-select__placeholder').text()).toBe('Etc/GMT-14（UTC+14）')
    odd.findComponent({ name: 'ElSelect' }).vm.$emit('visible-change', true)
    await flushPromises()
    expect(optionTexts()).toContain('Etc/GMT-14（UTC+14）')
  })

  it('分界說明取自後端 timezone_state', async () => {
    getDailyReviewStatusMock.mockResolvedValue({
      data: { enabled: true, timezone_state: tzState({ pending: { value: 'UTC', effective_date: '2026-10-12', effective_at: '2026-10-11T16:00:00Z' } }) },
    })
    let wrapper = mountField({ value: 'UTC' })
    await flushPromises()
    const boundary = wrapper.find('[data-test="dr-tz-boundary"]').text()
    expect(boundary).toContain('2026-10-12')
    expect(boundary).toContain('UTC')
    expect(boundary).toContain('Asia/Taipei（UTC+8）')
    // 有待生效變更時只留分界說明：一般例句拿草稿值舉例會寫錯昨天的切日時區
    expect(wrapper.find('[data-test="dr-tz-explain"]').exists()).toBe(false)
    expect(wrapper.findComponent(RouterLinkStub).props('to')).toEqual({
      path: '/audit-logs',
      query: { tab: 'logs', resource: 'security_policy', key: 'daily_review_timezone' },
    })
    wrapper.unmount()

    getDailyReviewStatusMock.mockResolvedValue({ data: { enabled: true, timezone_state: tzState() } })
    wrapper = mountField()
    await flushPromises()
    expect(wrapper.find('[data-test="dr-tz-boundary"]').exists()).toBe(false)
    // 沒有待生效變更時仍有變更紀錄連結
    expect(wrapper.find('[data-test="dr-tz-log"]').exists()).toBe(true)
  })

  it('說明以昨天為例寫出切日起訖與位移', async () => {
    const wrapper = mountField()
    await flushPromises()
    expect(wrapper.find('[data-test="dr-tz-explain"]').text()).toBe(
      '每日審閱以這個時區切日：例如 2026-10-10 是 2026-10-10 00:00 到 23:59（UTC+8）。所屬日隔天結束前簽核算準時，逾期提醒在 09:00 送出。'
    )
  })

  // 防：欄位草稿改成 UTC（尚未儲存，或已存但明天才生效），例句卻說昨天以 UTC 切
  it('例句的時區取自後端目前生效值，不取欄位草稿值', async () => {
    const wrapper = mountField({ value: 'UTC' })
    await flushPromises()
    expect(wrapper.find('[data-test="dr-tz-explain"]').text()).toContain('2026-10-10 00:00 到 23:59（UTC+8）')

    getDailyReviewStatusMock.mockResolvedValue({ data: { enabled: true, timezone_state: tzState({ active: 'UTC' }) } })
    wrapper.unmount()
    const utc = mountField({ value: 'Asia/Taipei' })
    await flushPromises()
    expect(utc.find('[data-test="dr-tz-explain"]').text()).toContain('2026-10-10 00:00 到 23:59（UTC+0）')
  })

  it('開關關閉時次要呈現並註明開啟後生效，仍可修改', async () => {
    const wrapper = mountField({ enabled: false })
    await flushPromises()
    expect(wrapper.find('[data-test="dr-tz-field"]').classes()).toContain('dr-tz--inactive')
    expect(wrapper.find('[data-test="dr-tz-inactive"]').text()).toBe('開啟每日審閱簽核後生效。')
    wrapper.findComponent({ name: 'ElSelect' }).vm.$emit('update:modelValue', 'UTC')
    expect(wrapper.emitted('update:value')).toEqual([['UTC']])
  })
})

describe('DailyReviewTimezoneConfirm', () => {
  const mountConfirm = () =>
    mount(DailyReviewTimezoneConfirm, { global: { plugins: [ElementPlus] } })
  const body = () => new DOMWrapper(document.body)

  it('改時區先確認：生效日、之前不變、留稽核紀錄；取消回 false', async () => {
    const wrapper = mountConfirm()
    const answer = wrapper.vm.ask({ from: 'Asia/Taipei', to: 'UTC', state: tzState() })
    await flushPromises()
    const text = body().find('[data-test="dr-tz-confirm"]').text()
    expect(text).toContain('變更業務時區')
    expect(text).toContain('Asia/Taipei（UTC+8）')
    expect(text).toContain('從 2026-10-12 這一天起，以 UTC 切。')
    expect(text).toContain('2026-10-11 以前的日子不變')
    expect(text).toContain('當時以 UTC+8 切日')
    expect(text).toContain('這項變更會留下稽核紀錄。')
    await body().find('[data-test="dr-tz-confirm-cancel"]').trigger('click')
    expect(await answer).toBe(false)
  })

  it('改回目前生效值時說明取消待生效變更；確認回 true', async () => {
    const wrapper = mountConfirm()
    const answer = wrapper.vm.ask({
      from: 'UTC',
      to: 'Asia/Taipei',
      state: tzState({ pending: { value: 'UTC', effective_date: '2026-10-12' } }),
    })
    await flushPromises()
    const text = body().find('[data-test="dr-tz-confirm"]').text()
    expect(text).toContain('取消待生效的時區變更')
    expect(text).toContain('取消原訂 2026-10-12 起改用 UTC，維持 Asia/Taipei。')
    expect(text).toContain('UTC（UTC+0）')
    await body().find('[data-test="dr-tz-confirm-ok"]').trigger('click')
    expect(await answer).toBe(true)
  })
})
