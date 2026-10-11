import { describe, it, expect, afterEach } from 'vitest'
import { mount, enableAutoUnmount, RouterLinkStub } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import SignoffRecordFacts from '../SignoffRecordFacts.vue'

// 10.4.1 條文列下方的運作紀錄。後端判定與數字照收不重算；本檔釘住四種呈現
// 各自說對的話——尤其「資料不足」依理由碼分兩種說法。

enableAutoUnmount(afterEach)

const record = (over = {}) => ({
  from: '2026-09-11',
  to: '2026-10-10',
  as_of: '2026-10-11T04:00:00Z',
  timezone: 'Asia/Taipei',
  required: 29,
  on_time: 22,
  late: 3,
  unsigned: 4,
  sign_rate_percent: 86,
  inferred_days: 0,
  enabled_since: '2026-08-31T16:00:00Z',
  enabled_since_inferred: false,
  enabled_days: 40,
  earliest_unsigned: '2026-10-06',
  ...over,
})

const verdict = (over = {}) => ({
  key: 'daily_review_enabled',
  group_code: 'pci_dss_4_0_1',
  clause_no: '10.4.1',
  comparator: 'signoff_record',
  current: 'true',
  expected: 'true',
  result: 'deviating',
  reason: 'signoff_unsigned_days',
  signoff: record(),
  ...over,
})

const mountFacts = (v) =>
  mount(SignoffRecordFacts, {
    props: { verdict: v, builtAt: '2026-10-11T04:00:00Z' },
    global: { plugins: [ElementPlus], stubs: { RouterLink: RouterLinkStub } },
  })

describe('SignoffRecordFacts 10.4.1 運作紀錄', () => {
  it('10.4.1 偏離時顯示未簽天數與補簽入口、關閉時不顯示簽核率', () => {
    const w = mountFacts(verdict())
    expect(w.find('[data-test="signoff-rate"]').text()).toContain('86%（25 / 29 天）')
    expect(w.find('[data-test="signoff-rate"]').text()).toContain('2026-09-11 至 2026-10-10')
    expect(w.find('[data-test="signoff-unsigned"]').text()).toContain('4 天')
    expect(w.find('[data-test="signoff-late"]').text()).toContain('3 次')
    expect(w.find('[data-test="signoff-unsigned-note"]').text()).toContain('有 4 天尚未簽核（最早 2026-10-06）')
    const link = w.findComponent(RouterLinkStub)
    expect(link.props('to')).toEqual({ path: '/audit-logs', query: { tab: 'reviews', date: '2026-10-06' } })

    const off = mountFacts(verdict({ current: 'false', reason: 'daily_review_disabled', signoff: undefined }))
    expect(off.find('[data-test="signoff-setting"]').text()).toBe('每日審閱簽核未開啟')
    expect(off.find('[data-test="signoff-rate"]').exists()).toBe(false)
    expect(off.find('[data-test="signoff-unsigned-note"]').exists()).toBe(false)
    expect(off.text()).not.toContain('%')
  })

  it('符合時不出補簽入口，遲簽只計數', () => {
    const w = mountFacts(verdict({ result: 'compliant', reason: 'meets_expectation',
      signoff: record({ on_time: 27, late: 2, unsigned: 0, sign_rate_percent: 100, earliest_unsigned: undefined }) }))
    expect(w.find('[data-test="signoff-rate"]').text()).toContain('100%（29 / 29 天）')
    expect(w.find('[data-test="signoff-late"]').text()).toContain('2 次')
    expect(w.find('[data-test="signoff-unsigned-note"]').exists()).toBe(false)
  })

  // 擋：來源故障被說成開啟未滿 7 天，使用者被引導等待而不知道是查詢問題
  it('資料不足依理由分支', async () => {
    const short = mountFacts(verdict({ result: 'insufficient_data', reason: 'signoff_insufficient_data',
      signoff: record({ required: 2, on_time: 2, late: 0, unsigned: 0, sign_rate_percent: 100,
        enabled_since: '2026-10-07T16:00:00Z', enabled_days: 3, earliest_unsigned: undefined }) }))
    expect(short.find('[data-test="signoff-enabled-since"]').text()).toContain('2026-10-08')
    // 已累計照畫布寫起訖（開啟日所屬日至昨日），同年省略年份；已簽天數照規格保留
    expect(short.find('[data-test="signoff-enabled-days"]').text()).toContain('3 天（10-08 至 10-10，已簽 2 天）')
    expect(short.find('[data-test="signoff-insufficient-note"]').text()).toContain('累計滿 7 天後自動判定')
    expect(short.find('[data-test="signoff-rate"]').exists()).toBe(false)

    const down = mountFacts(verdict({ result: 'insufficient_data', reason: 'signoff_source_unavailable', signoff: undefined }))
    expect(down.find('[data-test="signoff-unavailable-note"]').text()).toContain('目前無法取得每日簽核紀錄')
    expect(down.text()).not.toContain('7 天')
    expect(down.find('[data-test="signoff-enabled-since"]').exists()).toBe(false)
    expect(down.find('[data-test="signoff-enabled-days"]').exists()).toBe(false)
    expect(down.text()).not.toContain('開啟日')
    expect(down.text()).not.toContain('%')
    await down.find('[data-test="signoff-refresh"]').trigger('click')
    expect(down.emitted('refresh')).toHaveLength(1)
  })

  it('已累計：跨年寫全日期、今天才開或缺開啟日不寫起訖', () => {
    const insufficient = (over) => mountFacts(verdict({ result: 'insufficient_data',
      reason: 'signoff_insufficient_data', signoff: record({ earliest_unsigned: undefined, ...over }) }))
    const cross = insufficient({ enabled_since: '2025-12-29T16:00:00Z', enabled_days: 4, to: '2026-01-02' })
    expect(cross.find('[data-test="signoff-enabled-days"]').text()).toContain('4 天（2025-12-30 至 2026-01-02，已簽')
    const today = insufficient({ enabled_since: '2026-10-10T17:00:00Z', enabled_days: 0 })
    expect(today.find('[data-test="signoff-enabled-days"]').text()).toMatch(/^已累計0 天（已簽 \d+ 天）$/)
    const noSince = insufficient({ enabled_since: null, enabled_days: 0 })
    expect(noSince.find('[data-test="signoff-enabled-days"]').text()).not.toContain('至')
  })

  it('推定日只加說明不改結果', () => {
    const presumed = mountFacts(verdict({ signoff: record({ inferred_days: 4, earliest_unsigned: '2026-09-11' }) }))
    expect(presumed.find('[data-test="signoff-inferred-note"]').text()).toContain('其中 4 天的啟用狀態由推定而來')
    // 結果仍為偏離：未簽與補簽入口照常出現
    expect(presumed.find('[data-test="signoff-facts-measured"]').exists()).toBe(true)
    expect(presumed.find('[data-test="signoff-unsigned-note"]').text()).toContain('最早 2026-09-11')

    const plain = mountFacts(verdict())
    expect(plain.find('[data-test="signoff-inferred-note"]').exists()).toBe(false)
  })

  it('開啟日落在推定區段時旁註推定', () => {
    const w = mountFacts(verdict({ result: 'insufficient_data', reason: 'signoff_insufficient_data',
      signoff: record({ enabled_days: 3, enabled_since: '2026-10-07T16:00:00Z', enabled_since_inferred: true }) }))
    expect(w.find('[data-test="signoff-enabled-since"]').text()).toContain('2026-10-08（推定）')
  })
})
