import { describe, it, expect, afterEach } from 'vitest'
import { mount, enableAutoUnmount } from '@vue/test-utils'
import DailyReviewSignedCompare from '../DailyReviewSignedCompare.vue'

enableAutoUnmount(afterEach)

const list = (total) => ({ total, items: [], source_status: 'complete' })

const snapshot = (high, extra = {}) => ({
  date: '2026-10-01',
  login_failures: 0,
  login_failures_source: 'complete',
  high_risk_ops: high,
  high_risk_ops_source: 'complete',
  unreviewed_alerts: 0,
  alerts_total: 0,
  alerts_source: 'complete',
  ...extra,
})

const detail = (high, criteria) => ({
  counts: { alerts_total: 0, alerts_source: 'complete', high_risk_criteria: criteria },
  login_failures: list(0),
  high_risk_ops: list(high),
  alerts_after_sign: 0,
})

const mountCompare = (signedSnapshot, d) =>
  mount(DailyReviewSignedCompare, { props: { signedSnapshot, detail: d } })

describe('DailyReviewSignedCompare', () => {
  // 擋：判準調整造成的計數差被著成「與簽核時不同」的警示色，讓人以為紀錄被改過
  it('舊快照（無版本鍵）對現行版本 2：高危列不著色、標「口徑已調整」並顯示說明', () => {
    const wrapper = mountCompare(snapshot(5), detail(1, 2))
    const high = wrapper.find('[data-test="dr-compare-now-high"]')
    expect(high.text()).toBe('1')
    expect(wrapper.find('.dr-compare__diff').exists()).toBe(false)
    expect(wrapper.find('[data-test="dr-compare-criteria-tag"]').text()).toBe('口徑已調整')
    expect(wrapper.find('[data-test="dr-compare-criteria"]').text()).toContain('簽核後高危操作的計算口徑已調整')
  })

  it('同版本 5 對 4：照舊著色，不顯示口徑說明', () => {
    const wrapper = mountCompare(snapshot(5, { high_risk_criteria: 2 }), detail(4, 2))
    expect(wrapper.find('[data-test="dr-compare-now-high"]').classes()).toContain('dr-compare__diff')
    expect(wrapper.find('[data-test="dr-compare-criteria"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="dr-compare-criteria-tag"]').exists()).toBe(false)
  })

  it('兩邊都沒有版本鍵視為同為版本 1，行為與改動前相同', () => {
    const wrapper = mountCompare(snapshot(5), detail(4, undefined))
    expect(wrapper.find('[data-test="dr-compare-now-high"]').classes()).toContain('dr-compare__diff')
    expect(wrapper.find('[data-test="dr-compare-criteria"]').exists()).toBe(false)
  })

  it('口徑不同時登入失敗列仍照常比對著色', () => {
    const wrapper = mountCompare(snapshot(5, { login_failures: 2 }), {
      ...detail(1, 2),
      login_failures: list(3),
    })
    expect(wrapper.find('[data-test="dr-compare-now-login"]').classes()).toContain('dr-compare__diff')
    expect(wrapper.find('[data-test="dr-compare-now-high"]').classes()).not.toContain('dr-compare__diff')
  })
})
