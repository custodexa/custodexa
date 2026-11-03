// 紀錄的傳輸風險標示：空值不渲染、認得的值有短標籤與完整說明、不認得的值原樣顯示。
import { describe, it, expect, afterEach } from 'vitest'
import { mount, enableAutoUnmount } from '@vue/test-utils'
import i18n from '@/i18n'
import TransportRiskMark from '../TransportRiskMark.vue'
import { riskLabel } from '@/utils/transportDisplay'

enableAutoUnmount(afterEach)

// el-tooltip 的內容只在滑過時掛到 body；替身把 content 就地渲染，方便斷言
const tooltipStub = {
  props: ['content', 'placement', 'popperClass'],
  template:
    '<span class="tooltip-stub" :data-placement="placement" :data-popper-class="popperClass"><slot /><span data-test="tooltip-content">{{ content }}</span></span>',
}

const mountMark = (risk) =>
  mount(TransportRiskMark, {
    props: { risk },
    global: { plugins: [i18n], stubs: { 'el-tooltip': tooltipStub } },
  })

describe('TransportRiskMark', () => {
  it('空值不渲染任何 DOM', () => {
    const w = mountMark('')
    expect(w.find('[data-test="transport-risk-mark"]').exists()).toBe(false)
    expect(w.find('[data-test="tooltip-content"]').exists()).toBe(false)
  })

  it('資料庫改密未加密：短標籤、可鍵盤聚焦，說明內含風險項的完整說明', () => {
    const w = mountMark('db_rotation_unencrypted')
    const mark = w.find('[data-test="transport-risk-mark"]')
    expect(mark.exists()).toBe(true)
    expect(mark.attributes('tabindex')).toBe('0')
    expect(mark.text()).toBe(i18n.global.t('changeSecretPlans.transportRisk.tag'))
    const full = riskLabel({ key: 'db_rotation_unencrypted' })
    const tip = w.find('[data-test="tooltip-content"]').text()
    expect(tip).toContain(full)
    expect(tip).toBe(i18n.global.t('changeSecretPlans.transportRisk.tooltip', { risk: full }))
  })

  it('不認得的非空值原樣顯示', () => {
    const w = mountMark('future_risk_key')
    const mark = w.find('[data-test="transport-risk-mark"]')
    expect(mark.exists()).toBe(true)
    expect(mark.text()).toBe('future_risk_key')
    expect(w.find('[data-test="tooltip-content"]').text()).toBe(riskLabel({ key: 'future_risk_key' }))
  })

  it('說明開在標籤下方並套限寬樣式，不蓋住同一列的結果標籤', () => {
    const w = mountMark('db_rotation_unencrypted')
    const stub = w.find('.tooltip-stub')
    expect(stub.attributes('data-placement')).toBe('bottom')
    expect(stub.attributes('data-popper-class')).toBe('transport-risk-mark-popper')
  })
})
