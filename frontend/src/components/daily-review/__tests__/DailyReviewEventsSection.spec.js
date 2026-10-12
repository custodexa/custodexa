import { describe, it, expect, afterEach } from 'vitest'
import { mount, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import DailyReviewEventsSection from '../DailyReviewEventsSection.vue'

enableAutoUnmount(afterEach)

const mountSection = (kind, items) =>
  mount(DailyReviewEventsSection, {
    props: {
      kind,
      list: { total: items.length, items, source_status: 'complete' },
      count: items.length,
      timezone: 'UTC',
      windowStart: '2026-10-07T00:00:00Z',
      windowEnd: '2026-10-08T00:00:00Z',
    },
    global: { plugins: [ElementPlus] },
  })

const row = (id, extra) => ({
  id,
  created_at: '2026-10-07T01:00:00Z',
  username: 'system',
  client_ip: '',
  path: '',
  error_msg: '',
  action: 'delete',
  resource: 'retention',
  ...extra,
})

describe('DailyReviewEventsSection', () => {
  // 擋：沒有路徑的系統紀錄在抽屜裡是一格空白
  it('沒有路徑的系統紀錄顯示原因句', () => {
    const wrapper = mountSection('high_risk_ops', [
      row(1, { reason_code: 'retention_purge', reason_params: { target: 'audit_logs', days: '180', deleted: '42' } }),
      row(2, { path: '/api/v1/assets/7', action: 'delete', resource: 'asset' }),
    ])
    const cells = wrapper.findAll('[data-test="dr-events-reason"]')
    expect(cells).toHaveLength(2)
    expect(cells[0].text()).toBe('保留期限清除：操作日誌超過 180 天的資料，刪除 42 筆')
    expect(cells[1].text()).toBe('/api/v1/assets/7')
    for (const cell of cells) expect(cell.text().trim()).not.toBe('')
    expect(wrapper.text()).not.toContain('dailyReview.reason.')
  })

  it('角色增減分兩行，第二行列出加上與移除', () => {
    const wrapper = mountSection('high_risk_ops', [
      row(3, {
        action: 'update',
        resource: 'user',
        reason_code: 'role_mapping_applied',
        reason_params: { added: 'admin', removed: '唯讀稽核' },
      }),
    ])
    const cell = wrapper.find('[data-test="dr-events-reason"]')
    expect(cell.text()).toContain('外部登入時依群組映射調整角色')
    const sub = cell.find('[data-test="dr-events-reason-sub"]')
    expect(sub.exists()).toBe(true)
    expect(sub.findAll('span').map((s) => s.text())).toEqual(['加上：管理員', '移除：唯讀稽核'])
  })

  it('高危表下方說明不計入的紀錄，登入失敗表不顯示', () => {
    const high = mountSection('high_risk_ops', [row(4, { path: '/api/v1/assets/1' })])
    expect(high.find('[data-test="dr-events-excluded"]').text()).toContain('仍可在操作日誌查到')
    const login = mountSection('login_failures', [row(5, { error_msg: 'invalid password', resource: 'auth' })])
    expect(login.find('[data-test="dr-events-excluded"]').exists()).toBe(false)
    expect(login.find('[data-test="dr-events-reason"]').text()).toBe('invalid password')
  })
})
