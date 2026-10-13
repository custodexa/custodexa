// 最近一次登入嘗試：第一層只放白話原因與建議，第二層放機器碼與提供者自報說明（純文字）。
import { describe, it, expect, afterEach } from 'vitest'
import { mount, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import i18n from '@/i18n'
import PreflightLastAttempt from '../PreflightLastAttempt.vue'

enableAutoUnmount(afterEach)

const t = (key, params) => i18n.global.t(key, params)
const A = 'identitySources.preflight.attempt.'
const AT = '2026-10-13T06:28:00Z'

// 與後端 AttemptReasonCodes 對齊的 21 個原因碼
const REASON_CODES = [
  'success', 'pending_mfa', 'pending_mfa_enrollment', 'pending_password_change', 'source_denied',
  'admission_tid', 'admission_hd', 'admission_email_domain', 'admission_email_verified',
  'admission_not_prebound', 'admission_rules_noncompliant', 'code_exchange_failed', 'id_token_missing',
  'id_token_invalid', 'provider_unavailable', 'internal_error', 'provider_error', 'username_conflict',
  'account_removed', 'user_inactive', 'unknown',
]
const RULES_DETAILS = ['shared_needs_org_rule', 'empty_rule_set', 'consumer_tenant', 'email_needs_verified',
  'unknown_rule', 'invalid_rules', 'other']
const PROVIDER_DETAILS = ['access_denied', 'invalid_scope', 'unauthorized_client', 'server_error',
  'temporarily_unavailable', 'login_required', 'interaction_required', 'consent_required', 'other']

const outcomeOf = (code) =>
  code === 'success' ? 'success' : code.startsWith('pending_') ? 'pending' : 'failed'

const mountWith = (attempt) =>
  mount(PreflightLastAttempt, { props: { attempt, windowDays: 30 }, global: { plugins: [ElementPlus] } })

const openDetails = async (w) => {
  await w.find('[data-test="attempt-details-toggle"]').trigger('click')
}

// 單一成因的錯誤說法：沒有紀錄不足以斷定是提供者擋下
const SINGLE_CAUSE = /表示提供者在其頁面擋下/

describe('PreflightLastAttempt', () => {
  it('每個原因碼都渲染對應的第一層文案', () => {
    expect(REASON_CODES).toHaveLength(21)
    for (const code of REASON_CODES) {
      const w = mountWith({ at: AT, outcome: outcomeOf(code), reason_code: code, reason_detail: '', username: 'u' })
      const text = w.text()
      if (code === 'success') {
        // 成功時標籤已表達結果，不重複「登入成功」
        expect(w.find('[data-test="attempt-reason"]').exists(), code).toBe(false)
        expect(w.find('[data-test="attempt-label"]').text()).toBe(t(`${A}label.success`))
      } else if (code === 'provider_error') {
        expect(text, code).toContain(t(`${A}detail.provider_error.other`))
      } else if (code === 'admission_rules_noncompliant') {
        expect(text, code).toContain(t(`${A}reason.admission_rules_noncompliant`, {
          detail: t(`${A}detail.admission_rules_noncompliant.other`),
        }))
      } else {
        expect(w.find('[data-test="attempt-reason"]').text(), code).toBe(t(`${A}reason.${code}`))
      }
      w.unmount()
    }
  })

  it('提供者自報說明含標記時只以純文字呈現', async () => {
    const payload = '<img src=x onerror=alert(1)>'
    const w = mountWith({
      at: AT, outcome: 'denied', reason_code: 'provider_error', reason_detail: 'access_denied',
      provider_error: 'access_denied', provider_error_description: payload,
    })
    await openDetails(w)
    expect(w.findAll('img').length).toBe(0)
    expect(w.find('[data-test="attempt-detail-providerDescription"]').text()).toBe(payload)
  })

  it('准入規則不合規的每個子碼渲染對應說明', () => {
    for (const sub of RULES_DETAILS) {
      const w = mountWith({ at: AT, outcome: 'denied', reason_code: 'admission_rules_noncompliant', reason_detail: sub })
      expect(w.find('[data-test="attempt-reason"]').text(), sub).toContain(t(`${A}detail.admission_rules_noncompliant.${sub}`))
      w.unmount()
    }
  })

  it('提供者錯誤的每個代碼渲染對應說明；other 時第二層顯示原碼', async () => {
    for (const sub of PROVIDER_DETAILS) {
      const raw = sub === 'other' ? 'invalid_request' : sub
      const w = mountWith({ at: AT, outcome: 'denied', reason_code: 'provider_error', reason_detail: sub, provider_error: raw })
      expect(w.find('[data-test="attempt-reason"]').text(), sub).toBe(t(`${A}detail.provider_error.${sub}`))
      expect(w.find('[data-test="attempt-advice"]').text(), sub).toBe(t(`${A}providerAdvice.${sub}`))
      if (sub === 'other') {
        await openDetails(w)
        expect(w.find('[data-test="attempt-detail-providerCode"]').text()).toBe('invalid_request')
        expect(w.find('[data-test="attempt-label"]').text()).toBe(t(`${A}label.providerError`))
      }
      w.unmount()
    }
  })

  it('unknown 帶事件名時第二層顯示事件名；沒帶時沒有第二層', async () => {
    let w = mountWith({ at: AT, outcome: 'failed', reason_code: 'unknown', event: 'oidc_callback_rejected' })
    await openDetails(w)
    expect(w.find('[data-test="attempt-detail-event"]').text()).toBe('oidc_callback_rejected')
    w.unmount()
    w = mountWith({ at: AT, outcome: 'failed', reason_code: 'unknown' })
    expect(w.find('[data-test="attempt-details-toggle"]').exists()).toBe(false)
  })

  it('null：顯示時間範圍與三點可能原因，不含單一成因句', () => {
    const w = mountWith(null)
    expect(w.find('[data-test="attempt-none"]').text()).toBe(t(`${A}none`, { days: 30 }))
    const missing = w.find('[data-test="attempt-missing"]')
    expect(missing.findAll('li')).toHaveLength(3)
    expect(w.find('[data-test="attempt-compare-time"]').exists()).toBe(false)
    expect(w.text()).not.toMatch(SINGLE_CAUSE)
  })

  it('有紀錄：顯示紀錄，展開後先請比對時間並列同三點，不含單一成因句', async () => {
    const w = mountWith({ at: AT, outcome: 'success', reason_code: 'success', username: 'lin.wei' })
    expect(w.text()).toContain('lin.wei')
    expect(w.find('[data-test="attempt-missing"]').exists()).toBe(false)
    await w.find('[data-test="attempt-missing-toggle"]').trigger('click')
    expect(w.find('[data-test="attempt-compare-time"]').text()).toBe(t(`${A}compareTime`))
    expect(w.find('[data-test="attempt-missing"]').findAll('li')).toHaveLength(3)
    expect(w.text()).not.toMatch(SINGLE_CAUSE)
  })
})
