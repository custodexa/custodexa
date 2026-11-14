import { describe, it, expect, vi, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import ApiTokenRevokeDialog from '../ApiTokenRevokeDialog.vue'
import { ElDialogStub } from '@/__fixtures__/dialogStub'
import { standardTokens, tokenDrift, tokenProdApply } from '@/__fixtures__/apiTokens'

enableAutoUnmount(afterEach)

const mountDialog = (props = {}) =>
  mount(ApiTokenRevokeDialog, {
    props: { modelValue: true, token: tokenProdApply(), submit: vi.fn().mockResolvedValue(undefined), ...props },
    global: { plugins: [ElementPlus], stubs: { ElDialog: ElDialogStub } },
  })

describe('API token 撤銷確認', () => {
  it('本人撤銷用過的：問句含名稱與無法復原，紅框寫出最近使用時間與來源', () => {
    const w = mountDialog()
    expect(w.get('[data-test="revoke-question"]').text()).toBe('確定要撤銷「terraform-prod-apply」嗎？此操作無法復原。')
    const box = w.get('[data-test="revoke-consequence-used"]').text()
    expect(box).toContain('用這把的工具會立即無法呼叫管理 API')
    expect(box).toContain('來自 10.20.30.15')
    expect(w.text()).toContain('撤銷原因（選填，會留在紀錄裡）')
    expect(w.get('[data-test="revoke-note"]').attributes('placeholder')).toBe('例如：CI 流程已改用新的 API token')
  })

  it('尚未使用過的：換成黃框與較輕的說法', () => {
    const w = mountDialog({ token: tokenDrift() })
    const box = w.get('[data-test="revoke-consequence-unused"]').text()
    expect(box).toContain('這個 API token 尚未使用過')
    expect(box).toContain('它第一次呼叫就會被拒絕')
  })

  it('管理者撤銷他人的：主詞換成本人，說明本人會看到、原因欄註明誰看得到', () => {
    const w = mountDialog({ mode: 'admin', ownerName: 'ops-chen' })
    expect(w.get('[data-test="revoke-question"]').text()).toBe('確定要撤銷 ops-chen 的「terraform-prod-apply」嗎？此操作無法復原。')
    const box = w.get('[data-test="revoke-consequence-used"]').text()
    expect(box).toContain('ops-chen 用這把設定的工具會立即無法呼叫管理 API')
    expect(box).toContain('ops-chen 會在個人資料頁看到這把被你撤銷')
    expect(w.text()).toContain('撤銷原因（選填，ops-chen 與稽核紀錄都看得到）')
  })

  it('撤銷全部：只算尚未失效的，列出名稱並註明哪把永不到期', () => {
    const w = mountDialog({ mode: 'admin', all: true, tokens: standardTokens(), ownerName: 'ops-chen', token: null })
    expect(w.get('[data-test="revoke-question"]').text()).toBe('確定要撤銷 ops-chen 的全部 3 個可用 API token 嗎？此操作無法復原。')
    const box = w.get('[data-test="revoke-consequence-all"]').text()
    expect(box).toContain('ops-chen 用這些 API token 設定的工具會全部立即停止')
    expect(box).toContain('terraform-plan-ci')
    expect(box).toContain('（其中 drift-check 永不到期）')
    expect(box).not.toContain('jenkins-legacy')
    expect(box).toContain('要連登入一起停，請停用帳號')
    expect(w.get('[data-test="revoke-submit"]').text()).toBe('撤銷全部 API token')
  })

  it('確定撤銷：帶上去頭尾空白的原因送出，成功後關閉', async () => {
    const submit = vi.fn().mockResolvedValue({ revoked: 1 })
    const w = mountDialog({ submit })
    await w.get('[data-test="revoke-note"]').setValue('  CI 已改用 terraform-prod-apply-2 ')
    await w.get('[data-test="revoke-submit"]').trigger('click')
    await flushPromises()
    expect(submit).toHaveBeenCalledWith('CI 已改用 terraform-prod-apply-2')
    expect(w.emitted('done')[0][0]).toEqual({ revoked: 1 })
    expect(w.emitted('update:modelValue').at(-1)).toEqual([false])
  })

  it('處理中：撤銷鈕轉圈', async () => {
    let resolve
    const submit = vi.fn().mockReturnValue(new Promise((r) => { resolve = r }))
    const w = mountDialog({ submit })
    await w.get('[data-test="revoke-submit"]').trigger('click')
    await flushPromises()
    expect(w.get('[data-test="revoke-submit"]').classes()).toContain('is-loading')
    resolve()
    await flushPromises()
  })

  it('伺服器錯誤：對話框不關，頂端說明沒有被撤銷、仍可使用，原因保留', async () => {
    const submit = vi.fn().mockRejectedValue(new Error('500'))
    const w = mountDialog({ submit })
    await w.get('[data-test="revoke-note"]').setValue('CI 已改用 terraform-prod-apply-2')
    await w.get('[data-test="revoke-submit"]').trigger('click')
    await flushPromises()
    const alert = w.get('[data-test="revoke-failed"]').text()
    expect(alert).toContain('伺服器錯誤，請稍後重試')
    expect(alert).toContain('這個 API token 沒有被撤銷，仍可使用。')
    expect(w.emitted('update:modelValue')).toBeUndefined()
    expect(w.get('[data-test="revoke-note"]').element.value).toBe('CI 已改用 terraform-prod-apply-2')
  })

  it('對象已受保護（403）：說出拒絕理由、不說「伺服器錯誤」，並通知上層重新整理清單', async () => {
    const err = Object.assign(new Error('403'), {
      response: { status: 403, data: { code: 'AUTH_PROTECTED_ACCOUNT_OPERATION', error: 'forbidden' } },
    })
    const w = mountDialog({ mode: 'admin', ownerName: 'operator-a', submit: vi.fn().mockRejectedValue(err) })
    await w.get('[data-test="revoke-submit"]').trigger('click')
    await flushPromises()
    const alert = w.get('[data-test="revoke-failed"]').text()
    expect(alert).toContain('這個帳號受保護，你無法執行此操作')
    expect(alert).toContain('清單已重新整理')
    expect(alert).not.toContain('伺服器錯誤')
    expect(alert).not.toContain('仍可使用')
    expect(w.emitted('failed')).toHaveLength(1)
    expect(w.emitted('update:modelValue')).toBeUndefined()
  })

  it('撤銷全部被拒（404）：用「各 API token」的說法', async () => {
    const err = Object.assign(new Error('404'), { response: { status: 404, data: { error: 'not found' } } })
    const w = mountDialog({ all: true, tokens: standardTokens(), token: null, submit: vi.fn().mockRejectedValue(err) })
    await w.get('[data-test="revoke-submit"]').trigger('click')
    await flushPromises()
    expect(w.get('[data-test="revoke-failed"]').text()).toContain('請確認各 API token 目前的狀態')
    expect(w.emitted('failed')).toHaveLength(1)
  })

  it('限流（429）與伺服器錯誤一樣沿用「沒有被撤銷，仍可使用」，不觸發重新整理', async () => {
    const err = Object.assign(new Error('429'), { response: { status: 429, data: {} } })
    const w = mountDialog({ submit: vi.fn().mockRejectedValue(err) })
    await w.get('[data-test="revoke-submit"]').trigger('click')
    await flushPromises()
    expect(w.get('[data-test="revoke-failed"]').text()).toContain('仍可使用')
    expect(w.emitted('failed')).toBeUndefined()
  })
})
