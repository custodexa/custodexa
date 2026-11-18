import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import ApiTokenCreateDialog from '../ApiTokenCreateDialog.vue'
import i18n from '@/i18n'
import { ElDialogStub } from '@/__fixtures__/dialogStub'
import {
  FAKE_PLAINTEXT,
  eligibility,
  roleAdmin,
  roleAsset,
  roleSecurity,
  tokenDrift,
} from '@/__fixtures__/apiTokens'

enableAutoUnmount(afterEach)

const api = vi.hoisted(() => ({ create: vi.fn() }))
vi.mock('@/api/apiTokens', () => ({
  createMyApiToken: (...a) => api.create(...a),
  API_TOKEN_VERIFY_PATH: '/api/v1/api-tokens/verify',
}))

const mountDialog = (props = {}) =>
  mount(ApiTokenCreateDialog, {
    props: { modelValue: true, eligibility: eligibility(), username: 'ops-chen', ...props },
    global: { plugins: [ElementPlus], stubs: { ElDialog: ElDialogStub } },
  })

const choose = async (w, opt) => {
  await w.get(`[data-test="expiry-${opt}"] input`).setValue(true)
  await flushPromises()
}

const httpError = (status, data) => Object.assign(new Error('request failed'), { response: { status, data } })

beforeEach(() => {
  vi.clearAllMocks()
  i18n.global.locale.value = 'zh-TW'
  localStorage.clear()
  sessionStorage.clear()
})

describe('建立 API token 對話框', () => {
  it('初始：授權角色預設全選、到期時間沒有預選，摘要寫出能做什麼與來源限制', () => {
    const w = mountDialog()
    expect(w.get('[data-test="roles-count"]').text()).toBe('已選 2 個')
    expect(w.get('[data-test="roles-all"]').text()).toContain('全部（2 個管理角色）')
    expect(w.get('[data-test="expiry-hint"]').text()).toContain('選一個期限')
    expect(w.findAll('[data-test="expiry-options"] .is-active')).toHaveLength(0)
    const summary = w.get('[data-test="create-summary"]').text()
    expect(summary).toContain('只能讀取：資產管理員（研發三處、研發四處）、授權管理員（全系統）。不會新增、修改或刪除任何資料。')
    expect(summary).toContain('角色指派回來時一併恢復')
    expect(summary).toContain('只限管理與設定 API')
    expect(w.get('[data-test="summary-cidr"]').text()).toContain('203.0.113.0/24、198.51.100.0/24')
    expect(w.get('[data-test="roles-hint"]').text()).toContain('你另外持有的「一般使用者」不屬於管理類角色')
  })

  it('取消勾選一個角色：已選數與摘要即時改寫；全部取消時摘要說什麼都不能做', async () => {
    const w = mountDialog()
    await w.get('[data-test="role-9"] input').setValue(false)
    expect(w.get('[data-test="roles-count"]').text()).toBe('已選 1 個')
    expect(w.get('[data-test="summary-roles"]').text()).toContain('只能讀取：資產管理員（研發三處、研發四處）。')
    expect(w.get('[data-test="summary-roles"]').text()).not.toContain('授權管理員')
    await w.get('[data-test="role-5"] input').setValue(false)
    expect(w.get('[data-test="summary-none"]').text()).toBe('還沒有選任何角色，這把 API token 什麼都不能做。')
  })

  it('選 90 天：寫出到期時刻與天數；選永不到期：說明不會自動失效', async () => {
    const w = mountDialog()
    await choose(w, 'd90')
    const line = w.get('[data-test="expiry-line"]').text()
    expect(line).toContain('（90 天後）')
    expect(line).toContain('23:59:59')
    await choose(w, 'never')
    expect(w.get('[data-test="expiry-never-line"]').text()).toBe('這個 API token 不會自動失效。不再使用時，請自己撤銷。')
  })

  it('選自訂日期：出現日期欄與「當天 23:59:59 到期」，選定約三年後的日期寫成約 3 年後', async () => {
    const w = mountDialog()
    await choose(w, 'custom')
    expect(w.find('[data-test="expiry-custom"]').exists()).toBe(true)
    expect(w.text()).toContain('當天 23:59:59 到期')
    const d = new Date()
    d.setFullYear(d.getFullYear() + 3)
    w.vm.$.setupState.customDate = d
    await flushPromises()
    expect(w.get('[data-test="expiry-line"]').text()).toContain('約 3 年後')
  })

  it('什麼都沒填就送出：名稱、角色、期限各自在旁邊顯示錯誤，不送出請求', async () => {
    const w = mountDialog()
    await w.get('[data-test="roles-all"] input').setValue(false)
    await w.get('[data-test="create-submit"]').trigger('click')
    await flushPromises()
    expect(w.get('[data-test="err-name"]').text()).toBe('請輸入 API token 名稱')
    expect(w.get('[data-test="err-roles"]').text()).toBe('請至少選擇一個角色')
    expect(w.get('[data-test="err-expiry"]').text()).toBe('請選擇到期時間')
    expect(w.get('[data-test="roles-multi"]').classes()).toContain('is-error')
    expect(api.create).not.toHaveBeenCalled()
  })

  it('只有一個管理角色、帳號沒設允許來源網段：不畫勾選框，摘要說任何位址都能使用', () => {
    const w = mountDialog({ eligibility: eligibility({ grantable_roles: [roleAsset()], allowed_cidrs: [] }) })
    expect(w.find('[data-test="roles-multi"]').exists()).toBe(false)
    expect(w.get('[data-test="roles-single"]').text()).toContain('你只有這一個管理角色，會授權給它')
    expect(w.get('[data-test="summary-cidr"]').text()).toContain('沒有設定允許來源網段，任何位址都能使用')
  })

  it('勾選的角色含超級管理者：頂端黃框照樣出現並依權限換標題，摘要改寫成超級管理者看得到／能做的事', async () => {
    const w = mountDialog({ eligibility: eligibility({ grantable_roles: [roleAdmin()] }) })
    const read = w.get('[data-test="create-privilege-super"]').text()
    expect(read).toContain('這把 API token 授權了超級管理者角色（唯讀）')
    expect(read).toContain('設為唯讀時不能改變任何資料，但讀得到你看得到的所有管理與設定資料')
    expect(read).toContain('建立高權限 API token')
    expect(w.get('[data-test="summary-super"]').text()).toBe('只能讀取：管理員（全系統），也就是超級管理者看得到的所有管理與設定資料。不會新增、修改或刪除任何資料。')
    await w.get('[data-test="level-1-read_write"] input').setValue(true)
    const write = w.get('[data-test="create-privilege-super"]').text()
    expect(write).toContain('這把 API token 授權了超級管理者角色，並設為讀寫')
    expect(write).toContain('用它可以做你能做的所有管理與設定')
    expect(w.get('[data-test="summary-super"]').text()).toContain('也就是超級管理者能做的所有管理與設定')
    expect(w.get('[data-test="summary-super"] .is-write').text()).toBe('可以讀取，也可以修改：')
  })

  it('超級管理者唯讀、另一個角色讀寫：摘要逐角色寫出，不說成不能修改資料', async () => {
    const w = mountDialog({ eligibility: eligibility({ grantable_roles: [roleAdmin(), roleAsset()] }) })
    const adminId = roleAdmin().role_id
    const assetId = roleAsset().role_id
    for (const id of [adminId, assetId]) {
      const box = w.get(`[data-test="role-${id}"] input`)
      if (!box.element.checked) await box.setValue(true)
    }
    await w.get(`[data-test="level-${assetId}-read_write"] input`).setValue(true)
    expect(w.find('[data-test="summary-super"]').exists()).toBe(false)
    expect(w.get('[data-test="summary-write"] .is-write').text()).toBe('可以讀取，也可以修改：')
    expect(w.get('[data-test="summary-read"]').text()).not.toContain('不會新增、修改或刪除任何資料')
    expect(w.get('[data-test="create-summary"]').text()).not.toContain('不會新增、修改或刪除任何資料')
  })

  it('勾選系統安全管理員才出現黃框，取消勾選即消失', async () => {
    const w = mountDialog({ eligibility: eligibility({ grantable_roles: [roleSecurity(), roleAsset()] }) })
    expect(w.get('[data-test="create-privilege-security"]').text()).toContain('系統安全管理員角色')
    await w.get('[data-test="role-2"] input').setValue(false)
    expect(w.find('[data-test="create-privilege-security"]').exists()).toBe(false)
  })

  it('送出成功：帶名稱、角色與當天 23:59:59 的到期時刻，同一個對話框換成明文，交給父層的物件不含明文', async () => {
    api.create.mockResolvedValue({ ...tokenDrift({ id: 9, name: 'tf-new' }), token: FAKE_PLAINTEXT })
    const w = mountDialog()
    await w.get('[data-test="create-name"]').setValue('  tf-new ')
    await choose(w, 'd30')
    await w.get('[data-test="create-submit"]').trigger('click')
    await flushPromises()
    const payload = api.create.mock.calls[0][0]
    expect(payload.name).toBe('tf-new')
    expect(payload.roles).toEqual([{ role_id: 5, level: 'read' }, { role_id: 9, level: 'read' }])
    expect(payload).not.toHaveProperty('role_ids')
    expect(payload.never_expires).toBeUndefined()
    const at = new Date(payload.expires_at)
    expect([at.getHours(), at.getMinutes(), at.getSeconds()]).toEqual([23, 59, 59])
    expect(w.get('[data-test="reveal-secret"]').text()).toBe(FAKE_PLAINTEXT)
    expect(w.find('[data-test="create-form"]').exists()).toBe(false)
    expect(w.find('[data-test="create-cancel"]').exists()).toBe(false)
    expect(w.get('[data-test="reveal-close"]').text()).toBe('我已保存，關閉')
    const emitted = w.emitted('created')[0][0]
    expect(emitted.id).toBe(9)
    expect(Object.prototype.hasOwnProperty.call(emitted, 'token')).toBe(false)
  })

  it('選永不到期送出：請求只帶 never_expires', async () => {
    api.create.mockResolvedValue({ ...tokenDrift(), token: FAKE_PLAINTEXT })
    const w = mountDialog()
    await w.get('[data-test="create-name"]').setValue('drift-check-2')
    await choose(w, 'never')
    await w.get('[data-test="create-submit"]').trigger('click')
    await flushPromises()
    const payload = api.create.mock.calls[0][0]
    expect(payload.never_expires).toBe(true)
    expect(payload.expires_at).toBeUndefined()
  })

  it('明文只存在對話框裡：不寫入瀏覽器儲存、不輸出到主控台；關閉後重新打開看不到', async () => {
    const spies = ['log', 'info', 'warn', 'error', 'debug'].map((m) => vi.spyOn(console, m))
    api.create.mockResolvedValue({ ...tokenDrift(), token: FAKE_PLAINTEXT })
    const w = mountDialog()
    await w.get('[data-test="create-name"]').setValue('x')
    await choose(w, 'never')
    await w.get('[data-test="create-submit"]').trigger('click')
    await flushPromises()
    expect(w.text()).toContain(FAKE_PLAINTEXT)
    const stored = JSON.stringify({ ...localStorage }) + JSON.stringify({ ...sessionStorage })
    expect(stored).not.toContain(FAKE_PLAINTEXT)
    for (const spy of spies) {
      for (const call of spy.mock.calls) expect(JSON.stringify(call)).not.toContain(FAKE_PLAINTEXT)
    }
    await w.get('[data-test="reveal-close"]').trigger('click')
    expect(w.emitted('update:modelValue').at(-1)).toEqual([false])
    await w.setProps({ modelValue: false })
    await w.setProps({ modelValue: true })
    expect(w.text()).not.toContain(FAKE_PLAINTEXT)
    expect(w.find('[data-test="create-form"]').exists()).toBe(true)
    spies.forEach((s) => s.mockRestore())
  })

  it('同名：錯誤顯示在名稱欄下方，其他內容保留', async () => {
    api.create.mockRejectedValue(httpError(409, { code: 'CONFLICT_API_TOKEN_NAME' }))
    const w = mountDialog()
    await w.get('[data-test="create-name"]').setValue('terraform-prod-apply')
    await choose(w, 'd90')
    await w.get('[data-test="create-submit"]').trigger('click')
    await flushPromises()
    expect(w.get('[data-test="err-name"]').text()).toBe('你已經有同名的 API token，請換一個名稱')
    expect(w.get('[data-test="create-name"]').element.value).toBe('terraform-prod-apply')
    expect(w.get('[data-test="expiry-line"]').text()).toContain('90 天後')
  })

  it('伺服器錯誤：對話框頂端紅框說沒有建立，填的內容還在', async () => {
    api.create.mockRejectedValue(httpError(500, {}))
    const w = mountDialog()
    await w.get('[data-test="create-name"]').setValue('terraform-prod-apply')
    await choose(w, 'd90')
    await w.get('[data-test="create-submit"]').trigger('click')
    await flushPromises()
    const alert = w.get('[data-test="create-server-error"]').text()
    expect(alert).toContain('伺服器錯誤，請稍後重試')
    expect(alert).toContain('沒有建立 API token。你填的內容還在，可以直接再按一次。')
    expect(w.get('[data-test="create-name"]').element.value).toBe('terraform-prod-apply')
  })

  it('勾選的角色剛被收回：頂端說明原因並要求父層重新讀取可授權的角色', async () => {
    api.create.mockRejectedValue(httpError(400, { code: 'API_TOKEN_ROLE_NOT_GRANTABLE' }))
    const w = mountDialog()
    await w.get('[data-test="create-name"]').setValue('x')
    await choose(w, 'never')
    await w.get('[data-test="create-submit"]').trigger('click')
    await flushPromises()
    expect(w.get('[data-test="create-server-error"]').text()).toContain('勾選的角色中有你目前已沒有的管理角色')
    expect(w.emitted('stale-roles')).toHaveLength(1)
  })

  it('送出時才失去建立資格：關閉對話框並通知父層重新載入', async () => {
    api.create.mockRejectedValue(httpError(403, { code: 'API_TOKEN_NOT_ELIGIBLE' }))
    const w = mountDialog()
    await w.get('[data-test="create-name"]').setValue('x')
    await choose(w, 'never')
    await w.get('[data-test="create-submit"]').trigger('click')
    await flushPromises()
    expect(w.emitted('ineligible')).toHaveLength(1)
    expect(w.emitted('update:modelValue').at(-1)).toEqual([false])
  })

  it('處理中：建立鈕轉圈、欄位不清空', async () => {
    let resolve
    api.create.mockReturnValue(new Promise((r) => { resolve = r }))
    const w = mountDialog()
    await w.get('[data-test="create-name"]').setValue('terraform-prod-apply')
    await choose(w, 'd90')
    await w.get('[data-test="create-submit"]').trigger('click')
    await flushPromises()
    expect(w.get('[data-test="create-submit"]').classes()).toContain('is-loading')
    expect(w.get('[data-test="create-name"]').element.value).toBe('terraform-prod-apply')
    resolve({ ...tokenDrift(), token: FAKE_PLAINTEXT })
    await flushPromises()
  })
})

describe('每個角色的權限', () => {
  const activeLevel = (w, id) => w.get(`[data-test="level-${id}"] .is-active input`).element.value

  it('預設唯讀：每個勾選的角色都停在唯讀，摘要只有「只能讀取」一句', () => {
    const w = mountDialog()
    expect(activeLevel(w, 5)).toBe('read')
    expect(activeLevel(w, 9)).toBe('read')
    expect(w.find('[data-test="summary-write"]').exists()).toBe(false)
    expect(w.get('[data-test="summary-read"]').text()).toContain('不會新增、修改或刪除任何資料。')
    expect(w.get('[data-test="roles-hint"]').text()).toMatch(/^每個角色各選「唯讀」或「讀寫」，預設唯讀。只能從你自己的管理角色中選/)
  })

  it('把一個角色切成讀寫：該段轉琥珀色，摘要第一句以「可以讀取，也可以修改」列出它，第二句只列唯讀的', async () => {
    const w = mountDialog()
    await w.get('[data-test="level-5-read_write"] input').setValue(true)
    expect(activeLevel(w, 5)).toBe('read_write')
    expect(w.get('[data-test="level-5"]').classes()).toContain('is-write')
    expect(w.get('[data-test="level-9"]').classes()).not.toContain('is-write')
    expect(w.get('[data-test="summary-write"]').text()).toBe('可以讀取，也可以修改：資產管理員（研發三處、研發四處）。')
    expect(w.get('[data-test="summary-write"] .is-write').text()).toBe('可以讀取，也可以修改：')
    expect(w.get('[data-test="summary-read"]').text()).toBe('只能讀取：授權管理員（全系統）。')
  })

  it('全部設為讀寫：只改已勾選的角色，不會勾選未勾的；再按全部設為唯讀可一次改回', async () => {
    const w = mountDialog()
    await w.get('[data-test="role-9"] input').setValue(false)
    await w.get('[data-test="level-set-all-read_write"]').trigger('click')
    expect(activeLevel(w, 5)).toBe('read_write')
    expect(activeLevel(w, 9)).toBe('read')
    expect(w.get('[data-test="roles-count"]').text()).toBe('已選 1 個')
    await w.get('[data-test="role-9"] input').setValue(true)
    await w.get('[data-test="level-set-all-read_write"]').trigger('click')
    expect(activeLevel(w, 9)).toBe('read_write')
    await w.get('[data-test="level-set-all-read"]').trigger('click')
    expect(activeLevel(w, 5)).toBe('read')
    expect(activeLevel(w, 9)).toBe('read')
  })

  it('取消勾選再勾回：回到唯讀，不記得先前選的讀寫；未勾選時切換整組變灰不能按', async () => {
    const w = mountDialog()
    await w.get('[data-test="level-9-read_write"] input').setValue(true)
    expect(activeLevel(w, 9)).toBe('read_write')
    await w.get('[data-test="role-9"] input').setValue(false)
    expect(w.get('[data-test="level-9-read"] input').element.disabled).toBe(true)
    expect(w.get('[data-test="level-9-read_write"] input').element.disabled).toBe(true)
    expect(w.get('[data-test="level-9"]').classes()).not.toContain('is-write')
    await w.get('[data-test="role-9"] input').setValue(true)
    expect(activeLevel(w, 9)).toBe('read')
    expect(w.get('[data-test="level-9-read"] input').element.disabled).toBe(false)
  })

  it('用「全部」取消後再全選：每個角色都回到唯讀；全部取消時「全部設為」變灰', async () => {
    const w = mountDialog()
    await w.get('[data-test="level-set-all-read_write"]').trigger('click')
    await w.get('[data-test="roles-all"] input').setValue(false)
    expect(w.get('[data-test="level-set-all-read"]').attributes('disabled')).toBeDefined()
    expect(w.get('[data-test="level-set-all-read_write"]').attributes('disabled')).toBeDefined()
    await w.get('[data-test="roles-all"] input').setValue(true)
    expect(activeLevel(w, 5)).toBe('read')
    expect(activeLevel(w, 9)).toBe('read')
  })

  it('送出時每個勾選的角色各帶自己的層級', async () => {
    api.create.mockResolvedValue({ ...tokenDrift({ id: 11 }), token: FAKE_PLAINTEXT })
    const w = mountDialog()
    await w.get('[data-test="create-name"]').setValue('terraform-prod-apply-2')
    await w.get('[data-test="level-5-read_write"] input').setValue(true)
    await choose(w, 'd90')
    await w.get('[data-test="create-submit"]').trigger('click')
    await flushPromises()
    expect(api.create.mock.calls[0][0].roles).toEqual([
      { role_id: 5, level: 'read_write' },
      { role_id: 9, level: 'read' },
    ])
  })

  it('只有一個管理角色：沒有勾選框也沒有「全部設為」，仍要選權限，預設唯讀', async () => {
    api.create.mockResolvedValue({ ...tokenDrift(), token: FAKE_PLAINTEXT })
    const w = mountDialog({ eligibility: eligibility({ grantable_roles: [roleAsset()] }) })
    expect(w.find('[data-test="level-set-all"]').exists()).toBe(false)
    expect(w.get('[data-test="roles-single"]').text()).toContain('範圍：研發三處、研發四處')
    expect(activeLevel(w, 5)).toBe('read')
    await w.get('[data-test="level-5-read_write"] input').setValue(true)
    await w.get('[data-test="create-name"]').setValue('asset-sync')
    await choose(w, 'never')
    await w.get('[data-test="create-submit"]').trigger('click')
    await flushPromises()
    expect(api.create.mock.calls[0][0].roles).toEqual([{ role_id: 5, level: 'read_write' }])
  })

  it('系統安全管理員設讀寫、資產管理員唯讀：黃框只講高權限的那個角色與它的權限', async () => {
    const w = mountDialog({ eligibility: eligibility({ grantable_roles: [roleSecurity(), roleAsset()] }) })
    expect(w.get('[data-test="create-privilege-security"]').text()).toContain('這把 API token 授權了系統安全管理員角色（唯讀）')
    expect(w.get('[data-test="create-privilege-security"]').text()).toContain('讀得到全系統安全政策、通知與告警設定')
    await w.get('[data-test="level-2-read_write"] input').setValue(true)
    expect(w.get('[data-test="create-privilege-security"]').text()).toContain('這把 API token 授權了系統安全管理員角色，並設為讀寫')
    expect(w.get('[data-test="create-privilege-security"]').text()).toContain('用它可以變更全系統安全政策')
    expect(w.get('[data-test="summary-write"]').text()).toBe('可以讀取，也可以修改：系統安全管理員（全系統）。')
    expect(w.get('[data-test="summary-read"]').text()).toBe('只能讀取：資產管理員（研發三處、研發四處）。')
  })

  it('「唯讀與讀寫有什麼不同？」就地展開說明，右上可關閉', async () => {
    const w = mountDialog()
    expect(w.find('[data-test="level-explain"]').exists()).toBe(false)
    await w.get('[data-test="level-help"]').trigger('click')
    const text = w.get('[data-test="level-explain"]').text()
    expect(text).toContain('唯讀與讀寫有什麼不同')
    expect(text).toContain('也可以使用預覽、試算這類不會存下任何變更的功能')
    expect(text).toContain('這時兩個角色都要設為讀寫才做得到')
    expect(text).toContain('平台會拒絕這次呼叫，資料不會有任何變動')
    await w.get('[data-test="level-explain-close"]').trigger('click')
    expect(w.find('[data-test="level-explain"]').exists()).toBe(false)
  })

  it('全部取消就按建立：只有角色框紅字，權限不另驗證', async () => {
    const w = mountDialog()
    await w.get('[data-test="roles-all"] input').setValue(false)
    await w.get('[data-test="create-submit"]').trigger('click')
    await flushPromises()
    expect(w.get('[data-test="err-roles"]').text()).toBe('請至少選擇一個角色')
    expect(w.findAll('.atc-error')).toHaveLength(3)
  })
})

describe('句子之間的空白', () => {
  afterEach(() => {
    i18n.global.locale.value = 'zh-TW'
  })

  it('中文：摘要與角色說明的兩句之間沒有多出的空白', () => {
    const w = mountDialog()
    expect(w.get('[data-test="summary-roles"]').text()).not.toMatch(/。\s/)
    expect(w.get('[data-test="roles-hint"]').text()).not.toMatch(/[；。]\s/)
  })

  it('英文：兩句之間剛好一個空白，不會黏在一起', () => {
    i18n.global.locale.value = 'en-US'
    const w = mountDialog()
    const hint = w.get('[data-test="roles-hint"]').text()
    expect(hint).not.toMatch(/\.[A-Z]/)
    expect(hint).toMatch(/yours\. \S/)
    for (const p of w.findAll('[data-test="summary-roles"] p')) {
      expect(p.text()).not.toMatch(/\.[A-Z]/)
      expect(p.text()).not.toMatch(/\. {2}/)
    }
    expect(w.get('[data-test="summary-read"]').text()).toMatch(/^Can only read: \S/)
    expect(w.get('[data-test="summary-read"]').text()).toMatch(/\. It will not/)
  })

  it('日文：句號後不留空白', () => {
    i18n.global.locale.value = 'ja-JP'
    const w = mountDialog()
    expect(w.get('[data-test="summary-roles"]').text()).not.toMatch(/。\s/)
    expect(w.get('[data-test="roles-hint"]').text()).not.toMatch(/。\s/)
  })
})
