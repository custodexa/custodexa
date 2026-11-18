import { describe, it, expect, afterEach } from 'vitest'
import { flushPromises, mount, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import ApiTokenList from '../ApiTokenList.vue'
import {
  roleAsset,
  roleAuthz,
  standardTokens,
  tokenDrift,
  tokenPlanCi,
  tokenProdApply,
} from '@/__fixtures__/apiTokens'

enableAutoUnmount(afterEach)

const mountList = (props = {}) =>
  mount(ApiTokenList, {
    props: { tokens: standardTokens(), ...props },
    global: { plugins: [ElementPlus] },
  })

const rowIds = (w) =>
  w.findAll('tr[data-test^="token-row-"]').map((r) => Number(r.attributes('data-test').replace('token-row-', '')))

describe('API token 清單', () => {
  it('摘要數字：可用含即將到期、7 天內到期、已失效各自計數', () => {
    const w = mountList()
    expect(w.get('[data-test="summary-usable"]').text()).toContain('3')
    expect(w.get('[data-test="summary-usable"]').text()).toContain('可用')
    expect(w.get('[data-test="summary-expiring"]').text()).toContain('1')
    expect(w.get('[data-test="summary-expiring"]').classes()).toContain('is-warning')
    expect(w.get('[data-test="summary-inactive"]').text()).toContain('2')
  })

  it('沒有即將到期的時候，7 天內到期的格子不以琥珀色強調', () => {
    const w = mountList({ tokens: [tokenDrift()] })
    expect(w.get('[data-test="summary-expiring"]').classes()).not.toContain('is-warning')
  })

  it('可用區依到期時間由近到遠、永不到期排最後；已失效區收在下方並可收合', async () => {
    const w = mountList()
    expect(rowIds(w)).toEqual([1, 2, 3, 4, 5])
    const section = w.get('[data-test="inactive-section"]')
    expect(section.text()).toContain('已失效的 API token（2）')
    expect(section.text()).toContain('已到期、已撤銷或已因還原失效')
    await w.get('[data-test="inactive-toggle"]').trigger('click')
    expect(rowIds(w)).toEqual([1, 2, 3])
    expect(w.get('[data-test="inactive-toggle"]').attributes('aria-expanded')).toBe('false')
  })

  it('狀態文字取自後端投影：天數、有效、已到期、已撤銷與撤銷者', () => {
    const w = mountList()
    expect(w.get('[data-test="status-1"]').text()).toBe('3 天後到期')
    expect(w.get('[data-test="status-2"]').text()).toBe('有效')
    expect(w.get('[data-test="status-4"]').text()).toBe('已到期')
    expect(w.get('[data-test="status-5"]').text()).toBe('已撤銷')
    expect(w.get('[data-test="token-row-5"]').get('[data-test="revoked-by"]').text()).toBe('ops-chen 撤銷')
  })

  it('同一把 token 的狀態不依到期時間在前端重算：後端說有效就顯示有效', () => {
    const w = mountList({ tokens: [tokenProdApply({ expires_at: '2020-01-01T00:00:00Z' })] })
    expect(w.get('[data-test="status-2"]').text()).toBe('有效')
  })

  it('到期與最近使用：永不到期、尚未使用、來源位址', () => {
    const w = mountList()
    const drift = w.get('[data-test="token-row-3"]')
    expect(drift.get('[data-test="never-expires"]').text()).toBe('永不到期')
    expect(drift.text()).toContain('尚未使用')
    expect(w.get('[data-test="token-row-2"]').text()).toContain('來自 203.0.113.15')
  })

  it('授權角色列出角色與範圍', () => {
    const w = mountList()
    const prod = w.get('[data-test="token-row-2"]')
    expect(prod.get('[data-test="granted-role-2-5"]').text()).toContain('資產管理員')
    expect(prod.get('[data-test="granted-role-2-5"]').text()).toContain('研發三處、研發四處')
    expect(prod.get('[data-test="granted-role-2-9"]').text()).toContain('全系統')
  })

  it('撤銷只出現在可用與暫停的列，點下去送出該把', async () => {
    const w = mountList()
    expect(w.find('[data-test="revoke-1"]').exists()).toBe(true)
    expect(w.find('[data-test="revoke-4"]').exists()).toBe(false)
    expect(w.get('[data-test="no-action-5"]').text()).toBe('—')
    await w.get('[data-test="revoke-2"]').trigger('click')
    expect(w.emitted('revoke')[0][0].id).toBe(2)
  })

  it('不能撤銷時每一列的操作都是「—」', () => {
    const w = mountList({ canRevoke: false })
    expect(w.findAll('[data-test^="revoke-"]')).toHaveLength(0)
    expect(w.findAll('[data-test^="no-action-"]')).toHaveLength(5)
  })

  it('角色被收回：全部失去者標暫停（角色已收回）、角色劃線並註明已收回；仍可撤銷', () => {
    const suspended = tokenProdApply({
      status: 'suspended_roles_revoked',
      granted_roles: [roleAsset({ effective: false, scope: null }), roleAuthz({ effective: false, scope: null })],
    })
    const w = mountList({ tokens: [suspended] })
    expect(w.get('[data-test="status-2"]').text()).toBe('暫停（角色已收回）')
    expect(w.findAll('[data-test="role-revoked"]')).toHaveLength(2)
    expect(w.get('[data-test="granted-role-2-5"]').find('.atl-role--lost').exists()).toBe(true)
    expect(w.find('[data-test="revoke-2"]').exists()).toBe(true)
    expect(w.find('[data-test="inactive-section"]').exists()).toBe(false)
  })

  it('只失去部分角色時仍為有效，只有失去的那個角色註明已收回', () => {
    const partial = tokenProdApply({ granted_roles: [roleAsset(), roleAuthz({ effective: false, scope: null })] })
    const w = mountList({ tokens: [partial] })
    expect(w.get('[data-test="status-2"]').text()).toBe('有效')
    expect(w.get('[data-test="granted-role-2-9"]').text()).toContain('已收回')
    expect(w.get('[data-test="granted-role-2-5"]').text()).not.toContain('已收回')
  })

  it('帳號停用：狀態為暫停（帳號已停用），留在上方清單，摘要標示帳號停用中', () => {
    const tokens = [tokenPlanCi({ status: 'suspended_account_disabled' }), tokenDrift({ status: 'suspended_account_disabled' })]
    const w = mountList({ tokens, accountDisabled: true, mode: 'admin' })
    expect(w.get('[data-test="status-1"]').text()).toBe('暫停（帳號已停用）')
    expect(w.get('[data-test="summary-usable"]').text()).toContain('0')
    expect(w.get('[data-test="summary-usable"]').text()).toContain('可用（帳號停用中）')
    expect(w.find('[data-test="revoke-1"]').exists()).toBe(true)
  })

  it('還原後失效的 token 收進已失效區', () => {
    const w = mountList({ tokens: [tokenDrift({ status: 'invalidated_by_restore' })] })
    expect(w.get('[data-test="status-3"]').text()).toBe('已因還原失效')
    expect(w.get('[data-test="inactive-section"]').text()).toContain('（1）')
    expect(w.find('[data-test="revoke-3"]').exists()).toBe(false)
  })

  it('剛建立的那一列加上標記', () => {
    const w = mountList({ justCreatedId: 3 })
    expect(w.get('[data-test="token-row-3"]').classes()).toContain('is-new')
    expect(w.get('[data-test="token-row-3"]').get('[data-test="just-created"]').text()).toBe('剛建立')
    expect(w.findAll('[data-test="just-created"]')).toHaveLength(1)
  })

  it('剛建立後又撤銷：移到已失效區的那一列不再掛「剛建立」', () => {
    const w = mountList({ tokens: [tokenDrift({ status: 'revoked', revoked_at: '2026-11-13T05:00:00Z' })], justCreatedId: 3 })
    expect(w.get('[data-test="token-row-3"]').classes()).not.toContain('is-new')
    expect(w.find('[data-test="just-created"]').exists()).toBe(false)
  })

  it('本人模式：底部常駐「建立後不能修改」說明，名稱可聚焦看如何修改；管理者模式沒有', () => {
    const self = mountList({ showEditHint: true })
    expect(self.get('[data-test="edit-hint"]').text()).toContain('建立後不能修改名稱、授權角色、權限或到期時間')
    expect(self.get('[data-test="token-row-2"] [data-test="token-name"]').attributes('tabindex')).toBe('0')
    const admin = mountList({ mode: 'admin' })
    expect(admin.find('[data-test="edit-hint"]').exists()).toBe(false)
    expect(admin.get('[data-test="token-row-2"] [data-test="token-name"]').attributes('tabindex')).toBeUndefined()
  })
})

describe('API token 清單的權限欄', () => {
  const rw = (extra = {}) => ({ level: 'read_write', ...extra })
  const ro = (extra = {}) => ({ level: 'read', ...extra })

  it('三種總結：全部唯讀為灰色唯讀、全部讀寫為琥珀讀寫、兩者皆有為虛線框部分讀寫並寫出幾個角色讀寫', () => {
    const tokens = [
      tokenDrift({ id: 31, access: 'read', granted_roles: [roleAsset(ro()), roleAuthz(ro())] }),
      tokenProdApply({ id: 32, access: 'read_write', granted_roles: [roleAsset(rw()), roleAuthz(rw())] }),
      tokenProdApply({ id: 33, name: 'terraform-prod-apply-2', access: 'mixed', granted_roles: [roleAsset(rw()), roleAuthz(ro())] }),
    ]
    const w = mountList({ tokens })
    const cell = (id) => w.get(`[data-test="access-${id}"]`)
    expect(cell(31).get('[data-test="access-tag"]').text()).toBe('唯讀')
    expect(cell(31).get('[data-test="access-tag"]').classes()).toContain('ot-tag-neutral')
    expect(cell(31).find('[data-test="access-sub"]').exists()).toBe(false)
    expect(cell(32).get('[data-test="access-tag"]').text()).toBe('讀寫')
    expect(cell(32).get('[data-test="access-tag"]').attributes('data-access')).toBe('read_write')
    expect(cell(32).get('[data-test="access-tag"]').classes()).not.toContain('ot-tag-neutral')
    expect(cell(33).get('[data-test="access-tag"]').text()).toBe('部分讀寫')
    expect(cell(33).get('[data-test="access-tag"]').classes()).toContain('is-mixed')
    expect(cell(33).get('[data-test="access-sub"]').text()).toBe('1 個角色讀寫')
  })

  it('授權角色欄每個角色後面帶自己的權限小標', () => {
    const w = mountList({ tokens: [tokenProdApply({ id: 33, access: 'mixed', granted_roles: [roleAsset(rw()), roleAuthz(ro())] })] })
    expect(w.get('[data-test="granted-role-33-5"] [data-test="level-tag"]').text()).toBe('讀寫')
    expect(w.get('[data-test="granted-role-33-5"] [data-test="level-tag"]').attributes('data-level')).toBe('read_write')
    expect(w.get('[data-test="granted-role-33-9"] [data-test="level-tag"]').text()).toBe('唯讀')
  })

  it('升級前建立的 token：權限照實為讀寫，第二行以小字標出「升級前建立」', () => {
    const w = mountList({
      tokens: [
        tokenPlanCi({ id: 41, access: 'read_write', created_before_levels: true, granted_roles: [roleAsset(rw())] }),
        tokenDrift({ id: 42, access: 'read', created_before_levels: false, granted_roles: [roleAsset(ro())] }),
      ],
    })
    expect(w.get('[data-test="access-41"] [data-test="access-tag"]').text()).toBe('讀寫')
    expect(w.get('[data-test="access-41"] [data-test="access-sub"]').text()).toBe('升級前建立')
    expect(w.find('[data-test="access-42"] [data-test="access-sub"]').exists()).toBe(false)
  })

  it('總結依建立時的選擇：角色被收回後仍顯示部分讀寫，收回的角色劃線並保留權限小標', () => {
    const w = mountList({
      tokens: [tokenProdApply({ id: 33, access: 'mixed', granted_roles: [roleAsset(rw()), roleAuthz(ro({ effective: false, scope: null }))] })],
    })
    expect(w.get('[data-test="access-33"] [data-test="access-tag"]').text()).toBe('部分讀寫')
    const lost = w.get('[data-test="granted-role-33-9"]')
    expect(lost.get('[data-test="role-revoked"]').text()).toBe('已收回')
    expect(lost.get('[data-test="level-tag"]').text()).toBe('唯讀')
  })

  it('讀到不認得的層級或總結值：一律顯示為唯讀；沒有總結欄位時由各角色層級算出', () => {
    const w = mountList({
      tokens: [
        tokenDrift({ id: 51, access: 'admin', granted_roles: [roleAsset({ level: 'admin' })] }),
        tokenProdApply({ id: 52, granted_roles: [roleAsset(rw()), roleAuthz(ro())] }),
      ],
    })
    expect(w.get('[data-test="access-51"] [data-test="access-tag"]').text()).toBe('唯讀')
    expect(w.get('[data-test="granted-role-51-5"] [data-test="level-tag"]').text()).toBe('唯讀')
    expect(w.get('[data-test="access-52"] [data-test="access-tag"]').text()).toBe('部分讀寫')
  })

  it('欄頭「權限」旁有說明提示，內容與建立對話框的說明同一段', () => {
    const w = mountList({ tokens: [tokenDrift()] })
    expect(w.get('[data-test="col-access"]').text()).toContain('權限')
    expect(w.find('[data-test="col-access-help"]').attributes('tabindex')).toBe('0')
  })

  // 擋：說明元件的文字色與預設 dark 提示框的底色相同，滑過只看得到標籤與結尾句
  it('欄頭說明放在 light 提示框，提示框裡是說明元件', async () => {
    const w = mountList({ tokens: [tokenDrift()] })
    const tip = w.findAllComponents({ name: 'ElTooltip' })
      .find((c) => c.props('popperClass') === 'atl-explain-popper')
    expect(tip).toBeTruthy()
    expect(tip.props('effect')).toBe('light')
    await w.get('[data-test="col-access-help"]').trigger('mouseenter')
    await new Promise((r) => setTimeout(r, 300))
    await flushPromises()
    const popper = document.querySelector('.atl-explain-popper')
    expect(popper).not.toBeNull()
    expect(popper.classList.contains('is-light')).toBe(true)
    expect(popper.classList.contains('is-dark')).toBe(false)
    expect(popper.querySelector('[data-test="level-explain"]')).not.toBeNull()
  })
})
