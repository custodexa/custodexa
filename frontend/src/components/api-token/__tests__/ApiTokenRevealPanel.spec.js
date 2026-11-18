import { describe, it, expect, vi, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import ApiTokenRevealPanel from '../ApiTokenRevealPanel.vue'
import { FAKE_PLAINTEXT, roleAsset, roleAuthz, tokenDrift, tokenProdApply } from '@/__fixtures__/apiTokens'

enableAutoUnmount(afterEach)
afterEach(() => vi.unstubAllGlobals())

const mountPanel = (created = { ...tokenProdApply({ name: 'terraform-prod-apply-2' }), token: FAKE_PLAINTEXT }) =>
  mount(ApiTokenRevealPanel, {
    props: { created, username: 'ops-chen' },
    global: { plugins: [ElementPlus] },
  })

const stubClipboard = (impl) => {
  const writeText = vi.fn(impl)
  vi.stubGlobal('navigator', { ...navigator, clipboard: { writeText } })
  return writeText
}

describe('API token 一次性明文顯示', () => {
  it('明文、只顯示一次的警語、名稱、授權角色、到期與代表本人', () => {
    const w = mountPanel()
    expect(w.get('[data-test="reveal-secret"]').text()).toBe(FAKE_PLAINTEXT)
    expect(w.text()).toContain('這個 API token 只顯示這一次')
    expect(w.text()).toContain('關閉後無法再次取得')
    expect(w.get('[data-test="reveal-name"]').text()).toBe('terraform-prod-apply-2')
    expect(w.get('[data-test="reveal-role-5"]').text()).toContain('資產管理員（研發三處、研發四處）')
    expect(w.get('[data-test="reveal-role-9"]').text()).toContain('授權管理員（全系統）')
    expect(w.get('[data-test="reveal-expiry"]').text()).toMatch(/\d{4}\/\d{2}\/\d{2}/)
    expect(w.get('[data-test="reveal-expiry"]').text()).not.toContain('永不到期')
    expect(w.get('[data-test="reveal-represents"]').text()).toBe('ops-chen（你本人）')
  })

  it('永不到期：到期欄寫永不到期並提醒自己撤銷', () => {
    const w = mountPanel({ ...tokenDrift(), token: FAKE_PLAINTEXT })
    const text = w.get('[data-test="reveal-expiry"]').text()
    expect(text).toContain('永不到期')
    expect(text).toContain('不會自動失效；不再使用時請自己撤銷')
  })

  it('測試指令：畫面上只露出明文前段，指向自我查驗端點；複製時給完整指令', async () => {
    const writeText = stubClipboard(() => Promise.resolve())
    const w = mountPanel()
    const shown = w.get('[data-test="reveal-command"]').text()
    expect(shown).toContain('/api/v1/api-tokens/verify')
    expect(shown).toContain('Authorization: Bearer cxp_')
    expect(shown).not.toContain(FAKE_PLAINTEXT)
    await w.get('[data-test="copy-command"]').trigger('click')
    await flushPromises()
    expect(writeText.mock.calls[0][0]).toContain(`Bearer ${FAKE_PLAINTEXT}`)
    expect(w.get('[data-test="command-copied"]').text()).toBe('已複製')
  })

  it('複製明文成功：按鈕下方出現已複製', async () => {
    const writeText = stubClipboard(() => Promise.resolve())
    const w = mountPanel()
    await w.get('[data-test="copy-secret"]').trigger('click')
    await flushPromises()
    expect(writeText).toHaveBeenCalledWith(FAKE_PLAINTEXT)
    expect(w.get('[data-test="secret-copied"]').text()).toBe('已複製')
  })

  it('瀏覽器不允許複製：紅字請手動保存，明文仍在畫面上可選取', async () => {
    stubClipboard(() => Promise.reject(new Error('denied')))
    const w = mountPanel()
    await w.get('[data-test="copy-secret"]').trigger('click')
    await flushPromises()
    expect(w.get('[data-test="secret-copy-failed"]').text()).toBe('無法複製，請在離開前手動保存。')
    expect(w.get('[data-test="reveal-secret"]').text()).toBe(FAKE_PLAINTEXT)
    expect(w.find('[data-test="secret-copied"]').exists()).toBe(false)
  })

  it('測試指令複製失敗：指令框改顯示完整指令（可手動複製），紅字說明已改顯示完整指令', async () => {
    stubClipboard(() => Promise.reject(new Error('denied')))
    const w = mountPanel()
    expect(w.get('[data-test="reveal-command"]').text()).not.toContain(FAKE_PLAINTEXT)
    await w.get('[data-test="copy-command"]').trigger('click')
    await flushPromises()
    expect(w.get('[data-test="reveal-command"]').text()).toContain(`Bearer ${FAKE_PLAINTEXT}`)
    expect(w.get('[data-test="command-copy-failed"]').text()).toContain('已改顯示完整指令')
  })
})

describe('明文面板的權限', () => {
  const panel = (access, levels) =>
    mountPanel({
      ...tokenProdApply({
        name: 'terraform-prod-apply-2',
        access,
        granted_roles: [roleAsset({ level: levels[0] }), roleAuthz({ level: levels[1] })],
      }),
      token: FAKE_PLAINTEXT,
    })

  it('部分讀寫：權限列寫總結與一句說明，授權角色一行一個並各帶權限小標', () => {
    const w = panel('mixed', ['read_write', 'read'])
    expect(w.get('[data-test="reveal-access"] [data-test="access-tag"]').text()).toBe('部分讀寫')
    expect(w.get('[data-test="reveal-access"] [data-test="access-sub"]').text()).toBe('會改變資料的動作只能用設為讀寫的角色做')
    expect(w.get('[data-test="reveal-role-5"] [data-test="level-tag"]').text()).toBe('讀寫')
    expect(w.get('[data-test="reveal-role-9"] [data-test="level-tag"]').text()).toBe('唯讀')
  })

  it('全部唯讀與全部讀寫各有固定的說明', () => {
    expect(panel('read', ['read', 'read']).get('[data-test="reveal-access"]').text()).toContain('只能讀取，不能改變任何資料')
    expect(panel('read_write', ['read_write', 'read_write']).get('[data-test="reveal-access"]').text()).toContain('每個授權角色都可以讀取與修改')
  })

  it('測試指令的說明寫出回應會列出各角色的權限', () => {
    const w = panel('read', ['read', 'read'])
    expect(w.get('[data-test="reveal-test"]').text()).toContain('授權角色與各自的權限')
  })
})
