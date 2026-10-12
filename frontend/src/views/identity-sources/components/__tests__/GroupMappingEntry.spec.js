import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import i18n from '@/i18n'
import * as identitySourcesApi from '@/api/identitySources'
import GroupMappingEntry from '../GroupMappingEntry.vue'

enableAutoUnmount(afterEach)

const getIdentitySourcesMock = vi.fn()

// 只 mock 摘要用得到的那支；其餘匯出保留原樣，好讓下方斷言「沒有呼叫規則端點」
// 不必靠 mock 清單去猜元件會呼叫什麼
vi.mock('@/api/identitySources', async (importOriginal) => {
  const actual = await importOriginal()
  const spied = {}
  for (const [name, value] of Object.entries(actual)) {
    spied[name] = typeof value === 'function' ? vi.fn(value) : value
  }
  return {
    ...spied,
    getIdentitySources: (...a) => getIdentitySourcesMock(...a),
  }
})

const t = (key, params) => i18n.global.t(key, params)

// router-link 換成帶 to 屬性的 <a>，連結目標直接從 DOM 讀
const RouterLinkStub = {
  props: ['to'],
  template: '<a :href="to" data-test="stub-link"><slot /></a>',
}

const mountEntry = (props, slots = {}) =>
  mount(GroupMappingEntry, {
    props,
    slots,
    global: { plugins: [ElementPlus], stubs: { 'router-link': RouterLinkStub } },
  })

const row = (overrides = {}) => ({
  type: 'oidc',
  id: 7,
  role_mapping_rule_count: 3,
  user_group_mapping_rule_count: 2,
  ...overrides,
})

const summary = (wrapper) => wrapper.find('[data-test="mapping-summary"]').text()
const manageLink = (wrapper) => wrapper.find('[data-test="mapping-manage-link"]')

// 會打到映射規則端點的函式：詳情頁的區段一個都不該呼叫
const RULE_FUNCTIONS = Object.keys(identitySourcesApi).filter((name) =>
  /Mapping|ExternalGroup/.test(name) && typeof identitySourcesApi[name] === 'function'
)

describe('GroupMappingEntry：詳情頁的群組映射摘要與入口', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('(a) 有數字時顯示摘要句，按鈕連到該提供者的映射頁', async () => {
    getIdentitySourcesMock.mockResolvedValue({
      data: [row({ id: 8, role_mapping_rule_count: 9 }), row()],
    })
    const wrapper = mountEntry({ type: 'oidc', sourceId: 7 })
    await flushPromises()

    expect(summary(wrapper)).toBe(t('identitySources.mapping.summary', { roles: 3, userGroups: 2 }))
    expect(manageLink(wrapper).attributes('href')).toBe('/identity-sources/oidc/7/group-mappings')
    expect(manageLink(wrapper).text()).toBe(t('identitySources.mapping.manage'))
  })

  it('(b) 兩類規則皆為 0 時顯示尚未建立', async () => {
    getIdentitySourcesMock.mockResolvedValue({
      data: [row({ role_mapping_rule_count: 0, user_group_mapping_rule_count: 0 })],
    })
    const wrapper = mountEntry({ type: 'oidc', sourceId: 7 })
    await flushPromises()

    expect(summary(wrapper)).toBe(t('identitySources.mapping.summaryNone'))
    expect(manageLink(wrapper).exists()).toBe(true)
  })

  it('(c) API 失敗時明示讀不到、不顯示 0，按鈕仍在', async () => {
    getIdentitySourcesMock.mockRejectedValue(new Error('boom'))
    const wrapper = mountEntry({ type: 'oidc', sourceId: 7 })
    await flushPromises()

    expect(summary(wrapper)).toBe(t('identitySources.mapping.summaryUnavailable'))
    expect(summary(wrapper)).not.toMatch(/0/)
    expect(summary(wrapper)).not.toBe(t('identitySources.mapping.summaryNone'))
    expect(manageLink(wrapper).attributes('href')).toBe('/identity-sources/oidc/7/group-mappings')
  })

  it.each([
    ['找不到本列', [row({ id: 99 })]],
    ['型別不同的同 id 列', [row({ type: 'ldap' })]],
    ['角色計數非數字', [row({ role_mapping_rule_count: '3' })]],
    ['使用者群組計數缺欄', [row({ user_group_mapping_rule_count: undefined })]],
  ])('(d) %s時同讀不到', async (_label, data) => {
    getIdentitySourcesMock.mockResolvedValue({ data })
    const wrapper = mountEntry({ type: 'oidc', sourceId: 7 })
    await flushPromises()

    expect(summary(wrapper)).toBe(t('identitySources.mapping.summaryUnavailable'))
    expect(manageLink(wrapper).exists()).toBe(true)
  })

  it('(e) 來源未儲存時只見須先儲存的說明，沒有按鈕、不呼叫 API', async () => {
    const wrapper = mountEntry({ type: 'oidc', sourceId: null })
    await flushPromises()

    expect(wrapper.text()).toContain(t('identitySources.mapping.needSaveFirst'))
    expect(wrapper.find('[data-test="mapping-summary"]').exists()).toBe(false)
    expect(manageLink(wrapper).exists()).toBe(false)
    expect(getIdentitySourcesMock).not.toHaveBeenCalled()
  })

  it('(f) #attr 插槽有渲染，目錄型別連到目錄的映射頁', async () => {
    getIdentitySourcesMock.mockResolvedValue({ data: [row({ type: 'ldap', id: 3 })] })
    const wrapper = mountEntry(
      { type: 'ldap', sourceId: 3 },
      { attr: '<div data-test="attr-slot">memberOf</div>' },
    )
    await flushPromises()

    expect(wrapper.find('[data-test="attr-slot"]').exists()).toBe(true)
    expect(manageLink(wrapper).attributes('href')).toBe('/identity-sources/ldap/3/group-mappings')
    expect(summary(wrapper)).toBe(t('identitySources.mapping.summary', { roles: 3, userGroups: 2 }))
  })

  it('沒有規則清單，也不呼叫任何映射規則端點（擋清單或編輯操作被帶回來）', async () => {
    getIdentitySourcesMock.mockResolvedValue({ data: [row()] })
    const wrapper = mountEntry({ type: 'oidc', sourceId: 7 })
    await flushPromises()

    expect(wrapper.find('.el-table').exists()).toBe(false)
    expect(wrapper.findAll('input').length).toBe(0)
    expect(RULE_FUNCTIONS.length).toBeGreaterThan(0)
    for (const name of RULE_FUNCTIONS) {
      expect(identitySourcesApi[name], name).not.toHaveBeenCalled()
    }
  })
})
