import { describe, it, expect, vi, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import i18n from '@/i18n'
import PreflightPanel from '../PreflightPanel.vue'

enableAutoUnmount(afterEach)

vi.mock('@/api/identitySources', () => ({
  getSourceStatus: vi.fn(() => Promise.resolve({})),
  isNotImplemented: () => false,
  errorCode: () => '',
  CODE_LDAP_DIRECTORY_NOT_FOUND: 'LDAP_DIRECTORY_NOT_FOUND',
}))

const t = (key) => i18n.global.t(key)

const mountPanel = (props = {}) =>
  mount(PreflightPanel, {
    props: {
      type: 'oidc',
      sourceId: null,
      redirectUri: 'https://bastion.example.com/api/v1/auth/oidc/callback',
      redirectUriState: 'ready',
      ...props,
    },
    global: { plugins: [ElementPlus] },
  })

describe('PreflightPanel：OIDC 接通前確認清單', () => {
  it('只列系統實際使用的登記項，不含登出後回呼網址', async () => {
    const wrapper = mountPanel()
    await flushPromises()

    const keys = wrapper.vm.checklist.map((item) => item.key)
    expect(keys).toEqual(['redirect', 'app_type', 'groups_claim', 'secret'])
    expect(wrapper.text()).not.toMatch(/\/login(\s|$)/)
  })

  it('Entra 來源時回呼網址與群組宣告兩項顯示 Entra 設定位置', async () => {
    const wrapper = mountPanel({ entra: true })
    await flushPromises()

    const hints = wrapper.findAll('[data-test="preflight-entra-hint"]').map((h) => h.text())
    expect(hints).toEqual([
      t('identitySources.preflight.oidc.entraRedirect'),
      t('identitySources.preflight.oidc.entraGroupsClaim'),
    ])
  })

  it('非 Entra 來源不顯示 Entra 提示', async () => {
    const wrapper = mountPanel()
    await flushPromises()

    expect(wrapper.findAll('[data-test="preflight-entra-hint"]')).toHaveLength(0)
  })
})
