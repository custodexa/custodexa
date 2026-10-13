// 登入測試區：給可複製的連結與無痕說明，不開新分頁（同一個瀏覽器的新分頁共用登入）。
import { describe, it, expect, vi, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import i18n from '@/i18n'
import PreflightLoginTest from '../PreflightLoginTest.vue'

enableAutoUnmount(afterEach)

const t = (key) => i18n.global.t(key)
const P = 'identitySources.preflight.test.'
const URL = 'https://bastion.example.com/login?source=oidc:4'

const mountWith = (props) =>
  mount(PreflightLoginTest, { props: { type: 'oidc', ...props }, global: { plugins: [ElementPlus] } })

describe('PreflightLoginTest', () => {
  it('ready：顯示連結、無痕說明與後果警語；複製帶連結', async () => {
    const writeText = vi.fn(() => Promise.resolve())
    vi.stubGlobal('navigator', { clipboard: { writeText } })
    const w = mountWith({ state: 'ready', url: URL })
    expect(w.find('[data-test="login-test-url"]').text()).toBe(URL)
    expect(w.find('[data-test="login-test-private"]').text()).toBe(t(`${P}privateWindow`))
    expect(w.text()).toContain(t('identitySources.preflight.loginTestNoticeOidc'))
    await w.find('[data-test="login-test-copy"]').trigger('click')
    await flushPromises()
    expect(writeText).toHaveBeenCalledWith(URL)
    vi.unstubAllGlobals()
  })

  it('base_url_unset：不給連結，說明原因', () => {
    const w = mountWith({ state: 'base_url_unset', url: '' })
    expect(w.find('[data-test="login-test-url"]').exists()).toBe(false)
    expect(w.find('[data-test="login-test-unset"]').text()).toBe(t(`${P}baseUrlUnset`))
  })

  it('source_disabled：不給連結，說明來源啟用後才能測試', () => {
    const w = mountWith({ state: 'source_disabled', url: '' })
    expect(w.find('[data-test="login-test-url"]').exists()).toBe(false)
    expect(w.find('[data-test="login-test-disabled"]').text()).toBe(t(`${P}sourceDisabled`))
  })
})
