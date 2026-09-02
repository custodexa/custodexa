import { describe, it, expect, afterEach } from 'vitest'
import { mount, enableAutoUnmount } from '@vue/test-utils'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import LoginBanner from '../LoginBanner.vue'

// 逐測卸載：殘留元件會讓後續測試耗時隨序累積
enableAutoUnmount(afterEach)

const mountBanner = (props) => mount(LoginBanner, { props })

// SFC 原始碼以 cwd（frontend 根）為錨——vitest 轉換後的 import.meta.url 非真實路徑
const readSfc = (relative) =>
  readFileSync(join(process.cwd(), 'src', relative), 'utf8')

describe('LoginBanner', () => {
  it('內文為空時不渲染任何節點', () => {
    const wrapper = mountBanner({ title: '授權使用者專用', body: '' })
    expect(wrapper.find('.login-banner').exists()).toBe(false)
    expect(wrapper.text()).toBe('')
  })

  it('內文只有空白時視同未設定', () => {
    const wrapper = mountBanner({ title: '標題', body: '   \n  ' })
    expect(wrapper.find('.login-banner').exists()).toBe(false)
  })

  it('標題為空時只渲染內文', () => {
    const wrapper = mountBanner({ title: '', body: '僅供授權使用者存取' })
    expect(wrapper.find('.login-banner').exists()).toBe(true)
    expect(wrapper.find('.login-banner-title').exists()).toBe(false)
    expect(wrapper.find('.login-banner-body').text()).toBe('僅供授權使用者存取')
  })

  it('標題與內文皆有值時兩者都顯示', () => {
    const wrapper = mountBanner({ title: '授權使用者專用', body: '連線將被記錄' })
    expect(wrapper.find('.login-banner-title').text()).toBe('授權使用者專用')
    expect(wrapper.find('.login-banner-body').text()).toBe('連線將被記錄')
  })

  it('標記字元以原字顯示，不產生對應元素', () => {
    const wrapper = mountBanner({
      title: '',
      body: '<b>x</b> <script>alert(1)</script> [連結](https://example.test)',
    })
    const body = wrapper.find('.login-banner-body')
    expect(body.text()).toContain('<b>x</b>')
    expect(body.text()).toContain('<script>alert(1)</script>')
    expect(body.text()).toContain('[連結](https://example.test)')
    expect(wrapper.find('b').exists()).toBe(false)
    expect(wrapper.find('script').exists()).toBe(false)
    expect(wrapper.find('a').exists()).toBe(false)
  })

  it('換行以 pre-wrap 保留於單一節點內', () => {
    const wrapper = mountBanner({ title: '', body: '第一行\n第二行' })
    // 讀 textContent 而非 text()——後者會 trim，看不出模板縮排有沒有混進內文
    const body = wrapper.find('.login-banner-body')
    expect(body.element.textContent).toBe('第一行\n第二行')
  })

  it('告示區塊可由鍵盤聚焦並帶區域語意', () => {
    const wrapper = mountBanner({ title: '標題', body: '內文' })
    const region = wrapper.find('.login-banner')
    expect(region.attributes('tabindex')).toBe('0')
    expect(region.attributes('role')).toBe('region')
    expect(region.attributes('aria-label')).toBe('登入告示')
  })

  it('告示元件與登入頁皆不使用原始 HTML 綁定', () => {
    expect(readSfc('components/LoginBanner.vue')).not.toContain('v-html')
    expect(readSfc('views/Login.vue')).not.toContain('v-html')
  })
})
