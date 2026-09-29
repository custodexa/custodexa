import { describe, it, expect, afterEach } from 'vitest'
import { mount, enableAutoUnmount } from '@vue/test-utils'
import SidebarVersion from '../SidebarVersion.vue'
import { displayableVersion } from '@/utils/productVersion'

// 側欄版本行：有發布版號才顯示，其餘一律整行不渲染
enableAutoUnmount(afterEach)

const mountVersion = (props) => mount(SidebarVersion, { props })

describe('SidebarVersion', () => {
  it('展開時顯示「Custodexa <版本>」', () => {
    const wrapper = mountVersion({ raw: '1.13.0' })
    const row = wrapper.find('.sidebar-version')
    expect(row.exists()).toBe(true)
    expect(row.text()).toBe('Custodexa 1.13.0')
    expect(row.attributes('title')).toBe('Custodexa 1.13.0')
  })

  it('收合時只留版號，滑過仍看得到完整字樣', () => {
    const wrapper = mountVersion({ raw: '1.13.0', collapsed: true })
    const row = wrapper.find('.sidebar-version')
    expect(row.classes()).toContain('collapsed')
    expect(row.text()).toBe('1.13.0')
    expect(row.attributes('title')).toBe('Custodexa 1.13.0')
  })

  it('純文字、不可點：不是連結也不是按鈕', () => {
    const wrapper = mountVersion({ raw: '1.13.0' })
    expect(wrapper.find('a').exists()).toBe(false)
    expect(wrapper.find('button').exists()).toBe(false)
    expect(wrapper.find('[role="button"]').exists()).toBe(false)
  })

  it.each([
    ['開發建置的 dev', 'dev'],
    ['空字串', ''],
    ['只有空白', '   '],
    ['不像版號的字樣', 'unknown'],
  ])('%s 時整行不渲染', (_label, raw) => {
    const wrapper = mountVersion({ raw })
    expect(wrapper.find('.sidebar-version').exists()).toBe(false)
    expect(wrapper.text()).toBe('')
  })

  it('未傳版本（預設值）時整行不渲染', () => {
    const wrapper = mount(SidebarVersion)
    expect(wrapper.find('.sidebar-version').exists()).toBe(false)
  })
})

describe('displayableVersion', () => {
  it('接受發布版號與預發版後綴', () => {
    expect(displayableVersion('1.13.0')).toBe('1.13.0')
    expect(displayableVersion(' 1.13.0 ')).toBe('1.13.0')
    expect(displayableVersion('1.14.0-rc.1')).toBe('1.14.0-rc.1')
  })

  it('非字串一律不可顯示', () => {
    expect(displayableVersion(undefined)).toBe('')
    expect(displayableVersion(null)).toBe('')
    expect(displayableVersion(1.13)).toBe('')
  })
})
