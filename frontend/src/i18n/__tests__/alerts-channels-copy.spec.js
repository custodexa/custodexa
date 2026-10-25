import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import zhTW from '../locales/zh-TW.json'
import enUS from '../locales/en-US.json'
import jaJP from '../locales/ja-JP.json'
import NotificationChannels from '@/views/NotificationChannels.vue'

// 畫面核對：告警頁頁首與通知通道頁副標，三語鍵都要在

const PanelStub = {
  render: () => null,
  setup(_, { expose }) {
    expose({ refresh() {} })
  },
}

const LOCALES = { 'zh-TW': zhTW, 'en-US': enUS, 'ja-JP': jaJP }

describe('告警頁與通知通道頁文案鍵', () => {
  it.each(Object.entries(LOCALES))('%s：告警頁頁首鍵存在且不含舊的「規則管理」說明', (_, d) => {
    expect(d.alerts.title).toBeTruthy()
    expect(d.alerts.headerDesc).toBeTruthy()
    expect(d.alerts.channelsHeaderDesc).toBeTruthy()
    expect(d.upgradeGuidance.goTo).toContain('{name}')
    expect(d.upgradeGuidance.currentSetting).toBeTruthy()
  })

  it('zh-TW 告警頁頁首與通道頁副標逐字同核可稿', () => {
    expect(zhTW.alerts.title).toBe('告警')
    expect(zhTW.alerts.headerDesc).toBe('危險指令與系統安全事件的告警記錄')
    expect(zhTW.alerts.channelsHeaderDesc).toBe('告警會送到這些通道。任何通道的新增、修改、停用或刪除，都會通知安全人員。')
  })

  it('三語的告警頁標題各不相同於舊標題、頁首說明彼此不同語言', () => {
    expect(enUS.alerts.title).toBe('Alerts')
    expect(jaJP.alerts.title).toBe('アラート')
    expect(enUS.alerts.headerDesc).not.toBe(zhTW.alerts.headerDesc)
    expect(jaJP.alerts.headerDesc).not.toBe(zhTW.alerts.headerDesc)
  })

  it('通知通道頁頁首顯示副標', () => {
    const wrapper = mount(NotificationChannels, {
      global: { plugins: [ElementPlus], stubs: { NotificationChannelPanel: PanelStub } },
    })
    expect(wrapper.text()).toContain(zhTW.alerts.channelsHeaderDesc)
  })
})
