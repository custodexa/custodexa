// EP locale 橋接測試（i18n-foundation D4/codex r1 F2）：
// 指令式 ElMessageBox 走 app-level global config——驗證與 provider 共用的
// reactive 來源確實讓預設按鈕文字隨語言切換（含開啟中即時換語）
import { describe, it, expect, afterEach } from 'vitest'
import { createApp, h, nextTick } from 'vue'
import ElementPlus, { ElMessageBox } from 'element-plus'
import i18n, { DEFAULT_LOCALE, LANG_STORAGE_KEY, setLanguage } from '@/i18n'
import { epGlobalConfig, epLocale } from '@/i18n/element-plus'

describe('Element Plus locale 橋接', () => {
  afterEach(() => {
    i18n.global.locale.value = DEFAULT_LOCALE
    localStorage.removeItem(LANG_STORAGE_KEY)
    document.body.innerHTML = ''
  })

  it('epLocale 隨 i18n 語言映射 EP locale 物件', () => {
    expect(epLocale.value.name).toBe('zh-tw')
    i18n.global.locale.value = 'en-US'
    expect(epLocale.value.name).toBe('en')
    i18n.global.locale.value = 'ja-JP'
    expect(epLocale.value.name).toBe('ja')
  })

  it('指令式 MessageBox 預設按鈕文字隨語言（開啟中即時換語）', async () => {
    const host = document.createElement('div')
    document.body.appendChild(host)
    const app = createApp({ render: () => h('div') })
    app.use(i18n)
    app.use(ElementPlus, epGlobalConfig)
    app.mount(host)

    ElMessageBox.confirm('content', 'title').catch(() => {})
    await nextTick()
    await new Promise((r) => setTimeout(r))

    const confirmBtn = document.querySelector(
      '.el-message-box__btns .el-button--primary'
    )
    expect(confirmBtn, 'MessageBox 應已渲染').toBeTruthy()
    expect(confirmBtn.textContent.trim()).toBe('確定')

    setLanguage('en-US')
    await nextTick()
    await new Promise((r) => setTimeout(r))
    expect(confirmBtn.textContent.trim()).toBe('OK')

    ElMessageBox.close()
    app.unmount()
  })
})
