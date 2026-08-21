// 全域測試環境（i18n-foundation D9）：
// 1) 所有 mount 注入 i18n（zh-TW 預設，既有中文斷言不變）；
// 2) singleton Composer 跨測試 locale 污染防護——happy-dom 的 navigator.language
//    是 en-US，若不強制重設，resolveInitialLocale 會讓測試起始語言飄走。
import { config } from '@vue/test-utils'
import { beforeEach, afterEach } from 'vitest'
import i18n, { DEFAULT_LOCALE } from '@/i18n'

config.global.plugins = [...(config.global.plugins || []), i18n]

i18n.global.locale.value = DEFAULT_LOCALE

beforeEach(() => {
  i18n.global.locale.value = DEFAULT_LOCALE
})

afterEach(() => {
  i18n.global.locale.value = DEFAULT_LOCALE
})
