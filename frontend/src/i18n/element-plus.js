/**
 * Element Plus locale 與 i18n 的橋接（i18n-foundation D4）。
 * 單一 reactive 來源同時餵兩處：App.vue 的 el-config-provider（元件樹）與
 * main.js 的 app.use(ElementPlus, epGlobalConfig)（指令式 ElMessageBox/ElMessage
 * 走 app-level global config，provider 蓋不到——codex r1 F2 實證）。
 */
import { computed } from 'vue'
import zhTw from 'element-plus/es/locale/lang/zh-tw'
import en from 'element-plus/es/locale/lang/en'
import ja from 'element-plus/es/locale/lang/ja'
import i18n from './index'

const EP_LOCALES = {
  'zh-TW': zhTw,
  'en-US': en,
  'ja-JP': ja,
}

export const epLocale = computed(
  () => EP_LOCALES[i18n.global.locale.value] || zhTw
)

// app.use(ElementPlus, config) 內部 unref(config) 後對 .locale 的讀取仍具
// 反應性（provideGlobalConfig 以 computed 包裝），故傳 computed 即可全域連動
export const epGlobalConfig = computed(() => ({ locale: epLocale.value }))
