import { createApp } from 'vue'
import { createPinia } from 'pinia'
import ElementPlus from 'element-plus'
import 'element-plus/dist/index.css'
import 'element-plus/theme-chalk/dark/css-vars.css'
import './styles/tokens.css'
import './styles/dark-theme.css'
import * as ElementPlusIconsVue from '@element-plus/icons-vue'

import App from './App.vue'
import router from './router'
import { BRAND } from './brand'
import i18n, { setupDocumentMetadata } from './i18n'
import { epGlobalConfig } from './i18n/element-plus'

// 品牌樣板（brand-theming L0）：favicon 由 brand.js 驅動，index.html 不含品牌字；
// title 由 setupDocumentMetadata 隨語言切換更新（i18n-foundation D8），不在此一次性賦值
const favicon = document.querySelector('link[rel="icon"]')
if (favicon) favicon.href = BRAND.icon

const app = createApp(App)

// Pinia state management
app.use(createPinia())

// Vue Router
app.use(router)

// i18n（須於 mount 前安裝，元件 useI18n() 依賴此注入）
app.use(i18n)

// Element Plus：app-level config 傳 reactive locale——指令式 API
// （ElMessageBox/ElMessage）讀 app-level global config，須與
// el-config-provider 共用同一來源才會隨語言切換（i18n-foundation D4）
app.use(ElementPlus, epGlobalConfig)

// title 與 <html lang> 隨語言即時更新（watch immediate）
setupDocumentMetadata()

// Register Element Plus icons
for (const [key, component] of Object.entries(ElementPlusIconsVue)) {
  app.component(key, component)
}

app.mount('#app')
