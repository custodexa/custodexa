import { fileURLToPath, URL } from 'node:url'
import { defineConfig } from 'vitest/config'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  test: {
    environment: 'happy-dom',
    globals: true,
    setupFiles: ['./vitest.setup.js'],
    include: ['src/**/__tests__/**/*.spec.js'],
    // element-plus 若以 ESM/CJS 雙份載入，provide/inject 的 Symbol key 會不一致，
    // 導致 el-form 欄位註冊失效（validate 永遠通過）。強制 inline 單一實例。
    server: {
      deps: {
        inline: ['element-plus'],
      },
    },
    coverage: {
      provider: 'v8',
      reporter: ['text', 'text-summary'],
      include: ['src/**/*.{js,vue}'],
      exclude: ['src/poc/**', 'src/**/__tests__/**'],
    },
  },
})
