import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { resolve } from 'path'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [vue()],
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src'),
    },
  },
  server: {
    host: '0.0.0.0',
    port: 3000,
    proxy: {
      '/api/v1/connect': {
        target: 'ws://backend:8080',
        ws: true,
        changeOrigin: true,
      },
      '/api/v1/ssh': {
        target: 'ws://backend:8080',
        ws: true,
        changeOrigin: true,
      },
      // 會話即時監看 WS（一般 /sessions REST 請求同樣由此轉發到 backend）
      '/api/v1/sessions': {
        target: 'http://backend:8080',
        ws: true,
        changeOrigin: true,
      },
      '/api': {
        target: 'http://backend:8080',
        changeOrigin: true,
        rewrite: (path) => path,
      },
      '/ws': {
        target: 'ws://backend:8080',
        ws: true,
      },
    },
  },
  build: {
    outDir: 'dist',
    assetsDir: 'assets',
    sourcemap: false,
  },
})
