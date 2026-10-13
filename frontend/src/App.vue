<template>
  <el-config-provider :locale="epLocale">
    <router-view />
  </el-config-provider>
</template>

<script setup>
// EP locale 與 main.js 的 app-level config 共用同一 reactive 來源
// 元件樹走 provider、指令式 API 走 app-level
import { epLocale } from '@/i18n/element-plus'
</script>

<style>
* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

#app {
  font-size: var(--ot-font-size-md);
  color: var(--ot-text-primary);
  background-color: var(--ot-bg-page);
  height: 100vh;
}

/* Font family and smoothing live on body, not #app: message boxes, drawers,
   notifications and dialogs are mounted on body outside #app and would fall
   back to the browser default (a serif face on some platforms). */
body {
  margin: 0;
  padding: 0;
  height: 100vh;
  background-color: var(--ot-bg-page);
  font-family: var(--ot-font-sans);
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}
</style>
