<template>
  <!-- 40px 頂欄：連線頁寸土寸金，頂欄只留側欄開關與會話動作，其餘垂直空間讓給終端 -->
  <div class="workspace-header">
    <el-button
      size="small"
      text
      class="header-icon"
      @click="emit('toggle-sidebar')"
    >
      {{ collapsed ? '☰' : '◀' }}
    </el-button>
    <el-link
      class="brand-link"
      :underline="false"
      @click="openSystem"
    >
      {{ BRAND.name }}
    </el-link>
    <span class="workspace-hint">{{ $t('menu.workspace') }}</span>
    <!-- 語言切換：工作區是長駐連線面，切語言免 reload 不斷線 -->
    <el-dropdown
      class="workspace-lang"
      @command="setLanguage"
    >
      <span class="workspace-lang-label">{{ LOCALE_LABELS[locale] }}</span>
      <template #dropdown>
        <el-dropdown-menu>
          <el-dropdown-item
            v-for="l in SUPPORTED_LOCALES"
            :key="l"
            :command="l"
            :disabled="l === locale"
          >
            {{ LOCALE_LABELS[l] }}
          </el-dropdown-item>
        </el-dropdown-menu>
      </template>
    </el-dropdown>
  </div>
</template>

<script setup>
import { useI18n } from 'vue-i18n'
import { BRAND } from '@/brand'
import { SUPPORTED_LOCALES, LOCALE_LABELS, setLanguage } from '@/i18n'

defineProps({
  // 側欄是否收合（決定開關鈕的符號）
  collapsed: { type: Boolean, default: false },
})

const emit = defineEmits(['toggle-sidebar'])

const { locale } = useI18n()

function openSystem() {
  window.open('/', '_blank')
}
</script>

<style scoped>
.workspace-header {
  display: flex;
  align-items: center;
  gap: 10px;
  height: 40px;
  padding: 0 10px;
  flex-shrink: 0;
  background: var(--ot-bg-elevated);
  border-bottom: 1px solid var(--ot-border);
}

.header-icon {
  color: var(--ot-terminal-fg);
}

.brand-link {
  font-weight: 600;
  color: var(--ot-terminal-fg);
}

.workspace-hint {
  font-size: 12px;
  opacity: 0.6;
  color: var(--ot-terminal-fg);
}

.workspace-lang {
  margin-left: auto;
}

.workspace-lang-label {
  cursor: pointer;
  font-size: 12px;
  color: var(--ot-terminal-fg);
  opacity: 0.7;
}

.workspace-lang-label:hover {
  opacity: 1;
  color: var(--ot-primary);
}
</style>
