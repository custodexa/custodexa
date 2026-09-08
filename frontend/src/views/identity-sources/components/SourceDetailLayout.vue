<template>
  <div class="source-detail">
    <div class="source-detail__crumb">
      <router-link to="/identity-sources">
        {{ $t('identitySources.title') }}
      </router-link>
      <span class="source-detail__sep">/</span>
      <span>{{ title || $t('identitySources.unnamed') }}</span>
    </div>

    <div class="source-detail__head">
      <div class="source-detail__heading">
        <span class="source-detail__title">{{ title || $t('identitySources.unnamed') }}</span>
        <el-tag
          size="small"
          effect="plain"
        >
          {{ typeLabel }}
        </el-tag>
        <el-tag
          size="small"
          :type="enabled ? 'success' : 'info'"
          :effect="enabled ? 'light' : 'plain'"
        >
          {{ enabled ? $t('common.enabled') : $t('common.disabled') }}
        </el-tag>
      </div>
      <div class="source-detail__sub">
        {{ subtitle }}
      </div>
    </div>

    <div class="source-detail__body">
      <div class="source-detail__main">
        <slot />
      </div>
      <aside class="source-detail__aside">
        <slot name="panel" />
      </aside>
    </div>

    <!-- 頁底動作列。**破壞性動作不占主鍵位**：停用會讓經此來源登入的人全數
         進不來，它不該是滑到頁底最順手按到的那一顆。故已啟用時主鍵是「儲存」，
         停用退居次鍵；未啟用時主鍵才是「儲存並啟用」 -->
    <div class="source-detail__actions">
      <div class="source-detail__actions-left">
        <template v-if="enabled">
          <el-button
            type="primary"
            :loading="saving"
            :disabled="!canSave"
            @click="$emit('save', true)"
          >
            {{ $t('common.save') }}
          </el-button>
          <el-button
            :disabled="saving || !canSave"
            @click="$emit('save', false)"
          >
            {{ $t('identitySources.disableSource') }}
          </el-button>
        </template>
        <template v-else>
          <el-button
            type="primary"
            :loading="saving"
            :disabled="!canSave"
            @click="$emit('save', true)"
          >
            {{ $t('identitySources.saveAndEnable') }}
          </el-button>
          <el-button
            :disabled="saving || !canSave"
            @click="$emit('save', false)"
          >
            {{ $t('identitySources.saveWithoutEnabling') }}
          </el-button>
        </template>
        <span
          v-if="dirty"
          class="source-detail__dirty"
        >{{ $t('identitySources.unsavedChanges') }}</span>
      </div>
      <div class="source-detail__actions-right">
        <span
          v-if="lastSaved"
          class="source-detail__meta"
        >{{ lastSaved }}</span>
        <el-button
          :loading="testing"
          @click="$emit('test')"
        >
          {{ $t('identitySources.testConnection') }}
        </el-button>
      </div>
    </div>
  </div>
</template>

<script setup>
defineProps({
  title: { type: String, default: '' },
  typeLabel: { type: String, required: true },
  subtitle: { type: String, default: '' },
  enabled: { type: Boolean, default: false },
  saving: { type: Boolean, default: false },
  testing: { type: Boolean, default: false },
  dirty: { type: Boolean, default: false },
  // 讀取失敗或尚未讀到時不得存：空白表單送出去會把伺服器上的設定清空
  canSave: { type: Boolean, default: true },
  lastSaved: { type: String, default: '' },
})

defineEmits(['save', 'test'])
</script>

<style scoped>
.source-detail {
  padding-bottom: 72px;
}

.source-detail__crumb {
  margin-bottom: var(--ot-space-sm);
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-sm);
}

.source-detail__crumb a {
  color: var(--ot-primary, var(--el-color-primary));
  text-decoration: none;
}

.source-detail__sep {
  margin: 0 var(--ot-space-xs);
  color: var(--ot-text-disabled);
}

.source-detail__head {
  margin-bottom: var(--ot-space-lg);
}

.source-detail__heading {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: var(--ot-space-xs);
}

.source-detail__title {
  font-size: var(--ot-font-size-xl);
  font-weight: 600;
  color: var(--ot-text-primary);
}

.source-detail__sub {
  margin-top: var(--ot-space-xs);
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-sm);
}

/* 左寬右窄兩欄：右欄是常駐的接通前確認面板 */
.source-detail__body {
  display: flex;
  align-items: flex-start;
  gap: var(--ot-space-lg);
}

.source-detail__main {
  flex: 1;
  min-width: 0;
}

.source-detail__aside {
  width: 340px;
  flex-shrink: 0;
}

/* 窄視窗改為單欄：面板落到表單之後，不擠壓表單欄位 */
@media (max-width: 1180px) {
  .source-detail__body {
    flex-direction: column;
  }

  .source-detail__aside {
    width: 100%;
  }
}

.source-detail__actions {
  position: sticky;
  bottom: 0;
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: var(--ot-space-sm);
  margin-top: var(--ot-space-md);
  padding: var(--ot-space-sm) var(--ot-space-md);
  background-color: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
}

.source-detail__actions-left,
.source-detail__actions-right {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
}

/* 未儲存變更：與旁邊的中性提示同尺寸但走警示色 */
.source-detail__dirty {
  color: var(--ot-warning, #e6a23c);
  font-size: var(--ot-font-size-xs);
}

.source-detail__meta {
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
}
</style>
