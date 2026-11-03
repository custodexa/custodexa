<template>
  <el-form-item
    :label="t('assets.rotationChannel')"
    data-test="db-rotation-channel-item"
  >
    <el-select
      v-model="form.rotation_channel"
      :empty-values="[null, undefined]"
      class="full"
      data-test="db-rotation-channel"
      @change="() => emit('rotation-channel-change')"
    >
      <el-option
        :label="t('assets.dbRotation.optionNone')"
        value=""
      />
      <el-option
        :label="t('assets.dbRotation.optionDbNative')"
        value="db_native"
      />
    </el-select>
    <div
      v-if="dbRotationUnencrypted"
      class="db-rotation-alert"
      role="alert"
      data-test="db-rotation-unencrypted"
    >
      <TriangleAlert
        class="db-rotation-alert__icon"
        :size="16"
        aria-hidden="true"
      />
      <div class="db-rotation-alert__text">
        <div class="db-rotation-alert__title">
          {{ t('assets.dbRotation.unencryptedTitle') }}
        </div>
        <div data-test="db-rotation-unencrypted-body">
          {{ t('assets.dbRotation.unencryptedBody', { mode: tlsModeLabel }) }}
        </div>
        <el-button
          link
          type="primary"
          class="db-rotation-alert__action"
          data-test="db-rotation-go-tls"
          @click="emit('go-tls')"
        >
          {{ t('assets.dbRotation.goToTls') }}
        </el-button>
      </div>
    </div>
    <div
      v-else-if="form.rotation_channel === 'db_native'"
      class="form-tip db-rotation-encrypted"
      data-test="db-rotation-encrypted"
    >
      <Lock
        :size="12"
        aria-hidden="true"
      />
      {{ t('assets.dbRotation.encrypted', { mode: tlsModeLabel }) }}
    </div>
    <div class="form-tip">
      {{ t('assets.dbRotation.hint') }}
    </div>
    <div
      v-if="form.rotation_channel === 'db_native'"
      class="db-rotation-limits"
      data-test="db-rotation-limits"
    >
      <button
        type="button"
        class="db-rotation-limits__toggle"
        :aria-expanded="limitsOpen"
        data-test="db-rotation-limits-toggle"
        @click="limitsOpen = !limitsOpen"
      >
        <component
          :is="limitsOpen ? ChevronDown : ChevronRight"
          :size="12"
          aria-hidden="true"
        />
        {{ t('assets.dbRotation.limitsTitle') }}
      </button>
      <ul
        v-if="limitsOpen"
        class="db-rotation-limits__list"
      >
        <li
          v-for="n in 5"
          :key="n"
          :data-test="`db-rotation-limit-${n}`"
        >
          {{ t(`assets.dbRotation.limit${n}`) }}
        </li>
      </ul>
    </div>
  </el-form-item>
</template>

<script setup>
// 資料庫資產的改密通道選擇與未加密提示。未加密只提示不阻擋；
// 表單未存檔，只能以前端硬拷的加密檔位即時判定，儲存後的權威結果以伺服端回傳的傳輸風險為準。
import { ref, computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { TriangleAlert, Lock, ChevronDown, ChevronRight } from 'lucide-vue-next'
import { DB_ROTATION_ENCRYPTED_TLS_MODES } from '@/constants/rotationChannel'

const form = defineModel('form', { type: Object, required: true })

// go-tls：請上層把焦點移到 TLS 模式欄位（只移焦點，不改值）
const emit = defineEmits(['rotation-channel-change', 'go-tls'])

const { t } = useI18n()

const dbRotationUnencrypted = computed(
  () =>
    form.value.rotation_channel === 'db_native' &&
    !DB_ROTATION_ENCRYPTED_TLS_MODES.includes(form.value.db_tls_mode)
)

// 檔位名稱沿用 TLS 模式選單的既有文案，讓使用者對得上上方欄位
const TLS_MODE_LABEL_KEYS = {
  '': 'assets.tlsDefault',
  disable: 'assets.tlsDisable',
  require: 'assets.tlsRequire',
  'verify-ca': 'assets.tlsVerifyCa',
  'verify-full': 'assets.tlsVerifyFull',
}
const tlsModeLabel = computed(() => {
  const key = TLS_MODE_LABEL_KEYS[form.value.db_tls_mode || '']
  return key ? t(key) : form.value.db_tls_mode
})

const limitsOpen = ref(false)
</script>

<style scoped>
.full {
  width: 100%;
}

.form-tip {
  font-size: var(--ot-font-size-xs);
  color: var(--el-text-color-secondary);
  line-height: 1.6;
}

.db-rotation-alert {
  display: flex;
  gap: var(--ot-space-sm);
  width: 100%;
  margin-top: var(--ot-space-sm);
  padding: var(--ot-space-sm) var(--ot-space-md);
  border: 1px solid color-mix(in srgb, var(--ot-warning) 45%, transparent);
  border-radius: 6px;
  background: color-mix(in srgb, var(--ot-warning) 10%, transparent);
  font-size: var(--ot-font-size-xs);
  line-height: 1.6;
}

.db-rotation-alert__icon {
  flex: none;
  margin-top: 2px;
  color: var(--ot-warning);
}

.db-rotation-alert__title {
  font-weight: 600;
}

.db-rotation-alert__action {
  padding: 0;
  height: auto;
  font-size: var(--ot-font-size-xs);
}

.db-rotation-encrypted {
  display: flex;
  align-items: center;
  gap: 4px;
  margin-top: 4px;
}

.db-rotation-limits {
  width: 100%;
}

.db-rotation-limits__toggle {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 0;
  border: none;
  background: none;
  color: var(--ot-primary);
  font-size: var(--ot-font-size-xs);
  cursor: pointer;
}

.db-rotation-limits__list {
  margin: 4px 0 0;
  padding-left: 1.4em;
  font-size: var(--ot-font-size-xs);
  line-height: 1.7;
  color: var(--el-text-color-regular);
}
</style>
