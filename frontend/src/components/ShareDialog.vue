<template>
  <el-dialog
    :model-value="modelValue"
    :title="$t('shareDialog.title')"
    width="460px"
    @update:model-value="$emit('update:modelValue', $event)"
  >
    <template v-if="share">
      <el-alert
        type="success"
        :closable="false"
        :title="$t('shareDialog.created')"
      />
      <el-input
        :model-value="shareUrl"
        readonly
        class="share-url"
      >
        <template #append>
          <el-button @click="copyUrl">
            {{ $t('common.copy') }}
          </el-button>
        </template>
      </el-input>
      <div class="share-hint">
        {{ $t('shareDialog.validUntil', { time: formatTime(share.expires_at) }) }}
      </div>
    </template>
    <template v-else>
      <el-form
        label-position="top"
        size="small"
      >
        <el-form-item :label="$t('shareDialog.ttlLabel')">
          <el-input-number
            v-model="ttl"
            :min="1"
            :max="60"
          />
        </el-form-item>
      </el-form>
    </template>

    <template #footer>
      <el-button
        v-if="share"
        type="danger"
        :loading="busy"
        @click="revoke"
      >
        {{ $t('shareDialog.revoke') }}
      </el-button>
      <el-button
        v-else
        type="primary"
        :loading="busy"
        :disabled="!sessionId"
        @click="create"
      >
        {{ $t('shareDialog.create') }}
      </el-button>
    </template>
  </el-dialog>
</template>

<script setup>
import { ref, computed } from 'vue'
import { ElMessage } from 'element-plus'
import { createSessionShare, revokeSessionShare } from '@/api/sessions'
import { t, currentLocale } from '@/i18n'

const props = defineProps({
  modelValue: { type: Boolean, default: false },
  sessionId: { type: [Number, String], default: null },
})
defineEmits(['update:modelValue'])

const share = ref(null)
const ttl = ref(10)
const busy = ref(false)

const shareUrl = computed(() =>
  share.value ? `${window.location.origin}${share.value.share_path}` : ''
)

async function create() {
  busy.value = true
  try {
    share.value = await createSessionShare(props.sessionId, { ttl_minutes: ttl.value })
  } catch (err) {
    console.error('[ShareDialog] 建立分享失敗:', err)
  } finally {
    busy.value = false
  }
}

async function revoke() {
  busy.value = true
  try {
    await revokeSessionShare(props.sessionId)
    share.value = null
    ElMessage.success(t('shareDialog.revoked'))
  } catch (err) {
    console.error('[ShareDialog] 撤銷分享失敗:', err)
  } finally {
    busy.value = false
  }
}

async function copyUrl() {
  try {
    await navigator.clipboard.writeText(shareUrl.value)
    ElMessage.success(t('shareDialog.linkCopied'))
  } catch {
    ElMessage.error(t('common.copyFailed'))
  }
}

function formatTime(iso) {
  return new Date(iso).toLocaleTimeString(currentLocale())
}

defineExpose({ create, revoke, share, shareUrl })
</script>

<style scoped>
.share-url {
  margin-top: 12px;
}

.share-hint {
  margin-top: 8px;
  font-size: 12px;
  color: var(--el-text-color-secondary);
}
</style>
