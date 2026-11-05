<template>
  <el-button
    v-if="visible"
    :loading="checking"
    data-test="keystroke-entry"
    @click="open"
  >
    <el-icon v-if="!checking">
      <Keyboard />
    </el-icon>
    {{ $t('keystrokeView.entry.button') }}
  </el-button>
  <KeystrokeReasonDialog
    v-if="visible"
    v-model="reasonOpen"
    :session-id="sessionId"
    @success="onSuccess"
    @rights-lost="rightsLost = true"
    @not-viewable="onNotViewable"
  />
  <KeystrokeStatusDialog
    v-if="visible"
    v-model="statusOpen"
    :meta="meta"
  />
</template>

<script setup>
// 連線詳情頁頁首的鍵盤紀錄入口：只對持 keystroke:view 者顯示。
// 按下先查中繼資料（不解密、不需理由）：有可查看內容開理由對話框；沒有就直接顯示狀態說明。
import { computed, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { Keyboard } from 'lucide-vue-next'
import { t } from '@/i18n'
import { can } from '@/composables/useCapabilities'
import { getKeystrokeMeta } from '@/api/keystrokes'
import { holdKeystrokeView } from '@/utils/keystrokeView'
import KeystrokeReasonDialog from './KeystrokeReasonDialog.vue'
import KeystrokeStatusDialog from './KeystrokeStatusDialog.vue'

const props = defineProps({
  sessionId: { type: [String, Number], required: true },
})

const router = useRouter()
const rightsLost = ref(false)
const visible = computed(() => !rightsLost.value && can('keystroke:view'))
const checking = ref(false)
const reasonOpen = ref(false)
const statusOpen = ref(false)
const meta = ref(null)

const open = async () => {
  if (checking.value) return
  checking.value = true
  try {
    const res = await getKeystrokeMeta(props.sessionId)
    meta.value = res?.data ?? null
    if (meta.value?.viewable) reasonOpen.value = true
    else statusOpen.value = true
  } catch {
    ElMessage.error(t('keystrokeView.entry.metaFailed'))
  } finally {
    checking.value = false
  }
}

const onSuccess = ({ reason, data, loggedAt }) => {
  holdKeystrokeView(props.sessionId, reason, { data, loggedAt })
  router.push({ name: 'KeystrokeViewer', params: { id: String(props.sessionId) } })
}

// 送出時發現紀錄已不可查看：改走狀態說明
const onNotViewable = async () => {
  try {
    const res = await getKeystrokeMeta(props.sessionId)
    meta.value = res?.data ?? null
    statusOpen.value = true
  } catch {
    ElMessage.error(t('keystrokeView.entry.metaFailed'))
  }
}
</script>
