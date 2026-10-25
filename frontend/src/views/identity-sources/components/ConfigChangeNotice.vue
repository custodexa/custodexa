<template>
  <el-alert
    v-if="active && changed"
    class="detail-alert"
    data-test="config-change-notice"
    type="warning"
    :title="$t('identitySources.configChangeNotice')"
    :closable="false"
    show-icon
  />
</template>

<script>
// 儲存後會通知安全人員的連線設定欄位，與後端身分來源設定變更告警比較的欄位一致。
// 密碼與密鑰欄位的已存值為空字串，輸入任何內容即與已存快照不同。
export const CONNECTION_FIELDS = {
  ldap: [
    'name',
    'url',
    'bind_dn',
    'bind_password',
    'clear_bind_password',
    'base_dn',
    'user_filter',
    'attr_email',
    'attr_fullname',
    'attr_group',
    'skip_tls_verify',
  ],
  oidc: [
    'name',
    'client_secret',
    'username_claim',
    'email_claim',
    'display_name_claim',
    'groups_claim',
    'scopeExtras',
    'admission_mode',
    'rules',
    'force_shared',
  ],
}

export const changedConnectionFields = (kind, current, saved) =>
  (CONNECTION_FIELDS[kind] || []).filter(
    (k) => JSON.stringify(current?.[k]) !== JSON.stringify(saved?.[k])
  )
</script>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  kind: { type: String, required: true },
  // 表單目前值
  form: { type: Object, required: true },
  // 上次載入或儲存時的表單快照（JSON 字串）
  savedSnapshot: { type: String, default: '' },
  // 只在編輯既有來源時提示；新增尚無已存設定可比
  active: { type: Boolean, default: false },
})

const changed = computed(() => {
  if (!props.savedSnapshot) return false
  let saved
  try {
    saved = JSON.parse(props.savedSnapshot)
  } catch {
    return false
  }
  return changedConnectionFields(props.kind, props.form, saved).length > 0
})
</script>
