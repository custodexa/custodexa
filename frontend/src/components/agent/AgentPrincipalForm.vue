<template>
  <el-form
    label-position="top"
    data-test="agent-principal-form"
    @submit.prevent="submit"
  >
    <el-alert
      v-if="error"
      :title="error"
      type="error"
      :closable="false"
      show-icon
    />
    <el-form-item
      :label="t('common.username')"
      required
    >
      <el-input
        v-model="username"
        maxlength="50"
        data-test="agent-username"
      />
    </el-form-item>
    <el-form-item
      :label="t('agentPrincipals.owner')"
      required
    >
      <el-select
        v-model="ownerId"
        filterable
        remote
        :remote-method="loadOwners"
        :loading="loadingOwners"
        :placeholder="t('agentPrincipals.selectOwner')"
        data-test="agent-owner"
      >
        <el-option
          v-for="owner in owners"
          :key="owner.id"
          :label="`${owner.username} (#${owner.id})`"
          :value="owner.id"
        />
      </el-select>
    </el-form-item>
    <p class="agent-form__hint">
      {{ t('agentPrincipals.creationHelp') }}
    </p>
    <div class="agent-form__actions">
      <el-button
        :disabled="busy"
        @click="emit('cancel')"
      >
        {{ t('common.cancel') }}
      </el-button><el-button
        type="primary"
        :loading="busy"
        data-test="agent-submit"
        @click="submit"
      >
        {{ t('common.confirm') }}
      </el-button>
    </div>
  </el-form>
</template>
<script setup>
import { ref, onMounted, onBeforeUnmount } from 'vue'
import { t } from '@/i18n'
import { getUserList } from '@/api/user'
import { createAgentPrincipal } from '@/api/agents'
import { resolveApiError } from '@/api/error'
const emit = defineEmits(['created', 'cancel'])
const username = ref('')
const ownerId = ref(null)
const owners = ref([])
const loadingOwners = ref(false)
const busy = ref(false)
const error = ref('')
let lookup = 0
let disposed = false
async function loadOwners(search = '') {
  const version = ++lookup
  loadingOwners.value = true
  try {
    // This endpoint excludes agents by default; search is server-side.
    const result = await getUserList({ page: 1, page_size: 50, active: true, search: search || undefined })
    if (!disposed && version === lookup) owners.value = result.data || []
  } catch (cause) { if (!disposed && version === lookup) error.value = resolveApiError(cause?.response?.data, cause?.response?.status) }
  finally { if (!disposed && version === lookup) loadingOwners.value = false }
}
async function submit() {
  if (busy.value) return
  error.value = ''
  if (!ownerId.value) { error.value = resolveApiError({ code: 'VALIDATION_AGENT_OWNER_REQUIRED' }, 400); return }
  if (username.value.trim().length < 3) { error.value = t('users.usernameLength'); return }
  busy.value = true
  try {
    const result = await createAgentPrincipal({ username: username.value.trim(), owner_user_id: ownerId.value, roles: ['user'] })
    if (!disposed) emit('created', result)
  } catch (cause) { if (!disposed) error.value = resolveApiError(cause?.response?.data, cause?.response?.status) }
  finally { if (!disposed) busy.value = false }
}
onMounted(() => loadOwners())
onBeforeUnmount(() => { disposed = true; lookup++ })
</script>
<style scoped>
.agent-form__hint { color: var(--ot-text-secondary); font-size: var(--ot-font-size-sm); margin: var(--ot-space-md) 0; }
.agent-form__actions { display: flex; justify-content: flex-end; gap: var(--ot-space-sm); }
</style>
