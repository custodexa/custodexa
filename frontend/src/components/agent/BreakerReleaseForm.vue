<template>
  <el-form
    v-if="eligible"
    label-position="top"
    class="breaker-release"
    data-test="breaker-release"
    @submit.prevent="submit"
  >
    <el-alert
      v-if="error"
      :title="error"
      type="error"
      :closable="false"
    />
    <p
      v-if="done"
      role="status"
      data-test="release-success"
    >
      {{ t('agentBreaker.released') }}
    </p>
    <template v-else>
      <el-form-item
        :label="t('agentBreaker.reason')"
        required
      >
        <el-input
          v-model="reason"
          type="textarea"
          maxlength="1000"
          :disabled="busy"
        />
      </el-form-item>
      <p
        v-if="validation"
        role="alert"
      >
        {{ validation }}
      </p>
      <el-button
        type="primary"
        :loading="busy"
        :disabled="!reason.trim() || busy"
        data-test="release-submit"
        @click="submit"
      >
        {{ t('agentBreaker.release') }}
      </el-button>
    </template>
  </el-form>
</template>
<script setup>
import { computed, ref, watch, onBeforeUnmount } from 'vue'
import { t } from '@/i18n'
import { roleNames } from '@/composables/useRoles'
import { releaseAgentBreaker } from '@/api/agents'
import { resolveApiError } from '@/api/error'
const props = defineProps({ principal: { type: Object, required: true }, actor: { type: Object, required: true } })
const emit = defineEmits(['released'])
const reason = ref(''), error = ref(''), validation = ref(''), busy = ref(false), done = ref(false)
const eligible = computed(() => props.principal.kind === 'agent' && props.actor.id && props.actor.kind !== 'agent' && (roleNames(props.actor.roles).includes('admin') || props.principal.owner_user_id === props.actor.id))
let epoch = 0
watch(() => [props.principal.id, props.actor.id], () => { epoch++; reason.value = ''; error.value = ''; validation.value = ''; busy.value = false; done.value = false })
async function submit() {
  if (!eligible.value || busy.value || done.value) return
  validation.value = ''; error.value = ''
  const trimmed = reason.value.trim()
  if (!trimmed || new TextEncoder().encode(trimmed).length > 1000) { validation.value = t('agentBreaker.reasonRequired'); return }
  const version = epoch
  busy.value = true
  try { await releaseAgentBreaker(props.principal.id, trimmed); if (version === epoch) { done.value = true; reason.value = ''; emit('released') } }
  catch (e) { if (version === epoch) error.value = resolveApiError(e?.response?.data, e?.response?.status) }
  finally { if (version === epoch) busy.value = false }
}
onBeforeUnmount(() => { epoch++ })
</script>
<style scoped>
.breaker-release { padding: var(--ot-space-lg); border: 1px solid var(--ot-border-subtle); border-radius: var(--ot-radius-lg); background: var(--ot-bg-surface); }
p { color: var(--ot-text-secondary); font-size: var(--ot-font-size-md); }
</style>
