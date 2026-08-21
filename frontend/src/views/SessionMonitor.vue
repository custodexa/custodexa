<template>
  <MonitorTerminal
    :session-id="sessionId"
    @back="router.push('/sessions')"
  />
</template>

<script setup>
import { useRoute, useRouter } from 'vue-router'
import MonitorTerminal from '@/components/MonitorTerminal.vue'

const route = useRoute()
const router = useRouter()
const sessionId = route.params.id
</script>
