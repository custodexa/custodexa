import { ref, watch, onBeforeUnmount } from 'vue'
import { getAsset } from '@/api/assets'

// At most the displayed page (20 items). Current authorized names, never historical snapshots.
export function useAssetLabels(source) {
  const assets = ref({})
  let epoch = 0
  watch(source, async entries => {
    const version = ++epoch
    assets.value = {}
    const known = new Map(entries.filter(entry => Number(entry.id) > 0).map(entry => [Number(entry.id), entry]))
    await Promise.all([...known].map(async ([id, entry]) => {
      let value = entry
      if (!entry.name) {
        try { const result = await getAsset(id, { skipErrorToast: true }); value = result.data || result }
        catch { value = null }
      }
      if (version === epoch && value?.name) assets.value[id] = { name: value.name, protocol: value.protocol }
    }))
  }, { immediate: true })
  onBeforeUnmount(() => { epoch++ })
  return assets
}
