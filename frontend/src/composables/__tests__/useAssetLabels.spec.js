import { describe, it, expect, vi, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import { ref } from 'vue'
import { useAssetLabels } from '../useAssetLabels'
const api = vi.hoisted(() => ({ asset: vi.fn() }))
vi.mock('@/api/assets', () => ({ getAsset: api.asset }))
enableAutoUnmount(afterEach)
describe('current authorized asset labels', () => {
  it('uses known names, deduplicates IDs and leaves denied/retired assets unidentified', async () => {
    api.asset.mockReset().mockRejectedValue({ response: { status: 403 } })
    const w = mount({ setup() { return { labels: useAssetLabels(() => [{ id: 1, name: 'known' }, { id: 2 }, { id: 2 }]) } }, template: '<div />' })
    await flushPromises()
    expect(api.asset).toHaveBeenCalledTimes(1)
    expect(api.asset).toHaveBeenCalledWith(2, { skipErrorToast: true })
    expect(w.vm.labels).toEqual({ 1: { name: 'known', protocol: undefined } })
  })
  it('discards late results when the visible page changes', async () => {
    let resolve
    api.asset.mockReset().mockImplementation(id => id === 1 ? new Promise(r => { resolve = r }) : Promise.resolve({ name: 'current', protocol: 'ssh' }))
    const rows = ref([{ id: 1 }])
    const w = mount({ setup() { return { labels: useAssetLabels(() => rows.value) } }, template: '<div />' })
    rows.value = [{ id: 2 }]; await flushPromises()
    resolve({ name: 'previous' }); await flushPromises()
    expect(w.vm.labels).toEqual({ 2: { name: 'current', protocol: 'ssh' } })
  })
})
