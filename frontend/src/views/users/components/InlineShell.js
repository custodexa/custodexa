import { h } from 'vue'

/** 內嵌版的外殼：與對話框相同的 default／footer 插槽，但直接排在頁面上。 */
export default {
  name: 'InlineShell',
  inheritAttrs: false,
  setup(_, { slots }) {
    return () =>
      h('div', { class: 'inline-shell' }, [
        slots.default?.(),
        h('div', { class: 'inline-shell__footer' }, slots.footer?.()),
      ])
  },
}
