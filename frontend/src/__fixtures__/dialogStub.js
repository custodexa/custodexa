// el-dialog 在 happy-dom 內以過場動畫延後渲染內容；測試改用只依 modelValue 渲染的替身。
export const ElDialogStub = {
  name: 'ElDialog',
  props: { modelValue: Boolean, title: { type: String, default: '' } },
  emits: ['update:modelValue'],
  template:
    '<div v-if="modelValue" class="dialog-stub"><h3 class="dialog-title">{{ title }}</h3><slot /><div class="dialog-footer"><slot name="footer" /></div></div>',
}
