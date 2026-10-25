// 外部群組映射頁的重新驗證時限說明：三語都能把時限值插進句子，且兩種狀態講的是不同的事。
//
// 時限有值時，說明要同時交代「工作階段上限」與「讀不到群組超過時限即收回」；
// 設為 0 時，說明要交代「沒有上限、保留到下次登入」。呼叫端以 {limit} 傳入已帶單位的時限值。
import { describe, it, expect, afterEach } from 'vitest'
import i18n, { t } from '@/i18n'

const LOCALES = ['zh-TW', 'en-US', 'ja-JP']
const previous = i18n.global.locale.value

afterEach(() => {
  i18n.global.locale.value = previous
})

describe('identityGroupMappings.revalidation', () => {
  it.each(LOCALES)('%s：有時限的說明插入時限值，且不殘留未替換的變數', (locale) => {
    i18n.global.locale.value = locale
    const text = t('identityGroupMappings.revalidation.limited', { limit: '12 h' })
    expect(text).toContain('12 h')
    expect(text).not.toMatch(/\{limit\}/)
    expect(text).not.toBe('identityGroupMappings.revalidation.limited')
  })

  it.each(LOCALES)('%s：不設限的說明與有時限的說明不同，且不需要時限值', (locale) => {
    i18n.global.locale.value = locale
    const unlimited = t('identityGroupMappings.revalidation.unlimited')
    const limited = t('identityGroupMappings.revalidation.limited', { limit: '12 h' })
    expect(unlimited).not.toBe('identityGroupMappings.revalidation.unlimited')
    expect(unlimited).not.toMatch(/\{[^}]*\}/)
    expect(unlimited).not.toBe(limited)
  })
})
