import { describe, it, expect } from 'vitest'
import { ROLE_META, roleLabel, roleTagType, roleDescription } from '../roles'

// 角色顯示中繼資料完備性（role-enum-metadata-sync）：
// 後端 seed 四角色必須每個都有 label/tagType/description——
// 新增後端角色時此測試逼你補 META（缺漏=裸英文+缺說明段）
const SEEDED_ROLES = ['admin', 'auditor', 'approver', 'user']

describe('ROLE_META 完備性', () => {
  it.each(SEEDED_ROLES)('%s 具備 label/tagType/description', (name) => {
    expect(ROLE_META[name]?.label, `${name} 缺 label`).toBeTruthy()
    expect(ROLE_META[name]?.tagType, `${name} 缺 tagType`).toBeTruthy()
    expect(ROLE_META[name]?.description, `${name} 缺 description`).toBeTruthy()
  })

  it('詞彙表：稽核人員/審核人員/一般使用者（汰 審計員/一般使用者）', () => {
    expect(roleLabel('auditor')).toBe('稽核人員')
    expect(roleLabel('approver')).toBe('審核人員')
    expect(roleLabel('user')).toBe('一般使用者')
    expect(roleLabel('admin')).toBe('管理員')
  })

  it('未知角色優雅退回：原文＋info 色＋空說明', () => {
    expect(roleLabel('future_role')).toBe('future_role')
    expect(roleTagType('future_role')).toBe('info')
    expect(roleDescription('future_role')).toBe('')
  })
})
