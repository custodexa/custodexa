import { describe, it, expect } from 'vitest'
import {
  SCOPE_TYPES,
  scopeType,
  scopeTypeLabel,
  scopeTargetLabel,
  buildGroupPaths,
} from '../approver-scope'

// 完備性：值域硬拷後端 model/approver_scope.go:14-46 四維恰一
//（backend 加維度時此清單紅燈提醒前端補 META）
const BACKEND_SCOPE_DIMENSIONS = ['asset', 'asset_group', 'subject_user', 'subject_group']

describe('approver-scope 顯示事實源', () => {
  it('四維 META 完備（值域硬拷後端）', () => {
    expect(Object.keys(SCOPE_TYPES).sort()).toEqual([...BACKEND_SCOPE_DIMENSIONS].sort())
    BACKEND_SCOPE_DIMENSIONS.forEach((k) => {
      expect(SCOPE_TYPES[k].label, `${k} 缺 label`).toBeTruthy()
      expect(SCOPE_TYPES[k].tagType, `${k} 缺 tagType`).toBeTruthy()
    })
  })

  it('scopeType 按四維恰一判定', () => {
    expect(scopeType({ asset_id: 1 })).toBe('asset')
    expect(scopeType({ asset_group_id: 2 })).toBe('asset_group')
    expect(scopeType({ subject_user_id: 3 })).toBe('subject_user')
    expect(scopeType({ subject_group_id: 4 })).toBe('subject_group')
    expect(scopeTypeLabel({ asset_group_id: 2 })).toBe('節點（含子樹）')
  })

  it('buildGroupPaths 由 parent_id 自組全路徑，同名節點可分辨', () => {
    const groups = [
      { id: 1, name: 'prod' },
      { id: 2, name: 'db', parent_id: 1 },
      { id: 3, name: 'staging' },
      { id: 4, name: 'db', parent_id: 3 },
    ]
    const paths = buildGroupPaths(groups)
    expect(paths[2]).toBe('prod / db')
    expect(paths[4]).toBe('staging / db')
    expect(paths[1]).toBe('prod')
  })

  it('buildGroupPaths 環路防禦不無窮迴圈', () => {
    const paths = buildGroupPaths([
      { id: 1, name: 'a', parent_id: 2 },
      { id: 2, name: 'b', parent_id: 1 },
    ])
    expect(paths[1]).toBeTruthy()
  })

  it('scopeTargetLabel：節點帶全路徑、查無名稱回 #id 降級', () => {
    const paths = { 2: 'prod / db' }
    expect(scopeTargetLabel({ asset_id: 1, asset: { name: 'web-1' } })).toBe('web-1')
    expect(scopeTargetLabel({ asset_group_id: 2 }, paths)).toBe('prod / db')
    expect(scopeTargetLabel({ subject_user_id: 3, subject_user: { username: 'alice' } })).toBe('alice')
    expect(scopeTargetLabel({ subject_group_id: 4, subject_group: { name: 'SRE' } })).toBe('SRE')
    expect(scopeTargetLabel({ subject_user_id: 9 })).toBe('#9')
  })
})

// 審核方（actor）兩型（approval-routing-quorum D-7）
import { ACTOR_TYPES, actorType, actorLabel } from '../approver-scope'

describe('approver-scope 審核方顯示', () => {
  it('審核方兩型 META 完備（值域硬拷後端 approver_id XOR approver_group_id）', () => {
    expect(Object.keys(ACTOR_TYPES).sort()).toEqual(['group', 'user'])
    Object.values(ACTOR_TYPES).forEach((m) => {
      expect(m.label).toBeTruthy()
      expect(m.tagType).toBeTruthy()
    })
  })

  it('actorType/actorLabel 按審核方恰一判定，查無回 #id 降級', () => {
    expect(actorType({ approver_id: 8 })).toBe('user')
    expect(actorType({ approver_group_id: 4 })).toBe('group')
    expect(actorLabel({ approver_id: 8, approver: { username: 'appr' } })).toBe('appr')
    expect(actorLabel({ approver_group_id: 4, approver_group: { name: 'DBA' } })).toBe('DBA')
    expect(actorLabel({ approver_group_id: 4 })).toBe('#4')
  })
})
