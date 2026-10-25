import { describe, it, expect } from 'vitest'
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { ENTRY_RULES, canEnter } from '../entryRules'

// 入口規則的後端鏡像與前端 ENTRY_RULES 由同一份 golden 雙向比對（後端另有 TestRouteEntryRulesMirror）。
// golden 在開發容器掛在 /repo 下；主機端（CI）從 frontend/ 往上找。兩處都沒有是失敗，不是略過：
// 悄悄略過的等價檢查會空洞地通過。
const GOLDEN_REL = 'backend/internal/api/testdata/route-entry-rules.json'
const goldenPath = [`/repo/${GOLDEN_REL}`, join(process.cwd(), '..', GOLDEN_REL)].find((p) => existsSync(p))

const loadGolden = () => {
  if (!goldenPath) throw new Error(`共用 golden 不存在：${GOLDEN_REL}`)
  return JSON.parse(readFileSync(goldenPath, 'utf8'))
}

// ENTRY_RULES 的一筆規則轉成 golden 的列形狀。形狀不明（三者皆無或並存）以 kind 'invalid' 呈現，必然對不上。
const toRow = (path, rule) => {
  const shapes = [rule.signedIn === true, Array.isArray(rule.permissionsAll), Array.isArray(rule.permissionsAny)]
  if (shapes.filter(Boolean).length !== 1) return { path, kind: 'invalid', permissions: [] }
  if (rule.signedIn) return { path, kind: 'signed_in', permissions: [] }
  if (rule.permissionsAll) return { path, kind: 'all', permissions: [...rule.permissionsAll] }
  return { path, kind: 'any', permissions: [...rule.permissionsAny] }
}

const rowsOf = (rules) => Object.entries(rules).map(([path, rule]) => toRow(path, rule))

// 雙向比對，回傳每一處差異（空陣列＝相等）。權限鍵當集合比較。
export const compareRules = (rules, golden) => {
  const norm = (p) => [...p].sort().join(',')
  const mine = new Map(rowsOf(rules).map((r) => [r.path, r]))
  const theirs = new Map(golden.map((r) => [r.path, r]))
  const diffs = []
  for (const [path, r] of mine) {
    const g = theirs.get(path)
    if (!g) diffs.push(`${path}：ENTRY_RULES 有、golden 沒有`)
    else if (r.kind !== g.kind) diffs.push(`${path}：規則種類 ENTRY_RULES=${r.kind} golden=${g.kind}`)
    else if (norm(r.permissions) !== norm(g.permissions)) diffs.push(`${path}：權限鍵不同`)
  }
  for (const path of theirs.keys()) if (!mine.has(path)) diffs.push(`${path}：golden 有、ENTRY_RULES 沒有`)
  return diffs.sort()
}

describe('入口規則鏡像（與後端共用 golden）', () => {
  it('golden 存在（缺檔即失敗，不略過）', () => {
    expect(goldenPath, `找不到 ${GOLDEN_REL}`).toBeTruthy()
    expect(Array.isArray(loadGolden())).toBe(true)
  })

  it('ENTRY_RULES 與 golden 雙向相等（路徑集合、規則種類、權限鍵）', () => {
    expect(compareRules(ENTRY_RULES, loadGolden())).toEqual([])
  })

  it('golden 列數等於 ENTRY_RULES 列數，且不少於鏡像建立時凍結的 34 列', () => {
    const golden = loadGolden()
    expect(golden.length).toBe(Object.keys(ENTRY_RULES).length)
    expect(golden.length).toBeGreaterThanOrEqual(34)
  })

  it('比對器抓得到改規則、刪列與多列（在記憶體副本上）', () => {
    const golden = loadGolden()
    const copy = () => JSON.parse(JSON.stringify(ENTRY_RULES))
    expect(compareRules(copy(), golden)).toEqual([])
    const changed = copy()
    changed['/credentials'] = { permissionsAll: ['credential:view'] }
    expect(compareRules(changed, golden).some((d) => d.startsWith('/credentials'))).toBe(true)
    const dropped = copy()
    delete dropped['/users']
    expect(compareRules(dropped, golden)).toContain('/users：golden 有、ENTRY_RULES 沒有')
    const extra = { ...copy(), '/ghost': { signedIn: true } }
    expect(compareRules(extra, golden)).toContain('/ghost：ENTRY_RULES 有、golden 沒有')
  })

  it('以 golden 規則求 canEnter 與 ENTRY_RULES 一致（經 golden 還原規則形狀）', () => {
    const toRule = (row) =>
      row.kind === 'signed_in' ? { signedIn: true }
        : row.kind === 'all' ? { permissionsAll: row.permissions }
          : { permissionsAny: row.permissions }
    const only = (...keys) => (perms) => perms.every((p) => keys.includes(p))
    const byPath = Object.fromEntries(loadGolden().map((r) => [r.path, toRule(r)]))
    // 只具備 credential:set-secret：進得了憑證庫、進不了告警頁；只具備 audit:view：反之
    expect(canEnter(byPath['/credentials'], only('credential:set-secret'))).toBe(true)
    expect(canEnter(byPath['/alerts'], only('credential:set-secret'))).toBe(false)
    expect(canEnter(byPath['/alerts'], only('audit:view'))).toBe(true)
    expect(canEnter(byPath['/credentials'], only('audit:view'))).toBe(false)
    // 登入即可的入口不看能力
    expect(canEnter(byPath['/assets'], only())).toBe(true)
    for (const [path, rule] of Object.entries(ENTRY_RULES)) {
      for (const has of [only(), only('audit:view'), only('credential:set-secret'), only('user:manage')]) {
        expect(canEnter(byPath[path], has), path).toBe(canEnter(rule, has))
      }
    }
  })
})
