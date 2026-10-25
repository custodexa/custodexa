import { describe, it, expect, vi, beforeAll, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import { createHash } from 'node:crypto'
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import ElementPlus from 'element-plus'
import MainLayout from '@/components/MainLayout.vue'
import router, { createAuthGuard } from '../index'
import { ENTRY_RULES } from '../entryRules'
import { resetSessionForTests, setAccessToken } from '@/utils/session'

// Authorization decision baseline, E group: every subject x every entry rule.
//
// For each subject the real MainLayout is mounted with the subject's
// /auth/me answer (as captured by the backend baseline) and the real
// authentication guard is asked about every entry path. The record is the
// menu visibility and the guard outcome; the golden file holds the current
// behaviour and any change fails until it is re-captured with a reason.
//
// The /auth/me answers are the capability-projection input the backend baseline
// captured for the same subjects (subjects-auth-me-capabilities.json, recorded
// with the manifest hash and program version). Expectations stay the golden
// captured before the projection existed; the only approved difference is the self-service entries entry of approved-diffs.json.
// Nothing here derives permissions from roles.
//
// Re-capture: AUTHZ_BASELINE_RECAPTURE=<reason> npm run test -- authz-baseline-entries
// (refused when an existing record would change).
//
// Append-only re-capture: when entries are added, set both
// AUTHZ_BASELINE_RECAPTURE=<reason> and AUTHZ_BASELINE_APPEND_ENTRIES=<comma-separated new
// entry paths>. Every existing record is first checked with the comparator (active approvals
// apply; unapproved, pending-only, expect-mismatch, stale-active and vanished records refuse the
// write), then only the named entries are merged in. Existing records are kept as the golden
// holds them, byte for byte, and the merged golden must compare empty against the fresh capture
// before anything is written. A reason alone keeps the strict re-capture above; paths without a
// reason fail. It never writes approved-diffs.json.

enableAutoUnmount(afterEach)

vi.mock('vue-router', async (importOriginal) => {
  const actual = await importOriginal()
  return {
    ...actual,
    useRouter: () => ({ push: vi.fn() }),
    useRoute: () => ({ path: '/dashboard', query: {} }),
  }
})

const getCurrentUserMock = vi.fn()
vi.mock('@/api/auth', () => ({
  getCurrentUser: (...args) => getCurrentUserMock(...args),
  logout: vi.fn(),
}))
vi.mock('@/api/accessRequests', () => ({
  getPendingAccessRequestCount: vi.fn(() => Promise.resolve({ count: 0, review_count: 0 })),
}))
vi.mock('@/api/seal', () => ({
  getSealStatus: vi.fn(() => Promise.resolve({ state: 'unsealed' })),
  unseal: vi.fn(),
}))
// 側欄的每日簽核徽章在具簽核能力時會輪詢；不攔下就會打到真的 /api（有服務時回 401
// 觸發續期失敗而清掉會話，入口結果隨執行環境改變）
vi.mock('@/api/dailyReviews', () => ({
  getDailyReviewPendingCount: vi.fn(() => Promise.resolve({ data: { count: 0, overdue_count: 0 } })),
}))

const SUBJECTS_FILE = 'backend/cmd/server/testdata/authz-baseline/subjects-auth-me-capabilities.json'
const MANIFEST_FILE = 'backend/cmd/server/testdata/authz-baseline/manifest.json'
const APPROVED_FILE = 'backend/cmd/server/testdata/authz-baseline/approved-diffs.json'

// The dev container mounts the backend testdata under /repo; a host checkout
// (CI) reaches it relative to frontend/. Neither present is a failure, not a
// skip: a silently skipped equivalence check would pass vacuously.
const resolveShared = (rel) =>
  [`/repo/${rel}`, join(process.cwd(), '..', rel)].find((p) => existsSync(p))

const here = dirname(fileURLToPath(import.meta.url))
const GOLDEN = join(here, 'fixtures', 'authz-baseline', 'entries.golden.json')

// Entry paths as the menu lists them (query stripped).
const menuPathOf = (index) => String(index).split('?')[0]

const menuFor = async (body) => {
  localStorage.setItem('user', JSON.stringify(body))
  getCurrentUserMock.mockResolvedValue({ ...body })
  const wrapper = mount(MainLayout, {
    global: { plugins: [ElementPlus], stubs: { 'router-view': true } },
  })
  await flushPromises()
  const paths = wrapper.findAllComponents({ name: 'ElMenuItem' }).map((i) => menuPathOf(i.props('index')))
  wrapper.unmount()
  return new Set(paths)
}

const guard = createAuthGuard()

// Guard outcome: "allow" or the redirect target.
const guardResult = async (path) => {
  const resolved = router.resolve(path)
  const next = vi.fn()
  await guard({ path: resolved.path, meta: resolved.meta, query: {} }, { path: '/', meta: {} }, next)
  expect(next).toHaveBeenCalledTimes(1)
  const args = next.mock.calls[0]
  if (args.length === 0 || args[0] === undefined) return 'allow'
  return typeof args[0] === 'string' ? args[0] : JSON.stringify(args[0])
}

// Every path the menu can show for some subject: an entry absent here is
// not a menu item at all (recorded as null rather than false).
const menuCatalog = new Set()

const captureSubject = async (id, answer, entries) => {
  localStorage.clear()
  resetSessionForTests()
  const signedIn = answer.status === 200
  let menu = null
  if (signedIn) {
    menu = await menuFor(answer.body)
    menu.forEach((p) => menuCatalog.add(p))
    localStorage.clear()
    resetSessionForTests()
    setAccessToken('authz-baseline')
    localStorage.setItem('user', JSON.stringify(answer.body))
    // The guard loads the capabilities itself, from the same answer.
    getCurrentUserMock.mockResolvedValue({ ...answer.body })
  }
  // Subjects whose /auth/me is rejected (anonymous, deleted, agent) hold no
  // usable browser session: no access token and no cached user.
  const out = []
  for (const path of entries) {
    out.push({ subject: id, path, menu: menu, guard_result: await guardResult(path) })
  }
  return out
}

// compareEntries applies the shared approved-differences table (group E
// entries) the same way the backend comparator does: a difference passes
// only when an active entry selects it and its expectation holds; pending
// entries never approve; an active entry that matches nothing fails.
const E_FIELDS = ['menu_visible', 'guard_result']
const compareEntries = (oldRecs, newRecs, approved) => {
  const key = (r) => `${r.subject} ${r.path}`
  const olds = new Map(oldRecs.map((r) => [key(r), r]))
  const news = new Map(newRecs.map((r) => [key(r), r]))
  const entries = (approved.entries || []).filter((e) => e.selector?.group === 'E')
  const hits = new Map()
  const failures = []
  for (const k of new Set([...olds.keys(), ...news.keys()])) {
    const o = olds.get(k)
    const n = news.get(k)
    if (!o || !n) {
      failures.push({ id: `E/${k}`, verdict: 'unapproved', field: '@presence' })
      continue
    }
    const fields = E_FIELDS.filter((f) => JSON.stringify(o[f]) !== JSON.stringify(n[f]))
    if (fields.length === 0) continue
    let verdict = 'unapproved'
    let entry = ''
    for (const e of entries) {
      const sel = e.selector
      if (sel.subjects?.length && !sel.subjects.includes(o.subject)) continue
      if (sel.keys?.length && !sel.keys.includes(o.path)) continue
      if (!fields.every((f) => (sel.fields || []).includes(f))) continue
      if (e.status !== 'active') {
        if (verdict === 'unapproved') [verdict, entry] = ['pending-only', e.id]
        continue
      }
      hits.set(e.id, (hits.get(e.id) || 0) + 1)
      const holds = !e.expect || Object.entries(e.expect).every(([f, v]) => JSON.stringify(n[f]) === JSON.stringify(v))
      ;[verdict, entry] = [holds ? 'approved' : 'expect-mismatch', e.id]
      if (holds) break
    }
    if (verdict !== 'approved') failures.push({ id: `E/${k}`, verdict, entry, fields, old: o, new: n })
  }
  for (const e of entries) {
    if (e.status === 'active' && !hits.get(e.id)) failures.push({ id: e.id, verdict: 'stale-active' })
  }
  return failures
}

const canonical = (records) =>
  records
    .map(({ subject, path, menu_visible, guard_result }) => ({ subject, path, menu_visible, guard_result }))
    .sort((a, b) => (a.subject + ' ' + a.path).localeCompare(b.subject + ' ' + b.path))

// recaptureMode picks the re-capture behaviour from the environment.
// reason + paths = append-only; reason only = strict re-capture; paths only = error; neither = compare.
const recaptureMode = (env) => {
  const reason = (env.AUTHZ_BASELINE_RECAPTURE || '').trim()
  const newPaths = [
    ...new Set(
      (env.AUTHZ_BASELINE_APPEND_ENTRIES || '')
        .split(',')
        .map((p) => p.trim())
        .filter(Boolean)
    ),
  ]
  if (reason && newPaths.length) return { mode: 'append', reason, newPaths }
  if (reason) return { mode: 'recapture', reason, newPaths: [] }
  if (newPaths.length) {
    return { mode: 'error', newPaths, error: 'AUTHZ_BASELINE_APPEND_ENTRIES needs AUTHZ_BASELINE_RECAPTURE=<reason>' }
  }
  return { mode: 'compare', newPaths: [] }
}

const recordOrder = (a, b) => (a.subject + ' ' + a.path).localeCompare(b.subject + ' ' + b.path)

// appendEntryRecords merges only the named new entries into the golden. golden is
// { count, recaptures, records }, fresh is the canonical fresh capture, approved the shared table.
// It returns { ok, reasons, merged }; the caller writes merged only when ok. `note` is the
// re-capture reason recorded in the trail.
const appendEntryRecords = (golden, fresh, approved, newPaths, note = '') => {
  const refuse = (reasons) => ({ ok: false, reasons, merged: null })
  const paths = [...new Set((newPaths || []).map((p) => String(p).trim()).filter(Boolean))]
  if (paths.length === 0) return refuse(['no new entry paths named'])
  const key = (r) => `${r.subject} ${r.path}`
  const oldKeys = new Set(golden.records.map(key))
  const oldPaths = new Set(golden.records.map((r) => r.path))
  const subjectIds = [...new Set(golden.records.map((r) => r.subject))].sort()
  const reasons = []

  // 1. Every existing record, through the comparator. Only an active approval whose expectation
  //    holds passes; a vanished key is refused as a missing record.
  const freshOld = fresh.filter((r) => oldKeys.has(key(r)))
  for (const f of compareEntries(golden.records, freshOld, approved)) {
    reasons.push(`existing record refused: ${f.id} (${f.verdict})`)
  }

  // 2. Additions are limited to the named entries, each complete and not yet captured.
  const freshNew = fresh.filter((r) => !oldKeys.has(key(r)))
  for (const r of freshNew) {
    if (!paths.includes(r.path)) reasons.push(`addition outside the named entries: ${key(r)}`)
  }
  for (const path of paths) {
    if (oldPaths.has(path)) reasons.push(`entry already captured: ${path}`)
    const recs = freshNew.filter((r) => r.path === path)
    const have = recs.map((r) => r.subject).sort()
    if (have.length !== subjectIds.length || have.some((s, i) => s !== subjectIds[i])) {
      reasons.push(`entry ${path} is not one record per baseline subject`)
    }
  }
  if (reasons.length) return refuse(reasons)

  // 3. Existing records stay the golden's own objects; only the new ones are added.
  const records = [...golden.records, ...canonical(freshNew)].sort(recordOrder)
  const day = new Date().toISOString().slice(0, 10)
  const trail = `${day}: append entries ${paths.join(',')}${note ? ` (${note})` : ''}`
  const merged = { count: records.length, recaptures: [...(golden.recaptures || []), trail], records }

  // 4. The merged golden must compare empty against the fresh capture.
  const rest = compareEntries(merged.records, fresh, approved)
  if (rest.length) return refuse(rest.map((f) => `merged golden differs from fresh: ${f.id} (${f.verdict})`))
  return { ok: true, reasons: [], merged }
}

describe('authorization baseline: entry rules (E group)', () => {
  let records = []
  let subjects = null
  let manifest = null
  let approved = null
  let inputMeta = null

  beforeAll(async () => {
    const subjectsPath = resolveShared(SUBJECTS_FILE)
    const manifestPath = resolveShared(MANIFEST_FILE)
    const approvedPath = resolveShared(APPROVED_FILE)
    if (!subjectsPath || !manifestPath || !approvedPath) return
    approved = JSON.parse(readFileSync(approvedPath, 'utf8'))
    const input = JSON.parse(readFileSync(subjectsPath, 'utf8'))
    subjects = input.subjects
    manifest = JSON.parse(readFileSync(manifestPath, 'utf8'))
    inputMeta = {
      manifestSha: input.manifest_sha256,
      actualManifestSha: createHash('sha256').update(readFileSync(manifestPath)).digest('hex'),
      programVersion: input.program_version,
    }
    const entries = Object.keys(ENTRY_RULES).sort()
    const raw = []
    for (const id of Object.keys(subjects).sort()) {
      raw.push(...(await captureSubject(id, subjects[id], entries)))
    }
    records = canonical(
      raw.map((r) => ({
        ...r,
        menu_visible: r.menu === null ? null : menuCatalog.has(r.path) ? r.menu.has(r.path) : null,
      }))
    )
  }, 120000)

  it('reads the backend subject answers and manifest', () => {
    expect(subjects, `${SUBJECTS_FILE} not readable under /repo or ../`).not.toBeNull()
    expect(manifest, `${MANIFEST_FILE} not readable under /repo or ../`).not.toBeNull()
    expect(approved, `${APPROVED_FILE} not readable under /repo or ../`).not.toBeNull()
    expect(Object.keys(subjects)).toHaveLength(15)
  })

  it('takes its input from the backend capture of this baseline', () => {
    // The input is the projection captured against the same frozen manifest;
    // a stale or foreign file fails here instead of passing vacuously.
    expect(inputMeta.manifestSha).toBe(inputMeta.actualManifestSha)
    expect(inputMeta.programVersion).toBeTruthy()
    for (const answer of Object.values(subjects)) {
      if (answer.status !== 200) continue
      expect(Array.isArray(answer.body.permissions)).toBe(true)
      expect(Array.isArray(answer.body.scope_summary)).toBe(true)
    }
  })

  it('covers every entry rule for every subject', () => {
    const entries = Object.keys(ENTRY_RULES)
    expect(entries).toHaveLength(manifest.entry_rules)
    expect(records).toHaveLength(Object.keys(subjects).length * entries.length)
    for (const path of entries) {
      expect(records.filter((r) => r.path === path)).toHaveLength(Object.keys(subjects).length)
    }
  })

  it('matches the captured golden', () => {
    const mode = recaptureMode(process.env)
    const reason = mode.mode === 'recapture' ? mode.reason : ''
    const golden = existsSync(GOLDEN) ? JSON.parse(readFileSync(GOLDEN, 'utf8')) : null
    expect(mode.error || '').toBe('')
    if (mode.mode === 'append') {
      expect(golden, `no golden at ${GOLDEN}; append-only needs an existing one`).not.toBeNull()
      const result = appendEntryRecords(golden, records, approved, mode.newPaths, mode.reason)
      expect(result.reasons, 'append-only re-capture refused').toEqual([])
      writeFileSync(GOLDEN, JSON.stringify(result.merged, null, 1) + '\n')
      return
    }
    if (reason) {
      if (golden) {
        const fresh = new Map(records.map((r) => [`${r.subject} ${r.path}`, JSON.stringify(r)]))
        const changed = golden.records.filter((r) => {
          const now = fresh.get(`${r.subject} ${r.path}`)
          return now !== undefined && now !== JSON.stringify(r)
        })
        // Approved differences may change existing records only through the
        // comparator, never through re-capture.
        expect(changed, 're-capture refused: existing records would change').toEqual([])
      }
      mkdirSync(dirname(GOLDEN), { recursive: true })
      const recaptures = [...(golden?.recaptures || []), `${new Date().toISOString().slice(0, 10)}: ${reason}`]
      writeFileSync(GOLDEN, JSON.stringify({ count: records.length, recaptures, records }, null, 1) + '\n')
      return
    }
    expect(golden, `no golden at ${GOLDEN}; capture with AUTHZ_BASELINE_RECAPTURE=<reason>`).not.toBeNull()
    expect(golden.count).toBe(records.length)
    const failures = compareEntries(golden.records, records, approved)
    expect(failures.slice(0, 50), `${failures.length} entry differences not approved`).toEqual([])
  })
})

describe('append-only entry re-capture', () => {
  const SUBJECTS = ['sub-a', 'sub-b']
  const rec = (subject, path, menu_visible, guard_result) => ({ subject, path, menu_visible, guard_result })
  const base = () => [
    rec('sub-a', '/a', false, '/dashboard'),
    rec('sub-b', '/a', true, 'allow'),
    rec('sub-a', '/b', true, 'allow'),
    rec('sub-b', '/b', true, 'allow'),
  ]
  const goldenOf = (records) => ({ count: records.length, recaptures: ['2026-01-01: first'], records })
  const addNew = (path, subjects = SUBJECTS) => subjects.map((s) => rec(s, path, true, 'allow'))
  const ad = (over = {}) => ({
    id: 'AD-T',
    status: 'active',
    selector: { group: 'E', subjects: ['sub-a'], keys: ['/a'], fields: ['menu_visible', 'guard_result'] },
    expect: { menu_visible: true, guard_result: 'allow' },
    ...over,
  })
  const table = (...entries) => ({ entries })
  const withFresh = (changes, extra = []) => {
    const m = new Map(base().map((r) => [`${r.subject} ${r.path}`, r]))
    for (const c of changes) m.set(`${c.subject} ${c.path}`, c)
    return [...m.values(), ...extra]
  }

  it('keeps existing records verbatim and appends only the named entries', () => {
    const golden = goldenOf(base())
    // sub-a /a answers differently now; an active approval whose expectation holds selects it.
    const fresh = withFresh([rec('sub-a', '/a', true, 'allow')], addNew('/n'))
    const result = appendEntryRecords(golden, fresh, table(ad()), ['/n'])
    expect(result.reasons).toEqual([])
    expect(result.ok).toBe(true)
    const merged = result.merged
    const kept = merged.records.find((r) => r.subject === 'sub-a' && r.path === '/a')
    expect(kept).toBe(golden.records[0])
    expect(kept).toEqual(rec('sub-a', '/a', false, '/dashboard'))
    expect(merged.records.filter((r) => r.path === '/n')).toHaveLength(SUBJECTS.length)
    expect(merged.count).toBe(6)
    expect(merged.records).toHaveLength(6)
    expect(merged.recaptures.slice(0, 1)).toEqual(golden.recaptures)
    expect(merged.recaptures).toHaveLength(golden.recaptures.length + 1)
    // The full comparison is empty and the approval was used, not stale.
    expect(compareEntries(merged.records, fresh, table(ad()))).toEqual([])
    expect(compareEntries(merged.records, withFresh([]), table(ad()))).not.toEqual([])
  })

  it('refuses when an existing record differs without an active, holding approval', () => {
    const golden = goldenOf(base())
    const fresh = withFresh([rec('sub-a', '/a', true, 'allow')], addNew('/n'))
    const cases = {
      'no approval': table(),
      'pending-only approval': table(ad({ status: 'pending' })),
      'active approval whose expectation fails': table(ad({ expect: { menu_visible: false } })),
    }
    for (const [name, approved] of Object.entries(cases)) {
      const result = appendEntryRecords(golden, fresh, approved, ['/n'])
      expect(result.ok, name).toBe(false)
      expect(result.merged, name).toBeNull()
      expect(result.reasons.length, name).toBeGreaterThan(0)
    }
  })

  it('refuses when an active approval no longer matches anything', () => {
    const golden = goldenOf(base())
    // fresh equals the golden for sub-a /a, so the active approval selects nothing.
    const fresh = withFresh([], addNew('/n'))
    const result = appendEntryRecords(golden, fresh, table(ad()), ['/n'])
    expect(result.ok).toBe(false)
    expect(result.reasons.join('\n')).toContain('stale-active')
  })

  it('refuses additions outside the named new entries', () => {
    const golden = goldenOf(base())
    // A new subject answering for an existing entry.
    const newSubject = withFresh([], [...addNew('/n'), rec('sub-c', '/a', true, 'allow')])
    const r1 = appendEntryRecords(golden, newSubject, table(), ['/n'])
    expect(r1.ok).toBe(false)
    expect(r1.reasons.join('\n')).toContain('sub-c /a')
    // A new entry the caller did not name.
    const unnamed = withFresh([], [...addNew('/n'), ...addNew('/extra')])
    const r2 = appendEntryRecords(golden, unnamed, table(), ['/n'])
    expect(r2.ok).toBe(false)
    expect(r2.reasons.join('\n')).toContain('/extra')
  })

  it('refuses incomplete, already captured or vanished entries', () => {
    const golden = goldenOf(base())
    // Named entry missing one subject.
    const incomplete = appendEntryRecords(golden, withFresh([], addNew('/n', ['sub-a'])), table(), ['/n'])
    expect(incomplete.ok).toBe(false)
    expect(incomplete.reasons.join('\n')).toContain('/n')
    // Named entry already in the old golden.
    const captured = appendEntryRecords(golden, withFresh([], addNew('/n')), table(), ['/a'])
    expect(captured.ok).toBe(false)
    expect(captured.reasons.join('\n')).toContain('already captured')
    // An old key vanished from the fresh capture.
    const vanished = withFresh([], addNew('/n')).filter((r) => !(r.subject === 'sub-b' && r.path === '/b'))
    const gone = appendEntryRecords(golden, vanished, table(), ['/n'])
    expect(gone.ok).toBe(false)
    expect(gone.reasons.join('\n')).toContain('sub-b /b')
  })

  it('selects append mode only with both a reason and named entries', () => {
    const both = recaptureMode({ AUTHZ_BASELINE_RECAPTURE: 'why', AUTHZ_BASELINE_APPEND_ENTRIES: ' /n , /m ,' })
    expect(both.mode).toBe('append')
    expect(both.newPaths).toEqual(['/n', '/m'])
    expect(both.reason).toBe('why')
    expect(recaptureMode({ AUTHZ_BASELINE_RECAPTURE: 'why' }).mode).toBe('recapture')
    const pathsOnly = recaptureMode({ AUTHZ_BASELINE_APPEND_ENTRIES: '/n' })
    expect(pathsOnly.mode).toBe('error')
    expect(pathsOnly.error).toBeTruthy()
    expect(recaptureMode({}).mode).toBe('compare')
    expect(recaptureMode({ AUTHZ_BASELINE_RECAPTURE: '  ', AUTHZ_BASELINE_APPEND_ENTRIES: '' }).mode).toBe('compare')
  })
})
