import { defineStore } from 'pinia'
import { computed, ref } from 'vue'
import axios from 'axios'
import { useLogStore } from './log'
import type {
  BatchEnqueueResult, CriterionDelta, RecalcDelta, RecalcJob, RecalcJobSpec,
  RecalcResponse, RecalcServerJob, RecalcStats, SkippedEntry
} from '@/types'

interface SnapshotEntry {
  stats: RecalcStats
  round: number
  spec: RecalcJobSpec
  name: string
}

let seq = 0

export function specKey(spec: RecalcJobSpec): string {
  return JSON.stringify([[...spec.sources].sort(), spec.start ?? '', spec.end ?? ''])
}

export function parseBound(value: string | null): Date | null {
  if (!value) return null
  const s = value.trim()
  if (!s) return null
  if (/^\d{9,10}$/.test(s)) return new Date(Number(s) * 1000)
  const m = s.match(/^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2}))?)?$/)
  if (m) {
    const [, y, mo, d, hh, mm, ss] = m
    return new Date(Number(y), Number(mo) - 1, Number(d),
      hh ? Number(hh) : 0, mm ? Number(mm) : 0, ss ? Number(ss) : 0)
  }
  const dt = new Date(s)
  if (isNaN(dt.getTime())) throw new Error(`时间无法解析: ${s}`)
  return dt
}

function intervalsOverlap(a: RecalcJobSpec, b: RecalcJobSpec): boolean {
  // 时间区间相交（含边界）；未限定的一侧视为无限
  try {
    const aS = parseBound(a.start), aE = parseBound(a.end)
    const bS = parseBound(b.start), bE = parseBound(b.end)
    if (aS && bE && aS.getTime() > bE.getTime()) return false
    if (bS && aE && bS.getTime() > aE.getTime()) return false
    return true
  } catch {
    return false
  }
}

export function specsOverlap(a: RecalcJobSpec, b: RecalcJobSpec): boolean {
  // 来源集合相交（空集合表示全部来源）且时间区间相交
  const aSrc = new Set(a.sources), bSrc = new Set(b.sources)
  const sourceOverlap =
    aSrc.size === 0 || bSrc.size === 0 ||
    [...aSrc].some((s) => bSrc.has(s))
  return sourceOverlap && intervalsOverlap(a, b)
}

export function specLabel(spec: RecalcJobSpec): string {
  const src = spec.sources.length ? spec.sources.join('/') : '全部来源'
  const range = spec.start || spec.end
    ? `${spec.start || '…'} ~ ${spec.end || '…'}`
    : '全部时间'
  return `${src} | ${range}`
}

function validateSpec(spec: RecalcJobSpec): string {
  try {
    const s = parseBound(spec.start), e = parseBound(spec.end)
    if (s && e && s.getTime() > e.getTime()) return '时间范围起点晚于终点'
  } catch (err) {
    return `时间格式无法解析（${(err as Error).message}）`
  }
  return ''
}

function makeDelta(stats: RecalcStats, prev: RecalcStats | undefined): RecalcDelta {
  const num = (cur: number, old: number | undefined) =>
    old === undefined ? null : Number((cur - old).toFixed(2))
  const prevByKey = new Map((prev?.criteria || []).map((c) => [c.key, c]))
  const criteria: CriterionDelta[] = stats.criteria.map((c) => {
    const p = prevByKey.get(c.key)
    return {
      name: c.name,
      current: c.hitWindows,
      previous: p?.hitWindows ?? 0,
      diff: c.hitWindows - (p?.hitWindows ?? 0),
      hitNow: c.hit,
      hitBefore: p?.hit ?? false
    }
  })
  return {
    count: num(stats.count, prev?.count),
    anomalyCount: num(stats.anomalyCount, prev?.anomalyCount),
    maxSigma: num(stats.maxSigma, prev?.maxSigma),
    maxIqr: num(stats.maxIqr, prev?.maxIqr),
    criteria
  }
}

export const useRecalcStore = defineStore('recalc', () => {
  const jobs = ref<RecalcJob[]>([])
  const running = ref(false)
  const round = ref(0)
  // 上一轮（最近一次执行）各分组的结果快照，键为来源+时间范围
  const snapshot = ref<Map<string, SnapshotEntry>>(new Map())

  const hasQueued = computed(() =>
    jobs.value.some((j) => j.status === 'queued' || j.status === 'failed'))
  const lastRoundLabel = computed(() => (round.value === 0 ? '' : `第 ${round.value} 轮`))

  const availableSources = computed<string[]>(() => {
    const logStore = useLogStore()
    const set = new Set<string>()
    for (const log of logStore.result?.logs || []) {
      if (log.source) set.add(log.source)
    }
    if (set.size === 0) {
      ['nginx', 'api-gateway', 'load-balancer', 'httpd', 'mod_ssl', 'mod_rewrite',
       'user-service', 'order-service', 'payment-service', 'auth-service',
       'cron', 'systemd', 'kernel', 'docker'].forEach((s) => set.add(s))
    }
    return [...set].sort()
  })

  /** 批量入队：组内重复、与队列重复、与上一轮重叠的条目标明并跳过。 */
  function enqueueBatch(drafts: Array<{ name?: string } & RecalcJobSpec>): BatchEnqueueResult {
    const added: RecalcJob[] = []
    const skipped: SkippedEntry[] = []
    const seenInBatch: RecalcJobSpec[] = []

    for (const draft of drafts) {
      const spec: RecalcJobSpec = {
        sources: [...draft.sources],
        start: draft.start || null,
        end: draft.end || null
      }
      const name = draft.name?.trim() || specLabel(spec)
      let reason = ''
      let against = ''

      const dupBatchIdx = seenInBatch.findIndex((s) => specKey(s) === specKey(spec))
      const dupQueue = jobs.value.find((j) => specKey(j) === specKey(spec))
      const prevOverlap = [...snapshot.value.values()].find((entry) =>
        specsOverlap(spec, entry.spec))

      if (dupBatchIdx >= 0) {
        reason = '重复入队'
        against = `本批次第 ${dupBatchIdx + 1} 条「${specLabel(seenInBatch[dupBatchIdx])}」`
      } else if (dupQueue) {
        reason = '重复入队'
        against = `队列中已有的「${dupQueue.name}」`
      } else if (prevOverlap) {
        reason = '与上一轮范围重叠'
        against = `上一轮（第 ${prevOverlap.round} 轮）「${prevOverlap.name}」`
      } else {
        reason = validateSpec(spec)
        if (reason) against = specLabel(spec)
      }

      if (reason) {
        skipped.push({ name, spec, reason, against })
        continue
      }

      const job: RecalcJob = {
        id: ++seq,
        name,
        status: 'queued',
        sources: spec.sources,
        start: spec.start,
        end: spec.end
      }
      jobs.value.push(job)
      seenInBatch.push(spec)
      added.push(job)
    }
    return { added, skipped }
  }

  /** 整组重算：所有待处理/失败条目一次性提交，失败隔离在单条。 */
  async function runAll(): Promise<void> {
    const logStore = useLogStore()
    if (!logStore.result || running.value) return
    const pending = jobs.value.filter((j) => j.status === 'queued' || j.status === 'failed')
    if (!pending.length) return

    running.value = true
    // 本轮对照基线：执行前的上一轮快照，整批共用，避免同批条目互相污染
    const baseline = new Map(snapshot.value)
    pending.forEach((j) => { j.status = 'running'; j.error = '' })

    try {
      const { data } = await axios.post<RecalcResponse>('/api/recalculate', {
        logs: logStore.result.logs,
        rules: logStore.rules.filter((r) => r.enabled),
        jobs: pending.map((j) => ({
          name: j.name, sources: j.sources, start: j.start, end: j.end
        }))
      })
      // 整组执行成功后才进入下一轮
      applyResults(pending, data.results, baseline, true)
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err)
      pending.forEach((j) => {
        j.status = 'failed'
        j.error = `请求失败：${message}`
      })
    } finally {
      running.value = false
    }
  }

  /** 单条重试：与当前上一轮快照逐条对照。 */
  async function retryOne(job: RecalcJob): Promise<void> {
    const logStore = useLogStore()
    if (!logStore.result || running.value || job.status === 'running') return
    job.status = 'running'
    job.error = ''
    const baseline = new Map(snapshot.value)
    try {
      const { data } = await axios.post<RecalcResponse>('/api/recalculate', {
        logs: logStore.result.logs,
        rules: logStore.rules.filter((r) => r.enabled),
        jobs: [{ name: job.name, sources: job.sources, start: job.start, end: job.end }]
      })
      // 单条重试不推进轮次：结果仍归入当前轮，对照上一轮快照
      applyResults([job], data.results, baseline, false)
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err)
      job.status = 'failed'
      job.error = `请求失败：${message}`
    }
  }

  function applyResults(pending: RecalcJob[], results: RecalcServerJob[],
                        baseline: Map<string, SnapshotEntry>, bumpRound: boolean): void {
    let anySuccess = false
    const newRound = bumpRound ? round.value + 1 : Math.max(round.value, 1)
    const nextSnapshot = new Map(snapshot.value)
    for (const r of results) {
      const job = pending[r.index]
      if (!job) continue
      if (!r.ok) {
        job.status = 'failed'
        job.error = r.error || '重算失败'
        job.note = ''
        continue
      }
      const stats: RecalcStats = {
        count: r.count ?? 0,
        windowCount: r.windowCount ?? 0,
        anomalyCount: r.anomalyCount ?? 0,
        maxSigma: r.maxSigma ?? 0,
        meanSigma: r.meanSigma ?? 0,
        maxIqr: r.maxIqr ?? 0,
        meanIqr: r.meanIqr ?? 0,
        criteria: r.criteria ?? []
      }
      const prev = baseline.get(specKey(job))
      job.status = 'done'
      job.stats = stats
      job.note = r.note || ''
      job.error = ''
      job.round = newRound
      job.baselineRound = prev?.round
      job.delta = makeDelta(stats, prev?.stats)
      nextSnapshot.set(specKey(job), {
        stats, round: newRound,
        spec: { sources: job.sources, start: job.start, end: job.end },
        name: job.name
      })
      anySuccess = true
    }
    snapshot.value = nextSnapshot
    if (anySuccess) round.value = Math.max(round.value, newRound)
  }

  function removeJob(job: RecalcJob): void {
    jobs.value = jobs.value.filter((j) => j.id !== job.id)
  }
  function clearFinished(): void {
    jobs.value = jobs.value.filter((j) => j.status !== 'done')
  }
  function clearAll(): void {
    jobs.value = []
  }

  return {
    jobs, running, round, lastRoundLabel, availableSources, hasQueued,
    enqueueBatch, runAll, retryOne, removeJob, clearFinished, clearAll
  }
})
