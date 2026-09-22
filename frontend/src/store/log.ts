import { defineStore } from 'pinia'
import { computed, ref } from 'vue'
import axios from 'axios'
import type {
  AnalysisResult, AlertRule, BatchInputRow, QueueItem,
  RecomputeResult, RecomputeScope, RoundEntry,
} from '@/types'

/** 范围签名：同签名即视为重复入队 */
export function scopeKey(s: RecomputeScope): string {
  const src = [...s.sources].map(x => x.trim()).filter(Boolean).sort().join(',')
  return `${src}|${s.start ?? ''}|${s.end ?? ''}`
}

/** 两组来源是否有交集；任一为空（不限来源）即视为相交 */
function sourcesIntersect(a: string[], b: string[]): boolean {
  if (!a.length || !b.length) return true
  const setB = new Set(b)
  return a.some(s => setB.has(s))
}

/** 两个时间范围是否重叠；端点 null 表示不限 */
function rangesOverlap(a: RecomputeScope, b: RecomputeScope): boolean {
  if (a.start !== null && b.end !== null && a.start > b.end) return false
  if (b.start !== null && a.end !== null && b.start > a.end) return false
  return true
}

export function scopesOverlap(a: RecomputeScope, b: RecomputeScope): boolean {
  return sourcesIntersect(a.sources, b.sources) && rangesOverlap(a, b)
}

/** 上一轮同口径判定：固定阈值参数一致且启用的判定规则集一致 */
export function caliberMatches(a: RecomputeResult['caliber'], b: RecomputeResult['caliber']): boolean {
  return a.windowSize === b.windowSize
    && a.sigmaThreshold === b.sigmaThreshold
    && a.iqrScoreThreshold === b.iqrScoreThreshold
    && a.rules.length === b.rules.length
    && a.rules.every((r, i) => r === b.rules[i])
}

export const useLogStore = defineStore('log', () => {
  const result = ref<AnalysisResult | null>(null)
  const loading = ref(false)
  const searchQuery = ref('')
  const logType = ref('nginx')
  const rules = ref<AlertRule[]>([
    { id:1, name:'高频ERROR', type:'level', threshold:5, enabled:true },
    { id:2, name:'异常流量', type:'count', threshold:200, enabled:false },
    { id:3, name:'关键词命中', type:'keyword', threshold:0, enabled:true }
  ])

  // ---- 批量重算队列状态 ----
  const queue = ref<QueueItem[]>([])
  const previousRound = ref<RoundEntry[]>([])
  const running = ref(false)
  let seq = 0

  const availableSources = computed<string[]>(() => {
    const set = new Set<string>()
    ;(result.value?.logs || []).forEach(l => set.add(l.source))
    return [...set].sort()
  })
  const pendingCount = computed(() => queue.value.filter(q => q.status === 'pending').length)
  const doneCount = computed(() => queue.value.filter(q => q.status === 'done').length)
  const failedCount = computed(() => queue.value.filter(q => q.status === 'failed').length)
  const skippedCount = computed(() => queue.value.filter(q => q.status === 'skipped').length)

  const previousByKey = computed(() => {
    const map = new Map<string, RoundEntry>()
    previousRound.value.forEach(e => map.set(scopeKey(e.result.scope), e))
    return map
  })

  /** 找到与某条结果同范围的上一轮条目（用于逐条对照） */
  function previousOf(item: QueueItem): RoundEntry | undefined {
    if (!item.result) return undefined
    return previousByKey.value.get(scopeKey(item.result.scope))
  }

  async function generate() {
    loading.value=true
    try { const {data} = await axios.post('/api/generate',{type:logType.value,count:1000}) ; result.value=data }
    finally { loading.value=false }
  }

  async function detect() {
    if (!result.value) return
    loading.value=true
    try { const {data} = await axios.post('/api/detect',{logs:result.value.logs,rules:rules.value.filter(r=>r.enabled),query:searchQuery.value}) ; result.value=data }
    finally { loading.value=false }
  }

  /**
   * 整组入队：
   * - 与队列中已有条目同范围 => 标记为重复，指出与哪一条重复并跳过
   * - 与上一轮成功条目范围重叠（且非完全重复）=> 指出与哪几条重叠并跳过
   *
   * 若上一批尚未执行（队列里只有待处理/跳过条目），新行直接追加进同一轮队列；
   * 一旦上一批已执行过（含完成/失败），再次入队即开启新一轮，先把成功条目归档为基线。
   * 返回实际入队（pending）条数。
   */
  function enqueueBatch(rows: BatchInputRow[]): number {
    if (running.value) return 0
    const executed = queue.value.some(q => q.status === 'done' || q.status === 'failed' || q.status === 'running')
    if (executed) {
      previousRound.value = queue.value
        .filter(q => q.status === 'done' && q.result)
        .map(q => ({ label: q.label, result: q.result as RecomputeResult }))
      // 失败条目保留在新队列中，仍可单条/批量重试；跳过与待处理条目随上一轮关闭
      queue.value = queue.value.filter(q => q.status === 'failed')
    }

    let added = 0
    rows.forEach(row => {
      const scope: RecomputeScope = {
        sources: [...new Set(row.sources.map(s => s.trim()).filter(Boolean))],
        start: row.start,
        end: row.end,
      }
      const key = scopeKey(scope)
      seq += 1
      const id = seq

      const dup = queue.value.find(q => (q.status === 'pending' || q.status === 'running')
        && scopeKey(q.scope) === key)
      if (dup) {
        queue.value.push({ id, label: row.label, scope, status: 'skipped',
          skipReason: `与队列第 ${queue.value.indexOf(dup) + 1} 条「${dup.label}」范围完全相同，重复入队已跳过` })
        return
      }

      const overlaps = previousRound.value.filter(e => scopesOverlap(scope, e.result.scope))
      if (overlaps.length) {
        const names = overlaps.slice(0, 3).map(e => `「${e.label}」`).join('、')
        const more = overlaps.length > 3 ? ` 等 ${overlaps.length} 条` : ''
        queue.value.push({ id, label: row.label, scope, status: 'skipped',
          skipReason: `与上一轮 ${names}${more} 的时间范围/来源重叠，已跳过` })
        return
      }

      queue.value.push({ id, label: row.label, scope, status: 'pending' })
      added += 1
    })
    return added
  }

  function clearQueue() {
    if (running.value) return
    queue.value = []
  }

  /** 清空上一轮对照基线 */
  function clearPreviousRound() {
    previousRound.value = []
  }

  /** 把当前日志整批送往后端重算，失败的条目保留说明、可单条重试 */
  async function runQueue() {
    if (running.value || !result.value) return
    running.value = true
    try {
      for (const item of queue.value) {
        if (item.status !== 'pending') continue
        item.status = 'running'
        try {
          const { data } = await axios.post('/api/recompute', {
            logs: result.value.logs,
            rules: rules.value.filter(r => r.enabled),
            job: { jobId: `q-${item.id}`, label: item.label, scope: item.scope },
          })
          item.result = data
          item.error = undefined
          item.status = 'done'
        } catch (e: any) {
          item.status = 'failed'
          item.error = e?.response?.data?.detail || e?.message || '重算请求失败（网络或服务异常）'
        }
      }
    } finally {
      running.value = false
    }
  }

  /** 单条重试：仅重发失败条目，其它条目不动 */
  async function retryItem(item: QueueItem) {
    if (running.value || !result.value || item.status !== 'failed') return
    item.status = 'running'
    try {
      const { data } = await axios.post('/api/recompute', {
        logs: result.value.logs,
        rules: rules.value.filter(r => r.enabled),
        job: { jobId: `q-${item.id}-r${Date.now()}`, label: item.label, scope: item.scope },
      })
      item.result = data
      item.error = undefined
      item.status = 'done'
    } catch (e: any) {
      item.status = 'failed'
      item.error = e?.response?.data?.detail || e?.message || '重算请求失败（网络或服务异常）'
    }
  }

  async function retryFailed() {
    if (running.value) return
    running.value = true
    try {
      for (const item of queue.value.filter(q => q.status === 'failed')) {
        await retryItem(item)
      }
    } finally {
      running.value = false
    }
  }

  return {
    result, loading, searchQuery, logType, rules,
    queue, previousRound, running,
    availableSources, pendingCount, doneCount, failedCount, skippedCount,
    previousOf,
    generate, detect,
    enqueueBatch, clearQueue, clearPreviousRound,
    runQueue, retryItem, retryFailed,
  }
})
