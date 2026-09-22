<template>
  <div v-if="item.status === 'skipped'" class="detail-skip">⏭ {{ item.skipReason }}</div>
  <div v-else-if="item.status === 'failed'" class="detail-fail">
    <div class="detail-fail-msg">✗ 重算失败：{{ item.error }}</div>
    <div class="detail-fail-hint">范围或来源调整后可点击「重试」单独重发该条</div>
  </div>
  <div v-else-if="!item.result" class="muted pad">尚未重算</div>
  <div v-else class="detail">
    <div class="metrics">
      <div v-for="m in metrics" :key="m.name" class="metric">
        <span class="metric-name">{{ m.name }}</span>
        <span class="metric-val">{{ m.cur }}</span>
        <DeltaTag v-if="m.prev === undefined" :cur="m.cur" :prev="undefined"/>
        <DeltaTag v-else :cur="m.cur" :prev="m.prev"/>
      </div>
    </div>

    <div v-if="previous && !sameCaliber" class="caliber-warn">
      ⚠ 与上一轮的判定口径（窗口大小 / 阈值 / 启用规则）已变化，下列差异仅供参考
    </div>
    <div v-else-if="previous && result" class="caliber-ok">✓ 与上一轮统计口径一致（窗口 {{ result.caliber.windowSize }} 条，σ&gt;{{ result.caliber.sigmaThreshold }}，IQR&gt;{{ result.caliber.iqrScoreThreshold }}）</div>

    <div class="hits-title">命中的判定项（逐条对照上一轮）</div>
    <table class="hits-table">
      <thead>
        <tr><th>判定项</th><th>类型</th><th>级别</th><th>本次</th><th>上轮</th><th>变化</th></tr>
      </thead>
      <tbody>
        <tr v-if="!hitRows.length"><td colspan="6" class="muted">本轮无命中的判定项</td></tr>
        <tr v-for="h in hitRows" :key="h.id + ':' + h.gone" :class="{ gone: h.gone }">
          <td>{{ h.name }}<span v-if="h.gone">（本轮未再命中）</span></td>
          <td>{{ h.type }}</td>
          <td>{{ h.severity }}</td>
          <td>{{ h.count }}</td>
          <td>{{ prevCount(h.id) === undefined ? '—' : prevCount(h.id) }}</td>
          <td><DeltaTag :cur="h.count" :prev="prevCount(h.id)"/></td>
        </tr>
      </tbody>
    </table>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import DeltaTag from './DeltaTag.vue'
import { caliberMatches } from '../store/log'
import type { QueueItem, RecomputeResult, RoundEntry, RecomputeHit } from '../types'

const props = defineProps<{ item: QueueItem; previous?: RoundEntry }>()

const result = computed<RecomputeResult | undefined>(() => props.item.result)
const prev = computed<RecomputeResult | undefined>(() => props.previous?.result)
const sameCaliber = computed(() => !result.value || !prev.value || caliberMatches(result.value.caliber, prev.value.caliber))

const metrics = computed(() => {
  const r = result.value
  if (!r) return []
  const p = prev.value
  return [
    { name: '条目数', cur: r.matched, prev: p?.matched },
    { name: '窗口数', cur: r.windowCount, prev: p?.windowCount },
    { name: '异常窗口', cur: r.anomalyWindows, prev: p?.anomalyWindows },
    { name: 'σ 平均', cur: r.avgSigmaScore, prev: p?.avgSigmaScore },
    { name: 'σ 峰值', cur: r.maxSigmaScore, prev: p?.maxSigmaScore },
    { name: 'IQR 平均', cur: r.avgIqrScore, prev: p?.avgIqrScore },
    { name: 'IQR 峰值', cur: r.maxIqrScore, prev: p?.maxIqrScore },
  ]
})

interface HitRow extends RecomputeHit { gone: boolean }
const hitRows = computed<HitRow[]>(() => {
  const r = result.value
  if (!r) return []
  const cur = r.hits.map(h => ({ ...h, gone: false }))
  if (!prev.value) return cur
  const curIds = new Set(r.hits.map(h => h.id))
  const gone = prev.value.hits.filter(h => !curIds.has(h.id)).map(h => ({ ...h, count: 0, gone: true }))
  return [...cur, ...gone]
})

function prevCount(id: string): number | undefined {
  return prev.value?.hits.find(h => h.id === id)?.count
}
</script>

<style scoped>
.detail{padding:8px 12px;background:#0f172a66}
.metrics{display:flex;flex-wrap:wrap;gap:14px;margin-bottom:8px}
.metric{display:flex;flex-direction:column;font-size:11px;gap:2px}
.metric-name{color:#94a3b8}
.metric-val{color:#e2e8f0;font-size:14px;font-weight:600}
.hits-title{color:#38bdf8;font-size:12px;margin:6px 0}
.hits-table{border-collapse:collapse;font-size:11px;width:100%}
.hits-table th{color:#94a3b8;text-align:left;padding:3px 10px;border-bottom:1px solid #334155}
.hits-table td{color:#e2e8f0;padding:3px 10px;border-bottom:1px solid #1e293b}
.hits-table tr.gone td{color:#64748b}
.caliber-warn{color:#fbbf24;font-size:11px;margin:4px 0}
.caliber-ok{color:#4ade80;font-size:11px;margin:4px 0}
.detail-skip{padding:8px 12px;color:#fbbf24;font-size:12px;background:#0f172a66}
.detail-fail{padding:8px 12px;background:#0f172a66}
.detail-fail-msg{color:#f87171;font-size:12px}
.detail-fail-hint{color:#94a3b8;font-size:11px;margin-top:2px}
.muted{color:#64748b;font-size:11px}
.pad{padding:8px 12px}
</style>
