<template>
  <div class="panel">
    <div class="head">
      <h4>🧮 结果清单批量重算</h4>
      <span v-if="store.previousRound.length" class="round-tag">
        上一轮基线 {{ store.previousRound.length }} 条
        <el-button link type="primary" size="small" @click="store.clearPreviousRound()">清除</el-button>
      </span>
    </div>

    <!-- 整组编辑 -->
    <div class="editor">
      <div v-for="(row, idx) in rows" :key="idx" class="draft-row">
        <el-input v-model="row.label" size="small" placeholder="条目名称（可空）" style="width:150px"/>
        <el-select v-model="row.sources" multiple collapse-tags collapse-tags-tooltip
                   size="small" placeholder="全部来源" style="width:180px">
          <el-option v-for="s in store.availableSources" :key="s" :label="s" :value="s"/>
        </el-select>
        <el-date-picker v-model="row.range" type="datetimerange" size="small"
                        range-separator="~" start-placeholder="开始（不限）" end-placeholder="结束（不限）"
                        value-format="X" style="width:300px"/>
        <el-button link type="danger" size="small" @click="rows.splice(idx,1)">删除</el-button>
      </div>
      <div v-if="!rows.length" class="empty">还没有待加入的条目，点击下方按钮添加时间范围或来源分组</div>
      <div class="editor-actions">
        <el-button size="small" @click="addRow">＋ 添加一行</el-button>
        <el-button size="small" :disabled="!store.availableSources.length"
                   @click="fillBySources">⇲ 每种来源各建一行</el-button>
        <el-button size="small" type="primary"
                   :disabled="!rows.length || store.running || !store.result"
                   @click="enqueue">⤵ 整组加入队列</el-button>
        <span v-if="!store.result" class="hint">请先生成日志</span>
      </div>
    </div>

    <!-- 队列 -->
    <div class="queue-actions">
      <el-button size="small" type="warning" :loading="store.running"
                 :disabled="!store.pendingCount" @click="store.runQueue()">
        ▶ 批量重算{{ store.pendingCount ? `（${store.pendingCount} 条待处理）` : '' }}
      </el-button>
      <el-button size="small" :disabled="!store.failedCount || store.running"
                 @click="store.retryFailed()">↻ 重试全部失败（{{ store.failedCount }}）</el-button>
      <el-button size="small" :disabled="store.running || !store.queue.length"
                 @click="store.clearQueue()">清空队列</el-button>
      <span class="counters">完成 {{ store.doneCount }} · 跳过 {{ store.skippedCount }} · 失败 {{ store.failedCount }}</span>
    </div>

    <el-table :data="store.queue" size="small" stripe row-key="id" class="queue-table">
      <el-table-column type="expand">
        <template #default="{row}">
          <QueueDetail :item="row" :previous="store.previousOf(row)"/>
        </template>
      </el-table-column>
      <el-table-column label="#" type="index" width="40"/>
      <el-table-column label="条目" min-width="160">
        <template #default="{row}">
          <div class="cell-label">{{ row.label || scopeText(row.scope) }}</div>
          <div class="cell-sub">{{ scopeText(row.scope) }}</div>
        </template>
      </el-table-column>
      <el-table-column label="状态" width="80">
        <template #default="{row}">
          <el-tag size="small" :type="statusType(row.status)"
                  :effect="row.status==='skipped' ? 'plain' : 'dark'">
            {{ statusText(row.status) }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column label="条目数" width="95">
        <template #default="{row}">
          <template v-if="row.result">
            {{ row.result.matched }}
            <DeltaTag :cur="row.result.matched" :prev="store.previousOf(row)?.result.matched"/>
          </template>
          <span v-else class="muted">—</span>
        </template>
      </el-table-column>
      <el-table-column label="异常窗口" width="95">
        <template #default="{row}">
          <template v-if="row.result">
            {{ row.result.anomalyWindows }}/{{ row.result.windowCount }}
            <DeltaTag :cur="row.result.anomalyWindows" :prev="store.previousOf(row)?.result.anomalyWindows"/>
          </template>
          <span v-else class="muted">—</span>
        </template>
      </el-table-column>
      <el-table-column label="σ 均/峰" width="115">
        <template #default="{row}">
          <template v-if="row.result">
            {{ row.result.avgSigmaScore }} / {{ row.result.maxSigmaScore }}
            <DeltaTag :cur="row.result.avgSigmaScore" :prev="store.previousOf(row)?.result.avgSigmaScore"/>
          </template>
          <span v-else class="muted">—</span>
        </template>
      </el-table-column>
      <el-table-column label="命中判定" min-width="130">
        <template #default="{row}">
          <template v-if="row.result">
            <span>{{ hitKinds(row.result) }}</span>
            <DeltaTag :cur="hitTotal(row.result)"
                      :prev="store.previousOf(row) ? hitTotal(store.previousOf(row)!.result) : undefined"/>
          </template>
          <span v-else-if="row.status==='failed'" class="err-text">{{ row.error }}</span>
          <span v-else-if="row.status==='skipped'" class="skip-text">{{ row.skipReason }}</span>
          <span v-else class="muted">—</span>
        </template>
      </el-table-column>
      <el-table-column label="操作" width="60">
        <template #default="{row}">
          <el-button v-if="row.status==='failed'" link type="primary" size="small"
                     :disabled="store.running" @click="store.retryItem(row)">重试</el-button>
        </template>
      </el-table-column>
    </el-table>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { ElMessage } from 'element-plus'
import { useLogStore } from '../store/log'
import DeltaTag from './DeltaTag.vue'
import QueueDetail from './QueueDetail.vue'
import type { BatchInputRow, QueueItem, RecomputeResult, RecomputeScope } from '../types'

const store = useLogStore()

interface DraftRow { label: string; sources: string[]; range: [string, string] | null }
const rows = ref<DraftRow[]>([{ label: '', sources: [], range: null }])

function addRow() { rows.value.push({ label: '', sources: [], range: null }) }

function fillBySources() {
  rows.value = store.availableSources.map(s => ({
    label: `来源 ${s}`, sources: [s], range: null,
  }))
  if (!rows.value.length) addRow()
}

function enqueue() {
  const payload: BatchInputRow[] = []
  for (const r of rows.value) {
    let start: number | null = null
    let end: number | null = null
    if (r.range) {
      start = r.range[0] ? Number(r.range[0]) : null
      end = r.range[1] ? Number(r.range[1]) : null
    }
    if (start !== null && end !== null && start > end) {
      ElMessage.warning(`「${r.label || '未命名'}」的时间范围起始晚于结束，请调整`)
      return
    }
    payload.push({
      label: r.label.trim() || defaultLabel(r.sources, start, end),
      sources: r.sources,
      start, end,
    })
  }
  const added = store.enqueueBatch(payload)
  const skipped = store.skippedCount
  rows.value = [{ label: '', sources: [], range: null }]
  if (added) ElMessage.success(`已加入队列 ${added} 条${skipped ? `，另有 ${skipped} 条因重复或重叠被跳过` : ''}`)
  else ElMessage.warning(`本次 ${payload.length} 条全部因重复入队或与上一轮重叠被跳过，详见队列说明`)
}

function defaultLabel(sources: string[], start: number | null, end: number | null): string {
  const s = sources.length ? sources.join(',') : '全部来源'
  if (start === null && end === null) return s
  return `${s} ${fmtTime(start)}~${fmtTime(end)}`
}

function scopeText(scope: RecomputeScope): string {
  const src = scope.sources.length ? scope.sources.join(',') : '全部来源'
  if (scope.start === null && scope.end === null) return src
  return `${src}｜${fmtTime(scope.start)} ~ ${fmtTime(scope.end)}`
}

function fmtTime(ts: number | null): string {
  if (ts === null) return '不限'
  const d = new Date(ts * 1000)
  const p = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`
}

function statusText(s: QueueItem['status']): string {
  return ({ pending: '待处理', running: '重算中', done: '完成', failed: '失败', skipped: '跳过' } as const)[s]
}
function statusType(s: QueueItem['status']): 'info' | 'warning' | 'success' | 'danger' {
  return ({ pending: 'info', running: 'warning', done: 'success', failed: 'danger', skipped: 'info' } as const)[s]
}

function hitTotal(r: RecomputeResult): number {
  return r.hits.reduce((sum, x) => sum + x.count, 0)
}
function hitKinds(r: RecomputeResult): string {
  return `${r.hits.length} 项 / ${hitTotal(r)} 次`
}
</script>

<style scoped>
.panel{background:#1e293b;border-radius:8px;padding:12px;border:1px solid #334155}
.head{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px}
.panel h4{color:#38bdf8;font-size:13px}
.round-tag{font-size:11px;color:#94a3b8}
.editor{background:#0f172a88;border:1px solid #334155;border-radius:6px;padding:8px;margin-bottom:8px}
.draft-row{display:flex;gap:6px;align-items:center;margin-bottom:6px;flex-wrap:wrap}
.editor-actions{display:flex;gap:8px;align-items:center;margin-top:4px}
.queue-actions{display:flex;gap:8px;align-items:center;margin:8px 0}
.counters{font-size:11px;color:#94a3b8;margin-left:auto}
.hint{font-size:11px;color:#fbbf24}
.empty{color:#64748b;font-size:12px;padding:6px 0}
.cell-label{font-size:12px;color:#e2e8f0}
.cell-sub{font-size:10px;color:#94a3b8;margin-top:2px}
.muted{color:#64748b;font-size:11px}
.err-text{color:#f87171;font-size:11px}
.skip-text{color:#fbbf24;font-size:11px}
.queue-table{width:100%}
</style>
