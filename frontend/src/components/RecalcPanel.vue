<template>
  <div class="panel recalc-panel">
    <div class="rp-head">
      <h4>🧮 结果清单批量重算
        <el-tag v-if="store.lastRoundLabel" size="small" type="success" effect="dark">{{ store.lastRoundLabel }}</el-tag>
      </h4>
      <div class="rp-actions">
        <el-button size="small" type="primary" @click="openBatch">整组加入</el-button>
        <el-button size="small" type="warning" :loading="store.running"
                   :disabled="!store.hasQueued || !hasResult" @click="store.runAll()">
          ▶ 重算队列
        </el-button>
        <el-button size="small" @click="store.clearFinished()">清除已完成</el-button>
        <el-button size="small" @click="store.clearAll()">清空</el-button>
      </div>
    </div>
    <div class="rp-caliber">
      统计口径：与「检测异常」相同 —— 每 {{ caliber.windowSize }} 条日志一个窗口，
      3-sigma&gt;{{ caliber.sigmaThreshold }}、IQR&gt;{{ caliber.iqrThreshold }} 判异常，规则阈值沿用上方启用的告警规则
    </div>
    <div v-if="!hasResult" class="rp-empty">请先生成日志，再加入重算分组</div>
    <div v-else-if="!store.jobs.length" class="rp-empty">队列为空，点击「整组加入」批量添加时间范围/来源分组</div>
    <el-table v-else :data="store.jobs" size="small" max-height="360" stripe class="rp-table">
      <el-table-column label="分组" min-width="150">
        <template #default="{ row }">
          <div class="rp-name">{{ row.name }}</div>
          <div class="rp-sub">{{ formatSpec(row) }}</div>
        </template>
      </el-table-column>
      <el-table-column label="状态" width="86">
        <template #default="{ row }">
          <el-tag size="small" :type="statusType(row.status)" effect="dark">{{ statusText(row.status) }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column label="条目数" width="96">
        <template #default="{ row }">
          <template v-if="row.stats">{{ row.stats.count }}<Delta :v="row.delta?.count" :first="row.baselineRound === undefined"/></template>
          <span v-else class="muted">—</span>
        </template>
      </el-table-column>
      <el-table-column label="异常窗口" width="92">
        <template #default="{ row }">
          <template v-if="row.stats">{{ row.stats.anomalyCount }}/{{ row.stats.windowCount }}
            <Delta :v="row.delta?.anomalyCount" :first="row.baselineRound === undefined"/></template>
          <span v-else class="muted">—</span>
        </template>
      </el-table-column>
      <el-table-column label="最高 3σ / IQR" width="142">
        <template #default="{ row }">
          <template v-if="row.stats">
            {{ row.stats.maxSigma }} <Delta :v="row.delta?.maxSigma" :first="row.baselineRound === undefined"/> /
            {{ row.stats.maxIqr }} <Delta :v="row.delta?.maxIqr" :first="row.baselineRound === undefined"/>
          </template>
          <span v-else class="muted">—</span>
        </template>
      </el-table-column>
      <el-table-column label="命中的判定项（与上一轮对照）" min-width="220">
        <template #default="{ row }">
          <template v-if="row.stats">
            <el-tooltip placement="top" :disabled="!row.baselineRound">
              <template #content>
                对照基线：{{ row.baselineRound ? `第 ${row.baselineRound} 轮` : '无上一轮，本轮为首次计算' }}
              </template>
              <div class="crit-list">
                <span v-for="c in hitDeltas(row)" :key="c.name" class="crit"
                      :class="{ hit: c.hitNow, added: c.hitNow && !c.hitBefore, gone: !c.hitNow && c.hitBefore }">
                  {{ c.name }} · {{ c.current }}窗<Delta :v="c.diff" :first="row.baselineRound === undefined && c.current > 0"/>
                </span>
                <span v-if="!hitDeltas(row).length" class="muted">无命中项</span>
              </div>
            </el-tooltip>
            <div v-if="row.note" class="rp-note">注：{{ row.note }}</div>
          </template>
          <div v-else-if="row.status === 'failed'" class="rp-err">
            ⚠ {{ row.error }}
            <el-button size="small" type="primary" plain :loading="row.status === 'running'"
                       @click="store.retryOne(row)">单条重试</el-button>
          </div>
          <span v-else class="muted">待重算</span>
        </template>
      </el-table-column>
      <el-table-column label="操作" width="118">
        <template #default="{ row }">
          <el-button v-if="row.status === 'failed'" size="small" type="primary" plain
                     @click="store.retryOne(row)">重试</el-button>
          <el-button v-else-if="row.status === 'done'" size="small" plain
                     @click="store.retryOne(row)">再算一次</el-button>
          <el-button size="small" type="danger" plain
                     :disabled="row.status === 'running'" @click="store.removeJob(row)">移除</el-button>
        </template>
      </el-table-column>
    </el-table>

    <!-- 批量加入对话框 -->
    <el-dialog v-model="batchVisible" title="整组加入重算队列" width="760px" append-to-body>
      <div class="batch-tip">每行一个分组（时间范围 + 来源），一次可添加多行；重复或与上一轮重叠的行会被标明并跳过。</div>
      <div v-for="(row, idx) in drafts" :key="idx" class="draft-row">
        <el-input v-model="row.name" placeholder="分组名称（可空）" size="small" class="d-name"/>
        <el-date-picker v-model="row.range" type="datetimerange" size="small"
                        range-separator="~" start-placeholder="开始（可空）" end-placeholder="结束（可空）"
                        value-format="YYYY-MM-DDTHH:mm:ss" class="d-range"/>
        <el-select v-model="row.sources" multiple collapse-tags collapse-tags-tooltip
                   placeholder="全部来源" size="small" class="d-src">
          <el-option v-for="s in store.availableSources" :key="s" :label="s" :value="s"/>
        </el-select>
        <el-button size="small" type="danger" plain @click="drafts.splice(idx, 1)">✕</el-button>
      </div>
      <el-button size="small" @click="addDraft">+ 再加一行</el-button>
      <template #footer>
        <el-button @click="batchVisible = false">关闭</el-button>
        <el-button type="primary" @click="submitBatch">加入队列</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { computed, h, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { useLogStore } from '../store/log'
import { useRecalcStore, specLabel } from '../store/recalc'
import type { CriterionDelta, RecalcJob, RecalcJobSpec } from '../types'

interface Draft { name: string; range: [string, string] | null; sources: string[] }
type TagType = 'primary' | 'success' | 'warning' | 'info' | 'danger'

const logStore = useLogStore()
const store = useRecalcStore()
const batchVisible = ref(false)
const drafts = ref<Draft[]>([])

const hasResult = computed(() => !!logStore.result)
const caliber = { windowSize: 20, sigmaThreshold: 2.5, iqrThreshold: 3.0 }

function addDraft() {
  drafts.value.push({ name: '', range: null, sources: [] })
}
function openBatch() {
  if (!drafts.value.length) {
    addDraft()
    addDraft()
  }
  batchVisible.value = true
}
function submitBatch() {
  const payload = drafts.value
    .map((d) => ({
      name: d.name,
      sources: d.sources,
      start: d.range?.[0] ?? null,
      end: d.range?.[1] ?? null
    }))
    .filter((d) => d.name || d.start || d.end || d.sources.length)
  if (!payload.length) return
  const { added, skipped } = store.enqueueBatch(payload)
  drafts.value = []
  if (skipped.length) {
    ElMessage.warning(
      `加入 ${added.length} 条，跳过 ${skipped.length} 条：\n` +
      skipped.map((s) => `· ${s.name}：${s.reason}（${s.against}）`).join('\n')
    )
  } else {
    ElMessage.success(`已加入 ${added.length} 条重算分组`)
  }
}

function formatSpec(row: RecalcJobSpec): string {
  return specLabel(row)
}
function statusType(s: RecalcJob['status']): TagType {
  return s === 'done' ? 'success' : s === 'failed' ? 'danger' : s === 'running' ? 'warning' : 'info'
}
function statusText(s: RecalcJob['status']) {
  return { queued: '待重算', running: '重算中', done: '完成', failed: '失败' }[s]
}
function hitDeltas(row: RecalcJob): CriterionDelta[] {
  return (row.delta?.criteria || []).filter((c) => c.hitNow || c.hitBefore)
}

// 数值增减标记；首轮无上一轮时标注"首轮"
const Delta = {
  props: {
    v: { type: Number as () => number | null, default: null },
    first: { type: Boolean, default: false }
  },
  setup(props: { v: number | null; first: boolean }) {
    return () => {
      if (props.first) return h('span', { class: ['delta', 'd-first'] }, ' (首轮)')
      if (props.v === null || props.v === 0) return null
      const cls = props.v > 0 ? 'd-up' : 'd-down'
      const txt = props.v > 0 ? `+${props.v}` : `${props.v}`
      return h('span', { class: ['delta', cls] }, ` (${txt})`)
    }
  }
}
</script>

<style scoped>
.recalc-panel{margin-top:12px}
.rp-head{display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap}
.rp-head h4{color:#38bdf8;font-size:13px;display:flex;align-items:center;gap:6px}
.rp-actions{display:flex;gap:6px;flex-wrap:wrap}
.rp-caliber{font-size:11px;color:#94a3b8;margin:6px 0;padding:4px 8px;background:#0f172a;border-radius:4px;border-left:2px solid #38bdf8}
.rp-empty{color:#64748b;font-size:12px;padding:14px 0;text-align:center}
.rp-table{width:100%}
.rp-name{font-size:12px;color:#e2e8f0;font-weight:600}
.rp-sub{font-size:10px;color:#94a3b8;margin-top:2px}
.muted{color:#64748b;font-size:11px}
.crit-list{display:flex;flex-wrap:wrap;gap:4px}
.crit{font-size:10px;padding:1px 5px;border-radius:3px;background:#334155;color:#cbd5e1;white-space:nowrap}
.crit.hit{background:#7f1d1d55;color:#fca5a5}
.crit.added{outline:1px solid #22c55e}
.crit.gone{text-decoration:line-through;opacity:.75}
.rp-note{font-size:10px;color:#fbbf24;margin-top:3px}
.rp-err{font-size:11px;color:#f87171;display:flex;flex-direction:column;gap:4px;align-items:flex-start}
.delta{font-size:10px;font-weight:700}
.d-up{color:#f87171}
.d-down{color:#4ade80}
.d-first{color:#64748b;font-weight:400}
.batch-tip{font-size:12px;color:#94a3b8;margin-bottom:10px}
.draft-row{display:flex;gap:8px;margin-bottom:8px;align-items:center}
.d-name{width:150px;flex:none}
.d-range{flex:1;min-width:280px}
.d-src{width:200px;flex:none}
:deep(.el-table){background:transparent;color:#e2e8f0}
:deep(.el-table tr),:deep(.el-table th.el-table__cell),:deep(.el-table td.el-table__cell){background:transparent}
:deep(.el-table--striped .el-table__body tr.el-table__row--striped td.el-table__cell){background:#1e293b}
:deep(.el-table__body tr:hover>td.el-table__cell){background:#33415588!important}
:deep(.el-table th.el-table__cell){background:#0f172a;color:#94a3b8}
:deep(.el-table__inner-wrapper::before){background-color:#334155}
</style>
