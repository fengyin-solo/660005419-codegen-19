export interface LogEntry { id: number; timestamp: string; level: string; source: string; message: string; raw: string }
export interface TimeWindow { start: number; end: number; count: number; levels: Record<string,number>; sources: Record<string,number> }
export interface AnomalyScore { windowIndex: number; sigmaScore: number; iqrScore: number; isAnomaly: boolean; timestamp: string }
export interface AlertRule { id: number; name: string; type: string; threshold: number; enabled: boolean }
export interface Alert { id: number; ruleName: string; severity: string; message: string; timestamp: string }
export interface AnalysisResult { logs: LogEntry[]; windows: TimeWindow[]; anomalies: AnomalyScore[]; alerts: Alert[]; totalLogs: number }

// ---- 批量重算 ----
export interface RecomputeScope {
  sources: string[]          // 空数组表示不限来源
  start: number | null       // unix 秒，null 表示不限
  end: number | null
}

export type QueueItemStatus = 'pending' | 'running' | 'done' | 'failed' | 'skipped'

export interface RecomputeHit {
  id: string
  name: string
  type: string               // level / count / keyword / anomaly
  severity: string
  count: number
  windows: number[]
}

export interface RecomputeCaliber {
  windowSize: number
  sigmaThreshold: number
  iqrScoreThreshold: number
  rules: string[]
}

export interface RecomputeResult {
  jobId: string
  label: string
  scope: RecomputeScope
  matched: number
  totalScanned: number
  windowCount: number
  anomalyWindows: number
  avgSigmaScore: number
  maxSigmaScore: number
  avgIqrScore: number
  maxIqrScore: number
  hits: RecomputeHit[]
  caliber: RecomputeCaliber
}

export interface QueueItem {
  id: number
  label: string
  scope: RecomputeScope
  status: QueueItemStatus
  result?: RecomputeResult
  error?: string
  skipReason?: string
}

export interface BatchInputRow {
  label: string
  sources: string[]
  start: number | null
  end: number | null
}

export interface RoundEntry {
  label: string
  result: RecomputeResult
}
