export interface LogEntry { id: number; timestamp: string; level: string; source: string; message: string; raw: string }
export interface TimeWindow { start: number; end: number; count: number; levels: Record<string,number>; sources: Record<string,number> }
export interface AnomalyScore { windowIndex: number; sigmaScore: number; iqrScore: number; isAnomaly: boolean; timestamp: string }
export interface AlertRule { id: number; name: string; type: string; threshold: number; enabled: boolean }
export interface Alert { id: number; ruleName: string; severity: string; message: string; timestamp: string }
export interface AnalysisResult { logs: LogEntry[]; windows: TimeWindow[]; anomalies: AnomalyScore[]; alerts: Alert[]; totalLogs: number }

export type RecalcStatus = 'queued' | 'running' | 'done' | 'failed'

export interface RecalcCriterion {
  key: string
  name: string
  kind: 'rule' | 'stat'
  ruleType?: string
  hitWindows: number
  hit: boolean
}

export interface RecalcStats {
  count: number
  windowCount: number
  anomalyCount: number
  maxSigma: number
  meanSigma: number
  maxIqr: number
  meanIqr: number
  criteria: RecalcCriterion[]
}

export interface RecalcJobSpec {
  sources: string[]
  start: string | null
  end: string | null
}

export interface CriterionDelta {
  name: string
  current: number
  previous: number
  diff: number
  hitNow: boolean
  hitBefore: boolean
}

export interface RecalcDelta {
  count: number | null
  anomalyCount: number | null
  maxSigma: number | null
  maxIqr: number | null
  criteria: CriterionDelta[]
}

export interface RecalcJob extends RecalcJobSpec {
  id: number
  name: string
  status: RecalcStatus
  error?: string
  note?: string
  stats?: RecalcStats
  round?: number
  baselineRound?: number
  delta?: RecalcDelta
}

export interface RecalcServerJob extends Partial<RecalcStats> {
  index: number
  ok: boolean
  error?: string
  note?: string
}

export interface RecalcResponse {
  results: RecalcServerJob[]
  windowSize: number
  sigmaThreshold: number
  iqrThreshold: number
}

export interface SkippedEntry {
  name: string
  spec: RecalcJobSpec
  reason: string
  against: string
}

export interface BatchEnqueueResult {
  added: RecalcJob[]
  skipped: SkippedEntry[]
}

