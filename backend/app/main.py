import re, math, time, random
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
import numpy as np
from collections import defaultdict, Counter
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="Log Anomaly Detector")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

LOG_TEMPLATES = {
    "nginx": {
        "pattern": r'(?P<timestamp>\S+ \+\d{4}) (?P<source>\S+) (?P<level>\w+) (?P<message>.+)',
        "generator": lambda: {
            "timestamp": f"{random.randint(1,28):02d}/{'Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec'.split()[random.randint(0,11)]}/{2024}:{random.randint(0,23):02d}:{random.randint(0,59):02d}:{random.randint(0,59):02d} +0000",
            "source": random.choice(["nginx", "api-gateway", "load-balancer"]),
            "level": random.choices(["INFO", "WARN", "ERROR", "DEBUG"], weights=[50, 15, 5, 30])[0],
            "message": random.choice([
                'GET /api/users 200 0.032s', 'POST /api/orders 201 0.145s', 'GET /api/products 304 0.008s',
                'GET /static/main.js 200 0.002s', 'POST /api/login 401 0.023s', 'GET /admin 403 0.005s',
                'GET /api/health 200 0.001s', 'GET /api/orders?page=2 200 0.056s', 'connection timeout upstream',
                'SSL handshake failed', 'worker process exited on signal 9', 'upstream server unavailable'
            ])
        }
    },
    "apache": {
        "pattern": r'\[(?P<timestamp>[^\]]+)\] \[(?P<level>\w+)\] \[(?P<source>\S+)\] (?P<message>.+)',
        "generator": lambda: {
            "timestamp": f"{'Sun Mon Tue Wed Thu Fri Sat'.split()[random.randint(0,6)]} {'Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec'.split()[random.randint(0,11)]} {random.randint(1,28):02d} {random.randint(0,23):02d}:{random.randint(0,59):02d}:{random.randint(0,59):02d} {2024}",
            "source": random.choice(["httpd", "mod_ssl", "mod_rewrite"]),
            "level": random.choices(["notice", "warn", "error", "info"], weights=[40, 15, 5, 40])[0],
            "message": random.choice(["server configured", "caught SIGTERM", "resuming normal ops", "request exceeded limit",
                        "file does not exist", "client denied by server", "Invalid method in request"])
        }
    },
    "json_app": {
        "pattern": None,
        "generator": lambda: {
            "timestamp": f"{2024}-{random.randint(1,12):02d}-{random.randint(1,28):02d}T{random.randint(0,23):02d}:{random.randint(0,59):02d}:{random.randint(0,59):02d}.{random.randint(0,999):03d}Z",
            "source": random.choice(["user-service", "order-service", "payment-service", "auth-service"]),
            "level": random.choices(["INFO", "WARN", "ERROR", "DEBUG"], weights=[45, 20, 5, 30])[0],
            "message": random.choice([
                'User login successful user_id=10' + str(random.randint(100, 999)),
                'Order created order_id=ORD-' + str(random.randint(10000, 99999)),
                'Payment processed amount=' + str(random.randint(10, 999)),
                'Database connection pool exhausted',
                'Cache miss for key user_session_' + str(random.randint(100, 999)),
                'Circuit breaker opened for service payment',
                'Request latency exceeds threshold 5000ms',
                'NullPointerException at com.app.controller.UserController.getProfile'
            ])
        }
    },
    "custom": {
        "pattern": None,
        "generator": lambda: {
            "timestamp": str(int(time.time() - random.randint(0, 86400))),
            "source": random.choice(["cron", "systemd", "kernel", "docker"]),
            "level": random.choices(["info", "warning", "error", "debug"], weights=[40, 20, 5, 35])[0],
            "message": random.choice(["OOM killer invoked", "disk usage above 90%", "container restarted", "NTP sync lost",
                        "process oom_score_adj=500", "firewall rule updated", "mount point not found"])
        }
    }
}

# 与检测口径相关的常量：批量重算与 /api/detect 共用同一套，保证两轮统计口径一致
WINDOW_SIZE = 20
SIGMA_THRESHOLD = 2.5
IQR_THRESHOLD = 3.0

MONTH_ABBR = {m: i + 1 for i, m in enumerate(
    ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec'])}


class GenerateRequest(BaseModel):
    type: str = "nginx"
    count: int = 1000


class DetectRequest(BaseModel):
    logs: list
    rules: list = []
    query: str = ""


class RecalcJob(BaseModel):
    name: str = ""
    sources: List[str] = []
    start: Optional[str] = None
    end: Optional[str] = None


class RecalcRequest(BaseModel):
    logs: list
    rules: list = []
    jobs: List[RecalcJob] = []


# ---------------------------------------------------------------------------
# 统计原语：analyze_logs（检测接口）与批量重算共用，保证口径一致
# ---------------------------------------------------------------------------

def build_windows(logs: List[dict]) -> List[dict]:
    """按固定窗口大小切分日志（与检测接口相同的 20 条/窗口）。"""
    windows = []
    for i in range(0, len(logs), WINDOW_SIZE):
        chunk = logs[i:i + WINDOW_SIZE]
        levels = Counter(l["level"] for l in chunk)
        sources = Counter(l["source"] for l in chunk)
        windows.append({
            "start": i, "end": min(i + WINDOW_SIZE, len(logs)),
            "count": len(chunk),
            "levels": dict(levels),
            "sources": dict(sources)
        })
    return windows


def score_windows(windows: List[dict], logs: List[dict]) -> List[dict]:
    """3-sigma + IQR 异常打分，阈值与检测接口一致。"""
    counts = [w["count"] for w in windows]
    if not counts:
        return []
    mean = float(np.mean(counts))
    std = float(np.std(counts)) if len(counts) > 1 else 1.0
    q1 = float(np.percentile(counts, 25)) if len(counts) > 3 else mean - std
    q3 = float(np.percentile(counts, 75)) if len(counts) > 3 else mean + std
    iqr = q3 - q1 if q3 > q1 else 1.0

    anomalies = []
    for i, w in enumerate(windows):
        sigma_score = abs(w["count"] - mean) / max(std, 1e-5)
        iqr_low = q1 - 1.5 * iqr
        iqr_high = q3 + 1.5 * iqr
        iqr_score = 0.0
        if w["count"] < iqr_low or w["count"] > iqr_high:
            iqr_score = min(10.0, abs(w["count"] - (mean)) / max(iqr, 1e-5))
        anomalies.append({
            "windowIndex": i,
            "sigmaScore": round(sigma_score, 2),
            "iqrScore": round(iqr_score, 2),
            "isAnomaly": sigma_score > SIGMA_THRESHOLD or iqr_score > IQR_THRESHOLD,
            "timestamp": logs[i * WINDOW_SIZE]["timestamp"] if i * WINDOW_SIZE < len(logs) else ""
        })
    return anomalies


def rule_matches(rule: dict, w: dict) -> bool:
    """告警规则判定，条件与检测接口完全一致；keyword 规则检测接口本身不计命中。"""
    if rule.get("type") == "level":
        return w["levels"].get("ERROR", 0) > rule.get("threshold", 5)
    if rule.get("type") == "count":
        return w["count"] > rule.get("threshold", 200)
    return False


# ---------------------------------------------------------------------------
# 时间范围解析：四类模拟日志的时间戳格式 + 用户输入的时间范围
# ---------------------------------------------------------------------------

def parse_log_timestamp(value: Any) -> Optional[datetime]:
    """尽力解析单条日志的 timestamp，覆盖 nginx/apache/json_app/custom 四种格式。"""
    if value is None:
        return None
    s = str(value).strip()
    if not s:
        return None
    # custom: 秒级 Unix 时间戳
    if re.fullmatch(r'\d{9,10}', s):
        try:
            return datetime.fromtimestamp(int(s))
        except (ValueError, OSError):
            return None
    # json_app: 2024-05-12T03:04:05.123Z
    m = re.fullmatch(
        r'(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?Z?', s)
    if m:
        try:
            return datetime(*(int(g) for g in m.groups()))
        except ValueError:
            return None
    # nginx: 12/May/2024:03:04:05 +0000
    m = re.fullmatch(
        r'(\d{1,2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})(?:\s*[+-]\d{4})?', s)
    if m:
        day, mon, year, hh, mm, ss = m.groups()
        if mon.lower() in MONTH_ABBR:
            try:
                return datetime(int(year), MONTH_ABBR[mon.lower()], int(day),
                                int(hh), int(mm), int(ss))
            except ValueError:
                return None
    # apache: Wed May 12 03:04:05 2024
    m = re.fullmatch(
        r'(?:[A-Za-z]{3}\s+)?([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\d{4})', s)
    if m:
        mon, day, hh, mm, ss, year = m.groups()
        if mon.lower() in MONTH_ABBR:
            try:
                return datetime(int(year), MONTH_ABBR[mon.lower()], int(day),
                                int(hh), int(mm), int(ss))
            except ValueError:
                return None
    return None


def parse_range_bound(value: Any) -> Optional[datetime]:
    """解析重算分组的时间范围边界，支持日期/datetime-local/ISO/Unix 秒。"""
    if value is None:
        return None
    s = str(value).strip()
    if not s:
        return None
    if re.fullmatch(r'\d{9,10}', s):
        return datetime.fromtimestamp(int(s))
    fmts = (
        '%Y-%m-%dT%H:%M:%S', '%Y-%m-%dT%H:%M',
        '%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M',
        '%Y-%m-%d',
    )
    for fmt in fmts:
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    dt = parse_log_timestamp(s)
    if dt is None:
        raise ValueError(f"时间边界无法解析: {s!r}")
    return dt


def filter_logs(logs: List[dict], sources: List[str],
                start: Optional[datetime], end: Optional[datetime]
                ) -> Tuple[List[dict], int]:
    """按来源与时间范围筛选；启用了时间过滤时无法解析时间戳的日志跳过并计数。"""
    wanted = set(sources or [])
    use_time = start is not None or end is not None
    selected, unparsable = [], 0
    for log in logs:
        if wanted and log.get("source") not in wanted:
            continue
        if use_time:
            dt = parse_log_timestamp(log.get("timestamp"))
            if dt is None:
                unparsable += 1
                continue
            if start is not None and dt < start:
                continue
            if end is not None and dt > end:
                continue
        selected.append(log)
    return selected, unparsable


def evaluate_criteria(windows: List[dict], anomalies: List[dict],
                      rules: List[dict]) -> List[dict]:
    """逐判定项统计命中窗口数，判定条件与 rule_matches / score_windows 相同。"""
    criteria: List[dict] = []
    for rule in rules:
        rule = rule if isinstance(rule, dict) else {}
        rtype = rule.get("type", "")
        if rtype == "level":
            threshold = rule.get("threshold", 5)
            hit = sum(1 for w in windows
                      if w["levels"].get("ERROR", 0) > threshold)
            criteria.append({
                "key": f"rule:{rtype}:{threshold}",
                "name": f"{rule.get('name', '高频ERROR')}（ERROR>{threshold}/窗）",
                "kind": "rule", "ruleType": rtype,
                "hitWindows": hit, "hit": hit > 0
            })
        elif rtype == "count":
            threshold = rule.get("threshold", 200)
            hit = sum(1 for w in windows if w["count"] > threshold)
            criteria.append({
                "key": f"rule:{rtype}:{threshold}",
                "name": f"{rule.get('name', '异常流量')}（日志量>{threshold}/窗）",
                "kind": "rule", "ruleType": rtype,
                "hitWindows": hit, "hit": hit > 0
            })
        else:
            # 与检测接口保持一致：keyword 等规则不参与统计判定
            criteria.append({
                "key": f"rule:{rtype or 'unknown'}",
                "name": f"{rule.get('name', rtype or '未命名规则')}（检测接口未参与统计）",
                "kind": "rule", "ruleType": rtype or "unknown",
                "hitWindows": 0, "hit": False
            })
    sigma_hit = sum(1 for a in anomalies if a["sigmaScore"] > SIGMA_THRESHOLD)
    iqr_hit = sum(1 for a in anomalies if a["iqrScore"] > IQR_THRESHOLD)
    any_hit = sum(1 for a in anomalies if a["isAnomaly"])
    criteria.append({
        "key": "stat:3sigma", "kind": "stat",
        "name": f"3-sigma 异常分 > {SIGMA_THRESHOLD}",
        "hitWindows": sigma_hit, "hit": sigma_hit > 0
    })
    criteria.append({
        "key": "stat:iqr", "kind": "stat",
        "name": f"IQR 异常分 > {IQR_THRESHOLD}",
        "hitWindows": iqr_hit, "hit": iqr_hit > 0
    })
    criteria.append({
        "key": "stat:anomaly", "kind": "stat",
        "name": "统计异常窗口（3-sigma 或 IQR 命中）",
        "hitWindows": any_hit, "hit": any_hit > 0
    })
    return criteria


def summarize(logs: List[dict], rules: List[dict]) -> dict:
    """对一组日志执行与检测接口同口径的统计，返回重算条目所需指标。"""
    windows = build_windows(logs)
    anomalies = score_windows(windows, logs)
    sigma_scores = [a["sigmaScore"] for a in anomalies]
    iqr_scores = [a["iqrScore"] for a in anomalies]
    return {
        "count": len(logs),
        "windowCount": len(windows),
        "anomalyCount": sum(1 for a in anomalies if a["isAnomaly"]),
        "maxSigma": max(sigma_scores, default=0.0),
        "meanSigma": round(float(np.mean(sigma_scores)), 2) if sigma_scores else 0.0,
        "maxIqr": max(iqr_scores, default=0.0),
        "meanIqr": round(float(np.mean(iqr_scores)), 2) if iqr_scores else 0.0,
        "criteria": evaluate_criteria(windows, anomalies, rules),
    }


@app.post("/api/generate")
def generate_logs(req: GenerateRequest):
    tmpl = LOG_TEMPLATES.get(req.type, LOG_TEMPLATES["nginx"])
    logs = []
    for i in range(req.count):
        entry = tmpl["generator"]()
        logs.append({
            "id": i + 1,
            "timestamp": entry["timestamp"],
            "level": entry["level"],
            "source": entry["source"],
            "message": entry["message"],
            "raw": f"[{entry['timestamp']}] [{entry['level']}] [{entry['source']}] {entry['message']}"
        })
    return analyze_logs(logs, [], "")


@app.post("/api/detect")
def detect_anomalies(req: DetectRequest):
    return analyze_logs(req.logs, req.rules, req.query)


@app.post("/api/recalculate")
def recalculate(req: RecalcRequest):
    """批量重算：每个分组按时间范围/来源筛选日志，沿用检测接口口径重算。

    单条失败不影响其他分组，错误信息随该条返回，前端可据此做单条重试。
    """
    logs = req.logs if isinstance(req.logs, list) else []
    rules = [r for r in (req.rules or []) if isinstance(r, dict)]
    results = []
    for index, job in enumerate(req.jobs):
        try:
            start = parse_range_bound(job.start)
            end = parse_range_bound(job.end)
            if start and end and start > end:
                raise ValueError(f"时间范围起点({job.start})晚于终点({job.end})")
            selected, unparsable = filter_logs(logs, job.sources, start, end)
            stats = summarize(selected, rules)
            note = ""
            if not selected:
                note = "该时间范围/来源组合下没有可统计的日志，各项指标按 0 计"
            elif unparsable:
                note = f"{unparsable} 条日志时间戳无法解析，已按口径排除"
            results.append({"index": index, "ok": True, "note": note, **stats})
        except Exception as exc:  # 单条失败隔离
            results.append({"index": index, "ok": False, "error": str(exc)})
    return {
        "results": results,
        "windowSize": WINDOW_SIZE,
        "sigmaThreshold": SIGMA_THRESHOLD,
        "iqrThreshold": IQR_THRESHOLD,
    }


def analyze_logs(logs_data, rules, query):
    logs = logs_data
    n = len(logs)

    windows = build_windows(logs)

    anomalies = score_windows(windows, logs)

    # Alert rules
    alerts = []
    for i, rule in enumerate(rules):
        rule = rule if isinstance(rule, dict) else {}
        for w in windows:
            if rule.get("type") == "level" and rule_matches(rule, w):
                alerts.append({
                    "id": len(alerts) + 1, "ruleName": rule.get("name", "高频ERROR"),
                    "severity": "high", "message": f"窗口{w['start']}内ERROR日志{w['levels']['ERROR']}条超过阈值{rule.get('threshold',5)}",
                    "timestamp": time.strftime("%H:%M:%S")
                })
            if rule.get("type") == "count" and rule_matches(rule, w):
                alerts.append({
                    "id": len(alerts) + 1, "ruleName": rule.get("name", "异常流量"),
                    "severity": "medium", "message": f"窗口{w['start']}日志量{w['count']}超过阈值",
                    "timestamp": time.strftime("%H:%M:%S")
                })

    # Full-text search with TF-IDF
    if query:
        query_terms = query.lower().split()
        scored = []
        for log in logs:
            raw_lower = log["raw"].lower()
            score = sum(1 for t in query_terms if t in raw_lower)
            if score > 0:
                scored.append((score, log))
        logs = [l for _, l in sorted(scored, key=lambda x: x[0], reverse=True)]

    # Add non-rule alerts for high anomaly windows
    for a in anomalies:
        if a["isAnomaly"]:
            alerts.append({
                "id": len(alerts) + 1, "ruleName": "统计异常检测",
                "severity": "critical" if a["sigmaScore"] > 4 else "high",
                "message": f"窗口{a['windowIndex']}: 3-sigma={a['sigmaScore']}, IQR={a['iqrScore']}",
                "timestamp": a["timestamp"]
            })

    return {
        "logs": logs[:200],
        "windows": windows,
        "anomalies": anomalies,
        "alerts": alerts[:20],
        "totalLogs": n
    }
