import re, time, random
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
from collections import Counter
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

# 重算与主分析共用的统计口径参数（改动即同时影响两者，保证口径一致）
WINDOW_SIZE = 20          # 每个窗口的条目数
SIGMA_THRESHOLD = 2.5     # 3-sigma 命中阈值
IQR_SCORE_THRESHOLD = 3.0 # IQR 分数命中阈值
LEVEL_ALERT_TYPE = "level"
COUNT_ALERT_TYPE = "count"
KEYWORD_ALERT_TYPE = "keyword"


class GenerateRequest(BaseModel):
    type: str = "nginx"
    count: int = 1000


class DetectRequest(BaseModel):
    logs: list
    rules: list = []
    query: str = ""


class RecomputeScope(BaseModel):
    # 为空列表表示不限来源；start/end 为 unix 秒，None 表示不限
    sources: List[str] = []
    start: Optional[float] = None
    end: Optional[float] = None


class RecomputeJob(BaseModel):
    jobId: Optional[str] = None
    label: str = ""
    scope: RecomputeScope


class RecomputeRequest(BaseModel):
    logs: list
    rules: list = []
    job: RecomputeJob


class _BadRequest(Exception):
    def __init__(self, message: str):
        self.message = message


def _bad_request(message: str) -> Exception:
    return _BadRequest(message)


@app.exception_handler(_BadRequest)
def _bad_request_handler(request, exc: _BadRequest):
    from fastapi.responses import JSONResponse
    return JSONResponse(status_code=400, content={"detail": exc.message})


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


@app.post("/api/recompute")
def recompute(req: RecomputeRequest):
    """对单条重算任务按与主分析完全一致的口径重新计算条目数/得分/命中判定项。"""
    logs = req.logs or []
    scope = req.job.scope
    sources = set(s for s in (scope.sources or []) if s)
    rules = [r for r in (req.rules or []) if isinstance(r, dict) and r.get("enabled", True)]

    if scope.start is not None and scope.end is not None and scope.start > scope.end:
        raise _bad_request("时间范围起始晚于结束，请调整后重试")
    if sources:
        available = {l.get("source") for l in logs}
        unknown = sorted(sources - available)
        if unknown:
            raise _bad_request(f"来源不存在于当前数据中：{', '.join(unknown)}")

    subset = [l for l in logs if _in_scope(l, sources, scope.start, scope.end)]
    if not subset:
        target = _scope_description(sources, scope.start, scope.end)
        raise _bad_request(f"范围内没有可重算的日志（{target}），请扩大范围后重试")

    stats = compute_stats(subset, rules)
    return {
        "jobId": req.job.jobId,
        "label": req.job.label,
        "scope": {
            "sources": sorted(sources),
            "start": scope.start,
            "end": scope.end,
        },
        "matched": len(subset),
        "totalScanned": len(logs),
        "avgSigmaScore": stats["avgSigmaScore"],
        "maxSigmaScore": stats["maxSigmaScore"],
        "avgIqrScore": stats["avgIqrScore"],
        "maxIqrScore": stats["maxIqrScore"],
        "anomalyWindows": stats["anomalyWindows"],
        "windowCount": stats["windowCount"],
        "hits": stats["hits"],
        "caliber": stats["caliber"],
    }


# ---------------------------------------------------------------------------
# 共用计算逻辑：analyze_logs（图表/主流程）与 /api/recompute 都走这里的口径
# ---------------------------------------------------------------------------

def build_windows(logs: List[dict], window_size: int = WINDOW_SIZE) -> List[dict]:
    windows = []
    for i in range(0, len(logs), window_size):
        chunk = logs[i:i + window_size]
        levels = Counter(l["level"] for l in chunk)
        sources = Counter(l["source"] for l in chunk)
        windows.append({
            "start": i, "end": min(i + window_size, len(logs)),
            "count": len(chunk),
            "levels": dict(levels),
            "sources": dict(sources)
        })
    return windows


def score_windows(windows: List[dict], logs: List[dict]) -> List[dict]:
    counts = [w["count"] for w in windows]
    if counts:
        mean = float(np.mean(counts))
        std = float(np.std(counts)) if len(counts) > 1 else 1.0
        q1 = float(np.percentile(counts, 25)) if len(counts) > 3 else mean - std
        q3 = float(np.percentile(counts, 75)) if len(counts) > 3 else mean + std
    else:
        mean, std, q1, q3 = 0.0, 1.0, 0.0, 0.0
    iqr = q3 - q1 if q3 > q1 else 1.0

    anomalies = []
    for i, w in enumerate(windows):
        sigma_score = abs(w["count"] - mean) / max(std, 1e-5)
        iqr_low = q1 - 1.5 * iqr
        iqr_high = q3 + 1.5 * iqr
        iqr_score = 0.0
        if w["count"] < iqr_low or w["count"] > iqr_high:
            iqr_score = min(10.0, abs(w["count"] - mean) / max(iqr, 1e-5))
        anomalies.append({
            "windowIndex": i,
            "sigmaScore": round(sigma_score, 2),
            "iqrScore": round(iqr_score, 2),
            "isAnomaly": sigma_score > SIGMA_THRESHOLD or iqr_score > IQR_SCORE_THRESHOLD,
            "timestamp": logs[i * WINDOW_SIZE]["timestamp"] if i * WINDOW_SIZE < len(logs) else ""
        })
    return anomalies


def rule_hits(logs: List[dict], windows: List[dict], rules: List[dict],
              anomalies: Optional[List[dict]] = None, keyword_query: str = "") -> List[dict]:
    """统一的判定项命中统计：阈值规则 + 统计异常 + 关键词命中。

    返回每个判定项的 id/name/type/severity/count/windows，重算逐条对照以此为准。
    """
    hits: Dict[Tuple[str, str], dict] = {}

    def bucket(hit_id: str, name: str, hit_type: str, severity: str) -> dict:
        key = (hit_type, hit_id)
        if key not in hits:
            hits[key] = {
                "id": hit_id, "name": name, "type": hit_type,
                "severity": severity, "count": 0, "windows": []
            }
        return hits[key]

    for rule in rules:
        rule = rule if isinstance(rule, dict) else {}
        rtype = rule.get("type")
        threshold = rule.get("threshold", 5)
        name = rule.get("name", rtype or "规则")
        rid = str(rule.get("id", name))
        for w in windows:
            if rtype == LEVEL_ALERT_TYPE and w["levels"].get("ERROR", 0) > threshold:
                h = bucket(rid, name, LEVEL_ALERT_TYPE, "high")
                h["count"] += w["levels"]["ERROR"]
                h["windows"].append(w["start"])
            if rtype == COUNT_ALERT_TYPE and w["count"] > threshold:
                h = bucket(rid, name, COUNT_ALERT_TYPE, "medium")
                h["count"] += 1
                h["windows"].append(w["start"])
            if rtype == KEYWORD_ALERT_TYPE and keyword_query:
                terms = keyword_query.lower().split()
                kw_count = 0
                for l in logs[w["start"]:w["end"]]:
                    raw_lower = l.get("raw", "").lower()
                    if terms and all(t in raw_lower for t in terms):
                        kw_count += 1
                if kw_count > 0:
                    h = bucket(rid, name, KEYWORD_ALERT_TYPE, "medium")
                    h["count"] += kw_count
                    h["windows"].append(w["start"])

    if anomalies is None:
        anomalies = score_windows(windows, logs)
    for a in anomalies:
        if a["isAnomaly"]:
            h = bucket("stat", "统计异常检测", "anomaly",
                        "critical" if a["sigmaScore"] > 4 else "high")
            h["count"] += 1
            h["windows"].append(a["windowIndex"])

    return list(hits.values())


def caliber_signature(rules: List[dict]) -> dict:
    """口径快照：固定参数 + 启用规则集，跨轮对照时用于确认口径是否一致。"""
    return {
        "windowSize": WINDOW_SIZE,
        "sigmaThreshold": SIGMA_THRESHOLD,
        "iqrScoreThreshold": IQR_SCORE_THRESHOLD,
        "rules": sorted(
            f"{r.get('id', r.get('name', '?'))}:{r.get('type', '?')}>{r.get('threshold', 0)}"
            for r in rules if isinstance(r, dict) and r.get("enabled", True)
        ),
    }


def compute_stats(logs: List[dict], rules: List[dict]) -> dict:
    windows = build_windows(logs)
    anomalies = score_windows(windows, logs)
    hits = rule_hits(logs, windows, rules, anomalies=anomalies)
    sig = [a["sigmaScore"] for a in anomalies]
    iqr = [a["iqrScore"] for a in anomalies]
    return {
        "windowCount": len(windows),
        "anomalyWindows": sum(1 for a in anomalies if a["isAnomaly"]),
        "avgSigmaScore": round(float(np.mean(sig)), 2) if sig else 0.0,
        "maxSigmaScore": round(float(np.max(sig)), 2) if sig else 0.0,
        "avgIqrScore": round(float(np.mean(iqr)), 2) if iqr else 0.0,
        "maxIqrScore": round(float(np.max(iqr)), 2) if iqr else 0.0,
        "hits": hits,
        "caliber": caliber_signature(rules),
    }


# ---------------------------------------------------------------------------
# 时间范围解析：同一批日志里存在多种时间格式，按常见格式逐种解析
# ---------------------------------------------------------------------------

_MONTHS = {m: i + 1 for i, m in enumerate(
    "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split())}


def parse_timestamp(value: Any) -> Optional[float]:
    """把日志 timestamp 字段解析为 unix 秒；无法识别的格式返回 None。"""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    s = str(value).strip()
    if not s:
        return None
    # 纯数字（custom 格式）
    if re.fullmatch(r"\d+(\.\d+)?", s):
        try:
            return float(s)
        except ValueError:
            return None
    try:
        # json_app ISO，如 2024-05-12T03:04:05.123Z
        if "T" in s:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
            return dt.timestamp()
    except ValueError:
        pass
    try:
        # nginx，如 12/May/2024:03:04:05 +0000
        m = re.match(r"(\d{1,2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})", s)
        if m:
            day, mon, year, hh, mm, ss = m.groups()
            return datetime(int(year), _MONTHS[mon], int(day),
                            int(hh), int(mm), int(ss)).timestamp()
    except (ValueError, KeyError):
        pass
    try:
        # apache，如 Tue May 12 03:04:05 2024
        m = re.search(r"([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\d{4})", s)
        if m:
            mon, day, hh, mm, ss, year = m.groups()
            return datetime(int(year), _MONTHS[mon], int(day),
                            int(hh), int(mm), int(ss)).timestamp()
    except (ValueError, KeyError):
        pass
    return None


def _in_scope(log: dict, sources: set, start: Optional[float], end: Optional[float]) -> bool:
    if sources and log.get("source") not in sources:
        return False
    if start is not None or end is not None:
        ts = parse_timestamp(log.get("timestamp"))
        if ts is None:
            return False
        if start is not None and ts < start:
            return False
        if end is not None and ts > end:
            return False
    return True


def _scope_description(sources: set, start: Optional[float], end: Optional[float]) -> str:
    parts = []
    parts.append("来源=" + (",".join(sorted(sources)) if sources else "全部"))
    if start is not None or end is not None:
        parts.append(f"时间={_fmt_ts(start)} ~ {_fmt_ts(end)}")
    return "，".join(parts)


def _fmt_ts(ts: Optional[float]) -> str:
    if ts is None:
        return "不限"
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))


def analyze_logs(logs_data, rules, query):
    logs = logs_data
    n = len(logs)

    # Time windows (1min each for demonstration)
    windows = build_windows(logs)
    anomalies = score_windows(windows, logs)

    # Alert rules（保持原有告警明细与口径，图表直接消费 windows/anomalies）
    alerts = []
    for i, rule in enumerate(rules):
        rule = rule if isinstance(rule, dict) else {}
        for w in windows:
            if rule.get("type") == "level" and w["levels"].get("ERROR", 0) > rule.get("threshold", 5):
                alerts.append({
                    "id": len(alerts) + 1, "ruleName": rule.get("name", "高频ERROR"),
                    "severity": "high", "message": f"窗口{w['start']}内ERROR日志{w['levels']['ERROR']}条超过阈值{rule.get('threshold',5)}",
                    "timestamp": time.strftime("%H:%M:%S")
                })
            if rule.get("type") == "count" and w["count"] > rule.get("threshold", 200):
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
