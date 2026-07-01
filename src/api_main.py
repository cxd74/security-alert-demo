from fastapi import FastAPI
from pydantic import BaseModel
from typing import List


app = FastAPI(title="Security Alert Analysis API")


class Alert(BaseModel):
    device: str
    event_type: str
    src_ip: str
    dst_ip: str
    dst_port: int
    severity: str
    url: str | None = None


class AnalyzeResult(BaseModel):
    summary: str
    risk_level: str
    score: int
    affected_asset: str
    reasons: List[str]
    recommended_actions: List[str]
    need_human_review: bool


@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "message": "FastAPI 服务运行正常"
    }


@app.post("/analyze", response_model=AnalyzeResult)
def analyze_alert(alert: Alert):
    score = 0
    reasons = []
    actions = []

    if alert.severity == "high":
        score += 40
        reasons.append("告警原始等级为 high")

    if alert.event_type in ["SQL Injection", "Brute Force", "Command Execution"]:
        score += 30
        reasons.append("告警类型属于常见高风险攻击")

    if alert.dst_port in [22, 443, 3306, 3389]:
        score += 20
        reasons.append("目标端口属于重点关注端口")

    if alert.device == "WAF":
        reasons.append("告警来源为 WAF，可能与 Web 攻击有关")

    if score >= 80:
        risk_level = "high"
    elif score >= 50:
        risk_level = "medium"
    else:
        risk_level = "low"

    if alert.event_type == "SQL Injection":
        actions.append("检查目标接口是否存在 SQL 注入漏洞")
        actions.append("确认 WAF 是否已拦截该请求")
        actions.append("排查同一源 IP 是否存在连续攻击行为")
    elif alert.event_type == "Brute Force":
        actions.append("检查登录失败日志")
        actions.append("必要时封禁来源 IP")
        actions.append("确认目标账号是否存在异常登录")
    else:
        actions.append("检查相关系统日志")
        actions.append("确认告警是否为误报")
        actions.append("根据资产重要性决定是否升级处置")

    return {
        "summary": f"{alert.device} 发现 {alert.event_type} 告警，来源 IP 为 {alert.src_ip}，目标为 {alert.dst_ip}:{alert.dst_port}",
        "risk_level": risk_level,
        "score": score,
        "affected_asset": f"{alert.dst_ip}:{alert.dst_port}",
        "reasons": reasons,
        "recommended_actions": actions,
        "need_human_review": risk_level == "high"
    }