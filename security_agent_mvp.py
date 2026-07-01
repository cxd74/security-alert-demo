import json
import os
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI
from openai import OpenAI
from pydantic import BaseModel


app = FastAPI(title="Security Agent MVP")


# 1. 模拟资产数据库
ASSETS = {
    "10.10.5.20": {
        "asset_name": "用户登录系统",
        "asset_type": "Web应用服务器",
        "importance": "high",
        "internet_exposed": True
    },
    "10.10.5.30": {
        "asset_name": "测试服务器",
        "asset_type": "Linux服务器",
        "importance": "low",
        "internet_exposed": False
    }
}


# 2. 输入数据模型：一条安全告警
class AlertInput(BaseModel):
    alert_id: str
    device: str
    event_type: str
    src_ip: str
    dst_ip: str
    dst_port: int
    severity: str
    url: Optional[str] = None
    time: Optional[str] = None


# 3. 输出数据模型：智能体研判结果
class AnalyzeOutput(BaseModel):
    verdict: str
    severity: str
    affected_asset: str
    evidence: List[str]
    recommended_actions: List[str]
    need_human_review: bool


def write_log(filename: str, data: dict):
    """把输入、输出、错误写入 logs 文件夹。"""
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)

    log_path = log_dir / filename

    record = {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "data": data
    }

    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def get_asset_context(dst_ip: str) -> dict:
    """根据目标 IP 查询模拟资产。"""
    return ASSETS.get(dst_ip, {
        "asset_name": "未知资产",
        "asset_type": "未知类型",
        "importance": "unknown",
        "internet_exposed": "unknown"
    })


def local_rule_judge(alert: AlertInput, asset: dict) -> dict:
    """本地规则初判：先不用模型，自己算一个基础风险分。"""
    score = 0
    evidence = []

    if alert.severity == "high":
        score += 40
        evidence.append("告警原始等级为 high")

    if alert.event_type in ["SQL Injection", "Brute Force", "Command Execution"]:
        score += 30
        evidence.append(f"告警类型为 {alert.event_type}，属于重点关注攻击类型")

    if alert.dst_port in [22, 443, 3306, 3389]:
        score += 15
        evidence.append(f"目标端口 {alert.dst_port} 属于重点关注端口")

    if asset.get("importance") == "high":
        score += 10
        evidence.append("目标资产重要性为 high")

    if asset.get("internet_exposed") is True:
        score += 5
        evidence.append("目标资产暴露在公网")

    if score >= 80:
        severity = "high"
    elif score >= 50:
        severity = "medium"
    else:
        severity = "low"

    return {
        "score": score,
        "severity": severity,
        "evidence": evidence
    }


def call_llm(alert: AlertInput, asset: dict, rule_result: dict) -> dict:
    """调用 DeepSeek，让模型给出最终分析。"""
    api_key = os.getenv("DEEPSEEK_API_KEY")
    if not api_key:
        raise RuntimeError("未检测到 DEEPSEEK_API_KEY，请先在终端设置 API Key。")

    client = OpenAI(
        api_key=api_key,
        base_url="https://api.deepseek.com"
    )

    prompt = f"""
你是一名安全运营分析助手。

请只根据下面提供的告警数据、资产数据、本地规则判断结果进行分析。
不要编造攻击已经成功、攻击者身份、地理位置等没有证据的信息。

告警数据：
{json.dumps(alert.model_dump(), ensure_ascii=False, indent=2)}

资产数据：
{json.dumps(asset, ensure_ascii=False, indent=2)}

本地规则判断：
{json.dumps(rule_result, ensure_ascii=False, indent=2)}

请严格输出 JSON，不要输出 Markdown，不要输出多余文字。
JSON 格式如下：
{{
  "verdict": "一句话研判结论",
  "severity": "low/medium/high",
  "affected_asset": "资产名称 IP:端口",
  "evidence": ["证据1", "证据2"],
  "recommended_actions": ["建议1", "建议2", "建议3"],
  "need_human_review": true
}}
"""

    response = client.chat.completions.create(
        model="deepseek-chat",
        messages=[
            {"role": "user", "content": prompt}
        ],
        response_format={"type": "json_object"},
        max_tokens=1000
    )

    result_text = response.choices[0].message.content
    return json.loads(result_text)


@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "message": "Security Agent MVP is running"
    }


@app.post("/analyze", response_model=AnalyzeOutput)
def analyze(alert: AlertInput):
    """安全告警分析接口。"""

    try:
        # 1. 保存输入日志
        write_log("input_log.jsonl", alert.model_dump())

        # 2. 查询资产上下文
        asset = get_asset_context(alert.dst_ip)

        # 3. 本地规则初判
        rule_result = local_rule_judge(alert, asset)

        # 4. 调用模型综合分析
        llm_result = call_llm(alert, asset, rule_result)

        # 5. 保存输出日志
        write_log("output_log.jsonl", llm_result)

        return llm_result

    except Exception as e:
        error_info = {
            "error": str(e),
            "alert": alert.model_dump()
        }

        write_log("error_log.jsonl", error_info)

        # 出错时返回一个保底结果，避免接口直接崩掉
        return {
            "verdict": "分析失败，需要人工检查错误日志",
            "severity": "unknown",
            "affected_asset": f"{alert.dst_ip}:{alert.dst_port}",
            "evidence": [f"错误信息：{str(e)}"],
            "recommended_actions": ["检查 API Key、网络连接和模型返回格式"],
            "need_human_review": True
        }