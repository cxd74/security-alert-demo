import json
import os
from openai import OpenAI


def load_json(file_path):
    """读取 JSON 文件。"""
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


def calc_rule_score(alert, asset):
    """用简单规则给告警打一个基础分。"""
    score = 0
    reasons = []

    if alert.get("severity") == "high":
        score += 40
        reasons.append("告警原始等级为 high")

    if alert.get("event_type") in ["SQL Injection", "Brute Force", "Command Execution"]:
        score += 30
        reasons.append("告警类型属于常见高风险攻击")

    if alert.get("dst_port") in [22, 3306, 3389, 443]:
        score += 10
        reasons.append("目标端口属于重点关注端口")

    if asset.get("importance") == "high":
        score += 15
        reasons.append("目标资产重要性为 high")

    if asset.get("internet_exposed") is True:
        score += 5
        reasons.append("目标资产暴露在公网")

    if score >= 80:
        level = "high"
    elif score >= 50:
        level = "medium"
    else:
        level = "low"

    return {
        "score": score,
        "rule_risk_level": level,
        "rule_reasons": reasons
    }


def analyze_with_deepseek(alert, asset, rule_result):
    """调用 DeepSeek，让模型综合分析。"""

    api_key = os.getenv("DEEPSEEK_API_KEY")
    if not api_key:
        raise RuntimeError("没有检测到 DEEPSEEK_API_KEY，请先在终端设置 API Key。")

    client = OpenAI(
        api_key=api_key,
        base_url="https://api.deepseek.com"
    )

    system_prompt = """
你是一名安全运营分析助手。
你只能根据用户提供的告警数据、资产数据、规则评分进行分析。
不要编造攻击已成功、攻击者身份、地理位置、资产负责人真实姓名等没有证据的信息。
请输出严格 JSON，不要输出 Markdown，不要输出多余解释。
"""

    user_prompt = f"""
请分析下面这条安全告警，并结合资产信息判断风险。

告警数据 json：
{json.dumps(alert, ensure_ascii=False, indent=2)}

资产数据 json：
{json.dumps(asset, ensure_ascii=False, indent=2)}

规则评分 json：
{json.dumps(rule_result, ensure_ascii=False, indent=2)}

请输出如下 JSON 格式：
{{
  "summary": "一句话概括告警",
  "final_risk_level": "low/medium/high",
  "risk_reason": ["原因1", "原因2"],
  "affected_asset": "资产名称和 IP:端口",
  "possible_impact": ["可能影响1", "可能影响2"],
  "recommended_actions": ["建议动作1", "建议动作2", "建议动作3"],
  "need_human_review": true,
  "evidence": ["证据1", "证据2"]
}}
"""

    response = client.chat.completions.create(
        model="deepseek-v4-flash",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        response_format={"type": "json_object"},
        max_tokens=1200
    )

    result_text = response.choices[0].message.content
    return json.loads(result_text)


def main():
    alert = load_json("alert.json")
    assets = load_json("assets.json")

    dst_ip = alert.get("dst_ip")
    asset = assets.get(dst_ip, {
        "asset_name": "未知资产",
        "asset_type": "未知类型",
        "importance": "unknown",
        "owner": "unknown",
        "internet_exposed": "unknown"
    })

    rule_result = calc_rule_score(alert, asset)

    print("=== 本地规则评分 ===")
    print(json.dumps(rule_result, ensure_ascii=False, indent=2))

    print("\n=== DeepSeek 综合分析 ===")
    result = analyze_with_deepseek(alert, asset, rule_result)
    print(json.dumps(result, ensure_ascii=False, indent=2))

    with open("analysis_result.json", "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    print("\n分析结果已保存到 analysis_result.json")


if __name__ == "__main__":
    main()