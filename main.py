import json

with open("alert.json","r",encoding="utf-8") as f :
    alert = json.load(f)

event_type = alert["event_type"]
src_ip = alert["src_ip"]
dst_ip = alert["dst_ip"]
dst_port = alert["dst_port"]
severity = alert["severity"]

if dst_port == 3306:
    service = "MySQL 数据库"
elif dst_port == 443:
    service = "HTTPS 网站"
elif dst_port == 22:
    service = "SSH 远程登陆"
else:
    service = "未知服务"


print("=== 安全告警分析结果 ===")

if severity == "high":
    print("风险等级：高危")
else:
    print("风险等级：普通")

print(f"攻击类型：{event_type}")
print(f"攻击来源：{src_ip}")
print(f"攻击目标：{dst_ip}")
print(f"目标端口：{dst_port}")
print(f"目标服务：{service}")   