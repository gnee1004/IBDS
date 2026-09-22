import json
from zapv2 import ZAPv2

cfg = json.load(open("config/zap_config.json", encoding="utf-8-sig"))  # BOM 있을 수 있어서 utf-8-sig
zap = ZAPv2(
    proxies={"http": f"http://{cfg['host']}:{cfg['port']}", "https": f"http://{cfg['host']}:{cfg['port']}"},
    apikey=cfg["api_key"],
)

site = "192.168.55.201:8080"   # 본인 타겟의 host:port로 바꾸기
sessions = zap.httpsessions.sessions(site)
print("총 개수:", len(sessions))
for s in sessions:
    name, tokens = s["session"][0], s["session"][1]
    print(name, "->", tokens.get("PHPSESSID", {}).get("value"))

print("현재 활성 세션:", zap.httpsessions.active_session(site))