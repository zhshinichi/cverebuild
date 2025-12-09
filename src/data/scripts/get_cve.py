import json
from pathlib import Path
from openai import OpenAI

# === OpenAI (>=1.0) 客户端 ===
client = OpenAI(
    api_key="sk-ziyWDSRgl3ymsBm3MWN8C5fPJwrzxaakqdsCYsWIB0dTqHmg",
    base_url="https://api.openai-hub.com/v1"
)

MODEL = "gpt-4o-mini"

# 计算路径
CURRENT_DIR = Path(__file__).resolve().parent    # src/data/scripts
DATA_DIR = CURRENT_DIR.parent                    # src/data
ROOT = DATA_DIR / "cvelist"                      # src/data/cvelist

# 只检索 2025 年
TARGET_YEAR = "2025"
YEAR_DIR = ROOT / TARGET_YEAR

# 输出：只保留 true 的漏洞
OUTPUT_DIR = DATA_DIR / "large_scale"
OUTPUT_JSON = OUTPUT_DIR / "webcves.json"        # 仅保存 true 的条目
OUTPUT_ID_LIST = OUTPUT_DIR / "webcve_ids.txt"   # 仅保存 true 的 CVE ID

# 命中上限：命中 true 达到 300 即停止（不是总扫描数）
TARGET_TRUE_COUNT = 300


def is_target_vuln(cve_json):
    """
    使用 GPT-4o-mini 判断是否为 Web / 浏览器 / 前端 漏洞（排除硬件）
    """
    prompt = f"""
你是一名漏洞分类专家。请根据下面 CVE Record 判断漏洞类型，并输出 JSON。

分类要求：
1. 属于以下任一类型 → is_target=true：
    - Web 漏洞（Web Application）
    - 网页漏洞（HTML/DOM/JS/CSS/front-end）
    - 浏览器相关漏洞（Chrome/Firefox/Edge/Safari/WebKit/V8）

2. 必须排除：
    - 硬件漏洞（CPU/SoC/BIOS/固件）
    - 纯本地内存破坏（与 Web/Browser 毫无关联）
    - PyTorch、OpenSSL 等本地执行漏洞

CVE JSON：
{json.dumps(cve_json, ensure_ascii=False)}

请仅输出以下 JSON：
{{
    "is_target": true/false,
    "category": "web" | "browser" | "frontend" | "other",
    "reason": "简短原因"
}}
"""
    rsp = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "user", "content": prompt}],
        temperature=0
    )
    content = rsp.choices[0].message.content
    try:
        return json.loads(content)
    except Exception:
        return {"is_target": False, "category": "other", "reason": "模型输出解析失败"}


def scan_all():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    results_true_only = []   # 只保存 is_target=true 的完整条目
    filtered_ids = []        # 只保存 is_target=true 的 CVE ID
    scanned = 0
    hits = 0

    print(f"扫描目录: {YEAR_DIR}")

    if not YEAR_DIR.exists():
        raise FileNotFoundError(f"未找到 2025 年目录: {YEAR_DIR}")

    # 只遍历 2025/* 目录
    for prefix in sorted(YEAR_DIR.iterdir()):
        if not prefix.is_dir():
            continue

        for jf in sorted(prefix.glob("*.json")):
            # 若已达命中上限，则停止
            if hits >= TARGET_TRUE_COUNT:
                print(f"\n已命中 {TARGET_TRUE_COUNT} 个目标漏洞，停止扫描。\n")
                break

            with open(jf, "r", encoding="utf-8") as f:
                cve_json = json.load(f)

            res = is_target_vuln(cve_json)
            scanned += 1

            cve_id = cve_json.get("cveMetadata", {}).get("cveId", "UNKNOWN")

            if res.get("is_target"):
                hits += 1
                # 只保存命中条目
                results_true_only.append({
                    "cve": cve_id,
                    "file": str(jf),
                    "category": res.get("category"),
                    "reason": res.get("reason")
                })
                filtered_ids.append(cve_id)
                print(f"[TRUE]  {cve_id} → {res.get('category')} | {res.get('reason')}")
            else:
                print(f"[FALSE] {cve_id} → {res.get('category')} | {res.get('reason')}")

        if hits >= TARGET_TRUE_COUNT:
            break

    # === 仅保存 true 的结果 ===
    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(results_true_only, f, ensure_ascii=False, indent=2)

    with open(OUTPUT_ID_LIST, "w", encoding="utf-8") as f:
        for cid in filtered_ids:
            f.write(cid + "\n")

    print(f"\n扫描结束：已扫描 {scanned} 个文件，命中 {hits} 个目标漏洞。")
    print(f"已写入 True 条目：{OUTPUT_JSON}")
    print(f"已写入 True 的 CVE ID：{OUTPUT_ID_LIST}\n")


if __name__ == "__main__":
    scan_all()
