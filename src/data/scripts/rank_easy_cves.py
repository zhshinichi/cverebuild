#!/usr/bin/env python3
"""Rank CVEs in large_scale/data.json by ease of reproduction.

Heuristics (rough):
- Reward PoCs, curl commands, unauthenticated + low complexity descriptors.
- Penalize browser/CSRF/XSS/Windows-only requirements or high user interaction.

The goal is to quickly surface candidates that can likely be reproduced
without exhausting API budgets.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, List, Tuple

DATA_PATH = Path(__file__).resolve().parents[1] / "large_scale" / "data.json"

POS_KEYWORDS = {
    "path traversal": 12,
    "file inclusion": 12,
    "local file inclusion": 15,
    "directory traversal": 12,
    "command injection": 10,
    "remote code execution": 10,
    "rce": 8,
    "unauthenticated": 8,
    "curl ": 6,
    "python ": 4,
    "poc": 6,
    "proof of concept": 8,
    "demo": 3,
    "http": 3,
}

NEG_KEYWORDS = {
    "browser": -15,
    "csrf": -15,
    "xss": -15,
    "clickjacking": -10,
    "iframe": -5,
    "requires login": -8,
    "admin": -8,
    "windows": -7,
    "gui": -5,
}

CVSS_POSITIVE = [
    (re.compile(r"Privileges required\s+None", re.I), 8, "Privileges required: None"),
    (re.compile(r"User interaction\s+None", re.I), 8, "User interaction: None"),
    (re.compile(r"Attack complexity\s+Low", re.I), 5, "Attack complexity: Low"),
    (re.compile(r"Attack vector\s+Network", re.I), 5, "Attack vector: Network"),
]

CVSS_NEGATIVE = [
    (re.compile(r"User interaction\s+Required", re.I), -12, "User interaction: Required"),
    (re.compile(r"Privileges required\s+(High|Medium)", re.I), -8, "Privileges required: Elevated"),
]

BROWSER_CWE = {"CWE-352", "CWE-79", "CWE-601", "CWE-451"}


def load_data() -> Dict[str, dict]:
    with DATA_PATH.open("r", encoding="utf-8") as f:
        return json.load(f)


def normalize(text: str) -> str:
    return text.lower()


def compute_score(cve_id: str, entry: dict) -> Tuple[int, List[str]]:
    score = 0
    reasons: List[str] = []
    description = entry.get("description", "")
    sec_texts = "\n".join(sec.get("content", "") for sec in entry.get("sec_adv", []))
    blob = f"{description}\n{sec_texts}"
    blob_l = normalize(blob)

    if entry.get("sec_adv"):
        score += 10
        reasons.append("+10: 有安全公告提供背景")

    if any(sec.get("effective") for sec in entry.get("sec_adv", [])):
        score += 15
        reasons.append("+15: 公告被标记为有效/含 PoC")

    for kw, pts in POS_KEYWORDS.items():
        if kw in blob_l:
            score += pts
            reasons.append(f"+{pts}: 包含关键词 {kw}")

    for kw, pts in NEG_KEYWORDS.items():
        if kw in blob_l:
            score += pts
            reasons.append(f"{pts}: 包含关键词 {kw}")

    for regex, pts, label in CVSS_POSITIVE:
        if regex.search(blob):
            score += pts
            reasons.append(f"+{pts}: {label}")

    for regex, pts, label in CVSS_NEGATIVE:
        if regex.search(blob):
            score += pts
            reasons.append(f"{pts}: {label}")

    for cwe in entry.get("cwe", []):
        if cwe.get("id") in BROWSER_CWE:
            score -= 15
            reasons.append("-15: CWE 表示需要浏览器交互")

    return score, reasons


def main(top_n: int = 10) -> None:
    data = load_data()
    rankings: List[Tuple[str, int, List[str]]] = []
    for cve_id, entry in data.items():
        score, reasons = compute_score(cve_id, entry)
        rankings.append((cve_id, score, reasons))

    rankings.sort(key=lambda item: item[1], reverse=True)

    print(f"Top {top_n} easier-to-reproduce CVEs (heuristic):")
    for cve_id, score, reasons in rankings[:top_n]:
        print("-" * 60)
        print(f"{cve_id}: score {score}")
        entry = data[cve_id]
        print(f"  Software: {entry.get('sw_version', 'unknown')} | CWE: {[c.get('id') for c in entry.get('cwe', [])]}")
        desc = entry.get('description', '').split('\n')[0][:200]
        print(f"  Desc: {desc}...")
        print("  Reasons:")
        for reason in reasons[:6]:
            print(f"    - {reason}")
        if len(reasons) > 6:
            print("    - ...")


if __name__ == "__main__":
    main(top_n=15)
