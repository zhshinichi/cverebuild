#!/usr/bin/env python3
"""测试 CVE 分类器"""
import json
import sys
sys.path.insert(0, ".")

from planner.llm_classifier import LLMVulnerabilityClassifier, LLMClassifierConfig

with open("/workspaces/submission/src/data/simple_web_cves_20.json") as f:
    data = json.load(f)

cve_id = sys.argv[1] if len(sys.argv) > 1 else "CVE-2025-27719"
cve_entry = data.get(cve_id, {})
if not cve_entry:
    print(f"ERROR: CVE {cve_id} not found")
    sys.exit(1)

print(f"Testing classification for {cve_id}...")
print(f"Description: {cve_entry.get('description', '')[:200]}...")

config = LLMClassifierConfig(use_llm=True, fallback_to_rules=True)
classifier = LLMVulnerabilityClassifier(config)
decision = classifier.classify(cve_id, cve_entry)

print(f"\nResult:")
print(f"  Profile: {decision.profile}")
print(f"  Confidence: {decision.confidence}")
print(f"  Needs browser: {decision.resource_hints.get('needs_browser', False)}")
