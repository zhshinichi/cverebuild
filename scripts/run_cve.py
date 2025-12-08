#!/usr/bin/env python3
"""
Run a CVE reproduction end-to-end.
Auto-classifies the CVE and chooses DAG (new pipeline) or legacy flow.

Examples:
    python scripts/run_cve.py CVE-2025-1752
    python scripts/run_cve.py CVE-2024-2928 --mode dag --browser playwright
    python scripts/run_cve.py CVE-2025-1752 --mode legacy
"""

import argparse
import os
import subprocess
import sys
from typing import Optional, Tuple

# Container settings
CONTAINER_NAME = "competent_dewdney"
CONTAINER_WORKSPACE = "/workspaces/submission"
DEFAULT_DATA_JSON = f"{CONTAINER_WORKSPACE}/src/data/large_scale/simple_web_cves_20.json"
#DEFAULT_DATA_JSON = f"{CONTAINER_WORKSPACE}/src/data/example/data.json"
MAIN_PY = f"{CONTAINER_WORKSPACE}/src/main.py"

# API settings (fallback to placeholder key if not provided)
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "sk-ziyWDSRgl3ymsBm3MWN8C5fPJwrzxaakqdsCYsWIB0dTqHmg")
OPENAI_API_BASE = os.environ.get("OPENAI_API_BASE", "https://api.openai-hub.com/v1")


def classify_cve(cve_id: str, data_json: str) -> Tuple[str, bool, str]:
    """Use the LLM classifier to pick a profile, browser need, and execution mode."""
    print(f"[INFO] Classifying {cve_id} ...")

    classify_cmd = [
        "docker",
        "exec",
        "-w",
        f"{CONTAINER_WORKSPACE}/src",
        "-e",
        f"PYTHONPATH={CONTAINER_WORKSPACE}/src/agentlib",
        "-e",
        f"OPENAI_API_KEY={OPENAI_API_KEY}",
        "-e",
        f"OPENAI_API_BASE={OPENAI_API_BASE}",
        CONTAINER_NAME,
        "python3",
        "-c",
        f'''
import json
import sys
sys.path.insert(0, ".")
from planner.llm_classifier import LLMVulnerabilityClassifier, LLMClassifierConfig

with open("{data_json}") as f:
    data = json.load(f)

cve_entry = data.get("{cve_id}", {{}})
if not cve_entry:
    print("ERROR:CVE not found in data.json")
    sys.exit(1)

config = LLMClassifierConfig(use_llm=True, fallback_to_rules=True)
classifier = LLMVulnerabilityClassifier(config)
decision = classifier.classify("{cve_id}", cve_entry)
needs_browser = decision.resource_hints.get("needs_browser", False)
print(f"{{decision.profile}},{{needs_browser}},{{decision.execution_mode}}")
''',
    ]

    try:
        result = subprocess.run(
            classify_cmd,
            capture_output=True,
            text=True,
            timeout=120,
            encoding="utf-8",
            errors="replace",
        )

        if result.returncode != 0:
            print(f"[WARN] Classify failed: {result.stderr}")
            return "native-local", False

        output_lines = result.stdout.strip().split("\n")
        profile: Optional[str] = None
        needs_browser = False

        for line in output_lines:
            line_stripped = line.strip()
            if line_stripped.startswith("Profile:"):
                profile = line_stripped.split(":", 1)[1].strip()
            elif "Needs browser:" in line_stripped:
                needs_browser = "true" in line_stripped.lower()
            elif "," in line_stripped and any(
                p in line_stripped.lower()
                for p in ["native-local", "web-basic", "freestyle", "cloud-config", "iot-firmware"]
            ):
                parts = line_stripped.split(",")
                profile = parts[0].strip()
                needs_browser = parts[1].strip().lower() == "true" if len(parts) > 1 else False

        if profile is None and output_lines:
            last_line = output_lines[-1].strip()
            if last_line.startswith("ERROR:"):
                print(f"[ERROR] {last_line}")
                sys.exit(1)
            parts = last_line.split(",")
            profile = parts[0].strip() if parts else "native-local"
            needs_browser = parts[1].strip().lower() == "true" if len(parts) > 1 else False

        execution_mode = parts[2].strip().lower() if len(parts) > 2 else None
        if execution_mode not in ("legacy", "dag", "freestyle"):
            execution_mode = "dag" if profile in ("web-basic", "cloud-config") else ("freestyle" if profile == "freestyle" else "legacy")
        return profile or "native-local", needs_browser, execution_mode

    except subprocess.TimeoutExpired:
        print("[WARN] Classify timeout, using default profile")
        return "native-local", False, "legacy"
    except Exception as exc:  # noqa: broad-except
        print(f"[WARN] Classify error: {exc}, using default profile")
        return "native-local", False, "legacy"


def run_cve(
    cve_id: str,
    mode: str = "auto",
    browser_engine: str = "playwright",
    data_json: str = DEFAULT_DATA_JSON,
    profile_override: Optional[str] = None,
    target_url: Optional[str] = None,
) -> int:
    """Run CVE reproduction."""

    if mode == "auto":
        profile, needs_browser, execution_mode = classify_cve(cve_id, data_json)
    else:
        profile, needs_browser, execution_mode = profile_override or "native-local", False, "dag" if profile_override in ("web-basic","cloud-config","freestyle") else "legacy"

    effective_profile = profile_override or profile

    if mode == "auto":
        if execution_mode == "freestyle" or effective_profile == "freestyle":
            print("[INFO] Detected freestyle -> DAG + FreestyleAgent")
            mode = "dag"
        elif execution_mode == "dag" or effective_profile in ("web-basic", "cloud-config") or needs_browser:
            print(f"[INFO] Detected {effective_profile} -> DAG pipeline")
            mode = "dag"
        elif execution_mode == "legacy":
            print(f"[INFO] Detected {effective_profile} -> legacy flow")
            mode = "legacy"
        else:
            print(f"[INFO] Detected {effective_profile} -> legacy flow (default)")
            mode = "legacy"
    elif mode == "dag":
        print(f"[INFO] Force DAG, profile={effective_profile}")
    else:
        print("[INFO] Force legacy flow")

    if mode == "dag":
        container_cmd = [
            "python3",
            MAIN_PY,
            "--cve",
            cve_id,
            "--json",
            data_json,
            "--dag",
            "--browser-engine",
            browser_engine,
            "--profile",
            effective_profile,
        ]
        if target_url:
            container_cmd += ["--target-url", target_url]
    else:
        container_cmd = [
            "python3",
            MAIN_PY,
            "--cve",
            cve_id,
            "--json",
            data_json,
            "--run-type",
            "build,exploit,verify",
        ]

    cmd = [
        "docker",
        "exec",
        "-w",
        f"{CONTAINER_WORKSPACE}/src",
        "-e",
        f"OPENAI_API_KEY={OPENAI_API_KEY}",
        "-e",
        f"OPENAI_API_BASE={OPENAI_API_BASE}",
        "-e",
        "MODEL=gpt-4o-mini",
        "-e",
        f"SHARED_DIR={CONTAINER_WORKSPACE}/src/shared",
        "-e",
        "PYTHONIOENCODING=utf-8",
        "-e",
        "PYTHONUNBUFFERED=1",
        "-e",
        "PYTHONWARNINGS=ignore",
        CONTAINER_NAME,
    ] + container_cmd

    print(f"\n[RUN] Start {cve_id}")
    print(f"[RUN] Mode: {mode}")
    print(f"[RUN] Command: {' '.join(container_cmd)}\n")
    print("=" * 60)

    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        encoding="utf-8",
        errors="replace",
    )

    for line in iter(process.stdout.readline, ""):
        print(line, end="")

    process.wait()

    print("=" * 60)
    if process.returncode == 0:
        print(f"[OK] {cve_id} completed")
    else:
        print(f"[FAIL] {cve_id} failed (exit code: {process.returncode})")

    return process.returncode


def main() -> None:
    parser = argparse.ArgumentParser(
        description="CVE reproduction helper - auto classify and choose pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
    python scripts/run_cve.py CVE-2025-1752
    python scripts/run_cve.py CVE-2024-2928 --mode dag
    python scripts/run_cve.py CVE-2025-1752 --mode legacy
        """,
    )

    parser.add_argument("cve_id", type=str, help="CVE ID (e.g., CVE-2025-1752)")
    parser.add_argument(
        "--mode",
        type=str,
        choices=["auto", "dag", "legacy"],
        default="auto",
        help="Execution mode (default: auto)",
    )
    parser.add_argument(
        "--browser",
        type=str,
        choices=["playwright", "selenium"],
        default="playwright",
        help="Browser engine for web-basic profile",
    )
    parser.add_argument(
        "--json",
        type=str,
        default=DEFAULT_DATA_JSON,
        help="Path to CVE data file",
    )
    parser.add_argument(
        "--profile",
        type=str,
        choices=["native-local", "web-basic", "freestyle", "cloud-config", "iot-firmware", "auto"],
        default=None,
        help="Force DAG profile (auto or empty to classify)",
    )
    parser.add_argument(
        "--target-url",
        type=str,
        default=None,
        help="Pre-deployed target URL (for web-basic)",
    )

    args = parser.parse_args()

    if not args.cve_id.upper().startswith("CVE-"):
        print("Error: CVE ID must start with 'CVE-'")
        sys.exit(1)

    cve_id = args.cve_id.upper()

    # ANSI colors
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RESET = "\033[0m"
    BOLD = "\033[1m"

    print(f"\n{CYAN}┏{'━'*58}┓{RESET}")
    print(f"{CYAN}┃{RESET}{BOLD}{YELLOW}{'CVE-Genie Reproduction Runner':^58}{RESET}{CYAN}┃{RESET}")
    print(f"{CYAN}┣{'━'*58}┫{RESET}")
    print(f"{CYAN}┃{RESET}  {BOLD}CVE ID :{RESET} {GREEN}{cve_id:<47}{RESET}{CYAN}┃{RESET}")
    print(f"{CYAN}┃{RESET}  {BOLD}Mode   :{RESET} {GREEN}{args.mode:<47}{RESET}{CYAN}┃{RESET}")
    print(f"{CYAN}┗{'━'*58}┛{RESET}\n")

    exit_code = run_cve(
        cve_id,
        mode=args.mode,
        browser_engine=args.browser,
        data_json=args.json,
        profile_override=None if args.profile in (None, "auto") else args.profile,
        target_url=args.target_url,
    )
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
