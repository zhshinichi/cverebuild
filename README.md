# CVE-Genie

An LLM-based multi-agent framework for end-to-end reproduction of CVEs, now powered by a classifier + DAG execution engine with a legacy pipeline kept for compatibility.

See end-to-end reproduction logs and outputs of CVE-2024-4340 [here](src/results/CVE-2024-4340) and Figure 2 in the paper.

## Architecture Overview
- Classifier selects a profile and required capabilities, then PlanBuilder emits `plan.json`.
- DAG Executor runs the plan with capability adapters and records `events.jsonl` plus artifacts under `shared/<CVE>/`.
- Profiles live in `profiles/` (native-local, web-basic, cloud-config, freestyle); `--profile auto` enables automatic classification.
- Legacy linear workflow remains available (default without `--dag`).

## How to Run
### a) In DevContainer
> Easy to set up but it might not be compatible for CVEs that require running multiple services, as it can crash the DevContainer.
1. Clone this repository and `cd` into it.
2. Start the `devcontainer` in VS Code.
3. `cd` into the `src` directory.
4. Create a `.env` file in `src`, and add `OPENAI_API_KEY`.
5. Run one of the following:

**DAG mode (recommended for Web CVEs)**
```
ENV_PATH=.env MODEL=example_run python3 main.py \
  --cve CVE-2024-4340 \
  --json data/example/data.json \
  --dag
```

**Legacy mode (original pipeline)**
```
ENV_PATH=.env MODEL=example_run python3 main.py \
  --cve CVE-2024-4340 \
  --json data/example/data.json \
  --run-type build,exploit,verify
```

6. Results, logs, and artifacts are stored under `shared/<CVE>/` (or `SHARED_DIR` if set).

### b) In a Virtual Machine
Read the [VM Library Documentation](vm_library/README.md) on how to run it in a VM.

## Generate Fix Recommendations
Run the FixAdvisor workflow to obtain patch guidance without executing the full reproduction pipeline (legacy mode only):

```
ENV_PATH=.env MODEL=example_run python3 src/main.py \
  --cve CVE-2024-4340 \
  --json src/data/example/data.json \
  --run-type fix
```

The agent will summarize existing CWEs, known patches, and prior reproduction status to produce actionable remediation steps under `shared/<CVE>/`.

## Web Vulnerability Support
For browser-based vulnerabilities (CSRF, XSS, SSRF, etc.), use the DAG pipeline with the `web-basic` profile and a browser engine:

```
ENV_PATH=.env MODEL=example_run python3 src/main.py \
  --cve CVE-2024-2288 \
  --json src/data/example/data.json \
  --dag \
  --profile web-basic \
  --browser-engine playwright \
  --target-url http://localhost:9600
```

- `--browser-engine` supports `selenium` (default) or `playwright`.
- `--target-url` points to a pre-deployed target; otherwise the DAG may attempt to deploy using defaults.
- `WEB_DRIVER_TARGET_URL` can set a global default target URL.

**Option 1: Selenium (Default)**
```bash
pip install selenium
apt-get install -y chromium-chromedriver
```

**Option 2: Playwright (Recommended for advanced scenarios)**
```bash
pip install playwright
playwright install chromium
```

See `docs/planner/usage_guide.md` for architecture details and `examples/playwright_web_exploit.py` for usage examples.
