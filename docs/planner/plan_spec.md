# Planner & DAG Specification

This document defines the short‑term plan for introducing a classifier + planner pipeline that emits a machine-readable execution graph (`plan.json`). The goal is to decouple CVE workflows from the current linear chain in `main.py` and enable per-CVE customization.

## 1. Terminology

| Term | Description |
|------|-------------|
| **Profile** | High-level template describing a vulnerability class (e.g., `web-basic`, `native-local`, `cloud-config`). Profiles map to default step graphs. |
| **Step** | Smallest executable unit. Each step references a capability implementation (agent/tool) and consumes/produces typed artifacts. |
| **Artifact** | Named piece of data (structured JSON, file path, flag). Steps declare `inputs` and `outputs` referencing artifact names. |
| **Plan** | DAG describing steps, their capabilities, ordering, environment needs, and success conditions. Serialized as JSON to `plan.json`. |

## 2. Classifier Output

The classifier ingests:
- `data/<tier>/data.json` entry for the CVE
- CLI hints (e.g., `--profile web-basic` override)
- Historical metadata (past runs, repro success, etc.)

It returns:
```jsonc
{
  "cve_id": "CVE-2024-2928",
  "profile": "web-basic",
  "confidence": 0.82,
  "required_capabilities": [
    "InfoGenerator",
    "EnvironmentProvisioner",
    "ExploitExecutor",
    "HttpVerifier"
  ],
  "resource_hints": {
    "needs_browser": true,
    "needs_gpu": false,
    "services": ["mlflow"],
    "timeout": 3600
  }
}
```

## 3. plan.json Schema (MVP)

```jsonc
{
  "schema": "cvegenie/plan@v0",
  "cve_id": "<string>",
  "profile": "<string>",
  "artifacts": {
    "cve_info": {"type": "json"},
    "repo_state": {"type": "dir"},
    "exploit_log": {"type": "text"},
    "verification": {"type": "json"}
  },
  "steps": [
    {
      "id": "collect-info",
      "name": "Generate CVE summary",
      "capability": "InfoGenerator",
      "implementation": "CVEInfoGenerator",
      "inputs": ["cve_id", "cve_entry"],
      "outputs": ["cve_info"],
      "environment": "control",
      "retry": {"max": 1},
      "if": "!artifacts.cve_info"
    },
    {
      "id": "prepare-env",
      "name": "Prepare vulnerable environment",
      "capability": "EnvironmentProvisioner",
      "implementation": "RepoBuilder",
      "inputs": ["cve_info"],
      "outputs": ["repo_state"],
      "requires": ["collect-info"],
      "environment": "builder"
    },
    {
      "id": "exploit",
      "capability": "ExploitExecutor",
      "implementation": "Exploiter",
      "inputs": ["repo_state", "cve_info"],
      "outputs": ["exploit_log"],
      "requires": ["prepare-env"],
      "environment": "target"
    },
    {
      "id": "verify",
      "capability": "Verifier",
      "implementation": "CTFVerifier",
      "inputs": ["exploit_log"],
      "outputs": ["verification"],
      "requires": ["exploit"],
      "environment": "target",
      "success_condition": "verification.flag_found == true"
    }
  ]
}
```

### Required Fields
- `schema`: versioned identifier for tooling compatibility.
- `artifacts`: registry of artifact names and types (JSON, dir, text, binary, flag).
- `steps`: ordered array; orchestrator enforces DAG via `requires`.

### Optional Fields
- `environment`: logical name resolved by Environment Orchestrator (`control`, `builder`, `target`, `browser`).
- `if`: guard condition (Plan executor evaluates before scheduling step).
- `retry`: policy (max attempts, backoff).
- `success_condition`: expression run on step outputs.

## 4. Profiles (MVP)

| Profile | Description | Default Steps |
|---------|-------------|---------------|
| `native-local` | Current pipeline (binary/local exploit). | `collect-info → pre-req → repo → exploit → verify (CTF)` |
| `web-basic` | HTTP/Web driver exploit, no repo build. | `collect-info → env(web) → exploit-http → verify-http` |
| `cloud-config` | Config/API misuse; requires cloud credentials. | `collect-info → env(cloud) → exploit-api → verify-log` |

Profiles are YAML: `profiles/native-local.yaml`, etc., mapping capabilities to default implementations. Planner merges classifier result + profile to emit final plan.

## 5. Execution Contract

1. CLI loads/creates `plan.json` (cache under `shared/<CVE>/plan.json`).
2. Orchestrator reads plan, schedules steps respecting dependencies.
3. Each step is invoked via a capability adapter (simple Python callable for MVP).
4. Results emitted to ResultBus (artifact store + event log).

## 6. Next Steps

1. Implement `planner/__init__.py` with:
   - `classify(cve_entry) -> ProfileDecision`
   - `build_plan(decision, overrides) -> plan dict`
   - `save_plan(plan, path)`
2. Create default profile YAMLs.
3. Update `main.py` to:
   - Generate plan when missing
   - Iterate over `steps` instead of hard-coded booleans (initially map to existing agents)

This document will guide the upcoming refactor while remaining backward compatible (if `plan.json` missing, fall back to legacy linear pipeline).

## 7. Layered Architecture Snapshot

| Layer | Responsibilities | Current Status |
|-------|------------------|----------------|
| **Task Orchestration** | Classifier + DAG planner turn CVE metadata into graph of capability invocations. | `planner` package to host classifier + plan builder. |
| **Capability Interfaces** | Typed contracts such as `EnvironmentProvisioner`, `ExploitExecutor`, `Verifier`, `FixPlanner`; current agents implement these via adapters. | New `capabilities` module will declare protocols and light wrappers. |
| **Environment Orchestrator** | Resolves logical environments (`builder`, `browser`, `qemu`) into concrete providers (container, VM, remote lab) described via YAML. | MVP uses Docker devcontainer; future iteration slots in orchestrator service. |
| **Verification Strategy** | Chooses validators (HTTP diff, log regex, flag capture, hash) per classifier output; supports multiple simultaneous strategies. | Existing `Validator` covers flag capture; new strategy registry will extend coverage. |
| **Result & Sync Bus** | ResultBus remains authoritative sink for artifacts/logs and will expose per-step channels once DAG executor lands. | Current ResultBus handles CSV + shared folder sync. |
| **Fix / Regression Loop** | Treat FixAdvisor as a `FixPlanner` capability whose output can enqueue PatchApplier + RegressionTester nodes for future DAG runs. | Fix-only CLI mode exists; next step is wiring into DAG as optional tail stage. |

The layered view keeps the single-entry CLI but makes every stage replaceable via plugins and declarative profiles.
