# Planner Migration Plan

This document tracks how we will transition from the legacy linear pipeline to the classifier + DAG architecture.

## Phase 1 – Foundations (current PR)
- Define planner package with `ClassifierDecision`, `ExecutionPlan`, and step schema helpers.
- Ship heuristic `VulnerabilityClassifier` and `PlanBuilder` that can emit a best-effort `plan.json` using existing agents.
- Introduce capability interfaces (`EnvironmentProvisioner`, `ExploitExecutor`, etc.) for future adapters.
- Extend planner spec with layered architecture snapshot so the team shares the same vocabulary.

## Phase 2 – Dual Execution Path
1. Update CLI flow:
   - Load CVE entry, call classifier, persist `plan.json` under `shared/<CVE>/`.
   - If `--legacy` flag is passed, continue using booleans; otherwise execute DAG.
2. Implement lightweight plan executor that walks `plan.steps`, instantiates current agents, and records outputs via ResultBus.
3. Build adapters that map plan capabilities to concrete agent constructors.

## Phase 3 – Environment Orchestrator & Verification Strategies
- Add `env/*.yaml` describing providers (Docker, VM, BrowserFarm) and let plan steps declare logical environments.
- Replace hard-coded validator with strategy registry (HTTP diff, regex, flag, hash).
- Integrate FixAdvisor as `FixPlanner` capability triggered by classifier signal or step success criteria.

## Phase 4 – Plugin Ecosystem
- Document how to register new capabilities via entry points or config files.
- Support advanced profiles (`iot-firmware`, `cloud-config`) that pull in additional plugins (FirmwareFlasher, CloudConfigAuditor, etc.).
- Emit telemetry from ResultBus to message queue / DB for multi-run analytics.

## Backward Compatibility
Throughout each phase:
- Maintain legacy path until DAG executor achieves feature parity.
- Provide migration flags and clear README instructions per release.
