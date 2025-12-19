---
trigger: always_on
---

# CVEGenie – Project Operating Rules (Always On)

These are **project-level invariants** and must be treated as higher priority than conversational context.
If any other instruction conflicts with this file, **this file wins**.

---

## 1) Non-Negotiable Runtime Facts (DO NOT GUESS)

### Execution Environment
- This project **runs inside Docker** by default.
- Do **NOT** assume the code runs on the host OS unless explicitly stated.

### Container Identity
- Docker container name: `competent_dewdney`

### Volume Mount & Working Directory
- The project directory is mounted into the container.
- **Container project root (canonical):** `/workspaces/submission`
- All runtime paths, commands, and file references must default to **container paths**.

---

## 2) Terminology & Path Conventions (STRICT)

- “Project root” means: `/workspaces/submission`
- When you mention a file path, prefer:
  - **Container path** (default): `/workspaces/submission/...`
  - Host paths only if the user explicitly asks for host-side commands
- If the user provides a relative path (e.g., `src/main.py`), interpret it as:
  - `/workspaces/submission/src/main.py`

---

## 3) Command Generation Rules (DEFAULT TO DOCKER)

When proposing commands, assume one of these two states:

### State A (Preferred): User is already inside the container
- Default working directory:
  ```bash
  cd /workspaces/submission
