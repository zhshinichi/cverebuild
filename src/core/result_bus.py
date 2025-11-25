import os
import csv
import json
import subprocess
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional


class ResultBus:
    """统一结果持久化和工件同步服务，支持事件发布和分步日志记录。"""

    def __init__(
        self,
        cve_id: str,
        shared_root: str = None,
        project_root: Optional[str] = None,
        local_shared_dir: Optional[str] = None,
    ) -> None:
        self.cve_id = cve_id
        
        # 自动检测 shared 目录
        if shared_root is None:
            # 优先使用挂载目录
            mounted_shared = "/workspaces/submission/src/shared"
            if os.path.exists(os.path.dirname(mounted_shared)):
                shared_root = mounted_shared
            else:
                shared_root = "/shared"
        
        self.shared_root = shared_root
        self.project_root = project_root or os.path.dirname(os.path.dirname(__file__))

        default_local = os.path.join(self.project_root, "src", "shared")
        self.local_shared_dir = local_shared_dir or os.environ.get("LOCAL_SHARED_DIR", default_local)

        self.cve_dir = os.path.join(self.shared_root, self.cve_id)
        os.makedirs(self.cve_dir, exist_ok=True)

        # 事件流和订阅者（用于可观测性）
        self._event_log: List[Dict[str, Any]] = []
        self._subscribers: List[Callable[[Dict[str, Any]], None]] = []

    # ------------------------------------------------------------------
    # Result recording
    # ------------------------------------------------------------------
    def record_run(self, result: Dict[str, object]) -> None:
        """Append a normalized row to shared/results.csv."""
        os.makedirs(self.shared_root, exist_ok=True)
        csv_path = os.path.join(self.shared_root, "results.csv")

        header = ["CVE", "SUCCESS", "REASON", "COST", "TIME", "MODEL"]
        if not os.path.isfile(csv_path):
            with open(csv_path, "w", newline="", encoding="utf-8") as file:
                csv.writer(file).writerow(header)

        normalized = self._normalize_result(result)
        with open(csv_path, "a", newline="", encoding="utf-8") as file:
            csv.writer(file).writerow([
                self.cve_id,
                normalized["success"],
                normalized["reason"],
                normalized["cost"],
                normalized["time"],
                normalized["model"],
            ])

    def _normalize_result(self, result: Dict[str, object]) -> Dict[str, object]:
        return {
            "success": result.get("success", "False"),
            "reason": result.get("reason", result.get("info_file", "N/A")),
            "cost": result.get("cost", 0),
            "time": result.get("time", 0),
            "model": result.get("model", os.environ.get("MODEL", "unknown")),
        }

    # ------------------------------------------------------------------
    # 事件发布与订阅（可观测性）
    # ------------------------------------------------------------------
    def publish_event(self, event_type: str, step_id: Optional[str] = None, data: Optional[Dict[str, Any]] = None) -> None:
        """发布执行事件，记录到日志并通知订阅者。"""
        event = {
            "timestamp": datetime.now().isoformat(),
            "cve_id": self.cve_id,
            "event_type": event_type,
            "step_id": step_id,
            "data": data or {},
        }
        self._event_log.append(event)

        # 持久化到事件日志文件
        event_log_path = os.path.join(self.cve_dir, "events.jsonl")
        with open(event_log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")

        # 通知订阅者
        for subscriber in self._subscribers:
            try:
                subscriber(event)
            except Exception as exc:
                print(f"⚠️  订阅者执行失败: {exc}")

    def subscribe(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """注册事件订阅者。"""
        self._subscribers.append(callback)

    def get_event_log(self) -> List[Dict[str, Any]]:
        """获取当前会话的事件日志。"""
        return list(self._event_log)

    # ------------------------------------------------------------------
    # 产物与日志存储
    # ------------------------------------------------------------------
    def store_artifact(self, step_id: str, artifact_name: str, content: Any, artifact_type: str = "text") -> str:
        """存储步骤产物到 CVE 目录，返回文件路径。"""
        artifacts_dir = os.path.join(self.cve_dir, "artifacts", step_id)
        os.makedirs(artifacts_dir, exist_ok=True)

        if artifact_type == "json":
            file_path = os.path.join(artifacts_dir, f"{artifact_name}.json")
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(content, f, indent=2, ensure_ascii=False)
        elif artifact_type == "binary":
            file_path = os.path.join(artifacts_dir, artifact_name)
            with open(file_path, "wb") as f:
                f.write(content)
        else:  # text
            file_path = os.path.join(artifacts_dir, f"{artifact_name}.txt")
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(str(content))

        self.publish_event("artifact_stored", step_id=step_id, data={"artifact": artifact_name, "path": file_path})
        return file_path

    def load_artifact(self, step_id: str, artifact_name: str, artifact_type: str = "text") -> Any:
        """从 CVE 目录加载步骤产物。"""
        artifacts_dir = os.path.join(self.cve_dir, "artifacts", step_id)
        if artifact_type == "json":
            file_path = os.path.join(artifacts_dir, f"{artifact_name}.json")
            with open(file_path, "r", encoding="utf-8") as f:
                return json.load(f)
        elif artifact_type == "binary":
            file_path = os.path.join(artifacts_dir, artifact_name)
            with open(file_path, "rb") as f:
                return f.read()
        else:
            file_path = os.path.join(artifacts_dir, f"{artifact_name}.txt")
            with open(file_path, "r", encoding="utf-8") as f:
                return f.read()

    # ------------------------------------------------------------------
    # Artifact syncing
    # ------------------------------------------------------------------
    def sync_to_local(self) -> bool:
        """Copy /shared artifacts from container to the mounted local path."""
        if not self.local_shared_dir:
            print("⚠️  LOCAL_SHARED_DIR 未设置，跳过同步。")
            return False

        container_name = os.environ.get("TARGET_DOCKER_CONTAINER") or self._detect_container_name()
        if not container_name:
            print("⚠️  Unable to determine container name, skipping file sync.")
            return False

        os.makedirs(self.local_shared_dir, exist_ok=True)
        print(f"\n{'='*60}")
        print(f"📦 Copying files from container '{container_name}'...")
        print(f"   Source: {container_name}:{self.shared_root}/")
        print(f"   Target: {self.local_shared_dir}")

        copy_result = subprocess.run(
            ["docker", "cp", f"{container_name}:{self.shared_root}/.", self.local_shared_dir],
            capture_output=True,
            text=True,
        )

        if copy_result.returncode == 0:
            print(f"✅ Successfully copied files to {self.local_shared_dir}")
            if copy_result.stdout:
                print(copy_result.stdout)
            return True

        print(f"⚠️  Failed to copy files: {copy_result.stderr}")
        return False

    def _detect_container_name(self) -> Optional[str]:
        try:
            result = subprocess.run(
                ["docker", "ps", "--format", "{{.Names}}"],
                capture_output=True,
                text=True,
                check=True,
            )
            containers = [name for name in result.stdout.strip().split("\n") if name]
            return containers[0] if containers else None
        except subprocess.CalledProcessError as exc:
            print(f"⚠️  Error executing docker ps: {exc}")
            return None
        except FileNotFoundError:
            print("⚠️  Docker command not available inside container.")
            return None
