"""环境编排器：管理不同类型的执行环境（Docker、浏览器、虚拟机等）。"""
from __future__ import annotations

import os
import subprocess
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional


class EnvironmentProvider(ABC):
    """环境提供者基类。"""

    @abstractmethod
    def provision(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """配置并启动环境，返回环境元数据（如容器 ID、浏览器会话等）。"""
        pass

    @abstractmethod
    def teardown(self, metadata: Dict[str, Any]) -> None:
        """清理环境资源。"""
        pass


class DockerEnvironmentProvider(EnvironmentProvider):
    """Docker 容器环境提供者（复用现有容器或启动新容器）。"""

    def provision(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Args:
            config: {
                "image": "ubuntu:20.04",  # 可选，如果需要新容器
                "container_name": "existing-container",  # 可选，复用现有容器
                "volumes": {...},  # 可选
                "ports": {...}  # 可选
            }
        """
        container_name = config.get("container_name")
        
        if container_name:
            # 复用现有容器
            result = subprocess.run(
                ["docker", "inspect", container_name],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                print(f"✅ 复用现有容器: {container_name}")
                return {"container_name": container_name, "reused": True}
            else:
                print(f"⚠️  容器 {container_name} 不存在，将创建新容器")

        # 创建新容器（暂不实现完整逻辑，MVP 阶段依赖现有容器）
        image = config.get("image", "ubuntu:20.04")
        print(f"⚠️  Docker 环境自动创建功能未完成，请手动启动容器")
        return {"container_name": None, "image": image, "reused": False}

    def teardown(self, metadata: Dict[str, Any]) -> None:
        """清理容器（如果不是复用的）。"""
        if not metadata.get("reused") and metadata.get("container_name"):
            subprocess.run(["docker", "rm", "-f", metadata["container_name"]])
            print(f"🧹 清理容器: {metadata['container_name']}")


class BrowserEnvironmentProvider(EnvironmentProvider):
    """浏览器环境提供者（支持 Selenium 和 Playwright）。"""

    def provision(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Args:
            config: {
                "engine": "selenium" 或 "playwright",  # 默认 selenium
                "browser": "chrome" / "chromium",
                "headless": true,
                "proxy": "http://localhost:8080",  # 可选
                "target_url": "http://localhost:9600"
            }
        """
        engine = config.get("engine", "selenium").lower()
        
        if engine == "selenium":
            return self._provision_selenium(config)
        elif engine == "playwright":
            return self._provision_playwright(config)
        else:
            raise ValueError(f"不支持的浏览器引擎: {engine}")

    def _provision_selenium(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """使用 Selenium WebDriver。"""
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options as ChromeOptions
        except ImportError:
            raise RuntimeError("❌ Selenium 未安装，请运行: pip install selenium")

        browser_type = config.get("browser", "chrome")
        headless = config.get("headless", True)
        proxy = config.get("proxy")
        target_url = config.get("target_url", "http://localhost:9600")

        if browser_type == "chrome":
            options = ChromeOptions()
            if headless:
                options.add_argument("--headless")
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")
            
            if proxy:
                options.add_argument(f"--proxy-server={proxy}")

            driver = webdriver.Chrome(options=options)
            print(f"🌐 启动 Selenium Chrome ({'无头模式' if headless else '可视模式'})")
        else:
            raise NotImplementedError(f"Selenium 暂不支持浏览器: {browser_type}")

        return {
            "engine": "selenium",
            "driver": driver,
            "browser": browser_type,
            "target_url": target_url,
        }

    def _provision_playwright(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """使用 Playwright（异步驱动，提供更强大的网络控制）。"""
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            raise RuntimeError(
                "❌ Playwright 未安装，请运行:\n"
                "  pip install playwright\n"
                "  playwright install chromium"
            )

        browser_type = config.get("browser", "chromium")
        headless = config.get("headless", True)
        proxy = config.get("proxy")
        target_url = config.get("target_url", "http://localhost:9600")

        playwright = sync_playwright().start()
        
        launch_options = {"headless": headless}
        if proxy:
            launch_options["proxy"] = {"server": proxy}

        if browser_type == "chromium":
            browser = playwright.chromium.launch(**launch_options)
        elif browser_type == "firefox":
            browser = playwright.firefox.launch(**launch_options)
        elif browser_type == "webkit":
            browser = playwright.webkit.launch(**launch_options)
        else:
            playwright.stop()
            raise NotImplementedError(f"Playwright 暂不支持浏览器: {browser_type}")

        context = browser.new_context()
        page = context.new_page()
        
        print(f"🎭 启动 Playwright {browser_type} ({'无头模式' if headless else '可视模式'})")

        return {
            "engine": "playwright",
            "playwright": playwright,
            "browser": browser,
            "context": context,
            "page": page,
            "browser_type": browser_type,
            "target_url": target_url,
        }

    def teardown(self, metadata: Dict[str, Any]) -> None:
        """关闭浏览器。"""
        engine = metadata.get("engine", "selenium")
        
        if engine == "selenium":
            driver = metadata.get("driver")
            if driver:
                driver.quit()
                print("🧹 关闭 Selenium 浏览器")
        
        elif engine == "playwright":
            page = metadata.get("page")
            context = metadata.get("context")
            browser = metadata.get("browser")
            playwright = metadata.get("playwright")
            
            if page:
                page.close()
            if context:
                context.close()
            if browser:
                browser.close()
            if playwright:
                playwright.stop()
            print("🧹 关闭 Playwright 浏览器")


class EnvironmentOrchestrator:
    """环境编排器，根据配置选择合适的环境提供者。"""

    def __init__(self):
        self.providers = {
            "docker": DockerEnvironmentProvider(),
            "browser": BrowserEnvironmentProvider(),
        }
        self.active_environments: Dict[str, Dict[str, Any]] = {}

    def provision_environment(self, env_name: str, env_type: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        配置环境并记录元数据。
        
        Args:
            env_name: 环境逻辑名（如 "builder", "target", "browser"）
            env_type: 环境类型（"docker", "browser"）
            config: 环境配置
        
        Returns:
            环境元数据
        """
        if env_type not in self.providers:
            raise ValueError(f"不支持的环境类型: {env_type}")

        print(f"\n🔧 配置环境: {env_name} (类型: {env_type})")
        provider = self.providers[env_type]
        metadata = provider.provision(config)
        
        self.active_environments[env_name] = {
            "type": env_type,
            "metadata": metadata,
            "provider": provider,
        }
        
        return metadata

    def get_environment(self, env_name: str) -> Optional[Dict[str, Any]]:
        """获取已配置环境的元数据。"""
        env = self.active_environments.get(env_name)
        return env["metadata"] if env else None

    def teardown_all(self):
        """清理所有已配置的环境。"""
        print("\n🧹 开始清理所有环境...")
        for env_name, env_info in self.active_environments.items():
            provider = env_info["provider"]
            metadata = env_info["metadata"]
            try:
                provider.teardown(metadata)
            except Exception as exc:
                print(f"⚠️  清理环境 {env_name} 失败: {exc}")
        
        self.active_environments.clear()
        print("✅ 环境清理完成")

    @classmethod
    def from_yaml(cls, yaml_path: str) -> EnvironmentOrchestrator:
        """从 YAML 配置文件加载环境编排器（未来扩展）。"""
        raise NotImplementedError("YAML 配置加载功能待实现")
