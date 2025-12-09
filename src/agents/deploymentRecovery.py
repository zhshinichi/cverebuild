"""
DeploymentRecovery - 部署失败自动恢复系统

当环境部署失败时,尝试多种备选方案:
1. 切换PHP/Node.js版本
2. 使用Docker隔离环境
3. 降级依赖版本
4. 使用预编译二进制
"""

from typing import Dict, List, Tuple, Optional
import re


class DeploymentRecovery:
    """部署失败自动恢复"""
    
    # 常见错误模式 -> 恢复策略
    RECOVERY_STRATEGIES = {
        'php_version_mismatch': {
            'pattern': r'requires php ([\d\.]+)|php.*?version.*?([\d\.]+)',
            'action': 'use_docker_php',
            'priority': 1
        },
        'node_version_mismatch': {
            'pattern': r'requires node ([\d\.]+)|engine.*?node.*?([\d\.]+)',
            'action': 'use_nvm',
            'priority': 1
        },
        'composer_dependency_conflict': {
            'pattern': r'composer.*?conflict|dependency.*?conflict',
            'action': 'composer_update_with_platform_reqs',
            'priority': 2
        },
        'npm_dependency_conflict': {
            'pattern': r'npm.*?ERESOLVE|peer dep.*?conflict',
            'action': 'npm_legacy_peer_deps',
            'priority': 2
        },
        'missing_system_library': {
            'pattern': r'cannot find -l(\w+)|lib(\w+).*?not found',
            'action': 'install_system_deps',
            'priority': 3
        },
        'maven_pom_not_found': {
            'pattern': r'pom\.xml.*?not found|没有 POM|Non-readable POM',
            'action': 'search_maven_pom',
            'priority': 1
        },
        'working_directory_error': {
            'pattern': r'composer\.json.*?not found|package\.json.*?not found',
            'action': 'search_build_file',
            'priority': 1
        }
    }
    
    def __init__(self, deployment_strategy: Dict):
        self.ds = deployment_strategy
        self.repo_name = self._extract_repo_name(self.ds.get('repository_url', ''))
        self.attempted_recoveries = []
    
    def diagnose_failure(self, error_output: str, command: str) -> List[Dict]:
        """
        诊断失败原因并返回恢复策略列表
        
        返回: [{'strategy': 'use_docker_php', 'params': {...}, 'priority': 1}, ...]
        """
        strategies = []
        
        for error_type, config in self.RECOVERY_STRATEGIES.items():
            if re.search(config['pattern'], error_output, re.IGNORECASE):
                match = re.search(config['pattern'], error_output, re.IGNORECASE)
                
                strategy = {
                    'type': error_type,
                    'action': config['action'],
                    'priority': config['priority'],
                    'params': self._extract_params(error_type, match, error_output)
                }
                strategies.append(strategy)
        
        # 按优先级排序
        strategies.sort(key=lambda x: x['priority'])
        return strategies
    
    def generate_recovery_commands(self, strategy: Dict) -> List[str]:
        """根据恢复策略生成命令"""
        action = strategy['action']
        params = strategy['params']
        
        if action == 'use_docker_php':
            return self._generate_docker_php_commands(params)
        
        elif action == 'use_nvm':
            return self._generate_nvm_commands(params)
        
        elif action == 'composer_update_with_platform_reqs':
            return self._generate_composer_platform_commands()
        
        elif action == 'npm_legacy_peer_deps':
            return [
                f"cd {self.repo_name} && npm install --legacy-peer-deps",
                f"cd {self.repo_name} && npm start"
            ]
        
        elif action == 'install_system_deps':
            libs = params.get('missing_libs', [])
            install_cmds = [f"apt-get install -y lib{lib}-dev" for lib in libs]
            return install_cmds + [
                f"cd {self.repo_name} && composer install"  # 重试原命令
            ]
        
        elif action == 'search_maven_pom':
            return self._generate_maven_pom_search_commands()
        
        elif action == 'search_build_file':
            return self._generate_build_file_search_commands()
        
        return []
    
    def _generate_docker_php_commands(self, params: Dict) -> List[str]:
        """生成Docker PHP环境命令"""
        required_version = params.get('required_version', '7.4')
        working_dir = self.ds.get('working_directory', '')
        
        commands = []
        
        # 1. 创建专用容器
        container_name = f"cve_php_{required_version.replace('.', '_')}"
        commands.append(
            f"docker run -d --name {container_name} "
            f"-v $(pwd)/{self.repo_name}:/app "
            f"-w /app/{working_dir if working_dir else ''} "
            f"php:{required_version}-apache"
        )
        
        # 2. 安装composer
        commands.append(
            f"docker exec {container_name} bash -c '"
            f"curl -sS https://getcomposer.org/installer | php && "
            f"mv composer.phar /usr/local/bin/composer'"
        )
        
        # 3. 安装依赖
        commands.append(
            f"docker exec {container_name} composer install"
        )
        
        # 4. 启动服务
        commands.append(
            f"docker exec -d {container_name} apache2-foreground"
        )
        
        return commands
    
    def _generate_nvm_commands(self, params: Dict) -> List[str]:
        """生成Node.js版本切换命令"""
        required_version = params.get('required_version', '14')
        
        return [
            f"curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash",
            f"export NVM_DIR=\"$HOME/.nvm\" && source \"$NVM_DIR/nvm.sh\"",
            f"nvm install {required_version}",
            f"nvm use {required_version}",
            f"cd {self.repo_name} && npm install && npm start"
        ]
    
    def _generate_composer_platform_commands(self) -> List[str]:
        """生成忽略平台要求的composer命令"""
        working_dir = self.ds.get('working_directory', '')
        path = f"{self.repo_name}/{working_dir}" if working_dir else self.repo_name
        
        return [
            f"cd {path} && composer install --ignore-platform-reqs",
            f"cd {path} && composer update --ignore-platform-reqs"
        ]
    
    def _generate_build_file_search_commands(self) -> List[str]:
        """搜索构建文件并在正确目录执行"""
        return [
            f"find {self.repo_name} -name 'composer.json' -o -name 'package.json'",
            # 后续根据找到的路径动态生成cd命令
        ]
    
    def _generate_maven_pom_search_commands(self) -> List[str]:
        """生成 Maven pom.xml 搜索和修复命令"""
        return [
            f"find {self.repo_name} -name 'pom.xml' -type f",
            f"cd {self.repo_name} && find . -name 'pom.xml' -type f | head -1 | xargs dirname | xargs -I {{}} sh -c 'cd {{}} && pwd && mvn package -DskipTests'"
        ]
    
    def _extract_params(self, error_type: str, match, error_output: str) -> Dict:
        """从错误输出提取参数"""
        params = {}
        
        if error_type in ['php_version_mismatch', 'node_version_mismatch']:
            if match:
                # 提取版本号
                version = match.group(1) or match.group(2)
                params['required_version'] = version.split('-')[0]  # 7.1-7.4 -> 7.4
        
        elif error_type == 'missing_system_library':
            if match:
                lib_name = match.group(1)
                params['missing_libs'] = [lib_name]
        
        return params
    
    def _extract_repo_name(self, repo_url: str) -> str:
        if not repo_url:
            return ""
        return repo_url.rstrip('/').split('/')[-1].replace('.git', '')


# 集成到MidExecReflector的示例
class EnhancedMidExecReflector:
    """增强版中途反思器(集成自动恢复)"""
    
    def __init__(self, deployment_strategy: dict = None):
        self.deployment_strategy = deployment_strategy
        self.recovery = DeploymentRecovery(deployment_strategy) if deployment_strategy else None
    
    def _perform_reflection_with_recovery(self, failure_summary: dict) -> dict:
        """反思时尝试自动恢复"""
        if not self.recovery:
            return self._perform_standard_reflection(failure_summary)
        
        # 提取最后一次失败的输出
        last_error = failure_summary.get('last_error_output', '')
        last_command = failure_summary.get('last_command', '')
        
        # 诊断失败
        recovery_strategies = self.recovery.diagnose_failure(last_error, last_command)
        
        if recovery_strategies:
            print(f"[Recovery] 检测到 {len(recovery_strategies)} 个恢复策略")
            
            # 尝试第一个策略
            strategy = recovery_strategies[0]
            print(f"[Recovery] 尝试策略: {strategy['type']}")
            
            recovery_commands = self.recovery.generate_recovery_commands(strategy)
            
            return {
                'reflection_type': 'auto_recovery',
                'strategy': strategy['type'],
                'recovery_commands': recovery_commands,
                'explanation': f"检测到{strategy['type']},尝试自动恢复"
            }
        
        # 没有匹配的策略,使用标准反思
        return self._perform_standard_reflection(failure_summary)
