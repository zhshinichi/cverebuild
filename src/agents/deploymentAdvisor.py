"""
DeploymentAdvisor Agent - 部署策略顾问（实时观察者模式）

职责：
1. 实时监控FreestyleAgent的工具调用
2. 检测并自动修正部署命令错误（PHP版本、工作目录等）
3. 在错误发生前拦截并修正
4. 通用适用于所有CVE，不针对特定产品
"""

from typing import Dict, List, Optional, Tuple
import json
import re


class DeploymentAdvisor:
    """部署策略顾问 - 实时观察者模式"""
    
    def __init__(self, deployment_strategy: Dict):
        self.deployment_strategy = deployment_strategy
        self.repo_name = self._extract_repo_name(deployment_strategy.get('repository_url', ''))
        
        # 缓存关键信息以提高性能
        self.php_version = deployment_strategy.get('php_version')
        self.working_dir = deployment_strategy.get('working_directory')
        self.deployment_type = deployment_strategy.get('deployment_type')
        self.docker_compose_path = deployment_strategy.get('docker_compose_path')
        self.required_extensions = deployment_strategy.get('required_extensions', [])
        
        # 统计信息
        self.corrections_made = 0
        self.issues_detected = []
    
    def intercept_tool_call(self, tool_name: str, tool_args: Dict) -> Tuple[bool, Dict, str]:
        """
        拦截工具调用并检查/修正命令
        
        返回: (是否修正, 修正后的参数, 修正原因)
        """
        if tool_name == 'execute_linux_command':
            return self._intercept_command(tool_args)
        elif tool_name == 'run_docker_container':
            return self._intercept_docker_run(tool_args)
        
        return False, tool_args, ""
    
    def _intercept_command(self, args: Dict) -> Tuple[bool, Dict, str]:
        """拦截并修正Linux命令"""
        command = args.get('command', '')
        corrected = False
        reason = ""
        
        # 修正1: PHP版本不匹配时使用Docker容器
        if self.php_version and self.php_version.startswith('7'):
            if 'composer install' in command and 'docker' not in command:
                corrected_cmd, corrected, reason = self._fix_php_version_mismatch(command)
                if corrected:
                    args['command'] = corrected_cmd
                    return corrected, args, reason
        
        # 修正2: composer在错误目录运行
        if self.working_dir and 'composer' in command:
            corrected_cmd, corrected, reason = self._fix_working_directory(command)
            if corrected:
                args['command'] = corrected_cmd
                return corrected, args, reason
        
        # 修正3: docker-compose路径错误
        if self.deployment_type == 'docker-compose' and 'docker-compose' in command:
            corrected_cmd, corrected, reason = self._fix_docker_compose_path(command)
            if corrected:
                args['command'] = corrected_cmd
                return corrected, args, reason
        
        return False, args, ""
    
    def _fix_php_version_mismatch(self, command: str) -> Tuple[str, bool, str]:
        """修正PHP版本不匹配问题"""
        # 检查是否已经在使用PHP 7容器
        if 'php:7' in command or 'cve_php' in command:
            return command, False, ""
        
        # 如果正在尝试直接运行composer
        if 'composer install' in command:
            # 检查是否已经克隆了仓库
            if self.repo_name in command or 'cd ' in command:
                # 构建Docker命令
                if self.working_dir:
                    corrected = f"docker run --rm -v $(pwd)/{self.repo_name}:/app -w /app/{self.working_dir} composer:{self.php_version} install"
                else:
                    corrected = f"docker run --rm -v $(pwd)/{self.repo_name}:/app -w /app composer:{self.php_version} install"
                
                reason = f"Auto-corrected: Using PHP {self.php_version} Docker container (detected version mismatch)"
                self.corrections_made += 1
                self.issues_detected.append(f"PHP version mismatch: composer needs PHP {self.php_version}")
                
                print(f"[DeploymentAdvisor] 🔧 CORRECTING: PHP version mismatch")
                print(f"  Original: {command[:80]}...")
                print(f"  Corrected: {corrected[:80]}...")
                
                return corrected, True, reason
        
        return command, False, ""
    
    def _fix_working_directory(self, command: str) -> Tuple[str, bool, str]:
        """修正工作目录问题"""
        # 如果composer/npm等构建工具不在正确的子目录
        if self.working_dir:
            # 检查命令是否已经包含正确的工作目录
            if f"/{self.working_dir}" in command or f"cd {self.working_dir}" in command:
                return command, False, ""
            
            # 检测常见的错误模式
            if re.search(rf'cd {self.repo_name}\s*&&\s*composer', command):
                # 错误: cd CRMEB && composer install
                # 正确: cd CRMEB/crmeb && composer install
                corrected = command.replace(
                    f'cd {self.repo_name} &&',
                    f'cd {self.repo_name}/{self.working_dir} &&'
                )
                
                reason = f"Auto-corrected: Build tool must run in subdirectory {self.working_dir}/"
                self.corrections_made += 1
                self.issues_detected.append(f"Working directory: {self.working_dir}/")
                
                print(f"[DeploymentAdvisor] 🔧 CORRECTING: Working directory")
                print(f"  Original: {command[:80]}...")
                print(f"  Corrected: {corrected[:80]}...")
                
                return corrected, True, reason
        
        return command, False, ""
    
    def _fix_docker_compose_path(self, command: str) -> Tuple[str, bool, str]:
        """修正docker-compose路径问题"""
        if not self.docker_compose_path:
            return command, False, ""
        
        # 确保docker-compose在正确的子目录运行
        if self.repo_name and self.docker_compose_path not in command:
            if 'docker-compose up' in command:
                corrected = f"cd {self.repo_name}/{self.docker_compose_path} && docker-compose up -d"
                
                reason = f"Auto-corrected: docker-compose must run from {self.docker_compose_path}/"
                self.corrections_made += 1
                
                print(f"[DeploymentAdvisor] 🔧 CORRECTING: docker-compose path")
                print(f"  Corrected: {corrected}")
                
                return corrected, True, reason
        
        return command, False, ""
    
    def _intercept_docker_run(self, args: Dict) -> Tuple[bool, Dict, str]:
        """拦截并修正Docker运行命令"""
        # 确保使用正确的PHP版本镜像
        if self.php_version and args.get('image'):
            image = args['image']
            if 'php' in image and self.php_version not in image:
                args['image'] = f"php:{self.php_version}-apache"
                
                reason = f"Auto-corrected: Using PHP {self.php_version} image"
                self.corrections_made += 1
                
                print(f"[DeploymentAdvisor] 🔧 CORRECTING: PHP Docker image")
                print(f"  Corrected image: {args['image']}")
                
                return True, args, reason
        
        return False, args, ""
    
    def _extract_repo_name(self, repo_url: str) -> str:
        """从仓库URL提取仓库名"""
        if not repo_url:
            return ""
        return repo_url.rstrip('/').split('/')[-1].replace('.git', '')
    
    def get_statistics(self) -> Dict:
        """获取统计信息"""
        return {
            'corrections_made': self.corrections_made,
            'issues_detected': self.issues_detected
        }


# 测试代码
if __name__ == "__main__":
    print("="*80)
    print("DeploymentAdvisor - 实时观察者模式测试")
    print("="*80)
    
    # 模拟CRMEB的deployment_strategy
    strategy = {
        'repository_url': 'https://github.com/crmeb/CRMEB',
        'language': 'php',
        'build_tool': 'composer',
        'php_version': '7.4',
        'working_directory': 'crmeb',
        'deployment_type': 'docker-compose',
        'docker_compose_path': 'docker-compose'
    }
    
    advisor = DeploymentAdvisor(strategy)
    
    # 测试用例1: PHP版本不匹配
    print("\n[Test 1] PHP version mismatch:")
    cmd1 = "cd CRMEB && composer install"
    corrected, new_args, reason = advisor.intercept_tool_call('execute_linux_command', {'command': cmd1})
    print(f"  Corrected: {corrected}")
    if corrected:
        print(f"  New command: {new_args['command']}")
        print(f"  Reason: {reason}")
    
    # 测试用例2: 工作目录错误
    print("\n[Test 2] Wrong working directory:")
    cmd2 = "git clone https://github.com/crmeb/CRMEB && cd CRMEB && composer install"
    corrected, new_args, reason = advisor.intercept_tool_call('execute_linux_command', {'command': cmd2})
    print(f"  Corrected: {corrected}")
    if corrected:
        print(f"  New command: {new_args['command']}")
        print(f"  Reason: {reason}")
    
    # 测试用例3: docker-compose路径
    print("\n[Test 3] docker-compose path:")
    cmd3 = "docker-compose up -d"
    corrected, new_args, reason = advisor.intercept_tool_call('execute_linux_command', {'command': cmd3})
    print(f"  Corrected: {corrected}")
    if corrected:
        print(f"  New command: {new_args['command']}")
        print(f"  Reason: {reason}")
    
    # 统计信息
    print("\n" + "="*80)
    print("Statistics:")
    stats = advisor.get_statistics()
    print(json.dumps(stats, indent=2, ensure_ascii=False))
    print("="*80)
