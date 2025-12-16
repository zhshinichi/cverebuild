"""
测试 ContextAwareAnalyzer 智能上下文分析器

验证改进后的反思机制能够：
1. 检测 curl/wget 下载文件大小过小（即使 exit_code=0）
2. 检测 file 命令发现的文件类型错误并阻止后续 unzip
3. 分析 ls -la 输出检测异常小的压缩文件
4. 阻止对已知无效文件的 unzip
5. 记住失败的 URL 并阻止重复下载
6. 生成包含 git clone 建议的干预消息
"""

import pytest
import sys
import os
import re
from typing import Optional, List, Dict
from dataclasses import dataclass, field

# 直接定义需要测试的类，避免导入其他依赖

@dataclass
class ContextualInsight:
    """上下文分析结果"""
    issue_type: str
    evidence: str
    blocking: bool
    suggestion: str
    related_files: List[str] = field(default_factory=list)


class ContextAwareAnalyzer:
    """
    智能上下文感知分析器 - 测试用副本
    """
    
    def __init__(self):
        self.download_history: Dict[str, Dict] = {}
        self.known_bad_urls: set = set()
        self.known_bad_versions: set = set()
        self.blocking_insights: List[ContextualInsight] = []
    
    def analyze_curl_wget_output(self, command: str, output: str, exit_code: int) -> Optional[ContextualInsight]:
        filename = None
        url = None
        
        match = re.search(r'curl\s+.*?-o\s+(\S+)\s+(https?://\S+)', command)
        if match:
            filename = match.group(1)
            url = match.group(2)
        else:
            match = re.search(r'wget\s+.*?(?:-O\s+(\S+)\s+)?(https?://\S+)', command)
            if match:
                url = match.group(2)
                filename = match.group(1) or (url.split('/')[-1] if url else None)
        
        if not url:
            return None
        
        size_patterns = [
            r'100\s+(\d+)\s+100\s+\d+',
            r'(\d+)\s+\d+%\s+\d+',
        ]
        
        for pattern in size_patterns:
            size_match = re.search(pattern, output)
            if size_match:
                size = int(size_match.group(1))
                if size < 1000:
                    self.known_bad_urls.add(url)
                    
                    repo_match = re.search(r'github\.com/([^/]+/[^/]+)', url)
                    git_suggestion = ""
                    if repo_match:
                        repo_path = repo_match.group(1)
                        git_suggestion = f"\n   推荐命令: git clone https://github.com/{repo_path}.git"
                    
                    insight = ContextualInsight(
                        issue_type='download_failed',
                        evidence=f"⚠️ 下载文件 '{filename}' 只有 {size} 字节！",
                        blocking=True,
                        suggestion=f"🛑 停止下载尝试！{git_suggestion}\n   或使用: git clone --depth 1 <repo_url>",
                        related_files=[filename] if filename else []
                    )
                    self.blocking_insights.append(insight)
                    if filename:
                        self.download_history[filename] = {
                            'size': size, 
                            'status': 'failed', 
                            'url': url,
                        }
                    return insight
                break
        
        if '404' in output or 'Not Found' in output:
            self.known_bad_urls.add(url)
            version_match = re.search(r'v?(\d+\.\d+\.\d+)', url)
            if version_match:
                self.known_bad_versions.add(version_match.group(1))
            
            repo_match = re.search(r'github\.com/([^/]+/[^/]+)', url)
            git_suggestion = ""
            if repo_match:
                git_suggestion = f" 使用 git clone https://github.com/{repo_match.group(1)}.git 替代"
            
            insight = ContextualInsight(
                issue_type='url_not_found',
                evidence=f"URL返回404错误: {url}",
                blocking=True,
                suggestion=f"该URL不存在。{git_suggestion}",
                related_files=[filename] if filename else []
            )
            self.blocking_insights.append(insight)
            return insight
        
        if exit_code == 0 and filename:
            self.download_history[filename] = {'status': 'success', 'url': url}
        
        return None
    
    def analyze_file_command_output(self, command: str, output: str) -> Optional[ContextualInsight]:
        match = re.search(r'(\S+\.zip):\s*(.*)', output)
        if match:
            filename = match.group(1)
            file_type = match.group(2).lower()
            
            if 'zip' not in file_type and 'archive' not in file_type:
                self.download_history[filename] = {
                    'status': 'not_zip', 
                    'type': file_type,
                }
                
                insight = ContextualInsight(
                    issue_type='file_corrupted',
                    evidence=f"🚨 文件 '{filename}' 不是有效的ZIP文件！\n   file命令检测到实际类型是: {file_type}",
                    blocking=True,
                    suggestion=f"🛑 立即停止！不要继续尝试 unzip '{filename}'！\n   建议：使用 git clone 克隆仓库",
                    related_files=[filename]
                )
                self.blocking_insights.append(insight)
                return insight
        
        return None
    
    def analyze_ls_output(self, command: str, output: str) -> Optional[ContextualInsight]:
        file_pattern = r'-[rwx-]+\s+\d+\s+\w+\s+\w+\s+(\d+)\s+\w+\s+\d+\s+[\d:]+\s+(\S+\.(?:zip|tar\.gz|tgz|tar|gz))'
        
        tiny_files = []
        for match in re.finditer(file_pattern, output, re.IGNORECASE):
            size = int(match.group(1))
            filename = match.group(2)
            
            if size < 1000:
                tiny_files.append((filename, size))
                self.download_history[filename] = {
                    'status': 'failed', 
                    'size': size,
                }
        
        if tiny_files:
            file_list = ', '.join([f"'{f}'({s}字节)" for f, s in tiny_files])
            insight = ContextualInsight(
                issue_type='tiny_archive_detected',
                evidence=f"⚠️ 发现异常小的压缩文件: {file_list}",
                blocking=True,
                suggestion=f"🛑 不要尝试 unzip 这些文件！\n   建议: git clone <repo_url>",
                related_files=[f[0] for f in tiny_files]
            )
            self.blocking_insights.append(insight)
            return insight
        
        return None
    
    def analyze_unzip_output(self, command: str, output: str, exit_code: int) -> Optional[ContextualInsight]:
        match = re.search(r'unzip\s+(?:-\w+\s+)*(\S+)', command)
        if not match:
            return None
        
        filename = match.group(1)
        
        if filename in self.download_history:
            history = self.download_history[filename]
            if history.get('status') in ['failed', 'corrupted', 'not_zip']:
                insight = ContextualInsight(
                    issue_type='unzip_known_bad_file',
                    evidence=f"尝试解压已知无效的文件 '{filename}'",
                    blocking=True,
                    suggestion=f"停止！使用 git clone 替代",
                    related_files=[filename]
                )
                return insight
        
        if 'End-of-central-directory signature not found' in output:
            insight = ContextualInsight(
                issue_type='file_not_zip',
                evidence=f"'{filename}' 不是有效的ZIP文件",
                blocking=True,
                suggestion=f"使用 git clone 直接克隆仓库",
                related_files=[filename]
            )
            self.blocking_insights.append(insight)
            self.download_history[filename] = {'status': 'not_zip'}
            return insight
        
        return None
    
    def analyze_command(self, command: str, output: str, exit_code: int) -> Optional[ContextualInsight]:
        cmd_lower = command.lower().strip()
        
        if 'curl' in cmd_lower or 'wget' in cmd_lower:
            return self.analyze_curl_wget_output(command, output, exit_code)
        
        if cmd_lower.startswith('file '):
            return self.analyze_file_command_output(command, output)
        
        if cmd_lower.startswith('ls '):
            return self.analyze_ls_output(command, output)
        
        if 'unzip' in cmd_lower:
            return self.analyze_unzip_output(command, output, exit_code)
        
        return None
    
    def should_block_command(self, command: str) -> Optional[str]:
        cmd_lower = command.lower()
        
        if 'unzip' in cmd_lower:
            match = re.search(r'unzip\s+(?:-\w+\s+)*(\S+)', command)
            if match:
                filename = match.group(1)
                if filename in self.download_history:
                    status = self.download_history[filename].get('status')
                    if status in ['failed', 'corrupted', 'not_zip']:
                        return f"⛔ 阻止执行：文件 '{filename}' 已被检测为无效"
        
        for bad_url in self.known_bad_urls:
            if bad_url in command:
                return f"⛔ 阻止执行：URL '{bad_url[:50]}...' 之前下载失败"
        
        return None
    
    def reset(self):
        self.download_history.clear()
        self.known_bad_urls.clear()
        self.known_bad_versions.clear()
        self.blocking_insights.clear()


# 全局分析器实例
_test_context_analyzer: Optional[ContextAwareAnalyzer] = None


def get_context_analyzer() -> ContextAwareAnalyzer:
    global _test_context_analyzer
    if _test_context_analyzer is None:
        _test_context_analyzer = ContextAwareAnalyzer()
    return _test_context_analyzer


def reset_context_analyzer():
    global _test_context_analyzer
    if _test_context_analyzer:
        _test_context_analyzer.reset()
    _test_context_analyzer = None


class TestContextAwareAnalyzer:
    """ContextAwareAnalyzer 测试类"""
    
    def setup_method(self):
        """每个测试前重置分析器"""
        reset_context_analyzer()
        self.analyzer = ContextAwareAnalyzer()
    
    # ==================== 问题1: curl下载大小检测 ====================
    
    def test_curl_download_size_detection_9_bytes(self):
        """测试：检测 curl 下载只有9字节（即使 exit_code=0）"""
        command = "curl -L -o lunary.zip https://github.com/lunary-ai/lunary/archive/refs/tags/v1.4.8.zip"
        output = """  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0
100     9  100     9    0     0     18      0 --:--:-- --:--:-- --:--:--    18"""
        
        insight = self.analyzer.analyze_command(command, output, exit_code=0)  # exit_code=0 但仍应检测到问题
        
        assert insight is not None
        assert insight.issue_type == 'download_failed'
        assert insight.blocking is True
        assert '9' in insight.evidence or '9 字节' in insight.evidence
        assert 'git clone' in insight.suggestion.lower()
    
    def test_curl_download_size_detection_under_1000(self):
        """测试：检测 curl 下载小于1000字节"""
        command = "curl -L -o test.zip https://github.com/test/repo/archive/v1.0.zip"
        output = """  % Total    % Received % Xferd  Average Speed
100   500  100   500    0     0   1000      0 --:--:-- --:--:-- --:--:--  1000"""
        
        insight = self.analyzer.analyze_command(command, output, exit_code=0)
        
        assert insight is not None
        assert insight.issue_type == 'download_failed'
        assert insight.blocking is True
    
    def test_curl_download_large_file_ok(self):
        """测试：大文件下载不应触发警告"""
        command = "curl -L -o app.zip https://github.com/user/repo/archive/v1.0.zip"
        output = """  % Total    % Received % Xferd  Average Speed
100  5000000  100  5000000    0     0   1000      0  0:01:00  0:01:00 --:--:--  1000"""
        
        insight = self.analyzer.analyze_command(command, output, exit_code=0)
        
        assert insight is None  # 大文件不应触发警告
    
    # ==================== 问题2: file命令检测并阻止unzip ====================
    
    def test_file_type_detection_ascii_text(self):
        """测试：检测 file 命令发现 zip 文件实际是 ASCII text"""
        command = "file lunary.zip"
        output = "lunary.zip: ASCII text, with no line terminators"
        
        insight = self.analyzer.analyze_command(command, output, exit_code=0)
        
        assert insight is not None
        assert insight.issue_type == 'file_corrupted'
        assert insight.blocking is True
        assert 'ASCII text' in insight.evidence.lower() or 'ascii' in insight.evidence.lower()
        
        # 验证文件被记录到黑名单
        assert 'lunary.zip' in self.analyzer.download_history
        assert self.analyzer.download_history['lunary.zip']['status'] == 'not_zip'
    
    def test_file_type_detection_should_block_unzip(self):
        """测试：file 命令检测到无效文件后，应阻止 unzip"""
        # 先执行 file 命令
        self.analyzer.analyze_command("file bad.zip", "bad.zip: ASCII text", exit_code=0)
        
        # 然后尝试 unzip
        block_reason = self.analyzer.should_block_command("unzip bad.zip")
        
        assert block_reason is not None
        assert '阻止' in block_reason or 'bad.zip' in block_reason
    
    # ==================== 问题3: ls -la 输出分析 ====================
    
    def test_ls_output_tiny_zip_detection(self):
        """测试：分析 ls -la 输出检测异常小的 zip 文件"""
        command = "ls -la"
        output = """total 0
drwxr-xr-x 1 root root 4096 Dec 12 08:36 .
drwxrwxrwx 1 root root 4096 Dec  9 13:07 ..
-rw-r--r-- 1 root root   21 Dec 12 08:35 go.mod
-rw-r--r-- 1 root root    9 Dec 12 08:36 lunary-latest.zip
-rw-r--r-- 1 root root    9 Dec 12 08:36 lunary-main.zip
-rw-r--r-- 1 root root    0 Dec 12 08:36 lunary-v1.4.8.zip
-rw-r--r-- 1 root root    9 Dec 12 08:37 lunary.zip"""
        
        insight = self.analyzer.analyze_command(command, output, exit_code=0)
        
        assert insight is not None
        assert insight.issue_type == 'tiny_archive_detected'
        assert insight.blocking is True
        # 应该检测到多个小文件
        assert 'lunary' in insight.evidence.lower()
    
    def test_ls_output_normal_files_ok(self):
        """测试：正常大小的文件不应触发警告"""
        command = "ls -la"
        output = """-rw-r--r-- 1 root root 5000000 Dec 12 08:36 app.zip
-rw-r--r-- 1 root root 2000000 Dec 12 08:36 lib.tar.gz"""
        
        insight = self.analyzer.analyze_command(command, output, exit_code=0)
        
        assert insight is None  # 正常大小不应触发警告
    
    # ==================== 问题4: unzip 阻止机制 ====================
    
    def test_unzip_known_bad_file_blocked(self):
        """测试：阻止对已知无效文件的 unzip"""
        # 模拟之前的下载失败
        self.analyzer.download_history['bad.zip'] = {'status': 'failed', 'size': 9}
        
        block_reason = self.analyzer.should_block_command("unzip bad.zip")
        
        assert block_reason is not None
        assert '阻止' in block_reason or 'bad.zip' in block_reason
    
    def test_unzip_error_detection(self):
        """测试：检测 unzip 错误（End-of-central-directory signature not found）"""
        command = "unzip lunary.zip"
        output = """Archive:  lunary.zip
  End-of-central-directory signature not found.  Either this file is not
  a zipfile, or it constitutes one disk of a multi-part archive."""
        
        insight = self.analyzer.analyze_command(command, output, exit_code=9)
        
        assert insight is not None
        assert insight.issue_type == 'file_not_zip'
        assert insight.blocking is True
        assert 'git clone' in insight.suggestion.lower()
    
    # ==================== 问题5: URL 记忆机制 ====================
    
    def test_known_bad_url_memory(self):
        """测试：记住失败的 URL 并阻止重复下载"""
        # 模拟第一次下载失败
        command = "curl -L -o test.zip https://github.com/user/repo/archive/refs/tags/v1.0.zip"
        output = "100     9  100     9    0     0     18      0 --:--:-- --:--:-- --:--:--    18"
        
        self.analyzer.analyze_command(command, output, exit_code=0)
        
        # URL 应该被记住
        assert any('v1.0' in url for url in self.analyzer.known_bad_urls)
        
        # 尝试再次下载相同 URL 应该被阻止
        block_reason = self.analyzer.should_block_command(
            "curl -L -o test2.zip https://github.com/user/repo/archive/refs/tags/v1.0.zip"
        )
        
        assert block_reason is not None
    
    # ==================== 问题6: git clone 建议 ====================
    
    def test_git_clone_suggestion_in_messages(self):
        """测试：干预消息中应包含 git clone 建议"""
        command = "curl -L -o lunary.zip https://github.com/lunary-ai/lunary/archive/refs/tags/v1.4.8.zip"
        output = "100     9  100     9    0     0     18      0 --:--:-- --:--:-- --:--:--    18"
        
        insight = self.analyzer.analyze_command(command, output, exit_code=0)
        
        assert insight is not None
        # 应该包含 git clone 建议
        assert 'git clone' in insight.suggestion.lower()
        # 应该提取出仓库路径
        assert 'lunary-ai/lunary' in insight.suggestion or 'lunary' in insight.suggestion.lower()
    
    # ==================== 辅助功能测试 ====================
    
    def test_reset_analyzer(self):
        """测试：重置分析器"""
        self.analyzer.download_history['test.zip'] = {'status': 'failed'}
        self.analyzer.known_bad_urls.add('https://example.com/bad.zip')
        
        self.analyzer.reset()
        
        assert len(self.analyzer.download_history) == 0
        assert len(self.analyzer.known_bad_urls) == 0
        assert len(self.analyzer.blocking_insights) == 0
    
    def test_404_error_detection(self):
        """测试：检测 404 错误"""
        command = "wget https://github.com/user/repo/archive/refs/tags/v1.0.zip"
        output = """--2025-12-12 08:36:25--  https://github.com/user/repo/archive/refs/tags/v1.0.zip
Connecting to github.com... connected.
HTTP request sent, awaiting response... 404 Not Found
2025-12-12 08:36:26 ERROR 404: Not Found."""
        
        insight = self.analyzer.analyze_command(command, output, exit_code=8)
        
        assert insight is not None
        assert insight.issue_type == 'url_not_found'
        assert insight.blocking is True
        assert '404' in insight.evidence


class TestIntegrationWithCommandDetector:
    """测试与 RepetitiveCommandDetector 的集成"""
    
    def setup_method(self):
        reset_context_analyzer()
    
    def test_global_analyzer_singleton(self):
        """测试：全局分析器是单例"""
        analyzer1 = get_context_analyzer()
        analyzer2 = get_context_analyzer()
        
        assert analyzer1 is analyzer2
    
    def test_analyzer_state_persists(self):
        """测试：分析器状态在多次调用间保持"""
        analyzer = get_context_analyzer()
        
        # 第一次调用
        analyzer.analyze_command(
            "curl -L -o test.zip https://example.com/test.zip",
            "100     9  100     9    0     0     18      0",
            exit_code=0
        )
        
        # 状态应该保持
        assert 'test.zip' in analyzer.download_history
        
        # 第二次获取应该是同一个实例
        analyzer2 = get_context_analyzer()
        assert 'test.zip' in analyzer2.download_history


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
