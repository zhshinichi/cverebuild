# 修复 agentlib 导入: 避免本地 agentlib 目录干扰已安装的包
import sys
import os
_agents_dir = os.path.dirname(os.path.abspath(__file__))
_src_dir = os.path.dirname(_agents_dir)
_local_agentlib = os.path.join(_src_dir, 'agentlib')
_cwd = os.getcwd()

def _should_filter_path(p):
    """判断路径是否应该被过滤（因为它包含会干扰 agentlib 导入的目录）"""
    if not p:
        # 空字符串代表当前工作目录
        return os.path.exists(os.path.join(_cwd, 'agentlib'))
    resolved = os.path.abspath(p)
    return resolved == _src_dir and os.path.exists(os.path.join(resolved, 'agentlib'))

# 临时过滤掉可能导致冲突的路径，但导入完成后恢复
_original_path = sys.path[:]
sys.path = [p for p in sys.path if not _should_filter_path(p)]

from .knowledgeBuilder import KnowledgeBuilder
from .preReqBuilder import PreReqBuilder
from .repoBuilder import RepoBuilder
from .repoCritic import RepoCritic
from .exploiter import Exploiter
from .exploitCritic import ExploitCritic
from .ctfVerifier import CTFVerifier
from .sanityGuy import SanityGuy
from .cveInfoGenerator import CVEInfoGenerator
from .webDriverAgent import WebDriverAgent
from .webExploitCritic import WebExploitCritic
from .fixAdvisor import FixAdvisor
from .webEnvBuilder import WebEnvBuilder

# 新的分拆 Agents (Web 环境部署流水线)
from .projectSetup import ProjectSetupAgent
from .serviceStart import ServiceStartAgent
from .healthCheck import HealthCheckAgent

# 恢复原始 sys.path，确保其他模块（如 core）可以正常导入
sys.path = _original_path
