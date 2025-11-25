import argparse
from dotenv import load_dotenv
import signal
import os
import sys
import time
import subprocess
import csv
from datetime import datetime

# 修复模块导入优先级: 确保使用已安装的 agentlib 而非本地目录
# 问题: 某些路径下的 agentlib/ 目录会遮蔽已安装的 agentlib 包
_current_dir = os.path.dirname(os.path.abspath(__file__))
_agentlib_local = os.path.join(_current_dir, 'agentlib')

# 策略: 
# 1. 移除空字符串和本地 agentlib 路径，避免遮蔽已安装的包
# 2. 保留 site-packages 等系统路径
# 3. 将 _current_dir 添加到末尾（用于导入 agents, toolbox, core 等本地模块）
_paths_to_remove = ['', _agentlib_local]
sys.path = [p for p in sys.path if p not in _paths_to_remove]

# 确保 _current_dir 在 sys.path 中（放末尾，优先级低于 site-packages）
if _current_dir not in sys.path:
    sys.path.append(_current_dir)

class TeeLogger:
    """将输出同时写入终端和文件"""
    def __init__(self, log_file_path):
        self.terminal = sys.stdout
        self.log_file = open(log_file_path, 'w', encoding='utf-8', buffering=1)
    
    def write(self, message):
        self.terminal.write(message)
        self.log_file.write(message)
    
    def flush(self):
        self.terminal.flush()
        self.log_file.flush()
    
    def close(self):
        self.log_file.close()

class TimeoutExpired(Exception):
    def __init__(self, phase: str = None, message: str = "Timeout expired"):
        self.phase = phase
        self.message = f"{message} during phase: {phase}" if phase else message
        super().__init__(self.message)

def sanitize_cve_knowledge_for_builder(cve_knowledge: str) -> str:
    """
    移除 CVE 知识中可能触发安全对齐的 exploit payload 细节
    保留技术分析和修复建议，但删除具体的攻击代码
    """
    import re
    
    # 标记要移除的危险部分
    patterns_to_remove = [
        # 移除包含 ATTACH 的 SQL injection payload
        (r'(?:Example Exploit Request|Exploit Outline|Line-by-line breakdown).*?(?=\n\n[A-Z#]|\Z)', re.DOTALL),
        # 移除包含具体攻击步骤的代码块
        (r'```(?:sql|bash|shell)\n.*?ATTACH.*?```', re.DOTALL | re.IGNORECASE),
        # 移除 URL 编码的 payload
        (r'GET /fts/snippets/.*?highlight_end=.*?(?=\n\n|\Z)', re.DOTALL),
    ]
    
    sanitized = cve_knowledge
    for pattern, flags in patterns_to_remove:
        sanitized = re.sub(pattern, '[EXPLOIT DETAILS REDACTED FOR SAFE BUILD]', sanitized, flags=flags)
    
    # 添加安全说明
    safe_note = "\n\n⚠️ NOTE: Exploit payload details have been redacted from this knowledge base to prevent security policy violations during build. The builder's task is only to set up the vulnerable environment, not to execute exploits.\n"
    sanitized = safe_note + sanitized
    
    return sanitized

def alarm_handler(signum, frame):
    raise TimeoutExpired

if not os.environ.get('ENV_PATH'):
    load_dotenv()
else:
    dotenv_path = os.environ['ENV_PATH']
    load_dotenv(dotenv_path=dotenv_path)

if not os.environ.get('MODEL'):
    exit(1)

MODEL = os.environ['MODEL']

from toolbox import helper, CVEDataProcessor, Validator
from toolbox.web_detector import requires_web_driver, get_attack_type
from agents import KnowledgeBuilder, PreReqBuilder, RepoBuilder, RepoCritic, Exploiter, ExploitCritic, CTFVerifier, SanityGuy, CVEInfoGenerator, WebDriverAgent, WebExploitCritic, FixAdvisor, WebEnvBuilder
from core.result_bus import ResultBus

# -------------------------------------------------------------------------
# 🔧 动态配置所有 Agent 以提升复现率和解决 Token 问题
# -------------------------------------------------------------------------
AGENTS = [KnowledgeBuilder, PreReqBuilder, RepoBuilder, RepoCritic, Exploiter, ExploitCritic, CTFVerifier, SanityGuy, CVEInfoGenerator, WebDriverAgent, WebExploitCritic, FixAdvisor, WebEnvBuilder]
for agent_cls in AGENTS:
    # 配置 Token 超限策略 (解决 Context Window Exceeded 问题)
    # 当上下文超限时，自动移除最旧的 2 轮对话并重试，而不是直接失败
    agent_cls.__CONTEXT_WINDOW_EXCEEDED_STRATEGY__ = dict(
        name="remove_turns",
        number_to_remove=2,
    )

print(f"🔧 Configured all agents with auto-pruning strategy for token limits.")
# -------------------------------------------------------------------------

CVE_INFO_GEN = False
KB = False
PRE_REQ = False
REPO = False
REPO_CRITIC = False

EXPLOIT = False
EXPLOIT_CRITIC = False

CTF_VERIFIER = False
SANITY_CHECK = False
FIX_ADVISOR = False

TIMEOUT = 2700
MAX_COST = 5.00

# Web Driver 配置
WEB_DRIVER_TARGET_URL = os.environ.get('WEB_DRIVER_TARGET_URL', 'http://localhost:9600')

class CVEReproducer:
    def __init__(self, cve_id: str, cve_json: str, result_bus: ResultBus):
        self.cve_id = cve_id
        self.cve_json = cve_json
        self.total_cost = 0
        self.results = {}
        self.start_time = None
        self.result_bus = result_bus
        self._cached_cve_entry = None
        self._fix_ran = False

    def _load_cve_entry(self):
        if self._cached_cve_entry is not None:
            return self._cached_cve_entry

        if not self.cve_json:
            raise FileNotFoundError("❌ Data file path (--json) is required for this command")

        if not os.path.exists(self.cve_json):
            raise FileNotFoundError(f"❌ Data file not found: {self.cve_json}")

        import json

        with open(self.cve_json, 'r', encoding='utf-8') as f:
            all_cve_data = json.load(f)

        if self.cve_id not in all_cve_data:
            raise ValueError(f"❌ {self.cve_id} not found in {self.cve_json}")

        self._cached_cve_entry = all_cve_data[self.cve_id]
        return self._cached_cve_entry

    def _get_shared_dir(self) -> str:
        """获取 shared 目录路径（优先使用挂载目录）"""
        mounted = "/workspaces/submission/src/shared"
        if os.path.exists(os.path.dirname(mounted)):
            return mounted
        return "/shared"

    def _has_successful_reproduction(self) -> bool:
        csv_path = os.path.join(self._get_shared_dir(), 'results.csv')
        if not os.path.isfile(csv_path):
            return False

        import csv

        with open(csv_path, 'r', encoding='utf-8') as csv_file:
            reader = csv.DictReader(csv_file)
            for row in reader:
                if row.get('CVE') == self.cve_id and row.get('SUCCESS', '').lower() == 'true':
                    return True
        return False

    def _collect_patch_content(self, cve_entry: dict) -> str:
        patch_commits = cve_entry.get('patch_commits', []) or []
        snippets = []
        for patch in patch_commits:
            content = patch.get('content') if isinstance(patch, dict) else None
            if content:
                snippets.append(content.strip())
        return "\n\n".join(snippets) if snippets else "No official patch available"

    def _generate_fix_recommendations(self):
        self._fix_ran = True
        cve_entry = self._load_cve_entry()

        if self.start_time is None:
            self.start_time = time.time()

        cwe_entries = cve_entry.get('cwe', []) or []
        cwe_summary = ', '.join(filter(None, [
            f"{item.get('id', '').strip()} {item.get('value', '').strip()}".strip()
            for item in cwe_entries if isinstance(item, dict)
        ])) or 'Unknown CWE'

        vulnerability_type = cve_entry.get('vulnerability_type') or cwe_summary or 'Unknown vulnerability type'
        description = cve_entry.get('description', 'No description available')
        patch_content = self._collect_patch_content(cve_entry)
        reproduction_success = self._has_successful_reproduction()

        print(f"\n🩹 Generating fix recommendations for {self.cve_id} ...")

        advisor = FixAdvisor(
            cve_id=self.cve_id,
            vulnerability_type=vulnerability_type,
            cwe=cwe_summary,
            description=description,
            vulnerable_code=cve_entry.get('vulnerable_code', 'Not available'),
            patch_content=patch_content,
            reproduction_success=reproduction_success
        )

        advice = advisor.invoke().value
        helper.save_response(self.cve_id, advice, "fix_advisor")

        fix_dir = os.path.join(self._get_shared_dir(), self.cve_id)
        os.makedirs(fix_dir, exist_ok=True)
        fix_file = os.path.join(fix_dir, f"{self.cve_id}_fix_recommendations.txt")

        with open(fix_file, 'w', encoding='utf-8') as handle:
            handle.write(f"Fix Recommendations for {self.cve_id}\n")
            handle.write(f"Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            handle.write(f"Model: {MODEL}\n")
            handle.write(f"{'='*60}\n\n")
            handle.write(advice)

        cost = advisor.get_cost()
        self.update_cost(cost)

        print(f"✅ Fix recommendations saved to: {fix_file}")
        print(f"💡 Summary:\n{advice}\n")

        fix_result = {
            "fix_recommendations_file": fix_file,
            "fix_recommendations": advice,
            "fix_advisor_cost": cost,
            "reproduction_history": reproduction_success,
        }

        if not self.results:
            fix_result.update({
                "success": "True",
                "reason": f"Fix recommendations saved to {fix_file}"
            })
            self.results = fix_result
        else:
            self.results.update(fix_result)

        return fix_result
    
    def check_time(self, phase: str = None):
        if time.time() - self.start_time > TIMEOUT:
            raise TimeoutExpired(phase=phase)

    def update_cost(self, cost: float, exception: bool = False):
        self.total_cost += cost
        if self.total_cost >= MAX_COST and not exception:
            raise ValueError("Cost exceeds maximum limit")

    def run(self):
        fix_only_mode = FIX_ADVISOR and not any([CVE_INFO_GEN, KB, PRE_REQ, REPO, EXPLOIT, CTF_VERIFIER])
        try:
            if fix_only_mode:
                print(f"\n🩹 Running FixAdvisor workflow for {self.cve_id} ...")
                self._generate_fix_recommendations()
                return

            if CVE_INFO_GEN:
                print(f"\n📄 Generating CVE Information for {self.cve_id} ...")
                print("🤖 Model: ", MODEL)
                
                # 直接从 data.json 加载数据，不运行耗时的 CVEDataProcessor
                import json
                if not os.path.exists(self.cve_json):
                    raise FileNotFoundError(f"❌ Data file not found: {self.cve_json}")
                
                print(f"📖 Loading CVE data from: {self.cve_json}")
                with open(self.cve_json, 'r', encoding='utf-8') as f:
                    all_cve_data = json.load(f)
                
                if self.cve_id not in all_cve_data:
                    raise ValueError(f"❌ {self.cve_id} not found in {self.cve_json}")
                
                self.cve_info = all_cve_data[self.cve_id]
                print(f"✅ CVE data loaded successfully!")
                
                # 准备数据
                cwe = '\n'.join([f"* {c['id']} - {c['value']}" for c in self.cve_info.get("cwe", [])])
                
                # 从 sw_version_wget 提取项目名，如果不存在则使用空字符串
                sw_wget = self.cve_info.get("sw_version_wget", "")
                if sw_wget and "//" in sw_wget:
                    parts = sw_wget.split("//")[1].split("/")
                    project_name = parts[2] if len(parts) > 2 else "Unknown"
                else:
                    project_name = "Unknown"
                
                patches = '\n\n'.join([f"Commit Hash: {p['url'].split('/')[-1]}\n\"\"\"\n{p['content']}\n\"\"\"" for p in self.cve_info.get("patch_commits", [])])
                sec_adv = '\n\n'.join([f"Advisory: {a['url']}\n\"\"\"\n{a['content']}\n\"\"\"" for ix, a in enumerate(self.cve_info.get("sec_adv", []))])
                
                # 调用 CVE 信息生成 agent
                cve_info_generator = CVEInfoGenerator(
                    cve_id = self.cve_id,
                    description = self.cve_info.get("description", "No description available"),
                    cwe = cwe if cwe else "No CWE information available",
                    project_name = project_name,
                    affected_version = self.cve_info.get("sw_version", "Unknown"),
                    security_advisory = sec_adv if sec_adv else "No security advisory available",
                    patch = patches if patches else "No patch information available"
                )
                
                info_summary = cve_info_generator.invoke().value
                print(f"\n📋 CVE Information Summary:\n{info_summary}\n")
                
                # 保存到 shared 文件夹
                info_dir = os.path.join(self._get_shared_dir(), self.cve_id)
                os.makedirs(info_dir, exist_ok=True)
                info_file = os.path.join(info_dir, f'{self.cve_id}_info.txt')
                
                with open(info_file, 'w', encoding='utf-8') as f:
                    f.write(f"CVE Information Summary\n")
                    f.write(f"Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"{'='*60}\n\n")
                    f.write(info_summary)
                
                print(f"✅ CVE Information saved to: {info_file}")
                
                cost = cve_info_generator.get_cost()
                print(f"💰 Cost: ${cost:.4f}")
                
                self.results = {"success": "True", "info_file": info_file, "cost": cost}
                
                # info 命令也需要自动复制文件到本地
                print(f"\n📦 Copying generated files to local...")
                self.result_bus.sync_to_local()
                
                return
            
            if KB:
                print(f"\n🛠️ Reproducing {self.cve_id} ...")

                print("🤖 Model: ", MODEL)

                print("\n########################################\n" \
                    "# 1) 📚 Running CVE Processor ...\n" \
                    "########################################\n")
                
                print("\n----------------------------------------\n" \
                    "- a) 📋 CVE Data Processor \n" \
                    "-------------------------------------------\n")
                processor = CVEDataProcessor(self.cve_id, self.cve_json)
                self.cve_info = processor.run()
                helper.save_response(self.cve_id, self.cve_info, "cve_info", struct=True)

                print(f"✅ CVE Data Processor Done!")

                print("\n⏰ Starting timer ...")
                self.start_time = time.time()
                
                print("\n----------------------------------------\n" \
                    "- a) 🧠 Knowledge Builder \n" \
                    "-------------------------------------------\n")
        
                cwe = '\n'.join([f"* {c['id']} - {c['value']}" for c in self.cve_info["cwe"]])
                project_name = self.cve_info["sw_version_wget"].split("//")[1].split("/")[2]
                patches = '\n\n'.join([f"Commit Hash: {p['url'].split('/')[-1]}\n\"\"\"\n{p['content']}\n\"\"\"" for p in self.cve_info["patch_commits"]])
                sec_adv = '\n\n'.join([f"Advisory: {a['url']}\n\"\"\"\n{a['content']}\n\"\"\"" for ix, a in enumerate(self.cve_info["sec_adv"])])
                knowledge_builder = KnowledgeBuilder(
                    id = self.cve_id,
                    description = self.cve_info["description"],
                    cwe = cwe,
                    project_name = project_name,
                    affected_version = self.cve_info["sw_version"],
                    security_advisory = sec_adv,
                    patch = patches
                )
                res = knowledge_builder.invoke().value
                print(f"⛺️ Knowledge Base: '''\n{res}\n'''")
                helper.save_response(self.cve_id, res, "knowledge_builder")
                self.update_cost(knowledge_builder.get_cost())
                print(f"✅ Knowledge Builder Done!")
            else:
                try:
                    res = helper.load_response(self.cve_id, "knowledge_builder")
                    self.cve_info = helper.load_response(self.cve_id, "cve_info", struct=True)
                except FileNotFoundError:
                    print("❌ Knowledge Builder response not found!")
                    self.results = {"success": "False", "reason": "Knowledge Builder response not found"}
                    return
            self.cve_knowledge = res

            print(f"\n💰 Cost till Knowledge Builder = {self.total_cost}\n")

            if PRE_REQ:
                
                print("\n########################################\n" \
                    "# 2) 🛠️ Running Project Builder ...\n" \
                    "########################################\n")

                print("\n----------------------------------------\n" \
                    "- a) 📋 Pre-Requsites Builder \n" \
                    "-------------------------------------------\n")

                pre_req_builder = PreReqBuilder(
                    cve_knowledge = self.cve_knowledge,
                    project_dir_tree = self.cve_info['dir_tree']
                )
                res = pre_req_builder.invoke().value
                helper.save_response(self.cve_id, res, "pre_req_builder", struct=True)
                self.update_cost(pre_req_builder.get_cost())
                print(f"✅ Pre-Requsites Builder Done!")
            else:
                try:
                    res = helper.load_response(self.cve_id, "pre_req_builder", struct=True)
                except FileNotFoundError:
                    print("❌ Pre-Requsites Builder response not found!")
                    self.results = {"success": "False", "reason": "Pre-Requsites Builder response not found"}
                    return
            self.pre_reqs = res

            print(f"\n💰 Cost till Pre-Req = {self.total_cost}\n")

            if REPO:
                print("\n----------------------------------------\n" \
                    "- b) 🏭 Repository Builder \n" \
                    "-------------------------------------------\n")
                
                repo_done = False
                repo_feedback, critic_feedback = None, None
                repo_try, critic_try = 1, 1
                max_repo_tries, max_critic_tries = 3, 2

                while not repo_done and repo_try <= max_repo_tries and critic_try <= max_critic_tries:
                    self.check_time("project_build")
                    if repo_feedback or critic_feedback:
                        print("\n----------------------------------------\n" \
                            "- b) 🎯 Feedback-Based Repository Builder \n" \
                            "-------------------------------------------\n")
                    
                    repo_builder = RepoBuilder(
                        project_dir_tree = self.cve_info['dir_tree'],
                        cve_knowledge = sanitize_cve_knowledge_for_builder(self.cve_knowledge),
                        build_pre_reqs = self.pre_reqs,
                        feedback = repo_feedback,
                        critic_feedback = critic_feedback
                    )
                    res = repo_builder.invoke().value
                    critic_feedback = None # Reset critic feedback for next iteration

                    # Check if the agent stopped due to max iterations
                    if res == "Agent stopped due to max iterations.":
                        print("🛑 Repo Builder stopped due to max iterations!")
                        if repo_try < max_repo_tries:
                            print("📋 Summarizing work ...")
                            repo_builder.__OUTPUT_PARSER__ = None
                            res = repo_builder.invoke(dict(
                                ERROR = "You were not able to perform the task in the given maximum number of tool calls. Now summarize in detail the steps you took to solve the task, such that another agent could pick up where you left off. MAKE SURE TO INCLUDE ALL THE COMMANDS YOU RAN."
                            ))
                            repo_feedback = res.value
                            critic_feedback = None

                        self.update_cost(repo_builder.get_cost())
                    else:
                        self.repo_build = res

                        # ----- Save the repo build response -----
                        setup_logs = helper.parse_chat_messages(repo_builder.chat_history, include_human=True)
                        setup_logs = helper.remove_tree_from_setup_logs(setup_logs)
                        helper.save_response(self.cve_id, setup_logs, f"repo_builder_setup_logs")
                        print(f"📜 Setup Logs:\n'''\n{setup_logs}\n'''")

                        if self.repo_build['success'].lower() == "yes":
                            if REPO_CRITIC:
                                # ----- Invoke Critic for repo build -----
                                print("\n----------------------------------------\n" \
                                        "👀 Running Critic on Repo Builder ...\n" \
                                        "-------------------------------------------\n")
                                critic = RepoCritic(
                                    setup_logs = setup_logs
                                )
                                res = critic.invoke().value
                                helper.save_response(self.cve_id, res, "repo_critic", struct=True)
                                critic_try += 1

                                if res['decision'].lower() == 'no':
                                    print("❌ Critic rejected the repo build!")

                                    if res['possible'].lower() == 'no':
                                        print("🚨 It is not possible to correct the setup!!")
                                        self.results = {"success": "False", "reason": 'Not possible to build the repo!!!'}
                                        self.update_cost(repo_builder.get_cost())
                                        return
                                    
                                    if not res['feedback'].strip():
                                        print("🚨 No Feedback!!")
                                        self.results = {"success": "False", "reason": 'No feedback to correct the setup!!!'}
                                        self.update_cost(repo_builder.get_cost())
                                        return

                                    print("📋 Sending feedback to repo builder!")
                                    critic_feedback = res['feedback']
                                    repo_feedback = None # Reset repo feedback for critic iteration
                                    repo_try = 0
                                else:
                                    print("✅ Critic accepted the repo build!")
                                    # ------------------------------------------
                                    repo_done = True
                                    self.repo_build['time_left'] = TIMEOUT - (time.time() - self.start_time)
                                    helper.save_response(self.cve_id, self.repo_build, "repo_builder", struct=True)
                                    print(f"✅ Repo Builder Done!")
                                self.update_cost(critic.get_cost(), exception=repo_done)
                            else:
                                repo_done = True
                                self.repo_build['time_left'] = TIMEOUT - (time.time() - self.start_time)
                                helper.save_response(self.cve_id, self.repo_build, "repo_builder", struct=True)
                                print(f"✅ Repo Builder Done!")
                        else:
                            if repo_try < max_repo_tries:
                                print("❌ Repo could not be built!")
                                print("📋 Sending output feedback to Repo Builder ...")
                                repo_builder.__OUTPUT_PARSER__ = None
                                res = repo_builder.invoke(dict(
                                    ERROR = "As you were not able to build the repository, summarize in detail the steps you took to build the repository, such that an expert could take a look at it and try to resolve it. MAKE SURE TO INCLUDE ALL THE COMMANDS YOU RAN."
                                ))
                                repo_feedback = res.value
                                critic_feedback = None
                            else:
                                print("❌ Repo agent gave up!")
                        self.update_cost(repo_builder.get_cost(), exception=repo_done)
                    repo_try += 1

                if not repo_done:
                    print("❌ Repo could not be built!")
                    helper.save_response(self.cve_id, {"success": "no", "access": "Repo could not be built after all tries", "time_left": 1}, "repo_builder", struct=True)
                    self.results = {"success": "False", "reason": "Repo could not be built"}
                    return
                else:
                    print("✅ Repo Built Successfully!")
            else:
                try:
                    res = helper.load_response(self.cve_id, "repo_builder", struct=True)
                except FileNotFoundError:
                    print("❌ Repo Builder response not found!")
                    self.results = {"success": "False", "reason": "Repo Builder response not found"}
                    return
                self.repo_build = res
                # 如果跳过了 processor 阶段,初始化 start_time
                if self.start_time is None:
                    self.start_time = time.time()

            print(f"\n💰 Cost till Repo Builder = {self.total_cost}\n")

            if self.repo_build['success'].lower()=="no":
                self.results = {"success": "False", "reason": 'Repo was not built!!!'}
                return

            if EXPLOIT:
                os.environ['REPO_PATH'] = self.cve_info['repo_path']
                
                print("Time left: ", self.repo_build['time_left'])
                
                # 🌐 检测是否需要 WebDriver
                use_web_driver = requires_web_driver(self.cve_info)
                if use_web_driver:
                    attack_type = get_attack_type(self.cve_info)
                    print(f"\n🌐 Detected web-based vulnerability (Type: {attack_type})")
                    print("   Using WebDriver for browser automation...\n")
                
                print("\n########################################\n" \
                    "# 6) 🚀 Running Exploiter ...\n" \
                    "########################################\n")
                
                exploit_done = False
                exploit_feedback, exploit_critic_feedback = None, None
                exploit_try, exploit_critic_try = 1, 1
                max_exploit_tries, max_exploit_critic_tries = 3, 2

                while not exploit_done and exploit_try <= max_exploit_tries and exploit_critic_try <= max_exploit_critic_tries:
                    self.check_time("exploit_build")
                    if exploit_feedback or exploit_critic_feedback:
                        print("\n----------------------------------------\n" \
                            "- a) 🧨 Feedback-Based Exploiter \n" \
                            "-------------------------------------------\n")
                    
                    # 根据漏洞类型选择不同的 Exploiter
                    if use_web_driver:
                        print("\n🌐 Using WebDriverAgent for browser-based exploitation...\n")
                        exploiter = WebDriverAgent(
                            cve_knowledge = self.cve_knowledge,
                            target_url = WEB_DRIVER_TARGET_URL,
                            attack_type = attack_type
                        )
                    else:
                        exploiter = Exploiter(
                            cve_knowledge = self.cve_knowledge,
                            project_overview = self.pre_reqs['overview'],
                            project_dir_tree = self.cve_info['dir_tree'],
                            repo_build = self.repo_build,
                            feedback = exploit_feedback,
                            critic_feedback = exploit_critic_feedback
                        )
                    res = exploiter.invoke().value

                    # Check if the agent stopped due to max iterations
                    if res == "Agent stopped due to max iterations.":
                        print("🛑 Exploiter stopped due to max iterations!")
                        if exploit_try < max_exploit_tries:
                            print("📋 Summarizing work ...")
                            exploiter.__OUTPUT_PARSER__ = None
                            res = exploiter.invoke(dict(
                                ERROR = "You were not able to perform the task in the given maximum number of tool calls. Now summarize in detail the steps you took to solve the task, such that another agent could pick up where you left off. MAKE SURE TO INCLUDE ALL THE COMMANDS YOU RAN."
                            ))
                            exploit_feedback = res.value
                            exploit_critic_feedback = None
                        
                        self.update_cost(exploiter.get_cost())
                    else:
                        self.exploit = res

                        # ---- Save the exploit response ----
                        exploit_logs = helper.parse_chat_messages(exploiter.chat_history, include_human=True)
                        exploit_logs = helper.remove_tree_from_exploit_logs(exploit_logs)
                        helper.save_response(self.cve_id, exploit_logs, f"exploiter_logs")
                        print(f"📜 Exploit Logs:\n'''\n{exploit_logs}\n'''")

                        if self.exploit['success'].lower() == "yes":
                            if EXPLOIT_CRITIC:
                                # ----- Invoke Critic for exploit -----
                                print("\n----------------------------------------\n" \
                                        "👀 Running Critic on Exploiter ...\n" \
                                        "-------------------------------------------\n")
                                
                                # 根据是否使用 WebDriver 选择不同的 Critic
                                if use_web_driver:
                                    print("🌐 Using WebExploitCritic for browser-based validation...\n")
                                    critic = WebExploitCritic(
                                        exploit_logs = exploit_logs,
                                        cve_knowledge = self.cve_knowledge
                                    )
                                else:
                                    critic = ExploitCritic(
                                        exploit_logs = exploit_logs
                                    )
                                
                                res = critic.invoke().value
                                helper.save_response(self.cve_id, res, "exploit_critic", struct=True)
                                exploit_critic_try += 1

                                if res['decision'].lower() == 'no':
                                    print("❌ Critic rejected the exploit!")

                                    if res['possible'].lower() == 'no':
                                        print("🚨 It is not possible to exploit the vulnerability!!")
                                        self.results = {"success": "False", "reason": 'Not possible to exploit the vulnerability!!!'}
                                        return
                                    
                                    if not res['feedback'].strip():
                                        print("🚨 No Feedback!!")
                                        self.results = {"success": "False", "reason": 'No feedback to correct the exploit!!!'}
                                        return

                                    print("📋 Sending feedback to exploiter!")
                                    exploit_critic_feedback = res['feedback']
                                    exploit_feedback = None # Reset exploit feedback for critic iteration
                                    exploit_try = 0
                                else:
                                    print("✅ Critic accepted the exploit!")
                                    # ------------------------------------------
                                    exploit_done = True
                                    self.exploit['time_left'] = TIMEOUT - (time.time() - self.start_time)
                                    helper.save_response(self.cve_id, self.exploit, "exploiter", struct=True)
                                    print(f"✅ Exploiter Done!")
                                self.update_cost(critic.get_cost(), exception=exploit_done)
                            else:
                                exploit_done = True
                                self.exploit['time_left'] = TIMEOUT - (time.time() - self.start_time)
                                helper.save_response(self.cve_id, self.exploit, "exploiter", struct=True)
                                print(f"✅ Exploiter Done!")
                        else:
                            if exploit_try < max_exploit_tries:
                                print("❌ Exploiter failed!")
                                print("📋 Sending output feedback to Exploiter ...")
                                exploiter.__OUTPUT_PARSER__ = None
                                res = exploiter.invoke(dict(
                                    ERROR = "As you were not able to exploit the vulnerability, summarize in detail the steps you took to exploit the vulnerability, such that an expert could take a look at it and try to resolve it. MAKE SURE TO INCLUDE ALL THE COMMANDS YOU RAN."
                                ))
                                exploit_feedback = res.value
                                exploit_critic_feedback = None
                            else:
                                print("❌ Exploiter gave up!")
                        self.update_cost(exploiter.get_cost(), exception=exploit_done)
                    exploit_try += 1
                
                if not exploit_done:
                    print("❌ Exploiter failed!")
                    helper.save_response(self.cve_id, {"success": "no", "reason": "Exploiter failed"}, "exploiter", struct=True)
                    self.results = {"success": "False", "reason": "Exploiter failed"}
                    return
                else:
                    helper.create_exploit_script(self.exploit['poc'])
                    print("✅ Exploit Script Created!")
                    self.results = {"success": "True", "reason": "Exploit script created"}
            else:
                try:
                    res = helper.load_response(self.cve_id, "exploiter", struct=True)
                except FileNotFoundError:
                    print("❌ Exploiter response not found!")
                    self.results = {"success": "False", "reason": "Exploiter response not found"}
                    return
                self.exploit = res

            print(f"\n💰 Cost till Exploiter = {self.total_cost}\n")

            if self.exploit['success'].lower() == "no":
                self.results = {"success": "False", "reason": 'Exploit was not generated!!!'}
                return
            
            if CTF_VERIFIER:
                os.environ['REPO_PATH'] = self.cve_info['repo_path']

                print("Time left: ", self.exploit['time_left'])
                
                print("\n########################################\n" \
                    "- b) 🛡️ CTF Verifier \n" \
                    "########################################\n")
                
                verifier_done = False
                try_itr, sanity_itr = 1, 1
                max_flag_tries, max_sanity_tries = 5, 5
                ctf_feedback = None

                while not verifier_done and try_itr <= max_flag_tries and sanity_itr <= max_sanity_tries:
                    self.check_time("verifier_build")

                    if ctf_feedback:
                        print("\n----------------------------------------\n" \
                            "- b) 🛡️ Feedback-Based CTF Verifier \n" \
                            "-------------------------------------------\n")
                
                    ctf_verifier = CTFVerifier(
                        project_dir_tree = self.cve_info['dir_tree'],
                        cve_knowledge = self.cve_knowledge,
                        project_overview = self.pre_reqs['overview'],
                        repo_build = self.repo_build,
                        exploit = self.exploit,
                        feedback = ctf_feedback
                    )
                    res = ctf_verifier.invoke().value
                    self.ctf_verifier = res
                    helper.save_response(self.cve_id, self.ctf_verifier, "ctf_verifier", struct=True)
                    print(f"✅ CTF Verifier Done!")

                    print("\n----------------------------------------\n" \
                        "- c) 🎯 Validator \n" \
                        "-------------------------------------------\n")

                    validator = Validator(
                        verifier = self.ctf_verifier['verifier']
                    )
                    check, val_log = validator.validate()

                    if check:
                        print("🎯 Flag found!")

                        if SANITY_CHECK:
                            print("\n----------------------------------------\n" \
                                "- d) 🧼 Verifier Critic Agent\n" \
                                "-------------------------------------------\n")
                            sanity_guy = SanityGuy(
                                cve_knowledge = self.cve_knowledge,
                                project_access = self.repo_build['access'],
                                exploit = self.exploit['exploit'],
                                poc = self.exploit['poc'],
                                verifier = self.ctf_verifier['verifier'],
                                validator_logs = val_log
                            )
                            sanity_guy_res = sanity_guy.invoke().value
                            helper.save_response(self.cve_id, sanity_guy_res, "verifier_critic", struct=True)
                            sanity_itr += 1

                            if sanity_guy_res['decision'].lower() == "no":
                                print("❌ Critic rejected the verifier!")

                                if not sanity_guy_res['steps_to_fix']:
                                    print("🚨 No Feedback!!")
                                    self.results = {"success": "False", "reason": 'No feedback to correct the verifier!!!'}
                                    return
                                
                                print("📋 Sending feedback to CTF Verifier!")
                                ctf_feedback = f"Previous Code: ```\n{self.ctf_verifier['verifier']}\n```\n\nProposed Fixes: '''\n{sanity_guy_res['steps_to_fix']}\n'''"
                                try_itr = 0
                            else:
                                verifier_done = True
                                helper.save_response(self.cve_id, self.ctf_verifier, "ctf_verifier", struct=True)
                                print("✅ Critic accepted the verifier!")
                            self.update_cost(sanity_guy.get_cost(), exception=True)
                        else:
                            verifier_done = True
                            helper.save_response(self.cve_id, self.ctf_verifier, "ctf_verifier", struct=True)
                            print("✅ CTF Verifier Done!")
                    else:
                        print("❌ Flag not found!")
                        print("📋 Sending output feedback to CTF Verifier ...")
                        ctf_feedback = f"Previous Code: ```\n{self.ctf_verifier['verifier']}\n```\n\nOutput Logs: '''\n{validator.feedback}\n'''"
                    try_itr += 1
                    self.update_cost(ctf_verifier.get_cost(), exception=True)
                        
                if not verifier_done:
                    print("❌ CTF Verifier failed!")
                    helper.save_response(self.cve_id, {"success": "no", "reason": "CTF Verifier failed"}, "ctf_verifier", struct=True)
                    self.results = {"success": "False", "reason": "CTF Verifier failed"}
                    return
                else:
                    print("✅ CTF Verifier Done!")
                    helper.save_ctf_script(self.cve_id, self.ctf_verifier['verifier'], self.exploit['poc'])
                    self.results = {"success": "True", "reason": "CTF Verifier done! CVE reproduced!"}

        except TimeoutExpired as e:
            print(f"ERROR: {e.message}")
            self.results = {"success": "False", "reason": e.message}
            raise

        except Exception as e:
            print(f"ERROR: {str(e)}")
            self.results = {"success": "False", "reason": str(e)}
        
        finally:
            pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Reproduce a CVE")
    parser.add_argument(
        "--cve",
        type=str,
        required=True,
        help="CVE ID",
        default='CVE-2024-4340'
    )
    parser.add_argument(
        "--json",
        type=str,
        required=False,
        default=None,
        help="Path to the cve json file (optional, will use cvelist if not provided)"
    )
    parser.add_argument(
        "--run-type",
        type=str,
        required=False,
        help="Comma-separated stages to execute: info, build, exploit, verify, fix (Legacy mode only)",
        default='build,exploit,verify'
    )
    parser.add_argument(
        "--dag",
        action="store_true",
        help="Use new DAG-based architecture (recommended for Web CVEs)"
    )
    parser.add_argument(
        "--browser-engine",
        type=str,
        choices=['selenium', 'playwright'],
        default='selenium',
        help="Browser engine for Web CVEs (DAG mode only)"
    )
    parser.add_argument(
        "--profile",
        type=str,
        choices=['native-local', 'web-basic', 'cloud-config', 'auto'],
        default='auto',
        help="Execution profile for DAG mode ('auto' to classify automatically)"
    )
    parser.add_argument(
        "--target-url",
        type=str,
        default=None,
        help="Pre-deployed target URL for Web CVEs (e.g., http://target-host:8080)"
    )
    args = parser.parse_args()

    # ========== DAG 模式 ==========
    if args.dag:
        print("🚀 Running in DAG mode (new architecture)")
        
        # 加载 CVE 数据
        if not args.json:
            parser.error("--json is required for DAG mode")
        
        if not os.path.exists(args.json):
            print(f"❌ Data file not found: {args.json}")
            sys.exit(1)
        
        import json
        with open(args.json, 'r', encoding='utf-8') as f:
            all_cve_data = json.load(f)
        
        if args.cve not in all_cve_data:
            print(f"❌ {args.cve} not found in {args.json}")
            sys.exit(1)
        
        cve_entry = all_cve_data[args.cve]
        
        # 导入新架构模块
        from planner.classifier import VulnerabilityClassifier
        from planner.dag import PlanBuilder
        from planner.executor import DAGExecutor
        from capabilities.registry import CapabilityRegistry
        
        # 设置日志 (使用挂载目录以便同步到本地)
        shared_dir = '/workspaces/submission/src/shared' if os.path.exists('/workspaces/submission/src') else '/shared'
        log_dir = os.path.join(shared_dir, args.cve)
        os.makedirs(log_dir, exist_ok=True)
        log_file = os.path.join(log_dir, f'{args.cve}_dag_log.txt')
        
        tee_logger = TeeLogger(log_file)
        original_stdout = sys.stdout
        original_stderr = sys.stderr
        sys.stdout = tee_logger
        sys.stderr = tee_logger
        
        print(f"{'='*60}")
        print(f"DAG Mode - CVE Reproduction")
        print(f"CVE ID: {args.cve}")
        print(f"Profile: {args.profile}")
        print(f"Browser Engine: {args.browser_engine}")
        print(f"Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Model: {os.environ['MODEL']}")
        print(f"{'='*60}\n")
        
        try:
            # 1. 分类
            classifier = VulnerabilityClassifier()
            decision = classifier.classify(args.cve, cve_entry, args.profile if args.profile != 'auto' else None)
            
            print(f"🔍 Vulnerability classified as: {decision.profile}")
            print(f"📋 Required capabilities: {', '.join(decision.required_capabilities)}")
            print(f"💡 Confidence: {decision.confidence:.2f}\n")
            
            # 2. 生成执行计划
            builder = PlanBuilder()
            plan = builder.build(decision)
            
            # 为 Web 漏洞注入浏览器引擎配置和目标 URL
            if decision.profile == 'web-basic':
                target_url = args.target_url or os.environ.get('WEB_DRIVER_TARGET_URL', 'http://localhost:9600')
                print(f"🎯 Target URL: {target_url}\n")
                
                for step in plan.steps:
                    if step.id == 'browser-provision':
                        step.config['engine'] = args.browser_engine
                        step.config['target_url'] = target_url
                    if step.id == 'deploy-env':
                        step.config['target_url'] = target_url
            
            print(f"📝 Execution plan generated with {len(plan.steps)} steps:\n")
            for step in plan.steps:
                deps = f" (depends on: {', '.join(step.inputs)})" if step.inputs else ""
                print(f"  - {step.id}: {step.capability}{deps}")
            print()
            
            # 3. 初始化能力注册表
            registry = CapabilityRegistry()
            result_bus = ResultBus(args.cve)
            
            # 4. 执行 DAG
            executor = DAGExecutor(plan, result_bus, registry)
            
            # 初始化初始数据（第一个步骤的输入）
            executor.artifacts['cve_id'] = args.cve
            executor.artifacts['cve_entry'] = cve_entry
            
            signal.signal(signal.SIGALRM, alarm_handler)
            signal.alarm(TIMEOUT)
            
            success = executor.execute()
            
            signal.alarm(0)
            
            # 5. 结果统计
            print(f"\n{'='*60}")
            print(f"Execution completed: {'✅ SUCCESS' if success else '❌ FAILED'}")
            print(f"Total cost: ${executor.total_cost:.4f}")
            print(f"End Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"{'='*60}")
            
            # 保存结果
            result_bus.record_run({
                'success': str(success),
                'cost': executor.total_cost,
                'model': os.environ['MODEL'],
                'profile': decision.profile,
                'browser_engine': args.browser_engine if decision.profile == 'web-basic' else 'N/A'
            })
            result_bus.sync_to_local()
            
        except TimeoutExpired as e:
            signal.alarm(0)
            print(f"\n{'='*60}")
            print(f"ERROR: {e.message}")
            print(f"{'='*60}")
        except Exception as e:
            signal.alarm(0)
            print(f"\n{'='*60}")
            print(f"ERROR: {str(e)}")
            import traceback
            traceback.print_exc()
            print(f"{'='*60}")
        finally:
            sys.stdout = original_stdout
            sys.stderr = original_stderr
            tee_logger.close()
            print(f"✅ Log saved to: {log_file}")
        
        sys.exit(0)
    
    # ========== Legacy 模式 ==========
    print("🔧 Running in Legacy mode (original architecture)\n")

    run_types = [token.strip().lower() for token in args.run_type.split(',') if token.strip()]
    allowed_run_types = {'info', 'build', 'exploit', 'verify', 'fix'}

    if not run_types:
        parser.error("--run-type must include at least one stage (info, build, exploit, verify, fix)")

    invalid_run_types = [stage for stage in run_types if stage not in allowed_run_types]
    if invalid_run_types:
        parser.error(f"Unsupported run-type values: {', '.join(invalid_run_types)}")

    if 'fix' in run_types and len(run_types) > 1:
        parser.error("'fix' run-type must be used alone. Run fix recommendations separately if needed.")

    if 'fix' in run_types and not args.json:
        parser.error("--json is required when using the 'fix' run-type.")

    if 'info' in run_types:
        CVE_INFO_GEN = True
    if 'build' in run_types:
        KB = True
        PRE_REQ = True
        REPO = True
        REPO_CRITIC = True
    if 'exploit' in run_types:
        EXPLOIT = True
        EXPLOIT_CRITIC = True
    if 'verify' in run_types:
        CTF_VERIFIER = True
        SANITY_CHECK = True
    if 'fix' in run_types:
        FIX_ADVISOR = True

    result_bus = ResultBus(args.cve)
    reproducer = CVEReproducer(args.cve, args.json, result_bus)
    
    # 设置日志文件 (使用挂载目录以便同步到本地)
    shared_dir = '/workspaces/submission/src/shared' if os.path.exists('/workspaces/submission/src') else '/shared'
    log_dir = os.path.join(shared_dir, args.cve)
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, f'{args.cve}_log.txt')
    
    # 创建 TeeLogger 实例，同时输出到终端和文件
    tee_logger = TeeLogger(log_file)
    original_stdout = sys.stdout
    original_stderr = sys.stderr
    sys.stdout = tee_logger
    sys.stderr = tee_logger
    
    # 记录开始时间
    print(f"{'='*60}")
    print(f"CVE Reproduction Log")
    print(f"CVE ID: {args.cve}")
    print(f"Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Model: {os.environ['MODEL']}")
    print(f"{'='*60}\n")
    
    signal.signal(signal.SIGALRM, alarm_handler)
    signal.alarm(TIMEOUT)
    
    try:
        reproducer.run()
    except Exception as e:
        signal.alarm(0)
        print(f"\n{'='*60}")
        print(f"ERROR: {str(e)}")
        print(f"{'='*60}")
    
    # 记录结束信息
    print(f"\n{'='*60}")
    print("Cost:", reproducer.total_cost)
    reproducer.results['cost'] = reproducer.total_cost
    reproducer.results['time'] = TIMEOUT - signal.alarm(0)
    reproducer.results['model'] = os.environ['MODEL']
    print("Results:", reproducer.results)
    print(f"End Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}")
    
    # 恢复原始输出并关闭日志文件
    sys.stdout = original_stdout
    sys.stderr = original_stderr
    tee_logger.close()
    
    print(f"✅ Log saved to: {log_file}")
    
    # 通过 ResultBus 统一保存结果并同步文件
    result_bus.record_run(reproducer.results)
    result_bus.sync_to_local()
