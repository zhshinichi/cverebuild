import json, os, subprocess
from data.scripts import cve_processor, scraper_utils

class CVEDataProcessor:
    def __init__(self, cve_id: str, cve_json: str = None):
        self.cve_id = cve_id
        self.cve_json = cve_json

    def knowledge_builder_setup(cve_path: str) -> dict:
        """
        Loads the cve json file from the given path
        """
        if not os.path.exists(cve_path):
            raise FileNotFoundError(f"❌ File not found at {cve_path}")
        return json.loads(open(cve_path, "r", encoding='utf-8').read())

    def pre_reqs_builder_setup(cve_info: dict) -> str:
        """
        Clones a repo to a the parent of given commit and returns the directory tree of the repo
        """
        cur_dir = os.getcwd()
        os.chdir("simulation_environments/")

        if not os.path.exists(cve_info["project"]):
            subprocess.run(f"git clone {cve_info['git_url']}.git", shell=True, timeout=300)
            os.chdir(cve_info["project"])
            subprocess.run(f"git checkout {cve_info['hash']}~1", shell=True, timeout=300)
        else:
            os.chdir(cve_info["project"])
        os.environ['REPO_PATH'] = f"{cve_info['project']}/"
        dir_tree = subprocess.run("tree -d", shell=True, capture_output=True).stdout.decode("utf-8")
        os.chdir(cur_dir)

        return dir_tree
    
    def run(self, code_url: str = "") -> dict:
        cur_dir = os.getcwd()
        # 1) If cache exists, load cve from cache
        if self.cve_json:
            # 智能选择数据源（容器内降级逻辑 + CVE不存在时继续尝试fallback）
            primary_data = self.cve_json
            # 修复：使用正确的绝对路径而不是相对路径
            fallback_data = "/workspaces/submission/src/data/large_scale/simple_web_cves_20.json"
            
            cve = None
            data_file = None
            
            # 尝试主数据源
            if os.path.exists(primary_data):
                print(f"[CVEDataProcessor] Checking primary data: {primary_data}")
                try:
                    cve = json.loads(open(primary_data, "r", encoding='utf-8').read()).get(self.cve_id)
                    if cve:
                        data_file = primary_data
                        print(f"[CVEDataProcessor] ✅ Found {self.cve_id} in primary data")
                    else:
                        print(f"[CVEDataProcessor] ⚠️ {self.cve_id} not in primary data, trying fallback...")
                except Exception as e:
                    print(f"[CVEDataProcessor] ⚠️ Error reading primary data: {e}")
            
            # 如果主数据源没找到CVE，尝试fallback
            if not cve and os.path.exists(fallback_data):
                print(f"[CVEDataProcessor] Checking fallback data: {fallback_data}")
                try:
                    cve = json.loads(open(fallback_data, "r", encoding='utf-8').read()).get(self.cve_id)
                    if cve:
                        data_file = fallback_data
                        print(f"[CVEDataProcessor] ✅ Found {self.cve_id} in fallback data")
                except Exception as e:
                    print(f"[CVEDataProcessor] ⚠️ Error reading fallback data: {e}")
            
            # 如果两个数据源都没找到CVE
            if not cve:
                error_msg = f"❌ {self.cve_id} not found in any data source\n"
                error_msg += f"   Checked: {primary_data}\n"
                if os.path.exists(fallback_data):
                    error_msg += f"   Checked: {fallback_data}"
                else:
                    error_msg += f"   Fallback not available: {fallback_data}"
                raise ValueError(error_msg)
        
        # 2) Load and process cve from the 'cvelist' repository
        else:
            # a) get raw cve json from the cvelist repo
            _cve = cve_processor.get_cve_by_id(self.cve_id)

            # b) get github url from patch commit
            patch_urls = _cve.get("patch_urls")
            if patch_urls:
                print(f"🔍 Found patch URLs: {patch_urls}")

                # 首先检查数据里是否已经有 sw_version 和 sw_version_wget
                if _cve.get("sw_version") and _cve.get("sw_version_wget"):
                    print(f"📦 Using pre-defined version: {_cve.get('sw_version')}")
                    cve = {
                        "published_date": _cve.get("published_date") or cve_processor.get_published_date(_cve['id']),
                        "patch_commits": _cve.get("patch_commits") or [
                            {
                                "url": patch['patch_commit_url'],
                                "content": cve_processor.get_patch_content(patch['owner'], patch['project'], patch['hash'])
                            }
                            for patch in _cve.get('patch_urls')
                        ],
                        "sw_version": _cve.get("sw_version"),
                        "sw_version_wget": _cve.get("sw_version_wget"),
                        "description": _cve.get('description'),
                        "sec_adv": _cve.get("sec_adv"),
                    }
                else:
                    # 尝试从 GitHub 获取版本 tag
                    version_data = _cve.get("version_data")
                    if version_data:
                        try:
                            version = cve_processor.get_software_versions(_cve['id'])[0]
                        except Exception as e:
                            version = (False, 'anomaly')
                        
                        tag = None
                        if version[1] != 'n/a' and version[1] != 'anomaly':
                            tag = cve_processor.affected_version_exist(patch_urls[0]['owner'], patch_urls[0]['project'], version[1], version[0])
                        
                        if tag:
                            cve = {
                                "published_date": cve_processor.get_published_date(_cve['id']),
                                "patch_commits": [
                                    {
                                        "url": patch['patch_commit_url'],
                                        "content": cve_processor.get_patch_content(patch['owner'], patch['project'], patch['hash'])
                                    }
                                    for patch in _cve.get('patch_urls')
                                ],
                                "sw_version": f"{tag}",
                                "sw_version_wget": f"{patch_urls[0]['repo_url']}/archive/refs/tags/{tag}.zip",
                                "description": _cve.get('description')
                            }
                        else:
                            raise ValueError(f"❌ We were not able to find the affected version tag in the repo. Please provide the code_url argument")
                    else:
                        raise ValueError(f"❌ No version_data found and no pre-defined sw_version. Please provide the code_url argument")

            else:
                if code_url:
                    cve = {
                        "published_date": cve_processor.get_published_date(_cve['id']),
                        "patch_commits": [],
                        "sw_version": "n/a",
                        "sw_version_wget": code_url,
                        "description": _cve.get('description')
                    }
                else:
                    raise ValueError(f"❌ We were not able to find patch URLs, so please provide the code_url argument")
                
            potential_advisories = _cve.get("other_urls")
            sec_advs = []
            if potential_advisories:
                keywords = ['security', 'advisory', 'advisories', 'bounties', 'bounty']
                for url in potential_advisories:
                    url_words = url.split('/')
                    if any(keyword in url_words for keyword in keywords):
                        sec_adv_content = scraper_utils.scrape(url)
                        sec_advs.append({
                                            "url": url,
                                            "content": sec_adv_content
                                        })
            cve['sec_advs'] = sec_advs

            cwe = _cve.get("cwe")
            if cwe:
                cve["cwe"] = [{"id": c['id'], "value": c['value']} for c in cwe]

        # 3) download the vulnerable tag version of the repo
        subprocess.run("rm -rf simulation_environments/*", shell=True)
        os.chdir("simulation_environments/")
        
        # 检查是否是 pip 包（新字段 pip_package）
        pip_package = cve.get('pip_package')
        pip_version = cve.get('pip_version')
        
        if pip_package and pip_version:
            # 对于 pip 包，使用 pip download 下载源代码
            print(f"📦 Detected pip package: {pip_package}=={pip_version}")
            print(f"📥 Downloading pip package source...")
            
            # 使用 pip download 获取源代码分发包
            pip_result = subprocess.run(
                f"pip download {pip_package}=={pip_version} --no-deps --no-binary :all: -d .",
                shell=True,
                capture_output=True,
                text=True
            )
            
            if pip_result.returncode != 0:
                # 如果没有源代码分发包，尝试下载 wheel
                print("⚠️ Source distribution not available, downloading wheel...")
                pip_result = subprocess.run(
                    f"pip download {pip_package}=={pip_version} --no-deps -d .",
                    shell=True,
                    capture_output=True,
                    text=True
                )
            
            if pip_result.returncode != 0:
                os.chdir(cur_dir)
                raise RuntimeError(f"Failed to download pip package {pip_package}=={pip_version}: {pip_result.stderr}")
            
            # 解压下载的包
            downloaded_files = os.listdir(".")
            print(f"📂 Downloaded files: {downloaded_files}")
            
            # 处理 .tar.gz 或 .whl 文件
            for file in downloaded_files:
                if file.endswith('.tar.gz'):
                    subprocess.run(f"tar xzf {file}", shell=True)
                elif file.endswith('.whl'):
                    subprocess.run(f"unzip {file} -d {pip_package.replace('-', '_')}", shell=True)
            
            # 找到解压后的目录
            dirs = [f for f in os.listdir(".") if os.path.isdir(f)]
            if not dirs:
                os.chdir(cur_dir)
                raise FileNotFoundError(f"No directory found after extracting pip package")
            
            dir_name = dirs[0]
            print(f"📂 Using directory: {dir_name}")
            os.chdir(dir_name)
            os.environ['REPO_PATH'] = f"{dir_name}/"
            
            # 更新 cve 信息
            cve['dir_tree'] = subprocess.run("tree -d", shell=True, capture_output=True).stdout.decode("utf-8")
            cve['repo_path'] = f"{dir_name}/"
            os.chdir(cur_dir)
            
            return cve
        
        download_url = cve['sw_version_wget']
        print(f"📥 Downloading from: {download_url}")
        
        # 准备 codeload 备用 URL（用于 GitHub archive 下载失败时）
        # https://github.com/user/repo/archive/refs/tags/v1.0.zip -> https://codeload.github.com/user/repo/zip/refs/tags/v1.0
        codeload_url = None
        if 'github.com' in download_url and '/archive/' in download_url:
            import re
            match = re.match(r'https://github\.com/([^/]+)/([^/]+)/archive/(.+)\.zip', download_url)
            if match:
                owner, repo, ref_path = match.groups()
                codeload_url = f"https://codeload.github.com/{owner}/{repo}/zip/{ref_path}"
        
        zip_filename = download_url.split('/')[-1] if download_url.endswith('.zip') else 'download.zip'
        
        # 优先尝试原始方式（wget）
        wget_result = subprocess.run(
            f"wget --timeout=120 --tries=3 '{download_url}'", 
            shell=True, 
            capture_output=True,
            text=True
        )
        
        download_success = wget_result.returncode == 0
        
        if not download_success:
            print(f"⚠️ wget failed with return code {wget_result.returncode}")
            print(f"stderr: {wget_result.stderr}")
            
            # 构建尝试列表：先正常 SSL，再忽略 SSL 验证（处理代理/MITM 环境）
            curl_attempts = []
            target_url = codeload_url if codeload_url else download_url
            curl_attempts.append((f"curl -sSL --connect-timeout 60 --max-time 300 -o {zip_filename} '{target_url}'", "curl with SSL"))
            curl_attempts.append((f"curl -sSL -k --connect-timeout 60 --max-time 300 -o {zip_filename} '{target_url}'", "curl with -k (insecure)"))
            
            for curl_cmd, desc in curl_attempts:
                print(f"🔄 Trying {desc}: {target_url}")
                curl_result = subprocess.run(
                    curl_cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=360
                )
                if curl_result.returncode == 0:
                    # 检查下载的文件是否有效（不为空）
                    if os.path.exists(zip_filename) and os.path.getsize(zip_filename) > 0:
                        print(f"✅ Download succeeded with {desc}")
                        download_success = True
                        break
                print(f"⚠️ {desc} failed: {curl_result.stderr}")
            
            if not download_success:
                os.chdir(cur_dir)
                raise RuntimeError(f"Failed to download {download_url}: all download methods failed")

        # 检查是否有 zip 文件
        zip_files = [file for file in os.listdir(".") if file.endswith(".zip")]
        if not zip_files:
            os.chdir(cur_dir)
            raise FileNotFoundError(f"No .zip file found after downloading from {download_url}. Directory contents: {os.listdir('.')}")
        
        zip_name = zip_files[0]
        print(f"📦 Found zip file: {zip_name}")
        subprocess.run(f"unzip {zip_name}", shell=True)

        # 检查是否有解压后的目录
        dirs = [file for file in os.listdir(".") if os.path.isdir(file)]
        if not dirs:
            os.chdir(cur_dir)
            raise FileNotFoundError(f"No directory found after unzipping {zip_name}. Directory contents: {os.listdir('.')}")
        
        # 🔧 修复：选择与 zip 文件名最匹配的目录，避免选择残留目录
        zip_base = zip_name.replace('.zip', '').lower()
        # 尝试找到匹配的目录
        matching_dirs = [d for d in dirs if zip_base in d.lower() or d.lower() in zip_base]
        if matching_dirs:
            dir_name = matching_dirs[0]
        else:
            # 没有匹配的，选择最新创建的目录（刚解压的）
            dirs_with_time = [(d, os.path.getctime(d)) for d in dirs]
            dirs_with_time.sort(key=lambda x: x[1], reverse=True)
            dir_name = dirs_with_time[0][0]
        
        print(f"📂 Using directory: {dir_name} (from {len(dirs)} dirs)")
        os.chdir(dir_name)
        os.environ['REPO_PATH'] = f"{dir_name}/"

        # Fix syntax error in Calibre 7.15.0 fts.py (missing comma)
        fts_file = "src/calibre/srv/fts.py"
        if os.path.exists(fts_file):
            with open(fts_file, 'r', encoding='utf-8') as f:
                content = f.read()
            # Fix: query = rd.query.get('query' '') -> query = rd.query.get('query', '')
            content = content.replace("rd.query.get('query' '')", "rd.query.get('query', '')")
            with open(fts_file, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"✅ Applied syntax fix to {fts_file}")

        # 4) get the directory tree of the repo
        cve['dir_tree'] = subprocess.run("tree -d", shell=True, capture_output=True).stdout.decode("utf-8")
        cve['repo_path'] = f"{dir_name}/"
        os.chdir(cur_dir)

        return cve
