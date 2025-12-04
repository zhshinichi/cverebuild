"""
CVE Web漏洞筛选脚本
1. 从CVE JSON文件中筛选Web类型漏洞（100个）
2. 使用LLM判断复杂度，选出20个相对简单的漏洞进行复现
3. 输出格式与data.json一致，可直接用于CVE复现框架
"""

import os
import json
import re
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
import random

# LLM相关导入
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage


@dataclass
class CVEInfo:
    """CVE信息数据类"""
    cve_id: str
    description: str
    product: str
    vendor: str
    version: str
    cwe_ids: List[Dict[str, str]]  # 改为包含id和value的字典列表
    cvss_score: Optional[float]
    severity: Optional[str]
    references: List[str]
    file_path: str
    published_date: str = ""
    # 用于存储额外的原始数据
    raw_data: Dict = field(default_factory=dict)


# Web相关的CWE列表
WEB_RELATED_CWES = {
    # XSS相关
    "CWE-79",   # Cross-site Scripting (XSS)
    "CWE-80",   # Improper Neutralization of Script-Related HTML Tags
    
    # SQL注入
    "CWE-89",   # SQL Injection
    "CWE-564",  # SQL Injection: Hibernate
    
    # 命令注入
    "CWE-77",   # Command Injection
    "CWE-78",   # OS Command Injection
    
    # 路径遍历
    "CWE-22",   # Path Traversal
    "CWE-23",   # Relative Path Traversal
    "CWE-36",   # Absolute Path Traversal
    "CWE-29",   # Path Traversal: '\..\filename'
    
    # CSRF
    "CWE-352",  # Cross-Site Request Forgery (CSRF)
    
    # SSRF
    "CWE-918",  # Server-Side Request Forgery (SSRF)
    
    # 认证/授权
    "CWE-287",  # Improper Authentication
    "CWE-306",  # Missing Authentication for Critical Function
    "CWE-863",  # Incorrect Authorization
    "CWE-862",  # Missing Authorization
    "CWE-284",  # Improper Access Control
    
    # 信息泄露
    "CWE-200",  # Exposure of Sensitive Information
    "CWE-209",  # Error Message Information Leak
    "CWE-532",  # Information Exposure Through Log Files
    
    # 文件上传
    "CWE-434",  # Unrestricted Upload of File with Dangerous Type
    
    # 反序列化
    "CWE-502",  # Deserialization of Untrusted Data
    
    # 注入类
    "CWE-74",   # Injection
    "CWE-94",   # Code Injection
    "CWE-116",  # Improper Encoding or Escaping of Output
    
    # XML相关
    "CWE-611",  # XXE
    "CWE-91",   # XML Injection
    
    # LDAP注入
    "CWE-90",   # LDAP Injection
    
    # 模板注入
    "CWE-1336", # Server-Side Template Injection
    
    # 开放重定向
    "CWE-601",  # Open Redirect
    
    # Session相关
    "CWE-384",  # Session Fixation
    "CWE-613",  # Insufficient Session Expiration
    
    # 其他Web相关
    "CWE-400",  # Uncontrolled Resource Consumption
    "CWE-918",  # Server-Side Request Forgery
}

# Web相关关键词（用于描述匹配）
WEB_KEYWORDS = [
    # 漏洞类型
    "cross-site scripting", "xss", "sql injection", "sqli",
    "remote code execution", "rce", "command injection",
    "path traversal", "directory traversal", "lfi", "rfi",
    "csrf", "cross-site request forgery",
    "ssrf", "server-side request forgery",
    "xxe", "xml external entity",
    "authentication bypass", "authorization bypass",
    "file upload", "arbitrary file",
    "deserialization", "unserialize",
    "template injection", "ssti",
    "open redirect", "url redirect",
    "information disclosure", "sensitive data exposure",
    "ldap injection", "code injection",
    
    # Web技术关键词
    "web application", "web server", "web interface",
    "http", "https", "api", "rest api", "graphql",
    "html", "javascript", "json", "xml",
    "cookie", "session", "token", "jwt",
    "form", "input", "parameter", "query string",
    "url", "uri", "endpoint", "route",
    "request", "response", "header",
    "php", "asp", "jsp", "servlet",
    "django", "flask", "express", "node.js", "nodejs",
    "spring", "laravel", "rails", "ruby on rails",
    "wordpress", "drupal", "joomla", "cms",
    "apache", "nginx", "iis", "tomcat",
    "database", "mysql", "postgresql", "mongodb",
    "admin panel", "dashboard", "login", "portal",
    "upload", "download", "file manager",
]

# 产品关键词（表明是Web应用）
WEB_PRODUCT_KEYWORDS = [
    "wordpress", "drupal", "joomla", "magento",
    "prestashop", "opencart", "woocommerce",
    "phpbb", "vbulletin", "discourse",
    "gitlab", "github", "bitbucket",
    "jenkins", "bamboo", "teamcity",
    "grafana", "kibana", "prometheus",
    "nextcloud", "owncloud", "seafile",
    "moodle", "canvas", "blackboard",
    "roundcube", "zimbra", "horde",
    "phpMyAdmin", "adminer", "pgadmin",
    "webmin", "cpanel", "plesk",
    "api", "portal", "dashboard", "admin",
    "cms", "crm", "erp", "hrm",
    "plugin", "extension", "module", "addon",
    "theme", "template",
]


def parse_cve_json(file_path: str) -> Optional[CVEInfo]:
    """解析单个CVE JSON文件"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # 获取CVE ID
        cve_id = data.get("cveMetadata", {}).get("cveId", "")
        if not cve_id:
            return None
        
        # 检查状态
        state = data.get("cveMetadata", {}).get("state", "")
        if state != "PUBLISHED":
            return None
        
        # 获取发布日期
        published_date = data.get("cveMetadata", {}).get("datePublished", "")
        
        # 获取CNA容器
        cna = data.get("containers", {}).get("cna", {})
        if not cna:
            return None
        
        # 获取描述
        descriptions = cna.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break
        if not description and descriptions:
            description = descriptions[0].get("value", "")
        
        # 获取受影响产品信息
        affected = cna.get("affected", [])
        product = ""
        vendor = ""
        version = ""
        if affected:
            first_affected = affected[0]
            product = first_affected.get("product", "")
            vendor = first_affected.get("vendor", "")
            versions = first_affected.get("versions", [])
            if versions:
                v = versions[0]
                version = v.get("version", "") or v.get("lessThan", "")
        
        # 获取CWE IDs - 改为包含id和value的字典格式
        cwe_list = []
        problem_types = cna.get("problemTypes", [])
        for pt in problem_types:
            for desc in pt.get("descriptions", []):
                cwe_id = desc.get("cweId", "")
                cwe_desc = desc.get("description", "")
                if cwe_id:
                    cwe_list.append({
                        "id": cwe_id,
                        "value": f"{cwe_id} {cwe_desc}" if cwe_desc else cwe_id
                    })
        
        # 获取CVSS分数
        cvss_score = None
        severity = None
        metrics = cna.get("metrics", [])
        for metric in metrics:
            if "cvssV3_1" in metric:
                cvss_score = metric["cvssV3_1"].get("baseScore")
                severity = metric["cvssV3_1"].get("baseSeverity")
                break
            elif "cvssV4_0" in metric:
                cvss_score = metric["cvssV4_0"].get("baseScore")
                severity = metric["cvssV4_0"].get("baseSeverity")
                break
        
        # 获取引用链接
        references = []
        for ref in cna.get("references", []):
            url = ref.get("url", "")
            if url:
                references.append(url)
        
        return CVEInfo(
            cve_id=cve_id,
            description=description,
            product=product,
            vendor=vendor,
            version=version,
            cwe_ids=cwe_list,
            cvss_score=cvss_score,
            severity=severity,
            references=references,
            file_path=file_path,
            published_date=published_date,
            raw_data=data
        )
    except Exception as e:
        # print(f"Error parsing {file_path}: {e}")
        return None


def is_web_vulnerability(cve: CVEInfo) -> bool:
    """判断是否为Web类型漏洞"""
    # 1. 检查CWE是否为Web相关
    for cwe in cve.cwe_ids:
        cwe_id = cwe.get("id", "") if isinstance(cwe, dict) else cwe
        if cwe_id in WEB_RELATED_CWES:
            return True
    
    # 2. 检查描述中是否包含Web关键词
    desc_lower = cve.description.lower()
    for keyword in WEB_KEYWORDS:
        if keyword in desc_lower:
            return True
    
    # 3. 检查产品名是否为Web相关
    product_lower = cve.product.lower()
    for keyword in WEB_PRODUCT_KEYWORDS:
        if keyword in product_lower:
            return True
    
    return False


def collect_all_cve_files(base_path: str) -> List[str]:
    """收集所有CVE JSON文件路径"""
    cve_files = []
    base = Path(base_path)
    
    for json_file in base.rglob("CVE-*.json"):
        cve_files.append(str(json_file))
    
    return cve_files


def filter_web_cves(base_path: str, target_count: int = 100) -> List[CVEInfo]:
    """
    筛选Web类型CVE漏洞
    
    Args:
        base_path: CVE JSON文件所在的基础路径
        target_count: 目标筛选数量
        
    Returns:
        筛选出的CVE信息列表
    """
    print(f"正在收集CVE文件...")
    cve_files = collect_all_cve_files(base_path)
    print(f"共找到 {len(cve_files)} 个CVE文件")
    
    web_cves = []
    processed = 0
    
    print(f"正在筛选Web类型漏洞...")
    
    # 使用多线程加速解析
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(parse_cve_json, f): f for f in cve_files}
        
        for future in as_completed(futures):
            processed += 1
            if processed % 1000 == 0:
                print(f"已处理 {processed}/{len(cve_files)} 个文件，已找到 {len(web_cves)} 个Web漏洞")
            
            cve = future.result()
            if cve and is_web_vulnerability(cve):
                web_cves.append(cve)
                
                # 如果已经找到足够数量，可以提前停止
                # 但为了更好的多样性，我们继续处理所有文件
    
    print(f"\n筛选完成！共找到 {len(web_cves)} 个Web类型漏洞")
    
    # 如果找到的数量超过目标，随机选择
    if len(web_cves) > target_count:
        # 优先选择有明确CWE的漏洞
        cves_with_cwe = [c for c in web_cves if c.cwe_ids]
        cves_without_cwe = [c for c in web_cves if not c.cwe_ids]
        
        if len(cves_with_cwe) >= target_count:
            web_cves = random.sample(cves_with_cwe, target_count)
        else:
            need_more = target_count - len(cves_with_cwe)
            web_cves = cves_with_cwe + random.sample(cves_without_cwe, min(need_more, len(cves_without_cwe)))
    
    return web_cves[:target_count]


def evaluate_complexity_by_rules(cves: List[CVEInfo], select_count: int = 20) -> List[Dict]:
    """
    基于规则评估漏洞复杂度（当没有LLM API时使用）
    
    评分规则：
    - 开源软件优先（GitHub链接）
    - 简单漏洞类型优先（XSS, SQL注入等）
    - 无需认证的优先
    - 有明确版本号的优先
    """
    print("使用规则评估漏洞复杂度...")
    
    # 简单漏洞类型（容易复现）
    SIMPLE_CWES = {
        "CWE-79": 2,   # XSS - 很容易
        "CWE-89": 3,   # SQL注入 - 相对容易
        "CWE-22": 3,   # 路径遍历 - 相对容易
        "CWE-352": 4,  # CSRF - 中等
        "CWE-434": 4,  # 文件上传 - 中等
        "CWE-601": 3,  # 开放重定向 - 相对容易
        "CWE-78": 5,   # 命令注入 - 中等
        "CWE-94": 5,   # 代码注入 - 中等
        "CWE-862": 4,  # 缺少授权 - 中等
        "CWE-287": 5,  # 认证问题 - 中等偏难
        "CWE-502": 6,  # 反序列化 - 较难
        "CWE-611": 5,  # XXE - 中等
    }
    
    evaluated_cves = []
    
    for cve in cves:
        score = 5  # 默认中等复杂度
        reasons = []
        
        # 1. 检查是否有GitHub链接（开源软件更容易获取）
        github_refs = [r for r in cve.references if "github.com" in r.lower()]
        github_repo = ""
        if github_refs:
            score -= 2
            reasons.append("开源项目")
            # 尝试提取仓库地址
            for ref in github_refs:
                if "github.com/" in ref:
                    parts = ref.split("github.com/")[1].split("/")
                    if len(parts) >= 2:
                        github_repo = f"https://github.com/{parts[0]}/{parts[1]}"
                        break
        
        # 2. 检查CWE类型
        for cwe in cve.cwe_ids:
            cwe_id = cwe.get("id", "") if isinstance(cwe, dict) else cwe
            if cwe_id in SIMPLE_CWES:
                cwe_score = SIMPLE_CWES[cwe_id]
                if cwe_score < score:
                    score = cwe_score
                    reasons.append(f"简单漏洞类型({cwe_id})")
                break
        
        # 3. 检查是否有明确版本
        if cve.version and cve.version != "0":
            score -= 0.5
            reasons.append("有明确版本")
        
        # 4. 检查描述中是否有PoC相关词汇
        desc_lower = cve.description.lower()
        if any(word in desc_lower for word in ["poc", "proof of concept", "exploit", "payload"]):
            score -= 1
            reasons.append("可能有PoC")
        
        # 5. 检查是否需要认证
        if any(word in desc_lower for word in ["unauthenticated", "without authentication", "no authentication"]):
            score -= 1
            reasons.append("无需认证")
        elif any(word in desc_lower for word in ["authenticated", "requires authentication", "logged in"]):
            score += 1
            reasons.append("需要认证")
        
        # 确保分数在合理范围
        score = max(1, min(10, score))
        
        evaluated_cves.append({
            "cve": cve,
            "complexity_score": score,
            "reason": "; ".join(reasons) if reasons else "规则评估",
            "github_repo": github_repo,
            "recommended_version": cve.version
        })
    
    # 按复杂度分数排序（低分优先）
    evaluated_cves.sort(key=lambda x: x["complexity_score"])
    
    # 选出最简单的漏洞
    selected = evaluated_cves[:select_count]
    
    print(f"\n已选出 {len(selected)} 个相对简单的漏洞：")
    for item in selected:
        cve = item["cve"]
        print(f"  {cve.cve_id} (复杂度: {item['complexity_score']}) - {item['reason']}")
    
    return selected


def evaluate_complexity_with_llm(cves: List[CVEInfo], select_count: int = 20, api_key: str = None) -> List[Dict]:
    """
    使用LLM评估漏洞复杂度，选出相对简单的漏洞
    
    Args:
        cves: 待评估的CVE列表
        select_count: 最终选择数量
        api_key: OpenAI API密钥（可选，也可以通过环境变量OPENAI_API_KEY设置）
        
    Returns:
        选出的简单漏洞列表（包含复杂度评估信息）
    """
    print(f"\n正在使用LLM评估 {len(cves)} 个漏洞的复杂度...")
    
    # 直接使用配置的API密钥和base URL
    api_key = "sk-ziyWDSRgl3ymsBm3MWN8C5fPJwrzxaakqdsCYsWIB0dTqHmg"
    base_url = "https://api.openai-hub.com/v1"
    
    # 初始化LLM
    llm = ChatOpenAI(
        model="gpt-4o-mini",  # 使用较便宜的模型进行评估
        temperature=0,
        api_key=api_key,
        base_url=base_url
    )
    
    system_prompt = """你是一个安全漏洞复杂度评估专家。你需要评估给定CVE漏洞的复现复杂度。

评估标准（1-10分，分数越低越容易复现）：
1. 环境搭建难度：是否需要特殊配置、多个依赖服务、特定版本等
2. 漏洞触发难度：是否需要认证、特殊权限、复杂的利用链
3. 技术复杂度：漏洞原理是否清晰、是否有公开的PoC
4. 软件可获取性：受影响软件是否容易下载和部署（开源/免费优先）

请只返回一个JSON对象，格式如下：
{
    "score": <1-10的整数>,
    "reason": "<简短的评估理由，不超过50字>",
    "github_repo": "<如果能推断出GitHub仓库地址则填写，否则为空字符串>",
    "recommended_version": "<推荐测试的版本号>"
}"""

    evaluated_cves = []
    
    for i, cve in enumerate(cves):
        print(f"评估进度: {i+1}/{len(cves)} - {cve.cve_id}")
        
        # 尝试从引用中找到GitHub链接
        github_refs = [r for r in cve.references if "github.com" in r.lower()]
        cwe_str = ', '.join([c.get('id', '') for c in cve.cwe_ids]) if cve.cwe_ids else '未知'
        
        user_prompt = f"""请评估以下CVE漏洞的复现复杂度：

CVE ID: {cve.cve_id}
产品: {cve.product}
厂商: {cve.vendor}
版本: {cve.version}
CWE: {cwe_str}
CVSS分数: {cve.cvss_score if cve.cvss_score else '未知'}
严重性: {cve.severity if cve.severity else '未知'}

漏洞描述:
{cve.description}

参考链接:
{chr(10).join(cve.references[:5]) if cve.references else '无'}

GitHub相关链接:
{chr(10).join(github_refs[:3]) if github_refs else '无'}
"""
        
        try:
            response = llm.invoke([
                SystemMessage(content=system_prompt),
                HumanMessage(content=user_prompt)
            ])
            
            # 解析响应
            response_text = response.content.strip()
            # 处理可能的markdown代码块
            if "```json" in response_text:
                response_text = response_text.split("```json")[1].split("```")[0].strip()
            elif "```" in response_text:
                response_text = response_text.split("```")[1].split("```")[0].strip()
            
            result = json.loads(response_text)
            score = result.get("score", 10)
            reason = result.get("reason", "")
            github_repo = result.get("github_repo", "")
            recommended_version = result.get("recommended_version", cve.version)
            
            evaluated_cves.append({
                "cve": cve,
                "complexity_score": score,
                "reason": reason,
                "github_repo": github_repo,
                "recommended_version": recommended_version
            })
            
        except Exception as e:
            print(f"  评估失败: {e}")
            # 评估失败的给一个中等分数
            evaluated_cves.append({
                "cve": cve,
                "complexity_score": 5,
                "reason": "评估失败",
                "github_repo": "",
                "recommended_version": cve.version
            })
    
    # 按复杂度分数排序（低分优先）
    evaluated_cves.sort(key=lambda x: x["complexity_score"])
    
    # 选出最简单的漏洞
    selected = evaluated_cves[:select_count]
    
    print(f"\n已选出 {len(selected)} 个相对简单的漏洞：")
    for item in selected:
        cve = item["cve"]
        print(f"  {cve.cve_id} (复杂度: {item['complexity_score']}) - {item['reason']}")
    
    return selected


def convert_to_data_json_format(evaluated_cves: List[Dict]) -> Dict[str, Dict]:
    """
    将筛选结果转换为与data.json一致的格式
    
    Args:
        evaluated_cves: 评估后的CVE列表
        
    Returns:
        与data.json格式一致的字典
    """
    result = {}
    
    for item in evaluated_cves:
        cve = item["cve"]
        github_repo = item.get("github_repo", "")
        recommended_version = item.get("recommended_version", cve.version)
        
        # 构建sw_version_wget
        sw_version_wget = ""
        if github_repo:
            # 从GitHub仓库构建下载链接
            if github_repo.endswith("/"):
                github_repo = github_repo[:-1]
            if recommended_version:
                sw_version_wget = f"{github_repo}/archive/refs/tags/{recommended_version}.zip"
        
        # 构建patch_commits（从引用中提取GitHub commit链接）
        patch_commits = []
        for ref in cve.references:
            if "github.com" in ref and "/commit/" in ref:
                patch_commits.append({
                    "url": ref,
                    "content": ""  # 需要后续爬取
                })
        
        # 构建sec_adv（安全公告）
        sec_adv = []
        for ref in cve.references:
            # 识别常见的安全公告来源
            if any(domain in ref.lower() for domain in [
                "huntr.com", "security", "advisory", "cve.org",
                "nvd.nist.gov", "snyk.io", "github.com/security"
            ]):
                sec_adv.append({
                    "url": ref,
                    "content": "",  # 需要后续爬取
                    "effective": False,
                    "effective_reason": ""
                })
        
        # 如果没有找到安全公告，使用所有引用
        if not sec_adv and cve.references:
            for ref in cve.references[:3]:
                sec_adv.append({
                    "url": ref,
                    "content": "",
                    "effective": False,
                    "effective_reason": ""
                })
        
        result[cve.cve_id] = {
            "published_date": cve.published_date,
            "patch_commits": patch_commits,
            "sw_version": recommended_version or cve.version,
            "sw_version_wget": sw_version_wget,
            "description": cve.description,
            "sec_adv": sec_adv,
            "cwe": cve.cwe_ids,
            # 额外信息（方便后续处理）
            "_meta": {
                "product": cve.product,
                "vendor": cve.vendor,
                "cvss_score": cve.cvss_score,
                "severity": cve.severity,
                "complexity_score": item.get("complexity_score"),
                "complexity_reason": item.get("reason"),
                "github_repo": github_repo,
                "all_references": cve.references
            }
        }
    
    return result


def save_results_raw(cves: List[CVEInfo], output_file: str, stage: str = ""):
    """保存原始筛选结果到JSON文件"""
    results = []
    for cve in cves:
        results.append({
            "cve_id": cve.cve_id,
            "description": cve.description,
            "product": cve.product,
            "vendor": cve.vendor,
            "version": cve.version,
            "cwe_ids": cve.cwe_ids,
            "cvss_score": cve.cvss_score,
            "severity": cve.severity,
            "references": cve.references,
            "published_date": cve.published_date,
            "file_path": cve.file_path
        })
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    
    print(f"{stage}原始结果已保存到: {output_file}")


def save_results_formatted(data: Dict[str, Dict], output_file: str, stage: str = ""):
    """保存格式化的结果（与data.json格式一致）"""
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=4)
    
    print(f"{stage}格式化结果已保存到: {output_file}")


def print_summary(cves: List[CVEInfo], title: str = ""):
    """打印CVE摘要信息"""
    print(f"\n{'='*60}")
    print(f"{title}")
    print(f"{'='*60}")
    
    # CWE统计
    cwe_counter = {}
    for cve in cves:
        for cwe in cve.cwe_ids:
            cwe_id = cwe.get("id", "") if isinstance(cwe, dict) else cwe
            if cwe_id:
                cwe_counter[cwe_id] = cwe_counter.get(cwe_id, 0) + 1
    
    print(f"\n总数: {len(cves)}")
    
    if cwe_counter:
        print(f"\nCWE分布 (Top 10):")
        sorted_cwes = sorted(cwe_counter.items(), key=lambda x: -x[1])[:10]
        for cwe, count in sorted_cwes:
            print(f"  {cwe}: {count}")
    
    # 严重性分布
    severity_counter = {}
    for cve in cves:
        sev = cve.severity or "UNKNOWN"
        severity_counter[sev] = severity_counter.get(sev, 0) + 1
    
    print(f"\n严重性分布:")
    for sev, count in sorted(severity_counter.items()):
        print(f"  {sev}: {count}")
    
    print(f"\n前10个CVE:")
    for cve in cves[:10]:
        print(f"  {cve.cve_id}: {cve.product} - {cve.description[:80]}...")


def main():
    """主函数"""
    # 配置路径
    CVE_BASE_PATH = r"c:\Users\shinichi\submission\src\data\cvelist\2025"
    OUTPUT_DIR = r"c:\Users\shinichi\submission\src\data"
    
    # 确保输出目录存在
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    # 第一步：筛选100个Web类型漏洞
    print("="*60)
    print("第一步：筛选Web类型漏洞")
    print("="*60)
    
    web_cves = filter_web_cves(CVE_BASE_PATH, target_count=100)
    
    # 保存第一步原始结果
    step1_raw_output = os.path.join(OUTPUT_DIR, "web_cves_100_raw.json")
    save_results_raw(web_cves, step1_raw_output, "第一步")
    print_summary(web_cves, "第一步筛选结果：100个Web类型漏洞")
    
    # 第二步：使用LLM评估复杂度，选出20个简单漏洞
    print("\n" + "="*60)
    print("第二步：使用LLM评估复杂度")
    print("="*60)
    
    evaluated_cves = evaluate_complexity_with_llm(web_cves, select_count=20)
    
    # 转换为data.json格式
    formatted_data = convert_to_data_json_format(evaluated_cves)
    
    # 保存第二步结果（格式化版本，可直接用于框架）
    step2_output = os.path.join(OUTPUT_DIR, "simple_web_cves_20.json")
    save_results_formatted(formatted_data, step2_output, "第二步")
    
    # 同时保存原始评估结果
    step2_raw_output = os.path.join(OUTPUT_DIR, "simple_web_cves_20_raw.json")
    raw_results = []
    for item in evaluated_cves:
        cve = item["cve"]
        raw_results.append({
            "cve_id": cve.cve_id,
            "complexity_score": item["complexity_score"],
            "complexity_reason": item["reason"],
            "github_repo": item.get("github_repo", ""),
            "recommended_version": item.get("recommended_version", ""),
            "description": cve.description,
            "product": cve.product,
            "vendor": cve.vendor,
            "cwe_ids": cve.cwe_ids,
            "cvss_score": cve.cvss_score,
            "severity": cve.severity,
            "references": cve.references
        })
    with open(step2_raw_output, 'w', encoding='utf-8') as f:
        json.dump(raw_results, f, ensure_ascii=False, indent=2)
    print(f"第二步原始评估结果已保存到: {step2_raw_output}")
    
    print_summary([item["cve"] for item in evaluated_cves], "第二步筛选结果：20个简单Web漏洞")
    
    print("\n" + "="*60)
    print("筛选完成！")
    print(f"100个Web漏洞原始数据: {step1_raw_output}")
    print(f"20个简单漏洞（data.json格式）: {step2_output}")
    print(f"20个简单漏洞原始评估: {step2_raw_output}")
    print("="*60)
    print("\n注意：生成的data.json格式文件中，patch_commits和sec_adv的content字段为空，")
    print("需要后续使用爬虫工具获取详细内容。")


if __name__ == "__main__":
    main()
