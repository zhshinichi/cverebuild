#!/usr/bin/env python3
"""
Web CVE 分类器

用于从 data.json 中识别和筛选 Web 类型的漏洞。

Web 类型漏洞的特征：
1. CWE 类型：SQL注入、XSS、CSRF、SSRF、路径遍历、认证绕过等
2. 描述关键词：Web、HTTP、URL、API、endpoint、server、browser 等
3. 受影响组件：Flask、Django、Express、FastAPI、HTTP Server 等
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field


# 硬件相关的 CWE ID（这些漏洞通常无法用 Docker/源码复现）
HARDWARE_CWES = {
    'CWE-1188', # Insecure Default Initialization of Resource
    'CWE-1253', # Incorrect Selection of Fuse Values
    'CWE-1277', # Firmware Not Updateable
    'CWE-1304', # Improperly Preserved Integrity of Hardware Configuration State
    'CWE-1330', # Remanent Data Readable after Memory Erase
}

# Web 相关的 CWE ID
WEB_CWES = {
    # SQL 注入
    'CWE-89',   # SQL Injection
    'CWE-564',  # SQL Injection: Hibernate
    
    # XSS
    'CWE-79',   # Cross-site Scripting (XSS)
    'CWE-80',   # Basic XSS
    
    # CSRF
    'CWE-352',  # Cross-Site Request Forgery (CSRF)
    
    # SSRF
    'CWE-918',  # Server-Side Request Forgery (SSRF)
    
    # 认证/授权问题
    'CWE-287',  # Improper Authentication
    'CWE-306',  # Missing Authentication for Critical Function
    'CWE-285',  # Improper Authorization
    'CWE-639',  # Authorization Bypass Through User-Controlled Key
    'CWE-284',  # Improper Access Control
    
    # 路径遍历 / LFI / RFI
    'CWE-22',   # Path Traversal
    'CWE-23',   # Relative Path Traversal
    'CWE-29',   # Path Traversal: '\..\filename'
    'CWE-36',   # Absolute Path Traversal
    'CWE-73',   # External Control of File Name or Path
    'CWE-98',   # PHP Remote File Inclusion
    
    # 注入类
    'CWE-74',   # Injection
    'CWE-77',   # Command Injection
    'CWE-78',   # OS Command Injection
    'CWE-94',   # Code Injection
    'CWE-917',  # Expression Language Injection
    
    # 文件上传
    'CWE-434',  # Unrestricted Upload of File
    
    # 开放重定向
    'CWE-601',  # URL Redirection to Untrusted Site
    
    # XXE
    'CWE-611',  # XML External Entity Reference
    
    # 不安全的反序列化
    'CWE-502',  # Deserialization of Untrusted Data
    
    # 信息泄露
    'CWE-200',  # Information Disclosure
    'CWE-209',  # Error Message Information Leak
    'CWE-538',  # File and Directory Information Exposure
    
    # 默认凭证
    'CWE-1392', # Use of Default Credentials
    'CWE-798',  # Use of Hard-coded Credentials
    
    # 会话管理
    'CWE-384',  # Session Fixation
    'CWE-613',  # Insufficient Session Expiration
}

# Web 相关的描述关键词（正则表达式）
WEB_KEYWORDS_PATTERNS = [
    r'\bweb\s*(server|application|interface|service|ui)\b',
    r'\bhttp[s]?\b',
    r'\burl\b',
    r'\bapi\s*(endpoint|server)?\b',
    r'\bendpoint\b',
    r'\bbrowser\b',
    r'\bflask\b',
    r'\bdjango\b',
    r'\bexpress\b',
    r'\bfastapi\b',
    r'\buvicorn\b',
    r'\bnginx\b',
    r'\bapache\b',
    r'\bhtml\b',
    r'\bjavascript\b',
    r'\bcookie\b',
    r'\bsession\b',
    r'\bauth(entication|orization)?\b',
    r'\blogin\b',
    r'\bupload\b',
    r'\b(get|post|put|delete)\s+request\b',
    r'\bcors\b',
    r'\brest\s*api\b',
    r'\bgraphql\b',
    r'\bwebsocket\b',
    r'\bmlflow\b',
    r'\blollms\b',
    r'\bstreamlit\b',
    r'\bgradio\b',
    r'\bphp\b',
    r'\badmin\s*panel\b',
    r'/admin/',
]

# 硬件漏洞关键词（这些漏洞通常无法用 Docker/源码复现）
HARDWARE_KEYWORDS_PATTERNS = [
    r'\brouter\s*(firmware|backdoor)?\b',
    r'\bfirmware\b',
    r'\biot\s*(device)?\b',
    r'\bembedded\s*(system|device)?\b',
    r'\bgateway\s*(device)?\b',
    r'\bmodem\b',
    r'\bswitch\s*(device)?\b',
    r'\bhardware\b',
    r'\bsystem-on-chip\b',
    r'\bsoc\b',
    r'\btelnet\s*(backdoor|port 23)\b',
    r'\budp\s*port\s*\d+\s*(backdoor)?\b',
    r'\bbootloader\b',
    r'\bbios\b',
    r'\buefi\b',
    r'\bqemu\b',
    r'\bcamera\s*(firmware)?\b',
    r'\bnvr\b',
    r'\bdvr\b',
    r'\bsurveillance\b',
    r'\bnetcore\s*technology\b',
    r'\bnetis\b',
    r'\btp-link\b',
    r'\bd-link\b',
    r'\blinksys\b',
]


@dataclass
class WebCVEResult:
    """Web CVE 分类结果"""
    cve_id: str
    is_web: bool
    confidence: float  # 0.0 - 1.0
    reasons: List[str] = field(default_factory=list)
    cwe_matches: List[str] = field(default_factory=list)
    keyword_matches: List[str] = field(default_factory=list)
    has_deployable_source: bool = False
    data_quality_issue: Optional[str] = None
    is_hardware: bool = False  # 新增：是否为硬件漏洞
    hardware_reasons: List[str] = field(default_factory=list)  # 新增：硬件漏洞判定原因


class WebCVEClassifier:
    """Web CVE 分类器"""
    
    # CVE 报告仓库特征（这些仓库只包含漏洞报告，不是实际软件源码）
    CVE_REPORT_REPO_PATTERNS = [
        '/myCVE',      # f1rstb100d/myCVE, ting-06a/myCVE 等
        '/CVE-',       # CVE 报告仓库
        '/poc/',       # PoC 报告仓库
        '/cve/',       # CVE 报告
        '/Yu/',        # 特定的报告仓库
    ]
    
    def __init__(self):
        # 编译正则表达式以提高性能
        self.keyword_patterns = [
            (re.compile(pattern, re.IGNORECASE), pattern) 
            for pattern in WEB_KEYWORDS_PATTERNS
        ]
        self.hardware_patterns = [
            (re.compile(pattern, re.IGNORECASE), pattern)
            for pattern in HARDWARE_KEYWORDS_PATTERNS
        ]
    
    def _is_cve_report_repo(self, url: str) -> bool:
        """检测 URL 是否指向 CVE 报告仓库而非实际软件源码"""
        if not url:
            return False
        url_lower = url.lower()
        for pattern in self.CVE_REPORT_REPO_PATTERNS:
            if pattern.lower() in url_lower:
                return True
        return False
    
    def _check_data_quality(self, cve_entry: Dict) -> Tuple[bool, Optional[str]]:
        """
        检查 CVE 数据质量
        
        Returns:
            (has_deployable_source, issue_reason)
        """
        sw_version_wget = cve_entry.get("sw_version_wget", "")
        
        # 检查 1: sw_version_wget 为空
        if not sw_version_wget:
            return False, "No sw_version_wget - cannot auto-deploy"
        
        # 检查 2: sw_version_wget 指向 CVE 报告仓库
        if self._is_cve_report_repo(sw_version_wget):
            return False, "sw_version_wget points to CVE report repo, not actual software"
        
        return True, None
    
    def _check_cwe(self, cve_entry: Dict) -> List[str]:
        """检查 CWE 是否为 Web 类型"""
        cwe_list = cve_entry.get("cwe", [])
        matches = []
        for cwe in cwe_list:
            cwe_id = cwe.get("id", "")
            if cwe_id in WEB_CWES:
                matches.append(f"{cwe_id}: {cwe.get('value', '')}")
        return matches
    
    def _check_keywords(self, cve_entry: Dict) -> List[str]:
        """检查描述中是否包含 Web 相关关键词"""
        description = cve_entry.get("description", "").lower()
        matches = []
        for pattern, pattern_str in self.keyword_patterns:
            if pattern.search(description):
                matches.append(pattern_str)
        return matches
    
    def _check_sec_advisory(self, cve_entry: Dict) -> bool:
        """检查安全公告是否表明这是 Web 漏洞"""
        sec_adv = cve_entry.get("sec_adv", [])
        for adv in sec_adv:
            content = adv.get("content", "").lower()
            # 检查是否包含 HTTP 请求/响应示例
            if any(keyword in content for keyword in [
                'http request', 'http response', 'curl', 'post request', 
                'get request', 'localhost:', 'http://', 'https://'
            ]):
                return True
        return False
    
    def _check_hardware(self, cve_entry: Dict) -> Tuple[bool, List[str]]:
        """检测是否为硬件漏洞（无法用 Docker/源码复现）"""
        reasons = []
        
        # 1. 检查 CWE
        cwe_list = cve_entry.get("cwe", [])
        for cwe in cwe_list:
            cwe_id = cwe.get("id", "")
            if cwe_id in HARDWARE_CWES:
                reasons.append(f"Hardware CWE: {cwe_id} - {cwe.get('value', '')}")
        
        # 2. 检查描述关键词
        description = cve_entry.get("description", "").lower()
        for pattern, pattern_str in self.hardware_patterns:
            if pattern.search(description):
                reasons.append(f"Hardware keyword in description: {pattern_str}")
        
        # 3. 检查产品名称
        product = cve_entry.get("sw_name", "").lower()
        for pattern, pattern_str in self.hardware_patterns:
            if pattern.search(product):
                reasons.append(f"Hardware keyword in product name: {pattern_str}")
        
        # 4. 特殊检查：UDP 端口后门（典型的路由器固件后门）
        if re.search(r'udp\s*port\s*\d+', description, re.IGNORECASE):
            reasons.append("UDP port backdoor (typical router firmware vulnerability)")
        
        # 5. 检查模块信息（CVE 2.0 格式可能有）
        try:
            # 从原始 CVE 数据中提取 modules
            if 'modules' in str(cve_entry):
                if 'udp port' in str(cve_entry).lower():
                    reasons.append("Hardware module detected: UDP port service")
        except:
            pass
        
        return len(reasons) > 0, reasons
    
    def classify(self, cve_id: str, cve_entry: Dict) -> WebCVEResult:
        """
        分类单个 CVE 是否为 Web 类型
        
        Args:
            cve_id: CVE ID
            cve_entry: CVE 数据字典
            
        Returns:
            WebCVEResult 分类结果
        """
        reasons = []
        
        # 【优先检查】0. 硬件漏洞检测 - 如果是硬件漏洞，直接排除，不复现
        is_hardware, hardware_reasons = self._check_hardware(cve_entry)
        if is_hardware:
            return WebCVEResult(
                cve_id=cve_id,
                is_web=False,
                confidence=0.0,
                reasons=["[HARDWARE] This is a hardware vulnerability - cannot reproduce with Docker/source code"],
                is_hardware=True,
                hardware_reasons=hardware_reasons,
                has_deployable_source=False,
                data_quality_issue="Hardware vulnerability - requires physical device or firmware emulation"
            )
        
        # 1. 检查 CWE
        cwe_matches = self._check_cwe(cve_entry)
        if cwe_matches:
            reasons.append(f"CWE matches: {len(cwe_matches)} web-related CWEs")
        
        # 2. 检查关键词
        keyword_matches = self._check_keywords(cve_entry)
        if keyword_matches:
            reasons.append(f"Keyword matches: {len(keyword_matches)} patterns")
        
        # 3. 检查安全公告
        has_web_advisory = self._check_sec_advisory(cve_entry)
        if has_web_advisory:
            reasons.append("Security advisory contains HTTP examples")
        
        # 4. 检查数据质量
        has_deployable_source, data_quality_issue = self._check_data_quality(cve_entry)
        if not has_deployable_source:
            reasons.append(f"Data quality issue: {data_quality_issue}")
        
        # 计算置信度
        confidence = 0.0
        if cwe_matches:
            confidence += 0.4 * min(len(cwe_matches) / 2, 1.0)
        if keyword_matches:
            confidence += 0.3 * min(len(keyword_matches) / 3, 1.0)
        if has_web_advisory:
            confidence += 0.3
        
        # 判断是否为 Web 类型
        is_web = confidence >= 0.3 or len(cwe_matches) > 0
        
        return WebCVEResult(
            cve_id=cve_id,
            is_web=is_web,
            confidence=min(confidence, 1.0),
            reasons=reasons,
            cwe_matches=cwe_matches,
            keyword_matches=keyword_matches[:5],  # 只保留前5个
            has_deployable_source=has_deployable_source,
            data_quality_issue=data_quality_issue,
        )
    
    def classify_all(self, data: Dict) -> List[WebCVEResult]:
        """分类所有 CVE"""
        results = []
        for cve_id, cve_entry in data.items():
            result = self.classify(cve_id, cve_entry)
            results.append(result)
        return results


def analyze_web_cves(data_path: str, output_path: Optional[str] = None) -> Dict:
    """
    分析 data.json 中的 Web 类型 CVE
    
    Args:
        data_path: data.json 文件路径
        output_path: 可选的输出文件路径
        
    Returns:
        分析结果统计
    """
    # 加载数据
    with open(data_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    print(f"📊 Loaded {len(data)} CVEs from {data_path}")
    
    # 分类
    classifier = WebCVEClassifier()
    results = classifier.classify_all(data)
    
    # 统计
    web_cves = [r for r in results if r.is_web]
    deployable_web_cves = [r for r in web_cves if r.has_deployable_source]
    non_deployable_web_cves = [r for r in web_cves if not r.has_deployable_source]
    
    # 按置信度排序
    web_cves_sorted = sorted(web_cves, key=lambda x: x.confidence, reverse=True)
    
    # 输出结果
    print(f"\n{'='*60}")
    print(f"📈 Analysis Results")
    print(f"{'='*60}")
    print(f"Total CVEs: {len(data)}")
    print(f"Web CVEs: {len(web_cves)} ({len(web_cves)/len(data)*100:.1f}%)")
    print(f"  - Deployable: {len(deployable_web_cves)}")
    print(f"  - Non-deployable (data quality issues): {len(non_deployable_web_cves)}")
    
    # 高置信度 Web CVE
    high_confidence = [r for r in web_cves if r.confidence >= 0.7]
    print(f"\nHigh confidence Web CVEs (≥0.7): {len(high_confidence)}")
    
    # 显示前20个可部署的 Web CVE
    print(f"\n{'='*60}")
    print(f"🎯 Top 20 Deployable Web CVEs (sorted by confidence)")
    print(f"{'='*60}")
    
    for i, result in enumerate(deployable_web_cves[:20], 1):
        print(f"\n{i}. {result.cve_id} (confidence: {result.confidence:.2f})")
        print(f"   CWE: {', '.join(result.cwe_matches[:2]) if result.cwe_matches else 'N/A'}")
        print(f"   Keywords: {', '.join(result.keyword_matches[:3]) if result.keyword_matches else 'N/A'}")
    
    # 显示数据质量问题的 CVE
    print(f"\n{'='*60}")
    print(f"⚠️ Web CVEs with Data Quality Issues (top 10)")
    print(f"{'='*60}")
    
    for i, result in enumerate(non_deployable_web_cves[:10], 1):
        print(f"\n{i}. {result.cve_id}")
        print(f"   Issue: {result.data_quality_issue}")
    
    # 保存结果
    if output_path:
        output_data = {
            "summary": {
                "total": len(data),
                "web_cves": len(web_cves),
                "deployable": len(deployable_web_cves),
                "non_deployable": len(non_deployable_web_cves),
            },
            "deployable_web_cves": [
                {
                    "cve_id": r.cve_id,
                    "confidence": r.confidence,
                    "cwe_matches": r.cwe_matches,
                    "keyword_matches": r.keyword_matches,
                }
                for r in deployable_web_cves
            ],
            "non_deployable_web_cves": [
                {
                    "cve_id": r.cve_id,
                    "confidence": r.confidence,
                    "data_quality_issue": r.data_quality_issue,
                }
                for r in non_deployable_web_cves
            ],
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)
        print(f"\n✅ Results saved to: {output_path}")
    
    return {
        "total": len(data),
        "web_cves": len(web_cves),
        "deployable": len(deployable_web_cves),
        "non_deployable": len(non_deployable_web_cves),
        "results": results,
    }


def get_deployable_web_cve_ids(data_path: str) -> List[str]:
    """
    获取所有可部署的 Web CVE ID 列表
    
    这是一个便捷函数，可以在其他脚本中直接调用
    """
    result = analyze_web_cves(data_path)
    return [r.cve_id for r in result["results"] if r.is_web and r.has_deployable_source]


if __name__ == "__main__":
    import sys
    
    # 默认路径
    default_data_path = Path(__file__).parent.parent / "large_scale" / "data.json"
    
    data_path = sys.argv[1] if len(sys.argv) > 1 else str(default_data_path)
    output_path = sys.argv[2] if len(sys.argv) > 2 else None
    
    if not Path(data_path).exists():
        print(f"❌ File not found: {data_path}")
        sys.exit(1)
    
    analyze_web_cves(data_path, output_path)
