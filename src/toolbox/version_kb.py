"""
Version Mapping Knowledge Base Query Tool
用于查询跨语言库的版本映射关系，避免版本号幻觉
"""
import json
import os
from agentlib.lib import tools

# 加载版本映射知识库
KB_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'version_mapping_kb.json')

def _load_kb():
    """加载知识库文件"""
    try:
        with open(KB_PATH, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        return {"error": f"Failed to load knowledge base: {str(e)}"}

@tools.tool
def query_version_mapping(library_name: str, git_tag_version: str, target_language: str) -> str:
    """
    Query version mapping for cross-language libraries to get correct package manager version.
    
    This tool prevents version hallucination by providing accurate mappings between:
    - Git repository tags (e.g., v28.1)
    - Language-specific package versions (e.g., Maven 4.28.1, PyPI 5.28.1)
    
    **When to use:**
    - Before adding Maven/pip/npm dependencies with specific versions
    - When encountering "package not found" errors with version numbers
    - For libraries known to have different versioning across languages (protobuf, grpc, openssl)
    
    **Examples:**
    - query_version_mapping("protobuf", "v28.1", "maven") → "4.28.1"
    - query_version_mapping("protobuf", "v28.1", "python") → "5.28.1"
    - query_version_mapping("grpc", "v1.60.0", "maven") → "1.60.0"
    
    :param library_name: Library name (e.g., 'protobuf', 'grpc', 'openssl')
    :param git_tag_version: Git tag version from CVE data (e.g., 'v28.1', 'v1.60.0')
    :param target_language: Target language/package manager ('maven', 'python', 'npm', 'cpp', etc.)
    :return: Correct package version string or error message with guidance
    """
    kb = _load_kb()
    
    if "error" in kb:
        return kb["error"]
    
    # 标准化输入
    lib_key = library_name.lower().strip()
    lang_key = target_language.lower().strip()
    
    # 检查库是否存在
    if lib_key not in kb.get("libraries", {}):
        available = ", ".join(kb.get("libraries", {}).keys())
        return f"❌ Library '{library_name}' not found in knowledge base.\n\nAvailable libraries: {available}\n\nIf this is a new library, you may need to:\n1. Research its versioning scheme\n2. Verify versions on package registry\n3. Add to knowledge base for future use"
    
    lib_data = kb["libraries"][lib_key]
    
    # 检查目标语言是否存在
    if lang_key not in lib_data.get("version_schemes", {}):
        available_langs = ", ".join(lib_data.get("version_schemes", {}).keys())
        return f"❌ Target language '{target_language}' not found for {library_name}.\n\nAvailable mappings: {available_langs}"
    
    lang_data = lib_data["version_schemes"][lang_key]
    
    # 查找版本映射
    examples = lang_data.get("examples", {})
    if git_tag_version in examples:
        mapped_version = examples[git_tag_version]
        return f"""✅ Version Mapping Found:

Library: {lib_data.get('full_name', library_name)}
Git Tag: {git_tag_version}
Target: {target_language.upper()}
Mapped Version: **{mapped_version}**

Mapping Rule: {lang_data.get('mapping_rule', 'See examples')}
Verification URL: {lang_data.get('verification_url', 'N/A')}

Usage Example:
{_get_usage_example(lang_key, lib_data, mapped_version)}
"""
    
    # 如果精确版本未找到，提供映射规则
    return f"""⚠️ Exact version not in knowledge base, but here's the mapping rule:

Library: {lib_data.get('full_name', library_name)}
Git Tag: {git_tag_version}
Target: {target_language.upper()}

Mapping Rule: {lang_data.get('mapping_rule', 'Unknown')}
Pattern: {lang_data.get('pattern', 'Unknown')}

Known Examples:
{_format_examples(examples)}

**Action Required:**
1. Apply the mapping rule to calculate the version
2. Verify on package registry: {lang_data.get('verification_url', 'N/A')}
3. If version doesn't exist, try closest minor version

Common Mistakes for {library_name}:
{_format_mistakes(lib_data.get('common_mistakes', []))}
"""

def _get_usage_example(lang_key: str, lib_data: dict, version: str) -> str:
    """生成使用示例"""
    if lang_key == "maven":
        maven_data = lib_data["version_schemes"]["maven"]
        return f"""Maven (pom.xml):
<dependency>
    <groupId>{maven_data.get('group_id', 'UNKNOWN')}</groupId>
    <artifactId>{maven_data.get('artifact_id', 'UNKNOWN')}</artifactId>
    <version>{version}</version>
</dependency>"""
    elif lang_key == "python":
        python_data = lib_data["version_schemes"]["python"]
        pkg_name = python_data.get('package_name', 'UNKNOWN')
        return f"Python (requirements.txt):\n{pkg_name}=={version}"
    elif lang_key == "npm":
        return f"npm install {lib_data.get('package_name', 'UNKNOWN')}@{version}"
    else:
        return f"Version: {version}"

def _format_examples(examples: dict) -> str:
    """格式化示例列表"""
    if not examples:
        return "No examples available"
    lines = [f"  {git_tag} → {pkg_ver}" for git_tag, pkg_ver in list(examples.items())[:3]]
    return "\n".join(lines)

def _format_mistakes(mistakes: list) -> str:
    """格式化常见错误列表"""
    if not mistakes:
        return "None listed"
    return "\n".join([f"  - {m}" for m in mistakes])


@tools.tool
def list_known_libraries() -> str:
    """
    List all libraries in the version mapping knowledge base.
    
    Use this tool to check which libraries have known version mapping rules.
    
    :return: List of supported libraries with brief descriptions
    """
    kb = _load_kb()
    
    if "error" in kb:
        return kb["error"]
    
    libraries = kb.get("libraries", {})
    if not libraries:
        return "No libraries found in knowledge base"
    
    result = "📚 **Version Mapping Knowledge Base**\n\n"
    result += f"Total Libraries: {len(libraries)}\n\n"
    
    for lib_name, lib_data in libraries.items():
        result += f"**{lib_name.upper()}** - {lib_data.get('full_name', 'N/A')}\n"
        result += f"  Languages: {', '.join(lib_data.get('version_schemes', {}).keys())}\n"
        result += f"  Official: {lib_data.get('official_site', 'N/A')}\n\n"
    
    result += "\n**General Verification Tips:**\n"
    verification = kb.get("general_rules", {}).get("verification_before_use", {})
    for pkg_mgr, method in verification.items():
        result += f"  - {pkg_mgr.upper()}: {method}\n"
    
    return result
