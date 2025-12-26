# 版本映射知识库 (Version Mapping Knowledge Base)

## 📋 概述

版本映射知识库用于解决跨语言库的版本号不一致问题，防止 AI Agent 产生"版本幻觉"。

### 问题示例

**CVE-2024-7254 失败原因：**
```
CVE 数据: "protobuf v28.1"
❌ Agent 错误理解: pip install protobuf==28.1  (包不存在!)
✅ 正确版本: pip install protobuf==5.28.1
```

### 解决方案

通过独立的 JSON 知识库 + Agent 工具调用，而非硬编码在提示词中：

1. **结构化存储**：[src/data/version_mapping_kb.json](src/data/version_mapping_kb.json)
2. **工具查询**：`query_version_mapping(library, git_tag, language)`
3. **动态扩展**：添加新库无需修改提示词

---

## 🛠️ Agent 使用方式

### 可用工具

#### 1. `list_known_libraries()`
列出所有支持的库及其语言映射。

**使用场景：**
- 不确定某个库是否需要版本映射
- 查看当前支持哪些库

**示例：**
```python
# Agent 调用
list_known_libraries()

# 输出
📚 Version Mapping Knowledge Base
Total Libraries: 3

PROTOBUF - Protocol Buffers
  Languages: git_tag, maven, python, cpp
  Official: https://github.com/protocolbuffers/protobuf
...
```

#### 2. `query_version_mapping(library_name, git_tag_version, target_language)`
查询特定库的版本映射。

**参数说明：**
- `library_name`: 库名称（如 `protobuf`, `grpc`, `openssl`）
- `git_tag_version`: Git 仓库标签（如 `v28.1`, `v1.60.0`）
- `target_language`: 目标语言/包管理器（如 `maven`, `python`, `npm`）

**使用流程：**
```python
# 1. CVE 提到 protobuf v28.1，需要构建 Java 环境
query_version_mapping("protobuf", "v28.1", "maven")

# 2. 工具返回
✅ Version Mapping Found:
Library: Protocol Buffers
Git Tag: v28.1
Target: MAVEN
Mapped Version: **4.28.1**

Mapping Rule: Git vXX.Y → Maven 4.XX.Y
Verification URL: https://mvnrepository.com/artifact/com.google.protobuf/protobuf-java

Usage Example:
Maven (pom.xml):
<dependency>
    <groupId>com.google.protobuf</groupId>
    <artifactId>protobuf-java</artifactId>
    <version>4.28.1</version>
</dependency>

# 3. Agent 使用正确版本生成 pom.xml
```

### 典型工作流

```
RepoBuilder Agent 任务：为 CVE-2024-7254 构建环境
└─ 1. 检测到需要 protobuf v28.1
   └─ 2. 调用 list_known_libraries() 确认 protobuf 在知识库中
      └─ 3. 调用 query_version_mapping("protobuf", "v28.1", "maven")
         └─ 4. 获取正确版本 4.28.1
            └─ 5. 生成正确的 pom.xml
               └─ 6. Maven 成功下载依赖 ✅
```

---

## 📚 知识库结构

### 文件位置
```
src/data/version_mapping_kb.json
```

### JSON 结构
```json
{
  "metadata": {
    "description": "版本映射知识库",
    "last_updated": "2025-12-24"
  },
  "libraries": {
    "protobuf": {
      "full_name": "Protocol Buffers",
      "official_site": "https://github.com/...",
      "version_schemes": {
        "git_tag": { "pattern": "vXX.Y", "examples": [...] },
        "maven": {
          "group_id": "com.google.protobuf",
          "artifact_id": "protobuf-java",
          "pattern": "4.XX.Y",
          "mapping_rule": "Git vXX.Y → Maven 4.XX.Y",
          "verification_url": "https://mvnrepository.com/...",
          "examples": {
            "v28.1": "4.28.1",
            "v27.0": "4.27.0"
          }
        },
        "python": { ... }
      },
      "common_mistakes": [
        "使用 git tag 版本作为 Maven 版本"
      ]
    }
  },
  "general_rules": {
    "verification_before_use": { ... }
  }
}
```

---

## ➕ 添加新库

### 示例：添加 OpenSSL 版本映射

```json
{
  "libraries": {
    "openssl": {
      "full_name": "OpenSSL",
      "official_site": "https://github.com/openssl/openssl",
      "version_schemes": {
        "git_tag": {
          "pattern": "openssl-X.Y.Z",
          "examples": ["openssl-3.0.8", "openssl-1.1.1w"]
        },
        "ubuntu_apt": {
          "package_name": "libssl-dev",
          "pattern": "X.Y.Z-XubuntuY",
          "mapping_rule": "Check apt-cache search for available versions",
          "examples": {
            "openssl-3.0.8": "libssl-dev (3.0.2-0ubuntu1.12)",
            "openssl-1.1.1": "libssl1.1"
          }
        },
        "build_from_source": {
          "mapping_rule": "Use git tag directly, strip 'openssl-' prefix",
          "examples": {
            "openssl-3.0.8": "./config --prefix=/usr/local"
          }
        }
      },
      "common_mistakes": [
        "期望 apt 中有精确版本（应使用最接近的版本）"
      ]
    }
  }
}
```

### 添加步骤

1. **研究版本规律**：
   - 查看 Git 标签格式
   - 检查 Maven Central / PyPI / npm 实际版本
   - 找出映射规则

2. **编辑 JSON 文件**：
   - 添加到 `libraries` 对象
   - 包含所有支持的语言/包管理器
   - 提供至少 3 个版本示例

3. **测试验证**：
   ```python
   query_version_mapping("新库名", "vX.Y.Z", "maven")
   ```

4. **更新元数据**：
   - 修改 `metadata.last_updated`
   - 在 commit 中说明添加的库

---

## 🔍 当前支持的库

### 1. Protocol Buffers (protobuf)
- **语言**: Java (Maven), Python (pip), C++
- **映射规则**: 
  - Git vXX.Y → Maven 4.XX.Y
  - Git vXX.Y → PyPI 5.XX.Y
- **验证**: [Maven Central](https://mvnrepository.com/artifact/com.google.protobuf/protobuf-java)

### 2. gRPC
- **语言**: Java (Maven), Python (pip)
- **映射规则**: Git vX.YY.Z → 移除 `v` 前缀
- **验证**: [Maven Central](https://mvnrepository.com/artifact/io.grpc/grpc-all)

### 3. OpenSSL
- **语言**: Ubuntu apt, 源码编译
- **映射规则**: 使用 apt-cache 查找最接近版本
- **注意**: apt 中的版本通常与 Git 标签不完全一致

---

## 🎯 设计优势

### 对比硬编码在提示词中

| 特性 | 提示词硬编码 | 独立知识库 |
|------|-------------|-----------|
| **提示词长度** | 每添加一个库增加 ~500 tokens | 始终只需 ~100 tokens 说明如何查询 |
| **可维护性** | 修改需要重新测试所有 Agent | 修改 JSON 即可，不影响 Agent 逻辑 |
| **可扩展性** | 受限于 token 限制 | 可无限扩展，按需加载 |
| **准确性** | LLM 可能记错硬编码规则 | 工具调用返回精确查询结果 |
| **复用性** | 仅限当前 Agent | 所有 Agent 可复用（RepoBuilder, RepoCritic...） |

### 关键特性

✅ **结构化存储**：JSON 格式便于程序和人类阅读  
✅ **按需查询**：只在需要时调用工具，不占用上下文  
✅ **易于扩展**：添加新库无需修改任何代码  
✅ **验证友好**：包含官方链接和使用示例  
✅ **错误恢复**：未找到精确版本时提供映射规则  

---

## 🧪 测试

运行测试脚本验证知识库：
```bash
python test_version_kb.py
```

**预期输出：**
```
📚 知识库包含 3 个库:
  - protobuf
  - grpc
  - openssl

[1] protobuf v28.1 → Maven:
✅ protobuf v28.1 → MAVEN: 4.28.1
   Rule: Git vXX.Y → Maven 4.XX.Y
...
```

---

## 📝 提示词集成

在 [repoBuilder.system.j2](../prompts/repoBuilder/repoBuilder.system.j2) 中：

```jinja
⚠️ CRITICAL: VERSION NUMBER VERIFICATION
   For cross-language libraries (protobuf, grpc, openssl, etc.):
   
   **ALWAYS use `query_version_mapping` tool first!**
   
   Example workflow:
   1. CVE mentions "protobuf v28.1"
   2. Call: query_version_mapping("protobuf", "v28.1", "maven")
   3. Tool returns: "4.28.1" ✅
   4. Use correct version in pom.xml
```

**优势：**
- 提示词简洁（仅 ~10 行）
- 指导工具使用而非直接提供答案
- Agent 自主决定何时查询

---

## 🚀 未来扩展

### 计划添加的库
- [ ] **numpy** (Python C API 版本差异)
- [ ] **tensorflow** (Python vs C++ 库版本)
- [ ] **boost** (系统包 vs Conan 版本)
- [ ] **nodejs** (Node vs npm 包版本)

### 计划功能
- [ ] 自动从 Maven/PyPI 抓取版本验证
- [ ] 支持版本范围查询（如 `v28.x` → 所有 28 系列）
- [ ] 集成到 RepoCritic 的依赖验证流程

---

## 📊 效果评估

### CVE-2024-7254 案例

**修复前：**
```
❌ pip install protobuf==28.1  (包不存在)
❌ 手动猜测 protobuf-java:3.28.0  (不存在)
❌ 死循环尝试 10+ 次
```

**修复后：**
```
✅ query_version_mapping("protobuf", "v28.1", "maven")
✅ 返回 4.28.1
✅ Maven 成功下载依赖
✅ 环境构建成功
```

**节省时间**：从 30+ 分钟失败 → 5 分钟成功

---

## 🤝 贡献指南

遇到新的版本映射问题？欢迎添加到知识库：

1. Fork 并编辑 `src/data/version_mapping_kb.json`
2. 添加新库或完善现有映射
3. 运行 `test_version_kb.py` 验证
4. 提交 PR 并说明添加原因

---

**维护者**: AI Agent 复现系统团队  
**最后更新**: 2025-12-24
