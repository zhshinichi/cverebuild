# CVE Information Generator Agent

## 功能说明

`CVEInfoGenerator` 是一个专门用于生成 CVE 漏洞信息摘要的 Agent。它会分析给定的 CVE 数据，并生成包含以下内容的结构化报告:

1. **受影响的软件** (Affected Software)
   - 受影响的软件包/应用程序
   - 具体的版本范围
   - 软件类型

2. **漏洞类型** (Vulnerability Type)
   - CWE 分类
   - 漏洞类别(如路径穿越、SQL注入、远程代码执行等)
   - CVSS 严重性评分

3. **漏洞机制** (Vulnerability Mechanism)
   - 漏洞的根本原因
   - 代码层面的技术细节
   - 修复补丁的说明

4. **触发条件** (Trigger Conditions)
   - 利用漏洞的前提条件
   - 攻击向量
   - 触发步骤
   - PoC 信息(如果可用)

## 使用方法

### 基本用法

```bash
python src/main.py --cve CVE-2024-4340 --run-type info
```

### 参数说明

- `--cve`: CVE 编号(必需)
- `--run-type info`: 指定只生成 CVE 信息(不进行完整的漏洞复现)
- `--json`: 可选,指定包含 CVE 数据的 JSON 文件路径

### 输出位置

生成的信息会保存在: `/shared/{CVE_ID}/{CVE_ID}_info.txt`

例如: `/shared/CVE-2024-4340/CVE-2024-4340_info.txt`

## 使用示例

### 示例 1: 使用数据库中的 CVE

```bash
python src/main.py --cve CVE-2024-4340 --run-type info
```

### 示例 2: 使用自定义 JSON 文件

```bash
python src/main.py --cve CVE-2024-4340 --json src/data/example/data.json --run-type info
```

### 示例 3: 在 Docker 容器中运行

```bash
docker exec <container_name> python /app/src/main.py --cve CVE-2024-4340 --run-type info
```

## 输出示例

生成的文本文件将包含如下结构的内容:

```
CVE Information Summary
Generated at: 2025-11-17 10:30:00
============================================================

## 1. AFFECTED SOFTWARE
- sqlparse (Python library)
- Versions: < 0.5.0
- Type: SQL parsing library

## 2. VULNERABILITY TYPE
- CWE-674: Uncontrolled Recursion
- Classification: Denial of Service (DoS)
- CVSS Score: 7.5 (High)

## 3. VULNERABILITY MECHANISM
The vulnerability exists in the flatten() method of the TokenList class...
[详细的技术说明]

## 4. TRIGGER CONDITIONS
- No authentication required
- Attack Vector: Network
- PoC:
  ```python
  import sqlparse
  sqlparse.parse('[' * 10000 + ']' * 10000)
  ```
[详细的触发步骤]
```

## 集成到现有工作流

该功能可以与现有的漏洞复现流程结合使用:

1. **仅生成信息**: `--run-type info`
2. **构建+利用**: `--run-type build,exploit`
3. **完整流程**: `--run-type build,exploit,verify`

## 技术细节

- **LLM Model**: o4-mini (可在 .env 中配置)
- **输入**: CVE 数据(描述、CWE、补丁、安全公告等)
- **输出**: 结构化的文本报告
- **成本**: 根据实际 token 使用量计算(通常 < $0.01)

## 文件结构

```
src/
├── agents/
│   ├── cveInfoGenerator.py          # Agent 实现
│   └── __init__.py                   # 导出 Agent
├── prompts/
│   └── cveInfoGenerator/
│       ├── cveInfoGenerator.system.j2  # 系统提示词
│       └── cveInfoGenerator.user.j2    # 用户提示词
└── main.py                           # 集成入口
```

## 注意事项

1. 需要有效的 OpenAI API key (在 .env 文件中配置)
2. 确保 `/shared` 目录有写权限
3. 生成的信息质量取决于输入的 CVE 数据完整性
4. 如果安全公告或补丁信息缺失,部分内容可能显示 "Information not available"
