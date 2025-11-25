# 漏洞修复模块设计文档

## 概述
为 CVE 复现系统添加漏洞修复功能,形成完整的漏洞生命周期管理。

## 模块架构

### 1. FixAdvisor (修复建议生成器) - 已实现
**文件**: `src/agents/fixAdvisor.py`

**功能**:
- 基于官方补丁生成中文修复建议报告
- 提供替代修复方案
- 输出测试验证方法
- 安全配置建议

**使用方式**:
```python
# 在 main.py 中添加 fix 命令
if args.command == "fix":
    # 1. 加载 CVE 数据
    cve_data = load_cve_data(args.cve, args.json)
    
    # 2. 准备输入数据
    cwe = '\n'.join([f"* {c['id']} - {c['value']}" for c in cve_data.get("cwe", [])])
    patches = '\n\n'.join([f"### Commit: {p['url'].split('/')[-1]}\n```\n{p['content']}\n```" 
                          for p in cve_data.get("patch_commits", [])])
    
    # 3. 调用 FixAdvisor
    fix_advisor = FixAdvisor(
        cve_id=args.cve,
        vulnerability_type="Path Traversal",  # 从 CWE 推断
        cwe=cwe,
        description=cve_data.get("description"),
        vulnerable_code="从 simulation_environments 提取",
        patch_content=patches,
        reproduction_success=True  # 从 results.csv 读取
    )
    
    fix_report = fix_advisor.invoke().value
    
    # 4. 保存报告
    with open(f'/shared/{args.cve}/{args.cve}_fix_report.md', 'w') as f:
        f.write(fix_report)
```

### 2. 未来扩展方向

#### 2.1 PatchApplier (补丁应用器)
**目标**: 自动将修复应用到易受攻击的代码

```python
class PatchApplier(Agent):
    """
    智能补丁应用:
    1. 分析补丁的 diff
    2. 定位易受攻击代码中的对应位置
    3. 应用修改(考虑版本差异)
    4. 生成修复后的代码
    """
```

**实现思路**:
- 使用 AST 解析找到需要修改的函数/类
- LLM 理解补丁意图,适配到不同版本
- 生成 unified diff 或直接输出修复后的文件

#### 2.2 RegressionTester (回归测试器)
**目标**: 验证修复效果

```python
class RegressionTester(Agent):
    """
    修复验证:
    1. 重新运行原有的 exploit
    2. 验证漏洞是否被修复
    3. 运行功能测试确保无副作用
    4. 生成测试报告
    """
```

**实现思路**:
- 保存原始的 exploit 脚本
- 应用补丁后重新执行
- 比较修复前后的行为差异
- 如果有单元测试,自动运行

#### 2.3 SecurityHardener (安全加固器)
**目标**: 全面的安全加固建议

```python
class SecurityHardener(Agent):
    """
    超越单个漏洞的系统性加固:
    1. 扫描整个项目的潜在风险
    2. 配置安全检查工具(bandit, semgrep)
    3. 生成 CI/CD 安全门禁配置
    4. 依赖项安全审计
    """
```

## 命令行接口设计

```bash
# 生成修复建议
python main.py --cve CVE-2024-2928 --json data.json --command fix

# 应用修复(未来)
python main.py --cve CVE-2024-2928 --json data.json --command apply-fix

# 验证修复(未来)
python main.py --cve CVE-2024-2928 --json data.json --command verify-fix

# 完整流程(未来)
python main.py --cve CVE-2024-2928 --json data.json --command full-cycle
# 等价于: info -> reproduce -> fix -> apply -> verify
```

## 数据流设计

```
CVE 数据 (data.json)
  ↓
info 命令 → CVE_info.txt
  ↓
reproduce 命令 → reproduction_log.txt + success/fail
  ↓
fix 命令 → fix_report.md
  ↓
apply-fix 命令 → patched_code/ 
  ↓
verify-fix 命令 → verification_report.txt
```

## 优先级建议

### P0 (立即实现)
- [x] FixAdvisor 基础实现
- [ ] 集成到 main.py 作为新命令
- [ ] 测试生成修复建议报告的质量

### P1 (短期)
- [ ] PatchApplier 原型
- [ ] 简单的修复验证(重新运行 exploit)
- [ ] 支持从 results.csv 读取复现状态

### P2 (中期)
- [ ] RegressionTester 完整实现
- [ ] 支持多种语言的补丁应用
- [ ] 修复前后的对比可视化

### P3 (长期)
- [ ] SecurityHardener 系统性加固
- [ ] 机器学习辅助的修复方案排序
- [ ] 与 IDE 集成(VS Code 插件)

## 技术挑战

1. **版本适配**: 官方补丁可能基于不同版本,需要智能适配
2. **测试覆盖**: 如何确保修复不引入新问题
3. **代码理解**: LLM 需要深度理解代码语义
4. **多语言支持**: Python, JavaScript, Java 等不同语言的处理

## 研究价值

这个模块可以支撑以下研究方向:
1. **自动化漏洞修复**: LLM 在安全领域的应用
2. **补丁适配**: 跨版本的补丁迁移
3. **修复验证**: 形式化验证 + 测试的结合
4. **知识图谱**: 构建 CVE-CWE-Fix 的知识库
