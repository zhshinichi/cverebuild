# 安全工具Docker集成说明

## 快速安装

### Windows (PowerShell)
```powershell
cd src/toolbox/security_tools
.\install_tools.ps1
```

### Linux/Mac (Bash)
```bash
cd src/toolbox/security_tools
chmod +x install_tools.sh
./install_tools.sh
```

## 安装的工具

| 工具 | 镜像 | 用途 | 大小 |
|------|------|------|------|
| SQLmap | `parrotsec/sqlmap:latest` | SQL注入自动化利用 | ~150MB |
| WPScan | `wpscanteam/wpscan:latest` | WordPress漏洞扫描 | ~200MB |
| WhatWeb | `ilyaglow/whatweb:latest` | Web技术栈指纹识别 | ~100MB |
| Nikto | `securecodebox/scanner-nikto:latest` | 通用Web漏洞扫描 | ~50MB |
| ZAP (可选) | `owasp/zap2docker-stable:latest` | OWASP漏洞扫描器 | ~1.5GB |

**总大小**: ~500MB (不含ZAP) / ~2GB (含ZAP)

## 手动安装命令

如果自动脚本失败,可以手动运行:

```powershell
# 1. 拉取镜像
docker pull parrotsec/sqlmap:latest
docker pull wpscanteam/wpscan:latest
docker pull ilyaglow/whatweb:latest
docker pull securecodebox/scanner-nikto:latest
docker pull owasp/zap2docker-stable:latest  # 可选

# 2. 验证安装
docker images | Select-String -Pattern "sqlmap|wpscan|whatweb|nikto"

# 3. 测试运行
docker run --rm parrotsec/sqlmap --version
docker run --rm wpscanteam/wpscan --version
docker run --rm ilyaglow/whatweb --version
```

## 使用示例

### SQLmap - SQL注入测试
```bash
# 基础扫描
docker run --rm --network host parrotsec/sqlmap \
  -u "http://192.168.1.100:8080/vulnerable.php?id=1" \
  --batch --level=1 --risk=1

# 指定数据库类型
docker run --rm --network host parrotsec/sqlmap \
  -u "http://target:8080/?id=1" \
  --dbms=mysql --batch --dump

# POST请求注入
docker run --rm --network host parrotsec/sqlmap \
  -u "http://target/login.php" \
  --data="username=admin&password=test" \
  --batch
```

### WPScan - WordPress扫描
```bash
# 基础扫描
docker run --rm --network host wpscanteam/wpscan \
  --url http://192.168.1.100:8080 \
  --enumerate p,t,u

# 指定插件扫描
docker run --rm --network host wpscanteam/wpscan \
  --url http://target \
  --enumerate vp --plugins-detection aggressive

# 使用API Token (提高准确率)
docker run --rm --network host wpscanteam/wpscan \
  --url http://target \
  --api-token YOUR_API_TOKEN \
  --enumerate ap,at,u
```

### WhatWeb - 技术栈识别
```bash
# 快速指纹识别
docker run --rm --network host ilyaglow/whatweb \
  http://192.168.1.100:8080

# 详细模式
docker run --rm --network host ilyaglow/whatweb \
  -v http://target:8080

# JSON输出
docker run --rm --network host ilyaglow/whatweb \
  --log-json=- http://target
```

### Nikto - Web漏洞扫描
```bash
# 基础扫描
docker run --rm --network host securecodebox/scanner-nikto \
  -h 192.168.1.100 -p 8080

# 扫描特定路径
docker run --rm --network host securecodebox/scanner-nikto \
  -h target:8080 -root /admin/
```

## 网络配置说明

使用 `--network host` 的原因:
- 工具容器需要访问其他Docker容器中的漏洞环境
- `host`模式让工具直接访问宿主机网络,可以用容器名/localhost访问
- 如果漏洞环境在自定义网络,需要改用: `--network vuln_network`

## 输出目录

所有工具的输出保存在: `src/toolbox/security_tools/output/`

## 常见问题

### 1. Docker未运行
```
Error: Cannot connect to the Docker daemon
```
**解决**: 启动Docker Desktop

### 2. 网络连接问题
```
Error: Could not resolve host
```
**解决**: 检查目标容器是否运行,确认网络配置

### 3. 权限问题 (Linux)
```
Permission denied
```
**解决**: 
```bash
sudo usermod -aG docker $USER
# 重新登录或运行: newgrp docker
```

## 下一步

工具安装完成后,系统会自动集成到:
- `WebScannerCapability` - 自动调用SQLmap/WPScan/Nikto
- `WebFingerprintCapability` - 自动调用WhatWeb识别技术栈
- `FreestyleAgent` - 根据CVE类型智能选择工具
