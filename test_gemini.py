#!/usr/bin/env python3
"""测试 Gemini API 配置（通过 OpenAI 兼容接口）"""
import os
import sys
from dotenv import load_dotenv

# 加载环境变量
load_dotenv()

# 检查 API key
openai_key = os.getenv('OPENAI_API_KEY')
google_key = os.getenv('GOOGLE_API_KEY')

print("=" * 60)
print("API Key 检查:")
print(f"  OPENAI_API_KEY: {'✅ exists' if openai_key else '❌ missing'} (length: {len(openai_key) if openai_key else 0})")
print(f"  GOOGLE_API_KEY: {'✅ exists' if google_key else '❌ missing'} (length: {len(google_key) if google_key else 0})")
print("=" * 60)

if not google_key:
    print("❌ GOOGLE_API_KEY not found in environment")
    sys.exit(1)

# 测试模型注册
try:
    print("\n🔍 Testing model registry...")
    from src.agentlib.agentlib.lib.common.available_llms import ModelRegistry
    
    # 测试 GPT 模型
    gpt_name, gpt_class = ModelRegistry.get_llm_class_by_name('gpt-4o-mini')
    print(f"✅ GPT model: gpt-4o-mini -> {gpt_name}")
    print(f"   Class: {gpt_class.__name__}")
    
    # 测试 Gemini 模型
    gemini_name, gemini_class = ModelRegistry.get_llm_class_by_name('gemini-2.5-pro')
    print(f"✅ Gemini model: gemini-2.5-pro -> {gemini_name}")
    print(f"   Class: {gemini_class.__name__}")
    
except Exception as e:
    print(f"❌ Failed to load model: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# 测试实际调用
try:
    print("\n🧪 Testing Gemini API call...")
    print(f"   Using API key: {google_key[:10]}...{google_key[-10:]}")
    
    llm = gemini_class(
        model=gemini_name,
        temperature=0.5,
        base_url=os.getenv('OPENAI_API_BASE', 'https://api.openai-hub.com/v1')
    )
    
    response = llm.invoke("请用中文回复：你好，测试一下")
    print(f"✅ Gemini 响应: {response.content}")
    
except Exception as e:
    print(f"❌ API call failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

print("\n" + "=" * 60)
print("🎉 All tests passed! Gemini is ready to use.")
print("=" * 60)
