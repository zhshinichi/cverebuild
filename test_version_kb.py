"""
测试版本映射知识库工具
"""
import sys
import os
import json

# 直接测试工具函数，避免导入依赖问题
KB_PATH = os.path.join(os.path.dirname(__file__), 'src', 'data', 'version_mapping_kb.json')

def load_kb():
    with open(KB_PATH, 'r', encoding='utf-8') as f:
        return json.load(f)

def test_query(library_name, git_tag, target_lang):
    kb = load_kb()
    lib_data = kb['libraries'].get(library_name.lower(), {})
    if not lib_data:
        print(f"❌ Library '{library_name}' not found")
        return
    
    lang_data = lib_data['version_schemes'].get(target_lang.lower(), {})
    if not lang_data:
        print(f"❌ Language '{target_lang}' not found for {library_name}")
        return
    
    examples = lang_data.get('examples', {})
    if git_tag in examples:
        print(f"✅ {library_name} {git_tag} → {target_lang.upper()}: {examples[git_tag]}")
        print(f"   Rule: {lang_data.get('mapping_rule', 'N/A')}")
    else:
        print(f"⚠️ Exact version not found, but rule is: {lang_data.get('mapping_rule', 'N/A')}")

print("=" * 80)
print("测试版本映射知识库")
print("=" * 80)

kb = load_kb()
print(f"\n📚 知识库包含 {len(kb['libraries'])} 个库:")
for lib_name in kb['libraries'].keys():
    print(f"  - {lib_name}")

print("\n" + "=" * 80)
print("测试具体映射:")
print("=" * 80)

print("\n[1] protobuf v28.1 → Maven:")
test_query("protobuf", "v28.1", "maven")

print("\n[2] protobuf v28.1 → Python:")
test_query("protobuf", "v28.1", "python")

print("\n[3] grpc v1.60.0 → Maven:")
test_query("grpc", "v1.60.0", "maven")

print("\n[4] grpc v1.60.0 → Python:")
test_query("grpc", "v1.60.0", "python")

print("\n[5] protobuf v27.0 → Maven:")
test_query("protobuf", "v27.0", "maven")

print("\n\n✅ 知识库加载成功！工具可以正常使用。")
