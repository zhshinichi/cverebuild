#!/usr/bin/env python3
"""
清理 sec_adv 字段中的冗余内容，防止 token 超限
"""
import json
import sys
import os
from pathlib import Path


def truncate_sec_adv_content(content: str, max_length: int = 2000) -> str:
    """
    截取 sec_adv 内容，只保留关键的 PoC 和描述部分
    
    Args:
        content: 原始内容
        max_length: 最大保留长度
        
    Returns:
        截取后的内容
    """
    if len(content) <= max_length:
        return content
    
    # 尝试在合理的位置截断(在换行或句号处)
    truncated = content[:max_length]
    
    # 寻找最后一个完整的段落或句子
    for delimiter in ['\n\n', '\n', '. ', ' ']:
        last_pos = truncated.rfind(delimiter)
        if last_pos > max_length * 0.8:  # 至少保留 80% 的内容
            return truncated[:last_pos + len(delimiter)].strip() + "\n\n[Content truncated to reduce token usage]"
    
    return truncated.strip() + "\n\n[Content truncated to reduce token usage]"


def clean_cve_data(input_file: str, output_file: str, max_sec_adv_length: int = 2000):
    """
    清理 CVE 数据文件中的 sec_adv 字段
    
    Args:
        input_file: 输入文件路径
        output_file: 输出文件路径
        max_sec_adv_length: sec_adv content 的最大长度
    """
    print(f"Reading from: {input_file}")
    
    # 读取原始数据
    with open(input_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    total_cves = len(data)
    modified_count = 0
    total_saved_chars = 0
    
    print(f"Processing {total_cves} CVEs...")
    
    # 处理每个 CVE
    for cve_id, cve_data in data.items():
        if 'sec_adv' in cve_data and isinstance(cve_data['sec_adv'], list):
            for idx, adv in enumerate(cve_data['sec_adv']):
                if 'content' in adv and isinstance(adv['content'], str):
                    original_length = len(adv['content'])
                    
                    if original_length > max_sec_adv_length:
                        # 截取内容
                        adv['content'] = truncate_sec_adv_content(
                            adv['content'], 
                            max_sec_adv_length
                        )
                        new_length = len(adv['content'])
                        saved_chars = original_length - new_length
                        total_saved_chars += saved_chars
                        modified_count += 1
                        
                        print(f"  {cve_id}: Truncated sec_adv[{idx}] from {original_length} to {new_length} chars (saved {saved_chars} chars)")
    
    # 保存清理后的数据
    print(f"\nSaving cleaned data to: {output_file}")
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    
    # 输出统计信息
    print(f"\n{'='*60}")
    print(f"Processing Summary:")
    print(f"  Total CVEs: {total_cves}")
    print(f"  Modified entries: {modified_count}")
    print(f"  Total characters saved: {total_saved_chars:,}")
    print(f"  Average saved per modified entry: {total_saved_chars/modified_count if modified_count > 0 else 0:.0f} chars")
    print(f"{'='*60}")
    
    # 计算文件大小变化
    original_size = os.path.getsize(input_file)
    new_size = os.path.getsize(output_file)
    size_reduction = original_size - new_size
    reduction_pct = (size_reduction / original_size * 100) if original_size > 0 else 0
    
    print(f"\nFile Size:")
    print(f"  Original: {original_size:,} bytes ({original_size/1024/1024:.2f} MB)")
    print(f"  Cleaned:  {new_size:,} bytes ({new_size/1024/1024:.2f} MB)")
    print(f"  Reduced:  {size_reduction:,} bytes ({reduction_pct:.1f}%)")
    print(f"\n✅ Cleaned data saved successfully!")


def main():
    # 默认路径
    script_dir = Path(__file__).parent
    data_dir = script_dir.parent / "large_scale"
    
    input_file = data_dir / "data.json"
    output_file = data_dir / "data_clean.json"
    
    # 允许命令行参数覆盖
    if len(sys.argv) >= 2:
        input_file = Path(sys.argv[1])
    if len(sys.argv) >= 3:
        output_file = Path(sys.argv[2])
    
    # 检查输入文件是否存在
    if not input_file.exists():
        print(f"❌ Error: Input file not found: {input_file}")
        sys.exit(1)
    
    # 执行清理
    try:
        clean_cve_data(str(input_file), str(output_file))
    except Exception as e:
        print(f"\n❌ Error during processing: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
