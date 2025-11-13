import json
import os

# --- 配置 ---
input_file = '../large_scale/data.json'  # 你的主JSON文件名
output_dir = '../cve_files'  # 存放拆分后文件的目录名

# 新增限制：设置要生成的最大文件数
MAX_FILES_TO_GENERATE = 100 
# ------------

def split_cve_json_limited():
    """
    读取一个包含多个CVE条目的主JSON文件，
    并为每个CVE创建一个单独的JSON文件，直到达到设定的数量限制。
    """
    
    # 1. 确保输出目录存在
    if not os.path.exists(output_dir):
        try:
            os.makedirs(output_dir)
            print(f"已创建输出目录: {output_dir}")
        except OSError as e:
            print(f"错误: 创建目录 {output_dir} 失败。 {e}")
            return

    # 2. 读取主 data.json 文件
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            all_cve_data = json.load(f)
    except FileNotFoundError:
        print(f"错误: 未找到输入文件 '{input_file}'。请确保它在同一目录下。")
        return
    except json.JSONDecodeError:
        print(f"错误: 解析 '{input_file}' 中的JSON失败。文件格式可能已损坏。")
        return
    except Exception as e:
        print(f"读取文件时发生未知错误: {e}")
        return

    # 3. 遍历主文件中的每一个CVE条目 (键值对)
    count = 0
    print(f"开始处理 '{input_file}'...")
    print(f"*** 将最多生成 {MAX_FILES_TO_GENERATE} 个文件 ***")
    
    if not isinstance(all_cve_data, dict):
        print(f"错误: '{input_file}' 的顶层结构不是一个字典 (object)。")
        return

    for cve_id, cve_data in all_cve_data.items():
        
        # --- 新增的限制检查 ---
        if count >= MAX_FILES_TO_GENERATE:
            print(f"\n已达到 {MAX_FILES_TO_GENERATE} 个文件的生成限制。停止处理。")
            break  # 退出 for 循环
        # ---------------------

        # 构建新的数据结构，使其与您提供的示例格式一致
        # 即 { "CVE-ID": { ... } }
        output_data = {
            cve_id: cve_data
        }
        
        # 定义输出文件名
        output_filename = os.path.join(output_dir, f"{cve_id}.json")
        
        # 4. 写入单独的JSON文件
        try:
            with open(output_filename, 'w', encoding='utf-8') as f:
                # ensure_ascii=False 确保中文等非ASCII字符正确显示
                # indent=4 保持格式化，使其易于阅读
                json.dump(output_data, f, ensure_ascii=False, indent=4)
            print(f"  ({count + 1}/{MAX_FILES_TO_GENERATE}) 已创建: {output_filename}")
            count += 1 # 仅在成功创建文件后才增加计数
        except IOError as e:
            print(f"  > 错误: 无法写入文件 {output_filename}。 {e}")
        except Exception as e:
            print(f"  > 处理 {cve_id} 时发生未知错误: {e}")

    print(f"\n处理完成！")
    print(f"总共在 '{output_dir}' 目录中创建了 {count} 个CVE JSON文件。")

# --- 运行脚本 ---
if __name__ == "__main__":
    split_cve_json_limited()