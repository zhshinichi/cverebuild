#!/usr/bin/env python3
"""
测试日志功能的脚本
"""

import sys
import os
from datetime import datetime

class TeeLogger:
    """将输出同时写入终端和文件"""
    def __init__(self, log_file_path):
        self.terminal = sys.stdout
        self.log_file = open(log_file_path, 'w', encoding='utf-8', buffering=1)
    
    def write(self, message):
        self.terminal.write(message)
        self.log_file.write(message)
    
    def flush(self):
        self.terminal.flush()
        self.log_file.flush()
    
    def close(self):
        self.log_file.close()

# 测试
if __name__ == "__main__":
    # 创建测试目录
    test_dir = "test_log_output"
    os.makedirs(test_dir, exist_ok=True)
    log_file = os.path.join(test_dir, "test_log.txt")
    
    # 设置日志
    tee_logger = TeeLogger(log_file)
    original_stdout = sys.stdout
    original_stderr = sys.stderr
    sys.stdout = tee_logger
    sys.stderr = tee_logger
    
    # 测试输出
    print("="*60)
    print("Test Log Feature")
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60)
    print("\nThis is a test message.")
    print("This message should appear in both terminal and log file.")
    print("\nSimulating error output:")
    print("ERROR: This is a test error", file=sys.stderr)
    print("\n" + "="*60)
    print("Test completed!")
    print("="*60)
    
    # 恢复并关闭
    sys.stdout = original_stdout
    sys.stderr = original_stderr
    tee_logger.close()
    
    print(f"\n✅ Log saved to: {log_file}")
    print(f"📂 You can check the log file at: {os.path.abspath(log_file)}")
