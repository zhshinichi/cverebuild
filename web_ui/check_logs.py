import sqlite3
import json

conn = sqlite3.connect('tasks.db')
cur = conn.cursor()
cur.execute('SELECT output FROM tasks WHERE task_id = 6')
row = cur.fetchone()

if row and row[0]:
    output = json.loads(row[0])
    print(f"Total lines: {len(output)}")
    
    # 显示最后100行
    print("\n=== Last 100 lines ===\n")
    for i, line in enumerate(output[-100:]):
        msg = line.get('message', '')
        print(f"{msg[:200]}")
else:
    print("No output found")
