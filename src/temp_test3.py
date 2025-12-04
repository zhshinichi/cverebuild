from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
import time

options = Options()
options.add_argument('--headless')
options.add_argument('--no-sandbox')
options.add_argument('--disable-dev-shm-usage')

driver = webdriver.Chrome(options=options)
driver.get('http://172.17.0.3:5678/chat/test-webhook')
time.sleep(10)

# 检查页面上所有文本内容
html = driver.page_source

# 检查是否有 Welcome 文字
if 'Welcome' in html:
    print('=== Found Welcome in page')
    idx = html.find('Welcome')
    print(html[idx:idx+200])
else:
    print('=== Welcome NOT found')

# 检查是否有 XSS_PROOF
if 'XSS_PROOF' in html:
    print('=== Found XSS_PROOF in page!')
else:
    print('=== XSS_PROOF NOT found')

# 检查 onerror
if 'onerror' in html:
    print('=== Found onerror in page!')
else:
    print('=== onerror NOT found')

# 尝试查看 n8n 的全局变量
try:
    config = driver.execute_script('return window.n8nChat || window.__n8n__ || {}')
    print('=== n8n config:', config)
except Exception as e:
    print('=== Error getting config:', e)

# 保存完整页面用于分析
with open('/workspaces/submission/src/simulation_environments/chat_page.html', 'w') as f:
    f.write(html)
print('=== Saved page to chat_page.html')

driver.quit()
