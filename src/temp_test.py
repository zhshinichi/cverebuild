from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
import requests
import time

options = Options()
options.add_argument('--headless')
options.add_argument('--no-sandbox')
options.add_argument('--disable-dev-shm-usage')

driver = webdriver.Chrome(options=options)

# 访问 n8n
driver.get('http://172.17.0.3:5678')
time.sleep(3)
print('Current URL:', driver.current_url)

# 如果需要登录
if '/signin' in driver.current_url:
    print('Login page detected')
    time.sleep(2)
    inputs = driver.find_elements(By.CSS_SELECTOR, 'input')
    for inp in inputs:
        try:
            inp_type = inp.get_attribute('type') or ''
            if inp_type == 'email':
                inp.clear()
                inp.send_keys('admin@test.local')
            elif inp_type == 'password':
                inp.clear()
                inp.send_keys('Admin123!')
        except:
            pass
    
    # 点击登录
    buttons = driver.find_elements(By.TAG_NAME, 'button')
    for btn in buttons:
        try:
            if btn.is_displayed():
                btn.click()
                time.sleep(3)
                break
        except:
            pass

print('After login URL:', driver.current_url)

# 获取 cookies 并测试 API
cookies = driver.get_cookies()
print('Cookies:', len(cookies))

session = requests.Session()
for c in cookies:
    session.cookies.set(c['name'], c['value'])

# 获取 workflows
wf_resp = session.get('http://172.17.0.3:5678/rest/workflows')
print('Workflows API:', wf_resp.status_code)

if wf_resp.status_code == 200:
    import json
    data = wf_resp.json()
    workflows = data.get('data', data) if isinstance(data, dict) else data
    print(f'Found {len(workflows)} workflows')
    for wf in workflows:
        print(f"  ID: {wf.get('id')}, Name: {wf.get('name')}")
        if 'nodes' in wf:
            for node in wf['nodes']:
                params = node.get('parameters', {})
                if 'initialMessages' in params:
                    print(f"    initialMessages: {params['initialMessages'][:100]}...")

driver.quit()
