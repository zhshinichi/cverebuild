from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
import requests
import time

options = Options()
options.add_argument('--headless')
options.add_argument('--no-sandbox')

driver = webdriver.Chrome(options=options)
driver.get('http://172.17.0.3:5678')
time.sleep(3)

if '/signin' in driver.current_url:
    inputs = driver.find_elements(By.CSS_SELECTOR, 'input')
    for inp in inputs:
        inp_type = inp.get_attribute('type') or ''
        if inp_type == 'email':
            inp.send_keys('admin@test.local')
        elif inp_type == 'password':
            inp.send_keys('Admin123!')
    buttons = driver.find_elements(By.TAG_NAME, 'button')
    for btn in buttons:
        if btn.is_displayed():
            btn.click()
            time.sleep(3)
            break

cookies = driver.get_cookies()
session = requests.Session()
for c in cookies:
    session.cookies.set(c['name'], c['value'])

# 获取 workflow 的 webhook URL
resp = session.get('http://172.17.0.3:5678/rest/workflows/scpPjQ7nWtanxcqb')
if resp.status_code == 200:
    wf = resp.json()['data']
    print('Active:', wf.get('active'))
    for node in wf.get('nodes', []):
        print('Node webhookId:', node.get('webhookId'))
        print('Node type:', node.get('type'))

# 尝试访问正确的 webhook URL
print()
print('Testing webhook URLs:')
test_urls = [
    'http://172.17.0.3:5678/webhook/test-webhook/chat',
    'http://172.17.0.3:5678/webhook-test/test-webhook/chat',
]
for url in test_urls:
    r = requests.get(url, timeout=10)
    print(f'{url}: {r.status_code}')
    if r.status_code == 200 and '<html' in r.text.lower():
        print('  -> HTML page!')
        if 'initialMessages' in r.text:
            print('  -> Has initialMessages!')

driver.quit()
