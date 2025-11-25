#!/usr/bin/env python3
import os
os.chdir('/workspaces/submission/src')

from agents.webDriverAgent import WebDriverAgent
print('Import OK')

# Test tool creation
os.environ['OPENAI_API_KEY'] = 'test'
agent = WebDriverAgent(cve_knowledge="test", target_url="http://localhost:9600")
tools = agent.get_available_tools()
print(f"Tools count: {len(tools)}")
for t in tools:
    print(f"  - {t.name}")
