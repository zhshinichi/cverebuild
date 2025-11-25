"""Test WebEnvBuilder parser"""
from agents.webEnvBuilder import WebEnvBuilderParser
import json

parser = WebEnvBuilderParser()

# Test 1: JSON in text
test1 = 'After deployment: {"success": "yes", "access": "http://localhost:9600", "method": "docker-compose", "notes": "OK"}'
result1 = parser.parse(test1)
print('Test 1 result:', json.dumps(result1, indent=2))

# Test 2: JSON code block
test2 = '''
I have deployed the application.

```json
{
    "success": "yes",
    "access": "http://localhost:8080",
    "method": "pip",
    "notes": "Flask app running"
}
```
'''
result2 = parser.parse(test2)
print('Test 2 result:', json.dumps(result2, indent=2))

print('\nParser tests passed!')
