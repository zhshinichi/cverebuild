"""
Web-based vulnerability detector
Determines if a CVE requires browser interaction for exploitation
"""

# CWE types that typically require browser interaction
WEB_INTERACTION_CWE = {
    'CWE-352',  # Cross-Site Request Forgery (CSRF)
    'CWE-79',   # Cross-site Scripting (XSS)
    'CWE-601',  # URL Redirection to Untrusted Site ('Open Redirect')
    'CWE-451',  # User Interface (UI) Misrepresentation of Critical Information
    'CWE-1021', # Improper Restriction of Rendered UI Layers or Frames (Clickjacking)
    'CWE-829',  # Inclusion of Functionality from Untrusted Control Sphere
}

# CWE types that are typically local/library vulnerabilities (NOT requiring browser)
LOCAL_VULNERABILITY_CWE = {
    'CWE-400',  # Uncontrolled Resource Consumption (DoS)
    'CWE-502',  # Deserialization of Untrusted Data
    'CWE-78',   # OS Command Injection
    'CWE-94',   # Code Injection
    'CWE-22',   # Path Traversal
    'CWE-918',  # Server-Side Request Forgery (SSRF)
    'CWE-77',   # Command Injection
    'CWE-119',  # Buffer Overflow
    'CWE-125',  # Out-of-bounds Read
    'CWE-787',  # Out-of-bounds Write
    'CWE-416',  # Use After Free
    'CWE-476',  # NULL Pointer Dereference
    'CWE-190',  # Integer Overflow
    'CWE-20',   # Improper Input Validation
}

# Keywords in description that indicate web interaction needed
WEB_INTERACTION_KEYWORDS = [
    'csrf',
    'cross-site request forgery',
    'xss',
    'cross-site scripting',
    'clickjacking',
    'open redirect',
    'same-origin',
    'cors bypass',
    'cookie theft',
    'session hijacking',
]

# Keywords that indicate local/library vulnerability (NOT requiring browser)
LOCAL_VULNERABILITY_KEYWORDS = [
    'denial of service',
    'dos vulnerability',
    'resource exhaustion',
    'recursion limit',
    'stack overflow',
    'memory exhaustion',
    'cpu exhaustion',
    'deserialization',
    'pickle',
    'yaml.load',
    'command injection',
    'code execution',
    'rce',
    'remote code execution',
    'path traversal',
    'arbitrary file',
    'buffer overflow',
    'pip install',
    'python package',
    'python library',
    'npm install',
    'maven',
]

def requires_web_driver(cve_info: dict) -> bool:
    """
    Determine if a CVE requires WebDriver for exploitation
    
    Args:
        cve_info: Dictionary containing CVE information with keys:
                 - 'cwe': list of CWE dictionaries with 'id' field
                 - 'description': string description of the vulnerability
                 - 'sec_adv': list of security advisories
    
    Returns:
        bool: True if WebDriver is needed, False otherwise
    """
    
    description = cve_info.get('description', '').lower()
    
    # Step 1: Check for explicit local vulnerability CWE types (these NEVER need browser)
    if 'cwe' in cve_info:
        for cwe in cve_info['cwe']:
            cwe_id = cwe.get('id')
            if cwe_id in LOCAL_VULNERABILITY_CWE:
                return False  # Local vulnerability, no browser needed
    
    # Step 2: Check for local vulnerability keywords in description
    for keyword in LOCAL_VULNERABILITY_KEYWORDS:
        if keyword in description:
            return False  # Likely a local vulnerability
    
    # Step 3: Check for explicit web interaction CWE types
    if 'cwe' in cve_info:
        for cwe in cve_info['cwe']:
            if cwe.get('id') in WEB_INTERACTION_CWE:
                return True
    
    # Step 4: Check description for web interaction keywords
    for keyword in WEB_INTERACTION_KEYWORDS:
        if keyword in description:
            return True
    
    # Step 5: Check security advisories for web interaction keywords
    if 'sec_adv' in cve_info:
        for adv in cve_info['sec_adv']:
            content = adv.get('content', '').lower()
            for keyword in WEB_INTERACTION_KEYWORDS:
                if keyword in content:
                    return True
    
    # Default: No browser needed
    return False

def get_attack_type(cve_info: dict) -> str:
    """
    Determine the primary attack type for web-based vulnerabilities
    
    Args:
        cve_info: Dictionary containing CVE information
    
    Returns:
        str: Attack type ('csrf', 'xss', 'clickjacking', 'open_redirect', 'web')
    """
    
    # Check CWE first
    if 'cwe' in cve_info:
        for cwe in cve_info['cwe']:
            cwe_id = cwe.get('id')
            if cwe_id == 'CWE-352':
                return 'csrf'
            elif cwe_id == 'CWE-79':
                return 'xss'
            elif cwe_id == 'CWE-1021':
                return 'clickjacking'
            elif cwe_id == 'CWE-601':
                return 'open_redirect'
    
    # Check description
    description = cve_info.get('description', '').lower()
    if 'csrf' in description or 'cross-site request forgery' in description:
        return 'csrf'
    elif 'xss' in description or 'cross-site scripting' in description:
        return 'xss'
    elif 'clickjacking' in description:
        return 'clickjacking'
    elif 'open redirect' in description:
        return 'open_redirect'
    
    return 'web'  # Generic web vulnerability

if __name__ == "__main__":
    # Test case: CVE-2024-2288
    test_cve = {
        "cwe": [{"id": "CWE-352", "value": "Cross-Site Request Forgery (CSRF)"}],
        "description": "A Cross-Site Request Forgery (CSRF) vulnerability exists in the profile picture upload functionality",
        "sec_adv": [
            {"content": "The profile picture upload functionality is vulnerable to a CSRF attack"}
        ]
    }
    
    print(f"Requires WebDriver: {requires_web_driver(test_cve)}")
    print(f"Attack Type: {get_attack_type(test_cve)}")
