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

# Keywords in description that indicate web interaction needed
WEB_INTERACTION_KEYWORDS = [
    'csrf',
    'cross-site request forgery',
    'xss',
    'cross-site scripting',
    'clickjacking',
    'open redirect',
    'browser',
    'javascript',
    'cookie',
    'session',
    'same-origin',
    'cors',
    'referer',
    'origin header',
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
    
    # Check CWE types
    if 'cwe' in cve_info:
        for cwe in cve_info['cwe']:
            if cwe.get('id') in WEB_INTERACTION_CWE:
                return True
    
    # Check description for keywords
    description = cve_info.get('description', '').lower()
    for keyword in WEB_INTERACTION_KEYWORDS:
        if keyword in description:
            return True
    
    # Check security advisories
    if 'sec_adv' in cve_info:
        for adv in cve_info['sec_adv']:
            content = adv.get('content', '').lower()
            for keyword in WEB_INTERACTION_KEYWORDS:
                if keyword in content:
                    return True
    
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
