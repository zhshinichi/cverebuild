import os, re, json, requests
from typing import Generator
from openai import OpenAI
from pydantic import BaseModel, Field
from dateutil import parser
from .llm_utils import ask_structured_llm
from .data_processor import get_commit_data

CVE_DIR = os.path.join(os.path.dirname(__file__), '..', 'cvelist')

def fetch_patch_commit_url(cve: dict) -> tuple[list, list]:
    """
    Fetches the patch commit URLs from the list of URLs.
    Supports both CVE 4.0 and CVE 5.0 formats.
    """
    # CVE 5.0 format
    if 'containers' in cve:
        urls = []
        if 'cna' in cve['containers'] and 'references' in cve['containers']['cna']:
            urls = [{'url': ref['url']} for ref in cve['containers']['cna']['references']]
        elif 'adp' in cve['containers']:
            for adp in cve['containers']['adp']:
                if 'references' in adp:
                    urls.extend([{'url': ref['url']} for ref in adp['references']])
    # CVE 4.0 format
    elif 'references' in cve:
        urls = cve['references']['reference_data']
    else:
        return [], []
    
    git_re = r'(((?P<repo>(https|http):\/\/(bitbucket|github|gitlab)\.(org|com)\/(?P<owner>[^\/]+)\/(?P<project>[^\/]*))\/(commit|commits)\/(?P<hash>\w+)#?)+)' # Used this regex from CVEfixes (https://github.com/secureIT-project/CVEfixes)
    patch_commit_data = []
    other_urls = []

    for url in urls:
        match = re.search(git_re, url['url'])
        if match:
            patch_commit_data.append({
                'owner': match.group('owner'),
                'project': match.group('project'),
                'hash': match.group('hash'),
                'repo_url': match.group('repo').replace(r'http:', r'https:'),
                'patch_commit_url': url['url']
            })
        else:
            other_urls.append(url['url'])
    
    return patch_commit_data, other_urls

def get_cwe_id(cve: dict) -> list[str]:
    """
    Extracts CWE IDs from CVE data.
    Supports both CVE 4.0 and CVE 5.0 formats.
    """
    cwes = []
    
    # CVE 5.0 format
    if 'containers' in cve:
        if 'cna' in cve['containers'] and 'problemTypes' in cve['containers']['cna']:
            for problem in cve['containers']['cna']['problemTypes']:
                if 'descriptions' in problem:
                    for desc in problem['descriptions']:
                        cwe_info = {'id': 'n/a', 'value': 'n/a'}
                        if 'cweId' in desc:
                            cwe_info['id'] = desc['cweId']
                        if 'description' in desc:
                            cwe_info['value'] = desc['description']
                            # Try to extract CWE ID from description if not present
                            if cwe_info['id'] == 'n/a':
                                cwe_re = re.search(r'CWE-(\d+)', desc['description'])
                                if cwe_re:
                                    cwe_info['id'] = f"CWE-{cwe_re.group(1)}"
                        cwes.append(cwe_info)
    # CVE 4.0 format
    elif 'problemtype' in cve:
        if 'problemtype_data' in cve['problemtype']:
            for cwe in cve['problemtype']['problemtype_data']:
                cwe = cwe['description'][0]
                cwe_info = {'id': 'n/a', 'value': 'n/a'}
                if 'cweId' in cwe:
                    cwe_info['id'] = cwe['cweId']
                elif 'value' in cwe:
                    cwe_re = re.search(r'CWE-(\d+)', cwe['value'])
                    if cwe_re:
                        cwe_info['id'] = cwe_re.group(1)
                cwe_info['value'] = cwe['value']
                cwes.append(cwe_info)
    
    return cwes

def process_cve_data(cve: dict) -> dict:
    """
    Processes the CVE data and returns a dictionary.
    Supports both CVE 4.0 and CVE 5.0 formats.
    """
    patch_urls, other_urls = fetch_patch_commit_url(cve)
    cwe_id = get_cwe_id(cve)
    
    # CVE 5.0 format
    if 'cveMetadata' in cve:
        cve_id = cve['cveMetadata']['cveId']
        description = 'n/a'
        if 'containers' in cve and 'cna' in cve['containers']:
            if 'descriptions' in cve['containers']['cna']:
                for desc in cve['containers']['cna']['descriptions']:
                    if desc.get('lang') == 'en':
                        description = desc.get('value', 'n/a')
                        break
            
            # Extract affected vendor/product data
            vendor_data = []
            version_data = []
            if 'affected' in cve['containers']['cna']:
                for affected in cve['containers']['cna']['affected']:
                    vendor_info = {
                        'vendor_name': affected.get('vendor', 'n/a'),
                        'product': {
                            'product_data': [{
                                'product_name': affected.get('product', 'n/a'),
                                'version': {
                                    'version_data': affected.get('versions', [])
                                }
                            }]
                        }
                    }
                    vendor_data.append(vendor_info)
                    if 'versions' in affected:
                        version_data.extend(affected['versions'])
        
        cve_data = {
            'id': cve_id,
            'description': description,
            'cwe': cwe_id,
            'patch_urls': patch_urls,
            'other_urls': other_urls,
            'vendor_data': vendor_data,
            'version_data': version_data
        }
    # CVE 4.0 format
    else:
        cve_data = {
            'id': cve['CVE_data_meta']['ID'],
            'description': cve['description']['description_data'][0]['value'],
            'cwe': cwe_id,
            'patch_urls': patch_urls,
            'other_urls': other_urls,
            'vendor_data': cve['affects']['vendor']['vendor_data'] if 'affects' in cve else [],
            'version_data': cve['affects']['vendor']['vendor_data'][0]['product']['product_data'][0]['version']['version_data'] if 'affects' in cve else []
        }

    return cve_data

def cves_data(year: int = None) -> Generator[dict, None, None]:
    """
    Returns a generator of CVE data.
    """
    if year:
        cve_dir = os.path.join(CVE_DIR, str(year))
    else:
        cve_dir = CVE_DIR
    
    for subdir, _, files in os.walk(cve_dir):
        for file in files:
            if file.endswith('.json'):
                with open(os.path.join(subdir, file), 'r') as f:
                    cves_data = json.load(f)
                yield process_cve_data(cves_data)

def get_cve_by_id(cve_id: str) -> dict | None:
    """
    Returns the CVE data for the given CVE ID.
    """
    if not cve_id.startswith("CVE-") or len(cve_id.split('-')) != 3:
        raise ValueError("Invalid CVE ID format. Expected format: CVE-YYYY-NNNNNNN")
    
    # Extract year and numeric portion from the CVE ID
    _, year, number = cve_id.split('-')
    year = int(year)
    number = int(number)
    
    # Calculate the subdirectory
    sub_dir = f"{year}/{number // 1000}xxx"
    
    # Construct the full file path
    file_path = os.path.join(CVE_DIR, sub_dir, f"{cve_id}.json")

    # Check if the file exists
    if os.path.exists(file_path):
        with open(file_path, 'r', encoding='ISO-8859-1') as f:
            cve_data = json.load(f)
        return process_cve_data(cve_data)
    else:
        print(f"{file_path} does not exist")
        return None

def get_software_versions(cve_id: str) -> list[bool, str]:
    """
    Returns the affected software versions for the given CVE ID.
    """
    cve_data = get_cve_by_id(cve_id)
    versions = cve_data['version_data']

    true_versions = []
    for version in versions:
        less = False
        tag = version['version_value']
        relation = version['version_affected'] if 'version_affected' in version else None

        # 1) check if the version_data is present
        if tag == 'not down converted' or tag == 'n/a':
            true_versions.append((less, 'n/a'))

        # 2) check if the version_data is a range
        elif ',' in tag:
            tags = tag.split(',')
            before = tags[0]
            after = tags[1]

            # in case '=' is present in after or before
            if '=' in after:
                tag = after
            elif '=' in before:
                tag = before
            else:
                tag = after
                less = True
            
            if less:
                tag = tag.split('<')[1].strip()
            else:
                tag = tag.split('=')[1].strip()
        
            # a) check if the version has anything other than numbers
            if len(tag.split(' ')) > 1:
                true_versions.append((less, 'anomaly'))

            # b) check if the version_data is prefixed with 'v' or 'V'
            elif tag.startswith('v') or tag.startswith('V'):
                true_versions.append((less, tag[1:]))
            
            # c) version is valid
            else:
                true_versions.append((less, tag))

        # 3) check if the version value has '=' relation in it
        elif '=' in tag:
            tag = tag.split('=')[1].strip()

            # a) check if the version has anything other than numbers
            if len(tag.split(' ')) > 1:
                true_versions.append((less, 'anomaly'))

            # b) check if the version_data is prefixed with 'v' or 'V'
            elif tag.startswith('v') or tag.startswith('V'):
                true_versions.append((less, tag[1:]))
            
            # c) version is valid
            else:
                true_versions.append((less, tag))

        # 4) check if the version value has '<' relation in it
        elif '<' in tag:
            tag = tag.split('<')[1].strip()

            # a) check if the version has anything other than numbers
            if len(tag.split(' ')) > 1:
                true_versions.append((less, 'anomaly'))

            # b) check if the version_data is prefixed with 'v' or 'V'
            elif tag.startswith('v') or tag.startswith('V'):
                less = True
                true_versions.append((less, tag[1:]))
            
            # c) version is valid
            else:
                less = True
                true_versions.append((less, tag))

        # 5) check if the 'affected' value has '='
        elif '=' in relation:
            # a) check if the version has anything other than numbers
            if len(tag.split(' ')) > 1:
                true_versions.append((less, 'anomaly'))

            # b) check if the version_data is prefixed with 'v' or 'V'
            elif tag.startswith('v') or tag.startswith('V'):
                true_versions.append((less, tag[1:]))
            
            # c) version is valid
            else:
                true_versions.append((less, tag))
        
        # 6) check if the 'affected' value has '<'
        elif '<' in relation:
            # a) check if the version has anything other than numbers
            if len(tag.split(' ')) > 1:
                true_versions.append((less, 'anomaly'))

            # b) check if the version_data is prefixed with 'v' or 'V'
            elif tag.startswith('v') or tag.startswith('V'):
                less = True
                true_versions.append((less, tag[1:]))
            
            # c) version is valid
            else:
                less = True
                true_versions.append((less, tag))

        # 7) tag is valid
        else:
            # a) check if the version has anything other than numbers
            if len(tag.split(' ')) > 1:
                true_versions.append((less, 'anomaly'))

            # b) check if the version_data is prefixed with 'v' or 'V'
            elif tag.startswith('v') or tag.startswith('V'):
                true_versions.append((less, tag[1:]))
            
            # c) version is valid
            else:
                true_versions.append((less, tag))

    return true_versions

def affected_version_exist(repo_owner: str, repo_name: str, tag: str, less: bool) -> str:
    headers = {
        "Authorization": f"Bearer {os.getenv('GITHUB_TOKEN')}",
        "Accept": "application/vnd.github.v3+json"
    }
    if not less:
        url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/git/ref/tags/v{tag}"
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return f"v{tag}"
        elif response.status_code == 404:
            return None
        else:
            print(f"Error: {response.status_code}, {response.text}")
            return None
    else:
       page = 1
       found = False

       while True:
            url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/tags"

            params = {
                "per_page": 100,  # Max allowed per page
                "page": page
            }

            response = requests.get(url, headers=headers, params=params)

            if response.status_code == 200:
                tags = response.json()
                if not tags:
                    return None
                for tag_info in tags:
                    if found:
                        return tag_info["name"]
                    if tag_info["name"] == f"v{tag}":
                        found = True
                page += 1
            else:
                print(f"Error: {response.status_code}, {response.text}")
                return None

def cve_with_effective_sec_adv(sec_adv) -> dict:
    class AdvisoryResponse(BaseModel):
        reason: str = Field(..., description="The reason for the response")
        decision: bool = Field(..., description="The decision made by the model")

    sys = "You are a security researcher who is an expert in analyzing security advisories.\n" \
            "Your task is to analyze the given security advisory and see if it provides a proof of concept of the vulnerability or " \
            "detailed steps to reproduce the vulnerability."
    prompt = f"### Security Advisory\n{sec_adv}"

    res = ask_structured_llm(
        sys=sys,
        prompt=prompt,
        model="gpt-4o-2024-11-20",
        response_model=AdvisoryResponse
    )
    
    return {"decision": res.decision, "reason": res.reason}

def get_cve_by_id_v5(cve_id: str) -> dict | None:
    """
    Returns the CVE data for the given CVE ID.
    """
    if not cve_id.startswith("CVE-") or len(cve_id.split('-')) != 3:
        raise ValueError("Invalid CVE ID format. Expected format: CVE-YYYY-NNNNNNN")
    
    # Extract year and numeric portion from the CVE ID
    _, year, number = cve_id.split('-')
    year = int(year)
    number = int(number)
    
    # Calculate the subdirectory
    sub_dir = f"{year}/{number // 1000}xxx"
    
    # Construct the full file path
    file_path = os.path.join(os.path.join(os.path.dirname(__file__), '..', 'cvelistV5', 'cves', sub_dir, f"{cve_id}.json"))

    # Check if the file exists
    if os.path.exists(file_path):
        with open(file_path, 'r', encoding='ISO-8859-1') as f:
            cve_data = json.load(f)
        return cve_data
    else:
        print(f"{file_path} does not exist")
        return None

def get_published_date(cve_id: str) -> str:
    cve = get_cve_by_id_v5(cve_id)
    if cve:
        if 'cveMetadata' in cve:
            if 'datePublished' in cve['cveMetadata']:
                pub_date = cve['cveMetadata']['datePublished']
                return pub_date
    return None

def get_patch_content(owner: str, project: str, hash: str) -> str:
    patch_data = get_commit_data(owner, project, hash)
    if patch_data:
        patch_content = patch_data['msg']+'\n'+'\n'.join(['\nFilename: '+file['file_name']+':\n```\n'+'\n\n'.join([hunk['header']+'\n'+hunk['patch'] for hunk in file['hunks']])+'\n```' for file in patch_data['file_patch']])
        return patch_content
    return None