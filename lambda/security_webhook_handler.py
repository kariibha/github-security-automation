import json
import boto3
import os
import requests
from datetime import datetime
from typing import Dict, List, Any

# AWS Lambda function for GitHub webhook processing
# Handles push events, PR events, and scheduled CVE checks

def lambda_handler(event, context):
    """Main Lambda handler for GitHub security automation"""
    
    # Determine event type
    if 'httpMethod' in event:
        # API Gateway / Webhook event
        return handle_webhook(event, context)
    elif 'source' in event and event['source'] == 'aws.events':
        # EventBridge scheduled event
        return handle_scheduled_scan(event, context)
    else:
        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'Unknown event type'})
        }

def handle_webhook(event, context):
    """Handle GitHub webhook events"""
    
    # Verify GitHub signature
    if not verify_github_signature(event):
        return {
            'statusCode': 401,
            'body': json.dumps({'error': 'Invalid signature'})
        }
    
    # Parse webhook payload
    body = json.loads(event['body'])
    github_event = event['headers'].get('X-GitHub-Event')
    
    if github_event == 'push':
        return handle_push_event(body)
    elif github_event == 'pull_request':
        return handle_pr_event(body)
    elif github_event == 'repository':
        return handle_repo_event(body)
    
    return {
        'statusCode': 200,
        'body': json.dumps({'message': 'Event received'})
    }

def handle_push_event(payload: Dict) -> Dict:
    """Handle push events - scan for secrets and vulnerabilities"""
    
    repo = payload['repository']['full_name']
    commits = payload['commits']
    
    print(f"Processing push to {repo} with {len(commits)} commits")
    
    # Trigger security scan
    findings = []
    
    for commit in commits:
        # Check commit for secrets
        secrets = scan_commit_for_secrets(repo, commit['id'])
        if secrets:
            findings.extend(secrets)
    
    # If secrets found, create issue
    if findings:
        create_security_issue(repo, findings)
    
    return {
        'statusCode': 200,
        'body': json.dumps({
            'message': 'Push processed',
            'findings': len(findings)
        })
    }

def handle_pr_event(payload: Dict) -> Dict:
    """Handle PR events - run AI security review"""
    
    action = payload['action']
    
    if action not in ['opened', 'synchronize', 'reopened']:
        return {'statusCode': 200, 'body': json.dumps({'message': 'Ignored'})}
    
    repo = payload['repository']['full_name']
    pr_number = payload['pull_request']['number']
    
    print(f"Processing PR #{pr_number} in {repo}")
    
    # Trigger AI security review
    review_result = trigger_ai_review(repo, pr_number)
    
    # Post review as comment
    post_pr_comment(repo, pr_number, review_result)
    
    return {
        'statusCode': 200,
        'body': json.dumps({'message': 'PR reviewed'})
    }

def handle_scheduled_scan(event, context):
    """Handle scheduled CVE scans"""
    
    print("Running scheduled CVE scan")
    
    # Get all repositories
    repos = get_user_repositories()
    
    results = []
    
    for repo in repos:
        print(f"Scanning {repo}...")
        
        # Check for new CVEs
        cves = check_repository_cves(repo)
        
        if cves:
            # Use AI to analyze and prioritize
            analysis = analyze_cves_with_ai(repo, cves)
            
            # Create issue if critical
            if analysis.get('has_critical'):
                create_cve_issue(repo, analysis)
            
            results.append({
                'repo': repo,
                'cves': len(cves),
                'critical': analysis.get('critical_count', 0)
            })
    
    return {
        'statusCode': 200,
        'body': json.dumps({
            'message': 'Scheduled scan complete',
            'results': results
        })
    }

def scan_commit_for_secrets(repo: str, commit_sha: str) -> List[Dict]:
    """Scan commit for secrets using pattern matching and AI"""
    
    # Get commit diff
    diff = get_commit_diff(repo, commit_sha)
    
    # Pattern-based detection
    patterns = [
        r'(?i)(api[_-]?key|apikey)[\s]*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})',
        r'(?i)(secret|password|passwd)[\s]*[=:]\s*["\']?([^\s"\']{8,})',
        r'(?i)(aws_access_key_id|aws_secret_access_key)[\s]*[=:]\s*["\']?([A-Z0-9]{20,})',
        r'(?i)(github|gh)[_-]?token[\s]*[=:]\s*["\']?(ghp_[a-zA-Z0-9]{36})',
    ]
    
    findings = []
    
    import re
    for pattern in patterns:
        matches = re.finditer(pattern, diff)
        for match in matches:
            findings.append({
                'type': 'secret',
                'pattern': match.group(1),
                'commit': commit_sha,
                'severity': 'critical'
            })
    
    # AI-based detection for context
    if findings:
        ai_analysis = analyze_secrets_with_ai(diff, findings)
        findings = ai_analysis.get('confirmed_secrets', findings)
    
    return findings

def analyze_cves_with_ai(repo: str, cves: List[Dict]) -> Dict:
    """Use Bedrock Nova 2 Lite with web grounding to analyze CVEs"""
    
    bedrock = boto3.client('bedrock-runtime', region_name=os.environ.get('AWS_REGION', 'us-east-1'))
    
    # Extract CVE IDs for web grounding
    cve_ids = [cve.get('id', '') for cve in cves if cve.get('id')]
    web_query = f"Latest exploits, patches, and security advisories for {', '.join(cve_ids[:5])}"
    
    prompt = f"""Analyze these CVEs for repository {repo}:

{json.dumps(cves, indent=2)}

Provide:
1. Risk assessment for each CVE
2. Exploitability in this context
3. Priority ranking
4. Recommended actions

Respond in JSON format with: has_critical (bool), critical_count (int), analysis (string), recommendations (list)
"""
    
    body = {
        "messages": [
            {
                "role": "user",
                "content": [{"text": prompt}]
            }
        ],
        "inferenceConfig": {
            "maxTokens": 2000,
            "temperature": 0.3
        },
        "toolConfig": {
            "tools": [{
                "systemTool": {
                    "name": "nova_grounding"
                }
            }]
        }
    }
    
    response = bedrock.converse(
        modelId='us.amazon.nova-2-lite-v1:0',
        **body
    )
    
    # Extract text from response
    result_text = ""
    for content in response['output']['message']['content']:
        if 'text' in content:
            result_text += content['text']
    
    # Parse JSON from response
    if '```json' in result_text:
        result_text = result_text.split('```json')[1].split('```')[0]
    
    return json.loads(result_text.strip())

def analyze_secrets_with_ai(diff: str, potential_secrets: List[Dict]) -> Dict:
    """Use AI with web grounding to confirm if detected patterns are real secrets"""
    
    bedrock = boto3.client('bedrock-runtime', region_name=os.environ.get('AWS_REGION', 'us-east-1'))
    
    prompt = f"""Analyze this code diff for secrets:

{diff[:2000]}

Potential secrets detected:
{json.dumps(potential_secrets, indent=2)}

Determine if these are:
1. Real secrets (API keys, passwords, tokens)
2. Example/placeholder values
3. False positives

Respond in JSON: {{"confirmed_secrets": [...], "false_positives": [...], "analysis": "..."}}
"""
    
    body = {
        "messages": [
            {
                "role": "user",
                "content": [{"text": prompt}]
            }
        ],
        "inferenceConfig": {
            "maxTokens": 1000,
            "temperature": 0.2
        },
        "toolConfig": {
            "tools": [{
                "systemTool": {
                    "name": "nova_grounding"
                }
            }]
        }
    }
    
    response = bedrock.converse(
        modelId='us.amazon.nova-2-lite-v1:0',
        **body
    )
    
    # Extract text from response
    result_text = ""
    for content in response['output']['message']['content']:
        if 'text' in content:
            result_text += content['text']
    
    if '```json' in result_text:
        result_text = result_text.split('```json')[1].split('```')[0]
    
    return json.loads(result_text.strip())

def create_security_issue(repo: str, findings: List[Dict]):
    """Create GitHub issue for security findings"""
    
    token = os.environ.get('GITHUB_TOKEN')
    
    title = f"🚨 Security Alert: {len(findings)} potential secret(s) detected"
    
    body = f"""## Security Scan Results

**Date:** {datetime.utcnow().isoformat()}
**Findings:** {len(findings)}

### Detected Issues

"""
    
    for i, finding in enumerate(findings, 1):
        body += f"{i}. **{finding['type'].upper()}** in commit `{finding['commit'][:7]}`\n"
        body += f"   - Pattern: `{finding['pattern']}`\n"
        body += f"   - Severity: {finding['severity']}\n\n"
    
    body += """
### Immediate Actions Required

1. Rotate any exposed credentials immediately
2. Review the commits mentioned above
3. Remove secrets from git history if confirmed
4. Update `.gitignore` to prevent future leaks

### Need Help?

See the [Security Guide](../security-guide.md) for remediation steps.
"""
    
    # Create issue via GitHub API
    url = f"https://api.github.com/repos/{repo}/issues"
    headers = {
        'Authorization': f'token {token}',
        'Accept': 'application/vnd.github.v3+json'
    }
    
    response = requests.post(url, headers=headers, json={
        'title': title,
        'body': body,
        'labels': ['security', 'critical']
    })
    
    return response.json()

def create_cve_issue(repo: str, analysis: Dict):
    """Create GitHub issue for CVE findings"""
    
    token = os.environ.get('GITHUB_TOKEN')
    
    title = f"🔒 Security: {analysis['critical_count']} critical CVE(s) detected"
    
    body = f"""## CVE Security Alert

{analysis['analysis']}

### Recommended Actions

"""
    
    for rec in analysis.get('recommendations', []):
        body += f"- {rec}\n"
    
    url = f"https://api.github.com/repos/{repo}/issues"
    headers = {
        'Authorization': f'token {token}',
        'Accept': 'application/vnd.github.v3+json'
    }
    
    response = requests.post(url, headers=headers, json={
        'title': title,
        'body': body,
        'labels': ['security', 'dependencies']
    })
    
    return response.json()

# Helper functions (stubs - implement based on your needs)

def verify_github_signature(event: Dict) -> bool:
    """Verify GitHub webhook signature"""
    # Implement HMAC verification
    return True

def get_commit_diff(repo: str, commit_sha: str) -> str:
    """Get commit diff from GitHub"""
    token = os.environ.get('GITHUB_TOKEN')
    url = f"https://api.github.com/repos/{repo}/commits/{commit_sha}"
    headers = {'Authorization': f'token {token}'}
    response = requests.get(url, headers=headers)
    return response.text

def get_user_repositories() -> List[str]:
    """Get list of user repositories"""
    # Implement GitHub API call
    return []

def check_repository_cves(repo: str) -> List[Dict]:
    """Check repository for CVEs"""
    # Implement CVE database check
    return []

def trigger_ai_review(repo: str, pr_number: int) -> str:
    """Trigger AI security review"""
    return "AI review completed"

def post_pr_comment(repo: str, pr_number: int, comment: str):
    """Post comment on PR"""
    token = os.environ.get('GITHUB_TOKEN')
    url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    headers = {'Authorization': f'token {token}'}
    requests.post(url, headers=headers, json={'body': comment})
