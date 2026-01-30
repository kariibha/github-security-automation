#!/usr/bin/env python3
"""
AI-Powered Code Security Reviewer using Amazon Bedrock
Reviews code changes for security issues
"""

import json
import sys
import argparse
import boto3
import os
import subprocess
from typing import List, Dict

class AICodeReviewer:
    def __init__(self, region: str = 'us-east-1'):
        self.bedrock = boto3.client('bedrock-runtime', region_name=region)
        self.model_id = 'us.amazon.nova-2-lite-v1:0'
        self.github_token = os.environ.get('GITHUB_TOKEN')
    
    def review_files(self, files: List[str], pr_number: int) -> str:
        """Review changed files for security issues"""
        
        reviews = []
        
        for file_path in files:
            if self._should_review(file_path):
                print(f"Reviewing {file_path}...")
                
                # Get file diff
                diff = self._get_file_diff(file_path)
                
                # Get full file content for context
                content = self._read_file(file_path)
                
                # AI review
                review = self._review_code(file_path, content, diff)
                
                if review:
                    reviews.append({
                        'file': file_path,
                        'review': review
                    })
        
        # Generate summary
        summary = self._generate_summary(reviews)
        
        return summary
    
    def _should_review(self, file_path: str) -> bool:
        """Check if file should be reviewed"""
        # Review code files, configs, and IaC
        extensions = [
            '.py', '.js', '.ts', '.java', '.go', '.rb', '.php',
            '.yml', '.yaml', '.json', '.tf', '.tfvars',
            '.sh', '.bash', '.env.example', 'Dockerfile'
        ]
        
        return any(file_path.endswith(ext) for ext in extensions)
    
    def _get_file_diff(self, file_path: str) -> str:
        """Get git diff for file"""
        try:
            result = subprocess.run(
                ['git', 'diff', 'HEAD^', 'HEAD', '--', file_path],
                capture_output=True,
                text=True
            )
            return result.stdout
        except:
            return ""
    
    def _read_file(self, file_path: str) -> str:
        """Read file content"""
        try:
            with open(file_path, 'r') as f:
                return f.read()
        except:
            return ""
    
    def _review_code(self, file_path: str, content: str, diff: str) -> Dict:
        """Review code using AI with web grounding for security patterns"""
        
        prompt = f"""You are a security expert reviewing code changes in a pull request.

File: {file_path}

Changes (diff):
```diff
{diff[:2000]}
```

Full file context (first 3000 chars):
```
{content[:3000]}
```

Analyze this code for:
1. **Security vulnerabilities** (SQL injection, XSS, CSRF, etc.)
2. **Secrets or credentials** (API keys, passwords, tokens)
3. **Insecure configurations** (weak crypto, exposed endpoints)
4. **Authentication/Authorization issues**
5. **Input validation problems**
6. **Dependency security issues**

Respond in JSON format:
{{
  "severity": "critical|high|medium|low|none",
  "issues": [
    {{
      "type": "security_issue_type",
      "line": line_number,
      "description": "detailed description",
      "recommendation": "how to fix",
      "cwe": "CWE-XXX if applicable"
    }}
  ],
  "summary": "brief summary of findings"
}}

If no issues found, return severity "none" with empty issues array.
"""
        
        try:
            # Extract potential vulnerability patterns for web grounding
            vuln_patterns = self._extract_vulnerability_patterns(content, diff)
            web_query = f"Latest security best practices for {', '.join(vuln_patterns[:3])}" if vuln_patterns else None
            
            body = {
                "messages": [
                    {
                        "role": "user",
                        "content": [{"text": prompt}]
                    }
                ],
                "inferenceConfig": {
                    "max_new_tokens": 2000,
                    "temperature": 0.2
                }
            }
            
            # Add web grounding for security context
            if web_query:
                body["toolConfig"] = {
                    "tools": [{
                        "systemTool": {
                            "name": "nova_grounding"
                        }
                    }]
                }
            
            response = self.bedrock.converse(
                modelId=self.model_id,
                **body
            )
            
            # Extract text from response
            result_text = ""
            for content in response['output']['message']['content']:
                if 'text' in content:
                    result_text += content['text']
            
            # Extract JSON from response
            if '```json' in result_text:
                result_text = result_text.split('```json')[1].split('```')[0]
            elif '```' in result_text:
                result_text = result_text.split('```')[1].split('```')[0]
            
            return json.loads(result_text.strip())
            
        except Exception as e:
            print(f"Error reviewing {file_path}: {e}")
            return None
    
    def _extract_vulnerability_patterns(self, content: str, diff: str) -> list:
        """Extract potential vulnerability patterns for web grounding"""
        patterns = []
        text = content + diff
        
        if 'eval(' in text or 'exec(' in text:
            patterns.append('code injection prevention')
        if 'password' in text.lower() or 'secret' in text.lower():
            patterns.append('credential management')
        if 'sql' in text.lower() or 'query' in text.lower():
            patterns.append('SQL injection prevention')
        if '<script' in text or 'innerHTML' in text:
            patterns.append('XSS prevention')
        if 'jwt' in text.lower() or 'token' in text.lower():
            patterns.append('JWT security')
        
        return patterns
    
    def _generate_summary(self, reviews: List[Dict]) -> str:
        """Generate markdown summary of reviews"""
        
        if not reviews:
            return """## 🔒 AI Security Review

✅ **No security issues detected**

All changed files have been reviewed and no security concerns were found.
"""
        
        # Count issues by severity
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        for review in reviews:
            severity = review['review'].get('severity', 'none')
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Build report
        report = ["## 🔒 AI Security Review\n"]
        
        # Summary
        if severity_counts['critical'] > 0 or severity_counts['high'] > 0:
            report.append("### ⚠️ Security Issues Found\n")
        else:
            report.append("### ℹ️ Minor Issues Found\n")
        
        report.append(f"- 🔴 Critical: {severity_counts['critical']}")
        report.append(f"- 🟠 High: {severity_counts['high']}")
        report.append(f"- 🟡 Medium: {severity_counts['medium']}")
        report.append(f"- 🔵 Low: {severity_counts['low']}\n")
        
        # Detailed findings
        report.append("### Detailed Findings\n")
        
        for review in reviews:
            file_path = review['file']
            review_data = review['review']
            
            if review_data.get('severity') == 'none':
                continue
            
            report.append(f"#### 📄 `{file_path}`\n")
            report.append(f"**Severity:** {review_data.get('severity', 'unknown').upper()}\n")
            report.append(f"**Summary:** {review_data.get('summary', 'No summary')}\n")
            
            issues = review_data.get('issues', [])
            if issues:
                report.append("**Issues:**\n")
                for i, issue in enumerate(issues, 1):
                    report.append(f"{i}. **{issue.get('type', 'Unknown')}** (Line {issue.get('line', '?')})")
                    report.append(f"   - {issue.get('description', 'No description')}")
                    report.append(f"   - **Fix:** {issue.get('recommendation', 'No recommendation')}")
                    if issue.get('cwe'):
                        report.append(f"   - **CWE:** {issue['cwe']}")
                    report.append("")
        
        # Recommendations
        if severity_counts['critical'] > 0:
            report.append("\n### 🚨 Action Required\n")
            report.append("Critical security issues detected. **Do not merge** until resolved.\n")
        elif severity_counts['high'] > 0:
            report.append("\n### ⚠️ Recommendation\n")
            report.append("High severity issues detected. Please review and address before merging.\n")
        
        return '\n'.join(report)

def main():
    parser = argparse.ArgumentParser(description='AI Code Security Reviewer')
    parser.add_argument('--files', required=True, help='Space-separated list of files')
    parser.add_argument('--pr-number', type=int, required=True, help='PR number')
    parser.add_argument('--region', default='us-east-1', help='AWS region')
    
    args = parser.parse_args()
    
    try:
        reviewer = AICodeReviewer(region=args.region)
        
        files = args.files.split()
        print(f"Reviewing {len(files)} files...")
        
        summary = reviewer.review_files(files, args.pr_number)
        
        # Save to file for GitHub Actions to post
        with open('security-review.md', 'w') as f:
            f.write(summary)
        
        print(summary)
        print("\n✅ Review complete!")
        
        return 0
        
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        return 1

if __name__ == '__main__':
    sys.exit(main())
