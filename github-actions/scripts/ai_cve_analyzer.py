#!/usr/bin/env python3
"""
AI-Powered CVE Analyzer using Amazon Bedrock
Analyzes vulnerability reports and provides intelligent prioritization
"""

import json
import sys
import argparse
import boto3
from datetime import datetime
from typing import List, Dict, Any

class AICVEAnalyzer:
    def __init__(self, region: str = 'us-east-1'):
        self.bedrock = boto3.client('bedrock-runtime', region_name=region)
        self.model_id = 'us.amazon.nova-2-lite-v1:0'
    
    def analyze_vulnerabilities(self, vulnerabilities: List[Dict]) -> Dict[str, Any]:
        """Analyze vulnerabilities using AI"""
        
        # Prepare vulnerability summary
        vuln_summary = self._prepare_summary(vulnerabilities)
        
        # Create AI prompt
        prompt = self._create_analysis_prompt(vuln_summary)
        
        # Call Bedrock
        response = self._invoke_bedrock(prompt)
        
        return response
    
    def _prepare_summary(self, vulnerabilities: List[Dict]) -> str:
        """Prepare vulnerability summary for AI analysis"""
        summary = []
        
        for vuln in vulnerabilities:
            summary.append({
                'id': vuln.get('VulnerabilityID', 'Unknown'),
                'package': vuln.get('PkgName', 'Unknown'),
                'version': vuln.get('InstalledVersion', 'Unknown'),
                'severity': vuln.get('Severity', 'Unknown'),
                'title': vuln.get('Title', ''),
                'description': vuln.get('Description', '')[:200],
                'fixed_version': vuln.get('FixedVersion', 'Not available'),
                'cvss_score': vuln.get('CVSS', {}).get('nvd', {}).get('V3Score', 0)
            })
        
        return json.dumps(summary, indent=2)
    
    def _create_analysis_prompt(self, vuln_summary: str) -> str:
        """Create prompt for AI analysis"""
        return f"""You are a security expert analyzing vulnerabilities in a software project.

Analyze the following vulnerabilities and provide:
1. Risk prioritization (Critical/High/Medium/Low)
2. Exploitability assessment
3. Business impact analysis
4. Recommended remediation steps
5. Whether this should block deployment

Vulnerabilities:
{vuln_summary}

Provide your analysis in the following markdown format:

## 🔒 Security Analysis Report

### Executive Summary
[Brief overview of findings]

### Critical Findings
[List critical issues that need immediate attention]

### Risk Assessment
| CVE ID | Package | Severity | Exploitability | Business Impact | Priority |
|--------|---------|----------|----------------|-----------------|----------|
[Table of vulnerabilities with your assessment]

### Recommended Actions
1. [Immediate actions]
2. [Short-term actions]
3. [Long-term improvements]

### Deployment Recommendation
- [ ] ✅ Safe to deploy
- [ ] ⚠️ Deploy with caution
- [ ] ❌ Block deployment

### Detailed Analysis
[Detailed explanation of key vulnerabilities and context]
"""
    
    def _invoke_bedrock(self, prompt: str) -> str:
        """Invoke Bedrock API with Nova 2 Lite and web grounding"""
        
        # Extract CVE IDs for web grounding
        cve_ids = self._extract_cve_ids(prompt)
        
        # Build web grounding query
        web_query = f"Latest security information and exploits for {', '.join(cve_ids[:5])}" if cve_ids else None
        
        body = {
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"text": prompt}
                    ]
                }
            ],
            "inferenceConfig": {
                "max_new_tokens": 4000,
                "temperature": 0.3
            }
        }
        
        # Add web grounding configuration
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
        
        # Extract response text and citations
        result_text = ""
        citations = []
        for content in response['output']['message']['content']:
            if 'text' in content:
                result_text += content['text']
            if 'citationsContent' in content:
                for citation in content['citationsContent']['citations']:
                    citations.append(citation['location']['web']['url'])
        
        # Add grounding sources if available
        if citations:
            result_text += "\n\n### Sources\n"
            for url in citations:
                result_text += f"- {url}\n"
        
        return result_text
    
    def _extract_cve_ids(self, text: str) -> list:
        """Extract CVE IDs from text"""
        import re
        return re.findall(r'CVE-\d{4}-\d{4,7}', text)
    
    def load_trivy_report(self, report_path: str) -> List[Dict]:
        """Load Trivy JSON report"""
        with open(report_path, 'r') as f:
            data = json.load(f)
        
        vulnerabilities = []
        for result in data.get('Results', []):
            vulnerabilities.extend(result.get('Vulnerabilities', []))
        
        return vulnerabilities
    
    def save_report(self, analysis: str, output_path: str):
        """Save analysis report"""
        with open(output_path, 'w') as f:
            f.write(analysis)
        print(f"Analysis report saved to {output_path}")

def main():
    parser = argparse.ArgumentParser(description='AI-Powered CVE Analyzer')
    parser.add_argument('--report', required=True, help='Path to Trivy JSON report')
    parser.add_argument('--output', required=True, help='Output path for analysis')
    parser.add_argument('--region', default='us-east-1', help='AWS region')
    
    args = parser.parse_args()
    
    try:
        analyzer = AICVEAnalyzer(region=args.region)
        
        print("Loading vulnerability report...")
        vulnerabilities = analyzer.load_trivy_report(args.report)
        
        if not vulnerabilities:
            print("No vulnerabilities found!")
            with open(args.output, 'w') as f:
                f.write("## ✅ No Vulnerabilities Detected\n\nAll dependencies are secure!")
            return 0
        
        print(f"Analyzing {len(vulnerabilities)} vulnerabilities with AI...")
        analysis = analyzer.analyze_vulnerabilities(vulnerabilities)
        
        analyzer.save_report(analysis, args.output)
        
        print("✅ Analysis complete!")
        return 0
        
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        return 1

if __name__ == '__main__':
    sys.exit(main())
