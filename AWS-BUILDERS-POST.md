# Building an AI-Powered GitHub Security Scanner with Amazon Nova 2 Lite

## Executive Summary

This post describes a serverless security automation system that uses Amazon Nova 2 Lite with web grounding to detect secrets, analyze CVEs with real-time intelligence, and notify developers automatically on every code push. The solution combines open-source scanning tools with AI-powered analysis to help development teams prioritize vulnerabilities based on current threat intelligence rather than static severity labels.

## The Customer Problem

Development teams face two persistent security challenges:

1. **Accidental secret exposure** – API keys, credentials, and tokens committed to repositories
2. **Dependency vulnerability management** – Tracking CVEs across dozens of packages and prioritizing remediation

Traditional vulnerability scanners detect issues but provide limited context. When a scan returns 12 CVEs labeled "CRITICAL," teams lack the information needed to determine which vulnerabilities pose actual risk and require immediate attention.

## Why Static CVE Data Falls Short

Consider what a typical vulnerability scanner returns:

```
CVE-2024-21626 | CRITICAL | runc | 1.1.11 | "container breakout vulnerability"
```

This static description from a CVE database answers *what* but not *so what*. Teams need to know:
- Is this vulnerability being actively exploited?
- What is the actual attack vector?
- What specific remediation steps should we take?
- Are there workarounds if immediate patching isn't possible?

## Solution Overview

This solution adds an AI-powered intelligence layer using Amazon Nova 2 Lite with web grounding. When vulnerabilities are detected, Nova 2 Lite searches current web sources to provide:

```
CVE-2024-21626 is actively being exploited in the wild as of January 2026. 
CVSS 8.6. Attackers can escape containers via /proc/self/fd manipulation. 
Patch to runc 1.1.12+. If patching isn't immediate, restrict container 
capabilities and monitor for unusual /proc access patterns.
```

| Static Scanner Output | With Nova 2 Lite Analysis |
|-----------------------|---------------------------|
| CVE description from database | Real-time web intelligence with citations |
| Severity label | Active exploitation status |
| Vulnerability name | Specific attack vector explanation |
| No remediation context | Patch versions and workarounds |

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Pre-commit    │     │  GitHub Actions │     │    Lambda +     │
│   (Gitleaks)    │────▶│  (Trivy scan)   │────▶│   Nova 2 Lite   │
│   Block secrets │     │  Detect CVEs    │     │   AI Analysis   │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                                                        │
                                                        ▼
                                                ┌─────────────────┐
                                                │  Amazon SNS     │
                                                │  Notification   │
                                                └─────────────────┘
```

**Data flow:**
1. Developer commits code
2. Gitleaks pre-commit hook blocks secrets locally
3. On push, GitHub Actions runs Trivy vulnerability scan
4. Detected CVEs are stored in Amazon DynamoDB
5. DynamoDB Streams triggers AWS Lambda
6. Lambda invokes Amazon Nova 2 Lite with web grounding for analysis
7. Amazon SNS sends batched email notification with AI insights

## AWS Services Used

| Service | Purpose |
|---------|---------|
| **Amazon Bedrock** | Managed access to Amazon Nova 2 Lite foundation model |
| **Amazon Nova 2 Lite** | AI analysis with web grounding for real-time CVE intelligence |
| **AWS Lambda** | Serverless compute for on-demand CVE processing |
| **Amazon DynamoDB** | CVE storage with Streams for event-driven processing |
| **Amazon SNS** | Email notifications |
| **AWS SAM** | Infrastructure-as-code deployment |

## Open-Source Tools

| Tool | Purpose |
|------|---------|
| **[Trivy](https://trivy.dev/)** | Vulnerability scanner by Aqua Security for dependencies, containers, and IaC |
| **[Gitleaks](https://gitleaks.io/)** | Secret detection for pre-commit hooks |

## Implementation

### Nova 2 Lite with Web Grounding

Web grounding enables Nova 2 Lite to search current web sources when generating responses. The key implementation detail: web grounding uses `toolConfig` with a `systemTool`, not `additionalModelRequestFields`.

```python
import boto3

bedrock = boto3.client('bedrock-runtime', region_name='us-east-1')

response = bedrock.converse(
    modelId='us.amazon.nova-2-lite-v1:0',
    messages=[{
        "role": "user",
        "content": [{"text": "Analyze the risk for CVE-2024-21626"}]
    }],
    inferenceConfig={"maxTokens": 500, "temperature": 0.3},
    toolConfig={
        "tools": [{
            "systemTool": {
                "name": "nova_grounding"
            }
        }]
    }
)

# Extract text and citations
for content in response['output']['message']['content']:
    if 'text' in content:
        print(content['text'])
    if 'citationsContent' in content:
        for citation in content['citationsContent']['citations']:
            print(f"Source: {citation['location']['web']['url']}")
```

### GitHub Actions Workflow

```yaml
name: Security Scan
on:
  push:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          format: 'json'
          output: 'trivy-results.json'
          severity: 'HIGH,CRITICAL'
      
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: us-east-1
      
      - name: Store CVEs in DynamoDB
        run: |
          # Parse Trivy results and store in DynamoDB
          # DynamoDB Streams triggers Lambda for AI analysis
```

### IAM Permissions

Web grounding requires `bedrock:InvokeTool` permission:

```yaml
- Effect: Allow
  Action:
    - bedrock:Converse
    - bedrock:InvokeTool
  Resource:
    - !Sub 'arn:aws:bedrock:${AWS::Region}:${AWS::AccountId}:inference-profile/us.amazon.nova-2-lite-v1:0'
    - 'arn:aws:bedrock:*::foundation-model/*'
    - !Sub 'arn:aws:bedrock::${AWS::AccountId}:system-tool/*'
```

## Results

Testing with a `requirements.txt` containing Django 3.2.0:

1. Trivy detected 12 CVEs (8 Critical, 4 High)
2. Nova 2 Lite analyzed vulnerabilities with current web data
3. Single consolidated email delivered with AI-powered insights

Example AI analysis output:
> "CVE-2024-21626 is a high-severity container escape vulnerability in runc, allowing attackers to break out of containers. CVSS score 8.6. Patch immediately by upgrading to runc 1.1.12+."

## Pricing

Amazon Nova 2 Lite offers competitive price-performance:

| Pricing Component | Cost |
|-------------------|------|
| Input tokens | $0.00125 per 1K tokens |
| Output tokens | $0.005 per 1K tokens |
| Web grounding | $0.01 per search |

**Estimated cost per scan (batched CVE analysis):**
- Input (~1K tokens): $0.00125
- Output (~500 tokens): $0.0025  
- Web grounding: $0.01
- **Total: ~$0.01-0.02 per scan**

**Monthly estimate (10 scans/day): ~$4-6**

## Lessons Learned

1. **Batch notifications** – Initial implementation sent one email per CVE. Batching reduced notification volume significantly.
2. **Use inference profiles** – The model ID is `us.amazon.nova-2-lite-v1:0`, not `amazon.nova-2-lite-v1:0`.
3. **Web grounding configuration** – Web grounding is a system tool configured via `toolConfig`, not an inference parameter.

## Getting Started

```bash
git clone https://github.com/kariibha/github-security-automation.git
cd github-security-automation/infrastructure
sam build && sam deploy --guided
```

The repository includes:
- AWS SAM template for all resources
- GitHub Actions workflow for CVE scanning
- Pre-commit hook installer for secret detection
- Documentation

**Repository:** [github.com/kariibha/github-security-automation](https://github.com/kariibha/github-security-automation)

## Conclusion

This solution demonstrates how Amazon Nova 2 Lite with web grounding can transform static vulnerability data into actionable intelligence. By combining open-source scanning tools with AI-powered analysis, development teams can prioritize remediation based on current threat landscape rather than severity labels alone.

---

**Tags:** #AWS #AmazonBedrock #AmazonNova #Security #Serverless #GitHubActions
