# Building an AI-Powered GitHub Security Scanner with Amazon Nova 2 Lite

**TL;DR:** I built a serverless security automation system that uses Amazon Nova 2 Lite with web grounding to detect secrets, analyze CVEs with real-time intelligence, and notify developers—all triggered automatically on every push.

## The Problem

Every developer has accidentally committed a secret at some point. And keeping track of CVEs in your dependencies? That's a full-time job. I wanted a system that would:

1. **Block secrets before they're committed** (pre-commit hooks)
2. **Scan for vulnerable packages** on every push (GitHub Actions)
3. **Analyze CVEs with real-time intelligence** (not stale databases)
4. **Notify me immediately** with actionable insights

## The Solution: Nova 2 Lite + Web Grounding

The game-changer here is **Amazon Nova 2 Lite's web grounding feature**. Instead of relying on static CVE databases, it searches the web in real-time to provide current threat intelligence with citations.

### Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Pre-commit    │     │  GitHub Actions │     │    Lambda +     │
│   (gitleaks)    │────▶│  (Trivy scan)   │────▶│   Nova 2 Lite   │
│   Block secrets │     │  Detect CVEs    │     │   AI Analysis   │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                                                        │
                                                        ▼
                                                ┌─────────────────┐
                                                │  SNS Email      │
                                                │  Notification   │
                                                └─────────────────┘
```

### Key Components

| Component | Purpose |
|-----------|---------|
| Gitleaks pre-commit hook | Blocks secrets locally before commit |
| GitHub Actions + Trivy | Scans dependencies for CVEs on push |
| DynamoDB + Streams | Stores CVEs and triggers processing |
| Lambda + Nova 2 Lite | AI-powered CVE analysis with web grounding |
| SNS | Batched email notifications |

## The Code

### Using Nova 2 Lite with Web Grounding

The key insight: web grounding uses `toolConfig` with a `systemTool`, not `additionalModelRequestFields`:

```python
import boto3

bedrock = boto3.client('bedrock-runtime', region_name='us-east-1')

response = bedrock.converse(
    modelId='us.amazon.nova-2-lite-v1:0',  # Use inference profile
    messages=[{
        "role": "user",
        "content": [{"text": f"Analyze the risk for CVE-2024-21626"}]
    }],
    inferenceConfig={"maxTokens": 500, "temperature": 0.3},
    toolConfig={
        "tools": [{
            "systemTool": {
                "name": "nova_grounding"  # Enables web search
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
          # This triggers the Lambda via DynamoDB Streams
```

### Lambda CVE Processor

```python
def lambda_handler(event, context):
    """Process CVEs from DynamoDB stream with batched notifications"""
    
    # Collect CVEs from stream records
    cves = [parse_record(r) for r in event['Records'] if r['eventName'] == 'INSERT']
    
    # Get AI analysis with web grounding
    cve_list = ", ".join([c['cve_id'] for c in cves[:5]])
    response = bedrock.converse(
        modelId='us.amazon.nova-2-lite-v1:0',
        messages=[{"role": "user", "content": [{"text": f"Summarize risks for: {cve_list}"}]}],
        toolConfig={"tools": [{"systemTool": {"name": "nova_grounding"}}]}
    )
    
    # Send ONE batched notification (not per-CVE!)
    sns.publish(
        TopicArn=topic_arn,
        Subject=f"🚨 {len(cves)} CVEs Detected",
        Message=f"AI Analysis:\n{ai_summary}\n\nCVEs:\n{cve_details}"
    )
```

## Real Results

When I pushed a `requirements.txt` with Django 3.2.0, the system:

1. ✅ Trivy detected **12 CVEs** (8 Critical, 4 High)
2. ✅ Nova 2 Lite analyzed each with **real-time web data**
3. ✅ I received **one consolidated email** with AI insights

Example AI analysis for CVE-2024-21626:
> "CVE-2024-21626 is a high-severity container escape vulnerability in runc, allowing attackers to break out of containers. CVSS score 8.6. Patch immediately by upgrading to runc 1.1.12+."

## IAM Permissions for Web Grounding

Don't forget `bedrock:InvokeTool` for web grounding:

```yaml
- Effect: Allow
  Action:
    - bedrock:Converse
    - bedrock:InvokeTool  # Required for web grounding!
  Resource:
    - !Sub 'arn:aws:bedrock:${AWS::Region}:${AWS::AccountId}:inference-profile/us.amazon.nova-2-lite-v1:0'
    - 'arn:aws:bedrock:*::foundation-model/*'
    - !Sub 'arn:aws:bedrock::${AWS::AccountId}:system-tool/*'
```

## Cost Comparison

| Model | Monthly Cost (est.) |
|-------|---------------------|
| Claude 3.5 Sonnet | $30-80 |
| **Nova 2 Lite** | **$10-25** |

~70% savings with Nova 2 Lite, plus you get web grounding for real-time CVE intelligence.

## Lessons Learned

1. **Batch your notifications** - My first version sent one email per CVE. I got 12 emails in 2 minutes. 😅
2. **Use inference profiles** - The model ID is `us.amazon.nova-2-lite-v1:0`, not `amazon.nova-2-lite-v1:0`
3. **Web grounding = toolConfig** - It's a system tool, not an inference config option

## Try It Yourself

```bash
git clone https://github.com/YOUR_USERNAME/github-security-automation.git
cd github-security-automation/infrastructure
sam build && sam deploy --guided
```

The repo includes:
- SAM template for all AWS resources
- GitHub Actions workflow for CVE scanning
- Pre-commit hook installer for secret detection
- Full documentation in README.md

---

*Have questions? Find me on the AWS Community Builders Slack or Twitter [@kariibha](https://twitter.com/kariibha).*

**Tags:** #AWS #AmazonBedrock #NovaAI #Security #Serverless #GitHubActions
