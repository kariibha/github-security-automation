# AI-Powered GitHub Security Automation

Automatically detect secrets, scan for CVEs, and get AI-powered vulnerability analysis using Amazon Nova 2 Lite with web grounding.

## Features

- 🔒 **Pre-commit hooks** - Block secrets before they're committed
- 🔍 **CVE scanning** - Trivy scans dependencies on every push
- 🤖 **AI analysis** - Nova 2 Lite analyzes CVEs with real-time web data
- 📧 **Email alerts** - Batched notifications with AI insights

## Prerequisites

- AWS Account with Bedrock access (Nova 2 Lite enabled in us-east-1)
- GitHub account
- AWS CLI and SAM CLI installed
- Python 3.12+

## Quick Start

### 1. Clone and Deploy

```bash
git clone https://github.com/YOUR_USERNAME/github-security-automation.git
cd github-security-automation/infrastructure

# Deploy (replace with your email)
sam build
sam deploy --guided
```

When prompted:
- Stack name: `github-security` (or your choice)
- Region: `us-east-1` (required for Nova 2 Lite web grounding)
- NotificationEmail: Your email address
- Accept defaults for other options

### 2. Confirm Email Subscription

Check your inbox and click "Confirm subscription" from AWS SNS.

### 3. Note the Outputs

After deployment, note these values:
```
WebhookUrl: https://xxx.execute-api.us-east-1.amazonaws.com/Prod/webhook
CVETableName: github-security-cves
```

### 4. Add GitHub Actions Workflow

Copy `.github/workflows/security-scan.yml` to your repository:

```bash
mkdir -p your-repo/.github/workflows
cp github-actions/security-scan.yml your-repo/.github/workflows/
```

### 5. Configure GitHub Secrets

In your GitHub repository, go to Settings → Secrets → Actions and add:

| Secret | Value |
|--------|-------|
| `AWS_ACCESS_KEY_ID` | Your AWS access key |
| `AWS_SECRET_ACCESS_KEY` | Your AWS secret key |
| `DYNAMODB_TABLE` | The CVETableName from step 3 |

### 6. Add Webhook (Optional)

In your GitHub repository, go to Settings → Webhooks → Add webhook:
- Payload URL: The WebhookUrl from step 3
- Content type: `application/json`
- Events: Push, Pull requests

### 7. Install Pre-commit Hook (Optional)

```bash
# Install gitleaks
brew install gitleaks  # macOS
# or: sudo apt install gitleaks  # Ubuntu

# Run the installer in your repo
./install-gitleaks-hook.sh /path/to/your/repo
```

## GitHub Actions Workflow

The workflow (`.github/workflows/security-scan.yml`) does:

1. Runs Trivy to scan for vulnerabilities
2. Filters HIGH and CRITICAL CVEs
3. Stores them in DynamoDB
4. DynamoDB Stream triggers Lambda
5. Lambda uses Nova 2 Lite to analyze CVEs
6. Sends batched email notification

## Architecture

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  Pre-commit  │     │   GitHub     │     │   Lambda +   │
│  (gitleaks)  │────▶│   Actions    │────▶│  Nova 2 Lite │
│              │     │   (Trivy)    │     │              │
└──────────────┘     └──────────────┘     └──────────────┘
                            │                    │
                            ▼                    ▼
                     ┌──────────────┐     ┌──────────────┐
                     │  DynamoDB    │────▶│  SNS Email   │
                     │  + Streams   │     │  Notification│
                     └──────────────┘     └──────────────┘
```

## Cost Estimate

| Resource | Monthly Cost |
|----------|--------------|
| Lambda | ~$1-5 (depends on scan frequency) |
| DynamoDB | ~$1-2 (on-demand) |
| Nova 2 Lite | ~$5-15 (depends on CVE volume) |
| SNS | <$1 |
| **Total** | **~$10-25/month** |

## Customization

### Change Severity Filter

Edit `security-scan.yml`:
```yaml
severity: 'CRITICAL'  # Only critical (default: HIGH,CRITICAL)
```

### Adjust AI Analysis

Edit `lambda/cve_stream_processor.py`:
```python
inferenceConfig={"maxTokens": 500, "temperature": 0.3}
```

## Troubleshooting

### "AccessDeniedException" for Bedrock

Ensure your Lambda role has:
```yaml
- bedrock:Converse
- bedrock:InvokeTool  # Required for web grounding
```

### No emails received

1. Check you confirmed the SNS subscription
2. Check CloudWatch Logs for the CVE processor Lambda

### GitHub Actions failing

1. Verify AWS credentials are set in GitHub Secrets
2. Check the IAM user has `dynamodb:PutItem` permission

## Files

```
├── infrastructure/
│   └── template.yaml      # SAM template
├── lambda/
│   ├── cve_stream_processor.py    # CVE analysis + notifications
│   ├── security_webhook_handler.py # GitHub webhook handler
│   └── requirements.txt
├── github-actions/
│   └── security-scan.yml  # GitHub Actions workflow
├── install-gitleaks-hook.sh
└── test_nova.py           # Test Nova 2 Lite locally
```

## License

MIT
