"""CVE Stream Processor - Handles DynamoDB stream events for new CVEs"""
import json
import os
import boto3

def lambda_handler(event, context):
    """Process new CVE records from DynamoDB stream - batched notifications"""
    bedrock = boto3.client('bedrock-runtime', region_name='us-east-1')
    sns = boto3.client('sns', region_name='us-east-1')
    topic_arn = os.environ.get('SNS_TOPIC_ARN')
    
    # Collect all CVEs from this batch
    cves = []
    for record in event.get('Records', []):
        if record['eventName'] == 'INSERT':
            new_image = record['dynamodb']['NewImage']
            cves.append({
                'cve_id': new_image.get('cve_id', {}).get('S', 'Unknown'),
                'repo': new_image.get('repo', {}).get('S', 'Unknown'),
                'severity': new_image.get('severity', {}).get('S', 'Unknown'),
                'package': new_image.get('package', {}).get('S', 'Unknown')
            })
    
    if not cves:
        return {'statusCode': 200, 'body': 'No new CVEs'}
    
    # Get AI summary for all CVEs at once
    cve_list = ", ".join([c['cve_id'] for c in cves[:5]])  # Limit to first 5
    ai_summary = "Analysis not available"
    
    critical_count = sum(1 for c in cves if c['severity'] == 'CRITICAL')
    high_count = sum(1 for c in cves if c['severity'] == 'HIGH')
    
    if critical_count > 0 or high_count > 0:
        try:
            response = bedrock.converse(
                modelId='us.amazon.nova-2-lite-v1:0',
                messages=[{
                    "role": "user",
                    "content": [{"text": f"Briefly summarize the risk for these CVEs in 2-3 sentences: {cve_list}"}]
                }],
                inferenceConfig={"maxTokens": 300, "temperature": 0.3},
                toolConfig={"tools": [{"systemTool": {"name": "nova_grounding"}}]}
            )
            ai_summary = "".join(c.get('text', '') for c in response['output']['message']['content'] if 'text' in c)
        except Exception as e:
            print(f"AI analysis failed: {e}")
    
    # Send ONE batched notification
    if topic_arn:
        cve_details = "\n".join([f"  • {c['cve_id']} ({c['severity']}) - {c['package']}" for c in cves])
        sns.publish(
            TopicArn=topic_arn,
            Subject=f"🚨 {len(cves)} CVEs Detected: {critical_count} Critical, {high_count} High",
            Message=f"""Security Scan Complete

Repository: {cves[0]['repo']}
Total CVEs Found: {len(cves)}
Critical: {critical_count}
High: {high_count}

Vulnerabilities:
{cve_details}

AI Summary:
{ai_summary[:800]}

Action Required: Review and patch affected packages.
"""
        )
        print(f"Batched notification sent for {len(cves)} CVEs")
    
    return {'statusCode': 200, 'body': f'Processed {len(cves)} CVEs'}
