import os
import requests
import pandas as pd
from datetime import datetime, timedelta
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Constants
DEPLOYMENT_SLUG = os.getenv('DEPLOYMENT_SLUG')
STATUSES = ['ignored', 'fixing', 'reviewing']
AUTH_TOKEN = os.getenv('AUTH_TOKEN')
DEFAULT_REMEDIATION_WINDOW_DAYS = 60  # Default for non-high severity
HIGH_SEVERITY_WINDOW_DAYS = 30
CSV_FILE_PATH = 'findings_report.csv'

def get_findings(status):
    api_url = f'https://semgrep.dev/api/v1/deployments/{DEPLOYMENT_SLUG}/findings?page_size=3000&status={status}'
    headers = {
        'Authorization': f'Bearer {AUTH_TOKEN}'
    }
    response = requests.get(api_url, headers=headers)
    response.raise_for_status()  # Raise an error for bad status codes
    return response.json()['findings']

def process_findings(findings):
    processed_findings = []
    today = datetime.utcnow().date()
    for finding in findings:
        finding_date = datetime.strptime(finding['created_at'], '%Y-%m-%dT%H:%M:%S.%fZ')
        if finding['severity'].lower() == 'high':
            remediation_window = HIGH_SEVERITY_WINDOW_DAYS
        else:
            remediation_window = DEFAULT_REMEDIATION_WINDOW_DAYS
        expiration_date = finding_date + timedelta(days=remediation_window)
        expiration_date_str = expiration_date.strftime('%Y-%m-%d')
        past_due = expiration_date.date() < today
        
        processed_findings.append({
            'repository_name': finding['repository']['name'],
            'state': finding['state'],
            'triage_state': finding['triage_state'],
            'created_at': finding_date.strftime('%Y-%m-%d'),
            'expiration_date': expiration_date_str,
            'severity': finding['severity'],
            'remediation_window': remediation_window,
            'past_due': past_due,
            'rule_name': finding['rule_name'],
        })
    return processed_findings

def generate_csv(findings):
    df = pd.DataFrame(findings)
    df = df[['repository_name', 'state', 'triage_state', 'created_at', 'expiration_date', 'severity', 'remediation_window', 'past_due', 'rule_name']]
    df.to_csv(CSV_FILE_PATH, index=False)

def main():
    all_findings = []
    for status in STATUSES:
        findings = get_findings(status)
        all_findings.extend(findings)
    
    processed_findings = process_findings(all_findings)
    generate_csv(processed_findings)
    print(f'Report generated: {CSV_FILE_PATH}')

if __name__ == '__main__':
    main()
