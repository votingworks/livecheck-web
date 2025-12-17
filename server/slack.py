import requests

def markdown(text):
    return { "type": "mrkdwn", "text": text }

def log_success_to_slack(
    slack_webhook_url,
    success_result,
):
    response = requests.post(
        slack_webhook_url,
        headers={"Content-Type": "application/json"},
        json={
            "text": "Scan succeeded",
            "blocks": [
                {
                    "type": "section",
                    "text": markdown("*Scan succeeded*"),
                },
                {
                    "type": "context",
                    "elements": [
                        markdown(f":label: {success_result['machine_id']}"),
                        markdown(f":cd: {success_result['software_version']}"),
                        markdown(f":hash: {success_result['system_hash']}")
                    ],
                }
            ]
        }
    )

    if response.status_code != 200:
        print(f"Failed to log to Slack: {response.status_code}, {response.text}")
