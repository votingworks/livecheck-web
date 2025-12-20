import requests

def markdown(text):
    return { "type": "mrkdwn", "text": text }

def log_success_to_slack(
    slack_webhook_url,
    success_result,
    airtable_result=None,
):
    if airtable_result and not airtable_result["success"]:
        header_text = ":warning: Scan succeeded, but Airtable integration failed :warning:"
    else:
        header_text = ":white_check_mark: Scan succeeded"

    response = requests.post(
        slack_webhook_url,
        headers={"Content-Type": "application/json"},
        json={
            "text": header_text,
            "blocks": [
                {
                    "type": "section",
                    "text": markdown(f"*{header_text}*"),
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
