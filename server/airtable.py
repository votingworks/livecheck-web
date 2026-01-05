import requests

AIRTABLE_API_BASE = "https://api.airtable.com/v0"
SHV_EVENTS_TABLE = "SHV Events"


def log_success_to_airtable(api_key, base_id, success_result):
    """
    Creates a record in the SHV Events table.
    Returns {"success": True} or {"success": False, "error": "..."}
    """
    url = f"{AIRTABLE_API_BASE}/{base_id}/{SHV_EVENTS_TABLE}"

    try:
        response = requests.post(
            url,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            },
            json={
                "fields": {
                    "Machine ID": success_result.get("machine_id"),
                    "Election ID": success_result.get("election_id"),
                    "System Hash": success_result.get("system_hash"),
                    "Version": success_result.get("software_version"),
                    "Timestamp": success_result.get("timestamp")
                }
            }
        )

        if response.status_code in (200, 201):
            return {"success": True}
        else:
            print(f"Airtable: Failed to create record: {response.status_code}, {response.text}")
            return {"success": False, "error": f"API error {response.status_code}"}

    except Exception as e:
        print(f"Airtable: Exception: {e}")
        return {"success": False, "error": str(e)}
