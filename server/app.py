import os
from flask import Flask, send_from_directory, request

from .livecheck import processCodeData
from .slack import log_success_to_slack

STATIC_FOLDER= os.path.join(os.path.dirname(os.path.abspath(__file__)), "../dist")
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "")

app = Flask("livecheck", static_folder=None)

@app.route("/api/check", methods=["POST"])
def check():
    print("checking...")
    livecheck_data = request.get_data().decode('utf-8')
    result = processCodeData(livecheck_data)
    if result:
        if SLACK_WEBHOOK_URL:
            log_success_to_slack(SLACK_WEBHOOK_URL, result)
        return result, 200
    else:
        return "error", 401

# Serve the static HTML at remaining URLs that aren't static files
@app.route("/")
@app.route("/<path:path>")
def serve(path="index.html"):
    if os.path.exists(os.path.join(STATIC_FOLDER, path)):
        return send_from_directory(STATIC_FOLDER, path)
    else:
        return "not found", 404