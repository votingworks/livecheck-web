import os
from flask import Flask, send_from_directory, request

from .livecheck import processCodeData

STATIC_FOLDER="../dist"

app = Flask("livecheck", static_folder=None)

@app.route("/api/check", methods=["POST"])
def check():
    livecheck_data = request.get_data().decode('utf-8')
    result = processCodeData(livecheck_data)
    if result:
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

