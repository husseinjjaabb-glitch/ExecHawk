from flask import Flask, jsonify, request
from flask_socketio import SocketIO, emit
from pathlib import Path

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

FINDINGS_DIR = "./reports"
findings_db = {}

def load_findings():
    for f in Path(FINDINGS_DIR).glob("finding-*.md"):
        fid = int(f.stem.split("-")[1])
        content = f.read_text()
        # Parse severity from content
        severity = "MEDIUM"
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if f"[{sev}]" in content:
                severity = sev
                break
        findings_db[fid] = {
            "id": fid,
            "file": f.name,
            "content": content,
            "size": f.stat().st_size,
            "severity": severity,
            "description": content.split("**Title:**")[-1].split("\n")[0].strip() if "**Title:**" in content else "",
            "title": content.split("# ")[-1].split("\n")[0] if "# " in content else f"Finding #{fid}",
            "target": "",
            "status": "CONFIRMED"
        }

@app.route("/")
def index():
    return jsonify({"name": "Exec Hawk API", "status": "running"})

@app.route("/api/findings")
def get_findings():
    return jsonify(sorted(findings_db.values(), key=lambda x: x["id"], reverse=True))

@app.route("/api/findings/<int:fid>")
def get_finding(fid):
    return jsonify(findings_db.get(fid, {"error": "Not found"}))

@app.route("/api/findings/<int:fid>/confirm", methods=["POST"])
def confirm(fid):
    if fid in findings_db:
        findings_db[fid]["status"] = "CONFIRMED"
        socketio.emit("finding_update", {"id": fid, "status": "CONFIRMED"})
    return jsonify({"ok": True})

@app.route("/api/findings/<int:fid>/submit", methods=["POST"])
def submit(fid):
    return jsonify({"ok": True, "submitted": fid})

@socketio.on("connect")
def on_connect():
    emit("connected", {"msg": "Exec Hawk online"})

if __name__ == "__main__":
    load_findings()
    socketio.run(app, debug=True, port=8443)