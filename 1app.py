from flask import Flask, jsonify, request, render_template
from database import init_db, get_db, investigate

app = Flask(__name__)
init_db()

@app.route("/", methods=["GET"])
def dashboard():
    return render_template("index.html")

@app.route("/api/policy-lookup", methods=["GET"])
def policy_lookup():
    src = request.args.get("src")
    dst = request.args.get("dst")
    port = request.args.get("port", type=int)
    device_id = request.args.get("device_id")
    platform = request.args.get("platform")
    category = request.args.get("category")

    result = investigate(
        device_id=device_id,
        platform=platform,
        category=category,
        src=src,
        dst=dst,
        port=port
    )
    return jsonify(result)

@app.route("/api/search", methods=["GET"])
def search_records():
    query_term = request.args.get("q", "")
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM records 
        WHERE device_id LIKE ? OR platform LIKE ? OR category LIKE ? OR raw_data LIKE ?
    """, (f"%{query_term}%", f"%{query_term}%", f"%{query_term}%", f"%{query_term}%"))

    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify({"query": query_term, "results": rows, "count": len(rows)})

@app.route("/api/topology", methods=["GET"])
def get_topology():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM topology")
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify({"topology_nodes": rows})

@app.route("/api/automation", methods=["GET"])
def get_automation_results():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM automation_results ORDER BY timestamp DESC")
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify({"automation_results": rows})

@app.route("/api/health", methods=["GET"])
def health_check():
    return jsonify({"status": "healthy", "service": "PerDef Security Orchestrator API"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
