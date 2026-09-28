import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory


BASE_DIR = Path(__file__).resolve().parent
DATABASE = Path(os.environ.get("THREAT_MODEL_DB", BASE_DIR / "threat_models.sqlite3"))
app = Flask(__name__)

ASSET_TYPES = {
    "internet": "Internet",
    "user": "User",
    "web": "Web application",
    "api": "API service",
    "auth": "Identity service",
    "database": "Database",
    "cloud": "Cloud service",
    "network": "Network device",
}


def connect_db():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def seed_architecture():
    return {
        "nodes": [
            {"id": "internet", "name": "Public internet", "type": "internet"},
            {"id": "portal", "name": "Customer portal", "type": "web"},
            {"id": "identity", "name": "Auth API", "type": "auth"},
            {"id": "core-api", "name": "Core API", "type": "api"},
            {"id": "customer-db", "name": "Customer data", "type": "database"},
        ],
        "edges": [
            {"from": "internet", "to": "portal"},
            {"from": "portal", "to": "identity"},
            {"from": "portal", "to": "core-api"},
            {"from": "core-api", "to": "customer-db"},
        ],
    }


def init_db():
    with connect_db() as connection:
        connection.execute(
            """CREATE TABLE IF NOT EXISTS models (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                architecture TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )"""
        )
        count = connection.execute("SELECT COUNT(*) FROM models").fetchone()[0]
        if count == 0:
            connection.execute(
                "INSERT INTO models (name, description, architecture, updated_at) VALUES (?, ?, ?, ?)",
                (
                    "Northstar customer platform",
                    "Customer-facing services and their data boundaries.",
                    json.dumps(seed_architecture()),
                    datetime.now(timezone.utc).isoformat(),
                ),
            )


def serialize_model(row):
    model = dict(row)
    model["architecture"] = json.loads(model["architecture"])
    model["threats"] = analyze(model["architecture"])
    return model


def analyze(architecture):
    nodes = architecture.get("nodes", [])
    edges = architecture.get("edges", [])
    threats = []
    nodes_by_id = {node["id"]: node for node in nodes}
    incoming = {node["id"]: [] for node in nodes}
    outgoing = {node["id"]: [] for node in nodes}
    for edge in edges:
        if edge.get("from") in outgoing and edge.get("to") in incoming:
            outgoing[edge["from"]].append(edge["to"])
            incoming[edge["to"]].append(edge["from"])

    def internet_reachable(node_id):
        pending = [node_id]
        visited = set()
        while pending:
            current = pending.pop()
            if current in visited:
                continue
            visited.add(current)
            if nodes_by_id.get(current, {}).get("type") == "internet":
                return True
            pending.extend(incoming.get(current, []))
        return False

    def add(node, title, category, likelihood, impact, vector, mitigation):
        score = likelihood * impact
        level = "Critical" if score >= 17 else "High" if score >= 10 else "Medium" if score >= 5 else "Low"
        threats.append({
            "id": f"{node['id']}:{title}",
            "asset": node["name"],
            "asset_id": node["id"],
            "title": title,
            "category": category,
            "likelihood": likelihood,
            "impact": impact,
            "score": score,
            "level": level,
            "vector": vector,
            "mitigation": mitigation,
        })

    for node in nodes:
        kind = node.get("type")
        exposed = internet_reachable(node["id"])
        if kind in {"web", "api"}:
            add(node, "Injection through untrusted input", "Tampering", 3 if exposed else 2, 4,
                "User-controlled values reaching a query or command boundary.",
                ["Use parameterized queries and safe APIs", "Validate input against an allowlist", "Add security tests for every data boundary"])
            add(node, "Cross-site scripting", "Information Disclosure", 3 if exposed else 2, 3,
                "Untrusted content rendered in a browser context.",
                ["Encode output for its rendering context", "Apply a restrictive Content Security Policy", "Sanitize rich text with a maintained library"])
            add(node, "Service exhaustion", "Denial of Service", 3 if exposed else 2, 4,
                "High-volume requests or expensive operations consume service capacity.",
                ["Set request and payload limits", "Use rate limits and upstream protection", "Define timeouts and capacity alerts"])
            add(node, "Privilege escalation through weak authorization", "Elevation of Privilege", 3 if exposed else 2, 4,
                "An authenticated user or compromised service may reach actions beyond its intended role.",
                ["Authorize every request at the resource boundary", "Apply least privilege to users and service identities", "Test role and tenant isolation"])
        if kind in {"web", "api", "auth", "database", "cloud"}:
            add(node, "Insufficient audit trail", "Repudiation", 2, 3,
                "Missing or mutable event records make sensitive actions difficult to attribute.",
                ["Record actor, action, target, and timestamp", "Centralize and protect security logs from alteration", "Alert on gaps in critical audit events"])
        if kind in {"auth", "user"}:
            add(node, "Credential guessing or reuse", "Spoofing", 4 if exposed else 3, 4,
                "Weak, reused, or repeatedly guessed credentials.",
                ["Require MFA for sensitive access", "Rate-limit authentication attempts", "Screen passwords against known compromised values"])
            add(node, "Session or token theft", "Spoofing", 2 if exposed else 1, 5,
                "A stolen bearer token may impersonate a legitimate identity.",
                ["Use short-lived, audience-bound tokens", "Rotate refresh tokens and revoke sessions", "Protect cookies with Secure, HttpOnly, and SameSite"])
        if kind == "database":
            add(node, "Sensitive data exposure", "Information Disclosure", 3 if exposed else 2, 5,
                "Sensitive records may be read through an internet-reachable service path or an exposed data store.",
                ["Keep the database on a private network", "Encrypt sensitive data at rest and in transit", "Use a least-privilege database account"])
            add(node, "Unauthorized record changes", "Tampering", 2, 4,
                "A compromised upstream identity or service could alter stored records.",
                ["Scope database permissions to required operations", "Audit high-risk data changes", "Back up data and test restoration"])
        if kind in {"cloud", "network"}:
            add(node, "Misconfiguration exposes a resource", "Information Disclosure", 3, 4,
                "An overly broad network rule, policy, or storage permission exposes the asset.",
                ["Use private-by-default network policies", "Continuously review effective permissions", "Alert on public exposure changes"])
        if kind != "internet" and outgoing[node["id"]]:
            add(node, "Untrusted downstream response", "Tampering", 2, 3,
                "A downstream dependency can return unexpected or manipulated data.",
                ["Authenticate and validate service-to-service traffic", "Validate response schemas", "Apply timeouts and dependency failure handling"])

    return sorted(threats, key=lambda item: item["score"], reverse=True)


@app.get("/")
def index():
    return send_from_directory(BASE_DIR, "index.html")


@app.get("/api/models")
def list_models():
    with connect_db() as connection:
        rows = connection.execute("SELECT * FROM models ORDER BY updated_at DESC").fetchall()
    return jsonify([serialize_model(row) for row in rows])


@app.post("/api/models")
def create_model():
    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip()
    if not name:
        return jsonify({"error": "A model name is required."}), 400
    architecture = data.get("architecture") or {"nodes": [], "edges": []}
    with connect_db() as connection:
        cursor = connection.execute(
            "INSERT INTO models (name, description, architecture, updated_at) VALUES (?, ?, ?, ?)",
            (name[:100], str(data.get("description", ""))[:500], json.dumps(architecture), datetime.now(timezone.utc).isoformat()),
        )
        row = connection.execute("SELECT * FROM models WHERE id = ?", (cursor.lastrowid,)).fetchone()
    return jsonify(serialize_model(row)), 201


@app.get("/api/models/<int:model_id>")
def get_model(model_id):
    with connect_db() as connection:
        row = connection.execute("SELECT * FROM models WHERE id = ?", (model_id,)).fetchone()
    if row is None:
        return jsonify({"error": "Model not found."}), 404
    return jsonify(serialize_model(row))


@app.put("/api/models/<int:model_id>")
def update_model(model_id):
    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip()
    if not name:
        return jsonify({"error": "A model name is required."}), 400
    with connect_db() as connection:
        result = connection.execute(
            "UPDATE models SET name = ?, description = ?, architecture = ?, updated_at = ? WHERE id = ?",
            (name[:100], str(data.get("description", ""))[:500], json.dumps(data.get("architecture", {"nodes": [], "edges": []})), datetime.now(timezone.utc).isoformat(), model_id),
        )
        row = connection.execute("SELECT * FROM models WHERE id = ?", (model_id,)).fetchone()
    if result.rowcount == 0:
        return jsonify({"error": "Model not found."}), 404
    return jsonify(serialize_model(row))


@app.delete("/api/models/<int:model_id>")
def delete_model(model_id):
    with connect_db() as connection:
        result = connection.execute("DELETE FROM models WHERE id = ?", (model_id,))
    if result.rowcount == 0:
        return jsonify({"error": "Model not found."}), 404
    return "", 204


init_db()

if __name__ == "__main__":
    app.run(debug=True, port=int(os.environ.get("PORT", 5000)))