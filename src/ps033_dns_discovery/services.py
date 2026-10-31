"""Mock diagnostic HTTP endpoints. They bind to loopback only."""
from flask import Flask, jsonify, request
app = Flask(__name__)
TOKEN = "demo-token"  # Public demo credential; never reuse for real systems.

@app.before_request
def authenticate():
    if request.path != "/" and request.headers.get("Authorization") != f"Bearer {TOKEN}":
        return jsonify({"error": "Unauthorized: bearer token missing or invalid"}), 401

@app.get("/latency")
def latency():
    return jsonify({"service": "latency", "status": "ok", "latency_ms": 12.7, "note": "simulated measurement"})

@app.get("/traceroute")
def traceroute():
    return jsonify({"service": "traceroute", "status": "ok", "hops": [{"hop": 1, "host": "router.local", "ms": 1.2}, {"hop": 2, "host": "diagnostic-target.local", "ms": 8.4}], "note": "simulated route"})

@app.get("/health")
def health():
    return jsonify({"service": "health", "status": "healthy", "checks": {"dns": "ok", "http": "ok"}, "note": "mock health check"})
