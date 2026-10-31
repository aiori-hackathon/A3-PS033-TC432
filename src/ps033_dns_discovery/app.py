
"""Local web dashboard for the PS-033 DNS discovery demonstration."""
from __future__ import annotations

import threading

from flask import Flask, jsonify, render_template, request

from dns_lab import DNSLab, serve
import services
from discovery import discover, invoke

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

lab = DNSLab()
stop_event = threading.Event()
_started = False
_start_lock = threading.Lock()


def start_background():
    global _started

    with _start_lock:
        if _started:
            return

        threading.Thread(
            target=serve,
            args=(lab, stop_event),
            name="dns-lab",
            daemon=True,
        ).start()

        threading.Thread(
            target=lambda: services.app.run(
                host="127.0.0.1",
                port=5055,
                threaded=True,
                use_reloader=False,
            ),
            name="mock-services",
            daemon=True,
        ).start()

        _started = True


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/status")
def status():
    return jsonify({
        "mode": lab.get_mode(),
        "dns": "127.0.0.1:53535",
        "services": "127.0.0.1:5055",
    })


@app.post("/api/mode")
def mode():
    body = request.get_json(silent=True) or {}

    try:
        lab.set_mode(body.get("mode", "normal"))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    return jsonify({"mode": lab.get_mode()})


@app.post("/api/move")
def move():
    lab.set_endpoint_override("http://127.0.0.1:5056/health")
    lab.set_mode("normal")

    return jsonify({
        "message": "Metadata now points to an unavailable local port"
    })


@app.post("/api/restore")
def restore():
    lab.set_endpoint_override(None)
    lab.set_mode("normal")

    return jsonify({"message": "Normal demo data restored"})


def pipeline_stage(stage_id, label, status, detail):
    return {
        "id": stage_id,
        "label": label,
        "status": status,
        "detail": detail,
    }


@app.post("/api/run")
def run():
    body = request.get_json(silent=True) or {}
    service = body.get("service", "health")
    bad_token = bool(body.get("bad_token", False))

    pipeline = [
        pipeline_stage("dns", "DNS lookup", "pending", "Waiting for DNS response"),
        pipeline_stage("signature", "DNSSEC verification", "pending", "Waiting for signature verification"),
        pipeline_stage("metadata", "Metadata validation", "pending", "Waiting for metadata validation"),
        pipeline_stage("auth", "Bearer-token authentication", "pending", "Waiting for service authentication"),
        pipeline_stage("invoke", "Service invocation", "pending", "Waiting for service response"),
    ]

    try:
        if service not in {"latency", "traceroute", "health"}:
            raise ValueError("Unknown service")

        pipeline[0].update(
            status="passed",
            detail="DNS TXT response requested from local DNS lab",
        )

        try:
            metadata = discover(service)
        except Exception as exc:
            message = str(exc)
            if "signature" in message.lower() or "rrsig" in message.lower():
                pipeline[1].update(status="rejected", detail=message)
            elif "metadata" in message.lower() or "endpoint" in message.lower():
                pipeline[1].update(status="passed", detail="DNSSEC signature verified")
                pipeline[2].update(status="rejected", detail=message)
            else:
                pipeline[1].update(status="rejected", detail=message)

            for stage in pipeline:
                if stage["status"] == "pending":
                    stage.update(status="blocked", detail="Blocked by an earlier failure")

            raise

        pipeline[1].update(
            status="passed",
            detail="RRSIG verified using the locally pinned DNSKEY",
        )
        pipeline[2].update(
            status="passed",
            detail="Metadata schema and endpoint policy accepted",
        )

        try:
            result = invoke(
                metadata,
                "wrong-token" if bad_token else None,
            )
        except Exception as exc:
            message = str(exc)
            if "authentication failed" in message.lower():
                pipeline[3].update(status="rejected", detail=message)
            else:
                pipeline[3].update(
                    status="not_verified",
                    detail="Authentication outcome could not be verified",
                )
                pipeline[4].update(status="rejected", detail=message)

            for stage in pipeline:
                if stage["status"] == "pending":
                    stage.update(status="blocked", detail="Blocked by an earlier failure")

            raise

        pipeline[3].update(status="passed", detail="Bearer token accepted")
        pipeline[4].update(status="passed", detail="Diagnostic service returned a response")

        return jsonify({
            "ok": True,
            "service": service,
            "metadata": metadata,
            "result": result,
            "pipeline": pipeline,
        })

    except Exception as exc:
        app.logger.info("Discovery/invocation failed: %s", exc)
        return jsonify({
            "ok": False,
            "service": service,
            "error": str(exc),
            "pipeline": pipeline,
        }), 400


@app.post("/api/test")
def test():
    results = []
    original_mode = lab.get_mode()

    scenarios = [
        ("valid discovery and invocation", "normal", False, None, True),
        ("bogus DNSSEC signature", "bogus", False, None, False),
        ("malformed DNS metadata", "malformed", False, None, False),
        ("invalid bearer token", "normal", True, None, False),
        ("unavailable service endpoint", "normal", False,
         "http://127.0.0.1:5056/health", False),
    ]

    try:
        for name, mode_name, bad_token, endpoint, expected_success in scenarios:
            lab.set_endpoint_override(endpoint)
            lab.set_mode(mode_name)

            try:
                metadata = discover("health")
                invoke(metadata, "wrong-token" if bad_token else None)
                observed_success = True
                detail = "Request completed successfully"
            except Exception as exc:
                observed_success = False
                detail = str(exc)

            passed = observed_success == expected_success

            results.append({
                "case": name,
                "category": "positive" if expected_success else "security-negative",
                "expected": "accept" if expected_success else "reject",
                "observed": "accept" if observed_success else "reject",
                "outcome": "PASS" if passed else "FAIL",
                "detail": detail,
            })

    finally:
        lab.set_endpoint_override(None)
        lab.set_mode(original_mode)

    total = len(results)
    passed_count = sum(item["outcome"] == "PASS" for item in results)
    failed_count = total - passed_count
    security_count = sum(
        item["category"] == "security-negative" for item in results
    )
    rejected_count = sum(
        item["category"] == "security-negative"
        and item["observed"] == "reject"
        for item in results
    )

    return jsonify({
        "tests": results,
        "metrics": {
            "total": total,
            "passed": passed_count,
            "failed": failed_count,
            "security_scenarios": security_count,
            "detection_rejection_checks": security_count,
            "detected_and_rejected": rejected_count,
        },
        "summary": (
            "All scenarios behaved as expected"
            if failed_count == 0
            else "One or more scenarios did not behave as expected"
        ),
    })


if __name__ == "__main__":
    start_background()
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
        use_reloader=False,
    )
