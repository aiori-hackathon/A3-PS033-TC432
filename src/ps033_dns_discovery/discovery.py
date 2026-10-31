"""DNS TXT discovery, DNSSEC verification, metadata validation and invocation."""
from __future__ import annotations
import json
from pathlib import Path
from urllib.parse import urlparse
import dns.message, dns.query, dns.rcode, dns.rdatatype, dns.dnssec, dns.name, dns.rrset

ROOT = Path(__file__).resolve().parent
ZONE = dns.name.from_text("diag.test.")
DNS_HOST, DNS_PORT = "127.0.0.1", 53535
ALLOWED_SERVICES = {"latency", "traceroute", "health"}
ALLOWED_ENDPOINTS = {("127.0.0.1", 5055), ("localhost", 5055), ("127.0.0.1", 5056), ("localhost", 5056)}


def load_trust_anchor():
    path = ROOT / "trust_anchor.txt"
    if not path.is_file():
        raise RuntimeError("Trust anchor not found. Run: python setup_lab.py")
    fields = path.read_text(encoding="utf-8").split()
    try:
        index = fields.index("DNSKEY")
        return dns.rrset.from_text_list("diag.test.", 3600, "IN", "DNSKEY", [" ".join(fields[index + 1:])])
    except (ValueError, IndexError) as exc:
        raise RuntimeError("trust_anchor.txt is invalid; rerun setup_lab.py") from exc


def query(name: str, rdtype: str = "TXT"):
    message = dns.message.make_query(name, rdtype)
    response = dns.query.udp(message, DNS_HOST, port=DNS_PORT, timeout=2)
    if response.rcode() != dns.rcode.NOERROR:
        raise ValueError(f"DNS query failed: {dns.rcode.to_text(response.rcode())}")
    return response


def verify_txt(name: str, response):
    owner = dns.name.from_text(name)
    txt = next((rr for rr in response.answer if rr.rdtype == dns.rdatatype.TXT and rr.name == owner), None)
    sig = next((rr for rr in response.answer if rr.rdtype == dns.rdatatype.RRSIG and rr.name == owner and rr.covers == dns.rdatatype.TXT), None)
    if txt is None or sig is None:
        raise ValueError("Missing TXT metadata or RRSIG signature")
    dns.dnssec.validate(txt, sig, {ZONE: load_trust_anchor()})
    return txt


def validate_metadata(raw: str) -> dict:
    try:
        data = json.loads(raw)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError("Malformed metadata: invalid JSON") from exc
    required = {"name": str, "description": str, "endpoint": str, "auth": str, "token": str}
    if not isinstance(data, dict):
        raise ValueError("Malformed metadata: expected a JSON object")
    for field, expected in required.items():
        if not isinstance(data.get(field), expected) or not data[field].strip():
            raise ValueError(f"Malformed metadata: field '{field}' missing or wrong type")
    parsed = urlparse(data["endpoint"])
    if (parsed.scheme != "http" or parsed.username or parsed.password or parsed.path not in {"/latency", "/traceroute", "/health"}
            or parsed.query or parsed.fragment or (parsed.hostname, parsed.port) not in ALLOWED_ENDPOINTS):
        raise ValueError("Rejected endpoint: only approved local demo endpoints are allowed")
    if data["auth"] != "bearer":
        raise ValueError("Unsupported authentication method")
    return data


def discover(service: str) -> dict:
    if service not in ALLOWED_SERVICES:
        raise ValueError("Unknown service. Choose latency, traceroute, or health.")
    name = f"{service}.diag.test."
    txt = verify_txt(name, query(name))
    chunks = [part.decode("utf-8") if isinstance(part, bytes) else part for part in txt[0].strings]
    return validate_metadata("".join(chunks))


def invoke(metadata: dict, token_override: str | None = None) -> dict:
    import requests
    token = metadata["token"] if token_override is None else token_override
    try:
        response = requests.get(metadata["endpoint"], headers={"Authorization": f"Bearer {token}"}, timeout=2, allow_redirects=False)
        if response.status_code == 401:
            raise ValueError("Invocation rejected: service authentication failed (HTTP 401)")
        if response.is_redirect:
            raise ValueError("Invocation rejected: redirects are disabled")
        response.raise_for_status()
        try:
            return response.json()
        except requests.exceptions.JSONDecodeError as exc:
            raise ValueError("Service returned invalid JSON") from exc
    except requests.RequestException as exc:
        raise ValueError(f"Service unavailable: {exc}") from exc
