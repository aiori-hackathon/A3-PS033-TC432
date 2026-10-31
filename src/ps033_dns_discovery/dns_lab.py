"""Small UDP DNS responder for the local DNSSEC discovery lab."""
from __future__ import annotations
import json, socket, threading, time
from pathlib import Path
import dns.message, dns.name, dns.rcode, dns.rdatatype, dns.rrset, dns.flags, dns.dnssec
from cryptography.hazmat.primitives import serialization

ROOT = Path(__file__).resolve().parent
ZONE = dns.name.from_text("diag.test.")
HOST, PORT = "127.0.0.1", 53535
SERVICES = {
    "latency": {"name": "Latency Probe", "description": "Returns a simulated latency measurement", "endpoint": "http://127.0.0.1:5055/latency", "auth": "bearer", "token": "demo-token"},
    "traceroute": {"name": "Traceroute Probe", "description": "Returns a simulated route", "endpoint": "http://127.0.0.1:5055/traceroute", "auth": "bearer", "token": "demo-token"},
    "health": {"name": "Health Check", "description": "Returns mock service health", "endpoint": "http://127.0.0.1:5055/health", "auth": "bearer", "token": "demo-token"},
}
VALID_MODES = {"normal", "bogus", "malformed"}

class DNSLab:
    def __init__(self):
        key_path = ROOT / "lab_key.pem"
        if not key_path.is_file():
            raise RuntimeError("DNSSEC key not found. Run: python setup_lab.py")
        self.mode, self.endpoint_override = "normal", None
        self.lock = threading.RLock()
        self.key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        self.pub_dnskey = dns.dnssec.make_dnskey(self.key.public_key(), algorithm="ECDSAP256SHA256", flags=257)
        self.dnskey_rr = dns.rrset.from_rdata(ZONE, 3600, self.pub_dnskey)

    def set_mode(self, mode):
        if mode not in VALID_MODES:
            raise ValueError("Unsupported lab mode")
        with self.lock: self.mode = mode

    def get_mode(self):
        with self.lock: return self.mode

    def set_endpoint_override(self, endpoint):
        with self.lock: self.endpoint_override = endpoint

    def payload(self, service):
        with self.lock:
            data, mode = dict(SERVICES[service]), self.mode
            if self.endpoint_override: data["endpoint"] = self.endpoint_override
        if mode == "malformed": return '{"name": 55, "endpoint":'
        return json.dumps(data, separators=(",", ":"))

    def answer(self, request):
        response = dns.message.make_response(request)
        response.flags |= dns.flags.AA
        if not request.question:
            response.set_rcode(dns.rcode.FORMERR); return response
        question = request.question[0]
        if question.rdtype == dns.rdatatype.DNSKEY and question.name == ZONE:
            response.answer.append(self.dnskey_rr); return response
        labels = question.name.to_text().rstrip(".").split(".")
        if len(labels) != 3 or labels[1:] != ["diag", "test"] or question.rdtype not in (dns.rdatatype.TXT, dns.rdatatype.ANY):
            response.set_rcode(dns.rcode.NXDOMAIN); return response
        service = labels[0]
        if service not in SERVICES:
            response.set_rcode(dns.rcode.NXDOMAIN); return response
        owner = question.name
        original = dns.rrset.from_text(owner, 60, "IN", "TXT", json.dumps(self.payload(service)))
        now = int(time.time())
        signature = dns.dnssec.sign(original, self.key, ZONE, self.pub_dnskey, inception=now-60, expiration=now+3600)
        published = original
        if self.get_mode() == "bogus":
            published = dns.rrset.from_text(owner, 60, "IN", "TXT", json.dumps('{"name":"tampered","endpoint":"http://127.0.0.1:5055/health"}'))
        response.answer.extend([published, dns.rrset.from_rdata(owner, 60, signature)])
        return response


def serve(lab, stop_event):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, PORT)); sock.settimeout(.5)
    try:
        while not stop_event.is_set():
            try: packet, address = sock.recvfrom(8192)
            except socket.timeout: continue
            try: sock.sendto(lab.answer(dns.message.from_wire(packet)).to_wire(), address)
            except (ValueError, OSError): continue
    finally: sock.close()
