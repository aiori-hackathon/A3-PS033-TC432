"""Generate the demo DNSSEC signing key and local trust anchor."""
from pathlib import Path
import dns.dnssec, dns.name, dns.rrset
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

ROOT = Path(__file__).resolve().parent
ZONE = dns.name.from_text("diag.test.")

def main():
    key = ec.generate_private_key(ec.SECP256R1())
    (ROOT / "lab_key.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    dnskey = dns.dnssec.make_dnskey(key.public_key(), algorithm="ECDSAP256SHA256", flags=257)
    anchor = dns.rrset.from_rdata(ZONE, 3600, dnskey)
    (ROOT / "trust_anchor.txt").write_text(anchor.to_text() + "\n", encoding="utf-8")
    print("Created lab_key.pem and trust_anchor.txt")
    print("Keep these generated files local; they are excluded from Git.")

if __name__ == "__main__": main()
